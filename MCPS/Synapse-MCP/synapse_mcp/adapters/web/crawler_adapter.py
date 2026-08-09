# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import html
from html.parser import HTMLParser
import json
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, parse_qsl, urljoin, urlsplit, urlunsplit

from ...core import credentials, dumps, evidence, fingerprint, scope, workspace
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ...core.url_hygiene import (
    canonical_url_identity,
    normalize_parameter_name,
    redact_url_query_values,
    redact_value_preview as redact_sensitive_preview,
    safe_query_items,
)
from ...core.paths import synapse_python
from ..command_utils import (
    approval_metadata,
    background_requested,
    require_confirmed,
    require_external_output_allowed,
    require_in_scope,
    start_background_command,
)
from .surface_hygiene import is_likely_spa_asset_pollution, is_numeric_spa_route, resolve_discovered_link
from . import js_intel


STATIC_EXTENSIONS = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".webp",
    ".avif",
    ".pdf",
    ".zip",
)

HTML_TYPES = ("text/html", "application/xhtml+xml")
SCRIPT_TYPES = ("application/javascript", "text/javascript", "application/x-javascript", "text/ecmascript")
DEFAULT_USER_AGENT = "SynapseCrawler/0.1"
LINK_ATTRIBUTES = ("href", "src", "formaction", "data-href", "data-url", "data-link", "data-target")
CLICK_NAVIGATION_RE = re.compile(
    r"(?:location(?:\.href|\.assign)?|window\.open)\s*(?:=|\()\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
URL_LITERAL_RE = re.compile(
    r"""(?P<quote>['"])(?P<url>(?:https?://[^'"\s<>()]+|/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?))(?P=quote)""",
    re.IGNORECASE,
)
ERROR_SIGNAL_RE = re.compile(
    r"(traceback|stack trace|exception|sql syntax|syntax error|fatal error|internal server error|warning:|notice:)",
    re.IGNORECASE,
)
AUTH_PATH_MARKERS = ("/login", "/signin", "/sign-in", "/auth", "/sso", "/oauth", "/session", "/logout")
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


SENSITIVE_FORM_MARKERS = (
    "admin",
    "delete",
    "remove",
    "destroy",
    "disable",
    "logout",
    "password",
    "reset",
    "role",
    "permission",
    "account",
    "billing",
    "payment",
    "upload",
    "import",
    "export",
)
SENSITIVE_FIELD_MARKERS = ("pass", "token", "csrf", "secret", "auth", "cookie", "session", "jwt", "key", "otp", "mfa")
POST_SKIP_INPUT_TYPES = {"submit", "button", "reset", "file", "password", "image"}


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self.forms: list[dict[str, Any]] = []
        self.base_href = ""
        self.title_parts: list[str] = []
        self._in_title = False
        self._current_form: dict[str, Any] | None = None
        self._current_select: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr_map = {name.lower(): value or "" for name, value in attrs}
        if tag == "title":
            self._in_title = True
        if tag == "base" and attr_map.get("href") and not self.base_href:
            self.base_href = attr_map["href"]
        for attr in LINK_ATTRIBUTES:
            if attr_map.get(attr):
                self.links.append({"tag": tag, "attribute": attr, "url": attr_map[attr]})
        if tag == "meta" and attr_map.get("http-equiv", "").lower() == "refresh":
            refresh_url = refresh_content_url(attr_map.get("content", ""))
            if refresh_url:
                self.links.append({"tag": tag, "attribute": "content", "url": refresh_url})
        if attr_map.get("onclick"):
            for clicked_url in CLICK_NAVIGATION_RE.findall(attr_map["onclick"]):
                self.links.append({"tag": tag, "attribute": "onclick", "url": clicked_url})
        if tag == "form":
            self._current_form = {
                "method": attr_map.get("method", "GET").upper(),
                "action": attr_map.get("action", ""),
                "id": attr_map.get("id", ""),
                "name": attr_map.get("name", ""),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        if tag in {"input", "textarea", "select", "button"} and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "tag": tag,
                    "name": attr_map.get("name", ""),
                    "type": attr_map.get("type", ""),
                    "valuePreview": attr_map.get("value", "")[:120],
                }
            )
            if tag == "select":
                self._current_select = self._current_form["inputs"][-1]
        if tag == "option" and self._current_select is not None and not self._current_select.get("valuePreview"):
            self._current_select["valuePreview"] = attr_map.get("value", "")[:120]

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        if tag == "form":
            self._current_form = None
        if tag == "select":
            self._current_select = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)

    @property
    def title(self) -> str:
        return " ".join("".join(self.title_parts).split())[:240]


def normalize_url(value: str, base: str | None = None) -> str:
    value = value.strip()
    if not value:
        return ""
    if any(char in value for char in ("\r", "\n", "\t")):
        return ""
    absolute = urljoin(base, value) if base else value
    parsed = urlsplit(absolute if "://" in absolute else f"https://{absolute}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


def document_base_url(page_url: str, base_href: str) -> str:
    if not base_href:
        return page_url
    normalized = normalize_url(base_href, page_url)
    return normalized or page_url


def is_probably_code_url(url: str) -> bool:
    parsed = urlsplit(url)
    target = " ".join([parsed.path, parsed.query]).lower()
    if any(marker in target for marker in ("})();", "=>", "function ", "return ", "var ", "let ", "const ", "class ")):
        return True
    if any(char in parsed.path for char in ("{", "}", "[", "]", "`")):
        return True
    return False


def has_repeated_path_phrase(url: str) -> bool:
    segments = [segment for segment in urlsplit(url).path.split("/") if segment]
    if len(segments) < 6:
        return False
    for width in (1, 2, 3):
        for index in range(0, len(segments) - (width * 3) + 1):
            phrase = segments[index : index + width]
            if (
                phrase
                and segments[index + width : index + (width * 2)] == phrase
                and segments[index + (width * 2) : index + (width * 3)] == phrase
            ):
                return True
    return False


def is_junk_path(url: str) -> bool:
    """A path made of a single stray punctuation segment (e.g. ``/(``) is not a route.

    These come from broken literal extraction, not real navigation, and otherwise
    pollute the endpoint set and every downstream candidate list.
    """
    segments = [segment for segment in urlsplit(url).path.split("/") if segment]
    if len(segments) != 1:
        return False
    segment = segments[0]
    if not any(char.isalnum() for char in segment):
        return True
    if re.fullmatch(r"[gimsuy]+[,;)]?", segment):
        return True
    if "," in segment and any(char in segment for char in "()[]{}"):
        return segment.count("(") != segment.count(")") or segment.count("[") != segment.count("]") or segment.count("{") != segment.count("}")
    return False


def valid_discovered_url(url: str) -> bool:
    if not url:
        return False
    return (
        not is_probably_code_url(url)
        and not has_repeated_path_phrase(url)
        and not is_junk_path(url)
        and not is_likely_spa_asset_pollution(url)
    )


def is_spa_shell_asset(record: dict[str, Any]) -> bool:
    """True when a static/script URL was answered with the SPA's HTML shell.

    A single-page app's catch-all returns ``index.html`` (``text/html``, 2xx) for a
    mis-resolved relative asset path such as ``/route/chunk-XXXX.js``. The real asset
    lives elsewhere and keeps its real content type, so only a *fetched* static URL
    whose observed content types are all HTML is treated as a phantom endpoint.
    """
    url = str(record.get("url", ""))
    if not url or not is_static_url(url):
        return False
    if not record.get("fetched"):
        return False
    content_types = [str(item).lower() for item in record.get("contentTypes", []) if str(item).strip()]
    if not content_types:
        return False
    return all(any(html_type in content_type for html_type in HTML_TYPES) for content_type in content_types)


def is_script_discovered_numeric_spa_route(record: dict[str, Any]) -> bool:
    """True for bare numeric routes extracted from JavaScript and served by a SPA shell."""
    url = str(record.get("url", ""))
    if not is_numeric_spa_route(url) or not record.get("fetched"):
        return False
    if not any(is_script_url(str(source)) for source in record.get("discoveredFrom", [])):
        return False
    content_types = [str(item).lower() for item in record.get("contentTypes", []) if str(item).strip()]
    if not content_types:
        return False
    return all(any(html_type in content_type for html_type in HTML_TYPES) for content_type in content_types)


def prune_phantom_asset_urls(urls: dict[str, dict[str, Any]]) -> int:
    """Drop SPA-shell phantom asset endpoints from one host's URL map. Returns count removed."""
    phantom = [
        key
        for key, record in urls.items()
        if isinstance(record, dict)
        and (
            is_spa_shell_asset(record)
            or is_likely_spa_asset_pollution(record.get("url", ""))
            or is_script_discovered_numeric_spa_route(record)
        )
    ]
    for key in phantom:
        del urls[key]
    removed = set(phantom)
    while removed:
        orphaned = [
            key
            for key, record in urls.items()
            if isinstance(record, dict)
            and not record.get("fetched")
            and is_static_url(str(record.get("url", "")))
            and record.get("discoveredFrom")
            and all(str(source) in removed for source in record.get("discoveredFrom", []))
        ]
        if not orphaned:
            break
        for key in orphaned:
            del urls[key]
        removed.update(orphaned)
        phantom.extend(orphaned)
    return len(phantom)


def refresh_content_url(content: str) -> str:
    for part in content.split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name.strip().lower() == "url":
            return value.strip().strip("'\"")
    return ""


def url_host(url: str) -> str:
    return scope.normalize_host(url)


def header_value(headers: dict[str, str], name: str) -> str:
    wanted = name.lower()
    for header_name, value in headers.items():
        if header_name.lower() == wanted:
            return str(value)
    return ""


def is_static_url(url: str) -> bool:
    return urlsplit(url).path.lower().endswith(STATIC_EXTENSIONS)


def is_script_url(url: str) -> bool:
    return urlsplit(url).path.lower().endswith((".js", ".mjs"))


def is_script_content(url: str, content_type: str) -> bool:
    return is_script_url(url) or any(kind in content_type for kind in SCRIPT_TYPES)


def extract_literal_links(text: str, base_url: str, limit: int = 500) -> list[str]:
    links: list[str] = []
    for match in URL_LITERAL_RE.finditer(text[:1_500_000]):
        raw = match.group("url")
        if raw.startswith("//"):
            continue
        if raw.startswith("/") and raw.startswith(("/.", "/#", "/\\")):
            continue
        linked_url = normalize_url(raw, base_url)
        if not valid_discovered_url(linked_url):
            continue
        if is_numeric_spa_route(linked_url):
            continue
        if linked_url and linked_url not in links:
            links.append(linked_url)
            if len(links) >= limit:
                break
    return links


def query_parameters(url: str) -> list[str]:
    return sorted({item["name"] for item in safe_query_items(url)})


def split_http_message(raw: str) -> tuple[str, dict[str, str], str]:
    head, sep, body = raw.partition("\r\n\r\n")
    if not sep:
        head, _, body = raw.partition("\n\n")
    lines = head.splitlines()
    start = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return start, headers, body


def request_url_from_raw(raw_request: str, default_scheme: str = "https") -> tuple[str, str]:
    start, headers, _ = split_http_message(raw_request)
    parts = start.split(" ", 2)
    if len(parts) < 2:
        return "", ""
    method = parts[0].upper()
    target = parts[1]
    if target.startswith(("http://", "https://")):
        return method, normalize_url(target)
    host = headers.get("host", "")
    if not host:
        return method, ""
    return method, normalize_url(f"{default_scheme}://{host}{target}")


def response_status_and_type(raw_response: str) -> tuple[int | None, str]:
    start, headers, _ = split_http_message(raw_response)
    status = None
    parts = start.split(" ", 2)
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    return status, headers.get("content-type", "").split(";", 1)[0].strip().lower()


def _append_unique(record: dict[str, Any], key: str, values: list[Any]) -> None:
    current = record.setdefault(key, [])
    if not isinstance(current, list):
        current = []
        record[key] = current
    for value in values:
        if value in ("", None):
            continue
        if value not in current:
            current.append(value)


def _append_unique_dict(record: dict[str, Any], key: str, values: list[dict[str, Any]]) -> None:
    current = record.setdefault(key, [])
    if not isinstance(current, list):
        current = []
        record[key] = current
    seen = {json.dumps(item, sort_keys=True, ensure_ascii=False) for item in current if isinstance(item, dict)}
    for value in values:
        marker = json.dumps(value, sort_keys=True, ensure_ascii=False)
        if marker not in seen:
            seen.add(marker)
            current.append(value)


def _merge_url_metadata(record: dict[str, Any], metadata: dict[str, Any]) -> None:
    for key in (
        "bodyParameters",
        "jsonParameters",
        "cookieNames",
        "responseCookieNames",
        "authorizationSchemes",
        "requestContentTypes",
        "redirectLocations",
        "errorSignals",
        "technologySignals",
    ):
        _append_unique(record, key, metadata.get(key, []))
    _append_unique_dict(record, "interestingErrors", metadata.get("interestingErrors", []))
    _append_unique_dict(record, "observedRequests", metadata.get("observedRequests", []))
    _append_unique_dict(record, "responseCookieFlags", metadata.get("responseCookieFlags", []))
    if isinstance(metadata.get("responseHeaders"), dict):
        record.setdefault("responseHeaders", {})
        for name, value in metadata["responseHeaders"].items():
            if value and name not in record["responseHeaders"]:
                record["responseHeaders"][name] = value
    for key in ("hasAuthorization", "apiRoute", "jsonEndpoint", "graphqlEndpoint", "stateChanging", "authBoundary"):
        if metadata.get(key):
            record[key] = True


def cookie_names(header_value: str) -> list[str]:
    names = []
    for part in header_value.split(";"):
        name, _, _ = part.strip().partition("=")
        if name:
            names.append(name)
    return sorted(set(names))


def set_cookie_names(value: str) -> list[str]:
    names = []
    for header in value.split("\n"):
        name, _, _ = header.strip().partition("=")
        if name:
            names.append(name)
    return sorted(set(names))


def set_cookie_flags(value: str) -> list[dict[str, Any]]:
    """Extract cookie name + security flags from Set-Cookie header(s).

    Records names and flags only, never the cookie value (a likely secret)."""
    flags = []
    for header in value.split("\n"):
        header = header.strip()
        if not header:
            continue
        name = header.split("=", 1)[0].strip()
        if not name:
            continue
        attributes = [segment.strip().lower() for segment in header.split(";")[1:]]
        same_site = ""
        for segment in attributes:
            if segment.startswith("samesite"):
                _, _, raw = segment.partition("=")
                same_site = raw.strip() or "present"
        flags.append(
            {
                "name": name,
                "httpOnly": "httponly" in attributes,
                "secure": "secure" in attributes,
                "sameSite": same_site,
            }
        )
    return flags


# Response headers worth retaining for fingerprinting, security-header hygiene,
# and CORS analysis. Values are bounded; secret-bearing headers are excluded.
SELECTED_RESPONSE_HEADER_NAMES = (
    "server",
    "x-powered-by",
    "x-generator",
    "location",
    "content-type",
    "www-authenticate",
    "feature-policy",
    "content-security-policy",
    "content-security-policy-report-only",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "x-recruiting",
)


def selected_response_headers(headers: dict[str, str]) -> dict[str, str]:
    selected = {}
    for name in SELECTED_RESPONSE_HEADER_NAMES:
        value = header_value(headers, name)
        if value:
            selected[name] = value[:300]
    return selected


def html_technology_signals(body: str, limit: int = 20) -> list[str]:
    signals = []
    snippet = body[:250_000]
    for pattern in (
        r"(?is)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']{1,160})[\"']",
        r"(?is)<meta[^>]+content=[\"']([^\"']{1,160})[\"'][^>]+name=[\"']generator[\"']",
    ):
        for match in re.finditer(pattern, snippet):
            signals.append(f"generator:{' '.join(match.group(1).split())}")
    lowered = snippet.lower()
    for marker in ("wp-content", "drupal", "joomla", "liferay", "oracle apex", "wwv_flow", "javax.faces", "primefaces", "humhub", "fotoweb", "easyappointments"):
        if marker in lowered:
            signals.append(marker)
    return sorted(set(signals))[:limit]


def authorization_scheme(header_value: str) -> str:
    return header_value.strip().split(" ", 1)[0] if header_value.strip() else ""


def json_parameter_paths(value: Any, prefix: str = "", limit: int = 80) -> list[str]:
    paths: list[str] = []
    if len(paths) >= limit:
        return paths
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            paths.append(path)
            if len(paths) >= limit:
                break
            paths.extend(json_parameter_paths(item, path, limit - len(paths)))
            if len(paths) >= limit:
                break
    elif isinstance(value, list):
        for item in value[:10]:
            paths.extend(json_parameter_paths(item, prefix, limit - len(paths)))
            if len(paths) >= limit:
                break
    return sorted(set(paths))


def request_metadata(raw_request: str, url: str, method: str, entry: dict[str, Any]) -> dict[str, Any]:
    _, headers, body = split_http_message(raw_request)
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    parsed = urlsplit(url)
    metadata: dict[str, Any] = {
        "bodyParameters": [],
        "jsonParameters": [],
        "cookieNames": cookie_names(headers.get("cookie", "")),
        "authorizationSchemes": [],
        "requestContentTypes": [content_type] if content_type else [],
        "hasAuthorization": bool(headers.get("authorization")),
        "apiRoute": parsed.path.startswith("/api") or "/api/" in parsed.path,
        "jsonEndpoint": "json" in content_type or parsed.path.lower().endswith(".json"),
        "graphqlEndpoint": "graphql" in parsed.path.lower(),
        "stateChanging": method.upper() in STATE_CHANGING_METHODS,
        "observedRequests": [
            {
                "historyId": entry.get("id"),
                "method": method,
                "requestFile": str(entry.get("requestFile", "")),
                "responseFile": str(entry.get("responseFile", "")),
            }
        ],
    }
    scheme = authorization_scheme(headers.get("authorization", ""))
    if scheme:
        metadata["authorizationSchemes"].append(scheme)

    if body and content_type == "application/x-www-form-urlencoded":
        metadata["bodyParameters"] = sorted({name for name, _ in parse_qsl(body, keep_blank_values=True) if name})
    elif body and content_type == "application/json":
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            metadata["jsonParameters"] = json_parameter_paths(payload)
            if isinstance(payload, dict) and any(key in payload for key in ("query", "mutation", "operationName")):
                metadata["graphqlEndpoint"] = True
    return metadata


def response_metadata(raw_response: str, url: str, status: int | None, content_type: str) -> dict[str, Any]:
    _, headers, body = split_http_message(raw_response)
    location = headers.get("location", "")
    metadata: dict[str, Any] = {
        "redirectLocations": [],
        "interestingErrors": [],
        "errorSignals": [],
        "responseHeaders": selected_response_headers(headers),
        "responseCookieNames": set_cookie_names(headers.get("set-cookie", "")),
        "responseCookieFlags": set_cookie_flags(headers.get("set-cookie", "")),
        "technologySignals": html_technology_signals(body),
        "jsonEndpoint": "json" in content_type,
        "authBoundary": bool(status in {401, 403} or headers.get("www-authenticate")),
    }
    if location:
        normalized_location = normalize_url(location, url)
        metadata["redirectLocations"].append(normalized_location or location)
        if status is not None and 300 <= status < 400:
            metadata["redirect"] = True
    if location and any(marker in location.lower() for marker in AUTH_PATH_MARKERS):
        metadata["authBoundary"] = True
    signals = sorted(set(match.group(1).lower() for match in ERROR_SIGNAL_RE.finditer(body[:250_000])))
    if status is not None and status >= 500:
        signals.append(f"http_{status}")
    signals = sorted(set(signals))
    if signals:
        metadata["errorSignals"] = signals
        metadata["interestingErrors"].append(
            {
                "status": status,
                "contentType": content_type,
                "signals": signals[:10],
            }
        )
    return metadata


def new_sitemap(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": source,
        "summary": {"hostCount": 0, "urlCount": 0, "formCount": 0},
        "hosts": {},
    }


def ensure_host(sitemap: dict[str, Any], host: str) -> dict[str, Any]:
    hosts = sitemap["hosts"]
    if host not in hosts:
        hosts[host] = {"urls": {}, "forms": []}
    return hosts[host]


def upsert_url(
    sitemap: dict[str, Any],
    url: str,
    *,
    method: str = "GET",
    status: int | None = None,
    content_type: str = "",
    discovered_from: str | None = None,
    fetched: bool | None = None,
    title: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    host = url_host(url)
    host_entry = ensure_host(sitemap, host)
    urls = host_entry["urls"]
    if url not in urls:
        parsed = urlsplit(url)
        urls[url] = {
            "url": url,
            "scheme": parsed.scheme,
            "host": host,
            "path": parsed.path or "/",
            "query": parsed.query,
            "queryParameters": query_parameters(url),
            "methods": [],
            "statusCodes": [],
            "contentTypes": [],
            "discoveredFrom": [],
            "fetched": False,
            "title": "",
            "bodyParameters": [],
            "jsonParameters": [],
            "cookieNames": [],
            "responseCookieNames": [],
            "responseCookieFlags": [],
            "authorizationSchemes": [],
            "requestContentTypes": [],
            "responseHeaders": {},
            "technologySignals": [],
            "redirectLocations": [],
            "interestingErrors": [],
            "errorSignals": [],
            "observedRequests": [],
            "hasAuthorization": False,
            "apiRoute": False,
            "jsonEndpoint": False,
            "graphqlEndpoint": False,
            "stateChanging": False,
            "authBoundary": False,
        }
    record = urls[url]
    if method and method not in record["methods"]:
        record["methods"].append(method)
    if status is not None and status not in record["statusCodes"]:
        record["statusCodes"].append(status)
    if content_type and content_type not in record["contentTypes"]:
        record["contentTypes"].append(content_type)
    if discovered_from and discovered_from not in record["discoveredFrom"]:
        record["discoveredFrom"].append(discovered_from)
    if fetched is not None:
        record["fetched"] = record["fetched"] or fetched
    if title and not record["title"]:
        record["title"] = title
    if metadata:
        _merge_url_metadata(record, metadata)
    return record


def add_forms(sitemap: dict[str, Any], page_url: str, forms: list[dict[str, Any]], base_url: str | None = None) -> None:
    host = url_host(page_url)
    host_entry = ensure_host(sitemap, host)
    seen = {
        (
            canonical_url_identity(form.get("pageUrl", "")),
            form.get("method"),
            canonical_url_identity(form.get("action", "")),
            tuple(sorted(normalize_parameter_name(input_item.get("name", "")) for input_item in form.get("inputs", []) if normalize_parameter_name(input_item.get("name", "")))),
        )
        for form in host_entry["forms"]
    }
    resolution_base = base_url or page_url
    for form in forms:
        action = normalize_url(form.get("action", "") or page_url, resolution_base)
        if action and not valid_discovered_url(action):
            continue
        safe_inputs = []
        for input_item in form.get("inputs", []):
            if not isinstance(input_item, dict):
                continue
            safe_name = normalize_parameter_name(input_item.get("name", ""))
            safe_input = {**input_item, "name": safe_name}
            preview, fingerprint = redact_sensitive_preview(safe_name, input_item.get("valuePreview", ""))
            safe_input["valuePreview"] = preview
            if fingerprint:
                safe_input["valueFingerprint"] = fingerprint
                safe_input["valueRedacted"] = True
            safe_inputs.append(safe_input)
        row = {
            "pageUrl": redact_url_query_values(page_url),
            "canonicalPageUrl": canonical_url_identity(page_url),
            "method": form.get("method", "GET"),
            "action": redact_url_query_values(action),
            "canonicalAction": canonical_url_identity(action),
            "id": form.get("id", ""),
            "name": form.get("name", ""),
            "inputs": safe_inputs,
        }
        key = (row["canonicalPageUrl"], row["method"], row["canonicalAction"], tuple(sorted(input_item.get("name", "") for input_item in row["inputs"] if input_item.get("name"))))
        if key not in seen:
            seen.add(key)
            host_entry["forms"].append(row)
        if action:
            upsert_url(sitemap, action, method=row["method"], discovered_from=page_url)


def form_submission_url(form: dict[str, Any], page_url: str, base_url: str | None = None) -> str:
    method = str(form.get("method", "GET")).upper()
    if method != "GET":
        return ""
    action = normalize_url(form.get("action", "") or page_url, base_url or page_url)
    if not action or not valid_discovered_url(action):
        return ""
    parsed = urlsplit(action)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    existing_names = {name for name, _ in params}
    for input_item in form.get("inputs", []):
        if not isinstance(input_item, dict):
            continue
        name = str(input_item.get("name", "")).strip()
        if not name or name in existing_names:
            continue
        input_type = str(input_item.get("type", "")).lower()
        if input_type in {"submit", "button", "reset", "file", "password"}:
            continue
        params.append((name, default_input_value(input_item)))
        existing_names.add(name)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(params, doseq=True), ""))


def default_input_value(input_item: dict[str, Any]) -> str:
    value = str(input_item.get("valuePreview", ""))
    if value:
        return value
    input_type = str(input_item.get("type", "")).lower()
    if input_type in {"checkbox", "radio"}:
        return "on"
    return "1"


def default_post_input_value(input_item: dict[str, Any], target_url: str) -> str:
    value = str(input_item.get("valuePreview", ""))
    if value:
        return value
    input_type = str(input_item.get("type", "")).lower()
    name = str(input_item.get("name", "")).lower()
    if input_type in {"checkbox", "radio"}:
        return "on"
    if input_type in {"email"} or "email" in name:
        return "synapse@example.invalid"
    if input_type in {"url"} or any(marker in name for marker in ("url", "uri", "link", "callback", "webhook")):
        return "https://example.invalid/"
    if input_type in {"number", "range"} or any(marker in name for marker in ("count", "num", "qty", "quantity", "amount")):
        return "1"
    if input_type == "date" or "date" in name:
        return "2026-01-01"
    if input_type == "time" or "time" in name:
        return "12:00"
    if input_type == "tel" or "phone" in name:
        return "+15555550100"
    if any(marker in name for marker in ("search", "query", "q", "keyword")):
        return "synapse"
    if any(marker in name for marker in ("name", "title", "subject")):
        return "Synapse Test"
    if any(marker in name for marker in ("message", "comment", "description", "body", "content")):
        return "Synapse generated test submission for authorized mapping."
    host = url_host(target_url) or "target"
    return f"synapse-test-{host}"


def sensitive_field_name(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in SENSITIVE_FIELD_MARKERS)


def redacted_form_values(values: dict[str, str]) -> dict[str, str]:
    return {name: "[REDACTED]" if sensitive_field_name(name) else value[:160] for name, value in values.items()}


def post_form_values(form: dict[str, Any], target_url: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for input_item in form.get("inputs", []):
        if not isinstance(input_item, dict):
            continue
        name = str(input_item.get("name", "")).strip()
        if not name:
            continue
        input_type = str(input_item.get("type", "")).lower()
        if input_type in POST_SKIP_INPUT_TYPES:
            continue
        values[name] = default_post_input_value(input_item, target_url)
    return values


def post_form_sensitivity_reason(form: dict[str, Any]) -> str:
    method = str(form.get("method", "GET")).upper()
    if method != "POST":
        return ""
    action = str(form.get("action", "")).lower()
    form_name = f"{form.get('id', '')} {form.get('name', '')}".lower()
    input_names = " ".join(str(item.get("name", "")) for item in form.get("inputs", []) if isinstance(item, dict)).lower()
    input_types = {str(item.get("type", "")).lower() for item in form.get("inputs", []) if isinstance(item, dict)}
    haystack = f"{action} {form_name} {input_names}"
    if "password" in input_types or "file" in input_types:
        return "form includes password or file input"
    for marker in SENSITIVE_FORM_MARKERS:
        if marker in haystack:
            return f"form contains sensitive marker: {marker}"
    return ""


def previous_crawl_present(workspace_id: str, host: str) -> bool:
    actions_path = workspace.target_entity_path(workspace_id, host, "actions")
    if not actions_path.exists():
        return False
    try:
        actions = json.loads(actions_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    if not isinstance(actions, list):
        return False
    return any(isinstance(item, dict) and item.get("tool") == "crawler.crawl" for item in actions)


def require_previous_crawl(workspace_id: str, host: str) -> None:
    if not previous_crawl_present(workspace_id, host):
        raise McpError(
            -32602,
            "crawler.extended requires a previous crawler.crawl run for the target workspace before POST form submission.",
        )


def response_result_metadata(response: dict[str, Any], url: str, status: int | None, content_type: str) -> dict[str, Any]:
    headers = response.get("headers", {}) if isinstance(response.get("headers"), dict) else {}
    body = str(response.get("body", ""))
    location = header_value(headers, "location")
    metadata: dict[str, Any] = {
        "responseHeaders": selected_response_headers(headers),
        "responseCookieNames": set_cookie_names(header_value(headers, "set-cookie")),
        "responseCookieFlags": set_cookie_flags(header_value(headers, "set-cookie")),
        "technologySignals": html_technology_signals(body),
        "jsonEndpoint": "json" in content_type,
        "authBoundary": bool(status in {401, 403} or header_value(headers, "www-authenticate")),
        "redirectLocations": [],
        "interestingErrors": [],
        "errorSignals": [],
    }
    if location:
        metadata["redirectLocations"].append(normalize_url(location, url) or location)
    signals = sorted(set(match.group(1).lower() for match in ERROR_SIGNAL_RE.finditer(body[:250_000])))
    if status is not None and status >= 500:
        signals.append(f"http_{status}")
    signals = sorted(set(signals))
    if signals:
        metadata["errorSignals"] = signals
        metadata["interestingErrors"].append({"status": status, "contentType": content_type, "signals": signals[:10]})
    return metadata


def crawl_http_policy(args: dict[str, Any], timeout: int) -> HttpClientPolicy:
    policy_args = {
        **args,
        "followRedirects": False,
        "maxBodyBytes": int(args.get("maxBodyBytes", 1_000_000)),
    }
    return HttpClientPolicy.from_args(policy_args, timeout_seconds=timeout)


def fetch_crawl_url(
    url: str,
    request_headers: dict[str, str],
    policy: HttpClientPolicy,
    allowed_hosts: set[str],
    rejected_hosts: set[str],
    include_in_scope_hosts: bool,
    http_session: Any | None = None,
    workspace_id: str = "",
) -> dict[str, Any]:
    current_url = url
    redirects = 0
    attempted_requests = 0
    http_responses = 0

    def finish(payload: dict[str, Any]) -> dict[str, Any]:
        return {**payload, "attemptedCount": attempted_requests, "httpResponseCount": http_responses}

    while True:
        request = HttpRequest(url=current_url, headers=request_headers)
        attempted_requests += 1
        response = http_session.send(request) if http_session is not None else http_client.send(request, policy=policy)
        if response.status is None:
            return finish({"finalUrl": current_url, "status": None, "contentType": "", "body": "", "error": response.error})
        http_responses += 1
        content_type = header_value(response.headers, "content-type").split(";", 1)[0].strip().lower()
        response_meta = {
            "headers": response.headers,
            "responseHeaders": selected_response_headers(response.headers),
            "responseCookieNames": set_cookie_names(header_value(response.headers, "set-cookie")),
            "responseCookieFlags": set_cookie_flags(header_value(response.headers, "set-cookie")),
        }
        if response.status in REDIRECT_STATUSES:
            location = header_value(response.headers, "location")
            if not location:
                return finish({"finalUrl": current_url, "status": response.status, "contentType": content_type, "body": "", **response_meta, "error": "Redirect response did not include a Location header."})
            next_url = normalize_url(location, current_url)
            if not next_url:
                return finish({"finalUrl": current_url, "status": response.status, "contentType": content_type, "body": "", **response_meta, "error": f"Redirect Location was not a valid URL: {location}"})
            if not crawl_host_allowed(next_url, allowed_hosts, rejected_hosts, include_in_scope_hosts, workspace_id):
                return finish({
                    "finalUrl": current_url,
                    "status": response.status,
                    "contentType": content_type,
                    "body": "",
                    **response_meta,
                    "blockedRedirect": next_url,
                    "error": f"Redirected out of scope: {next_url}",
                })
            redirects += 1
            if redirects > 10:
                return finish({"finalUrl": current_url, "status": response.status, "contentType": content_type, "body": "", **response_meta, "error": "Too many redirects."})
            current_url = next_url
            continue
        return finish({"finalUrl": normalize_url(response.url or current_url), "status": response.status, "contentType": content_type, "body": response.body, **response_meta, "error": response.error})


def submit_post_form(
    form: dict[str, Any],
    page_url: str,
    request_headers: dict[str, str],
    http_policy: HttpClientPolicy,
    allowed_hosts: set[str],
    rejected_hosts: set[str],
    include_in_scope_hosts: bool,
    http_session: Any | None = None,
    workspace_id: str = "",
) -> dict[str, Any]:
    action_url = normalize_url(form.get("action", "") or page_url, page_url)
    if not action_url:
        return {"submitted": False, "error": "POST form action did not resolve to a valid URL."}
    if not crawl_host_allowed(action_url, allowed_hosts, rejected_hosts, include_in_scope_hosts, workspace_id):
        return {"submitted": False, "actionUrl": action_url, "error": "POST form action is outside authorized scope."}
    values = post_form_values(form, action_url)
    body = urlencode(values, doseq=True)
    headers = {
        **request_headers,
        "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    request = HttpRequest(url=action_url, method="POST", headers=headers, body=body)
    response = http_session.send(request) if http_session is not None else http_client.send(request, policy=http_policy)
    content_type = header_value(response.headers, "content-type").split(";", 1)[0].strip().lower() if response.status is not None else ""
    redirect_location = header_value(response.headers, "location")
    normalized_redirect = normalize_url(redirect_location, action_url) if redirect_location else ""
    return {
        "submitted": True,
        "actionUrl": action_url,
        "body": response.body,
        "status": response.status,
        "contentType": content_type,
        "headers": response.headers,
        "responseHeaders": selected_response_headers(response.headers),
        "responseCookieNames": set_cookie_names(header_value(response.headers, "set-cookie")),
        "responseCookieFlags": set_cookie_flags(header_value(response.headers, "set-cookie")),
        "redirectLocation": normalized_redirect or redirect_location,
        "error": response.error,
        "parameterNames": sorted(values),
        "submittedValues": redacted_form_values(values),
    }


def crawl_host_allowed(
    url: str,
    allowed_hosts: set[str],
    rejected_hosts: set[str],
    include_in_scope_hosts: bool,
    workspace_id: str = "",
) -> bool:
    host = url_host(url)
    if host in allowed_hosts:
        return True
    if host in rejected_hosts:
        return False
    if not include_in_scope_hosts:
        rejected_hosts.add(host)
        return False
    workspace_scope = workspace.workspace_scope(workspace_id) if workspace_id else {}
    has_workspace_scope = any(workspace_scope.get(name) for name in ("hosts", "patterns", "cidrs"))
    scope_result = scope.check_target_in_scope(url, workspace_scope) if has_workspace_scope else scope.check_target(url)
    if scope_result.get("inScope"):
        allowed_hosts.add(host)
        return True
    rejected_hosts.add(host)
    return False


def record_crawl_relation(
    relations: dict[tuple[str, str, str], dict[str, Any]],
    source_url: str,
    target_url: str,
    relation_type: str,
    *,
    followed: bool,
    workspace_id: str,
) -> None:
    source_host = url_host(source_url)
    target_host = url_host(target_url)
    if not source_host or not target_host or source_host == target_host:
        return
    workspace_scope = workspace.workspace_scope(workspace_id) if workspace_id else {}
    has_workspace_scope = any(workspace_scope.get(name) for name in ("hosts", "patterns", "cidrs"))
    checked = scope.check_target_in_scope(target_url, workspace_scope) if has_workspace_scope else scope.check_target(target_url)
    key = (source_url, target_url, relation_type)
    if followed:
        for existing_relation in relations.values():
            if existing_relation.get("sourceUrl") == source_url and existing_relation.get("targetUrl") == target_url:
                existing_relation["followed"] = True
    existing = relations.get(key)
    if existing:
        existing["followed"] = bool(existing.get("followed") or followed)
        return
    relations[key] = {
        "sourceUrl": source_url,
        "targetUrl": target_url,
        "sourceHost": source_host,
        "targetHost": target_host,
        "relationType": relation_type,
        "followed": followed,
        "scopeStatus": "in_scope" if checked.get("inScope") else "out_of_scope",
        "scopeMatch": checked.get("match", {}),
        "confidence": "high",
        "source": "crawler",
    }


def crawl_forms_for_sitemap(
    forms: list[dict[str, Any]],
    page_url: str,
    base_url: str,
    consider_discovered: Any,
) -> list[dict[str, Any]]:
    retained: list[dict[str, Any]] = []
    for form in forms:
        action_url = normalize_url(form.get("action", "") or page_url, base_url)
        if action_url and url_host(action_url) != url_host(page_url):
            if not consider_discovered(action_url, page_url, "form_action"):
                continue
        retained.append(form)
    return retained


def flatten_sitemap(sitemap: dict[str, Any]) -> dict[str, Any]:
    flat_hosts = []
    url_count = 0
    form_count = 0
    for host, data in sorted(sitemap["hosts"].items()):
        prune_phantom_asset_urls(data["urls"])
        urls = sorted(data["urls"].values(), key=lambda item: item["url"])
        forms = sorted(data["forms"], key=lambda item: (item["pageUrl"], item["action"], item["method"]))
        for record in urls:
            record["methods"].sort()
            record["statusCodes"].sort()
            record["contentTypes"].sort()
            record["discoveredFrom"].sort()
        url_count += len(urls)
        form_count += len(forms)
        flat_hosts.append({"host": host, "urlCount": len(urls), "formCount": len(forms), "urls": urls, "forms": forms})
    sitemap["hosts"] = flat_hosts
    sitemap["summary"] = {"hostCount": len(flat_hosts), "urlCount": url_count, "formCount": form_count}
    return sitemap


def sanitize_sitemap_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Remove sensitive/dynamic URL values and collapse canonical variants."""
    clean = json.loads(json.dumps(payload))
    for host_entry in clean.get("hosts", []):
        if not isinstance(host_entry, dict):
            continue
        merged_urls: dict[str, dict[str, Any]] = {}
        for record in host_entry.get("urls", []):
            if not isinstance(record, dict):
                continue
            raw_url = str(record.get("url", ""))
            canonical = canonical_url_identity(raw_url)
            safe_url = redact_url_query_values(raw_url)
            if not canonical or not safe_url:
                continue
            item = {**record, "url": safe_url, "canonicalUrl": canonical, "path": urlsplit(safe_url).path or "/"}
            item["queryParameters"] = sorted({query["name"] for query in safe_query_items(raw_url)})
            for field in ("discoveredFrom", "redirectLocations"):
                if isinstance(item.get(field), list):
                    item[field] = sorted({redact_url_query_values(value) for value in item[field] if redact_url_query_values(value)})
            existing = merged_urls.get(canonical)
            if existing is None:
                merged_urls[canonical] = item
                continue
            for field, value in item.items():
                if isinstance(value, list):
                    current = existing.get(field) if isinstance(existing.get(field), list) else []
                    existing[field] = current + [entry for entry in value if entry not in current]
                elif isinstance(value, bool):
                    existing[field] = bool(existing.get(field) or value)
                elif value not in ("", None, [], {}) and existing.get(field) in ("", None, [], {}):
                    existing[field] = value
        host_entry["urls"] = sorted(merged_urls.values(), key=lambda item: item["canonicalUrl"])

        merged_forms: dict[tuple[str, str, str, tuple[str, ...]], dict[str, Any]] = {}
        for form in host_entry.get("forms", []):
            if not isinstance(form, dict):
                continue
            page_url = redact_url_query_values(form.get("pageUrl", ""))
            action = redact_url_query_values(form.get("action", ""))
            inputs = []
            for input_item in form.get("inputs", []):
                if not isinstance(input_item, dict):
                    continue
                name = normalize_parameter_name(input_item.get("name", ""))
                if input_item.get("valueRedacted"):
                    safe_input = {**input_item, "name": name, "valuePreview": "<redacted>"}
                else:
                    preview, fingerprint = redact_sensitive_preview(name, input_item.get("valuePreview", ""))
                    safe_input = {**input_item, "name": name, "valuePreview": preview}
                    if fingerprint:
                        safe_input.update({"valueFingerprint": fingerprint, "valueRedacted": True})
                inputs.append(safe_input)
            input_names = tuple(sorted({item["name"] for item in inputs if item.get("name")}))
            key = (canonical_url_identity(page_url), str(form.get("method", "GET")).upper(), canonical_url_identity(action), input_names)
            if key not in merged_forms:
                merged_forms[key] = {
                    **form,
                    "pageUrl": page_url,
                    "canonicalPageUrl": key[0],
                    "method": key[1],
                    "action": action,
                    "canonicalAction": key[2],
                    "inputs": inputs,
                }
        host_entry["forms"] = sorted(merged_forms.values(), key=lambda item: (item["canonicalPageUrl"], item["canonicalAction"], item["method"]))
        host_entry["urlCount"] = len(host_entry["urls"])
        host_entry["formCount"] = len(host_entry["forms"])

    relations: dict[tuple[str, str, str], dict[str, Any]] = {}
    for relation in clean.get("relations", []):
        if not isinstance(relation, dict):
            continue
        source_url = redact_url_query_values(relation.get("sourceUrl", ""))
        target_url = redact_url_query_values(relation.get("targetUrl", ""))
        key = (canonical_url_identity(source_url), canonical_url_identity(target_url), str(relation.get("relationType", "")))
        if key not in relations:
            relations[key] = {**relation, "sourceUrl": source_url, "targetUrl": target_url}
        else:
            relations[key]["followed"] = bool(relations[key].get("followed") or relation.get("followed"))
    clean["relations"] = sorted(relations.values(), key=lambda item: (item.get("sourceHost", ""), item.get("relationType", ""), item.get("targetHost", ""), item.get("targetUrl", "")))

    crawl = clean.get("crawl")
    if isinstance(crawl, dict):
        for error in crawl.get("errors", []):
            if not isinstance(error, dict):
                continue
            for field in ("url", "formAction"):
                if error.get(field):
                    error[field] = redact_url_query_values(error[field])
        for submission in crawl.get("postSubmissions", []):
            if not isinstance(submission, dict):
                continue
            for field in ("pageUrl", "actionUrl", "redirectLocation"):
                if submission.get(field):
                    submission[field] = redact_url_query_values(submission[field])
            if isinstance(submission.get("submittedValues"), dict):
                safe_values = {}
                for name, value in submission["submittedValues"].items():
                    safe_name = normalize_parameter_name(name)
                    preview = str(value) if str(value) in {"[REDACTED]", "<redacted>"} else redact_sensitive_preview(safe_name, value, limit=160)[0]
                    safe_values[safe_name] = preview
                submission["submittedValues"] = safe_values
    source = clean.get("source")
    if isinstance(source, dict) and source.get("target"):
        source["target"] = redact_url_query_values(source["target"])
    if isinstance(source, dict) and isinstance(source.get("scope"), dict) and source["scope"].get("target"):
        source["scope"]["target"] = redact_url_query_values(source["scope"]["target"])
    summary = clean.get("summary")
    if isinstance(summary, dict):
        summary["urlCount"] = sum(int(host.get("urlCount", 0) or 0) for host in clean.get("hosts", []) if isinstance(host, dict))
        summary["formCount"] = sum(int(host.get("formCount", 0) or 0) for host in clean.get("hosts", []) if isinstance(host, dict))
    clean["sensitiveData"] = {"queryValuesRedacted": True, "canonicalIdentity": "scheme_host_path_sorted_parameter_names"}
    return clean


def graph_id(prefix: str, value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_")[:48]
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}_{slug}_{digest}" if slug else f"{prefix}_{digest}"


def endpoint_label(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        params = ",".join(query_parameters(url)[:5])
        return f"{path}?{params}" if params else f"{path}?"
    return path


def flow_graph_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    edge_keys: set[tuple[str, str, str, str, str]] = set()

    def add_node(node_id: str, node_type: str, label: str, **metadata: Any) -> None:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": node_type, "label": label, **metadata}

    def add_edge(source: str, target: str, edge_type: str, *, method: str = "", status: Any = None, observed: bool = False, submitted: bool = False, metadata: dict[str, Any] | None = None) -> None:
        key = (source, target, edge_type, method, str(status))
        if key in edge_keys:
            return
        edge_keys.add(key)
        edge = {
            "source": source,
            "target": target,
            "type": edge_type,
            "method": method,
            "status": status,
            "observed": observed,
            "submitted": submitted,
        }
        if metadata:
            edge.update(metadata)
        edges.append(edge)

    for host_entry in payload.get("hosts", []):
        if not isinstance(host_entry, dict):
            continue
        host = str(host_entry.get("host", ""))
        if not host:
            continue
        host_id = graph_id("host", host)
        add_node(host_id, "host", host, host=host)
        url_records = {str(item.get("url", "")): item for item in host_entry.get("urls", []) if isinstance(item, dict) and item.get("url")}
        for url, record in url_records.items():
            node_id = graph_id("url", url)
            methods = sorted(str(item) for item in record.get("methods", []) if item)
            status_codes = sorted(record.get("statusCodes", []))
            add_node(
                node_id,
                "endpoint",
                endpoint_label(url),
                url=url,
                host=host,
                path=record.get("path", ""),
                methods=methods,
                statusCodes=status_codes,
                fetched=bool(record.get("fetched")),
                stateChanging=bool(record.get("stateChanging")),
                authBoundary=bool(record.get("authBoundary")),
                apiRoute=bool(record.get("apiRoute")),
            )
            add_edge(host_id, node_id, "contains", observed=bool(record.get("fetched")))
            for observed_request in record.get("observedRequests", []):
                if not isinstance(observed_request, dict):
                    continue
                method = str(observed_request.get("method", "")).upper()
                add_edge(
                    host_id,
                    node_id,
                    "request",
                    method=method,
                    status=status_codes[0] if status_codes else None,
                    observed=True,
                    submitted=True,
                    metadata={"historyId": observed_request.get("historyId"), "requestFile": observed_request.get("requestFile", "")},
                )
            for source_url in record.get("discoveredFrom", []):
                source_url = str(source_url)
                source_id = graph_id("url", source_url)
                add_node(source_id, "endpoint", endpoint_label(source_url), url=source_url, host=url_host(source_url), path=urlsplit(source_url).path or "/")
                add_edge(
                    source_id,
                    node_id,
                    "navigation",
                    method=methods[0] if methods else "GET",
                    status=status_codes[0] if status_codes else None,
                    observed=bool(record.get("fetched")),
                    submitted=bool(record.get("fetched")),
                    metadata={"parameterNames": record.get("queryParameters", [])},
                )
            for redirect_url in record.get("redirectLocations", []):
                redirect_url = str(redirect_url)
                redirect_id = graph_id("url", redirect_url)
                add_node(redirect_id, "endpoint", endpoint_label(redirect_url), url=redirect_url, host=url_host(redirect_url), path=urlsplit(redirect_url).path or "/")
                redirect_status = next((status for status in status_codes if isinstance(status, int) and 300 <= status < 400), None)
                add_edge(node_id, redirect_id, "redirect", method=methods[0] if methods else "GET", status=redirect_status, observed=True, submitted=True)
        for form in host_entry.get("forms", []):
            if not isinstance(form, dict):
                continue
            page_url = str(form.get("pageUrl", ""))
            action = str(form.get("action", ""))
            method = str(form.get("method", "GET")).upper()
            input_names = sorted(str(item.get("name", "")) for item in form.get("inputs", []) if isinstance(item, dict) and item.get("name"))
            form_id = graph_id("form", f"{page_url}|{method}|{action}|{','.join(input_names)}")
            add_node(form_id, "form", f"{method} form", pageUrl=page_url, action=action, method=method, inputNames=input_names)
            if page_url:
                page_id = graph_id("url", page_url)
                add_node(page_id, "endpoint", endpoint_label(page_url), url=page_url, host=url_host(page_url), path=urlsplit(page_url).path or "/")
                add_edge(page_id, form_id, "form", method=method, observed=True, metadata={"inputNames": input_names})
            if action:
                action_id = graph_id("url", action)
                action_record = url_records.get(action, {})
                add_node(action_id, "endpoint", endpoint_label(action), url=action, host=url_host(action), path=urlsplit(action).path or "/")
                submitted = bool(action_record.get("fetched")) and method in set(action_record.get("methods", []))
                add_edge(form_id, action_id, "form_action", method=method, observed=submitted, submitted=submitted, metadata={"inputNames": input_names})

    for relation_item in payload.get("relations", []):
        if not isinstance(relation_item, dict):
            continue
        source_url = str(relation_item.get("sourceUrl") or "")
        target_url = str(relation_item.get("targetUrl") or "")
        if not source_url or not target_url:
            continue
        source_id = graph_id("url", source_url)
        target_id = graph_id("url", target_url)
        add_node(source_id, "endpoint", endpoint_label(source_url), url=source_url, host=url_host(source_url), path=urlsplit(source_url).path or "/")
        add_node(
            target_id,
            "related_endpoint",
            endpoint_label(target_url),
            url=target_url,
            host=url_host(target_url),
            path=urlsplit(target_url).path or "/",
            scopeStatus=relation_item.get("scopeStatus", ""),
            followed=bool(relation_item.get("followed")),
        )
        add_edge(
            source_id,
            target_id,
            str(relation_item.get("relationType") or "related_to"),
            method="GET",
            observed=True,
            submitted=bool(relation_item.get("followed")),
            metadata={
                "scopeStatus": relation_item.get("scopeStatus", ""),
                "followed": bool(relation_item.get("followed")),
            },
        )

    method_counts: dict[str, int] = {}
    for edge in edges:
        method = str(edge.get("method") or "")
        if method:
            method_counts[method] = method_counts.get(method, 0) + 1
    return {
        "summary": {
            "nodeCount": len(nodes),
            "edgeCount": len(edges),
            "methodCounts": dict(sorted(method_counts.items())),
            "observedEdgeCount": sum(1 for edge in edges if edge.get("observed")),
            "submittedEdgeCount": sum(1 for edge in edges if edge.get("submitted")),
        },
        "nodes": sorted(nodes.values(), key=lambda item: (item["type"], item["label"], item["id"])),
        "edges": sorted(edges, key=lambda item: (item["source"], item["target"], item["type"], item.get("method", ""))),
    }


def mermaid_label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")[:120]


def render_flow_graph_mermaid(graph: dict[str, Any]) -> str:
    lines = ["flowchart LR"]
    for node in graph.get("nodes", []):
        if not isinstance(node, dict):
            continue
        label = mermaid_label(node.get("label", node.get("id", "")))
        node_type = node.get("type", "")
        if node_type == "host":
            lines.append(f'  {node["id"]}(["{label}"])')
        elif node_type == "form":
            lines.append(f'  {node["id"]}{{"{label}"}}')
        else:
            methods = ",".join(str(item) for item in node.get("methods", [])[:3])
            suffix = f"\\n{methods}" if methods else ""
            lines.append(f'  {node["id"]}["{label}{suffix}"]')
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict):
            continue
        label_parts = [str(edge.get("method", "")), str(edge.get("status", "") or ""), str(edge.get("type", ""))]
        label = mermaid_label(" ".join(part for part in label_parts if part))
        lines.append(f'  {edge["source"]} -- "{label}" --> {edge["target"]}')
    return "\n".join(lines) + "\n"


def svg_text(value: Any, limit: int = 42) -> str:
    text = str(value).replace("\n", " ").strip()
    if len(text) > limit:
        text = f"{text[: limit - 1]}..."
    return html.escape(text, quote=True)


def render_flow_graph_svg(graph: dict[str, Any]) -> str:
    nodes = [item for item in graph.get("nodes", []) if isinstance(item, dict) and item.get("id")]
    edges = [item for item in graph.get("edges", []) if isinstance(item, dict)]
    columns = {"host": 60, "endpoint": 360, "form": 660}
    fallback_x = 960
    node_width = 230
    node_height = 56
    row_gap = 22
    top = 70
    positions: dict[str, tuple[int, int]] = {}
    type_counts: dict[str, int] = {}
    for node in nodes:
        node_type = str(node.get("type", "endpoint"))
        index = type_counts.get(node_type, 0)
        type_counts[node_type] = index + 1
        x = columns.get(node_type, fallback_x)
        y = top + index * (node_height + row_gap)
        positions[str(node["id"])] = (x, y)
    max_rows = max(type_counts.values(), default=1)
    width = 1240
    height = max(220, top + max_rows * (node_height + row_gap) + 60)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="Synapse flow graph">',
        "<defs>",
        '<marker id="arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L9,3 z" fill="#5f6673"/></marker>',
        "<style>",
        ".bg{fill:#ffffff}.title{font:700 18px sans-serif;fill:#1f2937}.meta{font:12px sans-serif;fill:#5f6673}.node{stroke:#3b4252;stroke-width:1.2}.host{fill:#e8f2ff}.endpoint{fill:#ecfdf3}.form{fill:#fff7dd}.unknown{fill:#f4f4f5}.label{font:12px sans-serif;fill:#111827}.sub{font:10px sans-serif;fill:#4b5563}.edge{stroke:#8a93a3;stroke-width:1.1;fill:none;marker-end:url(#arrow)}.edge-label{font:10px sans-serif;fill:#374151}",
        "</style>",
        "</defs>",
        f'<rect class="bg" x="0" y="0" width="{width}" height="{height}"/>',
        '<text class="title" x="32" y="34">Synapse Flow Graph</text>',
        f'<text class="meta" x="32" y="54">{len(nodes)} nodes, {len(edges)} edges</text>',
    ]
    for edge in edges:
        source = positions.get(str(edge.get("source", "")))
        target = positions.get(str(edge.get("target", "")))
        if not source or not target:
            continue
        x1, y1 = source
        x2, y2 = target
        start_x = x1 + node_width
        start_y = y1 + node_height // 2
        end_x = x2
        end_y = y2 + node_height // 2
        mid_x = (start_x + end_x) // 2
        label_parts = [edge.get("method", ""), edge.get("status", "") or "", edge.get("type", "")]
        label = svg_text(" ".join(str(part) for part in label_parts if str(part).strip()), 34)
        lines.append(f'<path class="edge" d="M {start_x} {start_y} C {mid_x} {start_y}, {mid_x} {end_y}, {end_x} {end_y}"/>')
        if label:
            lines.append(f'<text class="edge-label" x="{mid_x - 45}" y="{(start_y + end_y) // 2 - 4}">{label}</text>')
    for node in nodes:
        node_id = str(node["id"])
        x, y = positions[node_id]
        node_type = str(node.get("type", "unknown"))
        class_name = node_type if node_type in {"host", "endpoint", "form"} else "unknown"
        label = svg_text(node.get("label", node_id))
        sub_parts = []
        if node.get("methods"):
            sub_parts.append(",".join(str(item) for item in node.get("methods", [])[:4]))
        if node.get("statusCodes"):
            sub_parts.append(",".join(str(item) for item in node.get("statusCodes", [])[:4]))
        if node.get("inputNames"):
            sub_parts.append(f"inputs: {len(node.get('inputNames', []))}")
        sub = svg_text(" | ".join(sub_parts), 38)
        lines.append(f'<rect class="node {class_name}" x="{x}" y="{y}" width="{node_width}" height="{node_height}" rx="7"/>')
        lines.append(f'<text class="label" x="{x + 12}" y="{y + 23}">{label}</text>')
        if sub:
            lines.append(f'<text class="sub" x="{x + 12}" y="{y + 42}">{sub}</text>')
    lines.append("</svg>")
    return "\n".join(lines) + "\n"


def attach_flow_graph(payload: dict[str, Any]) -> dict[str, Any]:
    payload["flowGraph"] = flow_graph_from_payload(payload)
    return payload


def write_sitemap(
    payload: dict[str, Any],
    output: str | None,
    suffix: str,
    workspace_id: str | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    if output:
        path = Path(output).expanduser()
        prune_outputs = False
    elif workspace_id and target:
        path = workspace.target_output_path(workspace_id, target, "sitemap", suffix)
        prune_outputs = True
    else:
        path = workspace.workspace_output_path(workspace_id or workspace.default_workspace_id(), "sitemap", suffix)
        prune_outputs = True
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload.get("flowGraph"), dict):
        mermaid_path = path.with_name(f"{path.stem}.flow.mmd")
        svg_path = path.with_name(f"{path.stem}.flow.svg")
        payload["flowGraph"]["mermaidPath"] = str(mermaid_path)
        payload["flowGraph"]["svgPath"] = str(svg_path)
        mermaid_path.write_text(render_flow_graph_mermaid(payload["flowGraph"]), encoding="utf-8")
        svg_path.write_text(render_flow_graph_svg(payload["flowGraph"]), encoding="utf-8")
    payload["outputPath"] = str(path)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if prune_outputs:
        workspace.retain_latest_artifacts(path.parent, suffix, keep=1, sibling_suffixes=(".flow.mmd", ".flow.svg"))
    return payload


def scoped_hosts_or_empty() -> set[str]:
    return {host for host in scope.load_scope().get("hosts", []) if host}


def sitemap_from_dump(args: dict[str, Any]) -> str:
    dump_dir, entries = dumps.load_dump_entries(args["dumpPath"])
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    require_external_output_allowed(args, "output", workspace.workspace_path(workspace_id))
    only_in_scope = bool(args.get("onlyInScope", True))
    include_links = bool(args.get("includeLinks", True))
    default_scheme = args.get("defaultScheme", "https")
    scoped_hosts = scoped_hosts_or_empty()
    sitemap = new_sitemap(
        {
            "type": "burp-dump",
            "dumpDir": str(dump_dir),
            "onlyInScope": only_in_scope,
            "scopeHosts": sorted(scoped_hosts),
        }
    )
    warnings: list[str] = []
    if only_in_scope and not scoped_hosts:
        warnings.append("No persisted scope hosts found; included all hosts observed in the dump.")

    for entry in entries:
        request_file = Path(entry.get("requestFile", ""))
        if not request_file.exists():
            warnings.append(f"Missing request file for history item {entry.get('id')}: {request_file}")
            continue
        raw_request = request_file.read_text(encoding="utf-8", errors="replace")
        method, url = request_url_from_raw(raw_request, default_scheme)
        if not url:
            continue
        host = url_host(url)
        if only_in_scope and scoped_hosts and host not in scoped_hosts:
            continue
        raw_response = ""
        if entry.get("responseFile") and Path(entry["responseFile"]).exists():
            raw_response = Path(entry["responseFile"]).read_text(encoding="utf-8", errors="replace")
        status, content_type = response_status_and_type(raw_response)
        metadata = request_metadata(raw_request, url, method, entry)
        if raw_response:
            _merge_url_metadata(metadata, response_metadata(raw_response, url, status, content_type))
        upsert_url(sitemap, url, method=method, status=status, content_type=content_type, fetched=True, metadata=metadata)
        if include_links and raw_response and any(kind in content_type for kind in HTML_TYPES):
            _, _, body = split_http_message(raw_response)
            parser = PageParser()
            try:
                parser.feed(body[:1_000_000])
            except Exception:
                pass
            if parser.title:
                upsert_url(sitemap, url, title=parser.title)
            page_base = document_base_url(url, parser.base_href)
            add_forms(sitemap, url, parser.forms, page_base)
            for link in parser.links:
                linked_url = normalize_url(resolve_discovered_link(link["url"], page_base))
                if not linked_url or not valid_discovered_url(linked_url):
                    continue
                linked_host = url_host(linked_url)
                if only_in_scope and scoped_hosts and linked_host not in scoped_hosts:
                    continue
                upsert_url(sitemap, linked_url, discovered_from=url)

    payload = attach_flow_graph(sanitize_sitemap_payload(flatten_sitemap(sitemap)))
    if warnings:
        payload["warnings"] = warnings
    write_sitemap(payload, args.get("output"), "dump-sitemap.json", args.get("workspaceId"))
    if args.get("workspaceId"):
        ingestions = []
        actions = []
        for host_entry in payload.get("hosts", []):
            host = host_entry.get("host") if isinstance(host_entry, dict) else ""
            if not host:
                continue
            host_payload = {**payload, "hosts": [host_entry], "summary": {"hostCount": 1, "urlCount": host_entry.get("urlCount", 0), "formCount": host_entry.get("formCount", 0)}}
            ingestion = workspace.ingest_data(
                args.get("workspaceId"),
                host,
                "sitemap",
                "tool_output",
                "json",
                json.dumps(host_payload),
                {
                    "dumpPath": str(dump_dir),
                    "outputPath": payload["outputPath"],
                    "onlyInScope": only_in_scope,
                    "includeLinks": include_links,
                },
            )
            ingestions.append(ingestion)
            actions.append(
                workspace.record_action(
                    args.get("workspaceId"),
                    host,
                    {
                        "type": "tool_run",
                        "tool": "sitemap.from_dump",
                        "target": host,
                        "dumpPath": str(dump_dir),
                        "outputPath": payload["outputPath"],
                        "onlyInScope": only_in_scope,
                        "includeLinks": include_links,
                        "evidenceId": ingestion.get("evidenceId", ""),
                    },
                    ingestion.get("evidenceId", ""),
                )
            )
        payload["ingestions"] = ingestions
        payload["actions"] = actions
    return json.dumps(payload, indent=2)


def crawl_error_category(error: str, *, status: Any = None) -> str:
    text = str(error or "").lower()
    if status == 429 or "rate limit" in text or "too many requests" in text:
        return "rate_limited"
    if "redirected out of scope" in text or "blocked redirect" in text:
        return "blocked_redirect"
    if any(marker in text for marker in ("certificate", "handshake", "ssl", "tls")):
        return "tls"
    if any(marker in text for marker in ("timed out", "timeout", "deadline exceeded")):
        return "timeout"
    if any(marker in text for marker in ("name or service", "nodename", "dns", "resolve host", "name resolution")):
        return "dns"
    if any(marker in text for marker in ("connection reset", "reset by peer")):
        return "connection_reset"
    if "disabled" in text:
        return "backend_disabled"
    if any(marker in text for marker in ("connection refused", "connect error", "network is unreachable", "connection failed")):
        return "connection"
    if status is not None:
        return "http_error"
    return "other"


def crawl(args: dict[str, Any]) -> str:
    require_confirmed(args, "Active crawling requires confirm=true.")
    target = normalize_url(args["target"])
    if not target:
        raise McpError(-32602, "target must be an http(s) URL or hostname.")
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target, workspace_id)
    extended_mode = bool(args.get("_extendedMode"))
    tool_name = "crawler.extended" if extended_mode else "crawler.crawl"
    allowed_hosts = {scope_result["host"]}
    rejected_hosts: set[str] = set()
    include_in_scope_hosts = bool(args.get("includeInScopeHosts", True))
    max_pages = min(max(int(args.get("maxPages", 200)), 1), 1000)
    max_depth = min(max(int(args.get("maxDepth", 6)), 0), 10)
    timeout = min(max(int(args.get("requestTimeout", 15)), 1), 60)
    delay = min(max(int(args.get("delayMillis", 0)), 0), 10_000) / 1000
    user_agent = args.get("userAgent", DEFAULT_USER_AGENT)
    include_static = bool(args.get("includeStatic", False))
    analyze_scripts = bool(args.get("analyzeScripts", True))
    follow_get_forms = bool(args.get("followGetForms", True))
    submit_post_forms = bool(args.get("submitPostForms", False))
    max_post_forms = min(max(int(args.get("maxPostForms", 50)), 0), 500)
    include_sensitive_post_forms = bool(args.get("includeSensitivePostForms", False))
    if extended_mode:
        submit_post_forms = True
        if not args.get("credentialId"):
            raise McpError(-32602, "crawler.extended requires credentialId so POST form submissions run in an authorized authenticated context.")
        if not args.get("_previousCrawlVerified"):
            require_previous_crawl(workspace_id, scope_result["host"])
    approval = approval_metadata(args)
    require_external_output_allowed(
        args,
        "output",
        workspace.target_output_dir(workspace_id, scope_result["host"], "sitemap"),
    )
    if background_requested(args):
        return _start_background_crawl(
            args,
            target,
            scope_result,
            workspace_id,
            max_pages,
            max_depth,
            timeout,
            delay,
            include_static,
            include_in_scope_hosts,
            analyze_scripts,
            follow_get_forms,
            submit_post_forms,
            max_post_forms,
            include_sensitive_post_forms,
            approval,
            tool_name,
        )
    request_headers = {"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    credential_meta = None
    if args.get("credentialId"):
        credential = credentials.credential_for_target(str(args["credentialId"]), target)
        request_headers.update(credentials.headers_for_credential_target(credential, target))
        credential_meta = credentials.redact_credential(credential)
    http_policy = crawl_http_policy(args, timeout)
    sitemap = new_sitemap(
        {
            "type": "active-crawl",
            "target": target,
            "scope": scope_result,
            "maxPages": max_pages,
            "maxDepth": max_depth,
            "includeStatic": include_static,
            "includeInScopeHosts": include_in_scope_hosts,
            "analyzeScripts": analyze_scripts,
            "followGetForms": follow_get_forms,
            "submitPostForms": submit_post_forms,
            "maxPostForms": max_post_forms,
            "includeSensitivePostForms": include_sensitive_post_forms,
            "httpBackend": http_policy.backend,
            "approval": approval,
            **({"credential": credential_meta} if credential_meta else {}),
        }
    )
    queue: list[tuple[str, int, str | None]] = [(target, 0, None)]
    visited: set[str] = set()
    attempted_urls: set[str] = set()
    attempted_count = 0
    http_response_count = 0
    successful_fetch_count = 0
    blocked_redirect_count = 0
    errors: list[dict[str, Any]] = []
    post_submissions: list[dict[str, Any]] = []
    post_form_keys: set[tuple[str, str, tuple[str, ...]]] = set()
    discovered_relations: dict[tuple[str, str, str], dict[str, Any]] = {}
    cached_script_urls: dict[str, list[str]] = {}

    def consider_discovered(url: str, source_url: str, relation_type: str, *, followed: bool = False) -> bool:
        allowed = crawl_host_allowed(url, allowed_hosts, rejected_hosts, include_in_scope_hosts, workspace_id)
        record_crawl_relation(
            discovered_relations,
            source_url,
            url,
            relation_type,
            followed=allowed and followed,
            workspace_id=workspace_id,
        )
        return allowed

    crawl_session_context = http_client.session(http_policy)
    crawl_session = crawl_session_context.__enter__()

    while queue and len(attempted_urls) < max_pages:
        url, depth, discovered_from = queue.pop(0)
        if url in attempted_urls:
            continue
        host = url_host(url)
        if discovered_from:
            if not consider_discovered(url, discovered_from, "navigation", followed=True):
                continue
        elif not crawl_host_allowed(url, allowed_hosts, rejected_hosts, include_in_scope_hosts, workspace_id):
            continue
        if is_static_url(url) and not include_static and not (analyze_scripts and is_script_url(url)):
            upsert_url(sitemap, url, discovered_from=discovered_from)
            continue
        attempted_urls.add(url)
        fetch_result = fetch_crawl_url(
            url,
            request_headers,
            http_policy,
            allowed_hosts,
            rejected_hosts,
            include_in_scope_hosts,
            crawl_session,
            workspace_id,
        )
        attempted_count += int(fetch_result.get("attemptedCount", 1) or 0)
        http_response_count += int(fetch_result.get("httpResponseCount", 0) or 0)
        blocked_redirect = str(fetch_result.get("blockedRedirect") or "")
        if blocked_redirect:
            blocked_redirect_count += 1
            record_crawl_relation(
                discovered_relations,
                url,
                blocked_redirect,
                "redirect",
                followed=False,
                workspace_id=workspace_id,
            )
            status = fetch_result.get("status")
            upsert_url(
                sitemap,
                url,
                status=int(status) if isinstance(status, int) else None,
                content_type=str(fetch_result.get("contentType", "")),
                discovered_from=discovered_from,
                fetched=False,
                metadata={"redirectLocations": [blocked_redirect]},
            )
            errors.append(
                {
                    "url": url,
                    "blockedRedirect": blocked_redirect,
                    "status": status,
                    "error": str(fetch_result.get("error") or f"Redirected out of scope: {blocked_redirect}"),
                    "category": "blocked_redirect",
                }
            )
            continue
        if fetch_result.get("status") is None:
            upsert_url(sitemap, url, discovered_from=discovered_from, fetched=False)
            error_text = str(fetch_result.get("error", ""))
            errors.append({"url": url, "error": error_text, "category": crawl_error_category(error_text)})
            continue
        final_url = str(fetch_result["finalUrl"])
        if not crawl_host_allowed(final_url, allowed_hosts, rejected_hosts, include_in_scope_hosts, workspace_id):
            errors.append({"url": url, "error": f"Redirected out of scope: {final_url}", "category": "blocked_redirect"})
            blocked_redirect_count += 1
            continue
        if final_url != url:
            record_crawl_relation(
                discovered_relations,
                url,
                final_url,
                "redirect",
                followed=True,
                workspace_id=workspace_id,
            )
        status = int(fetch_result["status"])
        content_type = str(fetch_result.get("contentType", ""))
        text = str(fetch_result.get("body", ""))
        if fetch_result.get("error"):
            error_text = str(fetch_result["error"])
            errors.append({"url": url, "status": status, "error": error_text, "category": crawl_error_category(error_text, status=status)})
        elif status == 429:
            errors.append({"url": url, "status": status, "error": "HTTP 429 rate limit response.", "category": "rate_limited"})
        else:
            successful_fetch_count += 1
            visited.add(final_url)
        fetch_succeeded = not fetch_result.get("error") and status != 429

        upsert_url(
            sitemap,
            final_url,
            status=status,
            content_type=content_type,
            discovered_from=discovered_from,
            fetched=fetch_succeeded,
            metadata={
                "responseHeaders": fetch_result.get("responseHeaders", {}),
                "responseCookieNames": fetch_result.get("responseCookieNames", []),
                "responseCookieFlags": fetch_result.get("responseCookieFlags", []),
                "technologySignals": html_technology_signals(text),
            },
        )
        if analyze_scripts and is_script_content(final_url, content_type) and not fetch_result.get("error"):
            cached = js_intel.cache_crawler_asset(
                workspace_id,
                final_url,
                text,
                status=status,
                content_type=content_type,
                approval_id=str(approval.get("approvalId") or ""),
                response_metadata={
                    "status": status,
                    "contentType": content_type,
                    "finalUrl": redact_url_query_values(final_url),
                    "responseHeaders": fetch_result.get("responseHeaders", {}),
                },
            )
            if cached:
                cached_script_urls.setdefault(url_host(final_url), []).append(final_url)
        if not fetch_succeeded:
            continue
        if any(kind in content_type for kind in HTML_TYPES):
            parser = PageParser()
            try:
                parser.feed(text)
            except Exception:
                pass
            if parser.title:
                upsert_url(sitemap, final_url, title=parser.title)
            page_base = document_base_url(final_url, parser.base_href)
            add_forms(
                sitemap,
                final_url,
                crawl_forms_for_sitemap(parser.forms, final_url, page_base, consider_discovered),
                page_base,
            )
            if submit_post_forms:
                if not extended_mode:
                    errors.append(
                        {
                            "url": final_url,
                            "warning": "submitPostForms is recorded but POST form submission is only implemented by crawler.extended.",
                        }
                    )
                else:
                    for form in parser.forms:
                        if str(form.get("method", "GET")).upper() != "POST":
                            continue
                        action_url = normalize_url(form.get("action", "") or final_url, final_url)
                        input_names = tuple(
                            sorted(
                                str(item.get("name", ""))
                                for item in form.get("inputs", [])
                                if isinstance(item, dict) and item.get("name")
                            )
                        )
                        form_key = (final_url, action_url, input_names)
                        if form_key in post_form_keys:
                            continue
                        post_form_keys.add(form_key)
                        sensitivity_reason = post_form_sensitivity_reason({**form, "action": action_url})
                        if sensitivity_reason and not include_sensitive_post_forms:
                            errors.append(
                                {
                                    "url": final_url,
                                    "formAction": action_url,
                                    "warning": f"Skipped sensitive POST form by default: {sensitivity_reason}.",
                                }
                            )
                            continue
                        if len(post_submissions) >= max_post_forms:
                            errors.append({"url": final_url, "warning": "Reached maxPostForms limit; remaining POST forms were not submitted."})
                            break
                        if not consider_discovered(action_url, final_url, "form_action"):
                            errors.append({"url": final_url, "formAction": action_url, "warning": "Recorded external form action without submitting it."})
                            continue
                        action_id = f"act_post_{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}_{len(post_submissions) + 1:04d}"
                        post_result = submit_post_form(
                            form,
                            final_url,
                            request_headers,
                            http_policy,
                            allowed_hosts,
                            rejected_hosts,
                            include_in_scope_hosts,
                            crawl_session,
                            workspace_id,
                        )
                        if post_result.get("submitted"):
                            record_crawl_relation(
                                discovered_relations,
                                final_url,
                                action_url,
                                "form_action",
                                followed=True,
                                workspace_id=workspace_id,
                            )
                        action_host = url_host(str(post_result.get("actionUrl") or action_url))
                        submission = {
                            "actionId": action_id,
                            "pageUrl": final_url,
                            "actionUrl": post_result.get("actionUrl") or action_url,
                            "method": "POST",
                            "status": post_result.get("status"),
                            "contentType": post_result.get("contentType", ""),
                            "parameterNames": post_result.get("parameterNames", list(input_names)),
                            "submittedValues": post_result.get("submittedValues", {}),
                            "responseHeaders": post_result.get("responseHeaders", {}),
                            "responseCookieNames": post_result.get("responseCookieNames", []),
                            "redirectLocation": post_result.get("redirectLocation", ""),
                            "sensitiveForm": bool(sensitivity_reason),
                            "sensitivityReason": sensitivity_reason,
                            "error": post_result.get("error", ""),
                        }
                        post_submissions.append(submission)
                        evidence.log_event(
                            "crawler.extended.post",
                            f"Submitted POST form during extended crawl on {action_host}.",
                            {
                                "workspaceId": workspace_id,
                                "target": target,
                                "host": action_host,
                                "pageUrl": final_url,
                                "actionUrl": submission["actionUrl"],
                                "method": "POST",
                                "status": submission["status"],
                                "parameterNames": submission["parameterNames"],
                                "submittedValues": submission["submittedValues"],
                                "sensitiveForm": submission["sensitiveForm"],
                                "approval": approval,
                            },
                        )
                        workspace.record_action(
                            workspace_id,
                            action_host,
                            {
                                "type": "http_request",
                                "actionId": action_id,
                                "tool": "crawler.extended",
                                "target": target,
                                "pageUrl": final_url,
                                "requestUrl": submission["actionUrl"],
                                "method": "POST",
                                "status": submission["status"],
                                "contentType": submission["contentType"],
                                "parameterNames": submission["parameterNames"],
                                "submittedValues": submission["submittedValues"],
                                "responseHeaders": submission["responseHeaders"],
                                "responseCookieNames": submission["responseCookieNames"],
                                "redirectLocation": submission["redirectLocation"],
                                "sensitiveForm": submission["sensitiveForm"],
                                "sensitivityReason": submission["sensitivityReason"],
                                "credential": credential_meta,
                                "approval": approval,
                            },
                        )
                        if not post_result.get("submitted"):
                            errors.append({"url": final_url, "formAction": action_url, "error": post_result.get("error", "")})
                            continue
                        if post_result.get("status") is None:
                            errors.append({"url": action_url, "error": post_result.get("error", "")})
                            upsert_url(sitemap, action_url, method="POST", discovered_from=final_url, fetched=False)
                            continue
                        post_status = int(post_result["status"])
                        post_content_type = str(post_result.get("contentType", ""))
                        metadata = response_result_metadata(post_result, str(submission["actionUrl"]), post_status, post_content_type)
                        metadata.update(
                            {
                                "bodyParameters": list(submission["parameterNames"]),
                                "requestContentTypes": ["application/x-www-form-urlencoded"],
                                "stateChanging": True,
                                "hasAuthorization": bool(credential_meta),
                                "observedRequests": [
                                    {
                                        "method": "POST",
                                        "source": "crawler.extended",
                                        "pageUrl": final_url,
                                        "actionId": action_id,
                                    }
                                ],
                            }
                        )
                        upsert_url(
                            sitemap,
                            str(submission["actionUrl"]),
                            method="POST",
                            status=post_status,
                            content_type=post_content_type,
                            discovered_from=final_url,
                            fetched=True,
                            metadata=metadata,
                        )
                        redirect_url = str(submission.get("redirectLocation") or "")
                        if redirect_url and consider_discovered(redirect_url, str(submission["actionUrl"]), "redirect"):
                            upsert_url(sitemap, redirect_url, discovered_from=str(submission["actionUrl"]))
                            if depth < max_depth and redirect_url not in attempted_urls and all(item[0] != redirect_url for item in queue):
                                queue.append((redirect_url, depth + 1, str(submission["actionUrl"])))
                        if any(kind in post_content_type for kind in HTML_TYPES):
                            post_parser = PageParser()
                            try:
                                post_parser.feed(str(post_result.get("body", "")))
                            except Exception:
                                pass
                            post_base = document_base_url(str(submission["actionUrl"]), post_parser.base_href)
                            if post_parser.title:
                                upsert_url(sitemap, str(submission["actionUrl"]), title=post_parser.title)
                            add_forms(
                                sitemap,
                                str(submission["actionUrl"]),
                                crawl_forms_for_sitemap(
                                    post_parser.forms,
                                    str(submission["actionUrl"]),
                                    post_base,
                                    consider_discovered,
                                ),
                                post_base,
                            )
                            if depth < max_depth:
                                for link in post_parser.links:
                                    linked_url = normalize_url(resolve_discovered_link(link["url"], post_base))
                                    if not linked_url or not valid_discovered_url(linked_url):
                                        continue
                                    if not consider_discovered(linked_url, str(submission["actionUrl"]), "navigation"):
                                        continue
                                    upsert_url(sitemap, linked_url, discovered_from=str(submission["actionUrl"]))
                                    if linked_url not in attempted_urls and all(item[0] != linked_url for item in queue):
                                        queue.append((linked_url, depth + 1, str(submission["actionUrl"])))
            if depth < max_depth:
                for link in parser.links:
                    linked_url = normalize_url(resolve_discovered_link(link["url"], page_base))
                    if not linked_url or not valid_discovered_url(linked_url):
                        continue
                    if not consider_discovered(linked_url, final_url, "navigation"):
                        continue
                    upsert_url(sitemap, linked_url, discovered_from=final_url)
                    if linked_url not in attempted_urls and all(item[0] != linked_url for item in queue):
                        queue.append((linked_url, depth + 1, final_url))
                if follow_get_forms:
                    for form in parser.forms:
                        submission_url = form_submission_url(form, final_url, page_base)
                        if not submission_url:
                            continue
                        if not consider_discovered(submission_url, final_url, "get_form_submission"):
                            continue
                        upsert_url(sitemap, submission_url, method="GET", discovered_from=final_url)
                        if submission_url not in attempted_urls and all(item[0] != submission_url for item in queue):
                            queue.append((submission_url, depth + 1, final_url))
        if depth < max_depth and analyze_scripts and is_script_content(final_url, content_type):
            for linked_url in extract_literal_links(text, final_url):
                if not valid_discovered_url(linked_url):
                    continue
                if not consider_discovered(linked_url, final_url, "javascript_reference"):
                    continue
                upsert_url(sitemap, linked_url, discovered_from=final_url)
                if linked_url not in attempted_urls and all(item[0] != linked_url for item in queue):
                    queue.append((linked_url, depth + 1, final_url))
        if delay:
            time.sleep(delay)
    crawl_session_context.__exit__(None, None, None)

    flattened = flatten_sitemap(sitemap)
    flattened["relations"] = sorted(
        discovered_relations.values(),
        key=lambda item: (item["sourceHost"], item["relationType"], item["targetHost"], item["targetUrl"]),
    )
    for error in errors:
        if isinstance(error, dict) and not error.get("category"):
            error["category"] = crawl_error_category(str(error.get("error", "")), status=error.get("status"))
    categorized_error_counts: dict[str, int] = {}
    for error in errors:
        category = str(error.get("category") or "other") if isinstance(error, dict) else "other"
        categorized_error_counts[category] = categorized_error_counts.get(category, 0) + 1
    disposition = "complete"
    if successful_fetch_count == 0:
        disposition = "no_coverage"
    elif errors or queue:
        disposition = "partial"
    flattened["crawl"] = {
        "visitedCount": len(visited),
        "attemptedCount": attempted_count,
        "successfulFetchCount": successful_fetch_count,
        "httpResponseCount": http_response_count,
        "errorCount": len(errors),
        "blockedRedirectCount": blocked_redirect_count,
        "categorizedErrorCounts": categorized_error_counts,
        "disposition": disposition,
        "queuedRemaining": len(queue),
        "errors": errors,
        "relationCount": len(flattened["relations"]),
        "externalRelationCount": sum(1 for item in flattened["relations"] if item.get("scopeStatus") != "in_scope"),
        "includeInScopeHosts": include_in_scope_hosts,
        "analyzeScripts": analyze_scripts,
        "followGetForms": follow_get_forms,
        "submitPostForms": submit_post_forms,
        "extended": extended_mode,
        "maxPostForms": max_post_forms,
        "postSubmissionCount": len(post_submissions),
        "postSubmissions": post_submissions,
        "includeSensitivePostForms": include_sensitive_post_forms,
    }
    flattened["resultSummary"] = {
        "disposition": disposition,
        "attemptedCount": attempted_count,
        "successfulFetchCount": successful_fetch_count,
        "httpResponseCount": http_response_count,
        "visitedCount": len(visited),
        "errorCount": len(errors),
        "blockedRedirectCount": blocked_redirect_count,
        "categorizedErrorCounts": categorized_error_counts,
        "queuedRemaining": len(queue),
    }
    payload = attach_flow_graph(sanitize_sitemap_payload(flattened))
    write_sitemap(payload, args.get("output"), f"{scope_result['host']}-{tool_name.replace('.', '-')}-sitemap.json", workspace_id, scope_result["host"])
    evidence.log_event(
        tool_name,
        f"Crawled {len(visited)} pages for sitemap generation on {scope_result['host']}.",
        {
            "target": target,
            "host": scope_result["host"],
            "visitedCount": len(visited),
            "outputPath": payload["outputPath"],
            "includeInScopeHosts": include_in_scope_hosts,
            "analyzeScripts": analyze_scripts,
            "followGetForms": follow_get_forms,
            "submitPostForms": submit_post_forms,
            "postSubmissionCount": len(post_submissions),
            "relationCount": len(payload.get("relations", [])),
            "externalRelationCount": payload["crawl"].get("externalRelationCount", 0),
            "approval": approval,
        },
    )
    ingestions = []
    actions = []
    for host_entry in payload.get("hosts", []):
        host = host_entry.get("host") if isinstance(host_entry, dict) else ""
        if not host:
            continue
        host_payload = {
            **payload,
            "hosts": [host_entry],
            "relations": [
                item
                for item in payload.get("relations", [])
                if isinstance(item, dict) and host in {item.get("sourceHost"), item.get("targetHost")}
            ],
            "summary": {"hostCount": 1, "urlCount": host_entry.get("urlCount", 0), "formCount": host_entry.get("formCount", 0)},
        }
        host_visited = sum(1 for item in host_entry.get("urls", []) if isinstance(item, dict) and item.get("fetched"))
        ingestion = workspace.ingest_data(
            workspace_id,
            host,
            "crawler",
            "tool_output",
            "json",
            json.dumps(host_payload),
            {
                "target": target,
                "host": host,
                "seedHost": scope_result["host"],
                "visitedCount": host_visited,
                "outputPath": payload["outputPath"],
                "includeInScopeHosts": include_in_scope_hosts,
                "analyzeScripts": analyze_scripts,
                "followGetForms": follow_get_forms,
                "submitPostForms": submit_post_forms,
                "extended": extended_mode,
                "postSubmissionCount": len(post_submissions),
                "relationCount": len(host_payload["relations"]),
                "approval": approval,
            },
        )
        ingestions.append(ingestion)
        js_intel.link_crawler_cache_evidence(
            workspace_id,
            host,
            cached_script_urls.get(host, []),
            str(ingestion.get("evidenceId", "")),
        )
        actions.append(
            workspace.record_action(
                workspace_id,
                host,
                {
                    "type": "tool_run",
                    "tool": tool_name,
                    "target": target,
                    "seedHost": scope_result["host"],
                    "outputPath": payload["outputPath"],
                    "visitedCount": host_visited,
                    "queuedRemaining": len(queue),
                    "errorCount": len(errors),
                    "includeInScopeHosts": include_in_scope_hosts,
                    "analyzeScripts": analyze_scripts,
                    "followGetForms": follow_get_forms,
                    "submitPostForms": submit_post_forms,
                    "extended": extended_mode,
                    "postSubmissionCount": len(post_submissions),
                    "approval": approval,
                    "evidenceId": ingestion.get("evidenceId", ""),
                },
                ingestion.get("evidenceId", ""),
            )
        )
    payload["ingestions"] = ingestions
    payload["actions"] = actions
    if not args.get("_deferWorkflowRefreshToFinalizer"):
        payload["workflowRefresh"] = [
            fingerprint.refresh_workspace_target(workspace_id, str(ingestion.get("target", "")))
            for ingestion in ingestions
            if ingestion.get("target")
        ]
    payload["ingestion"] = next((item for item in ingestions if item.get("target") == scope_result["host"]), ingestions[0] if ingestions else {})
    payload["action"] = next((item for item in actions if item.get("action", {}).get("target") == target), actions[0] if actions else {})
    return json.dumps(payload, indent=2)


def _start_background_crawl(
    args: dict[str, Any],
    target: str,
    scope_result: dict[str, Any],
    workspace_id: str,
    max_pages: int,
    max_depth: int,
    timeout: int,
    delay: float,
    include_static: bool,
    include_in_scope_hosts: bool,
    analyze_scripts: bool,
    follow_get_forms: bool,
    submit_post_forms: bool,
    max_post_forms: int,
    include_sensitive_post_forms: bool,
    approval: dict[str, Any],
    tool_name: str = "crawler.crawl",
) -> str:
    public_target = redact_url_query_values(target) or target
    public_scope = {**scope_result, "target": public_target}
    worker_args = dict(args)
    worker_args["background"] = False
    worker_args["_deferWorkflowRefreshToFinalizer"] = True
    job_slug = tool_name.replace(".", "-")
    args_path = workspace.target_output_path(workspace_id, scope_result["host"], "jobs", f"{job_slug}-args.json")
    result_path = workspace.target_output_path(workspace_id, scope_result["host"], "jobs", f"{job_slug}-result.json")
    state_path = workspace.target_output_path(workspace_id, scope_result["host"], "jobs", f"{job_slug}-state.json")
    args_path.write_text(json.dumps(worker_args, indent=2, ensure_ascii=False), encoding="utf-8")
    _chmod_private(args_path)
    state_path.write_text(
        json.dumps(
            {
                "workspacesDir": str(workspace.WORKSPACES_DIR),
                "dumpDir": str(dumps.DUMP_DIR),
                "scopeFile": str(scope.SCOPE_FILE),
                "credentialsFile": str(credentials.CREDENTIALS_FILE),
                "evidenceDir": str(evidence.EVIDENCE_DIR),
                "evidenceLog": str(evidence.EVIDENCE_LOG),
                "orgsDir": str(evidence.ORGS_DIR),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    _chmod_private(state_path)
    timeout_seconds = int(args.get("timeoutSeconds") or max(300, int(max_pages * (timeout + delay) + 60)))
    cmd = [
        synapse_python(),
        "-m",
        "synapse_mcp.core.job_worker",
        "--tool",
        tool_name,
        "--args",
        str(args_path),
        "--result",
        str(result_path),
        "--state",
        str(state_path),
    ]
    event_data = {
        "workspaceId": workspace_id,
        "target": public_target,
        "host": scope_result["host"],
        "maxPages": max_pages,
        "maxDepth": max_depth,
        "requestTimeout": timeout,
        "includeStatic": include_static,
        "includeInScopeHosts": include_in_scope_hosts,
        "analyzeScripts": analyze_scripts,
        "followGetForms": follow_get_forms,
        "submitPostForms": submit_post_forms,
        "maxPostForms": max_post_forms,
        "includeSensitivePostForms": include_sensitive_post_forms,
        "approval": approval,
    }
    job = start_background_command(
        cmd,
        timeout_seconds=timeout_seconds,
        event_type=tool_name,
        summary=f"Ran {tool_name} against {scope_result['host']} in a background worker",
        display_cmd=cmd,
        event_data=event_data,
        tool=tool_name,
        workspace_id=workspace_id,
        target=public_target,
        output_path=str(result_path),
        finalizer_name="worker.result",
        finalizer_data={"resultPath": str(result_path)},
    )
    return json.dumps(
        {
            "target": public_target,
            "workspaceId": workspace_id,
            "scope": public_scope,
            "background": True,
            "job": job,
            "status": "started",
            "workerArgsPath": str(args_path),
            "workerStatePath": str(state_path),
            "resultPath": str(result_path),
            "timeoutSeconds": timeout_seconds,
            "crawlPolicy": {
                "maxPages": max_pages,
                "maxDepth": max_depth,
                "requestTimeout": timeout,
                "includeStatic": include_static,
                "includeInScopeHosts": include_in_scope_hosts,
                "analyzeScripts": analyze_scripts,
                "followGetForms": follow_get_forms,
                "submitPostForms": submit_post_forms,
                "maxPostForms": max_post_forms,
                "includeSensitivePostForms": include_sensitive_post_forms,
            },
            "message": f"{tool_name} is running in the background. Poll with jobs.status(jobId={job['jobId']!r}).",
        },
        indent=2,
    )


def crawl_extended(args: dict[str, Any]) -> str:
    require_confirmed(args, "Extended crawling with POST form submission requires confirm=true.")
    target = normalize_url(args["target"])
    if not target:
        raise McpError(-32602, "target must be an http(s) URL or hostname.")
    workspace_id = args.get("workspaceId") or workspace.default_workspace_id()
    scope_result = require_in_scope(target, workspace_id)
    if not args.get("credentialId"):
        raise McpError(-32602, "crawler.extended requires credentialId so POST form submissions run in an authorized authenticated context.")
    credentials.credential_for_target(str(args["credentialId"]), target)
    if not args.get("_previousCrawlVerified"):
        require_previous_crawl(workspace_id, scope_result["host"])
    extended_args = dict(args)
    extended_args["_extendedMode"] = True
    extended_args["_previousCrawlVerified"] = True
    extended_args["submitPostForms"] = True
    return crawl(extended_args)
