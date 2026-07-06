# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from .models import JsEndpointCandidate, JsParameterCandidate, JsSignal


JS_ASSET_EXTENSIONS = (".js", ".mjs")
JS_CONTENT_TYPES = ("javascript", "ecmascript")
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
MAX_SCAN_BYTES = 1_500_000
MAX_LITERAL_CHARS = 700
MAX_QUOTED_SCAN_CHARS = 2_000
MAX_CALL_TAIL_CHARS = 500
MAX_OBJECT_BODY_CHARS = 1_200
QUOTE_CHARS = {"'", '"', "`"}

FETCH_CALL_RE = re.compile(r"""\bfetch\s*\(""")
AXIOS_METHOD_CALL_RE = re.compile(r"""\baxios\.(?P<method>get|post|put|patch|delete|head|options)\s*\(""", re.IGNORECASE)
AXIOS_OBJECT_CALL_RE = re.compile(r"""\baxios\s*\(\s*\{""")
AJAX_OBJECT_CALL_RE = re.compile(r"""(?:\$\s*\.\s*ajax|\bajax)\s*\(\s*\{""")
XHR_OPEN_CALL_RE = re.compile(r"""\bopen\s*\(""")
OBJECT_FIELD_PREFIX_RE = re.compile(r"""\b(?P<key>url|baseURL|method|type)\b\s*:\s*""", re.IGNORECASE)
BASE_ASSIGN_PREFIX_RE = re.compile(r"""\b(?P<name>[A-Za-z_$][\w$]*(?:Base|BASE|Url|URL|Endpoint|ENDPOINT)[\w$]*)\s*[:=]\s*""")
GRAPHQL_RE = re.compile(r"""\b(?P<kind>query|mutation|subscription)\s+(?P<name>[A-Za-z_][\w]*)?""")
STORAGE_CALL_RE = re.compile(r"""\b(?P<store>localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\s*\(""")
HEADER_RE = re.compile(r"""(?P<quote>["']?)(?P<name>authorization|x-csrf-token|x-xsrf-token|csrf-token|xsrf-token|x-api-key|api-key)(?P=quote)\s*:""", re.IGNORECASE)
CSRF_RE = re.compile(r"""\b(?P<name>[A-Za-z_$][\w$]*(?:csrf|xsrf)[\w$]*|(?:csrf|xsrf)[-_]token|x[-_]csrf[-_]token|x[-_]xsrf[-_]token)\b""", re.IGNORECASE)
OBJECT_ID_RE = re.compile(
    r"""\b(?P<name>(?:user|account|org|organization|tenant|customer|project|team|role|group|order|invoice|file|document|resource|object|profile)(?:Id|ID|Uuid|UUID|Slug)|(?:user|account|org|organization|tenant|customer|project|team|role|group|order|invoice|file|document|resource|object|profile)_(?:id|uuid|slug))\b"""
)


LIBRARY_BANNER_SCAN_BYTES = 200_000
_VER = r"(\d+\.\d+(?:\.\d+){0,2})"


class LibrarySignature:
    """A curated client-side library: how to recognize it (in the asset filename and in a
    source banner/license comment) and its NVD CPE vendor:product for accurate CVE matching."""

    __slots__ = ("name", "vendor", "product", "filename", "banner")

    def __init__(self, name: str, vendor: str, product: str, filename: str, banner: str) -> None:
        self.name = name
        self.vendor = vendor
        self.product = product
        self.filename = re.compile(filename, re.IGNORECASE)
        self.banner = re.compile(banner, re.IGNORECASE)


def _filename_pattern(aliases: list[str]) -> str:
    alt = "|".join(aliases)
    # <alias>[-.@ ]<version>? optionally followed by min/slim/prod markers, then a .js/.mjs suffix.
    return rf"(?:^|[/._@-])(?:{alt})(?:[.@_-]v?{_VER})?(?:[._-](?:min|slim|bundle|prod|production|dev|development|common|umd|esm|cjs))*\.(?:js|mjs)"


# Ordered curated registry. Kept intentionally small and high-confidence: each entry maps to a
# real NVD CPE product with web-exploitable CVE history (XSS, prototype pollution, ReDoS, etc.).
JS_LIBRARY_SIGNATURES: list[LibrarySignature] = [
    LibrarySignature("jQuery UI", "jquery", "jquery_ui", _filename_pattern(["jquery-ui", "jquery.ui"]), rf"jquery\s+ui[\s-]+v?{_VER}"),
    LibrarySignature("jQuery", "jquery", "jquery", _filename_pattern(["jquery"]), rf"jquery(?:\s+javascript\s+library)?\s+v?{_VER}"),
    LibrarySignature("Bootstrap", "getbootstrap", "bootstrap", _filename_pattern(["bootstrap"]), rf"bootstrap(?:'s\s+javascript)?\s+v{_VER}"),
    LibrarySignature("AngularJS", "angularjs", "angular.js", _filename_pattern(["angular", "angular.min"]), rf"angular(?:js)?\s+v(1\.\d+(?:\.\d+){{0,2}})"),
    LibrarySignature("React", "facebook", "react", _filename_pattern(["react", "react-dom"]), rf"react(?:-dom)?\s+v{_VER}"),
    LibrarySignature("Vue.js", "vuejs", "vue", _filename_pattern(["vue"]), rf"vue(?:\.js)?\s+v{_VER}"),
    LibrarySignature("Lodash", "lodash", "lodash", _filename_pattern(["lodash"]), r"@license[\s\S]{0,80}?lodash"),
    LibrarySignature("Moment.js", "momentjs", "moment", _filename_pattern(["moment"]), rf"//!\s*version\s*:\s*{_VER}"),
    LibrarySignature("Handlebars", "handlebarsjs", "handlebars", _filename_pattern(["handlebars"]), rf"handlebars(?:\.js)?\s+v?{_VER}"),
    LibrarySignature("DOMPurify", "cure53", "dompurify", _filename_pattern(["dompurify", "purify"]), rf"dompurify\s+{_VER}"),
    LibrarySignature("Axios", "axios", "axios", _filename_pattern(["axios"]), rf"axios[\s/v]+{_VER}"),
    LibrarySignature("CKEditor", "ckeditor", "ckeditor", _filename_pattern(["ckeditor"]), rf"ckeditor\s+{_VER}"),
    LibrarySignature("TinyMCE", "tiny", "tinymce", _filename_pattern(["tinymce", "tiny_mce"]), rf"tinymce(?:.*?)(?:version|v)[:\s]+{_VER}"),
]


def _library_cpe(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version or '*'}:*:*:*:*:*:*:*"


def detect_libraries(text: str, source_asset: str) -> list[dict[str, Any]]:
    filename = urlsplit(str(source_asset)).path.lower()
    region = text[:LIBRARY_BANNER_SCAN_BYTES]
    results: list[dict[str, Any]] = []
    for sig in JS_LIBRARY_SIGNATURES:
        banner_match = sig.banner.search(region)
        filename_match = sig.filename.search(filename)
        if not banner_match and not filename_match:
            continue
        version = ""
        if banner_match and banner_match.groups() and banner_match.group(1):
            version = banner_match.group(1)
        if not version and filename_match:
            version = filename_match.group(1) or ""
        version = str(version or "")
        precision = "exact" if version else "unknown"
        if version:
            confidence, how = "high", "version banner/filename"
        elif banner_match:
            confidence, how = "medium", "source banner"
        else:
            confidence, how = "low", "asset filename"
        results.append(
            {
                "name": sig.name,
                "version": version,
                "versionPrecision": precision,
                "cpe": _library_cpe(sig.vendor, sig.product, version),
                "sourceAsset": source_asset,
                "confidence": confidence,
                "reason": f"Client-side library {sig.name}{(' ' + version) if version else ''} identified via {how}.",
            }
        )
    return results


def is_js_asset_url(url: str) -> bool:
    return urlsplit(str(url)).path.lower().endswith(JS_ASSET_EXTENSIONS)


def is_js_content_type(content_type: str) -> bool:
    lowered = str(content_type or "").lower()
    return any(marker in lowered for marker in JS_CONTENT_TYPES)


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


def clean_js_literal(value: str) -> str:
    value = value.strip()
    value = re.sub(r"""\$\{[^}]{1,120}\}""", "{value}", value)
    return value.replace("\\/", "/").replace("\\u002f", "/")


def looks_like_endpoint(value: str) -> bool:
    value = clean_js_literal(value)
    lowered = value.lower()
    if not value or len(value) > 700:
        return False
    if any(char in value for char in ("\n", "\r", "\t", "`", "{", "}")):
        return False
    if any(marker in lowered for marker in ("})();", "=>", "function ", "return ", "var ", "let ", "const ", "class ")):
        return False
    if lowered.count("/") > 40:
        return False
    if lowered.startswith(("http://", "https://", "//", "/")):
        return any(marker in lowered for marker in ("/api", "/graphql", "/rest", ".json", "/v1", "/v2", "/auth", "/users", "/admin")) or "?" in value
    if lowered.startswith(("api/", "graphql", "rest/", "v1/", "v2/")):
        return True
    return bool(re.search(r"""(?:^|/)(api|graphql|rest|v[0-9]|auth|oauth|users?|accounts?|tenants?|admin)(?:/|$|\?)""", lowered))


def extract_method(text: str, default: str = "GET") -> str:
    match = re.search(r"""(?:method|type)\s*:\s*["'`](?P<method>[A-Za-z]+)["'`]""", text, re.IGNORECASE)
    if not match:
        return default
    method = match.group("method").upper()
    return method if method in HTTP_METHODS else default


def confidence_for(raw: str, direct_call: bool) -> str:
    if direct_call and "{value}" not in raw:
        return "high"
    if raw.startswith(("http://", "https://", "/", "api/", "v1/", "v2/")):
        return "medium"
    return "low"


def dedupe(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    result = []
    for item in items:
        marker = tuple(item.get(key) for key in keys)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


def skip_ws(text: str, offset: int, limit: int | None = None) -> int:
    upper = min(len(text), limit if limit is not None else len(text))
    while offset < upper and text[offset].isspace():
        offset += 1
    return offset


def read_js_string(
    text: str,
    quote_offset: int,
    *,
    max_value_chars: int = MAX_LITERAL_CHARS,
    max_scan_chars: int = MAX_QUOTED_SCAN_CHARS,
) -> dict[str, Any] | None:
    if quote_offset >= len(text) or text[quote_offset] not in QUOTE_CHARS:
        return None
    quote = text[quote_offset]
    limit = min(len(text), quote_offset + max_scan_chars)
    value: list[str] = []
    truncated = False
    offset = quote_offset + 1
    while offset < limit:
        char = text[offset]
        if char == "\\":
            if offset + 1 >= limit:
                return None
            piece = text[offset : offset + 2]
            if len(value) + len(piece) <= max_value_chars:
                value.append(piece)
            else:
                truncated = True
            offset += 2
            continue
        if char == quote:
            return {
                "quote": quote,
                "value": "".join(value),
                "start": quote_offset,
                "end": offset + 1,
                "truncated": truncated,
            }
        if len(value) < max_value_chars:
            value.append(char)
        else:
            truncated = True
        offset += 1
    return None


def iter_js_string_literals(text: str) -> list[dict[str, Any]]:
    literals: list[dict[str, Any]] = []
    offset = 0
    while offset < len(text):
        char = text[offset]
        if char not in QUOTE_CHARS:
            offset += 1
            continue
        literal = read_js_string(text, offset)
        if literal:
            literals.append(literal)
            offset = int(literal["end"])
        else:
            # Bounded recovery for malformed/minified regions. Advancing by the
            # scan window keeps runtime linear on quote/backslash-heavy input,
            # while token-specific scanners can still find later valid calls.
            offset = min(len(text), offset + MAX_QUOTED_SCAN_CHARS)
    return literals


def read_next_string(text: str, offset: int, *, max_distance: int = 200) -> dict[str, Any] | None:
    limit = min(len(text), offset + max_distance)
    cursor = offset
    while cursor < limit:
        if text[cursor] in QUOTE_CHARS:
            literal = read_js_string(text, cursor)
            if literal:
                return literal
        cursor += 1
    return None


def tail_until_call_end(text: str, offset: int) -> str:
    limit = min(len(text), offset + MAX_CALL_TAIL_CHARS)
    closing = text.find(")", offset, limit)
    end = closing if closing != -1 else limit
    return text[offset:end]


def split_args_after_call_open(text: str, offset: int, max_args: int = 2) -> list[dict[str, Any]]:
    args: list[dict[str, Any]] = []
    cursor = offset
    limit = min(len(text), offset + MAX_CALL_TAIL_CHARS)
    while cursor < limit and len(args) < max_args:
        cursor = skip_ws(text, cursor, limit)
        if cursor >= limit or text[cursor] == ")":
            break
        if text[cursor] in QUOTE_CHARS:
            literal = read_js_string(text, cursor)
            if not literal:
                break
            args.append(literal)
            cursor = int(literal["end"])
        else:
            while cursor < limit and text[cursor] not in {",", ")"}:
                cursor += 1
        cursor = skip_ws(text, cursor, limit)
        if cursor < limit and text[cursor] == ",":
            cursor += 1
            continue
        break
    return args


def bounded_object_body(text: str, open_brace_offset: int) -> str:
    limit = min(len(text), open_brace_offset + MAX_OBJECT_BODY_CHARS)
    cursor = open_brace_offset + 1
    while cursor < limit:
        if text[cursor] in QUOTE_CHARS:
            literal = read_js_string(text, cursor, max_scan_chars=MAX_OBJECT_BODY_CHARS)
            cursor = int(literal["end"]) if literal else cursor + 1
            continue
        if text[cursor] == "}":
            return text[open_brace_offset + 1 : cursor]
        cursor += 1
    return text[open_brace_offset + 1 : limit]


def object_fields(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in OBJECT_FIELD_PREFIX_RE.finditer(body):
        literal = read_next_string(body, match.end(), max_distance=40)
        if literal:
            fields[match.group("key").lower()] = clean_js_literal(str(literal["value"]))
    return fields


def endpoint_candidate(raw: str, method: str, source_asset: str, offset: int, text: str, confidence: str, reason: str) -> dict[str, Any]:
    return JsEndpointCandidate(
        raw=clean_js_literal(raw),
        method=method.upper() if method.upper() in HTTP_METHODS else "GET",
        source_asset=source_asset,
        offset=offset,
        line=line_for_offset(text, offset),
        confidence=confidence,  # type: ignore[arg-type]
        reason=reason,
    ).as_dict()


def signal(signal_type: str, value: str, source_asset: str, confidence: str, reason: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    return JsSignal(
        type=signal_type,
        value=value,
        source_asset=source_asset,
        confidence=confidence,  # type: ignore[arg-type]
        reason=reason,
        metadata=metadata or {},
    ).as_dict()


def extract_from_source(text: str, source_asset: str, max_bytes: int = MAX_SCAN_BYTES) -> dict[str, list[dict[str, Any]]]:
    snippet = text[:max_bytes]
    endpoints: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []
    signals: list[dict[str, Any]] = []
    string_literals = iter_js_string_literals(snippet)

    for match in FETCH_CALL_RE.finditer(snippet):
        literal = read_next_string(snippet, match.end(), max_distance=80)
        if not literal:
            continue
        raw = clean_js_literal(str(literal["value"]))
        if looks_like_endpoint(raw):
            method = extract_method(tail_until_call_end(snippet, int(literal["end"])), "GET")
            endpoints.append(endpoint_candidate(raw, method, source_asset, match.start(), snippet, confidence_for(raw, True), "Literal URL in fetch() call."))

    for match in AXIOS_METHOD_CALL_RE.finditer(snippet):
        literal = read_next_string(snippet, match.end(), max_distance=80)
        if not literal:
            continue
        raw = clean_js_literal(str(literal["value"]))
        if looks_like_endpoint(raw):
            method = match.group("method").upper()
            endpoints.append(endpoint_candidate(raw, method, source_asset, match.start(), snippet, confidence_for(raw, True), "Literal URL in axios method call."))

    for regex, reason in ((AXIOS_OBJECT_CALL_RE, "Literal URL in axios object call."), (AJAX_OBJECT_CALL_RE, "Literal URL in AJAX object call.")):
        for match in regex.finditer(snippet):
            fields = object_fields(bounded_object_body(snippet, match.end() - 1))
            raw = fields.get("url", "")
            if looks_like_endpoint(raw):
                method = fields.get("method") or fields.get("type") or "GET"
                endpoints.append(endpoint_candidate(raw, method, source_asset, match.start(), snippet, confidence_for(raw, True), reason))

    for match in XHR_OPEN_CALL_RE.finditer(snippet):
        args = split_args_after_call_open(snippet, match.end(), max_args=2)
        if len(args) < 2:
            continue
        raw = clean_js_literal(str(args[1]["value"]))
        if looks_like_endpoint(raw):
            endpoints.append(endpoint_candidate(raw, str(args[0]["value"]), source_asset, match.start(), snippet, confidence_for(raw, True), "Literal URL in XMLHttpRequest.open() call."))

    for literal in string_literals:
        raw = clean_js_literal(str(literal["value"]))
        if looks_like_endpoint(raw):
            endpoints.append(endpoint_candidate(raw, "GET", source_asset, int(literal["start"]), snippet, confidence_for(raw, False), "API-like string literal in JavaScript."))

    for match in BASE_ASSIGN_PREFIX_RE.finditer(snippet):
        literal = read_next_string(snippet, match.end(), max_distance=40)
        if not literal:
            continue
        value = clean_js_literal(str(literal["value"]))
        if value and (value.startswith(("http://", "https://", "/", "api/")) or "api" in value.lower()):
            signals.append(signal("api_base_url", value, source_asset, "medium", "API/base URL constant found.", {"name": match.group("name")}))

    for match in GRAPHQL_RE.finditer(snippet):
        kind = match.group("kind")
        name = match.group("name") or ""
        signals.append(signal("graphql_operation", f"{kind} {name}".strip(), source_asset, "medium", "GraphQL operation keyword found.", {"operationType": kind, "operationName": name}))

    for literal in string_literals:
        raw = clean_js_literal(str(literal["value"]))
        if raw.lower().startswith(("ws://", "wss://")):
            signals.append(signal("websocket_url", raw, source_asset, "high", "WebSocket URL literal found."))

    for match in STORAGE_CALL_RE.finditer(snippet):
        literal = read_next_string(snippet, match.end(), max_distance=80)
        if literal:
            signals.append(signal("storage_key", clean_js_literal(str(literal["value"])), source_asset, "medium", "Browser storage key name found.", {"storage": match.group("store")}))

    for match in HEADER_RE.finditer(snippet):
        header_name = match.group("name")
        signals.append(signal("auth_header" if "auth" in header_name.lower() or "api-key" in header_name.lower() else "csrf_signal", header_name, source_asset, "medium", "Security-sensitive header name found."))

    for match in CSRF_RE.finditer(snippet):
        signals.append(signal("csrf_signal", match.group("name"), source_asset, "medium", "CSRF/XSRF token name found."))

    object_names = sorted({match.group("name") for match in OBJECT_ID_RE.finditer(snippet)})
    for name in object_names:
        signals.append(signal("object_identifier", name, source_asset, "medium", "Object identifier variable or property name found."))
        parameters.append(
            JsParameterCandidate(
                name=name,
                location="identifier",
                source_asset=source_asset,
                confidence="low",
                reason="Object identifier name found in JavaScript.",
            ).as_dict()
        )

    return {
        "endpoints": dedupe(endpoints, ("raw", "method", "sourceAsset")),
        "parameters": dedupe(parameters, ("name", "endpointRaw", "location", "sourceAsset")),
        "signals": dedupe(signals, ("type", "value", "sourceAsset")),
        "libraries": dedupe(detect_libraries(snippet, source_asset), ("name", "version", "sourceAsset")),
    }
