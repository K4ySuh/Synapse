# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from . import dumps, evidence, scope, workspace
from .http import HttpClientPolicy, HttpRequest, http_client


SENSITIVE_COOKIE_RE = re.compile(r"(session|token|auth|jwt|saml|shib|wwv|sid)", re.I)
PROTOCOL_ONLY_SERVICES = {"http", "https", "ssl/http", "http-proxy", "tcpwrapped"}
DEFAULT_VERSION_PROBE_LIMIT = 8
VERSION_PROBE_PATHS = {
    "default": ["/"],
    "wordpress": ["/readme.html"],
    "drupal": ["/CHANGELOG.txt"],
    "joomla": ["/administrator/manifests/files/joomla.xml"],
}


def _split_http(raw: str) -> tuple[str, dict[str, list[str]], str]:
    head, _, body = raw.partition("\r\n\r\n")
    if not body:
        head, _, body = raw.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    start_line = lines[0] if lines else ""
    headers: dict[str, list[str]] = defaultdict(list)
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()].append(value.strip())
    return start_line, dict(headers), body


def _header_values(headers: dict[str, list[str]], name: str) -> list[str]:
    return headers.get(name.lower(), [])


def _first_header(headers: dict[str, list[str]], name: str) -> str:
    values = _header_values(headers, name)
    return values[0] if values else ""


def _cookie_names_from_cookie_header(value: str) -> list[str]:
    names = []
    for part in value.split(";"):
        if "=" not in part:
            continue
        name, _ = part.split("=", 1)
        name = name.strip()
        if name:
            names.append(name)
    return names


def _cookie_name_from_set_cookie(value: str) -> str:
    first = value.split(";", 1)[0]
    if "=" not in first:
        return ""
    return first.split("=", 1)[0].strip()


def _cookie_flags(value: str) -> dict[str, bool | str]:
    parts = [part.strip() for part in value.split(";")]
    name = _cookie_name_from_set_cookie(value)
    lowered = [part.lower() for part in parts[1:]]
    return {
        "name": name,
        "httpOnly": "httponly" in lowered,
        "secure": "secure" in lowered,
        "sameSite": next((part.split("=", 1)[1] for part in parts[1:] if part.lower().startswith("samesite=")), ""),
    }


def _add(counter: Counter[str], value: str) -> None:
    if value:
        counter[value] += 1


def _detect_auth(request_headers: dict[str, list[str]], response_headers: dict[str, list[str]], haystack: str) -> set[str]:
    methods: set[str] = set()
    cookies = "; ".join(_header_values(request_headers, "cookie") + _header_values(response_headers, "set-cookie"))
    location = " ".join(_header_values(response_headers, "location"))
    www_auth = " ".join(_header_values(response_headers, "www-authenticate"))
    combined = "\n".join([haystack, cookies, location, www_auth]).lower()

    if "samlrequest" in combined or "relaystate" in combined or "protocol/saml" in combined:
        methods.add("SAML")
    if "_shibsession" in combined or "_shibsealed" in combined:
        methods.add("Shibboleth")
    if "openid-connect" in combined or "/protocol/openid-connect/" in combined or "id_token" in combined:
        methods.add("OIDC")
    if "oauth" in combined or "bearer " in combined:
        methods.add("OAuth/Bearer")
    if "basic " in www_auth.lower():
        methods.add("HTTP Basic")
    if "digest " in www_auth.lower():
        methods.add("HTTP Digest")
    if "cookie:" in haystack.lower() or cookies:
        methods.add("Cookie-based session")
    return methods


def _detect_technologies(request_target: str, request_headers: dict[str, list[str]], response_headers: dict[str, list[str]], body: str, raw: str) -> tuple[set[str], set[str], set[str], list[str]]:
    technologies: set[str] = set()
    dbms: set[str] = set()
    os_families: set[str] = set()
    observations: list[str] = []
    haystack = "\n".join([request_target, body[:12000], raw[:12000]]).lower()

    server = _first_header(response_headers, "server")
    powered_by = _first_header(response_headers, "x-powered-by")
    content_type = _first_header(response_headers, "content-type")
    if server:
        technologies.add(server)
        observations.append(f"Server header: {server}")
    if powered_by:
        technologies.add(powered_by)
        observations.append(f"X-Powered-By header: {powered_by}")
    if "application/json" in content_type:
        technologies.add("JSON API")
    if "text/html" in content_type:
        technologies.add("HTML")
    if any(marker in haystack for marker in ("microsoft-iis", "asp.net", "x-aspnet-version", "windows server")):
        os_families.add("windows")
        observations.append("Windows platform hint observed in HTTP headers or content")
    if any(marker in haystack for marker in ("ubuntu", "debian", "centos", "red hat", "rhel", "amazon linux", "alpine", "linux")):
        os_families.add("unix")
        observations.append("Linux/Unix platform hint observed in HTTP headers or content")
    if server and any(marker in server.lower() for marker in ("apache", "nginx", "openresty", "gunicorn", "uwsgi")):
        os_families.add("unix")
    if "/ords/" in request_target.lower() or "wwv_flow" in haystack or "oracle apex" in haystack or "p_flow_id" in haystack:
        technologies.add("Oracle APEX/ORDS")
        dbms.add("Oracle")
        observations.append("Oracle APEX/ORDS route or parameter observed")
    if "/i/libraries/apex/" in haystack or "apex_img_dir" in haystack:
        technologies.add("Oracle APEX front-end assets")
    if "jquery" in haystack:
        technologies.add("jQuery")
    if ".php" in request_target.lower() or "phpsessid" in haystack:
        technologies.add("PHP")
        dbms.update({"MySQL", "MariaDB"})
    if ".aspx" in request_target.lower() or "asp.net" in haystack or "aspnet_sessionid" in haystack:
        technologies.add("ASP.NET")
        dbms.add("Microsoft SQL Server")
        os_families.add("windows")
    if "jsessionid" in haystack:
        technologies.add("Java Servlet")
    if "express" in haystack:
        technologies.add("Express")

    signatures = {
        "Oracle": ("ora-", "oracle error", "quoted string not properly terminated"),
        "MySQL": ("mysql", "mariadb", "you have an error in your sql syntax"),
        "PostgreSQL": ("postgresql", "pg_query", "unterminated quoted string"),
        "Microsoft SQL Server": ("sql server", "microsoft ole db", "odbc sql server", "unclosed quotation mark"),
        "SQLite": ("sqlite", "sqlite3.operationalerror"),
    }
    for name, values in signatures.items():
        if any(value in haystack for value in values):
            dbms.add(name)
            observations.append(f"{name} error signature observed")

    return technologies, dbms, os_families, observations


def _split_product_version(value: str) -> tuple[str, str]:
    value = " ".join(str(value).strip().split())
    if not value:
        return "", ""
    slash_match = re.match(r"^([A-Za-z][A-Za-z0-9 ._+-]*?)/([0-9][A-Za-z0-9._+-]*)", value)
    if slash_match:
        return slash_match.group(1).strip(), slash_match.group(2).strip()
    space_match = re.match(r"^(.+?)\s+([0-9][A-Za-z0-9._+-]*)$", value)
    if space_match:
        return space_match.group(1).strip(), space_match.group(2).strip()
    # Generator-style values embed the version mid-string with trailing noise, e.g.
    # "Drupal 10 (https://www.drupal.org)" -> ("Drupal", "10"). Take the first dotted-numeric
    # token after the product name and discard the trailing URL/comment.
    mid_match = re.match(r"^([A-Za-z][A-Za-z0-9 ._+-]*?)\s+v?([0-9]+(?:\.[0-9]+){0,3})\b", value)
    if mid_match:
        return mid_match.group(1).strip(" .-"), mid_match.group(2).strip()
    return value, ""


def _normalize_technology_name(name: str) -> str:
    normalized = " ".join(str(name).split())
    lowered = normalized.lower()
    if lowered in {"apache", "apache http server", "apache httpd"}:
        return "Apache httpd"
    if lowered == "nginx":
        return "nginx"
    if lowered in {"microsoft-iis", "iis"}:
        return "Microsoft IIS"
    return normalized


_CPE_PRODUCT_MAP = {
    "apache httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "php": ("php", "php"),
    "asp.net": ("microsoft", "asp.net"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla\\!"),
    "jquery": ("jquery", "jquery"),
    "angular": ("angular", "angular"),
    "express": ("expressjs", "express"),
    "node.js": ("nodejs", "node.js"),
    "oracle apex": ("oracle", "application_express"),
    "oracle apex/ords": ("oracle", "application_express"),
    "java servlet": ("oracle", "java_servlet"),
}


def _synthesize_cpe(name: str, version: str) -> str:
    normalized = _normalize_technology_name(name)
    vendor_product = _CPE_PRODUCT_MAP.get(normalized.lower())
    if not vendor_product:
        return ""
    vendor, product = vendor_product
    cpe_version = " ".join(str(version).split()) or "*"
    return f"cpe:2.3:a:{vendor}:{product}:{cpe_version}:*:*:*:*:*:*:*"


def _technology_layer(name: str) -> str:
    lowered = name.lower()
    if any(marker in lowered for marker in ("cloudflare", "akamai", "fastly", "netscaler", "citrix")):
        return "security_edge"
    if any(marker in lowered for marker in ("keycloak", "shibboleth", "saml", "openid", "oidc", "cas", "oauth")):
        return "identity_provider"
    if any(marker in lowered for marker in ("apache", "nginx", "iis", "httpapi", "httpd", "openresty", "caddy")):
        return "web_server"
    if any(marker in lowered for marker in ("php", "java", "servlet", "jsf", "asp.net", "node", "express", "python", "ruby")):
        return "runtime"
    if any(marker in lowered for marker in ("angular", "react", "vue")):
        return "frontend_framework"
    if any(marker in lowered for marker in ("wordpress", "drupal", "joomla", "liferay", "oracle apex", "humhub", "fotoweb", "easy")):
        return "web_application"
    return "component"


def _component_key(name: str, version: str, layer: str) -> str:
    return f"{layer}|{name.lower()}|{version.lower()}"


def _add_component(
    components: dict[str, dict[str, Any]],
    *,
    name: str,
    version: str = "",
    layer: str = "",
    source: str,
    confidence: str,
    reason: str,
    evidence_ids: list[Any] | None = None,
) -> None:
    name = _normalize_technology_name(name)
    version = " ".join(str(version).split())
    if not name or name.lower() in PROTOCOL_ONLY_SERVICES:
        return
    layer = layer or _technology_layer(name)
    key = _component_key(name, version, layer)
    cpe = _synthesize_cpe(name, version)
    version_precision = "exact" if version else "unknown"
    record = components.setdefault(
        key,
        {
            "type": "technology_component",
            "name": name,
            "version": version,
            "cpe": cpe,
            "versionPrecision": version_precision,
            "layer": layer,
            "sources": [],
            "confidence": confidence,
            "reasons": [],
            "evidenceIds": [],
        },
    )
    if source not in record["sources"]:
        record["sources"].append(source)
    if reason and reason not in record["reasons"]:
        record["reasons"].append(reason)
    for evidence_id in evidence_ids or []:
        value = str(evidence_id)
        if value and value not in record["evidenceIds"]:
            record["evidenceIds"].append(value)
    if record["confidence"] != "high" and confidence == "high":
        record["confidence"] = "high"


def _headers_from_endpoint(endpoint: dict[str, Any]) -> dict[str, str]:
    headers = endpoint.get("responseHeaders", {})
    if isinstance(headers, dict):
        values = {str(name).lower(): str(value) for name, value in headers.items() if str(value)}
    else:
        values = {}
    if endpoint.get("server") and "server" not in values:
        values["server"] = str(endpoint["server"])
    return values


def _endpoint_signal_text(endpoint: dict[str, Any]) -> str:
    values = [
        endpoint.get("url", ""),
        endpoint.get("path", ""),
        endpoint.get("title", ""),
        " ".join(endpoint.get("technologySignals", []) if isinstance(endpoint.get("technologySignals"), list) else []),
        json.dumps(endpoint.get("responseHeaders", {}), sort_keys=True),
    ]
    return " ".join(str(item) for item in values).lower()


def _workspace_components(services: list[dict[str, Any]], endpoints: list[dict[str, Any]], observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    components: dict[str, dict[str, Any]] = {}
    for service in services:
        product = str(service.get("product") or "").strip()
        version = str(service.get("version") or "").strip()
        if product:
            tech_name, tech_version = _split_product_version(" ".join([product, version]).strip())
            _add_component(
                components,
                name=tech_name,
                version=tech_version,
                layer=_technology_layer(tech_name),
                source="service",
                confidence="high",
                reason=f"Service metadata observed on port {service.get('port')}: {product} {version}".strip(),
                evidence_ids=service.get("evidenceIds", []),
            )
        # A bare nmap service name with no detected product/version is a port-table guess
        # (e.g. port 3000 -> "ppp"), not a fingerprint, so it is not promoted to a technology
        # component.
    for endpoint in endpoints:
        headers = _headers_from_endpoint(endpoint)
        for header_name, source in (("server", "response_header"), ("x-powered-by", "response_header"), ("x-generator", "response_header")):
            value = headers.get(header_name, "")
            if value:
                tech_name, tech_version = _split_product_version(value)
                _add_component(
                    components,
                    name=tech_name,
                    version=tech_version,
                    source=source,
                    confidence="high" if header_name == "server" else "medium",
                    reason=f"{header_name} header observed: {value}",
                    evidence_ids=endpoint.get("evidenceIds", []),
                )
                if tech_name.lower() == "express":
                    _add_component(
                        components,
                        name="Node.js",
                        layer="runtime",
                        source=source,
                        confidence="medium",
                        reason="Express X-Powered-By header implies a Node.js runtime.",
                        evidence_ids=endpoint.get("evidenceIds", []),
                    )
        recruiting = headers.get("x-recruiting", "")
        if recruiting:
            _add_component(
                components,
                name="OWASP Juice Shop",
                layer="web_application",
                source="response_header",
                confidence="high",
                reason=f"x-recruiting header observed: {recruiting}",
                evidence_ids=endpoint.get("evidenceIds", []),
            )
        cookies = set(endpoint.get("cookieNames", []) if isinstance(endpoint.get("cookieNames"), list) else [])
        cookies.update(endpoint.get("responseCookieNames", []) if isinstance(endpoint.get("responseCookieNames"), list) else [])
        if "PHPSESSID" in cookies:
            _add_component(components, name="PHP", layer="runtime", source="cookie", confidence="medium", reason="PHP session cookie observed.", evidence_ids=endpoint.get("evidenceIds", []))
        if "JSESSIONID" in cookies or "jsessionid" in _endpoint_signal_text(endpoint):
            _add_component(components, name="Java Servlet", layer="runtime", source="cookie", confidence="medium", reason="JSESSIONID cookie or URL marker observed.", evidence_ids=endpoint.get("evidenceIds", []))
        signals = _endpoint_signal_text(endpoint)
        for needle, app_name in (
            ("easyappointments", "Easy!Appointments"),
            ("easy!appointments", "Easy!Appointments"),
            ("humhub", "HumHub"),
            ("fotoweb", "FotoWeb"),
            ("fotoware", "FotoWare"),
            ("oracle apex", "Oracle APEX"),
            ("wwv_flow", "Oracle APEX"),
            ("javax.faces", "JSF"),
            ("primefaces", "PrimeFaces"),
            ("wordpress", "WordPress"),
            ("wp-content", "WordPress"),
            ("drupal", "Drupal"),
            ("joomla", "Joomla"),
            ("liferay", "Liferay"),
            ("ng-version", "Angular"),
            ("angular", "Angular"),
        ):
            if needle in signals:
                _add_component(components, name=app_name, layer="web_application", source="endpoint", confidence="medium", reason=f"Endpoint signal matched {needle}.", evidence_ids=endpoint.get("evidenceIds", []))
    for observation in observations:
        if observation.get("type") == "cpe_observed":
            _add_component(components, name=str(observation.get("value", "")), layer="component_cpe", source="observation", confidence="medium", reason="CPE observed in external exposure metadata.", evidence_ids=observation.get("evidenceIds", []))
        elif observation.get("type") == "technology_component":
            source = str(observation.get("source") or ",".join(observation.get("sources", []) if isinstance(observation.get("sources"), list) else []) or "observation")
            confidence = str(observation.get("confidence") or "medium")
            name = str(observation.get("name") or observation.get("value") or "").strip()
            version = str(observation.get("version") or "").strip()
            if not version and name:
                name, version = _split_product_version(name)
            if source == "service" and confidence == "low" and not version:
                continue
            reasons = observation.get("reasons", []) if isinstance(observation.get("reasons"), list) else []
            reason = str(observation.get("reason") or "; ".join(str(item) for item in reasons[:2]) or "Technology component observation recorded in workspace.")
            _add_component(
                components,
                name=name,
                version=version,
                layer=str(observation.get("layer") or ""),
                source=source,
                confidence=confidence,
                reason=reason,
                evidence_ids=observation.get("evidenceIds", []),
            )
    return sorted(components.values(), key=lambda item: (item["layer"], item["name"], item.get("version", "")))


WINDOWS_OS_MARKERS = ("windows", "microsoft-iis", "asp.net")
UNIX_OS_MARKERS = ("linux", "unix", "ubuntu", "debian", "centos", "red hat", "rhel", "alpine", "nginx", "apache")


def _count_os_markers(counts: Counter[str], text: str) -> None:
    haystack = f"{text.lower()} {text.lower().replace(' ', '-')}"
    if any(marker in haystack for marker in WINDOWS_OS_MARKERS):
        counts["windows"] += 1
    if any(marker in haystack for marker in UNIX_OS_MARKERS):
        counts["unix"] += 1


def _workspace_possible_os(endpoints: list[dict[str, Any]], services: list[dict[str, Any]], observations: list[dict[str, Any]] | None = None) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for service in services:
        haystack = " ".join(str(service.get(key, "")) for key in ("name", "product", "version", "extrainfo")).lower()
        _count_os_markers(counts, haystack)
    for endpoint in endpoints:
        signals = _endpoint_signal_text(endpoint)
        _count_os_markers(counts, signals)
    for observation in observations or []:
        if not isinstance(observation, dict) or observation.get("type") != "technology_component":
            continue
        haystack = " ".join(str(observation.get(key, "")) for key in ("name", "value", "version", "reason")).lower()
        _count_os_markers(counts, haystack)
    return dict(counts.most_common())


def analyze_workspace(args: dict[str, Any]) -> dict[str, Any]:
    workspace_id = workspace.normalize_workspace_id(args["workspaceId"])
    target = workspace.normalize_target(args["target"])
    entities = workspace._load_target_entities(workspace_id, target)
    services = [
        item
        for item in entities.get("services", [])
        if isinstance(item, dict) and workspace.is_reportable(item) and item.get("analysisEligible") is not False
    ]
    endpoints = [item for item in entities.get("endpoints", []) if isinstance(item, dict)]
    observations = [item for item in entities.get("observations", []) if isinstance(item, dict)]
    components = _workspace_components(services, endpoints, observations)
    possible_os = _workspace_possible_os(endpoints, services, observations)
    meta = workspace._read_json(workspace.workspace_path(workspace_id) / "workspace.json", {})
    organization = str(args.get("organization") or meta.get("organization") or workspace_id or "unknown-org")
    fingerprint = {
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "organization": organization,
        "workspaceId": workspace_id,
        "host": target,
        "source": "workspace",
        "serviceCount": len(services),
        "endpointCount": len(endpoints),
        "technologyComponents": components,
        "technologies": {
            " ".join([item["name"], item.get("version", "")]).strip(): len(item.get("reasons", [])) or 1
            for item in components
        },
        "possibleOs": possible_os,
        "possibleDbms": {},
        "auth": {
            "loginLikeEndpointCount": sum(1 for item in endpoints if "login" in str(item.get("path") or item.get("url") or "").lower()),
            "authBoundaryCount": sum(1 for item in endpoints if item.get("authBoundary")),
        },
    }
    hdir = evidence.host_path(organization, target)
    hdir.mkdir(parents=True, exist_ok=True)
    fingerprint_path = hdir / "fingerprint.json"
    fingerprint_path.write_text(json.dumps(fingerprint, indent=2, ensure_ascii=False), encoding="utf-8")
    adapter_result = {
        "adapter": "fingerprint",
        "mode": "passive_analysis",
        "workspaceId": workspace_id,
        "target": target,
        "summary": f"Identified {len(components)} technology components from workspace context.",
        "entities": {
            "observations": [
                {
                    "type": "technology_component",
                    "value": " ".join([item["name"], item.get("version", "")]).strip(),
                    "name": item["name"],
                    "version": item.get("version", ""),
                    "layer": item.get("layer", "component"),
                    "source": ",".join(item.get("sources", [])),
                    "confidence": item.get("confidence", "low"),
                    "cpe": item.get("cpe", ""),
                    "versionPrecision": item.get("versionPrecision", "unknown"),
                    "reasons": item.get("reasons", []),
                    "evidenceIds": item.get("evidenceIds", []),
                    "reason": "; ".join(item.get("reasons", [])[:2]),
                }
                for item in components
            ]
        },
    }
    ingestion = None
    if args.get("ingest", True):
        ingestion = workspace.ingest_data(
            workspace_id,
            target,
            "adapter_result",
            "passive_analysis",
            "json",
            json.dumps(adapter_result, indent=2, ensure_ascii=False),
            {"adapter": "fingerprint", "fingerprintPath": str(fingerprint_path)},
        )
    evidence.log_event(
        "fingerprint.analyze_workspace",
        f"Generated workspace fingerprint for {target}.",
        {"workspaceId": workspace_id, "target": target, "organization": organization, "technologyCount": len(components), "path": str(fingerprint_path)},
    )
    return {"fingerprinted": True, "path": str(fingerprint_path), "fingerprint": fingerprint, **({"ingestion": ingestion} if ingestion else {})}


def refresh_workspace_target(
    workspace_id: str,
    target: str,
    *,
    organization: str = "",
    ingest: bool = True,
    refresh_perimeter: bool = True,
) -> dict[str, Any]:
    """Run passive workspace fingerprinting and refresh the perimeter view."""
    result: dict[str, Any] = {
        "workspaceId": workspace.normalize_workspace_id(workspace_id),
        "target": workspace.normalize_target(target),
    }
    result["fingerprint"] = analyze_workspace(
        {
            "workspaceId": result["workspaceId"],
            "target": result["target"],
            "organization": organization,
            "ingest": ingest,
        }
    )
    if refresh_perimeter:
        from . import perimeter

        result["perimeter"] = perimeter.analyze_workspace({"workspaceId": result["workspaceId"], "target": result["target"]})
    return result


def _target_base_url(value: str) -> str:
    parsed = urlsplit(value if "://" in str(value) else f"https://{value}")
    if not parsed.netloc:
        return ""
    return urlunsplit((parsed.scheme or "https", parsed.netloc, "/", "", ""))


def _probe_paths_for_components(components: list[dict[str, Any]], max_requests: int) -> list[str]:
    if not components:
        return []
    paths: list[str] = []
    for path in VERSION_PROBE_PATHS["default"]:
        if path not in paths:
            paths.append(path)
    for component in components:
        name = str(component.get("name", "")).lower()
        for marker, marker_paths in VERSION_PROBE_PATHS.items():
            if marker == "default" or marker not in name:
                continue
            for path in marker_paths:
                if path not in paths:
                    paths.append(path)
    return paths[: max(max_requests, 0)]


def _response_header_map(response: dict[str, Any]) -> dict[str, str]:
    headers = response.get("headers", {})
    if not isinstance(headers, dict):
        return {}
    return {str(name).lower(): str(value) for name, value in headers.items() if str(value)}


def _meta_generator_values(body: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(r"<meta\b[^>]*>", body[:20000], re.I):
        tag = match.group(0)
        if not re.search(r"\bname\s*=\s*['\"]?generator['\"]?", tag, re.I):
            continue
        content = re.search(r"\bcontent\s*=\s*['\"]([^'\"]+)['\"]", tag, re.I)
        if content:
            values.append(content.group(1).strip())
    return values


def _version_signals_from_response(response: dict[str, Any]) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []
    headers = _response_header_map(response)
    for header_name in ("server", "x-powered-by", "x-generator"):
        value = headers.get(header_name, "")
        if not value:
            continue
        name, version = _split_product_version(value)
        name = _normalize_technology_name(name)
        if name and version:
            signals.append({"name": name, "version": version, "source": header_name, "raw": value})
    body = str(response.get("body", "") or "")
    for value in _meta_generator_values(body):
        name, version = _split_product_version(value)
        name = _normalize_technology_name(name)
        if name and version:
            signals.append({"name": name, "version": version, "source": "meta_generator", "raw": value})
    return signals


def _matching_component(signal: dict[str, str], components: list[dict[str, Any]]) -> dict[str, Any] | None:
    signal_name = _normalize_technology_name(signal.get("name", ""))
    for component in components:
        component_name = _normalize_technology_name(str(component.get("name", "")))
        if component_name.lower() != signal_name.lower():
            continue
        if str(component.get("versionPrecision", "")) == "exact" and str(component.get("version", "")) == signal.get("version"):
            return None
        return component
    return None


def probe_versions(args: dict[str, Any]) -> dict[str, Any]:
    from synapse_mcp.adapters.command_utils import approval_metadata, require_confirmed, require_in_scope
    from synapse_mcp.adapters.web.active_probe import response_summary, store_http_exchange_evidence

    require_confirmed(args, "fingerprint.probe_versions sends active HTTP GET requests and requires confirm=true.")
    workspace_id = workspace.normalize_workspace_id(args["workspaceId"])
    target_input = str(args["target"])
    max_requests = max(int(args.get("maxRequests", DEFAULT_VERSION_PROBE_LIMIT) or 0), 0)
    scope_result = require_in_scope(target_input, workspace_id)
    target = scope_result["host"]
    base_url = _target_base_url(target_input) or f"https://{target}/"

    entities = workspace._load_target_entities(workspace_id, target)
    services = [
        item
        for item in entities.get("services", [])
        if isinstance(item, dict) and workspace.is_reportable(item) and item.get("analysisEligible") is not False
    ]
    endpoints = [item for item in entities.get("endpoints", []) if isinstance(item, dict)]
    observations = [item for item in entities.get("observations", []) if isinstance(item, dict)]
    components = _workspace_components(services, endpoints, observations)
    paths = _probe_paths_for_components(components, max_requests)
    approval = approval_metadata(args)
    policy = HttpClientPolicy.from_args(args, timeout_seconds=float(args.get("requestTimeout", 10)))
    probes: list[dict[str, Any]] = []
    enriched_observations: list[dict[str, Any]] = []
    seen_enrichments: set[tuple[str, str, str]] = set()

    with http_client.session(policy) as session:
        for path in paths:
            url = urlunsplit((urlsplit(base_url).scheme, urlsplit(base_url).netloc, path or "/", "", ""))
            request = {"url": url, "method": "GET", "headers": {"User-Agent": "Synapse-MCP/0.1"}, "body": ""}
            response = session.send(HttpRequest(url=url, method="GET", headers=request["headers"])).as_dict()
            exchange = store_http_exchange_evidence(
                workspace_id,
                target,
                "fingerprint_version_probe",
                request=request,
                response=response,
                metadata={"adapter": "fingerprint", "tool": "fingerprint.probe_versions", "path": path, "approval": approval},
            )
            signals = _version_signals_from_response(response)
            probe_record = {
                "url": url,
                "method": "GET",
                "response": response_summary(response, body_preview_bytes=0),
                "signals": signals,
                "exchangeEvidence": exchange,
            }
            probes.append(probe_record)
            for signal in signals:
                component = _matching_component(signal, components)
                if not component:
                    continue
                name = _normalize_technology_name(signal["name"])
                version = " ".join(str(signal["version"]).split())
                layer = str(component.get("layer") or _technology_layer(name))
                key = (name.lower(), version.lower(), layer)
                if key in seen_enrichments:
                    continue
                seen_enrichments.add(key)
                enriched_observations.append(
                    {
                        "type": "technology_component",
                        "value": f"{name} {version}",
                        "name": name,
                        "version": version,
                        "cpe": _synthesize_cpe(name, version),
                        "versionPrecision": "exact",
                        "layer": layer,
                        "source": "active_fingerprint_probe",
                        "confidence": "high",
                        "reason": f"Approved benign GET {path or '/'} observed {signal['source']} version signal: {signal['raw']}",
                        "evidenceIds": [exchange.get("evidenceId", "")],
                    }
                )

    raw = {
        "adapter": "fingerprint",
        "mode": "active_version_probe",
        "workspaceId": workspace_id,
        "target": target,
        "requestCount": len(probes),
        "maxRequests": max_requests,
        "probes": probes,
        "approval": approval,
        "entities": {"observations": enriched_observations},
    }
    ingestion = workspace.ingest_data(
        workspace_id,
        target,
        "adapter_result",
        "active_version_probe",
        "json",
        json.dumps(raw, indent=2, ensure_ascii=False),
        {"adapter": "fingerprint", "tool": "fingerprint.probe_versions", "target": target, "approval": approval},
    )
    action = workspace.record_action(
        workspace_id,
        target,
        {
            "type": "active_validation",
            "tool": "fingerprint.probe_versions",
            "target": target,
            "requestCount": len(probes),
            "upgradedComponentCount": len(enriched_observations),
            "exchangeEvidenceIds": [probe["exchangeEvidence"].get("evidenceId", "") for probe in probes],
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId", ""),
        },
        ingestion.get("evidenceId", ""),
    )
    refreshed = analyze_workspace({"workspaceId": workspace_id, "target": target, "ingest": True})
    evidence.log_event(
        "fingerprint.probe_versions",
        f"Ran approved bounded version probes for {target}.",
        {"workspaceId": workspace_id, "target": target, "requestCount": len(probes), "upgradedComponentCount": len(enriched_observations), "approval": approval},
    )
    return {
        "probed": True,
        "workspaceId": workspace_id,
        "target": target,
        "requestCount": len(probes),
        "maxRequests": max_requests,
        "upgradedComponents": enriched_observations,
        "probes": probes,
        "ingestion": ingestion,
        "action": action,
        "fingerprint": refreshed["fingerprint"],
    }


def _classify_endpoint(path: str) -> str:
    lowered = path.lower()
    if lowered.endswith((".js", ".css", ".png", ".gif", ".jpg", ".jpeg", ".svg", ".ico", ".woff", ".woff2")):
        return "static"
    if "/wwv_flow.ajax" in lowered or "x-requested-with" in lowered:
        return "ajax"
    if "/wwv_flow.accept" in lowered:
        return "form-submit"
    if "/ords/" in lowered:
        return "ords"
    return "page"


def _read_text_file(path: str | None) -> str:
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _entry_raw(entry: dict[str, Any]) -> tuple[str, str]:
    request = entry.get("request") if isinstance(entry.get("request"), str) else ""
    response = entry.get("response") if isinstance(entry.get("response"), str) else ""
    request = request or _read_text_file(entry.get("requestFile"))
    response = response or _read_text_file(entry.get("responseFile"))
    return request, response


def _summarize_host(host: str, records: list[dict[str, Any]], organization: str) -> dict[str, Any]:
    methods: Counter[str] = Counter()
    status_codes: Counter[str] = Counter()
    content_types: Counter[str] = Counter()
    servers: Counter[str] = Counter()
    technologies: Counter[str] = Counter()
    possible_dbms: Counter[str] = Counter()
    possible_os: Counter[str] = Counter()
    auth_methods: Counter[str] = Counter()
    request_cookie_names: Counter[str] = Counter()
    response_cookie_names: Counter[str] = Counter()
    endpoint_classes: Counter[str] = Counter()
    paths: Counter[str] = Counter()
    cors_origins: Counter[str] = Counter()
    security_headers: dict[str, Counter[str]] = defaultdict(Counter)
    cookie_security: dict[str, dict[str, Any]] = {}
    observations: list[str] = []
    samples: list[dict[str, Any]] = []

    for record in records:
        entry = record["entry"]
        raw_request = record["request"]
        raw_response = record["response"]
        req_line, req_headers, req_body = _split_http(raw_request)
        resp_line, resp_headers, resp_body = _split_http(raw_response)
        request_target = entry.get("url") or req_line.split(" ")[1] if " " in req_line else entry.get("url", "")
        parsed = urlsplit(request_target if "://" in request_target else f"https://{host}{request_target}")
        path = parsed.path or request_target or "/"

        _add(methods, entry.get("method") or (req_line.split(" ", 1)[0] if req_line else ""))
        status = entry.get("status") or resp_line
        status_match = re.search(r"\s(\d{3})\s", f" {status} ")
        _add(status_codes, status_match.group(1) if status_match else status)
        _add(content_types, _first_header(resp_headers, "content-type").split(";", 1)[0])
        _add(servers, _first_header(resp_headers, "server"))
        _add(endpoint_classes, _classify_endpoint(path))
        _add(paths, path)

        for cookie_header in _header_values(req_headers, "cookie"):
            for name in _cookie_names_from_cookie_header(cookie_header):
                request_cookie_names[name] += 1
        for set_cookie in _header_values(resp_headers, "set-cookie"):
            flags = _cookie_flags(set_cookie)
            name = str(flags["name"])
            if not name:
                continue
            response_cookie_names[name] += 1
            cookie_security[name] = flags

        for header in ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "x-xss-protection", "referrer-policy"):
            value = _first_header(resp_headers, header)
            if value:
                security_headers[header][value] += 1
        for origin in _header_values(resp_headers, "access-control-allow-origin"):
            cors_origins[origin] += 1

        tech, dbms, os_families, obs = _detect_technologies(request_target, req_headers, resp_headers, resp_body, raw_request + "\n" + raw_response)
        for item in tech:
            technologies[item] += 1
        for item in dbms:
            possible_dbms[item] += 1
        for item in os_families:
            possible_os[item] += 1
        for item in _detect_auth(req_headers, resp_headers, raw_request + "\n" + raw_response):
            auth_methods[item] += 1
        for item in obs:
            if item not in observations:
                observations.append(item)

        params = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        if len(samples) < 20:
            samples.append(
                {
                    "id": entry.get("id"),
                    "requestLine": entry.get("requestLine") or req_line,
                    "status": status,
                    "contentType": _first_header(resp_headers, "content-type"),
                    "params": params[:20],
                }
            )

    sensitive_cookies = sorted({name for name in set(request_cookie_names) | set(response_cookie_names) if SENSITIVE_COOKIE_RE.search(name)})
    fingerprint = {
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "organization": organization,
        "host": host,
        "source": "burp-dump",
        "requestCount": len(records),
        "methods": dict(methods.most_common()),
        "statusCodes": dict(status_codes.most_common()),
        "contentTypes": dict(content_types.most_common()),
        "endpointClasses": dict(endpoint_classes.most_common()),
        "topPaths": dict(paths.most_common(30)),
        "technologies": dict(technologies.most_common()),
        "possibleDbms": dict(possible_dbms.most_common()),
        "possibleOs": dict(possible_os.most_common()),
        "auth": {
            "methods": dict(auth_methods.most_common()),
            "cookieNames": {
                "request": sorted(request_cookie_names),
                "response": sorted(response_cookie_names),
                "sensitiveLikely": sensitive_cookies,
            },
        },
        "servers": dict(servers.most_common()),
        "securityHeaders": {name: dict(values.most_common()) for name, values in security_headers.items()},
        "cors": {"allowOrigins": dict(cors_origins.most_common())},
        "cookies": {"setCookieFlags": cookie_security},
        "observations": observations[:50],
        "samples": samples,
    }
    return fingerprint


def from_dump(dump_path: str, organization: str = "unknown-org", target: str = "", limit: int = 5000) -> dict[str, Any]:
    _, entries = dumps.load_dump_entries(dump_path)
    target_host = scope.normalize_host(target) if target else ""
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for entry in entries[:limit]:
        host = scope.normalize_host(entry.get("host", ""))
        if target_host and host != target_host:
            continue
        request, response = _entry_raw(entry)
        if not request and not response:
            continue
        if not host:
            _, headers, _ = _split_http(request)
            host = scope.normalize_host(_first_header(headers, "host"))
        if not host:
            continue
        by_host[host].append({"entry": entry, "request": request, "response": response})

    evidence.ensure_project(organization, sorted(by_host))
    fingerprints = []
    for host, records in sorted(by_host.items()):
        fingerprint = _summarize_host(host, records, organization)
        hdir = evidence.host_path(organization, host)
        hdir.mkdir(parents=True, exist_ok=True)
        fingerprint_path = hdir / "fingerprint.json"
        fingerprint_path.write_text(json.dumps(fingerprint, indent=2, ensure_ascii=False), encoding="utf-8")
        fingerprints.append({"host": host, "path": str(fingerprint_path), "requestCount": len(records)})

    summary = {
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "organization": organization,
        "dumpPath": str(Path(dump_path).expanduser().resolve()),
        "target": target or None,
        "hosts": fingerprints,
    }
    org_dir = evidence.project_path(organization)
    org_dir.mkdir(parents=True, exist_ok=True)
    summary_path = org_dir / "fingerprint-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    evidence.log_event(
        "fingerprint.from_dump",
        f"Generated host fingerprint from dump for {organization}",
        {"organization": organization, "target": target or sorted(by_host), "dumpPath": summary["dumpPath"], "hosts": sorted(by_host)},
    )
    return {"fingerprinted": True, "summaryPath": str(summary_path), "summary": summary}


def read_host_fingerprint(target: str, organization: str = "unknown-org") -> dict[str, Any]:
    host = scope.normalize_host(target)
    path = evidence.host_path(organization, host) / "fingerprint.json"
    if not path.exists():
        return {"target": target, "host": host, "organization": organization, "exists": False, "path": str(path)}
    return {
        "target": target,
        "host": host,
        "organization": organization,
        "exists": True,
        "path": str(path),
        "fingerprint": json.loads(path.read_text(encoding="utf-8")),
    }
