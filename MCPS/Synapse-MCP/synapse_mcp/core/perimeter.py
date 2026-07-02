# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from . import evidence, workspace
from .documentation.assets import banner_html, html_shell
from .errors import McpError


SEVERITIES = ("critical", "high", "medium", "low", "info")
AUTH_PATH_MARKERS = ("login", "signin", "sign-in", "auth", "sso", "oauth", "session", "account", "admin", "password")
AUTH_INPUT_MARKERS = ("pass", "user", "email", "login", "token", "otp", "mfa")
PROTOCOL_ONLY_SERVICES = {"http", "https", "ssl/http", "http-proxy", "tcpwrapped"}
LOGIN_VARIANT_QUERY_KEYS = {
    "app_code",
    "continue",
    "lang",
    "language",
    "locale",
    "next",
    "page_code",
    "relaystate",
    "return",
    "returnto",
    "returnurl",
    "service",
    "target",
}
APP_SIGNATURES = (
    ("easyappointments", "Easy!Appointments"),
    ("easy!appointments", "Easy!Appointments"),
    ("humhub", "HumHub"),
    ("fotoweb", "FotoWeb"),
    ("fotoware", "FotoWare"),
    ("oracle apex", "Oracle APEX"),
    ("wwv_flow", "Oracle APEX"),
    ("apex_authentication", "Oracle APEX"),
    ("javax.faces", "JSF"),
    ("jsf", "JSF"),
    ("videoacta", "VideoActa"),
    ("wordpress", "WordPress"),
    ("wp-content", "WordPress"),
    ("drupal", "Drupal"),
    ("citrix", "Citrix"),
    ("netscaler", "Citrix NetScaler"),
)
REPORT_CANDIDATE_OBSERVATION_TYPES = {
    "missing_security_header",
    "weak_csp",
    "insecure_cookie_flag",
    "possible_cors_misconfiguration",
}
WEB_VULN_OBSERVATION_PREFIXES = {
    "headers_cookies": ("missing_security_header", "weak_csp", "insecure_cookie_flag"),
    "csrf": ("csrf_", "possible_csrf", "csrf_candidate"),
    "cors": ("possible_cors_misconfiguration", "cors_"),
    "ssrf": ("ssrf_",),
    "lfi": ("lfi_", "file_handling_behavior_observed"),
    "ssti": ("ssti_", "possible_ssti"),
    "ssi": ("ssi_", "possible_ssi", "html_sink_observed"),
    "open_redirect": ("open_redirect_",),
    "command_injection": ("command_injection_", "possible_command_injection"),
    "graphql": ("graphql_",),
    "xxe": ("xxe_",),
    "insecure_deser": ("insecure_deser_", "possible_insecure_deserialization"),
    "tls_posture": ("tls_", "weak_tls", "certificate_"),
    "jwt": ("jwt_",),
    "xss": ("xss_",),
    "sqli": ("sqli_",),
}
_STATIC_ASSET_EXTENSIONS = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif",
)


def candidate_inventory(entities: dict[str, list[dict[str, Any]]], target: str = "") -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    by_module: dict[str, int] = {}
    target_host = workspace.normalize_target(target) if target else ""
    for observation in entities.get("observations", []):
        if not isinstance(observation, dict):
            continue
        if target_host and not _candidate_belongs_to_host(observation, target_host):
            continue
        module = candidate_module(str(observation.get("type", "")))
        if not module or _candidate_targets_noise_surface(observation):
            continue
        item = dict(observation)
        item["candidateModule"] = module
        items.append(item)
        by_module[module] = by_module.get(module, 0) + 1
    return {"total": len(items), "byModule": dict(sorted(by_module.items())), "items": items}


def candidate_module(observation_type: str) -> str:
    for module, prefixes in WEB_VULN_OBSERVATION_PREFIXES.items():
        if any(observation_type == prefix or observation_type.startswith(prefix) for prefix in prefixes):
            return module
    return ""


def analyze_workspace(args: dict[str, Any]) -> dict[str, Any]:
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    targets = _target_names(wid, args.get("target", ""))
    target_reports = []
    for target in targets:
        report = _analyze_target(wid, target)
        _write_target_perimeter(wid, target, report)
        target_reports.append(report)
    summary = _workspace_perimeter_summary(wid, target_reports)
    _write_workspace_summary(wid, summary)
    evidence.log_event(
        "perimeter.analyze_workspace",
        f"Analyzed external perimeter inventory for workspace {wid}.",
        {
            "workspaceId": wid,
            "target": args.get("target", ""),
            "targetCount": len(target_reports),
            "webApplicationCount": summary["counts"]["webApplications"],
            "technologyCount": summary["counts"]["technologyComponents"],
            "loginPortalCount": summary["counts"]["loginPortals"],
            "candidateCount": summary["counts"]["findingCandidates"],
        },
    )
    response = {"workspaceId": wid, "targetCount": len(target_reports), "summary": summary, "reportPath": str(_summary_path(wid))}
    if args.get("includeTargets") is True:
        response["targets"] = target_reports
    return response


def build_summary(args: dict[str, Any]) -> dict[str, Any]:
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    target = args.get("target", "")
    if args.get("refresh") is True or not _summary_path(wid).exists():
        return analyze_workspace({**args, "includeTargets": True})
    summary = workspace._read_json(_summary_path(wid), {})
    if target:
        host = workspace.normalize_target(target)
        target_report = workspace._read_json(_target_perimeter_path(wid, host), {})
        if not target_report:
            refreshed = analyze_workspace({**args, "includeTargets": True})
            return refreshed
        return {"workspaceId": wid, "targetCount": 1, "summary": _workspace_perimeter_summary(wid, [target_report]), "targets": [target_report]}
    targets = []
    for host in summary.get("targets", []):
        target_report = workspace._read_json(_target_perimeter_path(wid, str(host.get("target", ""))), {})
        if target_report:
            targets.append(target_report)
    return {"workspaceId": wid, "targetCount": len(targets), "summary": summary, "targets": targets}


def render_report(args: dict[str, Any]) -> dict[str, Any]:
    payload = build_summary({**args, "refresh": args.get("refresh", False)})
    report_format = str(args.get("format", "markdown")).lower()
    if report_format not in {"markdown", "html"}:
        raise McpError(-32602, "format must be markdown or html.")
    content = _render_html(payload) if report_format == "html" else _render_markdown(payload)
    result = {
        "workspaceId": payload["workspaceId"],
        "format": report_format,
        "bytes": len(content.encode("utf-8")),
        "content": content,
    }
    path = _write_report_output(payload["workspaceId"], args, content, "html" if report_format == "html" else "md")
    result["path"] = str(path)
    return result


def _target_names(workspace_id: str, target: str = "") -> list[str]:
    workspace.ensure_workspace(workspace_id)
    if target:
        return [workspace.normalize_target(target)]
    root = workspace.workspace_path(workspace_id) / "targets"
    targets = []
    for target_dir in sorted(root.glob("*")) if root.exists() else []:
        meta = workspace._read_json(target_dir / "target.json", {})
        if meta.get("target"):
            targets.append(str(meta["target"]))
    return targets


def _analyze_target(workspace_id: str, target: str) -> dict[str, Any]:
    host = workspace.normalize_target(target)
    entities = workspace.load_reportable_target_entities(workspace_id, host)
    services = [item for item in entities["services"] if isinstance(item, dict)]
    endpoints = [item for item in entities["endpoints"] if isinstance(item, dict)]
    observations = [item for item in entities["observations"] if isinstance(item, dict)]
    findings = [item for item in entities["findings"] if isinstance(item, dict)]
    actions = [item for item in entities["actions"] if isinstance(item, dict)]
    technologies = _technology_components(host, services, endpoints, observations)
    login_portals = _login_portals(host, endpoints, observations, technologies)
    protected_resources = _protected_resources(host, endpoints, login_portals)
    web_apps = _web_applications(host, endpoints, technologies, login_portals)
    candidates = _finding_candidates(host, findings, observations, login_portals)
    perimeter_observations = _perimeter_observations(host, endpoints, observations, services)
    return {
        "workspaceId": workspace_id,
        "target": host,
        "generatedAt": workspace.now_utc(),
        "asset": _asset_summary(host, services, endpoints, observations, actions),
        "webApplications": web_apps,
        "technologyComponents": technologies,
        "siteMap": _site_map(host, endpoints),
        "loginPortals": login_portals,
        "protectedResources": protected_resources,
        "perimeterObservations": perimeter_observations,
        "findingCandidates": candidates,
        "sourceCounts": {
            "services": len(services),
            "endpoints": len(endpoints),
            "observations": len(observations),
            "findings": len(findings),
            "actions": len(actions),
        },
    }


def _asset_summary(host: str, services: list[dict[str, Any]], endpoints: list[dict[str, Any]], observations: list[dict[str, Any]], actions: list[dict[str, Any]]) -> dict[str, Any]:
    addresses = sorted({str(item.get("address", "")).strip() for item in services if str(item.get("address", "")).strip()})
    ports = sorted({int(item.get("port")) for item in services if str(item.get("port", "")).isdigit()})
    protocols = sorted({str(item.get("protocol", "")).strip() for item in services if str(item.get("protocol", "")).strip()})
    return {
        "host": host,
        "addresses": addresses,
        "ports": ports,
        "protocols": protocols,
        "serviceCount": len(services),
        "endpointCount": len(endpoints),
        "observationCount": len(observations),
        "actionCount": len(actions),
        "hasWeb": bool(endpoints or any(_service_is_web(item) for item in services)),
    }


def _site_map(host: str, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    root = _site_map_node("/", "/")
    method_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    included = 0
    for endpoint in sorted(endpoints, key=lambda item: (str(item.get("path") or item.get("url") or ""), str(item.get("method", "")))):
        if not isinstance(endpoint, dict):
            continue
        if not _endpoint_belongs_to_host(endpoint, host):
            continue
        item = _site_map_endpoint(endpoint)
        included += 1
        method = item.get("method", "")
        if method:
            method_counts[method] = method_counts.get(method, 0) + 1
        status = item.get("status", "")
        if status:
            status_counts[status] = status_counts.get(status, 0) + 1
        _insert_site_map_endpoint(root, item)
    return {
        "host": host,
        "endpointCount": included,
        "methodCounts": dict(sorted(method_counts.items())),
        "statusCounts": dict(sorted(status_counts.items())),
        "tree": _sort_site_map_node(root),
    }


def _endpoint_belongs_to_host(endpoint: dict[str, Any], host: str) -> bool:
    url = str(endpoint.get("url", "") or "")
    parsed_host = (urlsplit(url).hostname or str(endpoint.get("host", "") or "")).lower()
    if parsed_host and parsed_host != host.lower():
        return False
    return not _is_polluted_endpoint_url(url)


def _is_polluted_endpoint_url(url: str) -> bool:
    parsed = urlsplit(url)
    target = " ".join([parsed.path, parsed.query]).lower()
    if any(marker in target for marker in ("})();", "=>", "function ", "return ", "var ", "let ", "const ", "class ")):
        return True
    if any(char in parsed.path for char in ("{", "}", "[", "]", "`")):
        return True
    return _has_repeated_path_phrase(parsed.path)


def _has_repeated_path_phrase(path: str) -> bool:
    segments = [segment for segment in path.split("/") if segment]
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


def _site_map_node(name: str, path: str) -> dict[str, Any]:
    return {"name": name, "path": path, "endpointCount": 0, "children": [], "endpoints": []}


def _site_map_endpoint(endpoint: dict[str, Any]) -> dict[str, Any]:
    url = str(endpoint.get("url") or "")
    parsed = urlsplit(url)
    path = str(endpoint.get("path") or parsed.path or "/") or "/"
    if not path.startswith("/"):
        path = "/" + path
    query_names = _site_map_query_names(endpoint, parsed)
    status = _endpoint_status(endpoint)
    content_types = endpoint.get("contentTypes", [])
    return {
        "type": "endpoint",
        "label": _site_map_endpoint_label(path, query_names),
        "path": path,
        "url": _site_map_display_url(url, path, query_names),
        "method": str(endpoint.get("method") or "GET").upper(),
        "status": str(status) if status not in ("", None) else "",
        "title": str(endpoint.get("title") or ""),
        "queryParameters": query_names,
        "contentTypes": [str(item) for item in content_types[:3]] if isinstance(content_types, list) else [],
        "flags": _site_map_endpoint_flags(endpoint),
    }


def _site_map_query_names(endpoint: dict[str, Any], parsed: Any) -> list[str]:
    names: list[str] = []
    raw_parameters = endpoint.get("queryParameters", [])
    if isinstance(raw_parameters, list):
        for item in raw_parameters:
            if isinstance(item, dict):
                value = str(item.get("name") or item.get("key") or "").strip()
            else:
                value = str(item).strip()
            if value and value not in names:
                names.append(value)
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if key and key not in names:
            names.append(key)
    return sorted(names)


def _site_map_endpoint_label(path: str, query_names: list[str]) -> str:
    if path == "/":
        label = "/"
    else:
        label = path.rstrip("/").rsplit("/", 1)[-1] or "/"
    if query_names:
        label += " ?" + ",".join(query_names)
    return label


def _site_map_display_url(url: str, path: str, query_names: list[str]) -> str:
    if not url:
        return path + (("?" + ",".join(query_names)) if query_names else "")
    parsed = urlsplit(url)
    query = "&".join(f"{name}=..." for name in query_names)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or path, query, ""))


def _site_map_endpoint_flags(endpoint: dict[str, Any]) -> list[str]:
    flags = []
    for key, label in (
        ("hasAuthorization", "auth"),
        ("authBoundary", "boundary"),
        ("apiRoute", "api"),
        ("jsonEndpoint", "json"),
        ("graphqlEndpoint", "graphql"),
        ("stateChanging", "state-changing"),
    ):
        if endpoint.get(key):
            flags.append(label)
    return flags


def _insert_site_map_endpoint(root: dict[str, Any], endpoint: dict[str, Any]) -> None:
    path = str(endpoint.get("path") or "/")
    folder_path = "/" if path == "/" else "/" + "/".join(path.strip("/").split("/")[:-1])
    if folder_path != "/" and path.endswith("/"):
        folder_path = "/" + "/".join(path.strip("/").split("/"))
    node = root
    node["endpointCount"] += 1
    current_path = ""
    for segment in [item for item in folder_path.strip("/").split("/") if item]:
        current_path += "/" + segment
        child = next((item for item in node["children"] if item.get("name") == segment), None)
        if child is None:
            child = _site_map_node(segment, current_path)
            node["children"].append(child)
        child["endpointCount"] += 1
        node = child
    node["endpoints"].append(endpoint)


def _sort_site_map_node(node: dict[str, Any]) -> dict[str, Any]:
    node["children"] = [_sort_site_map_node(child) for child in sorted(node.get("children", []), key=lambda item: str(item.get("name", "")).lower())]
    node["endpoints"] = sorted(node.get("endpoints", []), key=lambda item: (str(item.get("label", "")).lower(), str(item.get("method", ""))))
    return node


def _technology_components(host: str, services: list[dict[str, Any]], endpoints: list[dict[str, Any]], observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    components_by_key: dict[str, dict[str, Any]] = {}
    confidence_rank = {"low": 0, "medium": 1, "high": 2}

    def add(
        name: str,
        layer: str,
        source: str,
        confidence: str,
        reasons: list[str],
        evidence_ids: list[Any] | None = None,
        version: str = "",
    ) -> None:
        normalized = _normalize_technology_name(name)
        normalized_version = " ".join(str(version).split())
        if not normalized or normalized.lower() in PROTOCOL_ONLY_SERVICES:
            return
        # Dedupe by product (name/source), independent of version or layer, so the
        # same product is one component: a version-less detection merges into the
        # versioned one, and a product that two paths classify into different
        # layers (e.g. service vs component) is not double-counted. Keep the most
        # specific version; keep the first layer seen.
        key = f"{normalized.lower()}|{source}"
        evidence = [str(item) for item in evidence_ids or [] if str(item).strip()]
        existing = components_by_key.get(key)
        if existing is None:
            components_by_key[key] = {
                "type": "technology_component",
                "host": host,
                "name": normalized,
                "version": normalized_version,
                "layer": layer,
                "source": source,
                "confidence": confidence,
                "reasons": list(reasons),
                "evidenceIds": evidence,
            }
            return
        if normalized_version and len(normalized_version) > len(str(existing.get("version", ""))):
            existing["version"] = normalized_version
        for reason in reasons:
            if reason not in existing["reasons"]:
                existing["reasons"].append(reason)
        for item in evidence:
            if item not in existing["evidenceIds"]:
                existing["evidenceIds"].append(item)
        if confidence_rank.get(confidence, -1) > confidence_rank.get(existing.get("confidence", ""), -1):
            existing["confidence"] = confidence

    for service in services:
        product = str(service.get("product") or "").strip()
        version = str(service.get("version", "")).strip()
        if product:
            name, parsed_version = _split_product_version(" ".join([product, version]).strip())
            add(name, _layer_for_product(name), "service", "high", [_service_reason(service)], service.get("evidenceIds", []), parsed_version)
        # A bare nmap service name with no detected product/version is a port-table guess
        # (e.g. port 3000 -> "ppp"), not a fingerprint, so it is not promoted to a technology
        # component. The port/service is still captured in the asset summary and as a
        # non_web_service perimeter observation.
    for endpoint in endpoints:
        headers = _headers_from_endpoint(endpoint)
        for header_name in ("server", "x-powered-by", "x-generator"):
            value = headers.get(header_name, "")
            if not value:
                continue
            name, parsed_version = _split_product_version(value)
            add(name, _layer_for_product(name), "response_header", "high" if header_name == "server" else "medium", [f"{header_name} header observed: {value}"], endpoint.get("evidenceIds", []), parsed_version)
        cookies = []
        cookies.extend(endpoint.get("cookieNames", []) if isinstance(endpoint.get("cookieNames"), list) else [])
        cookies.extend(endpoint.get("responseCookieNames", []) if isinstance(endpoint.get("responseCookieNames"), list) else [])
        for cookie in cookies:
            cookie_name = str(cookie)
            if cookie_name.upper().startswith("NSC_"):
                add("Citrix NetScaler", "security_edge", "cookie", "medium", [f"Cookie name {cookie_name} suggests NetScaler."], endpoint.get("evidenceIds", []))
            elif cookie_name == "PHPSESSID":
                add("PHP", "runtime", "cookie", "medium", ["PHP session cookie observed."], endpoint.get("evidenceIds", []))
            elif cookie_name == "JSESSIONID":
                add("Java / Servlet", "runtime", "cookie", "medium", ["JSESSIONID cookie observed."], endpoint.get("evidenceIds", []))
            elif cookie_name.lower().startswith("asp.net"):
                add("ASP.NET", "runtime", "cookie", "medium", [f"ASP.NET-style cookie {cookie_name} observed."], endpoint.get("evidenceIds", []))
        signals = _endpoint_signals(endpoint)
        for needle, app_name in APP_SIGNATURES:
            if needle in signals:
                add(app_name, "web_application", "endpoint", "medium", [f"Endpoint signal matched {needle}."], endpoint.get("evidenceIds", []))
    for observation in observations:
        if observation.get("type") == "technology_component":
            name = str(observation.get("name") or observation.get("value") or "")
            version = str(observation.get("version") or "")
            source = str(observation.get("source") or "fingerprint")
            confidence = str(observation.get("confidence") or "medium").lower()
            # A service-sourced technology_component with no version and low confidence is a bare
            # nmap port-table guess (e.g. "ppp" on port 3000), not a fingerprint. Drop it so stale
            # or guess-only observations don't surface as detected technologies.
            if source == "service" and not version and confidence in {"low", ""}:
                continue
            layer = str(observation.get("layer") or _layer_for_product(name))
            reasons = observation.get("reasons") if isinstance(observation.get("reasons"), list) else [str(observation.get("reason") or "Workspace fingerprint observed this technology.")]
            add(name, layer, source, confidence, [str(item) for item in reasons], observation.get("evidenceIds", []), version)
            continue
        signals = " ".join(str(observation.get(key, "")) for key in ("type", "value", "templateId", "reason", "name")).lower()
        for needle, app_name in APP_SIGNATURES:
            if needle in signals:
                add(app_name, "web_application", "observation", "medium", [f"Observation signal matched {needle}."], observation.get("evidenceIds", []))
        if observation.get("type") == "cpe_observed":
            add(str(observation.get("value", "")), "component_cpe", "observation", "medium", ["CPE observed in external exposure metadata."], observation.get("evidenceIds", []))
    return sorted(components_by_key.values(), key=lambda item: (item["layer"], item["name"], item.get("version", "")))


def _web_applications(host: str, endpoints: list[dict[str, Any]], technologies: list[dict[str, Any]], login_portals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_base: dict[str, dict[str, Any]] = {}
    app_names = [item["name"] for item in technologies if item.get("layer") == "web_application"]
    for endpoint in endpoints:
        if not _endpoint_belongs_to_host(endpoint, host):
            continue
        url = str(endpoint.get("url", ""))
        base = _base_url(url)
        if not base:
            continue
        record = by_base.setdefault(
            base,
            {
                "type": "web_application",
                "host": host,
                "baseUrl": base,
                "appFamily": app_names[0] if app_names else "Unknown web application",
                "confidence": "medium" if app_names else "low",
                "routeCount": 0,
                "titles": [],
                "authRequired": False,
                "loginPortalCount": 0,
                "evidenceIds": [],
            },
        )
        record["routeCount"] += 1
        if endpoint.get("title") and endpoint["title"] not in record["titles"]:
            record["titles"].append(endpoint["title"])
        if endpoint.get("authBoundary"):
            record["authRequired"] = True
        _append_evidence(record, endpoint.get("evidenceIds", []))
    for portal in login_portals:
        base = _base_url(str(portal.get("url", "")))
        if base in by_base:
            by_base[base]["loginPortalCount"] += 1
            by_base[base]["authRequired"] = True
    if not by_base and technologies:
        by_base[f"https://{host}/"] = {
            "type": "web_application",
            "host": host,
            "baseUrl": f"https://{host}/",
            "appFamily": app_names[0] if app_names else "Unknown web application",
            "confidence": "low",
            "routeCount": 0,
            "titles": [],
            "authRequired": bool(login_portals),
            "loginPortalCount": len(login_portals),
            "evidenceIds": [],
        }
    return sorted(by_base.values(), key=lambda item: item["baseUrl"])


def _login_portals(host: str, endpoints: list[dict[str, Any]], observations: list[dict[str, Any]], technologies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    portals: dict[str, dict[str, Any]] = {}
    app_name = next((item["name"] for item in technologies if item.get("layer") == "web_application"), "")

    def add_portal(
        url: str,
        method: Any,
        status: Any,
        confidence: str,
        reasons: list[str],
        input_names: list[str],
        evidence_ids: Any,
        provider: str = "",
    ) -> None:
        if not url:
            return
        key = _canonical_login_key(url, provider, method, input_names)
        representative_url = _representative_login_url(url)
        if key not in portals:
            portals[key] = {
                "type": "login_portal",
                "host": host,
                "canonicalKey": key,
                "url": representative_url,
                "representativeUrl": representative_url,
                "technology": provider or app_name or "Unknown",
                "provider": provider or app_name or "Unknown",
                "method": method or "GET",
                "status": status,
                "confidence": confidence,
                "reasons": [],
                "inputNames": sorted(set(input_names)),
                "variantCount": 0,
                "sampleUrls": [],
                "evidenceIds": [],
            }
        record = portals[key]
        _prefer_lowercase_representative_variant(record, representative_url)
        if url not in record["sampleUrls"]:
            record["sampleUrls"].append(url)
        record["variantCount"] = len(record["sampleUrls"])
        for reason in reasons:
            if reason and reason not in record["reasons"]:
                record["reasons"].append(reason)
        for name in input_names:
            if name and name not in record["inputNames"]:
                record["inputNames"].append(name)
        _append_evidence(record, evidence_ids if isinstance(evidence_ids, list) else [])
        if record["confidence"] != "high" and confidence == "high":
            record["confidence"] = "high"

    for endpoint in endpoints:
        if not _endpoint_belongs_to_host(endpoint, host):
            continue
        url = str(endpoint.get("url", ""))
        if _is_weak_auth_false_positive(endpoint):
            continue
        signals = _endpoint_signals(endpoint)
        input_names = [str(item) for item in endpoint.get("inputNames", []) if str(item).strip()] if isinstance(endpoint.get("inputNames"), list) else []
        has_auth_input = any(marker in name.lower() for marker in AUTH_INPUT_MARKERS for name in input_names)
        has_auth_path = _has_auth_path(endpoint)
        if not (has_auth_input or has_auth_path):
            continue
        reasons = []
        if has_auth_input:
            reasons.append("Form/input names suggest authentication.")
        if has_auth_path:
            reasons.append("Path or URL suggests login/admin/auth surface.")
        if endpoint.get("authBoundary"):
            reasons.append("Endpoint was marked as an authentication boundary.")
        provider = _identity_provider_from_signals(signals) or app_name
        add_portal(
            url,
            endpoint.get("method", "GET"),
            _endpoint_status(endpoint),
            "high" if has_auth_input else "medium",
            reasons,
            input_names,
            endpoint.get("evidenceIds", []),
            provider,
        )
    for observation in observations:
        if str(observation.get("type", "")) in {"auth_boundary", "sitemap_finding_candidate", "post_form_candidate"}:
            value = str(observation.get("value") or observation.get("pageUrl") or "")
            if value and any(marker in value.lower() for marker in AUTH_PATH_MARKERS):
                input_names = [str(item) for item in observation.get("inputNames", []) if str(item).strip()] if isinstance(observation.get("inputNames"), list) else []
                method = observation.get("method", "")
                if not method and str(observation.get("type", "")) == "post_form_candidate":
                    method = "POST"
                add_portal(
                    value,
                    method,
                    "",
                    "low",
                    [str(observation.get("reason") or "Observation suggests authentication surface.")],
                    input_names,
                    observation.get("evidenceIds", []),
                    app_name,
                )
    for portal in portals.values():
        portal["inputNames"] = sorted(portal["inputNames"])
        portal["sampleUrls"] = portal["sampleUrls"][:5]
    return sorted(portals.values(), key=lambda item: item["representativeUrl"])


def _protected_resources(host: str, endpoints: list[dict[str, Any]], login_portals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    portal_urls = {str(portal.get("representativeUrl") or portal.get("url") or "") for portal in login_portals}
    for endpoint in endpoints:
        if not _endpoint_belongs_to_host(endpoint, host):
            continue
        url = str(endpoint.get("url", ""))
        if not url or not endpoint.get("authBoundary"):
            continue
        if _representative_login_url(url) in portal_urls or _has_auth_path(endpoint):
            continue
        redirect_locations = endpoint.get("redirectLocations", []) if isinstance(endpoint.get("redirectLocations"), list) else []
        resources.append(
            {
                "type": "protected_resource",
                "host": host,
                "url": url,
                "method": endpoint.get("method", "GET"),
                "status": _endpoint_status(endpoint),
                "redirectLocations": redirect_locations[:5],
                "confidence": "medium",
                "reason": "Endpoint appears protected and routes through an authentication boundary.",
                "evidenceIds": endpoint.get("evidenceIds", []),
            }
        )
    return _dedupe_items(resources, ("url", "method"))[:100]


def _perimeter_observations(host: str, endpoints: list[dict[str, Any]], observations: list[dict[str, Any]], services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for endpoint in endpoints:
        if not _endpoint_belongs_to_host(endpoint, host):
            continue
        if endpoint.get("authBoundary"):
            observation_type = "auth_boundary" if _has_auth_path(endpoint) else "protected_resource"
            reason = "Authentication boundary observed." if observation_type == "auth_boundary" else "Protected resource routes through an authentication boundary."
            items.append(_perimeter_observation(host, observation_type, endpoint.get("url", ""), reason, endpoint.get("evidenceIds", [])))
        if endpoint.get("apiRoute") or endpoint.get("jsonEndpoint") or endpoint.get("graphqlEndpoint"):
            items.append(_perimeter_observation(host, "api_surface", endpoint.get("url", ""), "API/JSON/GraphQL-like endpoint observed.", endpoint.get("evidenceIds", [])))
    for service in services:
        if _service_is_web(service) is False:
            items.append(_perimeter_observation(host, "non_web_service", f"{service.get('protocol', '')}/{service.get('port', '')}", "Non-web exposed service observed.", service.get("evidenceIds", [])))
    for observation in observations:
        observation_type = str(observation.get("type", ""))
        if _is_report_candidate_observation(observation_type) or observation_type in {"possible_cve", "cpe_observed"}:
            if not _candidate_belongs_to_host(observation, host):
                continue
            items.append(_perimeter_observation(host, observation_type, observation.get("value", ""), observation.get("reason", "Requires review."), observation.get("evidenceIds", [])))
    return _dedupe_items(items, ("type", "value"))[:100]


def _finding_candidates(host: str, findings: list[dict[str, Any]], observations: list[dict[str, Any]], login_portals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for finding in findings:
        # Only genuine candidate-status findings are test candidates. Confirmed findings
        # (e.g. passively-verified header/cookie/TLS hygiene) are real findings pending
        # operator sign-off, not candidates to test, so they are not re-listed here.
        if finding.get("status") == "candidate":
            url = _candidate_url(finding)
            candidates.append(
                {
                    "type": "perimeter_finding_candidate",
                    "host": host,
                    "title": finding.get("title", "Candidate finding"),
                    "severity": finding.get("severity", "info"),
                    "confidence": finding.get("confidence", "low"),
                    "source": "finding",
                    "category": _candidate_category("finding", finding.get("title", "")),
                    "reason": "Candidate finding requires operator review.",
                    "url": url,
                    "method": str(finding.get("method", "") or "").upper(),
                    "parameter": str(finding.get("parameter", "") or ""),
                    "location": str(finding.get("location", "") or ""),
                    "request": _candidate_request(finding),
                    "occurrenceCount": 1,
                    "evidenceIds": finding.get("evidenceIds", []),
                }
            )
    for observation in observations:
        observation_type = str(observation.get("type", ""))
        if _is_report_candidate_observation(observation_type):
            if not _candidate_belongs_to_host(observation, host):
                continue
            candidates.append(_observation_report_candidate(host, observation_type, observation))
    for portal in login_portals:
        if portal.get("confidence") in {"high", "medium"}:
            candidates.append(
                {
                    "type": "perimeter_finding_candidate",
                    "host": host,
                    "title": "Login/Admin Portal Exposed",
                    "severity": "info",
                    "confidence": portal.get("confidence", "medium"),
                    "source": "login_portal",
                    "category": "Exposed authentication surface",
                    "reason": "Public login/admin surface should be reviewed for product, version, MFA, and default-login exposure.",
                    "url": portal.get("representativeUrl") or portal.get("url", ""),
                    "method": str(portal.get("method", "") or "").upper(),
                    "parameter": "",
                    "location": "",
                    "request": _candidate_request(portal),
                    "value": portal.get("url", ""),
                    "sampleValues": portal.get("sampleUrls", []) if isinstance(portal.get("sampleUrls"), list) else [],
                    "variantCount": portal.get("variantCount", 1),
                    "occurrenceCount": 1,
                    "evidenceIds": portal.get("evidenceIds", []),
                }
            )
    return _merge_finding_candidates(candidates)[:100]


def _workspace_perimeter_summary(workspace_id: str, target_reports: list[dict[str, Any]]) -> dict[str, Any]:
    technology_matrix: dict[tuple[str, str, str, str], set[str]] = {}
    severity_counts = {severity: 0 for severity in SEVERITIES}
    target_candidate_counts: dict[str, int] = {}
    module_counts: dict[str, int] = {}
    for report in target_reports:
        host = report["target"]
        inventory = candidate_inventory(workspace.load_reportable_target_entities(workspace_id, host), host)
        target_candidate_counts[host] = int(inventory.get("total", 0) or 0)
        for module, count in inventory.get("byModule", {}).items() if isinstance(inventory.get("byModule"), dict) else []:
            module_counts[str(module)] = module_counts.get(str(module), 0) + int(count or 0)
        for tech in report.get("technologyComponents", []):
            name = str(tech.get("name", ""))
            if not name or name.lower() in PROTOCOL_ONLY_SERVICES:
                continue
            key = (name, str(tech.get("version", "")), str(tech.get("confidence", "")), str(tech.get("source", "")))
            technology_matrix.setdefault(key, set()).add(host)
        for candidate in report.get("findingCandidates", []):
            severity = str(candidate.get("severity", "info")).lower()
            severity_counts[severity if severity in severity_counts else "info"] += 1
    summary = {
        "workspaceId": workspace_id,
        "generatedAt": workspace.now_utc(),
        "targets": [
            {
                "target": report["target"],
                "ports": report["asset"].get("ports", []),
                "webApplicationCount": len(report.get("webApplications", [])),
                "technologyCount": len(report.get("technologyComponents", [])),
                "loginPortalCount": len(report.get("loginPortals", [])),
                "candidateCount": target_candidate_counts.get(report["target"], 0),
            }
            for report in target_reports
        ],
        "technologyMatrix": [
            {
                "technology": " ".join([name, version]).strip(),
                "name": name,
                "version": version,
                "confidence": confidence,
                "source": source,
                "hosts": sorted(hosts),
                "hostCount": len(hosts),
            }
            for (name, version, confidence, source), hosts in sorted(technology_matrix.items())
            if name
        ],
        "counts": {
            "targets": len(target_reports),
            "webApplications": sum(len(report.get("webApplications", [])) for report in target_reports),
            "technologyComponents": sum(len(report.get("technologyComponents", [])) for report in target_reports),
            "loginPortals": sum(len(report.get("loginPortals", [])) for report in target_reports),
            "findingCandidates": sum(target_candidate_counts.values()),
        },
        "candidateInventory": {"total": sum(target_candidate_counts.values()), "byModule": dict(sorted(module_counts.items()))},
        "candidateSeverityCounts": severity_counts,
    }
    return summary


def _render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    targets = payload["targets"]
    title, _subtitle = _report_title_and_subtitle(payload)
    lines = [
        f"# {title}",
        "",
        f"- Workspace: `{payload['workspaceId']}`",
        f"- Generated: `{summary.get('generatedAt', '')}`",
        f"- Targets: `{summary['counts']['targets']}`",
        f"- Web applications: `{summary['counts']['webApplications']}`",
        f"- Login portals: `{summary['counts']['loginPortals']}`",
        f"- Candidate review items: `{summary['counts']['findingCandidates']}`",
        "",
        "## Host Inventory",
        "",
        "| Host | Ports | Web Apps | Technologies | Login Portals | Candidates |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for target in summary.get("targets", []):
        lines.append(
            "| "
            + " | ".join(
                [
                    _md_cell(target.get("target")),
                    _md_cell(", ".join(str(item) for item in target.get("ports", []))),
                    str(target.get("webApplicationCount", 0)),
                    str(target.get("technologyCount", 0)),
                    str(target.get("loginPortalCount", 0)),
                    str(target.get("candidateCount", 0)),
                ]
            )
            + " |"
        )
    lines.extend(["", "## Technology Matrix", "", "| Technology | Version | Confidence | Source | Hosts |", "| --- | --- | --- | --- | --- |"])
    for item in summary.get("technologyMatrix", []):
        lines.append(f"| {_md_cell(item.get('name') or item.get('technology'))} | {_md_cell(item.get('version'))} | {_md_cell(item.get('confidence'))} | {_md_cell(item.get('source'))} | {_md_cell(', '.join(item.get('hosts', [])))} |")
    lines.extend(["", "## Web Applications", "", "| Host | Base URL | Application | Routes | Auth | Confidence |", "| --- | --- | --- | ---: | --- | --- |"])
    for report in targets:
        for app in report.get("webApplications", []):
            lines.append(
                f"| {_md_cell(report['target'])} | {_md_cell(app.get('baseUrl'))} | {_md_cell(app.get('appFamily'))} | {app.get('routeCount', 0)} | {'yes' if app.get('authRequired') else 'no'} | {_md_cell(app.get('confidence'))} |"
            )
    lines.extend(["", "## Login Portals", "", "| Host | Representative URL | Provider | Method | Status | Variants | Inputs | Reasons | Samples | Confidence |", "| --- | --- | --- | --- | --- | ---: | --- | --- | --- | --- |"])
    for report in targets:
        for portal in report.get("loginPortals", []):
            samples = [item for item in portal.get("sampleUrls", []) if item != (portal.get("representativeUrl") or portal.get("url"))] if isinstance(portal.get("sampleUrls"), list) else []
            lines.append(
                f"| {_md_cell(report['target'])} | {_md_cell(portal.get('representativeUrl') or portal.get('url'))} | {_md_cell(portal.get('provider') or portal.get('technology'))} | {_md_cell(portal.get('method'))} | {_md_cell(portal.get('status'))} | {portal.get('variantCount', 1)} | {_md_cell(_join_limited(portal.get('inputNames', []), 8))} | {_md_cell(_join_limited(portal.get('reasons', []), 3))} | {_md_cell(_join_limited(samples, 3))} | {_md_cell(portal.get('confidence'))} |"
            )
    lines.extend(["", "## Candidate Findings And Review Items", "", "| Host | Severity | Category | Request URL | Method | Parameter | Count | Source | Samples | Reason |", "| --- | --- | --- | --- | --- | --- | ---: | --- | --- | --- |"])
    for report in targets:
        for candidate in report.get("findingCandidates", []):
            lines.append(
                f"| {_md_cell(report['target'])} | {_md_cell(candidate.get('severity'))} | {_md_cell(candidate.get('category') or candidate.get('title'))} | {_md_cell(candidate.get('url') or candidate.get('value'))} | {_md_cell(candidate.get('method'))} | {_md_cell(candidate.get('parameter') or candidate.get('location'))} | {candidate.get('occurrenceCount', 1)} | {_md_cell(candidate.get('source'))} | {_md_cell(_join_limited(candidate.get('sampleValues', []), 3))} | {_md_cell(candidate.get('reason'))} |"
            )
    lines.extend(["", "## Recommended Next Steps", ""])
    lines.extend(_recommended_steps(targets))
    return "\n".join(lines).rstrip() + "\n"


def _render_html(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    targets = payload["targets"]
    title, subtitle = _report_title_and_subtitle(payload)
    inventory_rows = [
        [
            item.get("target", ""),
            ", ".join(str(port) for port in item.get("ports", [])),
            item.get("webApplicationCount", 0),
            item.get("technologyCount", 0),
            item.get("loginPortalCount", 0),
            item.get("candidateCount", 0),
        ]
        for item in summary.get("targets", [])
    ]
    technology_rows = [[item.get("name", item.get("technology", "")), item.get("version", ""), item.get("confidence", ""), item.get("source", ""), ", ".join(item.get("hosts", []))] for item in summary.get("technologyMatrix", [])]
    app_rows = [
        [report["target"], app.get("baseUrl", ""), app.get("appFamily", ""), app.get("routeCount", 0), "yes" if app.get("authRequired") else "no", app.get("confidence", "")]
        for report in targets
        for app in report.get("webApplications", [])
    ]
    portal_rows = []
    for report in targets:
        for portal in report.get("loginPortals", []):
            representative = portal.get("representativeUrl") or portal.get("url", "")
            samples = [item for item in portal.get("sampleUrls", []) if item != representative] if isinstance(portal.get("sampleUrls"), list) else []
            portal_rows.append(
                [
                    report["target"],
                    representative,
                    portal.get("provider") or portal.get("technology", ""),
                    portal.get("method", ""),
                    portal.get("status", ""),
                    portal.get("variantCount", 1),
                    _join_limited(portal.get("inputNames", []), 8),
                    _join_limited(portal.get("reasons", []), 3),
                    _join_limited(samples, 3),
                    portal.get("confidence", ""),
                ]
            )
    candidate_rows = [
        [
            report["target"],
            candidate.get("severity", ""),
            candidate.get("category") or candidate.get("title", ""),
            candidate.get("url") or candidate.get("value", ""),
            candidate.get("method", ""),
            candidate.get("parameter") or candidate.get("location", ""),
            candidate.get("occurrenceCount", 1),
            candidate.get("source", ""),
            _join_limited(candidate.get("sampleValues", []), 3),
            candidate.get("reason", ""),
        ]
        for report in targets
        for candidate in report.get("findingCandidates", [])
    ]
    steps = _recommended_steps(targets)
    body = "\n".join(
        [
            banner_html(
                title,
                subtitle,
                {
                    "workspace": payload["workspaceId"],
                    "generated": summary.get("generatedAt", ""),
                    "targets": summary["counts"]["targets"],
                },
            ),
            '<main class="synapse-report-main">',
            "<section>",
            "<h2>Summary</h2>",
            "<ul>",
            f"<li><strong>Targets:</strong> {_html(summary['counts']['targets'])}</li>",
            f"<li><strong>Web applications:</strong> {_html(summary['counts']['webApplications'])}</li>",
            f"<li><strong>Login portals:</strong> {_html(summary['counts']['loginPortals'])}</li>",
            f"<li><strong>Candidate review items:</strong> {_html(summary['counts']['findingCandidates'])}</li>",
            "</ul>",
            "</section>",
            "<section><h2>Host Inventory</h2>",
            _html_table(["Host", "Ports", "Web Apps", "Technologies", "Login Portals", "Candidates"], inventory_rows),
            "</section>",
            "<section><h2>Technology Matrix</h2>",
            _html_table(["Technology", "Version", "Confidence", "Source", "Hosts"], technology_rows),
            "</section>",
            "<section><h2>Site Map</h2>",
            _render_site_map_html(targets),
            "</section>",
            "<section><h2>Web Applications</h2>",
            _html_table(["Host", "Base URL", "Application", "Routes", "Auth", "Confidence"], app_rows),
            "</section>",
            "<section><h2>Login Portals</h2>",
            _html_table(["Host", "Representative URL", "Provider", "Method", "Status", "Variants", "Inputs", "Reasons", "Samples", "Confidence"], portal_rows),
            "</section>",
            "<section><h2>Candidate Findings And Review Items</h2>",
            _html_table(["Host", "Severity", "Category", "Request URL", "Method", "Parameter", "Count", "Source", "Samples", "Reason"], candidate_rows),
            "</section>",
            "<section><h2>Recommended Next Steps</h2><ul>",
            *[f"<li>{_html(step.lstrip('- '))}</li>" for step in steps],
            "</ul></section>",
            "</main>",
        ]
    )
    return html_shell(
        title,
        body,
        "function synapseToggleSiteMap(open){document.querySelectorAll('.sitemap-host,.sitemap-tree details').forEach(function(item){item.open=open;});}"
        "function synapseFilterSiteMap(value){var query=(value||'').toLowerCase();document.querySelectorAll('.sitemap-host').forEach(function(host){var match=!query||host.textContent.toLowerCase().indexOf(query)>-1;host.style.display=match?'':'none';if(match&&query){host.open=true;host.querySelectorAll('details').forEach(function(item){item.open=true;});}});}",
        {"workspace": payload["workspaceId"], "generated": summary.get("generatedAt", "")},
    )


def _report_title_and_subtitle(payload: dict[str, Any]) -> tuple[str, str]:
    targets = payload.get("targets", [])
    target_count = len(targets) if isinstance(targets, list) else int(payload.get("targetCount", 0) or 0)
    if target_count == 1:
        return "Application Surface Assessment", "Passive application inventory generated from normalized Synapse workspace state."
    return "External Perimeter Assessment", "Passive perimeter inventory generated from normalized Synapse workspace state."


def _render_site_map_html(targets: list[dict[str, Any]]) -> str:
    maps = [target.get("siteMap", {}) for target in targets if isinstance(target.get("siteMap"), dict) and target.get("siteMap", {}).get("endpointCount")]
    if not maps:
        return "<p>No endpoint records.</p>"
    controls = (
        "<div class=\"sitemap-controls\">"
        "<input type=\"search\" placeholder=\"Filter host, path, method, status, title, or tag\" oninput=\"synapseFilterSiteMap(this.value)\">"
        "<button type=\"button\" onclick=\"synapseToggleSiteMap(true)\">Expand all</button>"
        "<button type=\"button\" onclick=\"synapseToggleSiteMap(false)\">Collapse all</button>"
        "</div>"
    )
    hosts = []
    for site_map in maps:
        method_summary = ", ".join(f"{method}:{count}" for method, count in site_map.get("methodCounts", {}).items())
        status_summary = ", ".join(f"{status}:{count}" for status, count in site_map.get("statusCounts", {}).items())
        meta = " | ".join(item for item in [f"{site_map.get('endpointCount', 0)} endpoints", method_summary, status_summary] if item)
        hosts.append(
            "<details class=\"sitemap-host\">"
            f"<summary>{_html(site_map.get('host', ''))} <span class=\"muted\">{_html(meta)}</span></summary>"
            f"<div class=\"sitemap-tree\">{_render_site_map_node_html(site_map.get('tree', {}), root=True)}</div>"
            "</details>"
        )
    return controls + "".join(hosts)


def _render_site_map_node_html(node: dict[str, Any], root: bool = False) -> str:
    if not isinstance(node, dict):
        return ""
    children = node.get("children", []) if isinstance(node.get("children"), list) else []
    endpoints = node.get("endpoints", []) if isinstance(node.get("endpoints"), list) else []
    inner = "".join(_render_site_map_node_html(child) for child in children if isinstance(child, dict))
    inner += "".join(_render_site_map_endpoint_html(endpoint) for endpoint in endpoints if isinstance(endpoint, dict))
    if root:
        return inner or "<p>No endpoint records.</p>"
    return (
        "<details>"
        f"<summary>{_html(node.get('name', ''))} <span class=\"muted\">{_html(node.get('endpointCount', 0))}</span></summary>"
        f"{inner}"
        "</details>"
    )


def _render_site_map_endpoint_html(endpoint: dict[str, Any]) -> str:
    query = ", ".join(endpoint.get("queryParameters", [])) if isinstance(endpoint.get("queryParameters"), list) else ""
    content_type = ", ".join(endpoint.get("contentTypes", [])) if isinstance(endpoint.get("contentTypes"), list) else ""
    flags = "".join(f"<span class=\"badge\">{_html(flag)}</span>" for flag in endpoint.get("flags", []) if str(flag).strip()) if isinstance(endpoint.get("flags"), list) else ""
    detail_parts = [_html(item) for item in [str(endpoint.get("title", "")).strip(), content_type] if item]
    if flags:
        detail_parts.append(flags)
    detail = " | ".join(detail_parts)
    return (
        "<div class=\"sitemap-endpoint\">"
        f"<span>{_html(endpoint.get('method', ''))}</span>"
        f"<span>{_html(endpoint.get('status', ''))}</span>"
        f"<code title=\"{_html(endpoint.get('url', ''))}\">{_html(endpoint.get('label') or endpoint.get('path', ''))}</code>"
        f"<span>{_html(query)}</span>"
        f"<span class=\"muted\">{detail}</span>"
        "</div>"
    )


def _recommended_steps(targets: list[dict[str, Any]]) -> list[str]:
    steps = []
    for report in targets:
        host = report["target"]
        counts = _candidate_category_row_counts(report.get("findingCandidates", []))
        header_count = counts.get("Security header hygiene candidate", 0)
        cookie_count = counts.get("Cookie hygiene candidate", 0)
        if header_count or cookie_count:
            issue_bits = []
            if header_count:
                issue_bits.append(f"{header_count} security-header class(es)")
            if cookie_count:
                issue_bits.append(f"{cookie_count} cookie-flag issue(s)")
            steps.append(f"- Validate {' and '.join(issue_bits)} on representative responses for `{host}` and record the intended baseline policy.")
        if counts.get("Open redirect candidate", 0):
            steps.append(f"- Triage {counts['Open redirect candidate']} open-redirect candidate(s) on `{host}` with a harmless destination after approval.")
        if counts.get("Access-control candidate", 0):
            steps.append(f"- Use the access-control layer to review {counts['Access-control candidate']} role/function candidate(s) for `{host}`.")
        if any(item.get("layer") == "web_application" and item.get("confidence") != "high" for item in report.get("technologyComponents", [])):
            steps.append(f"- Confirm low/medium-confidence web application classifications on `{host}`.")
        if report.get("loginPortals") and not counts:
            steps.append(f"- Review login portals on `{host}` for product/version, MFA, default credential exposure, and access-control boundaries.")
    return steps or ["- No perimeter follow-up steps were inferred from the stored workspace data."]


def _candidate_category_row_counts(candidates: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in candidates if isinstance(candidates, list) else []:
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or item.get("title") or "").strip()
        if category:
            counts[category] = counts.get(category, 0) + 1
    return counts


def _write_target_perimeter(workspace_id: str, target: str, payload: dict[str, Any]) -> None:
    workspace._write_json(_target_perimeter_path(workspace_id, target), payload)


def _write_workspace_summary(workspace_id: str, payload: dict[str, Any]) -> None:
    workspace._write_json(_summary_path(workspace_id), payload)


def _summary_path(workspace_id: str) -> Path:
    return workspace.workspace_path(workspace_id) / "perimeter-summary.json"


def _target_perimeter_path(workspace_id: str, target: str) -> Path:
    return workspace.target_model_path(workspace_id, target, "perimeter.json")


def _write_report_output(workspace_id: str, args: dict[str, Any], content: str, extension: str) -> Path:
    path = workspace.resolve_report_output_path(
        workspace_id,
        args.get("outputPath", ""),
        extension=extension,
        default_name=f"perimeter.{extension}",
        allow_external=args.get("allowExternalOutput") is True,
        artifact="perimeter",
    )
    path.write_text(content, encoding="utf-8")
    return path


def _service_is_web(service: dict[str, Any]) -> bool:
    values = " ".join(str(service.get(key, "")) for key in ("name", "product", "port")).lower()
    return any(marker in values for marker in ("http", "https", "80", "443", "8080", "8443"))


def _service_reason(service: dict[str, Any]) -> str:
    pieces = [str(service.get(key, "")).strip() for key in ("protocol", "port", "product", "version", "name") if str(service.get(key, "")).strip()]
    return "Service metadata observed: " + " ".join(pieces)


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


def _layer_for_product(product: str) -> str:
    lowered = product.lower()
    if any(marker in lowered for marker in ("cloudflare", "netscaler", "citrix", "akamai", "fastly")):
        return "security_edge"
    if any(marker in lowered for marker in ("keycloak", "shibboleth", "saml", "openid", "oidc", "cas", "oauth")):
        return "identity_provider"
    if any(marker in lowered for marker in ("nginx", "apache", "iis", "httpapi", "httpd", "caddy")):
        return "web_server"
    if any(marker in lowered for marker in ("php", "java", "servlet", "jsf", "primefaces", "asp.net", "node", "python", "ruby")):
        return "runtime"
    if any(marker in lowered for marker in ("wordpress", "drupal", "joomla", "liferay", "oracle apex", "humhub", "fotoweb", "easy")):
        return "web_application"
    return "service"


def _endpoint_signals(endpoint: dict[str, Any]) -> str:
    values = [endpoint.get("url", ""), endpoint.get("path", ""), endpoint.get("title", "")]
    values.extend(endpoint.get("cookieNames", []) if isinstance(endpoint.get("cookieNames"), list) else [])
    values.extend(endpoint.get("responseCookieNames", []) if isinstance(endpoint.get("responseCookieNames"), list) else [])
    values.extend(endpoint.get("inputNames", []) if isinstance(endpoint.get("inputNames"), list) else [])
    values.extend(endpoint.get("technologySignals", []) if isinstance(endpoint.get("technologySignals"), list) else [])
    values.append(json.dumps(endpoint.get("responseHeaders", {}), sort_keys=True))
    values.append(endpoint.get("server", ""))
    return " ".join(str(item) for item in values).lower()


def _headers_from_endpoint(endpoint: dict[str, Any]) -> dict[str, str]:
    headers = endpoint.get("responseHeaders", {})
    values = {str(name).lower(): str(value) for name, value in headers.items() if str(value)} if isinstance(headers, dict) else {}
    if endpoint.get("server") and "server" not in values:
        values["server"] = str(endpoint["server"])
    return values


def _has_auth_path(endpoint: dict[str, Any]) -> bool:
    parsed = urlsplit(str(endpoint.get("url") or endpoint.get("path") or ""))
    path = parsed.path or str(endpoint.get("path", ""))
    tokens = [token for token in re_split_path(path.lower()) if token]
    token_set = set(tokens)
    if token_set.intersection(AUTH_PATH_MARKERS):
        return True
    return any(token in {"login", "signin", "auth", "oauth", "sso", "admin"} for token in tokens)


def _endpoint_status(endpoint: dict[str, Any]) -> Any:
    if endpoint.get("status") not in ("", None):
        return endpoint.get("status")
    statuses = endpoint.get("statusCodes")
    if isinstance(statuses, list) and statuses:
        return statuses[0]
    return ""


def _is_weak_auth_false_positive(endpoint: dict[str, Any]) -> bool:
    status = _endpoint_status(endpoint)
    title = str(endpoint.get("title", "")).lower()
    input_names = [str(item).lower() for item in endpoint.get("inputNames", [])] if isinstance(endpoint.get("inputNames"), list) else []
    has_auth_input = any(marker in name for marker in AUTH_INPUT_MARKERS for name in input_names)
    try:
        is_404 = int(status) == 404
    except (TypeError, ValueError):
        is_404 = False
    return (is_404 or "404 not found" in title or title.strip() == "not found") and not has_auth_input


def _identity_provider_from_signals(signals: str) -> str:
    lowered = signals.lower()
    if "keycloak" in lowered:
        return "Keycloak"
    if "shibboleth" in lowered or "_shib" in lowered:
        return "Shibboleth"
    if "saml" in lowered or "relaystate" in lowered:
        return "SAML"
    if "openid-connect" in lowered or "oidc" in lowered:
        return "OIDC"
    if "oauth" in lowered:
        return "OAuth"
    if " cas" in f" {lowered}" or "/cas/" in lowered:
        return "CAS"
    return ""


def _representative_login_url(url: str) -> str:
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return url
    path = re.sub(r"/+", "/", parsed.path or "/")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))


def _prefer_lowercase_representative_variant(record: dict[str, Any], candidate_url: str) -> None:
    current = str(record.get("representativeUrl") or record.get("url") or "")
    current_parsed = urlsplit(current)
    candidate_parsed = urlsplit(candidate_url)
    if not current_parsed.netloc or not candidate_parsed.netloc:
        return
    if (current_parsed.scheme.lower(), current_parsed.netloc.lower()) != (candidate_parsed.scheme.lower(), candidate_parsed.netloc.lower()):
        return
    if current_parsed.path.lower() != candidate_parsed.path.lower():
        return
    candidate_path = candidate_parsed.path or "/"
    current_path = current_parsed.path or "/"
    if candidate_path == candidate_path.lower() and current_path != current_path.lower():
        record["url"] = candidate_url
        record["representativeUrl"] = candidate_url


def _canonical_login_key(url: str, provider: str, method: Any, input_names: list[str]) -> str:
    parsed = urlsplit(url)
    host = parsed.netloc.lower()
    path = re.sub(r"/+", "/", parsed.path or "/").rstrip("/") or "/"
    query_keys = {key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    variant_only = bool(query_keys) and query_keys.issubset(LOGIN_VARIANT_QUERY_KEYS)
    query_marker = "" if variant_only else ",".join(sorted(query_keys - LOGIN_VARIANT_QUERY_KEYS))
    auth_signature = ",".join(sorted({name.lower() for name in input_names if name}))
    return "|".join([parsed.scheme.lower(), host, path.lower(), str(provider or "").lower(), str(method or "").upper(), auth_signature, query_marker])


def re_split_path(path: str) -> list[str]:
    separators = "/._-;:"
    normalized = path
    for separator in separators:
        normalized = normalized.replace(separator, " ")
    return normalized.split()


def _base_url(url: str) -> str:
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _append_evidence(record: dict[str, Any], evidence_ids: Any) -> None:
    current = record.setdefault("evidenceIds", [])
    if not isinstance(evidence_ids, list):
        return
    for evidence_id in evidence_ids:
        value = str(evidence_id)
        if value and value not in current:
            current.append(value)


def _perimeter_observation(host: str, observation_type: str, value: Any, reason: Any, evidence_ids: Any) -> dict[str, Any]:
    return {
        "type": observation_type,
        "host": host,
        "value": str(value),
        "reason": str(reason),
        "confidence": "medium",
        "evidenceIds": [str(item) for item in evidence_ids or [] if str(item).strip()] if isinstance(evidence_ids, list) else [],
    }


def _dedupe_items(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen = set()
    deduped = []
    for item in items:
        marker = tuple(str(item.get(key, "")) for key in keys)
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(item)
    return deduped


def _merge_finding_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    for candidate in candidates:
        marker = (
            str(candidate.get("title", "")),
            str(candidate.get("url") or candidate.get("value", "")),
            str(candidate.get("method", "")),
            str(candidate.get("parameter", "")),
            str(candidate.get("location", "")),
            str(candidate.get("source", "")),
        )
        record = merged.get(marker)
        if record is None:
            copied = dict(candidate)
            copied["occurrenceCount"] = int(copied.get("occurrenceCount", 1) or 1)
            copied["sampleValues"] = _unique_strings(copied.get("sampleValues", []))[:5]
            copied["evidenceIds"] = _unique_strings(copied.get("evidenceIds", []))
            merged[marker] = copied
            continue
        record["occurrenceCount"] = int(record.get("occurrenceCount", 1) or 1) + int(candidate.get("occurrenceCount", 1) or 1)
        for field in ("sampleValues", "evidenceIds"):
            current = record.setdefault(field, [])
            if not isinstance(current, list):
                current = []
                record[field] = current
            for value in candidate.get(field, []) if isinstance(candidate.get(field), list) else []:
                text = str(value).strip()
                if text and text not in current:
                    current.append(text)
        if not record.get("reason") and candidate.get("reason"):
            record["reason"] = candidate["reason"]
    return list(merged.values())


def _observation_report_candidate(host: str, observation_type: str, observation: dict[str, Any]) -> dict[str, Any]:
    method = observation.get("method", "")
    if not method and observation_type == "post_form_candidate":
        method = "POST"
    method = str(method or "").upper()
    header = str(observation.get("header", "") or "").strip().lower()
    cookie = str(observation.get("cookie", "") or "").strip()
    flag = str(observation.get("flag", "") or "").strip().lower()
    url = _candidate_url(observation)
    value = str(observation.get("value", "") or "").strip()
    location = str(observation.get("location", "") or "").strip()
    parameter = str(observation.get("parameter", "") or "").strip()
    sample_values = [str(item) for item in [value, observation.get("pageUrl", ""), observation.get("formAction", "")] if str(item).strip()]
    request = _candidate_request(observation)
    title = observation_type.replace("_", " ").title()

    if observation_type in {"missing_security_header", "weak_csp"}:
        header_label = _security_header_label(header)
        issue = "weak" if observation_type == "weak_csp" else "missing"
        title = f"{header_label} header {issue}" if header_label else "Security header hygiene issue"
        value = f"{header_label} header {issue} on observed responses" if header_label else "Security header issue on observed responses"
        request = f"{method + ' ' if method else ''}responses {issue} {header_label}".strip()
        parameter = header
        location = "response_header"
        url = ""
        sample_values = [f"{method + ' ' if method else ''}observed response".strip()]
    elif observation_type == "insecure_cookie_flag":
        flag_label = flag or "security"
        title = f"Cookie missing {flag_label} flag"
        value = f"{cookie or 'session-like cookie'} missing {flag_label} flag"
        request = f"Observed Set-Cookie metadata: {value}"
        parameter = cookie or flag_label
        location = "set_cookie"
        url = ""
        sample_values = ["Set-Cookie metadata without stored cookie value"]
    elif observation_type == "possible_broken_access_control":
        request_url = str(observation.get("requestUrl", "") or observation.get("url", "") or "").strip()
        replay_id = str(observation.get("replayId", "") or "").strip()
        matrix_id = str(observation.get("matrixId", "") or "").strip()
        test_class = str(observation.get("testClass", "") or "access-control").strip()
        value = request_url or str(observation.get("endpointPattern", "") or matrix_id or replay_id or "approved replay candidate").strip()
        request = f"{method + ' ' if method else ''}{value}".strip()
        if matrix_id:
            request = f"{request} ({matrix_id})"
        elif replay_id:
            request = f"{request} ({replay_id})"
        parameter = matrix_id or replay_id or parameter
        location = test_class
        url = request_url
        sample_values = [item for item in [request_url, matrix_id, replay_id] if item]
    elif observation_type.startswith("jwt_"):
        value = value or observation_type.replace("_", " ")
        request = value
        location = "jwt"

    return {
        "type": "perimeter_finding_candidate",
        "host": host,
        "title": title,
        "severity": _severity_for_observation(observation),
        "confidence": observation.get("confidence", "low"),
        "source": "observation",
        "category": _candidate_category(observation_type),
        "reason": observation.get("reason") or observation.get("testPlanSummary") or "Candidate observation requires review.",
        "url": url,
        "method": method,
        "parameter": parameter,
        "location": location,
        "request": request,
        "value": value,
        "sampleValues": sample_values[:5],
        "occurrenceCount": 1,
        "evidenceIds": observation.get("evidenceIds", []),
    }


def _candidate_url(item: dict[str, Any]) -> str:
    for key in ("url", "pageUrl", "formAction", "endpointUrl", "requestUrl", "value"):
        value = str(item.get(key, "") or "").strip()
        if value.startswith(("http://", "https://")):
            return value
    value = str(item.get("value", "") or "").strip()
    return value


def _candidate_belongs_to_host(item: dict[str, Any], host: str) -> bool:
    url = _candidate_url(item)
    if not url:
        return True
    parsed = urlsplit(url)
    if parsed.hostname and parsed.hostname.lower() != host.lower():
        return False
    return not _is_polluted_endpoint_url(url)


def _candidate_targets_noise_surface(observation: dict[str, Any]) -> bool:
    url = str(observation.get("url") or "")
    if not url:
        parts = str(observation.get("value") or "").split()
        url = parts[-1] if parts else ""
    if urlsplit(url).path.lower().endswith(_STATIC_ASSET_EXTENSIONS):
        return True
    if _is_polluted_endpoint_url(url):
        return True
    segments = [segment for segment in urlsplit(url).path.split("/") if segment]
    return len(segments) == 1 and segments[0].isdigit()


def _candidate_request(item: dict[str, Any]) -> str:
    url = _candidate_url(item)
    method = str(item.get("method", "") or "").upper()
    if method and url:
        return f"{method} {url}"
    return url or method


def _candidate_category(candidate_type: str, title: Any = "") -> str:
    value = f"{candidate_type} {title}".lower()
    if (
        "missing_security_header" in value
        or "weak_csp" in value
        or "content-security-policy" in value
        or "security-policy" in value
        or "security header" in value
        or "referrer-policy" in value
    ):
        return "Security header hygiene candidate"
    if "insecure_cookie_flag" in value:
        return "Cookie hygiene candidate"
    if "cors" in value:
        return "CORS candidate"
    if "csrf" in value:
        return "CSRF candidate"
    if "jwt" in value:
        return "JWT candidate"
    if "sqli" in value or "sql injection" in value or "sql_injection" in value:
        return "SQL injection candidate"
    if "xss" in value or "cross-site scripting" in value or "cross site scripting" in value:
        return "XSS candidate"
    if "open_redirect" in value or "open redirect" in value:
        return "Open redirect candidate"
    if "ssrf" in value:
        return "SSRF candidate"
    if "ssti" in value:
        return "SSTI candidate"
    if "lfi" in value or "rfi" in value or "file_download" in value or "file download" in value:
        return "File handling candidate"
    # Match SSI on specific tokens, not a bare "ssi" substring: bare "ssi" also
    # matches "mi-ssi-ng" / "se-ssi-on", which mislabeled "Missing ..." findings
    # as SSI candidates.
    if "ssi_" in value or "possible_ssi" in value or "html_sink" in value or "server-side include" in value or "server side include" in value:
        return "SSI candidate"
    if "command_injection" in value or "command injection" in value:
        return "Command injection candidate"
    if "access_control" in value or "access control" in value:
        return "Access-control candidate"
    if "post_form" in value or "post form" in value:
        return "State-changing POST form candidate"
    if "sitemap" in value:
        return "Workflow review candidate"
    if "login" in value or "auth" in value or "admin" in value:
        return "Exposed authentication surface"
    return "Candidate finding"


def _is_report_candidate_observation(observation_type: str) -> bool:
    if observation_type.endswith("_candidate"):
        return True
    if observation_type in REPORT_CANDIDATE_OBSERVATION_TYPES:
        return True
    return observation_type.startswith("jwt_")


def _security_header_label(header: str) -> str:
    labels = {
        "content-security-policy": "Content-Security-Policy",
        "strict-transport-security": "Strict-Transport-Security",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
    }
    return labels.get(str(header or "").lower(), str(header or "").strip())


def _unique_strings(values: Any) -> list[str]:
    result: list[str] = []
    if not isinstance(values, list):
        return result
    for value in values:
        text = str(value).strip()
        if text and text not in result:
            result.append(text)
    return result


def _join_limited(values: Any, limit: int) -> str:
    if not isinstance(values, list):
        return ""
    items = _unique_strings(values)
    shown = items[:limit]
    suffix = f" (+{len(items) - limit} more)" if len(items) > limit else ""
    return ", ".join(shown) + suffix


def _severity_for_observation(observation: dict[str, Any]) -> str:
    priority = str(observation.get("priority", "") or "").strip().lower()
    if priority in SEVERITIES:
        return priority
    score = int(observation.get("priorityScore", 0) or 0)
    if score >= 85:
        return "high"
    if score >= 65:
        return "medium"
    if score >= 35:
        return "low"
    return "info"


def _md_cell(value: Any) -> str:
    return str("" if value is None else value).replace("|", "\\|").replace("\n", " ").strip()


def _html(value: Any) -> str:
    return html.escape(str("" if value is None else value), quote=True)


def _html_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "<p>No records.</p>"
    widths = _column_widths(headers, rows)
    colgroup = "<colgroup>" + "".join(f'<col style="width:{width:.2f}%">' for width in widths) + "</colgroup>" if widths else ""
    header_html = "".join(f"<th>{_html(header)}</th>" for header in headers)
    row_html = []
    for row in rows:
        row_html.append("<tr>" + "".join(f"<td>{_html_cell(cell, headers[index] if index < len(headers) else '')}</td>" for index, cell in enumerate(row)) + "</tr>")
    return '<div class="table-wrap"><table>' + colgroup + "<thead><tr>" + header_html + "</tr></thead><tbody>" + "".join(row_html) + "</tbody></table></div>"


def _html_cell(value: Any, header: Any) -> str:
    rendered = str("" if value is None else value)
    badge = _badge_class(rendered, header)
    if badge:
        return f"<span class=\"badge {badge}\">{_html(rendered)}</span>"
    return _html(rendered)


def _badge_class(value: str, header: Any) -> str:
    header_text = str(header or "").strip().lower()
    if header_text not in {"severity", "confidence"}:
        return ""
    normalized = value.strip().lower()
    if normalized in {"critical", "high", "medium", "low", "info"}:
        return f"badge-{normalized}"
    return ""


def _column_widths(headers: list[Any], rows: list[list[Any]]) -> list[float]:
    if not headers:
        return []
    weights = []
    for index, header in enumerate(headers):
        values = [str(header or "")]
        for row in rows:
            if isinstance(row, list) and index < len(row):
                values.append(str(row[index] or ""))
        longest = max((len(value) for value in values), default=1)
        weights.append(max(8, min(34, longest)))
    total = sum(weights) or 1
    return [(weight / total) * 100 for weight in weights]
