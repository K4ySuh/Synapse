# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import ipaddress
from typing import Any
from urllib.parse import urlencode

from ...core import evidence, fingerprint, scope, workspace
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import require_confirmed


API_BASE = "https://api.shodan.io"
INTERNETDB_BASE = "https://internetdb.shodan.io"
_SESSION_API_KEY = ""


def api_key() -> str:
    key = _SESSION_API_KEY.strip()
    if not key:
        raise McpError(-32001, "Shodan API key is not configured for this session. Call shodan.session_key.set first.")
    return key


def set_session_key(args: dict[str, Any]) -> str:
    require_confirmed(args, "Setting the Shodan session API key requires confirm=true.")
    key = str(args.get("apiKey", "")).strip()
    if not key:
        raise McpError(-32602, "apiKey is required.")
    global _SESSION_API_KEY
    _SESSION_API_KEY = key
    return json.dumps({"configured": True, "source": "session", "persisted": False}, indent=2)


def clear_session_key(args: dict[str, Any]) -> str:
    require_confirmed(args, "Clearing the Shodan session API key requires confirm=true.")
    global _SESSION_API_KEY
    _SESSION_API_KEY = ""
    return json.dumps({"configured": False, "sessionCleared": True}, indent=2)


def session_key_status(_: dict[str, Any]) -> str:
    return json.dumps(
        {
            "configured": bool(_SESSION_API_KEY),
            "source": "session" if _SESSION_API_KEY else None,
            "persisted": False,
        },
        indent=2,
    )


def http_get_json(url: str, timeout_seconds: int = 30) -> Any:
    policy = HttpClientPolicy(timeout_seconds=timeout_seconds, max_body_bytes=5_000_000)
    response = http_client.send(HttpRequest(url=url, headers={"User-Agent": "Synapse-MCP/0.1"}), policy=policy)
    if response.status is None:
        raise McpError(-32000, f"Shodan request failed: {redact_secret(response.error)}")
    if response.status >= 400:
        raise McpError(-32000, f"Shodan HTTP error {response.status}: {redact_secret(response.body)[:500]}")
    try:
        return json.loads(response.body)
    except json.JSONDecodeError as exc:
        raise McpError(-32000, f"Shodan response was not JSON: {exc}") from exc


def shodan_url(path: str, params: dict[str, Any]) -> str:
    clean = {key: value for key, value in params.items() if value is not None and value != ""}
    clean["key"] = api_key()
    return f"{API_BASE}{path}?{urlencode(clean, doseq=True)}"


def redact_secret(value: str) -> str:
    key = _SESSION_API_KEY
    if key:
        return value.replace(key, "[REDACTED]")
    return value


def summarize_host(payload: dict[str, Any]) -> dict[str, Any]:
    services = []
    for banner in payload.get("data", [])[:100]:
        services.append(
            {
                "port": banner.get("port"),
                "transport": banner.get("transport"),
                "product": banner.get("product"),
                "version": banner.get("version"),
                "hostnames": banner.get("hostnames", [])[:10],
                "domains": banner.get("domains", [])[:10],
                "timestamp": banner.get("timestamp"),
                "ssl": summarize_ssl(banner.get("ssl")),
                "http": summarize_http(banner.get("http")),
            }
        )
    return {
        "ip": payload.get("ip_str"),
        "org": payload.get("org"),
        "isp": payload.get("isp"),
        "asn": payload.get("asn"),
        "country": payload.get("country_name"),
        "city": payload.get("city"),
        "hostnames": payload.get("hostnames", []),
        "domains": payload.get("domains", []),
        "ports": payload.get("ports", []),
        "vulns": sorted(list((payload.get("vulns") or {}).keys())) if isinstance(payload.get("vulns"), dict) else payload.get("vulns", []),
        "services": services,
    }


def summarize_ssl(ssl: Any) -> dict[str, Any] | None:
    if not isinstance(ssl, dict):
        return None
    cert = ssl.get("cert", {}) if isinstance(ssl.get("cert"), dict) else {}
    subject = cert.get("subject", {}) if isinstance(cert.get("subject"), dict) else {}
    issuer = cert.get("issuer", {}) if isinstance(cert.get("issuer"), dict) else {}
    return {
        "subjectCN": subject.get("CN"),
        "subjectO": subject.get("O"),
        "issuerCN": issuer.get("CN"),
        "expired": cert.get("expired"),
    }


def summarize_http(http: Any) -> dict[str, Any] | None:
    if not isinstance(http, dict):
        return None
    return {
        "title": http.get("title"),
        "server": http.get("server"),
        "host": http.get("host"),
        "location": http.get("location"),
        "status": http.get("status"),
    }


def host_lookup(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan host lookup requires confirm=true.")
    ip = args["ip"]
    params = {
        "history": str(bool(args.get("history", False))).lower(),
        "minify": str(bool(args.get("minify", False))).lower(),
    }
    payload = http_get_json(shodan_url(f"/shodan/host/{ip}", params), int(args.get("timeoutSeconds", 30)))
    result = summarize_host(payload) if not args.get("raw", False) else payload
    ingestion = maybe_ingest(args, ip, "shodan.host", result, {"ip": ip, "raw": bool(args.get("raw", False))})
    evidence.log_event("shodan.host", f"Looked up Shodan host {ip}", {"ip": ip, "workspaceId": ingestion.get("workspaceId") if ingestion else ""})
    return json.dumps(with_ingestion(result, ingestion), indent=2)


def internetdb_lookup(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan InternetDB lookup requires confirm=true.")
    ip = args["ip"]
    payload = http_get_json(f"{INTERNETDB_BASE}/{ip}", int(args.get("timeoutSeconds", 30)))
    result = summarize_internetdb(payload) if not args.get("raw", False) else payload
    ingestion = maybe_ingest(args, ip, "shodan.internetdb", result, {"ip": ip, "raw": bool(args.get("raw", False))})
    evidence.log_event("shodan.internetdb", f"Looked up InternetDB host {ip}", {"ip": ip, "workspaceId": ingestion.get("workspaceId") if ingestion else ""})
    return json.dumps(with_ingestion(result, ingestion), indent=2)


def summarize_internetdb(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "ip": payload.get("ip"),
        "hostnames": payload.get("hostnames", []),
        "ports": payload.get("ports", []),
        "cpes": payload.get("cpes", []),
        "vulns": payload.get("vulns", []),
        "tags": payload.get("tags", []),
    }


def domain_info(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan DNS domain lookup requires confirm=true.")
    domain = args["domain"]
    params = {
        "history": str(bool(args.get("history", False))).lower(),
        "type": args.get("type"),
        "page": int(args.get("page", 1)),
    }
    payload = http_get_json(shodan_url(f"/dns/domain/{domain}", params), int(args.get("timeoutSeconds", 30)))
    result = summarize_domain(payload) if not args.get("raw", False) else payload
    ingestion = maybe_ingest(args, domain, "shodan.domain", result, {"domain": domain, "raw": bool(args.get("raw", False))})
    evidence.log_event(
        "shodan.domain",
        f"Looked up Shodan DNS domain {domain}",
        {"domain": domain, "workspaceId": ingestion.get("workspaceId") if ingestion else ""},
    )
    return json.dumps(with_ingestion(result, ingestion), indent=2)


def summarize_domain(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data", [])
    records = []
    ips = set()
    values = set()
    for record in data[:500]:
        value = record.get("value")
        if record.get("type") in {"A", "AAAA"} and value:
            ips.add(value)
        if value:
            values.add(value)
        records.append(
            {
                "subdomain": record.get("subdomain"),
                "type": record.get("type"),
                "value": value,
                "lastSeen": record.get("last_seen"),
            }
        )
    return {
        "domain": payload.get("domain"),
        "tags": payload.get("tags", []),
        "subdomains": payload.get("subdomains", []),
        "more": payload.get("more"),
        "recordCountReturned": len(data),
        "uniqueIps": sorted(ips),
        "uniqueValuesSample": sorted(values)[:100],
        "records": records,
    }


def resolve(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan DNS resolve requires confirm=true.")
    hostnames = args["hostnames"]
    if isinstance(hostnames, list):
        hostnames = ",".join(hostnames)
    payload = http_get_json(shodan_url("/dns/resolve", {"hostnames": hostnames}), int(args.get("timeoutSeconds", 30)))
    evidence.log_event("shodan.resolve", "Resolved hostnames with Shodan DNS", {"hostnames": hostnames})
    return json.dumps(payload, indent=2)


def reverse(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan DNS reverse lookup requires confirm=true.")
    ips = args["ips"]
    if isinstance(ips, list):
        ips = ",".join(ips)
    payload = http_get_json(shodan_url("/dns/reverse", {"ips": ips}), int(args.get("timeoutSeconds", 30)))
    evidence.log_event("shodan.reverse", "Reverse-resolved IPs with Shodan DNS", {"ips": ips})
    return json.dumps(payload, indent=2)


def search_count(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan search count requires confirm=true.")
    query = args["query"]
    params = {"query": query, "facets": args.get("facets", "port,org,domain,asn")}
    payload = http_get_json(shodan_url("/shodan/host/count", params), int(args.get("timeoutSeconds", 30)))
    evidence.log_event("shodan.search_count", f"Counted Shodan query: {query}", {"query": query})
    return json.dumps(payload, indent=2)


def search_facets(args: dict[str, Any]) -> str:
    require_confirmed(args, "Listing Shodan search facets requires confirm=true.")
    payload = http_get_json(shodan_url("/shodan/host/search/facets", {}), int(args.get("timeoutSeconds", 30)))
    evidence.log_event("shodan.search_facets", "Listed Shodan search facets", {})
    return json.dumps({"facets": payload}, indent=2)


def search_filters(args: dict[str, Any]) -> str:
    require_confirmed(args, "Listing Shodan search filters requires confirm=true.")
    payload = http_get_json(shodan_url("/shodan/host/search/filters", {}), int(args.get("timeoutSeconds", 30)))
    evidence.log_event("shodan.search_filters", "Listed Shodan search filters", {})
    return json.dumps({"filters": payload}, indent=2)


def search(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan search requires confirm=true and may consume query credits.")
    query = args["query"]
    fields = args.get("fields", "ip_str,port,hostnames,domains,org,asn,transport,product,version,ssl.cert.subject,http.title,http.server,timestamp")
    params = {
        "query": query,
        "facets": args.get("facets"),
        "page": int(args.get("page", 1)),
        "minify": str(bool(args.get("minify", True))).lower(),
        "fields": fields,
    }
    payload = http_get_json(shodan_url("/shodan/host/search", params), int(args.get("timeoutSeconds", 30)))
    result = summarize_search(payload) if not args.get("raw", False) else payload
    ingest_target = args.get("target") or query_target_hint(query)
    ingestion = maybe_ingest(
        args,
        ingest_target,
        "shodan.search",
        result,
        {"query": query, "page": params["page"], "raw": bool(args.get("raw", False))},
    )
    evidence.log_event(
        "shodan.search",
        f"Searched Shodan query: {query}",
        {"query": query, "page": params["page"], "workspaceId": ingestion.get("workspaceId") if ingestion else ""},
    )
    return json.dumps(with_ingestion(result, ingestion), indent=2)


def target_summary(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan target summary requires confirm=true.")
    target = scope.normalize_host(args["target"])
    if not target:
        raise McpError(-32602, "target is required.")

    timeout_seconds = int(args.get("timeoutSeconds", 30))
    include_host = bool(args.get("includeHost", True))
    include_internetdb = bool(args.get("includeInternetDb", True))
    include_domain = bool(args.get("includeDomain", True))

    result: dict[str, Any] = {"target": target, "targetType": target_type(target)}
    resolved_ips: set[str] = set()

    if result["targetType"] == "ip":
        resolved_ips.add(target)
        if include_host:
            payload = http_get_json(
                shodan_url(
                    f"/shodan/host/{target}",
                    {
                        "history": str(bool(args.get("history", False))).lower(),
                        "minify": str(bool(args.get("minify", False))).lower(),
                    },
                ),
                timeout_seconds,
            )
            result["host"] = summarize_host(payload) if not args.get("raw", False) else payload
    else:
        if include_domain:
            domain_payload = http_get_json(
                shodan_url(
                    f"/dns/domain/{target}",
                    {
                        "history": str(bool(args.get("history", False))).lower(),
                        "type": args.get("type"),
                        "page": int(args.get("page", 1)),
                    },
                ),
                timeout_seconds,
            )
            domain_result = summarize_domain(domain_payload) if not args.get("raw", False) else domain_payload
            result["domain"] = domain_result
            for ip in domain_result.get("uniqueIps", []) if isinstance(domain_result, dict) else []:
                resolved_ips.add(ip)
        if include_host:
            resolved_payload = http_get_json(shodan_url("/dns/resolve", {"hostnames": target}), timeout_seconds)
            result["resolve"] = resolved_payload
            resolved_ip = resolved_payload.get(target) if isinstance(resolved_payload, dict) else None
            if resolved_ip:
                resolved_ips.add(resolved_ip)

    if include_internetdb:
        internetdb: dict[str, Any] = {}
        for ip in sorted(resolved_ips)[: int(args.get("maxInternetDbIps", 10))]:
            try:
                internetdb_payload = http_get_json(f"{INTERNETDB_BASE}/{ip}", timeout_seconds)
                internetdb[ip] = summarize_internetdb(internetdb_payload) if not args.get("raw", False) else internetdb_payload
            except McpError as exc:
                internetdb[ip] = {"error": exc.message}
        result["internetdb"] = internetdb

    result["openPorts"] = sorted(collect_ports(result))
    result["possibleCves"] = sorted(collect_vulns(result))
    result["ipLeakageCandidates"] = sorted(resolved_ips)
    ingestion = maybe_ingest(args, target, "shodan.target_summary", result, {"target": target, "raw": bool(args.get("raw", False))})
    evidence.log_event(
        "shodan.target_summary",
        f"Built Shodan target summary for {target}",
        {"target": target, "workspaceId": ingestion.get("workspaceId") if ingestion else ""},
    )
    return json.dumps(with_ingestion(result, ingestion), indent=2)


def maybe_ingest(
    args: dict[str, Any],
    target: str,
    source: str,
    result: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any] | None:
    if args.get("ingest") is False:
        return None
    workspace_id = args.get("workspaceId")
    if not workspace_id and args.get("ingest") is not True:
        return None
    normalized_target = scope.normalize_host(target)
    if not normalized_target:
        return None
    ingestion = workspace.ingest_data(
        workspace_id or workspace.default_workspace_id(),
        normalized_target,
        source,
        "osint",
        "json",
        json.dumps(result, indent=2, ensure_ascii=False),
        {"sourceKind": source, **metadata},
    )
    ingestion["workflowRefresh"] = fingerprint.refresh_workspace_target(ingestion["workspaceId"], ingestion["target"])
    return ingestion


def with_ingestion(result: Any, ingestion: dict[str, Any] | None) -> Any:
    if not ingestion:
        return result
    if isinstance(result, dict):
        return {**result, "ingestion": ingestion}
    return {"result": result, "ingestion": ingestion}


def query_target_hint(query: str) -> str:
    for prefix in ("hostname:", "domain:", "ssl.cert.subject.cn:"):
        marker = prefix
        if marker in query:
            value = query.split(marker, 1)[1].split()[0].strip('"')
            return value.lstrip("*.") if value else ""
    return ""


def target_type(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "hostname"


def collect_ports(value: Any) -> set[int]:
    ports: set[int] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            if key == "ports" and isinstance(nested, list):
                for port in nested:
                    if isinstance(port, int):
                        ports.add(port)
            else:
                ports.update(collect_ports(nested))
    elif isinstance(value, list):
        for item in value:
            ports.update(collect_ports(item))
    return ports


def collect_vulns(value: Any) -> set[str]:
    vulns: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in {"vulns", "cves"} and isinstance(nested, list):
                vulns.update(str(item) for item in nested if str(item).startswith("CVE-"))
            else:
                vulns.update(collect_vulns(nested))
    elif isinstance(value, list):
        for item in value:
            vulns.update(collect_vulns(item))
    return vulns


def summarize_search(payload: dict[str, Any]) -> dict[str, Any]:
    matches = []
    for match in payload.get("matches", [])[:100]:
        matches.append(
            {
                "ip": match.get("ip_str") or match.get("ip"),
                "port": match.get("port"),
                "hostnames": match.get("hostnames", [])[:10],
                "domains": match.get("domains", [])[:10],
                "org": match.get("org"),
                "asn": match.get("asn"),
                "product": match.get("product"),
                "version": match.get("version"),
                "timestamp": match.get("timestamp"),
                "httpTitle": (match.get("http") or {}).get("title") if isinstance(match.get("http"), dict) else None,
            }
        )
    return {"total": payload.get("total"), "facets": payload.get("facets", {}), "matches": matches}


def company_queries(args: dict[str, Any]) -> str:
    company = args.get("company", "").strip()
    domain = args.get("domain", "").strip()
    hostname = args.get("hostname", "").strip()
    org = args.get("org", company).strip()
    queries = []
    if domain:
        queries.extend(
            [
                {"purpose": "Hosts and services on domain", "query": f"hostname:{domain}"},
                {"purpose": "TLS certificates for domain", "query": f"ssl.cert.subject.cn:{domain}"},
                {"purpose": "Domain-tagged results", "query": f"domain:{domain}"},
            ]
        )
    if hostname:
        host = scope.normalize_host(hostname)
        queries.append({"purpose": "Specific hostname exposure", "query": f"hostname:{host}"})
    if org:
        quoted = quote_filter(org)
        queries.extend(
            [
                {"purpose": "Organization-owned exposed services", "query": f"org:{quoted}"},
                {"purpose": "TLS organization subject", "query": f"ssl.cert.subject.o:{quoted}"},
            ]
        )
    if company and not org:
        queries.append({"purpose": "Free-text company search", "query": quote_filter(company)})
    return json.dumps({"inputs": args, "queries": queries}, indent=2)


def quote_filter(value: str) -> str:
    if not value:
        return value
    if any(char.isspace() for char in value) and not (value.startswith('"') and value.endswith('"')):
        return json.dumps(value)
    return value
