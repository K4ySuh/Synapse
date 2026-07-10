# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import ipaddress
from collections import defaultdict
from typing import Any
from urllib.parse import urlencode

from ... import __version__
from ...core import evidence, fingerprint, scope, workspace
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import require_confirmed


API_BASE = "https://api.shodan.io"
INTERNETDB_BASE = "https://internetdb.shodan.io"
_SESSION_API_KEY = ""
USER_AGENT = f"Synapse-MCP/{__version__}"
DEFAULT_SEARCH_FIELDS = (
    "ip_str,port,hostnames,domains,org,isp,asn,transport,product,version,os,tags,"
    "cpe,cpe23,vulns,_shodan.module,location.country_name,location.city,"
    "ssl.cert.subject,ssl.cert.issuer,ssl.cert.expired,"
    "http.title,http.server,http.host,http.location,http.status,timestamp"
)


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
    response = http_client.send(HttpRequest(url=url, headers={"User-Agent": USER_AGENT}), policy=policy)
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


def normalize_ip(value: Any, field: str = "ip") -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise McpError(-32602, f"{field} must be a valid IPv4 or IPv6 address.") from exc


def normalize_hostname(value: Any, field: str = "hostname") -> str:
    host = scope.normalize_host(str(value)).strip().lower().rstrip(".")
    if not host or target_type(host) == "ip":
        raise McpError(-32602, f"{field} must be a hostname or domain.")
    return host


def clean_strings(value: Any, *, limit: int = 1000) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        values = []
    result: list[str] = []
    for item in values[:limit]:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def collect_cpes_from_value(*values: Any) -> list[str]:
    cpes: list[str] = []
    for value in values:
        for item in clean_strings(value):
            if item.startswith("cpe:") and item not in cpes:
                cpes.append(item)
    return cpes


def summarize_vulnerabilities(value: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if isinstance(value, dict):
        iterable = value.items()
    elif isinstance(value, list):
        iterable = ((item.get("cveId") or item.get("id"), item) if isinstance(item, dict) else (item, {} ) for item in value)
    else:
        iterable = []
    for raw_id, raw_metadata in iterable:
        cve_id = str(raw_id or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
        row = {
            "cveId": cve_id,
            "verified": bool(metadata.get("verified")),
            "cvss": metadata.get("cvss"),
            "summary": str(metadata.get("summary") or "")[:500],
            "references": clean_strings(metadata.get("references"), limit=20),
        }
        if row not in rows:
            rows.append(row)
    return rows


def relation(
    source_asset: str,
    target_asset: str,
    relation_type: str,
    *,
    source: str,
    confidence: str = "medium",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    left = str(source_asset or "").strip().lower().rstrip(".")
    right = str(target_asset or "").strip().lower().rstrip(".")
    if not left or not right or left == right:
        return None
    return {
        "sourceAsset": left,
        "targetAsset": right,
        "relationType": relation_type,
        "source": source,
        "confidence": confidence,
        **(metadata or {}),
    }


def dedupe_relations(items: list[dict[str, Any] | None]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        key = (
            str(item.get("sourceAsset", "")),
            str(item.get("targetAsset", "")),
            str(item.get("relationType", "")),
            str(item.get("source", "")),
        )
        deduped.setdefault(key, item)
    return sorted(deduped.values(), key=lambda item: (item["sourceAsset"], item["relationType"], item["targetAsset"]))


def summarize_host(payload: dict[str, Any]) -> dict[str, Any]:
    services: list[dict[str, Any]] = []
    all_cpes = collect_cpes_from_value(payload.get("cpes"), payload.get("cpe"), payload.get("cpe23"))
    for banner in payload.get("data", [])[:100] if isinstance(payload.get("data"), list) else []:
        if not isinstance(banner, dict):
            continue
        shodan_meta = banner.get("_shodan") if isinstance(banner.get("_shodan"), dict) else {}
        banner_cpes = collect_cpes_from_value(banner.get("cpes"), banner.get("cpe"), banner.get("cpe23"))
        for cpe in banner_cpes:
            if cpe not in all_cpes:
                all_cpes.append(cpe)
        services.append(
            {
                "port": banner.get("port"),
                "transport": banner.get("transport"),
                "product": banner.get("product"),
                "version": banner.get("version"),
                "module": shodan_meta.get("module"),
                "hostnames": clean_strings(banner.get("hostnames"), limit=10),
                "domains": clean_strings(banner.get("domains"), limit=10),
                "cpes": banner_cpes,
                "vulnerabilities": summarize_vulnerabilities(banner.get("vulns")),
                "timestamp": banner.get("timestamp"),
                "ssl": summarize_ssl(banner.get("ssl")),
                "http": summarize_http(banner.get("http")),
            }
        )
    ip = str(payload.get("ip_str") or payload.get("ip") or "")
    hostnames = clean_strings(payload.get("hostnames"))
    domains = clean_strings(payload.get("domains"))
    vulnerabilities = summarize_vulnerabilities(payload.get("vulns"))
    relations: list[dict[str, Any] | None] = []
    for hostname in hostnames:
        relations.append(relation(hostname, ip, "resolves_to", source="shodan.host", confidence="medium"))
        for domain in domains:
            if hostname == domain or hostname.endswith(f".{domain}"):
                relations.append(relation(hostname, domain, "belongs_to_domain", source="shodan.host", confidence="high"))
    return {
        "ip": ip,
        "org": payload.get("org"),
        "isp": payload.get("isp"),
        "asn": payload.get("asn"),
        "country": payload.get("country_name"),
        "city": payload.get("city"),
        "os": payload.get("os"),
        "tags": clean_strings(payload.get("tags")),
        "lastUpdate": payload.get("last_update"),
        "hostnames": hostnames,
        "domains": domains,
        "ports": sorted({int(port) for port in payload.get("ports", []) if isinstance(port, int)}),
        "cpes": all_cpes,
        "vulns": [item["cveId"] for item in vulnerabilities],
        "vulnerabilities": vulnerabilities,
        "services": services,
        "relations": dedupe_relations(relations),
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
        "subjectAltNames": clean_strings(cert.get("extensions", {}).get("subjectAltName") if isinstance(cert.get("extensions"), dict) else []),
        "issuerCN": issuer.get("CN"),
        "issuerO": issuer.get("O"),
        "expired": cert.get("expired"),
        "issued": cert.get("issued"),
        "expires": cert.get("expires"),
        "fingerprintSha256": (ssl.get("cert", {}).get("fingerprint", {}) or {}).get("sha256") if isinstance(ssl.get("cert"), dict) else None,
        "versions": clean_strings(ssl.get("versions")),
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
        "components": sorted((http.get("components") or {}).keys()) if isinstance(http.get("components"), dict) else [],
    }


def host_lookup(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan host lookup requires confirm=true.")
    ip = normalize_ip(args.get("ip"))
    params = {
        "history": str(bool(args.get("history", False))).lower(),
        "minify": str(bool(args.get("minify", False))).lower(),
    }
    payload = http_get_json(shodan_url(f"/shodan/host/{ip}", params), int(args.get("timeoutSeconds", 30)))
    summary = summarize_host(payload)
    result = payload if args.get("raw", False) else summary
    ingestion = maybe_ingest(args, ip, "shodan.host", summary, {"ip": ip, "rawResponseReturned": bool(args.get("raw", False))})
    evidence.log_event("shodan.host", f"Looked up Shodan host {ip}", {"ip": ip, "workspaceId": ingestion.get("workspaceId") if ingestion else ""})
    return json.dumps(with_ingestion(result, ingestion), indent=2)


def internetdb_lookup(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan InternetDB lookup requires confirm=true.")
    ip = normalize_ip(args.get("ip"))
    payload = http_get_json(f"{INTERNETDB_BASE}/{ip}", int(args.get("timeoutSeconds", 30)))
    summary = summarize_internetdb(payload)
    result = payload if args.get("raw", False) else summary
    ingestion = maybe_ingest(args, ip, "shodan.internetdb", summary, {"ip": ip, "rawResponseReturned": bool(args.get("raw", False))})
    evidence.log_event("shodan.internetdb", f"Looked up InternetDB host {ip}", {"ip": ip, "workspaceId": ingestion.get("workspaceId") if ingestion else ""})
    return json.dumps(with_ingestion(result, ingestion), indent=2)


def summarize_internetdb(payload: dict[str, Any]) -> dict[str, Any]:
    ip = str(payload.get("ip") or "")
    hostnames = clean_strings(payload.get("hostnames"))
    vulnerabilities = summarize_vulnerabilities(payload.get("vulns"))
    return {
        "ip": ip,
        "hostnames": hostnames,
        "ports": sorted({int(port) for port in payload.get("ports", []) if isinstance(port, int)}),
        "cpes": collect_cpes_from_value(payload.get("cpes")),
        "vulns": [item["cveId"] for item in vulnerabilities],
        "vulnerabilities": vulnerabilities,
        "tags": clean_strings(payload.get("tags")),
        "relations": dedupe_relations(
            [relation(hostname, ip, "resolves_to", source="shodan.internetdb", confidence="medium") for hostname in hostnames]
        ),
    }


def domain_info(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan DNS domain lookup requires confirm=true.")
    domain = normalize_hostname(args.get("domain"), "domain")
    params = {
        "history": str(bool(args.get("history", False))).lower(),
        "type": args.get("type"),
        "page": int(args.get("page", 1)),
    }
    payload = http_get_json(shodan_url(f"/dns/domain/{domain}", params), int(args.get("timeoutSeconds", 30)))
    summary = summarize_domain(payload)
    result = payload if args.get("raw", False) else summary
    ingestion = maybe_ingest(args, domain, "shodan.domain", summary, {"domain": domain, "rawResponseReturned": bool(args.get("raw", False))})
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
    relations: list[dict[str, Any] | None] = []
    for record in data[:500] if isinstance(data, list) else []:
        if not isinstance(record, dict):
            continue
        value = record.get("value")
        if record.get("type") in {"A", "AAAA"} and value:
            ips.add(value)
        if value:
            values.add(value)
        hostname = f"{record.get('subdomain')}.{payload.get('domain')}".strip(".") if record.get("subdomain") else str(payload.get("domain") or "")
        record_type = str(record.get("type") or "").upper()
        if hostname and value:
            relation_type = {"A": "resolves_to", "AAAA": "resolves_to", "CNAME": "aliases_to", "MX": "mail_routes_to", "NS": "delegated_to"}.get(record_type, "dns_record")
            relations.append(relation(hostname, str(value), relation_type, source="shodan.domain", confidence="high" if record_type in {"A", "AAAA", "CNAME"} else "medium"))
        records.append(
            {
                "subdomain": record.get("subdomain"),
                "hostname": hostname,
                "type": record_type,
                "value": value,
                "lastSeen": record.get("last_seen"),
            }
        )
    return {
        "domain": payload.get("domain"),
        "tags": payload.get("tags", []),
        "subdomains": payload.get("subdomains", []),
        "more": payload.get("more"),
        "recordCountReturned": len(data) if isinstance(data, list) else 0,
        "uniqueIps": sorted(ips),
        "uniqueValuesSample": sorted(values)[:100],
        "records": records,
        "relations": dedupe_relations(relations),
    }


def resolve(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan DNS resolve requires confirm=true.")
    hostnames = args["hostnames"]
    raw_hostnames = hostnames if isinstance(hostnames, list) else str(hostnames).split(",")
    normalized_hostnames = [normalize_hostname(item) for item in raw_hostnames if str(item).strip()]
    if not normalized_hostnames:
        raise McpError(-32602, "hostnames must contain at least one hostname.")
    hostnames = ",".join(normalized_hostnames)
    payload = http_get_json(shodan_url("/dns/resolve", {"hostnames": hostnames}), int(args.get("timeoutSeconds", 30)))
    evidence.log_event("shodan.resolve", "Resolved hostnames with Shodan DNS", {"hostnames": hostnames})
    return json.dumps(payload, indent=2)


def reverse(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan DNS reverse lookup requires confirm=true.")
    ips = args["ips"]
    raw_ips = ips if isinstance(ips, list) else str(ips).split(",")
    normalized_ips = [normalize_ip(item, "ips") for item in raw_ips if str(item).strip()]
    if not normalized_ips:
        raise McpError(-32602, "ips must contain at least one IP address.")
    ips = ",".join(normalized_ips)
    payload = http_get_json(shodan_url("/dns/reverse", {"ips": ips}), int(args.get("timeoutSeconds", 30)))
    evidence.log_event("shodan.reverse", "Reverse-resolved IPs with Shodan DNS", {"ips": ips})
    return json.dumps(payload, indent=2)


def search_count(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan search count requires confirm=true.")
    query = str(args.get("query") or "").strip()
    if not query:
        raise McpError(-32602, "query is required.")
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
    query = str(args.get("query") or "").strip()
    if not query:
        raise McpError(-32602, "query is required.")
    fields = args.get("fields", DEFAULT_SEARCH_FIELDS)
    params = {
        "query": query,
        "facets": args.get("facets"),
        "page": int(args.get("page", 1)),
        "minify": str(bool(args.get("minify", True))).lower(),
        "fields": fields,
    }
    payload = http_get_json(shodan_url("/shodan/host/search", params), int(args.get("timeoutSeconds", 30)))
    summary = summarize_search(payload)
    ingest_target = args.get("target") or query_target_hint(query)
    if ingest_target:
        seed = scope.normalize_host(str(ingest_target)).lower()
        seed_relations = []
        for match in summary.get("matches", []):
            asset = match_asset(match)
            seed_relations.append(
                relation(
                    seed,
                    asset,
                    "discovered_via_shodan_query",
                    source="shodan.search",
                    confidence="medium",
                    metadata={"query": query, "address": match.get("ip", "")},
                )
            )
        summary["relations"] = dedupe_relations([*summary.get("relations", []), *seed_relations])
    ingestions = maybe_ingest_search(
        args,
        str(ingest_target or ""),
        summary,
        {"query": query, "page": params["page"], "rawResponseReturned": bool(args.get("raw", False))},
    )
    evidence.log_event(
        "shodan.search",
        f"Searched Shodan query: {query}",
        {
            "query": query,
            "page": params["page"],
            "workspaceId": ingestions[0].get("workspaceId") if ingestions else "",
            "ingestedTargetCount": len(ingestions),
        },
    )
    result = payload if args.get("raw", False) else summary
    return json.dumps(with_ingestions(result, ingestions, preferred_target=str(ingest_target or "")), indent=2)


def target_summary(args: dict[str, Any]) -> str:
    require_confirmed(args, "Shodan target summary requires confirm=true.")
    target = scope.normalize_host(str(args.get("target") or "")).lower().rstrip(".")
    if not target:
        raise McpError(-32602, "target is required.")

    timeout_seconds = int(args.get("timeoutSeconds", 30))
    include_host = bool(args.get("includeHost", True))
    include_internetdb = bool(args.get("includeInternetDb", True))
    include_domain = bool(args.get("includeDomain", True))

    result: dict[str, Any] = {
        "target": target,
        "targetType": target_type(target),
        "sourceStatus": {},
    }
    raw_sources: dict[str, Any] = {}
    resolved_ips: set[str] = set()

    def collect_source(name: str, url: str) -> Any | None:
        try:
            payload = http_get_json(url, timeout_seconds)
        except McpError as exc:
            result["sourceStatus"][name] = {"status": "error", "error": exc.message}
            return None
        result["sourceStatus"][name] = {"status": "ok"}
        if args.get("raw", False):
            raw_sources[name] = payload
        return payload

    if result["targetType"] == "ip":
        target = normalize_ip(target, "target")
        result["target"] = target
        resolved_ips.add(target)
        if include_host:
            payload = collect_source(
                f"host:{target}",
                shodan_url(
                    f"/shodan/host/{target}",
                    {
                        "history": str(bool(args.get("history", False))).lower(),
                        "minify": str(bool(args.get("minify", False))).lower(),
                    },
                ),
            )
            if isinstance(payload, dict):
                result["host"] = summarize_host(payload)
    else:
        target = normalize_hostname(target, "target")
        result["target"] = target
        if include_domain:
            domain_target = normalize_hostname(args.get("domain") or target, "domain")
            domain_payload = collect_source(
                f"domain:{domain_target}",
                shodan_url(
                    f"/dns/domain/{domain_target}",
                    {
                        "history": str(bool(args.get("history", False))).lower(),
                        "type": args.get("type"),
                        "page": int(args.get("page", 1)),
                    },
                ),
            )
            if isinstance(domain_payload, dict):
                domain_result = summarize_domain(domain_payload)
                result["domain"] = domain_result
                for ip in domain_result.get("uniqueIps", []):
                    try:
                        resolved_ips.add(normalize_ip(ip))
                    except McpError:
                        continue
        resolved_payload = collect_source("resolve", shodan_url("/dns/resolve", {"hostnames": target}))
        result["resolve"] = resolved_payload or {}
        resolved_ip = resolved_payload.get(target) if isinstance(resolved_payload, dict) else None
        if resolved_ip:
            try:
                resolved_ips.add(normalize_ip(resolved_ip))
            except McpError:
                pass

        if include_host:
            hosts: dict[str, Any] = {}
            max_host_ips = min(max(int(args.get("maxHostIps", 3)), 0), 25)
            for ip in sorted(resolved_ips)[:max_host_ips]:
                host_payload = collect_source(
                    f"host:{ip}",
                    shodan_url(
                        f"/shodan/host/{ip}",
                        {
                            "history": str(bool(args.get("history", False))).lower(),
                            "minify": str(bool(args.get("minify", False))).lower(),
                        },
                    ),
                )
                if isinstance(host_payload, dict):
                    hosts[ip] = summarize_host(host_payload)
            result["hosts"] = hosts

    if include_internetdb:
        internetdb: dict[str, Any] = {}
        max_internetdb_ips = min(max(int(args.get("maxInternetDbIps", 10)), 0), 100)
        for ip in sorted(resolved_ips)[:max_internetdb_ips]:
            internetdb_payload = collect_source(f"internetdb:{ip}", f"{INTERNETDB_BASE}/{ip}")
            if isinstance(internetdb_payload, dict):
                internetdb[ip] = summarize_internetdb(internetdb_payload)
        result["internetdb"] = internetdb

    result["resolvedIps"] = sorted(resolved_ips)
    result["relations"] = dedupe_relations(
        [
            *collect_relations(result),
            *[
                relation(target, ip, "resolves_to", source="shodan.target_summary", confidence="high")
                for ip in sorted(resolved_ips)
            ],
        ]
    )
    result["openPorts"] = sorted(collect_ports(result))
    result["possibleCves"] = sorted(collect_vulns(result))
    # DNS resolution alone is not evidence that an address is an origin-IP leak.
    result["ipLeakageCandidates"] = []
    if raw_sources:
        result["rawSources"] = raw_sources
    ingestions = maybe_ingest_target_summary(
        args,
        target,
        result,
        {"target": target, "rawResponseReturned": bool(args.get("raw", False))},
    )
    evidence.log_event(
        "shodan.target_summary",
        f"Built Shodan target summary for {target}",
        {
            "target": target,
            "workspaceId": ingestions[0].get("workspaceId") if ingestions else "",
            "ingestedTargetCount": len(ingestions),
            "sourceStatus": result["sourceStatus"],
        },
    )
    return json.dumps(with_ingestions(result, ingestions, preferred_target=target), indent=2)


def maybe_ingest(
    args: dict[str, Any],
    target: str,
    source: str,
    result: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any] | None:
    if not ingestion_requested(args):
        return None
    normalized_target = scope.normalize_host(target)
    if not normalized_target:
        return None
    return ingest_payload(
        args,
        normalized_target,
        source,
        result,
        {"sourceKind": source, **metadata},
    )


def ingestion_requested(args: dict[str, Any]) -> bool:
    if args.get("ingest") is False:
        return False
    return bool(args.get("workspaceId")) or args.get("ingest") is True


def ingest_payload(
    args: dict[str, Any],
    target: str,
    source: str,
    result: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    ingestion = workspace.ingest_data(
        args.get("workspaceId") or workspace.default_workspace_id(),
        target,
        source,
        "osint",
        "json",
        json.dumps(result, indent=2, ensure_ascii=False),
        metadata,
    )
    ingestion["workflowRefresh"] = fingerprint.refresh_workspace_target(ingestion["workspaceId"], ingestion["target"])
    return ingestion


def match_asset(match: dict[str, Any], preferred: str = "") -> str:
    preferred_host = scope.normalize_host(preferred).lower() if preferred else ""
    hostnames = []
    for item in clean_strings(match.get("hostnames"), limit=20):
        hostname = item.lower().rstrip(".").removeprefix("*.")
        if hostname and hostname not in hostnames:
            hostnames.append(hostname)
    if preferred_host and preferred_host in hostnames:
        return preferred_host
    if hostnames:
        return hostnames[0]
    ip = str(match.get("ip") or match.get("ip_str") or "").strip()
    try:
        return normalize_ip(ip)
    except McpError:
        return ""


def payload_asset(payload: dict[str, Any], preferred: str = "") -> str:
    preferred_host = scope.normalize_host(preferred).lower() if preferred else ""
    hostnames = [item.lower().rstrip(".").removeprefix("*.") for item in clean_strings(payload.get("hostnames"), limit=20)]
    if preferred_host and preferred_host in hostnames:
        return preferred_host
    if hostnames:
        return hostnames[0]
    ip = str(payload.get("ip") or payload.get("ip_str") or "")
    try:
        return normalize_ip(ip)
    except McpError:
        return preferred_host


def collect_relations(value: Any) -> list[dict[str, Any]]:
    collected: list[dict[str, Any] | None] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            if key == "rawSources":
                continue
            if key == "relations" and isinstance(nested, list):
                collected.extend(item for item in nested if isinstance(item, dict))
            else:
                collected.extend(collect_relations(nested))
    elif isinstance(value, list):
        for item in value:
            collected.extend(collect_relations(item))
    return dedupe_relations(collected)


def relevant_relations(relations: list[dict[str, Any]], *assets: str) -> list[dict[str, Any]]:
    wanted = {scope.normalize_host(asset).lower() for asset in assets if scope.normalize_host(asset)}
    if not wanted:
        return []
    return [
        item
        for item in relations
        if str(item.get("sourceAsset", "")).lower() in wanted or str(item.get("targetAsset", "")).lower() in wanted
    ]


def maybe_ingest_search(
    args: dict[str, Any],
    seed_target: str,
    result: dict[str, Any],
    metadata: dict[str, Any],
) -> list[dict[str, Any]]:
    if not ingestion_requested(args):
        return []
    seed = scope.normalize_host(seed_target).lower() if seed_target else ""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for match in result.get("matches", []):
        if not isinstance(match, dict):
            continue
        asset = match_asset(match, seed)
        if asset:
            groups[asset].append(match)
    if seed:
        groups.setdefault(seed, [])
    ingestions: list[dict[str, Any]] = []
    relations = result.get("relations", []) if isinstance(result.get("relations"), list) else []
    for asset in sorted(groups):
        matches = groups[asset]
        payload = {
            "query": metadata.get("query", ""),
            "total": result.get("total"),
            "returned": len(matches),
            "matches": matches,
            "relations": relevant_relations(relations, asset, seed),
        }
        ingestions.append(
            ingest_payload(
                args,
                asset,
                "shodan.search",
                payload,
                {"sourceKind": "shodan.search", "seedTarget": seed, **metadata},
            )
        )
    return ingestions


def maybe_ingest_target_summary(
    args: dict[str, Any],
    target: str,
    result: dict[str, Any],
    metadata: dict[str, Any],
) -> list[dict[str, Any]]:
    if not ingestion_requested(args):
        return []
    groups: dict[str, dict[str, Any]] = {
        target: {
            "target": target,
            "targetType": result.get("targetType"),
            "domain": result.get("domain", {}),
            "resolve": result.get("resolve", {}),
            "resolvedIps": result.get("resolvedIps", []),
            "relations": result.get("relations", []),
            "sourceStatus": result.get("sourceStatus", {}),
        }
    }
    direct_host = result.get("host")
    if isinstance(direct_host, dict):
        asset = payload_asset(direct_host, target) or target
        groups.setdefault(asset, {"target": asset})["host"] = direct_host
    for ip, host_payload in result.get("hosts", {}).items() if isinstance(result.get("hosts"), dict) else []:
        if not isinstance(host_payload, dict):
            continue
        asset = payload_asset(host_payload, target) or str(ip)
        groups.setdefault(asset, {"target": asset})["host"] = host_payload
    for ip, internetdb_payload in result.get("internetdb", {}).items() if isinstance(result.get("internetdb"), dict) else []:
        if not isinstance(internetdb_payload, dict):
            continue
        asset = payload_asset(internetdb_payload, target) or str(ip)
        group = groups.setdefault(asset, {"target": asset})
        group.setdefault("internetdb", {})[str(ip)] = internetdb_payload

    relations = result.get("relations", []) if isinstance(result.get("relations"), list) else []
    ingestions: list[dict[str, Any]] = []
    for asset in sorted(groups):
        payload = groups[asset]
        payload["relations"] = relevant_relations(relations, asset, target)
        payload["openPorts"] = sorted(collect_ports(payload))
        payload["possibleCves"] = sorted(collect_vulns(payload))
        ingestions.append(
            ingest_payload(
                args,
                asset,
                "shodan.target_summary",
                payload,
                {"sourceKind": "shodan.target_summary", "seedTarget": target, **metadata},
            )
        )
    return ingestions


def with_ingestion(result: Any, ingestion: dict[str, Any] | None) -> Any:
    if not ingestion:
        return result
    if isinstance(result, dict):
        return {**result, "ingestion": ingestion}
    return {"result": result, "ingestion": ingestion}


def with_ingestions(result: Any, ingestions: list[dict[str, Any]], *, preferred_target: str = "") -> Any:
    if not ingestions:
        return result
    normalized_preferred = scope.normalize_host(preferred_target).lower() if preferred_target else ""
    primary = next((item for item in ingestions if item.get("target") == normalized_preferred), ingestions[0])
    if isinstance(result, dict):
        return {**result, "ingestion": primary, "ingestions": ingestions}
    return {"result": result, "ingestion": primary, "ingestions": ingestions}


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
                    try:
                        port_number = int(port)
                    except (TypeError, ValueError):
                        continue
                    if 1 <= port_number <= 65535:
                        ports.add(port_number)
            elif key == "port":
                try:
                    port_number = int(nested)
                except (TypeError, ValueError):
                    continue
                if 1 <= port_number <= 65535:
                    ports.add(port_number)
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
            if key in {"vulns", "cves", "vulnerabilities"}:
                vulns.update(item["cveId"] for item in summarize_vulnerabilities(nested))
            else:
                vulns.update(collect_vulns(nested))
    elif isinstance(value, list):
        for item in value:
            vulns.update(collect_vulns(item))
    return vulns


def summarize_search(payload: dict[str, Any]) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    relations: list[dict[str, Any] | None] = []
    for match in payload.get("matches", [])[:100] if isinstance(payload.get("matches"), list) else []:
        if not isinstance(match, dict):
            continue
        ip = str(match.get("ip_str") or match.get("ip") or "")
        hostnames = clean_strings(match.get("hostnames"), limit=10)
        domains = clean_strings(match.get("domains"), limit=10)
        shodan_meta = match.get("_shodan") if isinstance(match.get("_shodan"), dict) else {}
        vulnerabilities = summarize_vulnerabilities(match.get("vulns"))
        item = {
            "ip": ip,
            "port": match.get("port"),
            "hostnames": hostnames,
            "domains": domains,
            "org": match.get("org"),
            "isp": match.get("isp"),
            "asn": match.get("asn"),
            "transport": match.get("transport"),
            "product": match.get("product"),
            "version": match.get("version"),
            "module": shodan_meta.get("module"),
            "os": match.get("os"),
            "tags": clean_strings(match.get("tags")),
            "country": (match.get("location") or {}).get("country_name") if isinstance(match.get("location"), dict) else None,
            "city": (match.get("location") or {}).get("city") if isinstance(match.get("location"), dict) else None,
            "cpes": collect_cpes_from_value(match.get("cpes"), match.get("cpe"), match.get("cpe23")),
            "vulns": [row["cveId"] for row in vulnerabilities],
            "vulnerabilities": vulnerabilities,
            "timestamp": match.get("timestamp"),
            "http": summarize_http(match.get("http")),
            "ssl": summarize_ssl(match.get("ssl")),
        }
        item["httpTitle"] = item["http"].get("title") if isinstance(item.get("http"), dict) else None
        matches.append(item)
        for hostname in hostnames:
            relations.append(relation(hostname, ip, "resolves_to", source="shodan.search", confidence="medium"))
            for domain in domains:
                if hostname == domain or hostname.endswith(f".{domain}"):
                    relations.append(relation(hostname, domain, "belongs_to_domain", source="shodan.search", confidence="high"))
    assets = sorted({match_asset(item) for item in matches if match_asset(item)})
    return {
        "total": payload.get("total"),
        "returned": len(matches),
        "assetCount": len(assets),
        "assets": assets,
        "facets": payload.get("facets", {}),
        "matches": matches,
        "relations": dedupe_relations(relations),
    }


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
