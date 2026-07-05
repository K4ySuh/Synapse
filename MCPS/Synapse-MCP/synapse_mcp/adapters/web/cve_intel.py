# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from typing import Any, Callable
from urllib import parse

from ...core import evidence, workspace
from ...core.adapters import AdapterResult, RecommendedTest, WorkspaceEntityBundle, candidate_observation
from ...core.errors import McpError
from ...core.http import HttpClientPolicy, HttpRequest, http_client
from ..command_utils import approval_metadata, require_confirmed, require_in_scope
from .active_probe import build_http_request, build_manual_replay, redact_headers, response_summary, stable_slug, store_http_exchange_evidence
from . import nuclei_adapter


_SOURCE_CONFIG: dict[str, tuple[str, str]] = {
    "nvd": ("SYNAPSE_CVE_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
    "cisa_kev": ("SYNAPSE_CVE_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
    "poc_github_index": ("SYNAPSE_CVE_POC_GITHUB_URL", "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cveId}.json"),
    "github_search": ("SYNAPSE_CVE_GITHUB_SEARCH_URL", "https://api.github.com/search/repositories"),
    "searchsploit": ("SYNAPSE_CVE_SEARCHSPLOIT_BIN", "searchsploit"),
}
_DEFAULT_SOURCES = "nvd,shodan,poc_github_index,cisa_kev"
_ENDPOINT_OVERRIDES: dict[str, str] = {}
_SESSION_KEYS: dict[str, str] = {}
_LAST_SOURCE_STATUS: dict[str, dict[str, Any]] = {}
_LAST_FETCH_CONTEXT: dict[str, dict[str, Any]] = {}


class SourceFetchError(Exception):
    def __init__(self, source: str, url: str, detail: str, *, http_status: int | None = None, resolved_from: str = "") -> None:
        super().__init__(detail)
        self.source = source
        self.url = url
        self.detail = detail
        self.http_status = http_status
        self.resolved_from = resolved_from


class SourceSkipped(Exception):
    def __init__(self, source: str, detail: str) -> None:
        super().__init__(detail)
        self.source = source
        self.detail = detail


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("cve"), indent=2)


def _known_sources() -> set[str]:
    return {"shodan", *set(_SOURCE_CONFIG)}


def _resolve_source_config(source: str) -> dict[str, str]:
    normalized = str(source).strip().lower()
    if normalized == "shodan":
        return {"source": "shodan", "url": "workspace", "envVar": "", "resolvedFrom": "default"}
    if normalized not in _SOURCE_CONFIG:
        raise McpError(-32602, f"Unknown CVE source: {source}")
    env_var, baked_default = _SOURCE_CONFIG[normalized]
    if normalized in _ENDPOINT_OVERRIDES:
        return {"source": normalized, "url": _ENDPOINT_OVERRIDES[normalized], "envVar": env_var, "resolvedFrom": "override"}
    env_value = os.environ.get(env_var, "").strip()
    if env_value:
        return {"source": normalized, "url": env_value, "envVar": env_var, "resolvedFrom": "env"}
    return {"source": normalized, "url": baked_default, "envVar": env_var, "resolvedFrom": "default"}


def _enabled_sources(args: dict[str, Any] | None = None) -> list[str]:
    args = args or {}
    configured = args.get("sources")
    if isinstance(configured, str):
        raw = configured
    elif isinstance(configured, list):
        raw = ",".join(str(item) for item in configured)
    else:
        raw = os.environ.get("SYNAPSE_CVE_SOURCES", _DEFAULT_SOURCES)
    sources = []
    for item in raw.split(","):
        source = item.strip().lower()
        if not source:
            continue
        if source not in _known_sources():
            raise McpError(-32602, f"Unknown CVE source: {source}")
        if source not in sources:
            sources.append(source)
    return sources


def sources(args: dict[str, Any] | None = None) -> str:
    args = args or {}
    enabled = set(_enabled_sources(args))
    payload = {}
    for source in sorted(_known_sources()):
        resolved = _resolve_source_config(source)
        payload[source] = {
            "enabled": source in enabled,
            "url": resolved["url"],
            "resolvedFrom": resolved["resolvedFrom"],
            "envVar": resolved.get("envVar", ""),
            "lastStatus": _LAST_SOURCE_STATUS.get(source, {}),
        }
    return json.dumps({"sources": payload, "defaultEnabled": _enabled_sources({})}, indent=2)


def set_source_endpoint(args: dict[str, Any]) -> str:
    require_confirmed(args, "Changing a CVE source endpoint requires confirm=true.")
    source = str(args.get("source", "")).strip().lower()
    url = str(args.get("url", "")).strip()
    if source not in _SOURCE_CONFIG:
        raise McpError(-32602, f"Unknown endpoint-configurable CVE source: {source}")
    if not url:
        raise McpError(-32602, "url is required.")
    _ENDPOINT_OVERRIDES[source] = url
    resolved = _resolve_source_config(source)
    _LAST_SOURCE_STATUS[source] = _source_status(source, "ok", resolved, detail="runtime endpoint override set")
    return json.dumps({"source": source, "url": url, "resolvedFrom": "override", "persisted": False}, indent=2)


def reset_source_endpoint(args: dict[str, Any]) -> str:
    require_confirmed(args, "Resetting a CVE source endpoint requires confirm=true.")
    source = str(args.get("source", "")).strip().lower()
    if source not in _SOURCE_CONFIG:
        raise McpError(-32602, f"Unknown endpoint-configurable CVE source: {source}")
    _ENDPOINT_OVERRIDES.pop(source, None)
    resolved = _resolve_source_config(source)
    _LAST_SOURCE_STATUS[source] = _source_status(source, "ok", resolved, detail="runtime endpoint override cleared")
    return json.dumps({"source": source, "url": resolved["url"], "resolvedFrom": resolved["resolvedFrom"], "persisted": False}, indent=2)


def set_session_key(args: dict[str, Any]) -> str:
    require_confirmed(args, "Setting a CVE source session key requires confirm=true.")
    provider = str(args.get("provider", "")).strip().lower()
    if provider not in {"nvd", "github"}:
        raise McpError(-32602, "provider must be one of: nvd, github.")
    api_key = str(args.get("apiKey", "")).strip()
    if not api_key:
        raise McpError(-32602, "apiKey is required.")
    _SESSION_KEYS[provider] = api_key
    return json.dumps({"provider": provider, "configured": True, "source": "session", "persisted": False}, indent=2)


def clear_session_key(args: dict[str, Any]) -> str:
    require_confirmed(args, "Clearing a CVE source session key requires confirm=true.")
    provider = str(args.get("provider", "")).strip().lower()
    if provider not in {"nvd", "github"}:
        raise McpError(-32602, "provider must be one of: nvd, github.")
    _SESSION_KEYS.pop(provider, None)
    return json.dumps({"provider": provider, "configured": False, "sessionCleared": True, "persisted": False}, indent=2)


def session_key_status(_: dict[str, Any] | None = None) -> str:
    return json.dumps(
        {
            "providers": {
                "nvd": {"configured": bool(_SESSION_KEYS.get("nvd")), "source": "session" if _SESSION_KEYS.get("nvd") else None, "persisted": False},
                "github": {"configured": bool(_SESSION_KEYS.get("github")), "source": "session" if _SESSION_KEYS.get("github") else None, "persisted": False},
            }
        },
        indent=2,
    )


def correlate(args: dict[str, Any]) -> str:
    require_confirmed(args, "CVE correlation touches third-party intelligence sources and requires confirm=true.")
    workspace_id = workspace.normalize_workspace_id(args["workspaceId"])
    target = workspace.normalize_target(args["target"])
    entities = workspace._load_target_entities(workspace_id, target)
    components = _technology_components(entities)
    observations = [item for item in entities.get("observations", []) if isinstance(item, dict)]
    selected = _enabled_sources(args)
    source_status: dict[str, dict[str, Any]] = {}
    discovery_records: list[dict[str, Any]] = []
    discovery_returned = False

    discovery_args = {**args, "_workspaceId": workspace_id, "_target": target, "_observations": observations}
    for source in selected:
        if source not in DISCOVERY_SOURCES:
            continue
        records = _run_discovery_source(source, DISCOVERY_SOURCES[source], components, discovery_args, source_status)
        discovery_returned = discovery_returned or bool(records)
        discovery_records.extend(records)

    merged = _merge_discovery_records(discovery_records)
    cve_ids = sorted({item["cveId"] for item in merged})
    enrichment: dict[str, dict[str, Any]] = {}
    for source in selected:
        if source not in ENRICHMENT_SOURCES:
            continue
        data = _run_enrichment_source(source, ENRICHMENT_SOURCES[source], cve_ids, {**args, "_workspaceId": workspace_id, "_target": target}, source_status)
        _merge_enrichment(enrichment, data)

    candidates = [_candidate_from_record(item, enrichment.get(item["cveId"], {}), source_status) for item in merged]
    result = AdapterResult(
        adapter="cve",
        mode="passive_analysis",
        workspace_id=workspace_id,
        target=target,
        summary=f"Correlated {len(candidates)} CVE candidate exposure(s) from {len(selected)} source(s).",
        entities=WorkspaceEntityBundle(observations=[item["observation"] for item in candidates]),
        recommended_tests=recommended_tests(),
        limitations=[
            "CVE presence in public intelligence does not prove exploitability on this target.",
            "PoC references are stored as read-only evidence and are never fetched or executed by Synapse.",
            "Online lookups send only product, version, CPE, and CVE identifiers to third-party sources.",
        ],
        metadata={"sourceStatus": source_status, "sources": selected, "cveDataAvailable": discovery_returned},
    )
    payload = {
        **result.as_ingest_payload(),
        "candidates": [item["candidate"] for item in candidates],
        "candidateCount": len(candidates),
        "sourceStatus": source_status,
        "sources": selected,
        "cveDataAvailable": discovery_returned,
    }
    ingestion = None
    if args.get("ingest", True):
        ingestion = workspace.ingest_data(
            workspace_id,
            target,
            "adapter_result",
            "passive_analysis",
            "json",
            json.dumps(payload, indent=2, ensure_ascii=False),
            {"adapter": "cve", "sources": selected, "sourceStatus": source_status},
        )
    evidence.log_event(
        "cve.correlate",
        f"Correlated CVE candidates for {target}.",
        {"workspaceId": workspace_id, "target": target, "candidateCount": len(candidates), "sources": selected},
    )
    return json.dumps({**payload, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def _technology_components(entities: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    components = []
    seen = set()
    for observation in entities.get("observations", []):
        if not isinstance(observation, dict) or observation.get("type") != "technology_component":
            continue
        name = str(observation.get("name") or observation.get("value") or "").strip()
        if not name:
            continue
        version = str(observation.get("version", "") or "").strip()
        key = (name.lower(), version.lower(), str(observation.get("cpe", "")).lower())
        if key in seen:
            continue
        seen.add(key)
        components.append(
            {
                "name": name,
                "version": version,
                "cpe": str(observation.get("cpe", "") or ""),
                "versionPrecision": str(observation.get("versionPrecision", "unknown") or "unknown"),
                "confidence": str(observation.get("confidence", "low") or "low"),
                "evidenceIds": observation.get("evidenceIds", []),
            }
        )
    return components


def _run_discovery_source(
    source: str,
    fn: Callable[[list[dict[str, Any]], dict[str, Any]], list[dict[str, Any]]],
    components: list[dict[str, Any]],
    args: dict[str, Any],
    source_status: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    resolved = _resolve_source_config(source)
    try:
        records = fn(components, args)
    except SourceSkipped as exc:
        status = _source_status(source, f"skipped: {exc.detail}", resolved, detail=exc.detail)
        source_status[source] = status
        _LAST_SOURCE_STATUS[source] = status
        return []
    except SourceFetchError as exc:
        status = _source_status(source, "error", {"url": exc.url, "resolvedFrom": exc.resolved_from or resolved["resolvedFrom"]}, http_status=exc.http_status, detail=exc.detail)
        source_status[source] = status
        _LAST_SOURCE_STATUS[source] = status
        return []
    except Exception as exc:
        status = _source_status(source, "error", resolved, detail=str(exc))
        source_status[source] = status
        _LAST_SOURCE_STATUS[source] = status
        return []
    context = _LAST_FETCH_CONTEXT.get(source, resolved)
    status = _source_status(source, "ok", {"url": context.get("url", resolved["url"]), "resolvedFrom": context.get("resolvedFrom", resolved["resolvedFrom"])}, http_status=context.get("httpStatus"))
    source_status[source] = status
    _LAST_SOURCE_STATUS[source] = status
    return records


def _run_enrichment_source(
    source: str,
    fn: Callable[[list[str], dict[str, Any]], dict[str, dict[str, Any]]],
    cve_ids: list[str],
    args: dict[str, Any],
    source_status: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    resolved = _resolve_source_config(source)
    if not cve_ids:
        status = _source_status(source, "skipped: no CVEs discovered", resolved, detail="no CVEs discovered")
        source_status[source] = status
        _LAST_SOURCE_STATUS[source] = status
        return {}
    try:
        records = fn(cve_ids, args)
    except SourceSkipped as exc:
        status = _source_status(source, f"skipped: {exc.detail}", resolved, detail=exc.detail)
        source_status[source] = status
        _LAST_SOURCE_STATUS[source] = status
        return {}
    except SourceFetchError as exc:
        status = _source_status(source, "error", {"url": exc.url, "resolvedFrom": exc.resolved_from or resolved["resolvedFrom"]}, http_status=exc.http_status, detail=exc.detail)
        source_status[source] = status
        _LAST_SOURCE_STATUS[source] = status
        return {}
    except Exception as exc:
        status = _source_status(source, "error", resolved, detail=str(exc))
        source_status[source] = status
        _LAST_SOURCE_STATUS[source] = status
        return {}
    context = _LAST_FETCH_CONTEXT.get(source, resolved)
    status = _source_status(source, "ok", {"url": context.get("url", resolved["url"]), "resolvedFrom": context.get("resolvedFrom", resolved["resolvedFrom"])}, http_status=context.get("httpStatus"))
    source_status[source] = status
    _LAST_SOURCE_STATUS[source] = status
    return records


def _source_status(source: str, status: str, resolved: dict[str, Any], *, http_status: Any = None, detail: str = "") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": status,
        "url": str(resolved.get("url", "")),
        "resolvedFrom": str(resolved.get("resolvedFrom", "default")),
    }
    if http_status is not None:
        payload["httpStatus"] = http_status
    if detail:
        payload["detail"] = detail
    return payload


def _cache_file(workspace_id: str, target: str, source: str, query: Any) -> Any:
    digest = hashlib.sha256(json.dumps(query, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()[:20]
    cache_dir = workspace.target_output_dir(workspace_id, target, "cve-cache")
    return cache_dir / f"{source}_{digest}.json"


def _fetch_json_source(source: str, query: Any, url: str, args: dict[str, Any], *, headers: dict[str, str] | None = None) -> Any:
    workspace_id = str(args.get("_workspaceId") or args.get("workspaceId") or workspace.default_workspace_id())
    target = str(args.get("_target") or args.get("target") or "cve-intel")
    resolved = _resolve_source_config(source)
    cache_path = _cache_file(workspace_id, target, source, {"url": url, "query": query})
    if args.get("refresh") is not True and cache_path.exists():
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        _LAST_FETCH_CONTEXT[source] = {"url": cached.get("url", url), "resolvedFrom": cached.get("resolvedFrom", resolved["resolvedFrom"]), "httpStatus": cached.get("httpStatus", 200)}
        return cached.get("payload")

    policy = HttpClientPolicy.from_args(args, timeout_seconds=float(args.get("requestTimeout", 20)))
    policy.max_body_bytes = max(policy.max_body_bytes, int(args.get("maxBodyBytes", 5_000_000)))
    request_headers = {"User-Agent": "Synapse-MCP/0.1", **(headers or {})}
    response = http_client.send(HttpRequest(url=url, headers=request_headers), policy=policy)
    _LAST_FETCH_CONTEXT[source] = {"url": url, "resolvedFrom": resolved["resolvedFrom"], "httpStatus": response.status}
    if response.status is None:
        raise SourceFetchError(source, url, response.error or "request failed", resolved_from=resolved["resolvedFrom"])
    if response.status >= 400:
        raise SourceFetchError(source, url, response.body[:500] or f"HTTP {response.status}", http_status=response.status, resolved_from=resolved["resolvedFrom"])
    try:
        payload = json.loads(response.body or "{}")
    except json.JSONDecodeError as exc:
        raise SourceFetchError(source, url, f"response was not JSON: {exc}", http_status=response.status, resolved_from=resolved["resolvedFrom"]) from exc

    evidence_record = workspace.store_raw_evidence(
        workspace_id,
        target,
        f"cve_{source}",
        "cve_intelligence",
        "json",
        json.dumps(payload, indent=2, ensure_ascii=False),
        {"source": source, "url": url, "query": query, "resolvedFrom": resolved["resolvedFrom"], "httpStatus": response.status},
    )
    cache_path.write_text(
        json.dumps(
            {
                "source": source,
                "url": url,
                "query": query,
                "resolvedFrom": resolved["resolvedFrom"],
                "httpStatus": response.status,
                "evidence": evidence_record,
                "payload": payload,
                "cachedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return payload


def _fetch_nvd(query: dict[str, Any], args: dict[str, Any]) -> Any:
    resolved = _resolve_source_config("nvd")
    params = {key: value for key, value in query.items() if value}
    url = f"{resolved['url']}?{parse.urlencode(params)}"
    headers = {"apiKey": _SESSION_KEYS["nvd"]} if _SESSION_KEYS.get("nvd") else None
    return _fetch_json_source("nvd", query, url, args, headers=headers)


def _fetch_cisa_kev(args: dict[str, Any]) -> Any:
    resolved = _resolve_source_config("cisa_kev")
    return _fetch_json_source("cisa_kev", {"feed": "known_exploited_vulnerabilities"}, resolved["url"], args)


def _fetch_poc_github_index(cve_id: str, args: dict[str, Any]) -> Any:
    resolved = _resolve_source_config("poc_github_index")
    year = _cve_year(cve_id)
    url = resolved["url"].format(year=year, cveId=cve_id)
    return _fetch_json_source("poc_github_index", {"cveId": cve_id, "year": year}, url, args)


def _fetch_github_search(cve_id: str, args: dict[str, Any]) -> Any:
    if not _SESSION_KEYS.get("github"):
        raise SourceSkipped("github_search", "no token")
    resolved = _resolve_source_config("github_search")
    query = {"q": f"{cve_id} in:name,description,readme", "per_page": int(args.get("githubPerPage", 5))}
    url = f"{resolved['url']}?{parse.urlencode(query)}"
    return _fetch_json_source("github_search", query, url, args, headers={"Authorization": f"Bearer {_SESSION_KEYS['github']}"})


def _discover_nvd(components: list[dict[str, Any]], args: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    min_cvss = float(args.get("minCvss", 0) or 0)
    for component in components:
        name = str(component.get("name", "")).strip()
        version = str(component.get("version", "")).strip()
        cpe = str(component.get("cpe", "")).strip()
        if not name:
            continue
        query = {"cvssV3Severity": "", "resultsPerPage": int(args.get("nvdResultsPerComponent", 20))}
        if cpe and "*" not in cpe.split(":")[5:6]:
            query["cpeName"] = cpe
        else:
            query["keywordSearch"] = " ".join([name, version]).strip()
        payload = _fetch_nvd(query, args)
        if isinstance(payload, dict) and int(payload.get("httpStatus", 0) or 0) >= 400:
            resolved = _resolve_source_config("nvd")
            raise SourceFetchError("nvd", resolved["url"], str(payload.get("detail") or payload.get("body") or "HTTP error"), http_status=int(payload["httpStatus"]), resolved_from=resolved["resolvedFrom"])
        for item in payload.get("vulnerabilities", []) if isinstance(payload, dict) else []:
            cve = item.get("cve", {}) if isinstance(item, dict) else {}
            cve_id = _normalize_cve_id(cve.get("id", ""))
            if not cve_id:
                continue
            cvss, severity = _cvss_from_nvd(cve)
            if cvss is not None and cvss < min_cvss:
                continue
            references, exploit_refs = _references_from_nvd(cve)
            records.append(
                {
                    "cveId": cve_id,
                    "cvss": cvss,
                    "severity": severity,
                    "summary": _summary_from_nvd(cve),
                    "references": references,
                    "exploitReferences": exploit_refs,
                    "publishedDate": str(cve.get("published", "")),
                    "component": name,
                    "version": version,
                    "cpe": cpe,
                    "versionPrecision": component.get("versionPrecision", "unknown"),
                    "source": "nvd",
                    "discoverySources": ["nvd"],
                    "evidenceIds": component.get("evidenceIds", []),
                }
            )
    return records


def _discover_shodan(components: list[dict[str, Any]], args: dict[str, Any]) -> list[dict[str, Any]]:
    observations = args.get("_observations", [])
    cves = []
    for observation in observations if isinstance(observations, list) else []:
        if not isinstance(observation, dict) or observation.get("type") != "possible_cve":
            continue
        cve_id = _normalize_cve_id(observation.get("value", ""))
        if cve_id and cve_id not in cves:
            cves.append(cve_id)
    if not cves:
        return []
    if len(components) == 1:
        component = components[0]
        component_name = str(component.get("name", ""))
        version = str(component.get("version", ""))
        cpe = str(component.get("cpe", ""))
        precision = str(component.get("versionPrecision", "unknown"))
    else:
        component_name = "Shodan-reported exposure"
        version = ""
        cpe = ""
        precision = "shodan_asserted"
    return [
        {
            "cveId": cve_id,
            "cvss": None,
            "severity": "",
            "summary": "Reported by Shodan/InternetDB and requires validation before being treated as a finding.",
            "references": [],
            "exploitReferences": [],
            "publishedDate": "",
            "component": component_name,
            "version": version,
            "cpe": cpe,
            "versionPrecision": precision,
            "source": "shodan",
            "discoverySources": ["shodan"],
            "evidenceIds": [],
        }
        for cve_id in cves
    ]


def _enrich_cisa_kev(cve_ids: list[str], args: dict[str, Any]) -> dict[str, dict[str, Any]]:
    payload = _fetch_cisa_kev(args)
    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    wanted = set(cve_ids)
    enriched = {}
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = _normalize_cve_id(item.get("cveID", "") or item.get("cveId", ""))
        if cve_id not in wanted:
            continue
        enriched[cve_id] = {
            "knownExploited": True,
            "notes": [
                str(item.get("vulnerabilityName", "")),
                str(item.get("requiredAction", "")),
                str(item.get("dueDate", "")),
            ],
            "source": "cisa_kev",
        }
    return enriched


def _enrich_poc_github_index(cve_ids: list[str], args: dict[str, Any]) -> dict[str, dict[str, Any]]:
    enriched = {}
    for cve_id in cve_ids:
        try:
            payload = _fetch_poc_github_index(cve_id, args)
        except SourceFetchError as exc:
            if exc.http_status == 404:
                continue
            raise
        refs = _poc_refs_from_payload(payload, "poc_github_index")
        if refs:
            enriched[cve_id] = {"pocReferences": refs, "source": "poc_github_index"}
    return enriched


def _enrich_github_search(cve_ids: list[str], args: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not _SESSION_KEYS.get("github"):
        raise SourceSkipped("github_search", "no token")
    enriched = {}
    for cve_id in cve_ids:
        payload = _fetch_github_search(cve_id, args)
        items = payload.get("items", []) if isinstance(payload, dict) else []
        refs = []
        for item in items[:10]:
            if not isinstance(item, dict):
                continue
            url = str(item.get("html_url", "") or "")
            if url:
                refs.append({"source": "github_search", "url": url, "stars": int(item.get("stargazers_count", 0) or 0)})
        if refs:
            enriched[cve_id] = {"pocReferences": refs, "source": "github_search"}
    return enriched


def _enrich_searchsploit(cve_ids: list[str], args: dict[str, Any]) -> dict[str, dict[str, Any]]:
    resolved = _resolve_source_config("searchsploit")
    binary = shutil.which(resolved["url"]) if "/" not in resolved["url"] else resolved["url"]
    if not binary:
        raise SourceSkipped("searchsploit", "searchsploit not installed")
    enriched = {}
    timeout = int(args.get("searchsploitTimeout", 10))
    for cve_id in cve_ids:
        proc = subprocess.run([binary, "--cve", cve_id, "--json"], capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode not in {0, 1}:
            continue
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            continue
        refs = _searchsploit_refs(payload)
        if refs:
            enriched[cve_id] = {"pocReferences": refs, "exploitReferences": refs, "source": "searchsploit"}
    _LAST_FETCH_CONTEXT["searchsploit"] = {"url": resolved["url"], "resolvedFrom": resolved["resolvedFrom"], "httpStatus": None}
    return enriched


DISCOVERY_SOURCES: dict[str, Callable[[list[dict[str, Any]], dict[str, Any]], list[dict[str, Any]]]] = {
    "nvd": lambda components, args: _discover_nvd(components, args),
    "shodan": lambda components, args: _discover_shodan(components, args),
}
ENRICHMENT_SOURCES: dict[str, Callable[[list[str], dict[str, Any]], dict[str, dict[str, Any]]]] = {
    "cisa_kev": lambda cve_ids, args: _enrich_cisa_kev(cve_ids, args),
    "poc_github_index": lambda cve_ids, args: _enrich_poc_github_index(cve_ids, args),
    "github_search": lambda cve_ids, args: _enrich_github_search(cve_ids, args),
    "searchsploit": lambda cve_ids, args: _enrich_searchsploit(cve_ids, args),
}


def _merge_discovery_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for record in records:
        cve_id = _normalize_cve_id(record.get("cveId", ""))
        component = str(record.get("component", "") or "")
        version = str(record.get("version", "") or "")
        cpe = str(record.get("cpe", "") or "")
        if not cve_id or not component:
            continue
        key = (cve_id, component, version, cpe)
        existing = merged.setdefault(
            key,
            {
                **record,
                "cveId": cve_id,
                "discoverySources": [],
                "references": [],
                "exploitReferences": [],
                "evidenceIds": [],
            },
        )
        for source in record.get("discoverySources", [record.get("source", "")]):
            if source and source not in existing["discoverySources"]:
                existing["discoverySources"].append(source)
        for field in ("references", "exploitReferences", "evidenceIds"):
            for value in record.get(field, []):
                if value and value not in existing[field]:
                    existing[field].append(value)
        if record.get("cvss") is not None and (existing.get("cvss") is None or float(record["cvss"]) > float(existing.get("cvss") or 0)):
            existing["cvss"] = float(record["cvss"])
            existing["severity"] = record.get("severity", "")
        if record.get("summary") and not existing.get("summary"):
            existing["summary"] = record["summary"]
        if record.get("publishedDate") and not existing.get("publishedDate"):
            existing["publishedDate"] = record["publishedDate"]
    return sorted(merged.values(), key=lambda item: (item["cveId"], item["component"], item.get("version", "")))


def _merge_enrichment(target: dict[str, dict[str, Any]], incoming: dict[str, dict[str, Any]]) -> None:
    for cve_id, data in incoming.items():
        cve_id = _normalize_cve_id(cve_id)
        if not cve_id:
            continue
        record = target.setdefault(cve_id, {"knownExploited": False, "pocReferences": [], "exploitReferences": [], "notes": [], "sources": []})
        if data.get("knownExploited"):
            record["knownExploited"] = True
        source = data.get("source")
        if source and source not in record["sources"]:
            record["sources"].append(source)
        for field in ("pocReferences", "exploitReferences", "notes"):
            for value in data.get(field, []):
                if value and value not in record[field]:
                    record[field].append(value)


def _candidate_from_record(record: dict[str, Any], enrichment: dict[str, Any], source_status: dict[str, dict[str, Any]]) -> dict[str, Any]:
    cve_id = record["cveId"]
    component = str(record.get("component", ""))
    version = str(record.get("version", ""))
    cvss = record.get("cvss")
    cvss_score = float(cvss) if cvss is not None else 0.0
    known_exploited = bool(enrichment.get("knownExploited"))
    poc_refs = list(enrichment.get("pocReferences", []))
    exploit_refs = list(record.get("exploitReferences", []))
    for ref in enrichment.get("exploitReferences", []):
        if ref not in exploit_refs:
            exploit_refs.append(ref)
    exploit_maturity = _exploit_maturity(known_exploited, poc_refs, exploit_refs)
    priority, priority_score, tags = _priority(cvss_score, known_exploited, bool(poc_refs))
    confidence = _applicability_confidence(record)
    candidate_id = f"cve_{cve_id}_{stable_slug(component)}_{stable_slug(version)}"
    reason = _candidate_reason(cve_id, component, version, confidence, exploit_maturity)
    summary = str(record.get("summary", ""))[:300]
    metadata = {
        "candidateId": candidate_id,
        "cveId": cve_id,
        "cvssScore": cvss_score if cvss is not None else None,
        "cvssSeverity": record.get("severity", ""),
        "component": component,
        "version": version,
        "cpe": record.get("cpe", ""),
        "versionPrecision": record.get("versionPrecision", "unknown"),
        "discoverySources": sorted(record.get("discoverySources", [])),
        "knownExploited": known_exploited,
        "pocReferences": poc_refs,
        "pocCount": len(poc_refs),
        "exploitReferences": exploit_refs,
        "exploitMaturity": exploit_maturity,
        "publishedDate": record.get("publishedDate", ""),
        "summary": summary,
        "nucleiTemplate": "",
        "testable": True,
        "sourceStatus": source_status,
        "references": record.get("references", []),
        "validationStatus": "proposed",
        "tags": ["cve", exploit_maturity, *tags],
    }
    observation = candidate_observation(
        candidate_type="cve_candidate",
        value=cve_id,
        reason=reason,
        confidence=confidence,
        priority=priority,
        priority_score=priority_score,
        tags=metadata["tags"],
        metadata=metadata,
    )
    candidate = {"candidateId": candidate_id, "priority": priority, "priorityScore": priority_score, "confidence": confidence, "reason": reason, **metadata}
    return {"candidate": candidate, "observation": observation}


def _candidate_reason(cve_id: str, component: str, version: str, confidence: str, maturity: str) -> str:
    subject = " ".join([component, version]).strip()
    return f"{cve_id} is associated with {subject}; applicability confidence={confidence}; exploitMaturity={maturity}."


def _applicability_confidence(record: dict[str, Any]) -> str:
    sources = set(record.get("discoverySources", []))
    if sources == {"shodan"}:
        return "medium"
    if str(record.get("versionPrecision", "")) == "exact":
        return "high"
    return "low"


def _priority(cvss: float, known_exploited: bool, public_poc: bool) -> tuple[str, int, list[str]]:
    if cvss >= 9.0:
        priority = "critical"
    elif cvss >= 7.0:
        priority = "high"
    elif cvss >= 4.0:
        priority = "medium"
    elif cvss > 0:
        priority = "low"
    else:
        priority = "low"
    score = round(cvss * 10)
    tags = []
    if known_exploited:
        return "critical", max(score, 95), ["known-exploited"]
    if public_poc:
        tags.append("public-poc")
        priority = _bump_priority(priority)
        score = max(score, 70 if priority == "high" else 50)
    return priority, score, tags


def _bump_priority(priority: str) -> str:
    order = ["info", "low", "medium", "high"]
    if priority == "critical":
        return "critical"
    try:
        return order[min(order.index(priority) + 1, len(order) - 1)]
    except ValueError:
        return "medium"


def _exploit_maturity(known_exploited: bool, poc_refs: list[Any], exploit_refs: list[Any]) -> str:
    if known_exploited:
        return "in_the_wild"
    if poc_refs:
        return "public_poc"
    if exploit_refs:
        return "exploit_referenced"
    return "none"


def _cvss_from_nvd(cve: dict[str, Any]) -> tuple[float | None, str]:
    metrics = cve.get("metrics", {}) if isinstance(cve.get("metrics"), dict) else {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if not isinstance(values, list) or not values:
            continue
        metric = values[0] if isinstance(values[0], dict) else {}
        data = metric.get("cvssData", {}) if isinstance(metric.get("cvssData"), dict) else {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or metric.get("baseSeverity") or ""
        if score is not None:
            return float(score), str(severity).lower()
    return None, ""


def _references_from_nvd(cve: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    refs = []
    exploit_refs = []
    ref_data = cve.get("references", {}).get("referenceData", []) if isinstance(cve.get("references"), dict) else []
    for ref in ref_data:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url", "") or "")
        if not url:
            continue
        tags = [str(tag) for tag in ref.get("tags", [])] if isinstance(ref.get("tags"), list) else []
        item = {"source": "nvd", "url": url, "tags": tags}
        refs.append(item)
        if any(str(tag).lower() == "exploit" for tag in tags):
            exploit_refs.append(item)
    return refs, exploit_refs


def _summary_from_nvd(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    if isinstance(descriptions, list):
        for item in descriptions:
            if isinstance(item, dict) and item.get("lang") == "en":
                return str(item.get("value", ""))[:300]
    return ""


def _poc_refs_from_payload(payload: Any, source: str) -> list[dict[str, Any]]:
    items = []
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        for key in ("pocs", "repositories", "items"):
            if isinstance(payload.get(key), list):
                items = payload[key]
                break
        if not items and payload.get("html_url"):
            items = [payload]
    refs = []
    for item in items[:25]:
        if not isinstance(item, dict):
            continue
        url = str(item.get("html_url") or item.get("url") or item.get("repo") or "")
        if not url:
            continue
        ref = {"source": source, "url": url}
        stars = item.get("stargazers_count", item.get("stars"))
        if isinstance(stars, int):
            ref["stars"] = stars
        refs.append(ref)
    return refs


def _searchsploit_refs(payload: dict[str, Any]) -> list[dict[str, Any]]:
    results = payload.get("RESULTS_EXPLOIT", []) if isinstance(payload, dict) else []
    refs = []
    for item in results[:25]:
        if not isinstance(item, dict):
            continue
        path = str(item.get("Path", "") or item.get("EDB-ID", "") or "")
        title = str(item.get("Title", "") or "")
        if path or title:
            refs.append({"source": "searchsploit", "url": path, "title": title})
    return refs


def _normalize_cve_id(value: Any) -> str:
    text = str(value).strip().upper()
    if text.startswith("CVE-"):
        return text
    return ""


def _cve_year(cve_id: str) -> str:
    parts = cve_id.split("-")
    return parts[1] if len(parts) > 2 and parts[1].isdigit() else "unknown"


def recommended_tests() -> list[RecommendedTest]:
    return [
        RecommendedTest(
            name="benign_cve_signal_replay",
            description="Send one bounded benign request and look for component/CVE-specific response evidence.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="low",
            payload_strategy="Use a non-exploit marker parameter or plain GET request; never fetch or execute PoC code.",
        ),
        RecommendedTest(
            name="delegate_to_nuclei_template",
            description="When a known safe nuclei template exists, build a command for the existing nuclei tool instead of implementing a new scanner.",
            sends_traffic=True,
            requires_confirmation=True,
            risk_tier="medium",
        ),
    ]


def _coerce_cve_candidate(args: dict[str, Any]) -> dict[str, Any]:
    candidate = args.get("candidate")
    if isinstance(candidate, dict):
        return dict(candidate)
    candidate_id = str(args.get("candidateId", "") or "")
    workspace_id = args.get("workspaceId")
    target = args.get("target")
    if candidate_id and workspace_id and target:
        entities = workspace._load_target_entities(workspace.normalize_workspace_id(str(workspace_id)), workspace.normalize_target(str(target)))
        for observation in entities.get("observations", []):
            if isinstance(observation, dict) and observation.get("candidateId") == candidate_id:
                return dict(observation)
    cve_id = _normalize_cve_id(args.get("cveId", "") or args.get("value", ""))
    if not cve_id:
        raise McpError(-32602, "Provide a candidate object, or candidateId with workspaceId/target, or cveId.")
    return {
        "candidateId": candidate_id or f"cve_{cve_id}_{stable_slug(args.get('component', 'manual'))}_{stable_slug(args.get('version', ''))}",
        "type": "cve_candidate",
        "value": cve_id,
        "cveId": cve_id,
        "component": str(args.get("component", "")),
        "version": str(args.get("version", "")),
        "confidence": str(args.get("confidence", "low")),
        "exploitMaturity": str(args.get("exploitMaturity", "none")),
        "pocReferences": args.get("pocReferences", []),
        "knownExploited": bool(args.get("knownExploited", False)),
        "nucleiTemplate": str(args.get("nucleiTemplate", "")),
    }


def plan_tests(args: dict[str, Any]) -> str:
    candidate = _coerce_cve_candidate(args)
    nuclei_template = str(candidate.get("nucleiTemplate", "") or "")
    target = str(args.get("target") or candidate.get("url") or "")
    nuclei_invocation = None
    if nuclei_template and target:
        nuclei_invocation = {
            "tool": "nuclei.build_command",
            "arguments": {
                "workspaceId": args.get("workspaceId", workspace.default_workspace_id()),
                "target": target,
                "profile": "low_noise",
                "templates": [nuclei_template],
            },
        }
    plan = {
        "candidateId": candidate.get("candidateId", ""),
        "cveId": candidate.get("cveId") or candidate.get("value"),
        "component": candidate.get("component", ""),
        "version": candidate.get("version", ""),
        "knownExploited": bool(candidate.get("knownExploited")),
        "exploitMaturity": candidate.get("exploitMaturity", "none"),
        "pocReferencesBySource": _group_refs_by_source(candidate.get("pocReferences", [])),
        "verificationApproach": "Build one benign replay request, or delegate to the existing nuclei tool when a safe template id is available.",
        "nucleiTemplate": nuclei_template,
        "nucleiBuildCommand": nuclei_invocation,
        "expectedSignals": _expected_signals(candidate),
        "guardrails": [
            "This plan sends no traffic.",
            "Benign verification only; cve.execute_test requires confirm=true and in-scope target authorization.",
            "Do not fetch, clone, compile, or execute PoC code.",
            "Use workspace.promote_observation_to_finding only after operator review of verification evidence.",
        ],
        "promotionPath": {
            "tool": "workspace.promote_observation_to_finding",
            "selector": {"candidateId": candidate.get("candidateId", ""), "type": "cve_candidate", "value": candidate.get("cveId") or candidate.get("value")},
        },
    }
    return json.dumps(plan, indent=2)


def prepare_replay(args: dict[str, Any]) -> str:
    candidate = _coerce_cve_candidate(args)
    replay_args = _replay_args(args, candidate)
    replay = build_manual_replay(
        replay_args,
        adapter="cve",
        payloads=[_benign_payload(candidate)],
        expected_signals=_expected_signals(candidate),
        guardrails=[
            "Use only this benign marker request.",
            "Do not fetch or execute PoC code referenced by the candidate.",
            "If a nucleiTemplate is present, prefer the existing nuclei tool path for template validation.",
        ],
    )
    replay["cveId"] = candidate.get("cveId") or candidate.get("value")
    replay["component"] = candidate.get("component", "")
    replay["pocReferences"] = candidate.get("pocReferences", [])
    replay["nucleiTemplate"] = candidate.get("nucleiTemplate", "")
    return json.dumps(replay, indent=2)


def execute_test(args: dict[str, Any]) -> str:
    require_confirmed(args, "Running a CVE verification replay requires confirm=true.")
    candidate = _coerce_cve_candidate(args)
    workspace_id = workspace.normalize_workspace_id(args.get("workspaceId") or workspace.default_workspace_id())
    target_url = _target_url(args, candidate)
    scope_result = require_in_scope(target_url, workspace_id)
    nuclei_template = str(candidate.get("nucleiTemplate", "") or "")
    if nuclei_template and args.get("forceDirectReplay") is not True:
        built = nuclei_adapter.build_command(
            {
                "workspaceId": workspace_id,
                "target": target_url,
                "profile": "low_noise",
                "templates": [nuclei_template],
                "includeWorkspaceUrls": True,
            }
        )
        return json.dumps(
            {
                "delegateToNuclei": {
                    "template": nuclei_template,
                    "tool": "nuclei.run_profile",
                    "buildCommandTool": "nuclei.build_command",
                    "arguments": {"workspaceId": workspace_id, "target": target_url, "profile": "low_noise", "templates": [nuclei_template], "confirm": True},
                    "builtCommand": {key: value for key, value in built.items() if not key.startswith("_")},
                },
                "candidate": candidate,
            },
            indent=2,
        )

    replay_args = _replay_args(args, candidate)
    payload = _benign_payload(candidate)
    built = build_http_request(target_url, str(replay_args.get("method", "GET")), str(replay_args.get("parameter", "synapse_cve_probe")), str(replay_args.get("location", "query")), payload, args.get("credentialId"))
    approval = approval_metadata(args)
    policy = HttpClientPolicy.from_args(args, timeout_seconds=float(args.get("requestTimeout", 10)))
    with http_client.session(policy) as session:
        response_payload = session.send(
            HttpRequest(url=built["url"], method=built["method"], headers=built["headers"], body=built.get("_bodyBytes")),
        ).as_dict()
    signal = _response_cve_signal(candidate, response_payload)
    exchange_evidence = store_http_exchange_evidence(
        workspace_id,
        scope_result["host"],
        "cve_http_exchange",
        request={key: value for key, value in built.items() if not key.startswith("_")},
        response=response_payload,
        metadata={"adapter": "cve", "candidateId": candidate.get("candidateId", ""), "cveId": candidate.get("cveId") or candidate.get("value"), "approval": approval},
    )
    raw = {
        "candidate": candidate,
        "request": {key: value for key, value in built.items() if key != "headers" and not key.startswith("_")},
        "requestHeaders": redact_headers(built["headers"]),
        "response": response_summary(response_payload, body_preview_bytes=120),
        "exchangeEvidence": exchange_evidence,
        "assessment": "possible_cve" if signal else "inconclusive",
        "approval": approval,
        "entities": {
            "observations": [
                {
                    "type": "cve_validation_result",
                    "value": candidate.get("cveId") or candidate.get("value"),
                    "candidateId": f"cve_validation_{stable_slug(candidate.get('candidateId', candidate.get('value', '')))}",
                    "sourceCandidateId": candidate.get("candidateId", ""),
                    "assessment": "possible_cve" if signal else "inconclusive",
                    "confidence": "medium" if signal else "low",
                    "priority": candidate.get("priority", "low"),
                    "reason": "Benign replay produced a CVE/component-specific response signal." if signal else "Benign replay did not produce a CVE/component-specific response signal.",
                    "evidenceIds": [exchange_evidence.get("evidenceId", "")],
                }
            ]
        },
    }
    ingestion = workspace.ingest_data(
        workspace_id,
        scope_result["host"],
        "adapter_result",
        "active_validation",
        "json",
        json.dumps(raw, indent=2, ensure_ascii=False),
        {"adapter": "cve", "target": target_url, "host": scope_result["host"], "approval": approval},
    )
    action = workspace.record_action(
        workspace_id,
        scope_result["host"],
        {
            "type": "active_validation",
            "tool": "cve.execute_test",
            "target": target_url,
            "cveId": candidate.get("cveId") or candidate.get("value"),
            "candidateId": candidate.get("candidateId", ""),
            "assessment": raw["assessment"],
            "exchangeEvidenceIds": [exchange_evidence.get("evidenceId", "")],
            "approval": approval,
            "evidenceId": ingestion.get("evidenceId", ""),
        },
        ingestion.get("evidenceId", ""),
    )
    validation = _record_cve_validation(workspace_id, scope_result["host"], candidate, "confirmed" if signal else "inconclusive", [exchange_evidence.get("evidenceId", "")])
    evidence.log_event(
        "cve.execute_test",
        f"Ran approved benign CVE replay for {candidate.get('cveId') or candidate.get('value')} against {scope_result['host']}.",
        {"workspaceId": workspace_id, "target": target_url, "host": scope_result["host"], "assessment": raw["assessment"], "approval": approval},
    )
    return json.dumps({"test": raw, "ingestion": ingestion, "action": action, "validation": validation}, indent=2)


def _record_cve_validation(workspace_id: str, target: str, candidate: dict[str, Any], outcome: str, evidence_ids: list[str]) -> dict[str, Any]:
    candidate_id = str(candidate.get("candidateId", ""))
    if not candidate_id:
        return {"recorded": False, "reason": "candidate has no candidateId"}
    try:
        result = workspace.record_candidate_validation(workspace_id, target, {"candidateId": candidate_id}, outcome, evidence_ids=evidence_ids)
    except McpError:
        return {"recorded": False, "outcome": outcome, "reason": "no matching CVE candidate in workspace state"}
    return {"recorded": True, "outcome": outcome, "findingDraft": result.get("findingDraft")}


def _target_url(args: dict[str, Any], candidate: dict[str, Any]) -> str:
    explicit = str(args.get("url") or candidate.get("url") or "")
    if explicit:
        return explicit if "://" in explicit else f"https://{explicit}"
    target = str(args.get("target") or candidate.get("target") or "")
    if not target:
        raise McpError(-32602, "target or url is required for CVE replay.")
    return target if "://" in target else f"https://{target}/"


def _replay_args(args: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    target_url = _target_url(args, candidate)
    return {
        **args,
        "candidate": {
            "candidateId": candidate.get("candidateId", ""),
            "url": target_url,
            "method": args.get("method") or candidate.get("method") or "GET",
            "parameter": args.get("parameter") or candidate.get("parameter") or "synapse_cve_probe",
            "location": args.get("location") or candidate.get("location") or "query",
            "reasons": candidate.get("reasons", []),
        },
        "payload": args.get("payload") or _benign_payload(candidate),
    }


def _benign_payload(candidate: dict[str, Any]) -> str:
    cve_id = str(candidate.get("cveId") or candidate.get("value") or "cve").lower()
    return f"synapse-benign-{stable_slug(cve_id)}"


def _expected_signals(candidate: dict[str, Any]) -> list[str]:
    cve_id = str(candidate.get("cveId") or candidate.get("value") or "")
    component = str(candidate.get("component", "") or "")
    version = str(candidate.get("version", "") or "")
    return [
        f"The response exposes {cve_id} or a vulnerability-specific banner." if cve_id else "The response exposes a vulnerability-specific banner.",
        f"The response confirms the affected component/version: {' '.join([component, version]).strip()}." if component else "The response confirms the affected component/version.",
        "A safe template-specific signal appears without executing public PoC code.",
    ]


def _response_cve_signal(candidate: dict[str, Any], response: dict[str, Any]) -> bool:
    text = json.dumps(response, sort_keys=True).lower()
    cve_id = str(candidate.get("cveId") or candidate.get("value") or "").lower()
    component = str(candidate.get("component", "") or "").lower()
    version = str(candidate.get("version", "") or "").lower()
    if cve_id and cve_id in text:
        return True
    if component and version and component in text and version in text:
        return True
    return False


def _group_refs_by_source(refs: Any) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for ref in refs if isinstance(refs, list) else []:
        if not isinstance(ref, dict):
            continue
        source = str(ref.get("source", "unknown") or "unknown")
        grouped.setdefault(source, []).append(ref)
    return grouped
