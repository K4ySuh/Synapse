# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from ...core import background_jobs, credentials, dumps, evidence, scope, workspace
from ...core.errors import McpError
from ...core.http import client as http_client
from ...core.http.models import HttpClientPolicy, HttpRequest
from ...core.js import extractors, normalizer
from ...core.js.models import JsAnalysisResult, JsAsset, SOURCE
from ...core.paths import SYNAPSE_ROOT, synapse_python
from ...core.url_hygiene import canonical_url_identity, redact_url_query_values
from ..command_utils import background_requested, require_in_scope
from . import surface_hygiene


TOOL = "js-intelligence"
DEFAULT_MAX_ASSETS = 50
# Active fetching sends one request per asset; keep the default batch and a total
# wall-clock budget small so the call stays well under the MCP tool deadline.
DEFAULT_FETCH_MAX_ASSETS = 20
DEFAULT_FETCH_BUDGET_SECONDS = 30.0
DEFAULT_MAX_BYTES = 750_000
DEFAULT_JOB_TIMEOUT_SECONDS = 1800
DEFAULT_MAX_CONCURRENT_JS_JOBS = 3
BACKGROUND_JS_TOOLS = {"js.analyze_static", "js.normalize_endpoints"}


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def capabilities(_: dict[str, Any] | None = None) -> str:
    return json.dumps(
        {
            "name": "js_intelligence",
            "category": "web",
            "source": SOURCE,
            "capabilities": ["passive_analysis", "result_ingestion"],
            "sendsTraffic": {
                "discover_assets": False,
                "fetch_assets": True,
                "analyze_static": False,
                "normalize_endpoints": False,
                "build_app_model": False,
                "render_app_map": False,
            },
            "requiresConfirmation": {"fetch_assets": True},
            "defaultRiskTier": "low",
            "executionMode": "async_default",
            "backgroundJobProvider": "jobs",
            "maxConcurrentBackgroundJobs": DEFAULT_MAX_CONCURRENT_JS_JOBS,
            "produces": ["javascript_assets", "endpoints", "parameters", "observations", "app_model", "app_map_report"],
            "limitations": [
                "Does not execute JavaScript.",
                "Does not perform active vulnerability testing.",
                "Fetched assets are bounded by count, timeout, and maximum body size.",
                "Security-sensitive header names are stored without credential values.",
            ],
        },
        indent=2,
    )


def discover_assets(args: dict[str, Any]) -> str:
    workspace_id = workspace.normalize_workspace_id(args["workspaceId"])
    target = workspace.normalize_target(args["target"])
    max_assets = int(args.get("maxAssets", DEFAULT_MAX_ASSETS))
    include_evidence_raw = bool(args.get("includeEvidenceRaw", True))
    workspace.add_target(workspace_id, target)
    entities = workspace._load_target_entities(workspace_id, target)
    assets = _discover_from_entities(entities)
    assets.extend(_load_cached_assets(workspace_id, target))
    if include_evidence_raw:
        assets.extend(_discover_from_raw_evidence(workspace_id, target))
    assets = _dedupe_assets(assets)[:max_assets]
    manifest = _write_json_artifact(workspace_id, target, "manifests", "assets.json", {"source": SOURCE, "workspaceId": workspace_id, "target": target, "assets": assets})
    evidence.log_event(
        "js.discover_assets",
        f"Discovered {len(assets)} JavaScript assets for {target}.",
        {"workspaceId": workspace_id, "target": target, "assetCount": len(assets), "manifestPath": str(manifest)},
    )
    return json.dumps({"workspaceId": workspace_id, "target": target, "assetCount": len(assets), "assets": assets, "manifestPath": str(manifest)}, indent=2)


def fetch_assets(args: dict[str, Any]) -> str:
    workspace_id = workspace.normalize_workspace_id(args["workspaceId"])
    target_input = str(args["target"])
    target = workspace.normalize_target(target_input)
    policy = HttpClientPolicy.from_args(args, timeout_seconds=float(args.get("requestTimeout", 10)))
    workspace.add_target(workspace_id, target)
    max_assets = int(args.get("maxAssets", DEFAULT_FETCH_MAX_ASSETS))
    max_bytes = int(args.get("maxBytesPerAsset", DEFAULT_MAX_BYTES))
    budget_seconds = float(args.get("totalBudgetSeconds", DEFAULT_FETCH_BUDGET_SECONDS))
    if budget_seconds <= 0:
        budget_seconds = DEFAULT_FETCH_BUDGET_SECONDS
    asset_inputs = args.get("assets")
    if isinstance(asset_inputs, list) and asset_inputs:
        assets = [_asset_from_input(item, target_input) for item in asset_inputs if isinstance(item, (str, dict))]
    else:
        discovered = json.loads(discover_assets({"workspaceId": workspace_id, "target": target_input, "maxAssets": max_assets}))
        assets = discovered.get("assets", [])
    # Reuse one pooled client for the whole batch and stop starting new requests
    # once the wall-clock budget is spent, so a few slow assets cannot push the
    # call past the MCP tool deadline (which would orphan the worker thread).
    fetch_policy = HttpClientPolicy(
        backend=policy.backend,
        timeout_seconds=policy.timeout_seconds,
        max_body_bytes=max_bytes,
        follow_redirects=policy.follow_redirects,
        proxy_url=policy.proxy_url,
        verify_tls=policy.verify_tls,
        http2=policy.http2,
    )
    user_agent = str(args.get("userAgent") or "SynapseJSIntel/0.1")
    # Optional scoped session/credential so SSO-gated static assets (e.g. SPA JS
    # behind Shibboleth) can be fetched. Resolved by reference; secrets never
    # appear in args or results. Mirrors crawler.crawl's credential handling.
    credential_id = str(args.get("credentialId") or "").strip()
    credential = credentials.credential_for_target(credential_id, target_input) if credential_id else None
    credential_meta = credentials.redact_credential(credential) if credential else None
    candidate_assets = [asset for asset in assets[:max_assets] if isinstance(asset, dict) and asset.get("url")]
    refresh = bool(args.get("refresh", False))
    fetched: list[dict[str, Any]] = []
    network_assets: list[dict[str, Any]] = []
    for asset in candidate_assets:
        cached = None if refresh else _find_cached_asset(workspace_id, target, str(asset.get("url") or ""), max_bytes=max_bytes)
        if cached:
            fetched.append({**cached, "cacheHit": True})
        else:
            network_assets.append(asset)
    if policy.backend != "disabled" and network_assets and args.get("confirm") is not True:
        raise McpError(
            -32001,
            "Fetching uncached JavaScript assets sends HTTP traffic and requires confirm=true. "
            "Cached assets can be reused without confirmation; use refresh=true only for a deliberate re-fetch.",
        )
    errors: list[dict[str, Any]] = []
    budget_exceeded = False
    deadline = time.monotonic() + budget_seconds
    with http_client.session(fetch_policy) as session:
        for index, asset in enumerate(network_assets):
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0.1:
                budget_exceeded = True
                for skipped in network_assets[index:]:
                    errors.append({"url": str(skipped.get("url") or ""), "error": f"Skipped: fetch budget of {budget_seconds:g}s exceeded."})
                break
            url = str(asset.get("url") or "")
            try:
                require_in_scope(url, workspace_id)
            except McpError as exc:
                errors.append({"url": url, "error": str(exc)})
                continue
            headers = {"User-Agent": user_agent}
            if credential is not None:
                headers.update(credentials.headers_for_credential_target(credential, url))
            response = session.send(
                HttpRequest(url=url, method="GET", headers=headers),
                timeout_seconds=min(fetch_policy.timeout_seconds, remaining_seconds),
            )
            if time.monotonic() >= deadline:
                budget_exceeded = True
            final_url = response.url or url
            if response.status is None or response.error:
                errors.append({"url": url, "status": response.status, "error": response.error})
                continue
            content_type = _header(response.headers, "content-type")
            if not (extractors.is_js_asset_url(final_url) or extractors.is_js_content_type(content_type)):
                errors.append({"url": final_url, "status": response.status, "error": f"Response is not JavaScript-like: {content_type}"})
                continue
            body = response.body[:max_bytes]
            fetched_asset = cache_asset(
                workspace_id,
                target,
                final_url,
                body,
                status=int(response.status),
                content_type=content_type,
                source="js.fetch_assets",
                source_endpoint=str(asset.get("sourceEndpoint") or ""),
                discovered_from=[str(item) for item in asset.get("discoveredFrom", []) if item] if isinstance(asset.get("discoveredFrom"), list) else [],
                approval_id=str(args.get("approvalId") or ""),
                max_bytes=max_bytes,
            )
            if not fetched_asset:
                errors.append({"url": final_url, "status": response.status, "error": "Asset exceeded cache retention or size policy."})
                continue
            fetched_asset["cacheHit"] = False
            fetched.append(fetched_asset)
    manifest = _write_json_artifact(
        workspace_id,
        target,
        "manifests",
        "fetched-assets.json",
        {"source": SOURCE, "workspaceId": workspace_id, "target": target, "assets": fetched, "errors": errors},
    )
    evidence.log_event(
        "js.fetch_assets",
        f"Fetched {len(fetched)} JavaScript assets for {target}.",
        {
            "workspaceId": workspace_id,
            "target": target,
            "assetCount": len(fetched),
            "errorCount": len(errors),
            "manifestPath": str(manifest),
            "approvalId": args.get("approvalId", ""),
            "approvalReason": args.get("approvalReason", ""),
            "riskTier": args.get("riskTier", "low"),
            "httpBackend": policy.backend,
            "budgetSeconds": budget_seconds,
            "budgetExceeded": budget_exceeded,
            "cacheHitCount": sum(1 for item in fetched if item.get("cacheHit")),
            "networkFetchCount": sum(1 for item in fetched if item.get("cacheHit") is False),
            "credentialId": credential_id,
            "authenticated": credential is not None,
        },
    )
    result = {
        "workspaceId": workspace_id,
        "target": target,
        "assetCount": len(fetched),
        "assets": fetched,
        "errors": errors,
        "manifestPath": str(manifest),
        "budgetSeconds": budget_seconds,
        "budgetExceeded": budget_exceeded,
        "cacheHitCount": sum(1 for item in fetched if item.get("cacheHit")),
        "networkFetchCount": sum(1 for item in fetched if item.get("cacheHit") is False),
        "refresh": refresh,
    }
    if credential_meta is not None:
        result["credential"] = credential_meta
    return json.dumps(result, indent=2)


def analyze_static(args: dict[str, Any]) -> str:
    workspace_id = workspace.normalize_workspace_id(args["workspaceId"])
    target = workspace.normalize_target(args["target"])
    workspace.add_target(workspace_id, target)
    if background_requested(args):
        return _start_background_js_worker("js.analyze_static", args, workspace_id, target)
    max_bytes = int(args.get("maxBytesPerAsset", DEFAULT_MAX_BYTES))
    assets = _load_assets_for_analysis(workspace_id, target, args)
    all_endpoints: list[dict[str, Any]] = []
    all_parameters: list[dict[str, Any]] = []
    all_signals: list[dict[str, Any]] = []
    all_libraries: list[dict[str, Any]] = []
    analyzed_assets = []
    errors = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        path = Path(str(asset.get("localPath") or ""))
        if not path.exists():
            errors.append({"asset": asset.get("url", ""), "error": f"Asset file not found: {path}"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")[:max_bytes]
        extracted = extractors.extract_from_source(text, str(asset.get("url") or str(path)), max_bytes=max_bytes)
        all_endpoints.extend(extracted["endpoints"])
        all_parameters.extend(extracted["parameters"])
        all_signals.extend(extracted["signals"])
        all_libraries.extend(extracted.get("libraries", []))
        analyzed_assets.append(asset)
    libraries = _collapse_libraries(all_libraries)
    result = JsAnalysisResult(
        assets=analyzed_assets,
        endpoints=_dedupe_dicts(all_endpoints, ("raw", "method", "sourceAsset")),
        parameters=_dedupe_dicts(all_parameters, ("name", "endpointRaw", "location", "sourceAsset")),
        signals=_dedupe_dicts(all_signals, ("type", "value", "sourceAsset")),
        libraries=libraries,
        summary={
            "assetCount": len(analyzed_assets),
            "endpointCount": len(_dedupe_dicts(all_endpoints, ("raw", "method", "sourceAsset"))),
            "parameterCount": len(_dedupe_dicts(all_parameters, ("name", "endpointRaw", "location", "sourceAsset"))),
            "signalCount": len(_dedupe_dicts(all_signals, ("type", "value", "sourceAsset"))),
            "libraryCount": len(libraries),
            "errors": errors,
        },
    ).as_dict()
    analysis_path = _write_json_artifact(workspace_id, target, "analysis", "static-analysis.json", result)
    evidence.log_event(
        "js.analyze_static",
        f"Statically analyzed {len(analyzed_assets)} JavaScript assets for {target}.",
        {"workspaceId": workspace_id, "target": target, "analysisPath": str(analysis_path), "endpointCount": result["summary"]["endpointCount"]},
    )
    return json.dumps({**result, "analysisPath": str(analysis_path)}, indent=2)


def normalize_endpoints(args: dict[str, Any]) -> str:
    workspace_id = workspace.normalize_workspace_id(args["workspaceId"])
    target_input = str(args["target"])
    target = workspace.normalize_target(target_input)
    workspace.add_target(workspace_id, target)
    if background_requested(args):
        return _start_background_js_worker("js.normalize_endpoints", args, workspace_id, target)
    analysis = _load_analysis(workspace_id, target, args)
    existing_endpoints = workspace._load_target_entities(workspace_id, target).get("endpoints", [])
    base_url = str(args.get("baseUrl") or _observed_base_url(existing_endpoints, target) or _base_url(target_input, target))
    entities = normalizer.build_entities(
        analysis,
        target=target,
        base_url=base_url,
        existing_endpoints=existing_endpoints,
    )
    payload = {"source": SOURCE, "workspaceId": workspace_id, "target": target, "entities": entities, "analysisSummary": analysis.get("summary", {})}
    normalized_path = _write_json_artifact(workspace_id, target, "normalized", "normalized-adapter-result.json", payload)
    ingestion = None
    if args.get("ingest", True):
        ingestion = workspace.ingest_data(
            workspace_id,
            target,
            SOURCE,
            "js_static_analysis",
            "json",
            json.dumps(payload, indent=2, ensure_ascii=False),
            {"analysisPath": args.get("analysisPath", ""), "normalizedPath": str(normalized_path)},
        )
    evidence.log_event(
        "js.normalize_endpoints",
        f"Normalized JavaScript-derived entities for {target}.",
        {
            "workspaceId": workspace_id,
            "target": target,
            "endpointCount": len(entities["endpoints"]),
            "parameterCount": len(entities["parameters"]),
            "observationCount": len(entities["observations"]),
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload, "normalizedPath": str(normalized_path), **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def _start_background_js_worker(tool_name: str, args: dict[str, Any], workspace_id: str, target: str) -> str:
    _enforce_js_job_limit(int(args.get("maxConcurrentJobs") or DEFAULT_MAX_CONCURRENT_JS_JOBS))
    worker_args = dict(args)
    worker_args["background"] = False
    job_slug = tool_name.replace(".", "-")
    args_path = workspace.target_output_path(workspace_id, target, "jobs", f"{job_slug}-args.json")
    result_path = workspace.target_output_path(workspace_id, target, "jobs", f"{job_slug}-result.json")
    state_path = workspace.target_output_path(workspace_id, target, "jobs", f"{job_slug}-state.json")
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
    timeout_seconds = int(args.get("timeoutSeconds") or DEFAULT_JOB_TIMEOUT_SECONDS)
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
        "target": target,
        "timeoutSeconds": timeout_seconds,
        "maxConcurrentJobs": int(args.get("maxConcurrentJobs") or DEFAULT_MAX_CONCURRENT_JS_JOBS),
        "normalizeAfter": bool(args.get("normalizeAfter", False)),
        "ingest": args.get("ingest", True),
    }
    job = background_jobs.start_command(
        cmd,
        timeout_seconds=timeout_seconds,
        event_type=tool_name,
        summary=f"Ran {tool_name} for {target} in a background worker",
        display_cmd=cmd,
        event_data=event_data,
        tool=tool_name,
        workspace_id=workspace_id,
        target=target,
        output_path=str(result_path),
        finalizer_name="js.worker.result",
        finalizer_data={"resultPath": str(result_path), "tool": tool_name, "args": worker_args},
    )
    return json.dumps(
        {
            "workspaceId": workspace_id,
            "target": target,
            "background": True,
            "job": job,
            "status": "started",
            "workerArgsPath": str(args_path),
            "workerStatePath": str(state_path),
            "resultPath": str(result_path),
            "timeoutSeconds": timeout_seconds,
            "message": f"{tool_name} is running in the background. Poll with jobs.status(jobId={job['jobId']!r}).",
        },
        indent=2,
    )


def _enforce_js_job_limit(max_jobs: int) -> None:
    active = background_jobs.list_jobs(limit=1000, active_only=True).get("jobs", [])
    js_active = [job for job in active if str(job.get("tool", "")) in BACKGROUND_JS_TOOLS]
    if len(js_active) >= max(max_jobs, 1):
        job_ids = [str(job.get("jobId", "")) for job in js_active[:5]]
        raise McpError(
            -32003,
            f"Too many JavaScript analysis/normalization jobs are already running ({len(js_active)}). "
            f"Poll with jobs.status(jobId=...) before starting more. Active job IDs: {', '.join(job_ids)}",
        )


def _js_worker_finalizer(_record: dict[str, Any], _result: dict[str, Any], data: dict[str, Any]) -> dict[str, Any] | None:
    result_path = Path(str(data.get("resultPath", "")))
    payload = background_jobs.read_worker_result_file(result_path)
    if payload.get("isError"):
        return payload
    response = {**payload, "resultPath": str(result_path)}
    if data.get("tool") == "js.analyze_static":
        args = data.get("args", {}) if isinstance(data.get("args"), dict) else {}
        if args.get("normalizeAfter") is True:
            normalize_args = {
                "workspaceId": payload.get("workspaceId") or args.get("workspaceId"),
                "target": payload.get("target") or args.get("target"),
                "analysisPath": payload.get("analysisPath") or str(result_path),
                "baseUrl": args.get("baseUrl", ""),
                "ingest": args.get("ingest", True),
                "timeoutSeconds": args.get("normalizeTimeoutSeconds") or args.get("timeoutSeconds") or DEFAULT_JOB_TIMEOUT_SECONDS,
                "background": True,
                "maxConcurrentJobs": args.get("maxConcurrentJobs") or DEFAULT_MAX_CONCURRENT_JS_JOBS,
            }
            try:
                response["normalizeJob"] = json.loads(normalize_endpoints(normalize_args))
            except Exception as exc:
                response["normalizeJobError"] = f"{type(exc).__name__}: {exc}"
    return response


background_jobs.register_finalizer("js.worker.result", _js_worker_finalizer)


def build_app_model(args: dict[str, Any]) -> str:
    workspace_id = workspace.normalize_workspace_id(args["workspaceId"])
    target = workspace.normalize_target(args["target"])
    analysis = _load_analysis(workspace_id, target, args, required=False) or {"assets": [], "endpoints": [], "signals": [], "summary": {}}
    context = workspace.prepare_target_context(workspace_id, target, purpose="js_app_model", max_tokens=int(args.get("maxTokens", 2500)))
    signal_groups: dict[str, list[str]] = {}
    for item in analysis.get("signals", []) if isinstance(analysis.get("signals"), list) else []:
        if isinstance(item, dict):
            signal_groups.setdefault(str(item.get("type") or "js_signal"), [])
            value = str(item.get("value") or "")
            if value and value not in signal_groups[str(item.get("type") or "js_signal")]:
                signal_groups[str(item.get("type") or "js_signal")].append(value)
    max_endpoints = int(args.get("maxEndpoints", 25))
    model = {
        "source": SOURCE,
        "workspaceId": workspace_id,
        "target": target,
        "summary": {
            "assetCount": len(analysis.get("assets", [])) if isinstance(analysis.get("assets"), list) else 0,
            "jsEndpointCandidates": len(analysis.get("endpoints", [])) if isinstance(analysis.get("endpoints"), list) else 0,
            "workspaceEndpointCount": context.get("knownEndpoints", {}).get("total", 0),
            "signalTypes": sorted(signal_groups.keys()),
        },
        "jsAssets": [
            {"url": item.get("url"), "size": item.get("size"), "sha256": item.get("sha256")}
            for item in analysis.get("assets", [])[:max_endpoints]
            if isinstance(item, dict)
        ],
        "derivedEndpoints": analysis.get("endpoints", [])[:max_endpoints] if isinstance(analysis.get("endpoints"), list) else [],
        "signals": {key: values[:25] for key, values in signal_groups.items()},
        "workspaceContext": {
            "interestingEndpoints": context.get("interestingEndpoints", [])[:max_endpoints],
            "stateChangingCandidates": context.get("stateChangingCandidates", [])[:max_endpoints],
            "authSurface": context.get("authSurface", [])[:max_endpoints],
        },
        "operatorNotes": [
            "JavaScript-derived endpoints are inferred unless independently observed in traffic or crawl output.",
            "No JavaScript was executed and no vulnerability testing was performed.",
        ],
    }
    path = _write_json_artifact(workspace_id, target, "app-model", "app-model.json", model)
    evidence.log_event("js.build_app_model", f"Built JavaScript app model for {target}.", {"workspaceId": workspace_id, "target": target, "path": str(path)})
    return json.dumps({**model, "appModelPath": str(path)}, indent=2)


def render_app_map(args: dict[str, Any]) -> str:
    workspace_id = workspace.normalize_workspace_id(args["workspaceId"])
    target = workspace.normalize_target(args["target"])
    format_name = str(args.get("format") or "html").lower()
    if format_name not in {"html", "markdown", "json"}:
        raise McpError(-32602, "format must be one of: html, markdown, json.")
    entities = workspace._load_target_entities(workspace_id, target)
    latest_analysis = _load_analysis(workspace_id, target, args, required=False)
    app_map = build_full_app_map(workspace_id, target, entities, latest_analysis)
    if format_name == "json":
        content = json.dumps(app_map, indent=2, ensure_ascii=False)
        extension = "json"
    elif format_name == "markdown":
        content = _render_app_map_markdown(app_map)
        extension = "md"
    else:
        content = _render_app_map_layer_html(workspace_id, target)
        extension = "html"
    output_path = _write_report_output(workspace_id, target, args, content, extension)
    artifact_path = _write_json_artifact(workspace_id, target, "app-map", "app-map.json", app_map)
    evidence.log_event(
        "js.render_app_map",
        f"Rendered JavaScript-enriched application map for {target}.",
        {
            "workspaceId": workspace_id,
            "target": target,
            "format": format_name,
            "outputPath": str(output_path),
            "artifactPath": str(artifact_path),
            "endpointCount": app_map["summary"]["endpointCount"],
            "jsInferredEndpointCount": app_map["summary"]["jsInferredEndpointCount"],
        },
    )
    return json.dumps(
        {
            "workspaceId": workspace_id,
            "target": target,
            "format": format_name,
            "outputPath": str(output_path),
            "artifactPath": str(artifact_path),
            "summary": app_map["summary"],
        },
        indent=2,
    )


def _render_app_map_layer_html(workspace_id: str, target: str) -> str:
    # The HTML application map and the JavaScript Intelligence layer report are
    # the same document; the lazy import avoids the layers -> js_intel cycle.
    from ...core.documentation import layers as documentation_layers
    from ...core.documentation.layer_renderer import render_layer_report

    context = documentation_layers.build_layer_report_context({"workspaceId": workspace_id, "target": target, "layer": "js"})["layerReport"]
    return render_layer_report(context, "html")


def build_full_app_map(workspace_id: str, target: str, entities: dict[str, list[dict[str, Any]]], analysis: dict[str, Any] | None = None) -> dict[str, Any]:
    endpoints = [item for item in entities.get("endpoints", []) if isinstance(item, dict)]
    parameters = [item for item in entities.get("parameters", []) if isinstance(item, dict)]
    observations = [item for item in entities.get("observations", []) if isinstance(item, dict)]
    params_by_endpoint: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for parameter in parameters:
        key = (str(parameter.get("method") or "GET").upper(), str(parameter.get("url") or ""))
        params_by_endpoint.setdefault(key, []).append(parameter)
    endpoint_items = []
    for endpoint in endpoints:
        method = str(endpoint.get("method") or "GET").upper()
        url = str(endpoint.get("url") or "")
        parsed = urlsplit(url)
        source = str(endpoint.get("source") or "")
        derived = bool(endpoint.get("derived") or endpoint.get("inferred") or source == SOURCE)
        endpoint_items.append(
            {
                "method": method,
                "url": url,
                "host": endpoint.get("host") or (parsed.hostname or "").lower(),
                "path": endpoint.get("path") or parsed.path or "/",
                "status": endpoint.get("status") or _first(endpoint.get("statusCodes", [])),
                "statusCodes": endpoint.get("statusCodes", []) if isinstance(endpoint.get("statusCodes"), list) else [],
                "queryParameters": endpoint.get("queryParameters", []) if isinstance(endpoint.get("queryParameters"), list) else [],
                "parameters": [
                    {
                        "name": parameter.get("name", ""),
                        "location": parameter.get("location", ""),
                        "source": parameter.get("source", ""),
                        "confidence": parameter.get("confidence", ""),
                    }
                    for parameter in params_by_endpoint.get((method, url), [])
                ],
                "source": source or "workspace",
                "sourceAsset": endpoint.get("sourceAsset", ""),
                "confidence": endpoint.get("confidence", "observed" if not derived else "low"),
                "origin": "js_inferred" if derived else "observed",
                "derived": derived,
                "observed": not derived,
                "flags": _endpoint_flags(endpoint),
                "title": endpoint.get("title", ""),
            }
        )
    endpoint_items = sorted(endpoint_items, key=lambda item: (str(item.get("host", "")), str(item.get("path", "")), str(item.get("method", "")), str(item.get("url", ""))))
    js_observations = [
        {
            "type": item.get("type", ""),
            "value": item.get("value", ""),
            "sourceAsset": item.get("sourceAsset", ""),
            "confidence": item.get("confidence", ""),
            "reason": item.get("reason", ""),
            "metadata": item.get("metadata", {}),
        }
        for item in observations
        if str(item.get("type", "")).startswith("js_")
    ]
    assets = _assets_for_report(workspace_id, target, analysis or {})
    return {
        "source": SOURCE,
        "workspaceId": workspace_id,
        "target": target,
        "generatedAt": workspace.now_utc(),
        "summary": {
            "endpointCount": len(endpoint_items),
            "observedEndpointCount": len([item for item in endpoint_items if item["origin"] == "observed"]),
            "jsInferredEndpointCount": len([item for item in endpoint_items if item["origin"] == "js_inferred"]),
            "assetCount": len(assets),
            "jsSignalCount": len(js_observations),
            "parameterCount": len(parameters),
        },
        "assets": assets,
        "requests": endpoint_items,
        "tree": _build_request_tree(endpoint_items),
        "jsSignals": js_observations,
    }


def _base_url(target_input: str, target: str) -> str:
    if str(target_input).startswith(("http://", "https://")):
        parsed = urlsplit(str(target_input))
        return f"{parsed.scheme}://{parsed.netloc}/"
    return f"https://{target}/"


def _observed_base_url(endpoints: list[dict[str, Any]], target: str) -> str:
    target_host = workspace.normalize_target(target)
    preferred_counts: dict[str, int] = {}
    fallback_counts: dict[str, int] = {}
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        url = str(endpoint.get("url") or "")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        if (parsed.hostname or "").lower() != target_host:
            continue
        base = f"{parsed.scheme}://{parsed.netloc}/"
        fallback_counts[base] = fallback_counts.get(base, 0) + 1
        if not _is_js_inferred_endpoint(endpoint):
            preferred_counts[base] = preferred_counts.get(base, 0) + 1
    return _most_frequent_base(preferred_counts or fallback_counts)


def _is_js_inferred_endpoint(endpoint: dict[str, Any]) -> bool:
    source = str(endpoint.get("source") or "").lower().replace("-", "_")
    discovery_method = str(endpoint.get("discoveryMethod") or "").lower().replace("-", "_")
    return bool(
        source == SOURCE
        or discovery_method in {"js_intelligence", "static_js"}
        or endpoint.get("inferred")
        or endpoint.get("derived")
    )


def _most_frequent_base(counts: dict[str, int]) -> str:
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _asset_from_input(item: str | dict[str, Any], target_input: str) -> dict[str, Any]:
    if isinstance(item, str):
        return {"url": urljoin(_base_url(target_input, workspace.normalize_target(target_input)), item), "source": SOURCE}
    url = str(item.get("url") or "")
    if url and not url.startswith(("http://", "https://", "//")):
        url = urljoin(_base_url(target_input, workspace.normalize_target(target_input)), url)
    return {**item, "url": url, "source": SOURCE}


def _discover_from_entities(entities: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    assets = []
    for endpoint in entities.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        url = str(endpoint.get("url") or "")
        content_types = endpoint.get("contentTypes", [])
        content_type = " ".join(str(item) for item in content_types) if isinstance(content_types, list) else str(endpoint.get("contentType") or "")
        if not (extractors.is_js_asset_url(url) or extractors.is_js_content_type(content_type)):
            continue
        if surface_hygiene.is_spa_shell_asset_record(endpoint):
            continue
        parsed = urlsplit(url)
        assets.append(
            JsAsset(
                url=url,
                host=(parsed.hostname or "").lower(),
                path=parsed.path or "/",
                source_endpoint=url,
                discovered_from=[str(item) for item in endpoint.get("discoveredFrom", []) if item] if isinstance(endpoint.get("discoveredFrom"), list) else [],
                confidence="high" if endpoint.get("fetched") else "medium",
            ).as_dict()
        )
    return assets


def _discover_from_raw_evidence(workspace_id: str, target: str) -> list[dict[str, Any]]:
    assets = []
    evidence_dir = workspace.target_path(workspace_id, target) / "evidence"
    for path in sorted(evidence_dir.glob("*_raw.json"))[-20:]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for url in _walk_urls(payload):
            if not extractors.is_js_asset_url(url):
                continue
            if surface_hygiene.is_likely_spa_asset_pollution(url):
                continue
            parsed = urlsplit(url)
            assets.append(
                JsAsset(
                    url=url,
                    host=(parsed.hostname or "").lower(),
                    path=parsed.path or "/",
                    source_endpoint=url,
                    discovered_from=[str(path)],
                    confidence="medium",
                ).as_dict()
            )
    return assets


def _walk_urls(value: Any) -> list[str]:
    urls = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"url", "sourceEndpoint"} and isinstance(item, str):
                urls.append(item)
            else:
                urls.extend(_walk_urls(item))
    elif isinstance(value, list):
        for item in value:
            urls.extend(_walk_urls(item))
    return urls


def _load_assets_for_analysis(workspace_id: str, target: str, args: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(args.get("assetPaths"), list):
        assets = []
        for path in args["assetPaths"]:
            p = Path(str(path)).expanduser().resolve(strict=False)
            assets.append({"url": str(p), "localPath": str(p), "source": SOURCE})
        return assets
    raw_manifest = str(
        args.get("manifestPath")
        or _latest_artifact(workspace_id, target, "manifests", "fetched-assets.json")
        or _latest_artifact(workspace_id, target, "manifests", "assets.json")
        or ""
    )
    if not raw_manifest:
        return []
    manifest_path = Path(raw_manifest).expanduser().resolve(strict=False)
    if not manifest_path.exists():
        return []
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    assets = payload.get("assets", []) if isinstance(payload.get("assets"), list) else []
    return [_resolve_asset_local_path(item, manifest_path) for item in assets if isinstance(item, dict)]


def _resolve_asset_local_path(asset: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    local_path = str(asset.get("localPath") or "").strip()
    if not local_path:
        return asset
    path = Path(local_path).expanduser()
    if not path.is_absolute():
        manifest_relative = (manifest_path.parent / path).resolve(strict=False)
        if manifest_relative.exists():
            path = manifest_relative
        else:
            path = (SYNAPSE_ROOT / path).resolve(strict=False)
    else:
        path = path.resolve(strict=False)
    return {**asset, "localPath": str(path)}


def _load_analysis(workspace_id: str, target: str, args: dict[str, Any], required: bool = True) -> dict[str, Any]:
    raw_path = str(args.get("analysisPath") or _latest_artifact(workspace_id, target, "analysis", "static-analysis.json") or "")
    if not raw_path:
        if required:
            raise McpError(-32602, "No JS analysis found. Run js.analyze_static first or pass analysisPath.")
        return {}
    path = Path(raw_path).expanduser().resolve(strict=False)
    if not path.exists():
        if required:
            raise McpError(-32602, "No JS analysis found. Run js.analyze_static first or pass analysisPath.")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise McpError(-32602, f"Invalid JS analysis JSON: {path}") from exc
    return payload if isinstance(payload, dict) else {}


def _read_json_file(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _tool_root(workspace_id: str, target: str) -> Path:
    root = workspace.target_output_dir(workspace_id, target, TOOL)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _asset_dir(workspace_id: str, target: str) -> Path:
    path = _tool_root(workspace_id, target) / "assets"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _cache_index_path(workspace_id: str, target: str) -> Path:
    return _asset_dir(workspace_id, target) / "cache-index.json"


def cache_asset(
    workspace_id: str,
    target: str,
    url: str,
    body: str,
    *,
    status: int,
    content_type: str,
    source: str,
    source_endpoint: str = "",
    discovered_from: list[str] | None = None,
    approval_id: str = "",
    evidence_ids: list[str] | None = None,
    response_metadata: dict[str, Any] | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    body_bytes = body.encode("utf-8", errors="replace")
    if not body_bytes or len(body_bytes) > max_bytes or not (200 <= int(status) < 300):
        return {}
    digest = hashlib.sha256(body_bytes).hexdigest()
    normalized_url = canonical_url_identity(url) or url
    url_digest = hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()[:16]
    cache_key = hashlib.sha256(f"{normalized_url}|{digest}".encode("utf-8")).hexdigest()
    asset_path = _asset_dir(workspace_id, target) / f"{url_digest}-{digest}.js"
    if not asset_path.exists():
        asset_path.write_text(body, encoding="utf-8", errors="replace")
        _chmod_private(asset_path)
    public_url = redact_url_query_values(url) or url
    parsed = urlsplit(public_url)
    asset = JsAsset(
        url=public_url,
        host=(parsed.hostname or "").lower(),
        path=parsed.path or "/",
        source_endpoint=redact_url_query_values(source_endpoint or url) or source_endpoint or url,
        local_path=str(asset_path),
        sha256=digest,
        status=status,
        content_type=content_type,
        size=len(body_bytes),
        fetched_at=workspace.now_utc(),
        discovered_from=discovered_from or [],
        confidence="high",
    ).as_dict()
    asset.update(
        {
            "cacheKey": cache_key,
            "canonicalUrl": normalized_url,
            "cacheSource": source,
            "approvalId": approval_id,
            "evidenceIds": sorted({str(item) for item in evidence_ids or [] if item}),
            "responseMetadata": response_metadata or {},
            "provenance": [
                {
                    "source": source,
                    "approvalId": approval_id,
                    "evidenceIds": sorted({str(item) for item in evidence_ids or [] if item}),
                    "responseMetadata": response_metadata or {},
                    "fetchedAt": asset["fetchedAt"],
                }
            ],
        }
    )
    index_path = _cache_index_path(workspace_id, target)
    with workspace.workspace_lock(workspace_id):
        try:
            payload = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else {"assets": []}
        except (OSError, json.JSONDecodeError):
            payload = {"assets": []}
        existing = next(
            (item for item in payload.get("assets", []) if isinstance(item, dict) and item.get("cacheKey") == cache_key),
            None,
        )
        if existing:
            existing_refs = existing.get("evidenceIds", []) if isinstance(existing.get("evidenceIds"), list) else []
            asset["evidenceIds"] = sorted({*existing_refs, *asset.get("evidenceIds", [])})
            asset["provenance"] = [
                *(existing.get("provenance", []) if isinstance(existing.get("provenance"), list) else []),
                *asset["provenance"],
            ]
        assets = [item for item in payload.get("assets", []) if isinstance(item, dict) and item.get("cacheKey") != cache_key]
        assets.append(asset)
        index_path.write_text(
            json.dumps({"source": SOURCE, "workspaceId": workspace_id, "target": target, "assets": assets}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        _chmod_private(index_path)
    return asset


def cache_crawler_asset(
    workspace_id: str,
    url: str,
    body: str,
    *,
    status: int,
    content_type: str,
    approval_id: str = "",
    response_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return cache_asset(
        workspace_id,
        workspace.normalize_target(url),
        url,
        body,
        status=status,
        content_type=content_type,
        source="crawler",
        source_endpoint=url,
        approval_id=approval_id,
        response_metadata=response_metadata,
    )


def link_crawler_cache_evidence(workspace_id: str, target: str, urls: list[str], evidence_id: str) -> None:
    identities = {canonical_url_identity(url) for url in urls if canonical_url_identity(url)}
    index_path = _cache_index_path(workspace_id, target)
    if not evidence_id or not identities or not index_path.exists():
        return
    with workspace.workspace_lock(workspace_id):
        try:
            payload = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        changed = False
        for asset in payload.get("assets", []):
            if not isinstance(asset, dict) or asset.get("cacheSource") != "crawler" or asset.get("canonicalUrl") not in identities:
                continue
            refs = [str(item) for item in asset.get("evidenceIds", []) if item]
            if evidence_id not in refs:
                asset["evidenceIds"] = refs + [evidence_id]
                provenance = asset.get("provenance", []) if isinstance(asset.get("provenance"), list) else []
                for item in provenance:
                    if isinstance(item, dict) and item.get("source") == "crawler":
                        item_refs = [str(ref) for ref in item.get("evidenceIds", []) if ref]
                        if evidence_id not in item_refs:
                            item["evidenceIds"] = item_refs + [evidence_id]
                changed = True
        if changed:
            index_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _load_cached_assets(workspace_id: str, target: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> list[dict[str, Any]]:
    index_path = _cache_index_path(workspace_id, target)
    if not index_path.exists():
        return []
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    assets = []
    for item in payload.get("assets", []):
        if not isinstance(item, dict):
            continue
        path = Path(str(item.get("localPath") or ""))
        try:
            valid = path.is_file() and 0 < path.stat().st_size <= max_bytes and path.stat().st_size == int(item.get("size", 0) or 0)
            if valid and item.get("sha256"):
                valid = hashlib.sha256(path.read_bytes()).hexdigest() == str(item["sha256"])
        except OSError:
            valid = False
        if valid:
            assets.append(item)
    return assets


def _find_cached_asset(workspace_id: str, target: str, url: str, *, max_bytes: int) -> dict[str, Any] | None:
    identity = canonical_url_identity(url)
    matches = [item for item in _load_cached_assets(workspace_id, target, max_bytes=max_bytes) if item.get("canonicalUrl") == identity]
    return matches[-1] if matches else None


def _write_json_artifact(workspace_id: str, target: str, folder: str, suffix: str, payload: dict[str, Any]) -> Path:
    root = _tool_root(workspace_id, target) / folder
    root.mkdir(parents=True, exist_ok=True)
    path = root / workspace.timestamped_filename(suffix)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    workspace.retain_latest_artifacts(root, suffix, keep=1)
    return path


def _latest_artifact(workspace_id: str, target: str, folder: str, suffix: str) -> str:
    root = _tool_root(workspace_id, target) / folder
    matches = sorted(root.glob(f"*-{suffix}"))
    return str(matches[-1]) if matches else ""


def _dedupe_assets(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for asset in sorted(assets, key=_asset_sort_key):
        url = str(asset.get("url") or "")
        existing = merged.get(url)
        if existing is None or (asset.get("localPath") and not existing.get("localPath")):
            combined = {**(existing or {}), **asset}
            prior_discovered = (existing or {}).get("discoveredFrom", [])
            discovered = list(
                dict.fromkeys(
                    [
                        *(prior_discovered if isinstance(prior_discovered, list) else []),
                        *(asset.get("discoveredFrom", []) if isinstance(asset.get("discoveredFrom"), list) else []),
                    ]
                )
            )
            combined["discoveredFrom"] = discovered
            merged[url] = combined
    return list(merged.values())


def _asset_sort_key(asset: dict[str, Any]) -> tuple[int, int, str]:
    url = str(asset.get("url") or "")
    path = urlsplit(url).path or "/"
    penalty = 0
    if surface_hygiene.is_likely_spa_asset_pollution(url):
        penalty += 100
    if str(asset.get("confidence", "")).lower() == "high":
        penalty -= 20
    if asset.get("sourceEndpoint") == url:
        penalty -= 5
    return (penalty, path.count("/"), url)


def _dedupe_dicts(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    result = []
    for item in items:
        marker = tuple(item.get(key) for key in keys)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


def _collapse_libraries(libraries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse per-asset library detections to one component per (name, version). When a
    version was recovered for a library anywhere, drop the version-less duplicates for that
    library so a single bundle without a version banner does not spawn a second component."""
    versioned_names = {str(lib.get("name")) for lib in libraries if str(lib.get("version") or "")}
    seen: set[tuple[str, str]] = set()
    result: list[dict[str, Any]] = []
    for lib in libraries:
        name = str(lib.get("name") or "")
        version = str(lib.get("version") or "")
        if not name:
            continue
        if not version and name in versioned_names:
            continue
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        result.append(lib)
    return result


def _header(headers: dict[str, str], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return ""


def _first(value: Any) -> Any:
    return value[0] if isinstance(value, list) and value else ""


def _endpoint_flags(endpoint: dict[str, Any]) -> list[str]:
    flags = []
    if endpoint.get("derived") or endpoint.get("inferred") or endpoint.get("source") == SOURCE:
        flags.append("js-inferred")
    else:
        flags.append("observed")
    if endpoint.get("graphqlEndpoint") or "graphql" in str(endpoint.get("path", "")).lower():
        flags.append("graphql")
    if endpoint.get("hasAuthorization"):
        flags.append("auth")
    if str(endpoint.get("method", "")).upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        flags.append("state-changing")
    confidence = str(endpoint.get("confidence") or "")
    if confidence:
        flags.append(f"confidence:{confidence}")
    return flags


def _assets_for_report(workspace_id: str, target: str, analysis: dict[str, Any]) -> list[dict[str, Any]]:
    assets = analysis.get("assets", []) if isinstance(analysis.get("assets"), list) else []
    if not assets:
        latest = _latest_artifact(workspace_id, target, "manifests", "fetched-assets.json")
        if latest:
            try:
                payload = json.loads(Path(latest).read_text(encoding="utf-8"))
                assets = payload.get("assets", []) if isinstance(payload.get("assets"), list) else []
            except (OSError, json.JSONDecodeError):
                assets = []
    return [
        {
            "url": item.get("url", ""),
            "sourceAsset": item.get("url", ""),
            "localPath": item.get("localPath", ""),
            "sha256": item.get("sha256", ""),
            "size": item.get("size", 0),
            "status": item.get("status", ""),
            "contentType": item.get("contentType", ""),
        }
        for item in assets
        if isinstance(item, dict)
    ]


def _build_request_tree(requests: list[dict[str, Any]]) -> dict[str, Any]:
    root = {"name": "/", "path": "/", "children": {}, "requests": []}
    for request in requests:
        path = str(request.get("path") or "/")
        segments = [segment for segment in path.strip("/").split("/") if segment]
        current = root
        current_path = ""
        for segment in segments:
            current_path += "/" + segment
            children = current.setdefault("children", {})
            if segment not in children:
                children[segment] = {"name": segment, "path": current_path, "children": {}, "requests": []}
            current = children[segment]
        current.setdefault("requests", []).append(request)
    return _sort_tree(root)


def _sort_tree(node: dict[str, Any]) -> dict[str, Any]:
    children = node.get("children", {})
    child_nodes = [_sort_tree(child) for _, child in sorted(children.items(), key=lambda item: item[0].lower())] if isinstance(children, dict) else []
    requests = sorted(node.get("requests", []), key=lambda item: (str(item.get("method", "")), str(item.get("url", "")))) if isinstance(node.get("requests"), list) else []
    endpoint_count = len(requests) + sum(int(child.get("endpointCount", 0)) for child in child_nodes)
    return {
        "name": node.get("name", ""),
        "path": node.get("path", ""),
        "endpointCount": endpoint_count,
        "children": child_nodes,
        "requests": requests,
    }


def _render_app_map_markdown(app_map: dict[str, Any]) -> str:
    summary = app_map.get("summary", {})
    lines = [
        "# JavaScript-Enriched Application Map",
        "",
        f"- Workspace: `{app_map.get('workspaceId', '')}`",
        f"- Target: `{app_map.get('target', '')}`",
        f"- Generated: `{app_map.get('generatedAt', '')}`",
        f"- Requests: `{summary.get('endpointCount', 0)}` total, `{summary.get('observedEndpointCount', 0)}` observed, `{summary.get('jsInferredEndpointCount', 0)}` JS-inferred",
        f"- JavaScript assets: `{summary.get('assetCount', 0)}`",
        f"- JS signals: `{summary.get('jsSignalCount', 0)}`",
        "",
        "## Requests",
        "",
        "| Origin | Method | Path | Parameters | Source Asset | Confidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for request in app_map.get("requests", []) if isinstance(app_map.get("requests"), list) else []:
        params = ", ".join(str(item.get("name", "")) for item in request.get("parameters", []) if isinstance(item, dict) and item.get("name"))
        query = ", ".join(request.get("queryParameters", [])) if isinstance(request.get("queryParameters"), list) else ""
        lines.append(
            "| "
            + " | ".join(
                _md_cell(value)
                for value in [
                    request.get("origin", ""),
                    request.get("method", ""),
                    request.get("url", ""),
                    ", ".join(item for item in [query, params] if item),
                    request.get("sourceAsset", ""),
                    request.get("confidence", ""),
                ]
            )
            + " |"
        )
    lines.extend(["", "## JavaScript Signals", "", "| Type | Value | Confidence | Source Asset |", "| --- | --- | --- | --- |"])
    for item in app_map.get("jsSignals", []) if isinstance(app_map.get("jsSignals"), list) else []:
        lines.append("| " + " | ".join(_md_cell(value) for value in [item.get("type", ""), item.get("value", ""), item.get("confidence", ""), item.get("sourceAsset", "")]) + " |")
    lines.append("")
    return "\n".join(lines)


def _md_cell(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ").strip()


def _write_report_output(workspace_id: str, target: str, args: dict[str, Any], content: str, extension: str) -> Path:
    path = workspace.resolve_report_output_path(
        workspace_id,
        args.get("outputPath", ""),
        extension=extension,
        default_name=f"js-app-map-{workspace.slug(target)}.{extension}",
        allow_external=args.get("allowExternalOutput") is True,
        artifact="JS app-map",
    )
    path.write_text(content, encoding="utf-8")
    return path
