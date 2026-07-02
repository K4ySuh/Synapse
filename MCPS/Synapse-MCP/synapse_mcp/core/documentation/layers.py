# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import urlsplit

from ...adapters.web import access_control, js_intel
from .. import credentials, perimeter, workspace
from ..errors import McpError
from .models import LayerReportContext, LayerReportSection, LayerTargetContext, WorkspaceReportContext
from .redaction import policy_from_args, redact


LayerProvider = Callable[[dict[str, Any]], dict[str, Any]]
DEFAULT_LAYERS = ("perimeter", "js", "auth", "access_control", "web_vulnerabilities")

# Table columns that carry high-detail operational identifiers. Current alpha
# HTML reports are internal artifacts, so these columns stay in the report
# source and the renderer marks them for presentation-only CSS hiding in the
# High-Level view. This is not a security or client-deliverable redaction layer.
SAFE_OMITTED_COLUMNS = ("Credential ID", "Approval ID", "Local Path")

def _short_local_path(path: Any) -> str:
    # Show stored assets as a workspace-relative path rather than an absolute one:
    # keeps the table narrow and avoids leaking the operator's filesystem layout
    # into the report. The SHA-256 column already identifies the file.
    normalized = str(path or "").replace("\\", "/")
    marker = "/workspaces/"
    index = normalized.find(marker)
    if index != -1:
        return normalized[index + 1 :]
    return normalized.rsplit("/", 1)[-1] if "/" in normalized else normalized


def list_layers(_: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "layers": [
            {
                "layer": "perimeter",
                "title": "External Perimeter",
                "description": "External assets, technologies, web applications, login portals, protected resources, sitemap, and review candidates.",
                "sendsTraffic": False,
                "refreshable": True,
            },
            {
                "layer": "js",
                "title": "JavaScript Intelligence",
                "description": "Observed and JavaScript-inferred endpoints, assets, client-side signals, and analysis coverage gaps.",
                "sendsTraffic": False,
                "refreshable": False,
            },
            {
                "layer": "auth",
                "title": "Authentication Surface",
                "description": "Login portals, protected resources, authentication boundaries, session indicators, and redacted credential/profile metadata.",
                "sendsTraffic": False,
                "refreshable": True,
            },
            {
                "layer": "access_control",
                "title": "Access Control",
                "description": "Object candidates, user/role contexts, test matrix entries, replay summaries, and access-control gaps.",
                "sendsTraffic": False,
                "refreshable": False,
            },
            {
                "layer": "web_vulnerabilities",
                "title": "Web Vulnerability Candidates",
                "description": "Passive candidate observations from web vulnerability analyzers, grouped by module and kept distinct from confirmed findings.",
                "sendsTraffic": False,
                "refreshable": False,
            },
        ]
    }


def build_layer_report_context(args: dict[str, Any]) -> dict[str, Any]:
    layer = _normalize_layer(args.get("layer") or args.get("reportLayer") or "perimeter")
    provider = _providers().get(layer)
    if provider is None:
        raise McpError(-32602, f"Unknown report layer: {layer}")
    return {"contextType": "layer_report", "layerReport": provider({**args, "layer": layer})}


def build_workspace_report_context(args: dict[str, Any]) -> dict[str, Any]:
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    # The consolidated workspace report defaults to the full operator view; the
    # high-level view is an explicit usability opt-in. Both views are internal.
    policy = policy_from_args({**args, "redactionMode": args.get("redactionMode") or "internal"})
    selected = _selected_layers(args)
    layer_contexts = []
    gaps: list[str] = []
    next_steps: list[str] = []
    included_layers: list[str] = []
    for layer in selected:
        payload = build_layer_report_context({**args, "layer": layer})["layerReport"]
        # Consolidated reports always span every selected layer; empty layers
        # still render with explicit empty-state sections at the render boundary.
        layer_contexts.append(payload)
        included_layers.append(layer)
        gaps.extend(str(item) for item in payload.get("gaps", []) if str(item).strip())
        next_steps.extend(str(item) for item in payload.get("recommendedNextSteps", []) if str(item).strip())
    workspace_steps = _workspace_recommended_next_steps(layer_contexts, gaps, next_steps)
    context = WorkspaceReportContext(
        workspace_id=wid,
        title=str(args.get("title") or _workspace_report_title(policy.mode)),
        generated_at=workspace.now_utc(),
        layers=layer_contexts,
        summary={
            "layerCount": len(layer_contexts),
            "layers": included_layers,
            "targetCount": len(_target_names(wid, str(args.get("target", "") or ""))),
        },
        gaps=_dedupe_strings(gaps)[:80],
        recommended_next_steps=workspace_steps[:80],
        redaction=policy,
    )
    return {"contextType": "workspace_report", "workspaceReport": context.as_dict()}


def _workspace_report_title(mode: str) -> str:
    # The HTML output carries both the Operator and High-Level views behind a
    # client-side toggle, so the document title stays view-neutral (the active
    # view name is shown in the banner, not the title).
    return "Synapse Security Report"


def _providers() -> dict[str, LayerProvider]:
    return {
        "perimeter": _perimeter_layer,
        "js": _js_layer,
        "auth": _auth_layer,
        "access_control": _access_control_layer,
        "web_vulnerabilities": _web_vulnerabilities_layer,
    }


def _normalize_layer(value: Any) -> str:
    layer = str(value or "").strip().lower().replace("-", "_")
    if layer == "javascript":
        return "js"
    if layer in {"authentication", "authn"}:
        return "auth"
    if layer in {"access", "authorization", "authz"}:
        return "access_control"
    if layer in {"web_vulns", "vulns", "vulnerabilities", "web_vulnerability"}:
        return "web_vulnerabilities"
    return layer


def _selected_layers(args: dict[str, Any]) -> list[str]:
    raw = args.get("layers")
    if isinstance(raw, str):
        items = [item.strip() for item in raw.split(",")]
    elif isinstance(raw, list):
        items = [str(item).strip() for item in raw]
    else:
        items = list(DEFAULT_LAYERS)
    selected = []
    for item in items:
        layer = _normalize_layer(item)
        if layer not in _providers():
            raise McpError(-32602, f"Unknown report layer: {layer}")
        if layer not in selected:
            selected.append(layer)
    return selected or list(DEFAULT_LAYERS)


def _perimeter_layer(args: dict[str, Any]) -> dict[str, Any]:
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    policy = policy_from_args(args)
    payload = perimeter.build_summary({"workspaceId": wid, "target": args.get("target", ""), "refresh": bool(args.get("refresh", False))})
    summary = payload.get("summary", {})
    counts = summary.get("counts", {}) if isinstance(summary.get("counts"), dict) else {}
    summary_targets = summary.get("targets", []) if isinstance(summary.get("targets"), list) else []
    inventory_counts_by_target = {
        str(item.get("target", "")): int(item.get("candidateCount", 0) or 0)
        for item in summary_targets
        if isinstance(item, dict)
    }
    targets = [item for item in payload.get("targets", []) if isinstance(item, dict)]
    single_target = len(targets) == 1
    target_contexts = []
    for report in targets:
        # Drop SPA-shell phantom/noise candidates (e.g. CORS flagged on a mis-resolved
        # chunk .js or a bare numeric route) so the count, list, and table agree and the
        # report stays de-noised over already-stored crawl data.
        report["findingCandidates"] = [
            candidate
            for candidate in report.get("findingCandidates", [])
            if isinstance(candidate, dict) and not _candidate_targets_noise_surface(candidate)
        ]
        site_map = report.get("siteMap", {}) if isinstance(report.get("siteMap"), dict) else {}
        target_contexts.append(
            LayerTargetContext(
                target=str(report.get("target", "")),
                summary={
                    "serviceCount": report.get("asset", {}).get("serviceCount", 0),
                    "endpointCount": report.get("asset", {}).get("endpointCount", 0),
                    "webApplicationCount": len(report.get("webApplications", [])),
                    "technologyCount": len(report.get("technologyComponents", [])),
                    "loginPortalCount": len(report.get("loginPortals", [])),
                    "protectedResourceCount": len(report.get("protectedResources", [])),
                    "candidateCount": inventory_counts_by_target.get(str(report.get("target", "")), 0),
                },
                sections=[
                    _section(
                        "site_map",
                        "Site Map",
                        "tree",
                        tree=site_map.get("tree", {}) if isinstance(site_map.get("tree"), dict) else {},
                        summary=f"{site_map.get('endpointCount', 0)} endpoint records.",
                    )
                ],
                observations=redact(report.get("perimeterObservations", []), policy),
                candidates=redact(report.get("findingCandidates", []), policy),
                evidence_ids=_evidence_ids(report),
                gaps=_perimeter_gaps(report),
                recommended_next_steps=_perimeter_steps(report),
            )
        )
    context = LayerReportContext(
        workspace_id=wid,
        layer="perimeter",
        title="Application Surface Report" if single_target else "External Perimeter Report",
        generated_at=str(summary.get("generatedAt") or workspace.now_utc()),
        summary=redact(
            {
                "targetCount": counts.get("targets", len(targets)),
                "endpointCount": sum(int(report.get("asset", {}).get("endpointCount", 0) or 0) for report in targets),
                "webApplicationCount": counts.get("webApplications", 0),
                "technologyCount": len(summary.get("technologyMatrix", [])) if isinstance(summary.get("technologyMatrix"), list) else counts.get("technologyComponents", 0),
                "loginPortalCount": counts.get("loginPortals", 0),
                "candidateCount": counts.get("findingCandidates", 0),
                "generatedAt": summary.get("generatedAt", ""),
            },
            policy,
        ),
        targets=target_contexts,
        sections=[
            _section(
                "host_inventory",
                "Host Inventory",
                "table",
                headers=["Host", "Ports", "Web Apps", "Technologies", "Login Portals", "Candidates"],
                rows=[
                    [
                        item.get("target", ""),
                        ", ".join(str(port) for port in item.get("ports", [])),
                        item.get("webApplicationCount", 0),
                        item.get("technologyCount", 0),
                        item.get("loginPortalCount", 0),
                        item.get("candidateCount", 0),
                    ]
                    for item in summary_targets
                    if isinstance(item, dict)
                ],
            ),
            _section(
                "technology_matrix",
                "Technology Matrix",
                "table",
                headers=["Technology", "Version", "Source", "Hosts"],
                rows=[
                    [item.get("name") or item.get("technology", ""), item.get("version", ""), item.get("source", ""), ", ".join(item.get("hosts", []))]
                    for item in summary.get("technologyMatrix", [])
                    if isinstance(item, dict)
                ],
            ),
            _section(
                "web_applications",
                "Web Applications",
                "table",
                headers=["Host", "Base URL", "Application", "Routes", "Auth"],
                rows=[
                    [report.get("target", ""), app.get("baseUrl", ""), app.get("appFamily", ""), app.get("routeCount", 0), "yes" if app.get("authRequired") else "no"]
                    for report in targets
                    for app in report.get("webApplications", [])
                    if isinstance(app, dict)
                ],
            ),
            _section(
                "login_portals",
                "Login Portals",
                "table",
                headers=["Host", "Representative URL", "Provider", "Method", "Status", "Variants", "Inputs"],
                rows=[
                    [
                        report.get("target", ""),
                        portal.get("representativeUrl") or portal.get("url", ""),
                        portal.get("provider") or portal.get("technology", ""),
                        portal.get("method", ""),
                        portal.get("status", ""),
                        portal.get("variantCount", 1),
                        _join(portal.get("inputNames", [])),
                    ]
                    for report in targets
                    for portal in report.get("loginPortals", [])
                    if isinstance(portal, dict)
                ],
            ),
            _candidate_section(
                "candidate_review_items",
                "Candidate Findings And Review Items",
                ["Host", "Severity", "Category", "Request", "Method", "Parameter", "Candidate ID", "Evidence", "Count", "Source", "Reason"],
                [
                    [
                        report.get("target", ""),
                        candidate.get("severity", ""),
                        candidate.get("category") or candidate.get("title", ""),
                        _candidate_request_label(candidate),
                        _candidate_metadata_value(candidate, "method"),
                        _candidate_parameter_label(candidate),
                        _candidate_id(candidate),
                        _join(candidate.get("evidenceIds", []), limit=3) or "not recorded",
                        candidate.get("occurrenceCount", 1),
                        candidate.get("source", ""),
                        candidate.get("reason", ""),
                    ]
                    for report in targets
                    for candidate in report.get("findingCandidates", [])
                    if isinstance(candidate, dict) and not _candidate_targets_noise_surface(candidate)
                ],
                group_by="Category",
            ),
        ],
        gaps=_dedupe_strings([gap for ctx in target_contexts for gap in ctx.gaps]),
        recommended_next_steps=_dedupe_strings([step for ctx in target_contexts for step in ctx.recommended_next_steps]),
        redaction=policy,
    )
    return context.as_dict()


def _js_layer(args: dict[str, Any]) -> dict[str, Any]:
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    policy = policy_from_args(args)
    targets = _target_names(wid, str(args.get("target", "") or ""))
    target_contexts = []
    asset_rows: list[list[Any]] = []
    signal_rows: list[list[Any]] = []
    gaps: list[str] = []
    steps: list[str] = []
    totals = {"endpointCount": 0, "observedEndpointCount": 0, "jsInferredEndpointCount": 0, "assetCount": 0, "jsSignalCount": 0, "parameterCount": 0}
    for target in targets:
        entities = workspace.load_reportable_target_entities(wid, target)
        # Hide SPA-shell phantom asset endpoints (already-stored crawl noise) so the
        # JS request map matches a freshly crawled, de-noised workspace.
        entities = {**entities, "endpoints": [item for item in entities["endpoints"] if not is_phantom_asset_endpoint(item)]}
        app_map = js_intel.build_full_app_map(wid, target, entities, None)
        summary = app_map.get("summary", {})
        for key in totals:
            totals[key] += int(summary.get(key, 0) or 0)
        for asset in app_map.get("assets", []):
            if isinstance(asset, dict):
                asset_rows.append([target, asset.get("url", ""), asset.get("status", ""), asset.get("size", ""), asset.get("sha256", ""), _short_local_path(asset.get("localPath", ""))])
        for signal in app_map.get("jsSignals", []):
            if isinstance(signal, dict):
                signal_record = {
                    "host": target,
                    "type": signal.get("type", ""),
                    "value": signal.get("value", ""),
                    "sourceAsset": signal.get("sourceAsset", ""),
                    "reason": signal.get("reason", ""),
                }
                signal_rows.append([target, signal_record["type"], signal_record["value"], signal_record["sourceAsset"], signal_record["reason"]])
        target_gaps = _js_gaps(target, app_map)
        gaps.extend(target_gaps)
        target_steps = _js_steps(target, app_map, target_gaps)
        steps.extend(target_steps)
        target_contexts.append(
            LayerTargetContext(
                target=target,
                summary=summary,
                sections=[_section("request_map", "Request Map", "tree", tree=app_map.get("tree", {}), summary=f"{summary.get('endpointCount', 0)} request records.")],
                observations=redact(app_map.get("jsSignals", []), policy),
                evidence_ids=_evidence_ids(app_map),
                gaps=target_gaps,
                recommended_next_steps=target_steps,
            )
        )
    asset_headers, asset_rows = _audience_columns(["Host", "URL", "Status", "Size", "SHA-256", "Local Path"], asset_rows, policy)
    context = LayerReportContext(
        workspace_id=wid,
        layer="js",
        title="JavaScript Intelligence Report",
        generated_at=workspace.now_utc(),
        summary=totals,
        targets=target_contexts,
        sections=[
            _section("assets", "JavaScript Assets", "table", headers=asset_headers, rows=asset_rows),
            _signal_section("signals", "JavaScript Signals", ["Host", "Type", "Value", "Source Asset", "Reason"], signal_rows),
        ],
        gaps=_dedupe_strings(gaps),
        recommended_next_steps=_dedupe_strings(steps),
        redaction=policy,
    )
    return context.as_dict()


def _auth_layer(args: dict[str, Any]) -> dict[str, Any]:
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    policy = policy_from_args(args)
    payload = perimeter.build_summary({"workspaceId": wid, "target": args.get("target", ""), "refresh": bool(args.get("refresh", False))})
    targets = [item for item in payload.get("targets", []) if isinstance(item, dict)]
    target_names = [str(item.get("target", "")) for item in targets if str(item.get("target", "")).strip()]
    credential_rows = _credential_rows(target_names)
    portal_rows: list[list[Any]] = []
    protected_rows: list[list[Any]] = []
    boundary_rows: list[list[Any]] = []
    target_contexts = []
    gaps: list[str] = []
    steps: list[str] = []
    for report in targets:
        target = str(report.get("target", ""))
        entities = workspace.load_reportable_target_entities(wid, target)
        target_portals = report.get("loginPortals", []) if isinstance(report.get("loginPortals"), list) else []
        protected = report.get("protectedResources", []) if isinstance(report.get("protectedResources"), list) else []
        boundaries = [item for item in report.get("perimeterObservations", []) if isinstance(item, dict) and item.get("type") in {"auth_boundary", "protected_resource"}]
        for portal in target_portals:
            if isinstance(portal, dict):
                portal_rows.append([target, portal.get("representativeUrl") or portal.get("url", ""), portal.get("provider") or portal.get("technology", ""), portal.get("method", ""), portal.get("status", ""), _join(portal.get("inputNames", []))])
        for item in protected:
            if isinstance(item, dict):
                protected_rows.append([target, item.get("method", ""), item.get("url", ""), item.get("status", ""), _join(item.get("redirectLocations", [])), item.get("reason", "")])
        for item in boundaries:
            boundary_rows.append([target, item.get("type", ""), item.get("value", ""), item.get("reason", "")])
        target_gaps = _auth_gaps(target, target_portals, protected, entities)
        target_steps = _auth_steps(target, target_portals, protected, entities)
        gaps.extend(target_gaps)
        steps.extend(target_steps)
        target_contexts.append(
            LayerTargetContext(
                target=target,
                summary={
                    "loginPortalCount": len(target_portals),
                    "protectedResourceCount": len(protected),
                    "authBoundaryObservationCount": len(boundaries),
                    "credentialMetadataCount": len([row for row in credential_rows if target in str(row[2]) or not row[2]]),
                },
                observations=redact(boundaries, policy),
                evidence_ids=_evidence_ids({"loginPortals": target_portals, "protectedResources": protected, "observations": boundaries}),
                gaps=target_gaps,
                recommended_next_steps=target_steps,
            )
        )
    context = LayerReportContext(
        workspace_id=wid,
        layer="auth",
        title="Authentication Surface Report",
        generated_at=workspace.now_utc(),
        summary={"targetCount": len(targets), "loginPortalCount": len(portal_rows), "protectedResourceCount": len(protected_rows), "credentialMetadataCount": len(credential_rows)},
        targets=target_contexts,
        sections=[
            _section("login_portals", "Login Portals", "table", headers=["Host", "Representative URL", "Provider", "Method", "Status", "Inputs"], rows=portal_rows),
            _section("protected_resources", "Protected Resources", "table", headers=["Host", "Method", "URL", "Status", "Redirects", "Reason"], rows=protected_rows),
            _section("auth_boundaries", "Authentication Boundary Observations", "table", headers=["Host", "Type", "Value", "Reason"], rows=boundary_rows),
            _section("credential_metadata", "Redacted Credential/Profile Metadata", "table", headers=["ID", "Type", "Scopes", "Username/Profile", "Auth State"], rows=credential_rows),
        ],
        gaps=_dedupe_strings(gaps),
        recommended_next_steps=_dedupe_strings(steps),
        redaction=policy,
    )
    return context.as_dict()


def _access_control_layer(args: dict[str, Any]) -> dict[str, Any]:
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    policy = policy_from_args(args)
    targets = _target_names(wid, str(args.get("target", "") or ""))
    target_contexts = []
    object_rows: list[list[Any]] = []
    context_rows: list[list[Any]] = []
    matrix_rows: list[list[Any]] = []
    replay_rows: list[list[Any]] = []
    candidate_rows: list[list[Any]] = []
    gaps: list[str] = []
    steps: list[str] = []
    summary = {"objectCount": 0, "contextCount": 0, "matrixCount": 0, "replayCount": 0, "accessControlReviewItems": 0}
    for target in targets:
        objects = access_control.read_access_control_items(wid, target, "objects")
        contexts = access_control.read_access_control_items(wid, target, "contexts")
        matrix = access_control.read_access_control_items(wid, target, "matrix")
        replays = access_control.read_access_control_items(wid, target, "replays")
        entities = workspace.load_reportable_target_entities(wid, target)
        candidates = [
            item
            for item in entities["observations"]
            if isinstance(item, dict)
            and (str(item.get("type", "")).startswith("access_control_") or item.get("type") == "possible_broken_access_control")
        ]
        summary["objectCount"] += len(objects)
        summary["contextCount"] += len(contexts)
        summary["matrixCount"] += len(matrix)
        summary["replayCount"] += len(replays)
        summary["accessControlReviewItems"] += len(candidates)
        has_target_data = bool(objects or contexts or matrix or replays or candidates)
        if not has_target_data:
            continue
        for item in objects:
            object_rows.append([target, item.get("objectType", ""), item.get("method", ""), item.get("endpointPattern", ""), item.get("identifierName", ""), item.get("location", ""), item.get("testClass", ""), item.get("priority", ""), item.get("reason", "")])
        for item in contexts:
            context_rows.append([target, item.get("contextId", ""), item.get("label", ""), item.get("role", ""), item.get("authState", ""), item.get("credentialId", ""), _join(item.get("ownedObjectTypes", []))])
        for item in matrix:
            matrix_rows.append([target, item.get("matrixId", ""), item.get("testClass", ""), item.get("method", ""), item.get("endpointPattern", ""), _join(item.get("requiredContexts", [])), item.get("riskTier", ""), "yes" if item.get("stateChanging") else "no"])
        for item in replays:
            replay_rows.append(
                [
                    target,
                    item.get("replayId", ""),
                    item.get("matrixId", ""),
                    item.get("testClass", ""),
                    item.get("method", ""),
                    item.get("requestUrl") or item.get("endpointPattern", ""),
                    item.get("endpointPattern", ""),
                    item.get("assessment", ""),
                    item.get("approval", {}).get("approvalId", "") if isinstance(item.get("approval"), dict) else "",
                ]
            )
        for item in candidates:
            candidate_rows.append([target, item.get("type", ""), _access_control_candidate_value(item), item.get("priority", ""), item.get("reason", "")])
        target_gaps = _access_control_gaps(target, objects, contexts, matrix, replays)
        target_steps = _access_control_steps(target, objects, contexts, matrix, replays)
        gaps.extend(target_gaps)
        steps.extend(target_steps)
        target_contexts.append(
            LayerTargetContext(
                target=target,
                summary={"objectCount": len(objects), "contextCount": len(contexts), "matrixCount": len(matrix), "replayCount": len(replays), "accessControlReviewItems": len(candidates)},
                observations=redact(candidates, policy),
                evidence_ids=_evidence_ids({"objects": objects, "contexts": contexts, "matrix": matrix, "replays": replays, "observations": candidates}),
                gaps=target_gaps,
                recommended_next_steps=target_steps,
            )
        )
    context_headers, context_rows = _audience_columns(["Host", "Context ID", "Label", "Role", "Auth State", "Credential ID", "Owned Object Types"], context_rows, policy)
    replay_headers, replay_rows = _audience_columns(["Host", "Replay ID", "Matrix ID", "Class", "Method", "Request URL", "Endpoint Pattern", "Assessment", "Approval ID"], replay_rows, policy)
    context = LayerReportContext(
        workspace_id=wid,
        layer="access_control",
        title="Access Control Report",
        generated_at=workspace.now_utc(),
        summary=summary,
        targets=target_contexts,
        # Always emit the full canonical section set; empty sections render an
        # explicit empty-state line at the render boundary rather than vanishing.
        sections=[
            _section("objects", "Object And Function Candidates", "table", headers=["Host", "Object Type", "Method", "Endpoint Pattern", "Identifier", "Location", "Class", "Priority", "Reason"], rows=object_rows),
            _section("contexts", "Recorded User/Role Contexts", "table", headers=context_headers, rows=context_rows),
            _section("matrix", "Access-Control Test Matrix", "table", headers=["Host", "Matrix ID", "Class", "Method", "Endpoint Pattern", "Required Contexts", "Risk", "State Changing"], rows=matrix_rows),
            _section("replays", "Replay Results", "table", headers=replay_headers, rows=replay_rows),
            _candidate_section("candidates", "Access-Control Candidate Observations", ["Host", "Type", "Value", "Priority", "Reason"], candidate_rows, group_by="Type"),
        ],
        gaps=_dedupe_strings(gaps),
        recommended_next_steps=_dedupe_strings(steps),
        redaction=policy,
    )
    return context.as_dict()


def _web_vulnerabilities_layer(args: dict[str, Any]) -> dict[str, Any]:
    wid = workspace.normalize_workspace_id(args["workspaceId"])
    policy = policy_from_args(args)
    targets = _target_names(wid, str(args.get("target", "") or ""))
    target_contexts = []
    candidate_rows: list[list[Any]] = []
    finding_rows: list[list[Any]] = []
    gaps: list[str] = []
    steps: list[str] = []
    module_counts: dict[str, int] = {}
    summary = {"targetCount": len(targets), "candidateCount": 0, "findingCount": 0, "moduleCounts": module_counts}
    for target in targets:
        entities = workspace.load_reportable_target_entities(wid, target)
        inventory = perimeter.candidate_inventory(entities, target)
        target_candidates = [item for item in inventory.get("items", []) if isinstance(item, dict)]
        target_modules: dict[str, int] = dict(inventory.get("byModule", {})) if isinstance(inventory.get("byModule"), dict) else {}
        target_candidates_by_module: dict[str, list[dict[str, Any]]] = {}
        for module, count in target_modules.items():
            module_counts[module] = module_counts.get(module, 0) + int(count or 0)
        for observation in target_candidates:
            module = str(observation.get("candidateModule", ""))
            if module:
                target_candidates_by_module.setdefault(module, []).append(observation)
        candidate_rows.extend(_web_vulnerability_summary_rows(target, target_candidates_by_module))
        target_findings = [item for item in entities["findings"] if isinstance(item, dict)]
        for finding in target_findings:
            finding_rows.append(
                [
                    target,
                    finding.get("severity", ""),
                    finding.get("title", ""),
                    finding.get("status", ""),
                    _join(finding.get("affectedAssets", []), limit=4) or target,
                    _join(finding.get("evidenceIds", []), limit=3) or "not recorded",
                ]
            )
        target_gaps = _web_vulnerability_gaps(target, entities, target_modules)
        target_steps = _web_vulnerability_steps(target, target_modules, target_gaps)
        gaps.extend(target_gaps)
        steps.extend(target_steps)
        summary["candidateCount"] += int(inventory.get("total", 0) or 0)
        summary["findingCount"] += len(target_findings)
        target_contexts.append(
            LayerTargetContext(
                target=target,
                summary={"candidateCount": len(target_candidates), "findingCount": len(target_findings), "moduleCounts": target_modules},
                observations=redact(target_candidates, policy),
                candidates=redact(target_candidates, policy),
                evidence_ids=_evidence_ids({"observations": target_candidates, "findings": target_findings}),
                gaps=target_gaps,
                recommended_next_steps=target_steps,
            )
        )
    context = LayerReportContext(
        workspace_id=wid,
        layer="web_vulnerabilities",
        title="Web Vulnerability Candidate Report",
        generated_at=workspace.now_utc(),
        summary=redact(summary, policy),
        targets=target_contexts,
        sections=[
            _candidate_section(
                "web_vulnerability_candidates",
                "High-Value Candidate Surface",
                ["Host", "Module", "Top Surface", "Parameter", "Priority", "Count", "Evidence", "Reason"],
                candidate_rows,
                group_by="Module",
            ),
            _section("reviewed_findings", "Workspace Findings", "table", headers=["Host", "Severity", "Title", "Status", "Affected Assets", "Evidence"], rows=finding_rows),
        ],
        gaps=_dedupe_strings(gaps),
        recommended_next_steps=_dedupe_strings(steps),
        redaction=policy,
    )
    return context.as_dict()


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


def _workspace_recommended_next_steps(layer_contexts: list[dict[str, Any]], gaps: list[str], fallback_steps: list[str]) -> list[str]:
    steps: list[str] = []
    for layer in layer_contexts:
        name = str(layer.get("layer", ""))
        summary = layer.get("summary", {}) if isinstance(layer.get("summary"), dict) else {}
        if name == "access_control":
            candidate_counts = _candidate_group_counts(layer)
            possible_bac = candidate_counts.get("possible_broken_access_control", 0)
            replay_count = int(summary.get("replayCount", 0) or 0)
            if possible_bac:
                steps.append(
                    f"Review the {possible_bac} possible broken access-control replay candidate(s) before promotion; use the replay IDs and approval IDs in the access-control layer to decide whether each is expected access, a finding, or a false positive."
                )
            elif replay_count:
                steps.append(
                    f"Close out the {replay_count} access-control replay result(s) by recording reviewer disposition for any inconclusive or expected-access comparisons."
                )
        elif name == "perimeter":
            candidate_counts = _candidate_group_counts(layer)
            header_count = candidate_counts.get("Security header hygiene candidate", 0)
            cookie_count = candidate_counts.get("Cookie hygiene candidate", 0)
            open_redirect_count = candidate_counts.get("Open redirect candidate", 0)
            if header_count or cookie_count:
                issue_bits = []
                if header_count:
                    issue_bits.append(f"{header_count} security-header class(es)")
                if cookie_count:
                    issue_bits.append(f"{cookie_count} cookie-flag issue(s)")
                steps.append(
                    f"Consolidate the header/cookie hygiene observations into one remediation review: validate {' and '.join(issue_bits)} on representative SPA/API responses and document the intended baseline policy."
                )
            if open_redirect_count:
                steps.append(
                    f"Triage the {open_redirect_count} open-redirect candidate(s) separately from hygiene items; validate only with a harmless destination after explicit approval."
                )
        elif name == "js":
            asset_count = int(summary.get("assetCount", 0) or 0)
            signal_count = int(summary.get("jsSignalCount", 0) or 0)
            inferred_count = int(summary.get("jsInferredEndpointCount", 0) or 0)
            if asset_count and signal_count == 0:
                steps.append(
                    f"Re-check JavaScript analysis coverage: {asset_count} asset(s) are stored but no client-side signals were extracted, so confirm the bundles were analyzed with the current parser before relying on JS coverage."
                )
            elif inferred_count:
                steps.append(f"Validate the {inferred_count} JS-inferred endpoint(s) against observed traffic before treating them as confirmed attack surface.")
        elif name == "auth":
            login_count = int(summary.get("loginPortalCount", 0) or 0)
            protected_count = int(summary.get("protectedResourceCount", 0) or 0)
            credential_count = int(summary.get("credentialMetadataCount", 0) or 0)
            if login_count and protected_count == 0:
                steps.append(
                    f"Define a small protected-resource baseline for the {login_count} login/auth surface(s), then map expected anonymous, normal-user, and privileged-user behavior using credential references."
                )
            elif credential_count and protected_count:
                steps.append(f"Use the {credential_count} stored credential reference(s) to validate the recorded protected-resource boundaries without embedding secrets in reports.")
        elif name == "web_vulnerabilities":
            candidate_count = int(summary.get("candidateCount", 0) or 0)
            if candidate_count:
                steps.append(f"Review the {candidate_count} passive web vulnerability candidate observation(s) before requesting active validation or promoting findings.")
    if not steps:
        steps.extend(fallback_steps)
    if not steps and gaps:
        steps.append("Review the coverage gaps above and add the next validation step for each unresolved layer.")
    return _dedupe_strings(steps)


def _candidate_group_counts(layer: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    sections = layer.get("sections", []) if isinstance(layer.get("sections"), list) else []
    for section in sections:
        metadata = section.get("metadata", {}) if isinstance(section, dict) and isinstance(section.get("metadata"), dict) else {}
        groups = metadata.get("groups", []) if isinstance(metadata.get("groups"), list) else []
        for group in groups:
            if not isinstance(group, dict):
                continue
            category = str(group.get("category", "") or "").strip()
            if not category:
                continue
            counts[category] = counts.get(category, 0) + int(group.get("count", 0) or len(group.get("rows", []) if isinstance(group.get("rows"), list) else []))
    return counts


def _access_control_candidate_value(item: dict[str, Any]) -> str:
    value = str(item.get("value", "") or "").strip()
    if value:
        return value
    method = str(item.get("method", "") or "").upper().strip()
    request_url = str(item.get("requestUrl", "") or item.get("url", "") or "").strip()
    endpoint = str(item.get("endpointPattern", "") or "").strip()
    matrix_id = str(item.get("matrixId", "") or "").strip()
    replay_id = str(item.get("replayId", "") or "").strip()
    base = request_url or endpoint or matrix_id or replay_id
    if method and base and base.startswith(("http://", "https://", "/")):
        base = f"{method} {base}"
    if matrix_id and matrix_id not in base:
        return f"{base} ({matrix_id})" if base else matrix_id
    if replay_id and replay_id not in base:
        return f"{base} ({replay_id})" if base else replay_id
    return base


_STATIC_ASSET_EXTENSIONS = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif",
)


def _is_static_asset_url(url: Any) -> bool:
    return urlsplit(str(url or "")).path.lower().endswith(_STATIC_ASSET_EXTENSIONS)


def is_phantom_asset_endpoint(record: dict[str, Any]) -> bool:
    """True for a static-asset endpoint the SPA answered with its HTML shell.

    These phantom endpoints are born when a crawler resolves a relative asset URL
    against a route directory and the catch-all returns ``index.html`` (text/html,
    2xx). The crawler now drops them at ingest, but reports must also hide any that
    are already stored in a workspace so every generated report stays de-noised.
    """
    if not isinstance(record, dict) or not _is_static_asset_url(record.get("url", "")):
        return False
    if not record.get("fetched"):
        return False
    content_types = [str(item).lower() for item in (record.get("contentTypes") or []) if str(item).strip()]
    if not content_types:
        return False
    return all(("text/html" in content_type or "application/xhtml" in content_type) for content_type in content_types)


def _candidate_targets_noise_surface(observation: dict[str, Any]) -> bool:
    """True when a candidate's surface is report noise rather than a real API surface.

    Covers SPA-shell static assets (e.g. a mis-resolved ``/route/chunk-XXXX.js``) and
    bare single all-numeric SPA route literals (e.g. ``/160``) that the catch-all
    answers with the HTML shell. Such candidates only flood the report; the underlying
    endpoint, if real, still appears in the site map.
    """
    url = str(observation.get("url") or "")
    if not url:
        parts = str(observation.get("value") or "").split()
        url = parts[-1] if parts else ""
    if _is_static_asset_url(url):
        return True
    segments = [segment for segment in urlsplit(url).path.split("/") if segment]
    return len(segments) == 1 and segments[0].isdigit()


def _web_vulnerability_summary_rows(target: str, candidates_by_module: dict[str, list[dict[str, Any]]]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    ordered = sorted(
        candidates_by_module.items(),
        key=lambda item: (
            min((_severity_rank(_candidate_priority(candidate)) for candidate in item[1]), default=5),
            -len(item[1]),
            item[0],
        ),
    )
    for module, candidates in ordered:
        filtered = [candidate for candidate in candidates if isinstance(candidate, dict)]
        if not filtered:
            continue
        top = sorted(filtered, key=_candidate_report_sort_key)[0]
        evidence_ids: list[Any] = []
        for candidate in filtered:
            evidence_ids.extend(candidate.get("evidenceIds", []) if isinstance(candidate.get("evidenceIds"), list) else [])
        rows.append(
            [
                target,
                module,
                _candidate_surface_label(top),
                _candidate_parameter_label(top),
                _candidate_priority(top),
                len(filtered),
                _join(_dedupe_strings([str(item) for item in evidence_ids]), limit=3) or "not recorded",
                _candidate_report_reason(top),
            ]
        )
    return rows


def _candidate_report_sort_key(candidate: dict[str, Any]) -> tuple[int, int, str]:
    return (
        _severity_rank(_candidate_priority(candidate)),
        -int(candidate.get("priorityScore", 0) or 0),
        _candidate_surface_label(candidate),
    )


def _candidate_priority(candidate: dict[str, Any]) -> str:
    value = str(candidate.get("priority") or candidate.get("severity") or "").strip().lower()
    return value if value in _SEVERITY_RANK else "info"


def _candidate_surface_label(candidate: dict[str, Any]) -> str:
    label = _candidate_request_label(candidate)
    parts = label.split(maxsplit=1)
    if len(parts) == 2 and parts[1].startswith(("http://", "https://")):
        parsed = urlsplit(parts[1])
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return f"{parts[0]} {path}"
    if label.startswith(("http://", "https://")):
        parsed = urlsplit(label)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path
    return label


def _candidate_report_reason(candidate: dict[str, Any]) -> str:
    reason = str(candidate.get("reason") or "").strip()
    if reason:
        return reason
    reasons = candidate.get("reasons")
    if isinstance(reasons, list):
        return "; ".join(str(item) for item in reasons[:2] if str(item).strip())
    return ""


def _web_vulnerability_gaps(target: str, entities: dict[str, list[dict[str, Any]]], module_counts: dict[str, int]) -> list[str]:
    gaps = []
    if not entities["endpoints"] and not entities["parameters"]:
        gaps.append(f"No endpoint or parameter data is recorded for web vulnerability analysis on {target}.")
        return gaps
    if "xss" not in module_counts and not _target_has_module_action(entities, "xss"):
        gaps.append(f"No XSS passive candidate analysis is recorded for {target}.")
    if "sqli" not in module_counts and not _target_has_module_action(entities, "sqli"):
        gaps.append(f"No SQL injection passive candidate analysis is recorded for {target}.")
    return gaps


def _web_vulnerability_steps(target: str, module_counts: dict[str, int], gaps: list[str]) -> list[str]:
    steps = []
    if any("XSS" in gap or "SQL injection" in gap for gap in gaps):
        steps.append(f"Run workspace-native XSS and SQLi passive analyzers for {target}, then review generated candidates before any active validation.")
    if module_counts:
        total = sum(module_counts.values())
        steps.append(f"Review {total} web vulnerability candidate observation(s) for {target}; promote only operator-accepted issues to findings.")
    return steps


def _target_has_module_action(entities: dict[str, list[dict[str, Any]]], module: str) -> bool:
    for action in entities["actions"]:
        if not isinstance(action, dict):
            continue
        for key in ("tool", "adapter", "profile", "type"):
            value = str(action.get(key, "") or "").lower()
            if value.startswith(f"{module}.") or value == module:
                return True
    return False


def _audience_columns(headers: list[str], rows: list[list[Any]], policy: Any) -> tuple[list[str], list[list[Any]]]:
    """Preserve table columns for internal HTML presentation switching.

    Older redaction-oriented reports omitted columns here. Current alpha
    reports are internal operator artifacts, so high-level mode reduces noise
    with CSS in the renderer rather than removing source values.
    """
    return headers, rows


def _section(section_id: str, title: str, kind: str, *, headers: list[str] | None = None, rows: list[list[Any]] | None = None, items: list[dict[str, Any]] | None = None, tree: dict[str, Any] | None = None, summary: str = "", metadata: dict[str, Any] | None = None) -> LayerReportSection:
    return LayerReportSection(section_id=section_id, title=title, kind=kind, headers=headers or [], rows=rows or [], items=items or [], tree=tree or {}, summary=summary, metadata=metadata or {})


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_rank(value: Any) -> int:
    return _SEVERITY_RANK.get(str(value or "").strip().lower(), 5)


def _candidate_groups(headers: list[str], rows: list[list[Any]], group_by: str) -> list[dict[str, Any]]:
    """Group flat candidate rows into per-category tables.

    The grouping column becomes each group's heading and is dropped from the
    per-group table columns. Rows are ordered by severity within a group, and
    groups by their most severe row. This keeps heterogeneous review items
    (one per analyzer category) legible instead of a single flat table that
    floods the report.
    """
    if group_by not in headers:
        return [{"category": "Candidates", "count": len(rows), "headers": list(headers), "rows": list(rows)}] if rows else []
    group_index = headers.index(group_by)
    out_headers = [header for index, header in enumerate(headers) if index != group_index]
    severity_index = out_headers.index("Severity") if "Severity" in out_headers else (out_headers.index("Priority") if "Priority" in out_headers else None)
    count_index = out_headers.index("Count") if "Count" in out_headers else None
    grouped: dict[str, list[list[Any]]] = {}
    order: list[str] = []
    for row in rows:
        category = str(row[group_index] if group_index < len(row) else "").strip() or "Uncategorized"
        if category not in grouped:
            grouped[category] = []
            order.append(category)
        grouped[category].append([cell for index, cell in enumerate(row) if index != group_index])
    groups: list[dict[str, Any]] = []
    for category in order:
        group_rows = grouped[category]
        if severity_index is not None:
            group_rows = sorted(group_rows, key=lambda candidate: _severity_rank(candidate[severity_index] if severity_index < len(candidate) else ""))
        display_count = len(group_rows)
        if count_index is not None and group_by == "Module":
            display_count = sum(int(row[count_index] or 0) for row in group_rows if count_index < len(row) and str(row[count_index] or "").isdigit()) or len(group_rows)
        groups.append({"category": category, "count": display_count, "headers": out_headers, "rows": group_rows})
    if severity_index is not None:
        groups.sort(key=lambda group: min((_severity_rank(row[severity_index]) for row in group["rows"] if severity_index < len(row)), default=5))
    return groups


def _candidate_section(section_id: str, title: str, headers: list[str], rows: list[list[Any]], *, group_by: str) -> LayerReportSection:
    """A candidate/review section rendered as compact per-category tables.

    Flat ``rows`` are kept on the section for content detection and JSON
    consumers; ``metadata.groups`` carries the grouped view the renderer uses.
    """
    return _section(section_id, title, "candidate_groups", headers=headers, rows=rows, metadata={"groups": _candidate_groups(headers, rows, group_by)})


def _signal_groups(headers: list[str], rows: list[list[Any]], group_by: str = "Type") -> list[dict[str, Any]]:
    if group_by not in headers:
        return [{"category": "JavaScript signals", "count": len(rows), "headers": list(headers), "rows": list(rows)}] if rows else []
    group_index = headers.index(group_by)
    out_headers = [header for index, header in enumerate(headers) if index != group_index]
    grouped: dict[str, list[list[Any]]] = {}
    for row in rows:
        category = str(row[group_index] if group_index < len(row) else "").strip() or "uncategorized_signal"
        grouped.setdefault(category, []).append([cell for index, cell in enumerate(row) if index != group_index])
    groups = [
        {
            "category": category,
            "count": len(group_rows),
            "headers": out_headers,
            "rows": sorted(group_rows, key=lambda item: str(item[1] if len(item) > 1 else item[0]).lower()),
        }
        for category, group_rows in grouped.items()
    ]
    return sorted(groups, key=lambda group: (-int(group.get("count", 0) or 0), str(group.get("category", "")).lower()))


def _signal_section(section_id: str, title: str, headers: list[str], rows: list[list[Any]]) -> LayerReportSection:
    return _section(section_id, title, "signal_groups", headers=headers, rows=rows, metadata={"groups": _signal_groups(headers, rows)})


def _candidate_request_label(candidate: dict[str, Any]) -> str:
    request = str(candidate.get("request") or "").strip()
    if request:
        return request
    url = str(candidate.get("url") or candidate.get("value") or "").strip()
    if url:
        method = str(candidate.get("method") or "").upper().strip()
        return f"{method} {url}".strip()
    return "not recorded"


def _candidate_metadata_value(candidate: dict[str, Any], key: str) -> str:
    value = str(candidate.get(key) or "").strip()
    return value if value else "not recorded"


def _candidate_parameter_label(candidate: dict[str, Any]) -> str:
    return str(candidate.get("parameter") or candidate.get("location") or "not recorded")


def _candidate_id(candidate: dict[str, Any]) -> str:
    for key in ("candidateId", "id", "findingId"):
        value = str(candidate.get(key) or "").strip()
        if value:
            return value
    basis = "|".join(
        str(candidate.get(key) or "")
        for key in ("type", "title", "url", "value", "method", "parameter", "source")
    )
    slug = "".join(char.lower() if char.isalnum() else "-" for char in basis).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return (slug[:120] or "not recorded")


def _join(value: Any, limit: int = 8) -> str:
    if not isinstance(value, list):
        return str(value or "")
    items = [str(item) for item in value if str(item).strip()]
    suffix = f" (+{len(items) - limit} more)" if len(items) > limit else ""
    return ", ".join(items[:limit]) + suffix


def _request_parameters(request: dict[str, Any]) -> str:
    params = []
    if isinstance(request.get("queryParameters"), list):
        params.extend(str(item) for item in request["queryParameters"] if str(item).strip())
    for item in request.get("parameters", []) if isinstance(request.get("parameters"), list) else []:
        if isinstance(item, dict) and item.get("name"):
            params.append(str(item["name"]))
    return _join(_dedupe_strings(params))


def _evidence_ids(value: Any) -> list[str]:
    ids: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "evidenceIds" and isinstance(item, list):
                ids.extend(str(ev_id) for ev_id in item if str(ev_id).strip())
            else:
                ids.extend(_evidence_ids(item))
    elif isinstance(value, list):
        for item in value:
            ids.extend(_evidence_ids(item))
    return _dedupe_strings(ids)


def _dedupe_strings(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _perimeter_gaps(report: dict[str, Any]) -> list[str]:
    host = report.get("target", "target")
    gaps = []
    if not report.get("asset", {}).get("endpointCount"):
        gaps.append(f"No endpoint records are available for {host}.")
    if report.get("loginPortals") and not report.get("protectedResources"):
        gaps.append(f"Login portals were identified for {host}, but protected resource coverage is limited.")
    if report.get("findingCandidates"):
        gaps.append(f"{len(report.get('findingCandidates', []))} perimeter candidate review item(s) require operator review for {host}.")
    return gaps


def _perimeter_steps(report: dict[str, Any]) -> list[str]:
    host = report.get("target", "target")
    steps = []
    counts = _candidate_category_counts(report.get("findingCandidates", []))
    header_count = counts.get("Security header hygiene candidate", 0)
    cookie_count = counts.get("Cookie hygiene candidate", 0)
    if header_count or cookie_count:
        issue_bits = []
        if header_count:
            issue_bits.append(f"{header_count} security-header class(es)")
        if cookie_count:
            issue_bits.append(f"{cookie_count} cookie-flag issue(s)")
        steps.append(f"Validate {' and '.join(issue_bits)} on representative responses for {host} and record the intended baseline policy.")
    if counts.get("Open redirect candidate", 0):
        steps.append(f"Triage {counts['Open redirect candidate']} open-redirect candidate(s) on {host} with a harmless destination after approval.")
    if counts.get("Access-control candidate", 0):
        steps.append(f"Use the access-control layer to review {counts['Access-control candidate']} role/function candidate(s) for {host}.")
    if report.get("loginPortals") and not steps:
        steps.append(f"Review login portals on {host} for product/version, MFA, default-login exposure, and auth boundary behavior.")
    return steps


def _js_gaps(target: str, app_map: dict[str, Any]) -> list[str]:
    summary = app_map.get("summary", {})
    gaps = []
    if int(summary.get("assetCount", 0) or 0) == 0:
        gaps.append(f"No fetched JavaScript assets are recorded for {target}.")
    if int(summary.get("jsInferredEndpointCount", 0) or 0) == 0:
        gaps.append(f"No JavaScript-inferred endpoints are recorded for {target}.")
    if int(summary.get("jsSignalCount", 0) or 0) == 0:
        gaps.append(f"No JavaScript client-side auth/storage/API signals are recorded for {target}.")
    return gaps


def _js_steps(target: str, app_map: dict[str, Any], gaps: list[str]) -> list[str]:
    steps = []
    if gaps:
        steps.append(f"Run or refresh JavaScript discovery, approved asset fetch, static analysis, and endpoint normalization for {target} when in scope.")
    if app_map.get("summary", {}).get("jsInferredEndpointCount"):
        steps.append(f"Validate high-value JS-inferred endpoints for {target} against observed traffic before treating them as confirmed surface.")
    return steps


def _auth_gaps(target: str, portals: list[dict[str, Any]], protected: list[dict[str, Any]], entities: dict[str, list[dict[str, Any]]]) -> list[str]:
    gaps = []
    auth_like = [item for item in entities["endpoints"] if isinstance(item, dict) and (item.get("authBoundary") or item.get("hasAuthorization"))]
    if not portals and auth_like:
        gaps.append(f"Authentication-like endpoints exist for {target}, but no canonical login portal was identified.")
    if portals and not protected:
        gaps.append(f"Login portals exist for {target}, but protected-resource coverage is limited.")
    if portals and not any(item.get("tool") in {"credentials.authenticate", "credentials.browser_authenticate", "credentials.validate_session"} for item in entities["actions"]):
        gaps.append(f"No recorded authenticated session validation action exists for {target}.")
    return gaps


def _auth_steps(target: str, portals: list[dict[str, Any]], protected: list[dict[str, Any]], entities: dict[str, list[dict[str, Any]]]) -> list[str]:
    steps = []
    if portals:
        steps.append(f"Confirm the authentication flow for {target}, including MFA/SSO/CAPTCHA/manual approval requirements before storing or refreshing credentials.")
    if protected:
        steps.append(f"Validate protected resources for {target} with approved credential IDs and record expected session behavior.")
    if not entities["actions"]:
        steps.append(f"Record authentication setup or validation decisions for {target} before authenticated testing.")
    return steps


def _access_control_gaps(target: str, objects: list[dict[str, Any]], contexts: list[dict[str, Any]], matrix: list[dict[str, Any]], replays: list[dict[str, Any]]) -> list[str]:
    gaps = []
    if not objects:
        gaps.append(f"No access-control object/function candidates are recorded for {target}.")
    if len(contexts) < 2:
        gaps.append(f"Fewer than two authorized user/role contexts are recorded for {target}.")
    if objects and not matrix:
        gaps.append(f"Object candidates exist for {target}, but no access-control test matrix is recorded.")
    if matrix and not replays:
        gaps.append(f"Access-control matrix entries exist for {target}, but no approved replay results are recorded.")
    return gaps


def _access_control_steps(target: str, objects: list[dict[str, Any]], contexts: list[dict[str, Any]], matrix: list[dict[str, Any]], replays: list[dict[str, Any]]) -> list[str]:
    steps = []
    possible = len([item for item in replays if str(item.get("assessment", "")).lower() == "possible_broken_access_control"])
    inconclusive = len([item for item in replays if str(item.get("assessment", "")).lower() == "inconclusive"])
    if possible:
        steps.append(f"Review {possible} possible broken access-control replay candidate(s) for {target} and promote only operator-accepted issues to findings.")
    if inconclusive:
        steps.append(f"Resolve or document {inconclusive} inconclusive access-control replay result(s) for {target}.")
    if not objects:
        steps.append(f"Run passive access-control object identification for {target}.")
    if len(contexts) < 2:
        steps.append(f"Record at least two authorized user/role contexts for {target} before building replay plans.")
    if objects and not matrix:
        steps.append(f"Build an access-control test matrix for {target}.")
    if matrix and not replays:
        steps.append(f"Seek explicit approval before executing selected access-control replay tests for {target}.")
    return steps


def _candidate_category_counts(candidates: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in candidates if isinstance(candidates, list) else []:
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or item.get("title") or "").strip()
        if not category:
            continue
        counts[category] = counts.get(category, 0) + int(item.get("occurrenceCount", 1) or 1)
    return counts


def _credential_rows(targets: list[str] | None = None) -> list[list[Any]]:
    try:
        payload = credentials.list_credentials()
    except Exception:
        return []
    items = payload.get("credentials", []) if isinstance(payload, dict) else []
    target_set = {workspace.normalize_target(target) for target in targets or [] if workspace.normalize_target(target)}
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if target_set and not _credential_matches_targets(item, target_set):
            continue
        rows.append(
            [
                item.get("id", ""),
                item.get("type", ""),
                _join(item.get("scopes", [])),
                item.get("username", "") or item.get("profileId", ""),
                item.get("authState", ""),
            ]
        )
    return rows


def _credential_matches_targets(item: dict[str, Any], targets: set[str]) -> bool:
    scopes = item.get("scopes", [])
    if not isinstance(scopes, list):
        return False
    for raw_scope in scopes:
        scope_value = str(raw_scope or "").strip().lower()
        if not scope_value:
            continue
        if scope_value in targets:
            return True
        if scope_value.startswith("*."):
            suffix = scope_value[1:]
            if any(target.endswith(suffix) for target in targets):
                return True
    return False
