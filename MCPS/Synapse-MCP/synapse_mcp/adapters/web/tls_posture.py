# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import Any

from ...core import evidence, workspace
from ...core.adapters import AdapterResult, WorkspaceEntityBundle, passive_finding
from .active_probe import stable_slug

DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("tls_posture"), indent=2)


def analyze_workspace(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    max_candidates = int(args.get("maxCandidates", 100))
    context = workspace.prepare_target_context(workspace_id, target, purpose="tls_posture_analysis", max_tokens=4000)
    entities = workspace._load_target_entities(workspace.normalize_workspace_id(workspace_id), workspace.normalize_target(target))
    candidates = find_candidates(entities)[:max_candidates]
    result = build_result(workspace_id, target, candidates, context)
    payload = {
        **result.as_ingest_payload(),
        "candidateCount": len(candidates),
        "candidates": candidates,
        "contextSummary": {
            "serviceCount": len(entities.get("services", [])),
            "endpointCount": context.get("knownEndpoints", {}).get("total", 0),
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
            json.dumps(payload, indent=2, ensure_ascii=False),
            {"adapter": "tls_posture", "maxCandidates": max_candidates},
        )
        # Passive marker so coverage recognizes the module ran even though it now emits findings.
        workspace.record_action(
            workspace_id,
            target,
            {
                "type": "passive_analysis",
                "tool": "tls_posture.analyze_workspace",
                "summary": f"Analyzed passive TLS posture ({len(candidates)} finding(s)).",
            },
            ingestion.get("evidenceId", ""),
        )
    evidence.log_event(
        "tls_posture.analyze_workspace",
        f"Analyzed passive TLS posture for {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "candidateCount": len(candidates),
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def find_candidates(entities: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for service in entities.get("services", []):
        if not isinstance(service, dict):
            continue
        ssl = service.get("ssl")
        if not isinstance(ssl, dict) or not ssl:
            continue
        for candidate in _service_candidates(service, ssl):
            candidates.setdefault(candidate["candidateId"], candidate)
    for observation in entities.get("observations", []):
        if not isinstance(observation, dict):
            continue
        ssl = observation.get("ssl")
        if not isinstance(ssl, dict) or not ssl:
            continue
        service = {
            "host": observation.get("host") or observation.get("target") or observation.get("value", ""),
            "port": observation.get("port", ""),
            "source": observation.get("source", "observation"),
        }
        for candidate in _service_candidates(service, ssl):
            candidates.setdefault(candidate["candidateId"], candidate)
    return sorted(candidates.values(), key=lambda item: item["priorityScore"], reverse=True)


def _service_candidates(service: dict[str, Any], ssl: dict[str, Any]) -> list[dict[str, Any]]:
    host = str(service.get("host", "") or service.get("address", ""))
    port = service.get("port", "")
    source = str(service.get("source", "shodan"))
    location = f"{host}:{port}" if port not in ("", None) else host
    results: list[dict[str, Any]] = []
    if ssl.get("expired") is True:
        results.append(
            _candidate(
                "tls_expired_certificate",
                host,
                port,
                "high",
                85,
                f"TLS certificate for {location} is marked expired in existing {source} data.",
                {"expired": True},
            )
        )
    for protocol in _protocols(ssl):
        if protocol in DEPRECATED_PROTOCOLS:
            results.append(
                _candidate(
                    "tls_deprecated_protocol",
                    host,
                    port,
                    "medium",
                    65,
                    f"{location} advertises deprecated TLS/SSL protocol {protocol} in existing {source} data.",
                    {"protocol": protocol},
                )
            )
    cert_issue = _cert_identity_issue(host, ssl)
    if cert_issue:
        priority, score = ("medium", 55) if cert_issue["kind"] == "mismatch" else ("low", 35)
        results.append(
            _candidate(
                "tls_self_signed_or_mismatch",
                host,
                port,
                priority,
                score,
                f"TLS certificate identity issue for {location}: {cert_issue['reason']}.",
                cert_issue,
            )
        )
    return results


def _candidate(
    candidate_type: str,
    host: str,
    port: Any,
    priority: str,
    score: int,
    reason: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "candidateId": f"{candidate_type}_{stable_slug(host)}_{stable_slug(port)}_{stable_slug(metadata.get('protocol', metadata.get('kind', 'cert')))}"[:170],
        "type": candidate_type,
        "host": host,
        "port": port,
        "value": f"{host}:{port}" if port not in ("", None) else host,
        "priority": priority,
        "priorityScore": score,
        "confidence": "medium",
        "reasons": [reason],
        **metadata,
    }


def _protocols(ssl: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    for key in ("protocols", "versions", "supportedProtocols", "tlsVersions"):
        if isinstance(ssl.get(key), list):
            values.extend(ssl[key])
    if isinstance(ssl.get("protocol"), str):
        values.append(ssl["protocol"])
    normalized = []
    for value in values:
        text = str(value).strip()
        key = text.lower().replace("_", "").replace("-", "").replace(" ", "")
        mapping = {
            "tls1": "TLSv1.0",
            "tls1.0": "TLSv1.0",
            "tlsv1": "TLSv1.0",
            "tlsv1.0": "TLSv1.0",
            "tls1.1": "TLSv1.1",
            "tlsv1.1": "TLSv1.1",
            "ssl2": "SSLv2",
            "sslv2": "SSLv2",
            "ssl3": "SSLv3",
            "sslv3": "SSLv3",
        }
        normalized.append(mapping.get(key, text))
    return normalized


def _cert_identity_issue(host: str, ssl: dict[str, Any]) -> dict[str, Any] | None:
    subject_cn = str(ssl.get("subjectCN") or ssl.get("subjectCn") or ssl.get("cn") or "")
    issuer_cn = str(ssl.get("issuerCN") or ssl.get("issuerCn") or "")
    if subject_cn and issuer_cn and subject_cn == issuer_cn:
        return {"kind": "self_signed", "subjectCN": subject_cn, "issuerCN": issuer_cn, "reason": "issuer CN matches subject CN"}
    if host and subject_cn and not _hostname_matches(host, subject_cn) and not _hostname_matches_any(host, ssl.get("subjectAltNames")):
        return {"kind": "mismatch", "subjectCN": subject_cn, "issuerCN": issuer_cn, "reason": f"certificate CN {subject_cn} does not cover host {host}"}
    return None


def _hostname_matches_any(host: str, names: Any) -> bool:
    if not isinstance(names, list):
        return False
    return any(_hostname_matches(host, str(name)) for name in names)


def _hostname_matches(host: str, pattern: str) -> bool:
    host = host.lower().strip(".")
    pattern = pattern.lower().strip(".")
    if not host or not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host.count(".") >= pattern.count(".")
    return host == pattern


def build_result(workspace_id: str, target: str, candidates: list[dict[str, Any]], context: dict[str, Any]) -> AdapterResult:
    host = workspace.normalize_target(target)
    findings = [_finding_from_candidate(host, candidate) for candidate in candidates]
    return AdapterResult(
        adapter="tls_posture",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=host,
        summary=f"Recorded {len(findings)} TLS posture findings from existing data.",
        entities=WorkspaceEntityBundle(findings=findings),
        limitations=[
            "Normalizes TLS data already collected by Shodan/perimeter ingestion; it performs no live TLS handshake.",
            "Deep cipher/protocol scanning belongs to sslscan, testssl, nuclei, or another approved external workflow.",
        ],
        metadata={"findingCount": len(findings), "contextEndpointCount": context.get("knownEndpoints", {}).get("total", 0)},
    )


def _tls_severity(candidate_type: str, score: int) -> str:
    # An expired certificate or a deprecated protocol is a concrete exposure, not mere
    # hygiene, so it is rated medium; identity issues fall back to a score-based low/info.
    if candidate_type in {"tls_expired_certificate", "tls_deprecated_protocol"}:
        return "medium"
    return "low" if score >= 45 else "info"


def _finding_from_candidate(host: str, candidate: dict[str, Any]) -> dict[str, Any]:
    # TLS posture issues are confirmed from already-collected certificate/protocol data,
    # so they are findings rather than candidates to actively re-test.
    candidate_type = str(candidate.get("type", ""))
    reason = candidate["reasons"][0] if candidate.get("reasons") else "TLS posture issue identified."
    if candidate_type == "tls_expired_certificate":
        title = "Expired TLS certificate"
    elif candidate_type == "tls_deprecated_protocol":
        title = f"Deprecated TLS/SSL protocol {candidate.get('protocol', '')}".strip()
    elif candidate.get("kind") == "mismatch":
        title = "TLS certificate hostname mismatch"
    elif candidate.get("kind") == "self_signed":
        title = "Self-signed TLS certificate"
    else:
        title = "TLS posture issue"
    discriminator = str(candidate.get("protocol") or candidate.get("kind") or candidate.get("port") or "")
    return passive_finding(
        key=f"finding:hygiene:{stable_slug(host)}:{stable_slug(candidate_type)}:{stable_slug(discriminator)}"[:170],
        title=title,
        severity=_tls_severity(candidate_type, int(candidate.get("priorityScore", 0) or 0)),
        reason=reason,
        host=host,
        affected_urls=[str(candidate.get("value", ""))] if candidate.get("value") else [],
        evidence_ids=candidate.get("evidenceIds", []),
        remediation="Renew/replace the certificate and disable deprecated protocols so the TLS endpoint presents a valid, modern configuration.",
        tags=["tls-posture", candidate_type.replace("_", "-")],
        category="TLS posture",
    )
