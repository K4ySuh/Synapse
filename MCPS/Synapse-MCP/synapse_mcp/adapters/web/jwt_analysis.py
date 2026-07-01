# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from typing import Any

from ...core import evidence, workspace
from ...core.adapters import AdapterResult, WorkspaceEntityBundle, candidate_observation
from ...core.errors import McpError

# Bounded built-in list of common development/example HMAC secrets. This is a
# guessability check, not a brute force; it never expands at runtime.
WEAK_SECRETS = (
    "secret", "secretkey", "secret_key", "secret123", "supersecret", "topsecret",
    "s3cr3t", "your-256-bit-secret", "your_jwt_secret", "jwt", "jwtsecret",
    "jwt_secret", "jwtkey", "key", "mykey", "sharedsecret", "password", "passw0rd",
    "p@ssw0rd", "changeme", "changeit", "admin", "root", "test", "default",
    "token", "12345678", "123456", "qwerty", "letmein", "helloworld", "hmac",
    "signature", "apisecret", "authsecret", "privatekey",
)
HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
PRIVILEGED_CLAIM_NAMES = {"role", "roles", "admin", "is_admin", "isadmin", "scope", "scopes",
                          "permissions", "authorities", "groups", "grp", "acl"}
PRIVILEGED_VALUES = {"admin", "administrator", "superuser", "root", "*", "all", "sysadmin", "owner"}
KID_INJECTION_RE = re.compile(r"[/\\]|\.\.|['\"]|--|\bunion\b|\bselect\b", re.IGNORECASE)


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("jwt"), indent=2)


def analyze(args: dict[str, Any]) -> str:
    token = args.get("token")
    if not isinstance(token, str) or token.count(".") < 2:
        raise McpError(-32602, "A JWT (header.payload.signature) string is required in 'token'.")
    parts = token.split(".")
    if len(parts) != 3:
        raise McpError(-32602, "Only compact JWS tokens with three segments are supported (JWE is not analyzed).")
    header = _decode_segment(parts[0], "header")
    payload = _decode_segment(parts[1], "payload")
    alg = str(header.get("alg", "")).strip()
    kid = header.get("kid")
    findings = _evaluate(alg, header, payload, token)

    summary_label = f"jwt(alg={alg or 'unknown'}{', kid set' if kid else ''})"
    result_payload = {
        "summary": summary_label,
        "header": {"alg": alg, "typ": header.get("typ", ""), "kid": str(kid) if kid is not None else ""},
        "claimNames": sorted(str(name) for name in payload.keys()),
        "findings": findings,
        "highSeverityCount": sum(1 for item in findings if item["severity"] == "high"),
    }

    ingestion = None
    workspace_id = args.get("workspaceId")
    target = args.get("target")
    if args.get("ingest") and workspace_id and target:
        ingestion = _ingest(workspace_id, target, summary_label, alg, kid, findings)
    evidence.log_event(
        "jwt.analyze",
        f"Analyzed a JWT (alg={alg or 'unknown'}); {result_payload['highSeverityCount']} high-severity flag(s).",
        {"alg": alg, "kidPresent": bool(kid), "findingCount": len(findings), "ingested": bool(ingestion)},
    )
    return json.dumps({**result_payload, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def _evaluate(alg: str, header: dict[str, Any], payload: dict[str, Any], token: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if alg.lower() in {"none", ""}:
        findings.append(_finding("jwt_alg_none", "high",
            "Token header declares alg=none; a server that honors it accepts unsigned, forgeable tokens."))
    elif alg.upper() in HMAC_ALGS:
        matched = _weak_secret_match(alg.upper(), token)
        if matched is not None:
            findings.append(_finding("jwt_weak_secret", "high",
                f"HMAC signature was reproduced with a common built-in weak secret (length {matched}); rotate the signing key.",
                extra={"secretLength": matched}))
    if header.get("kid") is not None and KID_INJECTION_RE.search(str(header.get("kid", ""))):
        findings.append(_finding("jwt_kid_injection_surface", "medium",
            "The 'kid' header contains path/SQL metacharacters; if used to resolve the key it may be injectable.",
            extra={"kid": str(header.get("kid", ""))[:120]}))
    if "exp" not in payload:
        findings.append(_finding("jwt_missing_expiry", "medium",
            "Token has no 'exp' claim, so it never expires and remains valid if leaked."))
    for name, value in payload.items():
        lowered = str(name).lower()
        if lowered in PRIVILEGED_CLAIM_NAMES and _looks_privileged(value):
            findings.append(_finding("jwt_dangerous_claim", "low",
                f"Token carries a privileged claim '{name}'; tampering tests should confirm it is server-validated.",
                extra={"claim": str(name)}))
    return findings


def _weak_secret_match(alg: str, token: str) -> int | None:
    signing_input, _, signature = token.rpartition(".")
    try:
        expected = _b64url_to_bytes(signature)
    except (binascii.Error, ValueError):
        return None
    digestmod = HMAC_ALGS[alg]
    for secret in WEAK_SECRETS:
        candidate = hmac.new(secret.encode("utf-8"), signing_input.encode("utf-8"), digestmod).digest()
        if hmac.compare_digest(candidate, expected):
            return len(secret)
    return None


def _looks_privileged(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in PRIVILEGED_VALUES
    if isinstance(value, list):
        return any(_looks_privileged(item) for item in value)
    return False


def _ingest(workspace_id: str, target: str, summary_label: str, alg: str, kid: Any, findings: list[dict[str, Any]]) -> dict[str, Any]:
    observations = [
        candidate_observation(
            candidate_type=item["type"],
            value=summary_label,
            reason=item["detail"],
            confidence="medium" if item["severity"] == "high" else "low",
            priority=item["severity"] if item["severity"] in {"high", "medium", "low"} else "low",
            priority_score={"high": 80, "medium": 55, "low": 30}.get(item["severity"], 20),
            tags=["jwt", item["type"].replace("_", "-")],
            metadata={"alg": alg, "kidPresent": bool(kid)},
        )
        for item in findings
    ]
    result = AdapterResult(
        adapter="jwt",
        mode="passive_analysis",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"JWT analysis: {len(findings)} observation(s).",
        entities=WorkspaceEntityBundle(observations=observations),
        limitations=["Offline structural analysis only; the raw token and any matched secret are never stored."],
    )
    return workspace.ingest_data(
        workspace_id, target, "adapter_result", "passive_analysis", "json",
        json.dumps(result.as_ingest_payload(), indent=2, ensure_ascii=False),
        {"adapter": "jwt"},
    )


def _finding(finding_type: str, severity: str, detail: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"type": finding_type, "severity": severity, "detail": detail, **(extra or {})}


def _decode_segment(segment: str, name: str) -> dict[str, Any]:
    try:
        decoded = _b64url_to_bytes(segment)
        parsed = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise McpError(-32602, f"JWT {name} segment is not valid base64url-encoded JSON.") from exc
    if not isinstance(parsed, dict):
        raise McpError(-32602, f"JWT {name} segment did not decode to a JSON object.")
    return parsed


def _b64url_to_bytes(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))
