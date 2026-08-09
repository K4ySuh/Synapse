# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Canonical, protocol-independent execution and authorization intent types.

The objects in this module are deliberately immutable and JSON-serializable.
They describe what an action may contact and write; they are not grants and do
not accept caller assertions as authority.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import ipaddress
import json
import posixpath
import re
from pathlib import Path
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit

from . import atomic_io, scope, workspace


PLAN_VERSION = 1
LEGACY_APPROVAL_FIELDS = frozenset({"confirm", "approvalId", "approvalReason", "riskTier"})
_UNRESERVED_PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")


class ExecutionPlanError(ValueError):
    """Typed failure raised before an unplanned effect can occur."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


def _decode_unreserved(match: re.Match[str]) -> str:
    value = chr(int(match.group(1), 16))
    return value if value.isalnum() or value in "-._~" else match.group(0).upper()


def _canonical_path(value: str) -> str:
    decoded = _UNRESERVED_PERCENT.sub(_decode_unreserved, value or "/")
    trailing = decoded.endswith("/")
    normalized = posixpath.normpath(decoded)
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    if trailing and normalized != "/":
        normalized += "/"
    return normalized


def _canonical_host(value: str) -> str:
    host = value.rstrip(".").lower()
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ExecutionPlanError("invalid_target", f"Target host is not canonicalizable: {value}") from exc


@dataclass(frozen=True, slots=True, order=True)
class CanonicalTarget:
    scheme: str
    host: str
    port: int
    path: str = "/"

    @classmethod
    def from_url(cls, value: str) -> "CanonicalTarget":
        raw = str(value or "").strip()
        parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ExecutionPlanError("invalid_target", "Execution targets must use http or https.")
        if parsed.username is not None or parsed.password is not None:
            raise ExecutionPlanError("target_userinfo_forbidden", "Execution target URLs cannot contain userinfo.")
        if not parsed.hostname:
            raise ExecutionPlanError("invalid_target", f"Execution target has no host: {value}")
        try:
            port = parsed.port or (443 if scheme == "https" else 80)
        except ValueError as exc:
            raise ExecutionPlanError("invalid_target", f"Execution target has an invalid port: {value}") from exc
        return cls(scheme=scheme, host=_canonical_host(parsed.hostname), port=port, path=_canonical_path(parsed.path))

    @property
    def origin(self) -> tuple[str, str, int]:
        return (self.scheme, self.host, self.port)

    def to_dict(self) -> dict[str, Any]:
        return {"scheme": self.scheme, "host": self.host, "port": self.port, "path": self.path}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CanonicalTarget":
        return cls(str(value["scheme"]), str(value["host"]), int(value["port"]), str(value.get("path") or "/"))


@dataclass(frozen=True, slots=True, order=True)
class TargetSelector:
    target: CanonicalTarget
    path_mode: Literal["exact", "prefix", "any"] = "exact"
    provenance: str = "requested_target"

    def matches(self, candidate: CanonicalTarget) -> bool:
        if self.target.origin != candidate.origin:
            return False
        if self.path_mode == "any":
            return True
        if self.path_mode == "exact":
            return self.target.path == candidate.path
        prefix = self.target.path.rstrip("/") or "/"
        if prefix == "/":
            return candidate.path.startswith("/")
        return candidate.path == prefix or candidate.path.startswith(f"{prefix}/")

    def to_dict(self) -> dict[str, Any]:
        return {"target": self.target.to_dict(), "pathMode": self.path_mode, "provenance": self.provenance}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TargetSelector":
        mode = str(value.get("pathMode") or "exact")
        if mode not in {"exact", "prefix", "any"}:
            raise ExecutionPlanError("invalid_execution_plan", f"Unknown target path mode: {mode}")
        return cls(CanonicalTarget.from_dict(value["target"]), mode, str(value.get("provenance") or "requested_target"))  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class ScopeSnapshot:
    hosts: tuple[str, ...] = ()
    patterns: tuple[str, ...] = ()
    cidrs: tuple[str, ...] = ()
    organization: str = ""
    notes: str = ""
    source: Literal["workspace", "global", "explicit"] = "explicit"

    @classmethod
    def from_value(
        cls,
        value: Mapping[str, Any],
        *,
        source: Literal["workspace", "global", "explicit"] = "explicit",
    ) -> "ScopeSnapshot":
        hosts = tuple(sorted({_canonical_host(scope.normalize_host(str(item))) for item in value.get("hosts", []) if str(item).strip()}))
        patterns = tuple(sorted({str(item).strip().lower() for item in value.get("patterns", []) if str(item).strip()}))
        normalized_cidrs: set[str] = set()
        for item in value.get("cidrs", []):
            try:
                normalized_cidrs.add(str(ipaddress.ip_network(str(item).strip(), strict=False)))
            except ValueError:
                continue
        return cls(
            hosts,
            patterns,
            tuple(sorted(normalized_cidrs)),
            str(value.get("organization") or ""),
            str(value.get("notes") or ""),
            source,
        )

    @classmethod
    def for_workspace(cls, workspace_id: str) -> "ScopeSnapshot":
        workspace_value = workspace.workspace_scope(workspace_id) if workspace_id else {}
        uses_workspace = any(workspace_value.get(name) for name in ("hosts", "patterns", "cidrs"))
        selected = workspace_value if uses_workspace else scope.load_scope()
        return cls.from_value(selected, source="workspace" if uses_workspace else "global")

    @property
    def digest(self) -> str:
        encoded = json.dumps(self.authorization_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def contains(self, target: CanonicalTarget) -> bool:
        return bool(scope.check_target_in_scope(target.host, self.to_dict()).get("inScope"))

    def to_dict(self) -> dict[str, Any]:
        value = self.authorization_dict()
        if self.organization:
            value["organization"] = self.organization
        if self.notes:
            value["notes"] = self.notes
        value["source"] = self.source
        return value

    def authorization_dict(self) -> dict[str, Any]:
        return {"hosts": list(self.hosts), "patterns": list(self.patterns), "cidrs": list(self.cidrs)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScopeSnapshot":
        source = str(value.get("source") or "explicit")
        if source not in {"workspace", "global", "explicit"}:
            raise ExecutionPlanError("invalid_execution_plan", f"Unknown scope snapshot source: {source}")
        return cls.from_value(value, source=source)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class RedirectPolicy:
    follow: bool = False
    max_hops: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"follow": self.follow, "maxHops": self.max_hops}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RedirectPolicy":
        return cls(bool(value.get("follow")), max(int(value.get("maxHops") or 0), 0))


@dataclass(frozen=True, slots=True)
class TargetEnvelope:
    workspace_id: str
    scope_digest: str
    scope_snapshot: ScopeSnapshot
    exact_targets: tuple[TargetSelector, ...]
    seeds: tuple[CanonicalTarget, ...]
    entire_workspace_scope: bool = False
    redirect_policy: RedirectPolicy = RedirectPolicy()
    expansion_reasons: tuple[str, ...] = ()

    def allows(self, value: str) -> bool:
        candidate = CanonicalTarget.from_url(value)
        if any(selector.matches(candidate) for selector in self.exact_targets):
            return True
        return self.entire_workspace_scope and self.scope_snapshot.contains(candidate)

    def require(self, value: str, *, redirect_hop: int | None = None) -> CanonicalTarget:
        if redirect_hop is not None:
            if not self.redirect_policy.follow:
                raise ExecutionPlanError("redirect_not_authorized", "The execution plan does not allow redirects.")
            if redirect_hop > self.redirect_policy.max_hops:
                raise ExecutionPlanError("redirect_limit_exceeded", "The execution plan redirect hop limit was exceeded.")
        candidate = CanonicalTarget.from_url(value)
        if not self.allows(value):
            kind = "redirect" if redirect_hop is not None else "target"
            raise ExecutionPlanError(
                f"{kind}_outside_target_envelope",
                f"The {kind} destination {candidate.scheme}://{candidate.host}:{candidate.port}{candidate.path} is outside the execution target envelope.",
            )
        return candidate

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspaceId": self.workspace_id,
            "scopeDigest": self.scope_digest,
            "scopeSnapshot": self.scope_snapshot.to_dict(),
            "exactTargets": [item.to_dict() for item in self.exact_targets],
            "seeds": [item.to_dict() for item in self.seeds],
            "entireWorkspaceScope": self.entire_workspace_scope,
            "redirectPolicy": self.redirect_policy.to_dict(),
            "expansionReasons": list(self.expansion_reasons),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TargetEnvelope":
        snapshot = ScopeSnapshot.from_dict(value.get("scopeSnapshot", {}))
        digest = str(value.get("scopeDigest") or snapshot.digest)
        if digest != snapshot.digest:
            raise ExecutionPlanError("scope_digest_mismatch", "Execution plan scope snapshot does not match its digest.")
        return cls(
            workspace_id=str(value.get("workspaceId") or ""),
            scope_digest=digest,
            scope_snapshot=snapshot,
            exact_targets=tuple(TargetSelector.from_dict(item) for item in value.get("exactTargets", [])),
            seeds=tuple(CanonicalTarget.from_dict(item) for item in value.get("seeds", [])),
            entire_workspace_scope=bool(value.get("entireWorkspaceScope")),
            redirect_policy=RedirectPolicy.from_dict(value.get("redirectPolicy", {})),
            expansion_reasons=tuple(str(item) for item in value.get("expansionReasons", [])),
        )


@dataclass(frozen=True, slots=True)
class ProviderRoute:
    backend: Literal["direct", "proxy", "disabled"]
    proxy_endpoint: CanonicalTarget | None = None
    source: str = "request"
    credential_ref: str | None = None
    embedded_credentials: bool = False
    trust_environment: bool = False

    @classmethod
    def from_values(cls, backend: str, proxy_url: str | None, credential_ref: str | None = None) -> "ProviderRoute":
        normalized = str(backend or "direct").lower()
        if normalized not in {"direct", "proxy", "disabled"}:
            raise ExecutionPlanError("invalid_http_backend", f"Unsupported HTTP backend: {backend}")
        if normalized != "proxy":
            return cls(normalized, source="request", trust_environment=False)  # type: ignore[arg-type]
        if not proxy_url:
            raise ExecutionPlanError("proxy_endpoint_required", "The proxy backend requires an explicit proxy endpoint.")
        parsed = urlsplit(str(proxy_url))
        embedded = parsed.username is not None or parsed.password is not None
        if embedded:
            raise ExecutionPlanError(
                "embedded_proxy_credentials_forbidden",
                "Proxy credentials must be supplied by proxyCredentialId, not embedded in proxyUrl.",
            )
        if parsed.query or parsed.fragment:
            raise ExecutionPlanError(
                "invalid_proxy_endpoint",
                "Proxy endpoints cannot contain query or fragment data; use proxyCredentialId for authentication.",
            )
        if parsed.path not in {"", "/"}:
            raise ExecutionPlanError(
                "invalid_proxy_endpoint",
                "Proxy endpoints must identify an origin, without an application path.",
            )
        clean_host = parsed.hostname or ""
        try:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except ValueError as exc:
            raise ExecutionPlanError("invalid_proxy_endpoint", "The proxy endpoint has an invalid port.") from exc
        if parsed.scheme.lower() not in {"http", "https"} or not clean_host:
            raise ExecutionPlanError("invalid_proxy_endpoint", "Proxy endpoints must be explicit http(s) URLs.")
        endpoint = CanonicalTarget(parsed.scheme.lower(), _canonical_host(clean_host), port, "/")
        return cls("proxy", endpoint, "request", credential_ref, embedded, False)

    def matches(self, backend: str, proxy_url: str | None, credential_ref: str | None = None) -> bool:
        try:
            candidate = ProviderRoute.from_values(backend, proxy_url, credential_ref)
        except ExecutionPlanError:
            return False
        return candidate == self

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "proxyEndpoint": self.proxy_endpoint.to_dict() if self.proxy_endpoint else None,
            "source": self.source,
            "credentialRef": self.credential_ref,
            "embeddedCredentials": self.embedded_credentials,
            "trustEnvironment": self.trust_environment,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProviderRoute":
        endpoint = value.get("proxyEndpoint")
        backend = str(value.get("backend") or "direct")
        if backend not in {"direct", "proxy", "disabled"}:
            raise ExecutionPlanError("invalid_execution_plan", f"Unknown provider backend: {backend}")
        return cls(
            backend,  # type: ignore[arg-type]
            CanonicalTarget.from_dict(endpoint) if isinstance(endpoint, Mapping) else None,
            str(value.get("source") or "request"),
            str(value["credentialRef"]) if value.get("credentialRef") else None,
            bool(value.get("embeddedCredentials")),
            bool(value.get("trustEnvironment")),
        )


@dataclass(frozen=True, slots=True, order=True)
class LocalOutputDestination:
    path: str
    purpose: str
    within_workspace: bool
    disposition: Literal["create", "overwrite"]
    may_prune: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "purpose": self.purpose,
            "withinWorkspace": self.within_workspace,
            "disposition": self.disposition,
            "mayPrune": self.may_prune,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LocalOutputDestination":
        disposition = str(value.get("disposition") or "create")
        if disposition not in {"create", "overwrite"}:
            raise ExecutionPlanError("invalid_execution_plan", f"Unknown output disposition: {disposition}")
        return cls(
            str(value["path"]),
            str(value["purpose"]),
            bool(value.get("withinWorkspace")),
            disposition,  # type: ignore[arg-type]
            bool(value.get("mayPrune")),
        )


@dataclass(frozen=True, slots=True)
class EffectEnvelope:
    traffic: tuple[str, ...] = ()
    local_writes: tuple[str, ...] = ()
    local_change: bool = False
    local_destruction: bool = False
    remote_state_change: bool = False
    credential_use: bool = False
    secret_use: bool = False
    replay_safety: str = "pure_read"

    @classmethod
    def from_effects(cls, effects: Any) -> "EffectEnvelope":
        return cls(
            tuple(sorted(str(item) for item in effects.traffic)),
            tuple(sorted(str(item) for item in effects.local_writes)),
            bool(effects.local_change),
            bool(effects.local_destruction),
            bool(effects.remote_state_change),
            bool(effects.credential_use),
            bool(effects.secret_use),
            str(effects.replay_safety),
        )

    def permits(self, required: "EffectEnvelope") -> bool:
        if not set(required.traffic).issubset(self.traffic) or not set(required.local_writes).issubset(self.local_writes):
            return False
        for maximum, actual in (
            (self.local_change, required.local_change),
            (self.local_destruction, required.local_destruction),
            (self.remote_state_change, required.remote_state_change),
            (self.credential_use, required.credential_use),
            (self.secret_use, required.secret_use),
        ):
            if actual and not maximum:
                return False
        if self.replay_safety == "pure_read" and required.replay_safety != "pure_read":
            return False
        if self.replay_safety in {"idempotent_write", "idempotent_control"} and required.replay_safety not in {
            "pure_read",
            "idempotent_write",
            "idempotent_control",
        }:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "traffic": list(self.traffic),
            "localWrites": list(self.local_writes),
            "localChange": self.local_change,
            "localDestruction": self.local_destruction,
            "remoteStateChange": self.remote_state_change,
            "credentialUse": self.credential_use,
            "secretUse": self.secret_use,
            "replaySafety": self.replay_safety,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EffectEnvelope":
        return cls(
            tuple(sorted(str(item) for item in value.get("traffic", []))),
            tuple(sorted(str(item) for item in value.get("localWrites", []))),
            bool(value.get("localChange")),
            bool(value.get("localDestruction")),
            bool(value.get("remoteStateChange")),
            bool(value.get("credentialUse")),
            bool(value.get("secretUse")),
            str(value.get("replaySafety") or "pure_read"),
        )


@dataclass(frozen=True, slots=True)
class ContinuationLineage:
    kind: str = "dispatch"
    origin_action_id: str = ""
    origin_correlation_id: str = ""
    parent_plan_fingerprint: str = ""
    job_id: str = ""
    handler: str = ""
    binding_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "originActionId": self.origin_action_id,
            "originCorrelationId": self.origin_correlation_id,
            "parentPlanFingerprint": self.parent_plan_fingerprint,
            "jobId": self.job_id,
            "handler": self.handler,
            "bindingFingerprint": self.binding_fingerprint,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ContinuationLineage":
        return cls(
            str(value.get("kind") or "dispatch"),
            str(value.get("originActionId") or ""),
            str(value.get("originCorrelationId") or ""),
            str(value.get("parentPlanFingerprint") or ""),
            str(value.get("jobId") or ""),
            str(value.get("handler") or ""),
            str(value.get("bindingFingerprint") or ""),
        )


@dataclass(frozen=True, slots=True)
class AuthorizationIntent:
    action_id: str
    workspace_id: str
    target_envelope: TargetEnvelope
    methods: tuple[str, ...] = ()
    credential_refs: tuple[str, ...] = ()
    providers: tuple[ProviderRoute, ...] = ()
    local_outputs: tuple[LocalOutputDestination, ...] = ()
    lineage: ContinuationLineage = ContinuationLineage()

    def to_dict(self) -> dict[str, Any]:
        return {
            "actionId": self.action_id,
            "workspaceId": self.workspace_id,
            "targetEnvelope": self.target_envelope.to_dict(),
            "methods": list(self.methods),
            "credentialRefs": list(self.credential_refs),
            "providers": [item.to_dict() for item in self.providers],
            "localOutputs": [item.to_dict() for item in self.local_outputs],
            "lineage": self.lineage.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorizationIntent":
        return cls(
            str(value["actionId"]),
            str(value.get("workspaceId") or ""),
            TargetEnvelope.from_dict(value.get("targetEnvelope", {})),
            tuple(str(item).upper() for item in value.get("methods", [])),
            tuple(str(item) for item in value.get("credentialRefs", [])),
            tuple(ProviderRoute.from_dict(item) for item in value.get("providers", [])),
            tuple(LocalOutputDestination.from_dict(item) for item in value.get("localOutputs", [])),
            ContinuationLineage.from_dict(value.get("lineage", {})),
        )


def request_fingerprint(arguments: Mapping[str, Any]) -> str:
    material = {key: value for key, value in arguments.items() if key not in LEGACY_APPROVAL_FIELDS and not key.startswith("_")}
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    action_id: str
    correlation_id: str
    intent: AuthorizationIntent
    effects: EffectEnvelope
    request_fingerprint: str
    runtime_input_fingerprint: str
    plan_fingerprint: str = ""
    version: int = PLAN_VERSION

    @classmethod
    def create(
        cls,
        *,
        action_id: str,
        correlation_id: str,
        intent: AuthorizationIntent,
        effects: Any,
        arguments: Mapping[str, Any],
    ) -> "ExecutionPlan":
        fingerprint = request_fingerprint(arguments)
        plan = cls(action_id, correlation_id, intent, EffectEnvelope.from_effects(effects), fingerprint, fingerprint)
        return plan._sealed()

    def _sealed(self) -> "ExecutionPlan":
        unsigned = self.to_dict(include_fingerprint=False)
        digest = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        return replace(self, plan_fingerprint=digest)

    def verify(self) -> None:
        if self._sealed().plan_fingerprint != self.plan_fingerprint:
            raise ExecutionPlanError("execution_plan_tampered", "Execution plan fingerprint validation failed.")
        if self.action_id != self.intent.action_id:
            raise ExecutionPlanError("execution_plan_action_mismatch", "Execution plan and intent action IDs differ.")

    def for_continuation(self, *, kind: str, runtime_arguments: Mapping[str, Any], job_id: str = "") -> "ExecutionPlan":
        lineage = ContinuationLineage(
            kind=kind,
            origin_action_id=self.intent.lineage.origin_action_id or self.action_id,
            origin_correlation_id=self.intent.lineage.origin_correlation_id or self.correlation_id,
            parent_plan_fingerprint=self.plan_fingerprint,
            job_id=job_id,
        )
        return replace(
            self,
            intent=replace(self.intent, lineage=lineage),
            runtime_input_fingerprint=request_fingerprint(runtime_arguments),
            plan_fingerprint="",
        )._sealed()

    def bind_continuation(
        self,
        *,
        job_id: str,
        handler: str,
        material: Mapping[str, Any],
    ) -> "ExecutionPlan":
        """Seal trusted job/finalizer metadata into this continuation plan."""

        self.verify()
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
        binding = hashlib.sha256(encoded).hexdigest()
        current = self.intent.lineage
        lineage = replace(
            current,
            kind=current.kind if current.kind != "dispatch" else "background_job",
            origin_action_id=current.origin_action_id or self.action_id,
            origin_correlation_id=current.origin_correlation_id or self.correlation_id,
            job_id=job_id,
            handler=handler,
            binding_fingerprint=binding,
        )
        return replace(self, intent=replace(self.intent, lineage=lineage), plan_fingerprint="")._sealed()

    def assert_continuation_binding(
        self,
        *,
        job_id: str,
        handler: str,
        material: Mapping[str, Any],
    ) -> None:
        self.verify()
        lineage = self.intent.lineage
        if lineage.job_id != job_id or lineage.handler != handler:
            raise ExecutionPlanError(
                "continuation_identity_diverged",
                "Job/finalizer identity differs from the creation-time execution plan.",
            )
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
        if hashlib.sha256(encoded).hexdigest() != lineage.binding_fingerprint:
            raise ExecutionPlanError(
                "continuation_binding_diverged",
                "Persisted job/finalizer metadata differs from the creation-time execution plan.",
            )

    def assert_runtime_input(self, arguments: Mapping[str, Any]) -> None:
        self.verify()
        if request_fingerprint(arguments) != self.runtime_input_fingerprint:
            raise ExecutionPlanError("runtime_input_diverged", "Runtime action input differs from the input covered by policy.")

    def assert_http_policy(self, backend: str, proxy_url: str | None, credential_ref: str | None = None) -> None:
        self.verify()
        if len(self.intent.providers) != 1 or not self.intent.providers[0].matches(backend, proxy_url, credential_ref):
            raise ExecutionPlanError("http_provider_diverged", "Runtime HTTP backend/proxy differs from the policy-reviewed provider route.")

    def assert_http_request(self, url: str, method: str, *, redirect_hop: int | None = None) -> CanonicalTarget:
        self.verify()
        normalized_method = str(method or "GET").upper()
        if self.intent.methods and normalized_method not in self.intent.methods:
            raise ExecutionPlanError("method_outside_execution_plan", f"HTTP method {normalized_method} is outside the execution plan.")
        return self.intent.target_envelope.require(url, redirect_hop=redirect_hop)

    def output(self, purpose: str) -> LocalOutputDestination:
        self.verify()
        try:
            return next(item for item in self.intent.local_outputs if item.purpose == purpose)
        except StopIteration as exc:
            raise ExecutionPlanError("output_outside_execution_plan", f"No planned output exists for {purpose}.") from exc

    def output_for_path(self, value: str) -> LocalOutputDestination:
        """Return the exact planned destination represented by ``value``."""

        self.verify()
        resolved = str(Path(value).expanduser().resolve(strict=False))
        try:
            return next(item for item in self.intent.local_outputs if item.path == resolved)
        except StopIteration as exc:
            raise ExecutionPlanError(
                "output_outside_execution_plan",
                f"No planned local output exists for {resolved}.",
            ) from exc

    def to_dict(self, *, include_fingerprint: bool = True) -> dict[str, Any]:
        value = {
            "version": self.version,
            "actionId": self.action_id,
            "correlationId": self.correlation_id,
            "intent": self.intent.to_dict(),
            "effects": self.effects.to_dict(),
            "requestFingerprint": self.request_fingerprint,
            "runtimeInputFingerprint": self.runtime_input_fingerprint,
        }
        if include_fingerprint:
            value["planFingerprint"] = self.plan_fingerprint
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionPlan":
        plan = cls(
            str(value["actionId"]),
            str(value.get("correlationId") or ""),
            AuthorizationIntent.from_dict(value["intent"]),
            EffectEnvelope.from_dict(value["effects"]),
            str(value.get("requestFingerprint") or ""),
            str(value.get("runtimeInputFingerprint") or value.get("requestFingerprint") or ""),
            str(value.get("planFingerprint") or ""),
            int(value.get("version") or PLAN_VERSION),
        )
        if plan.version != PLAN_VERSION:
            raise ExecutionPlanError("unsupported_execution_plan", f"Unsupported execution plan version: {plan.version}")
        plan.verify()
        return plan


def empty_target_envelope(workspace_id: str) -> TargetEnvelope:
    snapshot = ScopeSnapshot.for_workspace(workspace_id)
    return TargetEnvelope(workspace_id, snapshot.digest, snapshot, (), ())


def resolve_local_outputs(
    *,
    requested_path: str | None,
    default_path: Path,
    workspace_root: Path,
    allow_external: bool,
    purposes: tuple[str, str, str] = ("crawler.sitemap", "crawler.flow_mermaid", "crawler.flow_svg"),
) -> tuple[LocalOutputDestination, ...]:
    candidate = Path(requested_path).expanduser() if requested_path else default_path
    primary = candidate.resolve(strict=False)
    root = workspace_root.resolve(strict=False)
    try:
        primary.relative_to(root)
        within = True
    except ValueError:
        within = False
    if not within and not allow_external:
        raise ExecutionPlanError(
            "external_output_approval_required",
            f"Exact external output requires allowExternalOutput=true: {primary}",
        )
    paths = (primary, primary.with_name(f"{primary.stem}.flow.mmd"), primary.with_name(f"{primary.stem}.flow.svg"))
    may_prune = requested_path is None
    return tuple(
        LocalOutputDestination(
            str(path),
            purpose,
            within,
            "overwrite" if path.exists() else "create",
            may_prune,
        )
        for path, purpose in zip(paths, purposes)
    )


def write_planned_text(plan: ExecutionPlan, purpose: str, content: str) -> Path:
    destination = plan.output(purpose)
    path = Path(destination.path)
    if path.resolve(strict=False) != path:
        raise ExecutionPlanError("output_path_changed", f"Planned output path changed through a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.resolve(strict=False) != path:
        raise ExecutionPlanError("output_path_changed", f"Planned output path changed during directory creation: {path}")
    current = "overwrite" if path.exists() else "create"
    if destination.disposition == "create" and current == "overwrite":
        raise ExecutionPlanError("output_overwrite_not_authorized", f"Planned create would overwrite an existing output: {path}")
    atomic_io.atomic_write_text(path, content, mode=None, fsync=True)
    return path
