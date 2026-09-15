# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Trusted, bounded observations from Synapse-owned synchronous effect seams.

The Registry binds a dispatch for the duration of its executor. Effect helpers
call these functions at the boundary; action results and caller data cannot
create trusted observations. Durable persistence remains the Authority
repository's single finalization transaction.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import replace
import hashlib
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any, Iterator

from .execution import EffectEnvelope, ExecutionPlan, ExecutionPlanError
from .execution_lifecycle import (
    EffectDiscrepancy,
    EffectValidationVerdict,
    ExecutionRun,
    NoOpExecutionObserver,
    NormalizedEffectObservation,
    ObservationCoverage,
    ObservationCoverageStatus,
    ObservationSource,
    ObservationTrustClass,
    ObserverResult,
    validate_observed_effects,
)


_ACTIVE: ContextVar[tuple["SynchronousExecutionObserver", str, ExecutionPlan] | None] = ContextVar(
    "synapse_synchronous_execution", default=None
)

# This is boundary coverage, not a claim that every action using the boundary
# has complete coverage. Task 6F can project these classes into capabilities.
OWNED_SYNCHRONOUS_COVERAGE = MappingProxyType({
    "http": ("canonical_target", "method", "redirect_hop", "backend", "credential_category", "response_status"),
    "local_output": ("planned_path", "disposition", "content_digest", "content_size"),
    "child_process": ("executable_fingerprint", "argument_fingerprint", "start", "exit", "timeout"),
})


class SynchronousExecutionObserver(NoOpExecutionObserver):
    observer_id = "synapse.synchronous-effects-v1"

    def __init__(self) -> None:
        self._lock = RLock()
        self._events: dict[str, list[tuple[str, EffectEnvelope, dict[str, Any]]]] = {}
        self._gaps: dict[str, set[str]] = {}
        self._declared: dict[str, tuple[str, ...] | None] = {}

    @contextmanager
    def bind(
        self, execution_run_id: str, plan: ExecutionPlan,
        *, declared_classes: tuple[str, ...] | None = None,
    ) -> Iterator[None]:
        plan.verify()
        with self._lock:
            self._events[execution_run_id] = []
            self._gaps[execution_run_id] = set()
            self._declared[execution_run_id] = declared_classes
        token = _ACTIVE.set((self, execution_run_id, plan))
        try:
            yield
        finally:
            _ACTIVE.reset(token)

    def discard(self, execution_run_id: str) -> None:
        with self._lock:
            self._events.pop(execution_run_id, None)
            self._gaps.pop(execution_run_id, None)
            self._declared.pop(execution_run_id, None)

    def record(self, run_id: str, effect_class: str, effects: EffectEnvelope, detail: dict[str, Any]) -> None:
        with self._lock:
            self._events[run_id].append((effect_class, effects, detail))

    def gap(self, run_id: str, effect_class: str) -> None:
        with self._lock:
            self._gaps[run_id].add(effect_class)

    def finalize(self, run: ExecutionRun, *, outcome_kind: str, observed_at: str) -> ObserverResult:
        run.verify()
        run_id = run.identity.execution_run_id
        with self._lock:
            # Finalization may be retried after a failed store commit. Consume
            # buffers only after the caller confirms the durable transition.
            events = tuple(self._events.get(run_id, ()))
            gaps = set(self._gaps.get(run_id, ()))
            declared = self._declared.get(run_id)
        if not events and not gaps:
            return super().finalize(run, outcome_kind=outcome_kind, observed_at=observed_at)
        observations = tuple(
            NormalizedEffectObservation(
                observation_id=f"observation-{hashlib.sha256(f'{run_id}:{sequence}'.encode()).hexdigest()[:32]}",
                execution_run_id=run_id,
                sequence=sequence,
                source=ObservationSource(ObservationTrustClass.RUNTIME_OBSERVED, self.observer_id),
                effect_class=effect_class,
                observed_effects=effects,
                observed_at=observed_at,
                detail=detail,
            ).sealed()
            for sequence, (effect_class, effects, detail) in enumerate(events, 1)
        )
        classes = {item.effect_class for item in observations} | gaps
        coverage = tuple(
            ObservationCoverage(
                effect_class,
                ObservationCoverageStatus.PARTIAL if effect_class in gaps else ObservationCoverageStatus.OBSERVED,
                self.observer_id,
            )
            for effect_class in sorted(classes)
        )
        # An owned seam cannot attest that other effects inside a broad action
        # were observed. Keep those runs explicitly unobservable.
        effects = run.intent.execution_plan.effects
        if declared is not None and not {item.effect_class for item in observations}.issubset(declared):
            coverage += (ObservationCoverage("undeclared_boundary", ObservationCoverageStatus.NOT_INSTRUMENTED, self.observer_id),)
        if declared is not None and effects.local_writes and len(effects.local_writes) > 1:
            coverage += (ObservationCoverage("other_local_writes", ObservationCoverageStatus.NOT_INSTRUMENTED, self.observer_id),)
        if effects.traffic and "http" not in classes and "child_process" not in classes:
            coverage += (ObservationCoverage("other_traffic", ObservationCoverageStatus.NOT_INSTRUMENTED, self.observer_id),)
        if effects.local_writes and "local_output" not in classes and "child_process" not in classes:
            coverage += (ObservationCoverage("other_local_writes", ObservationCoverageStatus.NOT_INSTRUMENTED, self.observer_id),)
        validation = validate_observed_effects(
            run, observations, coverage,
            validation_id=f"validation-{hashlib.sha256(f'{run_id}:{observed_at}'.encode()).hexdigest()[:32]}",
            validated_at=observed_at,
        )
        if gaps.intersection({"http", "local_output", "command_policy"}) and validation.verdict is not EffectValidationVerdict.OUTSIDE_ENVELOPE:
            validation = replace(
                validation,
                verdict=EffectValidationVerdict.INCOMPLETE,
                discrepancies=(EffectDiscrepancy("observation_coverage", "An owned effect boundary did not complete observation."),),
                validation_fingerprint="",
            ).sealed()
        if events and outcome_kind not in {"success", "succeeded"} and validation.verdict is EffectValidationVerdict.WITHIN_ENVELOPE:
            # An executor failure after an effect is not proof of complete coverage.
            coverage += (ObservationCoverage("executor_completion", ObservationCoverageStatus.PARTIAL, self.observer_id),)
            validation = validate_observed_effects(
                run, observations, coverage, validation_id=validation.validation_id, validated_at=observed_at
            )
        return ObserverResult(observations, validation)


def _binding() -> tuple[SynchronousExecutionObserver, str, ExecutionPlan] | None:
    return _ACTIVE.get()


def _same_active_plan(bound: ExecutionPlan, candidate: ExecutionPlan) -> bool:
    if bound.plan_fingerprint == candidate.plan_fingerprint:
        return True
    lineage = candidate.intent.lineage
    return (
        lineage.kind in {"background_worker", "background_job"}
        and lineage.origin_action_id == bound.action_id
        and lineage.origin_correlation_id == bound.correlation_id
        and lineage.parent_plan_fingerprint == bound.plan_fingerprint
        and candidate.action_id == bound.action_id
        and candidate.intent == replace(bound.intent, lineage=lineage)
        and candidate.effects == bound.effects
        and candidate.request_fingerprint == bound.request_fingerprint
    )


def http_before(url: str, method: str, *, backend: str, proxy_url: str | None,
                credential_ref: str | None, redirect_hop: int | None,
                headers: dict[str, str], policy_plan: ExecutionPlan | None) -> None:
    binding = _binding()
    if binding is None:
        return
    observer, run_id, plan = binding
    if plan.effects.traffic == ("third_party",):
        # Provider calls have a distinct route/coverage contract in Task 6E.
        observer.gap(run_id, "provider_http")
        return
    if plan.effects.remote_state_change or method.upper() not in {"GET", "HEAD", "OPTIONS"}:
        observer.gap(run_id, "remote_state")
    try:
        if policy_plan is not None and not _same_active_plan(plan, policy_plan):
            raise ExecutionPlanError("http_plan_diverged", "HTTP policy plan differs from the active dispatch.")
        plan.assert_http_policy(backend, proxy_url, credential_ref)
        plan.assert_http_request(url, method, redirect_hop=redirect_hop)
        credential_use = any(name.lower() in {"authorization", "cookie", "proxy-authorization"} for name in headers) or bool(credential_ref)
        effects = EffectEnvelope(
            traffic=("authorized_target",),
            credential_use=credential_use,
        )
        if not plan.effects.permits(effects):
            raise ExecutionPlanError("http_effect_outside_execution_plan", "HTTP effect exceeds the execution plan.")
    except ExecutionPlanError:
        observer.gap(run_id, "http")
        raise


def http_after(url: str, method: str, *, backend: str, redirect_hop: int | None,
               headers: dict[str, str], credential_ref: str | None, status: int) -> None:
    binding = _binding()
    if binding is None:
        return
    observer, run_id, plan = binding
    if plan.effects.traffic == ("third_party",):
        return
    target = plan.assert_http_request(url, method, redirect_hop=redirect_hop)
    credential_use = any(name.lower() in {"authorization", "cookie", "proxy-authorization"} for name in headers) or bool(credential_ref)
    effects = EffectEnvelope(
        traffic=("authorized_target",),
        credential_use=credential_use,
    )
    observer.record(run_id, "http", effects, {
        "target": target.to_dict(), "method": method.upper(), "backend": backend,
        "redirectHop": redirect_hop or 0, "status": status,
        "credentialCategory": "reference" if credential_use else "none",
    })


def effect_gap(effect_class: str) -> None:
    binding = _binding()
    if binding is not None:
        binding[0].gap(binding[1], effect_class)


def local_output_before(plan: ExecutionPlan, purpose: str, path: Path) -> None:
    binding = _binding()
    if binding is None:
        return
    observer, run_id, bound_plan = binding
    if not _same_active_plan(bound_plan, plan):
        observer.gap(run_id, "local_output")
        raise ExecutionPlanError("output_plan_diverged", "Output plan differs from the active dispatch.")
    if plan.output(purpose).path != str(path):
        observer.gap(run_id, "local_output")
        raise ExecutionPlanError("output_path_diverged", "Output path differs from the active dispatch.")
    domains = plan.effects.local_writes
    if not domains or not plan.effects.local_change:
        observer.gap(run_id, "local_output")
        raise ExecutionPlanError("output_effect_outside_execution_plan", "Local output effect exceeds the execution plan.")
    if not plan.effects.permits(EffectEnvelope(local_change=True, replay_safety=plan.effects.replay_safety)):
        observer.gap(run_id, "local_output")
        raise ExecutionPlanError("output_effect_outside_execution_plan", "Local output effect exceeds the execution plan.")


def local_output_after(plan: ExecutionPlan, purpose: str, path: Path, content: str, disposition: str) -> None:
    binding = _binding()
    if binding is None:
        return
    observer, run_id, bound_plan = binding
    if not _same_active_plan(bound_plan, plan):
        observer.gap(run_id, "local_output")
        raise ExecutionPlanError("output_plan_diverged", "Output plan differs from the active dispatch.")
    domains = plan.effects.local_writes
    if len(domains) != 1:
        observer.gap(run_id, "local_output")
        return
    encoded = content.encode("utf-8")
    effects = EffectEnvelope(
        local_writes=domains, local_change=True,
        local_destruction=disposition == "overwrite", replay_safety=plan.effects.replay_safety,
    )
    observer.record(run_id, "local_output", effects, {
        "purpose": purpose, "pathRef": f"sha256:{hashlib.sha256(str(path).encode()).hexdigest()}",
        "digest": hashlib.sha256(encoded).hexdigest(), "size": len(encoded),
        "disposition": disposition,
    })


def local_output_before_delete(plan: ExecutionPlan, path: Path) -> None:
    try:
        destination = plan.output_for_path(str(path))
    except ExecutionPlanError:
        effect_gap("local_output")
        raise
    if not destination.may_prune or not plan.effects.local_destruction:
        effect_gap("local_output")
        raise ExecutionPlanError("output_delete_not_authorized", "The execution plan does not permit this local deletion.")
    binding = _binding()
    if binding is not None and not _same_active_plan(binding[2], plan):
        binding[0].gap(binding[1], "local_output")
        raise ExecutionPlanError("output_plan_diverged", "Deletion plan differs from the active dispatch.")
    if path.resolve(strict=False) != path:
        effect_gap("local_output")
        raise ExecutionPlanError("output_path_changed", "Planned deletion path changed through a symlink.")


def local_output_deleted(plan: ExecutionPlan, path: Path, size: int) -> None:
    binding = _binding()
    if binding is None:
        return
    observer, run_id, _ = binding
    domains = plan.effects.local_writes
    if len(domains) != 1:
        observer.gap(run_id, "local_output")
        return
    observer.record(run_id, "local_output", EffectEnvelope(
        local_writes=domains, local_change=True, local_destruction=True,
        replay_safety=plan.effects.replay_safety,
    ), {
        "operation": "delete", "pathRef": f"sha256:{hashlib.sha256(str(path).encode()).hexdigest()}",
        "size": size,
    })


def command_started(cmd: list[str]) -> None:
    binding = _binding()
    if binding is None:
        return
    observer, run_id, _ = binding
    # A child may contact destinations Synapse cannot see. Mark coverage partial
    # even if the process exits successfully; never attest its internal effects.
    observer.gap(run_id, "child_process")
    observer.record(run_id, "child_process", EffectEnvelope(), {
        "executableRef": f"sha256:{hashlib.sha256(str(Path(cmd[0]).resolve()).encode()).hexdigest()}",
        "argumentsRef": f"sha256:{hashlib.sha256(repr(cmd).encode()).hexdigest()}",
        "state": "started", "workingDirectoryRef": f"sha256:{hashlib.sha256(str(Path.cwd()).encode()).hexdigest()}",
    })


def command_before(event_data: dict[str, Any] | None) -> None:
    binding = _binding()
    if binding is None:
        return
    observer, run_id, plan = binding
    target = str((event_data or {}).get("target") or "")
    if plan.intent.target_envelope.exact_targets:
        if not target:
            observer.gap(run_id, "command_policy")
            raise ExecutionPlanError("command_target_missing", "Command target is not bound to the execution plan.")
        try:
            plan.intent.target_envelope.require(target)
        except ExecutionPlanError:
            observer.gap(run_id, "command_policy")
            raise
    if plan.effects.traffic and "authorized_target" not in plan.effects.traffic:
        observer.gap(run_id, "command_policy")
        raise ExecutionPlanError("command_effect_outside_execution_plan", "Command traffic is not covered by the execution plan.")


def command_finished(*, return_code: int | None, timed_out: bool) -> None:
    binding = _binding()
    if binding is None:
        return
    observer, run_id, _ = binding
    observer.record(run_id, "child_process", EffectEnvelope(), {
        "state": "timeout" if timed_out else "exited", "returnCode": return_code,
    })
