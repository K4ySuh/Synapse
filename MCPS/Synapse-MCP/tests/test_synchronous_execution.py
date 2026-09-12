"""Owned synchronous effects are bound to one durable execution run."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import httpx

from helpers import isolated_state
from synapse_mcp.app.actions import (
    ActionEffects, ActionRequest, ExecutionContext, ExecutionUnknown, Idempotency, REGISTRY, RiskClass, Success,
)
from synapse_mcp.app.facade import CompactFacadeService, FacadeCallContext
from synapse_mcp.core import workspace
from synapse_mcp.core.execution import (
    AuthorizationIntent, CanonicalTarget, ContinuationLineage, ExecutionPlan,
    ExecutionPlanError, LocalOutputDestination, ProviderRoute, RedirectPolicy, ScopeSnapshot,
    TargetEnvelope, TargetSelector, empty_target_envelope, write_planned_text,
)
from synapse_mcp.core.http import HttpClientPolicy, HttpRequest, http_client
from synapse_mcp.core.synchronous_observer import SynchronousExecutionObserver, command_finished, command_started
from synapse_mcp.adapters.command_utils import run_command
from synapse_mcp.policy import (
    AuthorityGrant, AuthorityMode, BudgetLimits, StateChangePolicy,
    WorkspaceAuthorityRepository,
)


def _grant(plan: ExecutionPlan, *, grant_id: str) -> AuthorityGrant:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return AuthorityGrant(
        grant_id=grant_id, workspace_id=plan.intent.workspace_id, revision=1,
        mode=AuthorityMode.FULL_DELEGATED,
        scope_digest=plan.intent.target_envelope.scope_digest,
        target_envelope=plan.intent.target_envelope,
        allowed_action_patterns=(plan.action_id,), allowed_methods=plan.intent.methods,
        allowed_effects=plan.effects, risk_ceiling=RiskClass.HIGH,
        credential_refs=plan.intent.credential_refs, provider_routes=plan.intent.providers,
        third_party_providers=(), local_outputs=plan.intent.local_outputs,
        budgets=BudgetLimits(None, None, None, None),
        state_change_policy=StateChangePolicy.ALLOW,
        created_at=now - timedelta(days=1), expires_at=now + timedelta(days=1),
        approved_by="operator:fixture",
    )


def _plan(*, target: str = "", output: Path | None = None) -> ExecutionPlan:
    if target:
        canonical = CanonicalTarget.from_url(target)
        snapshot = ScopeSnapshot.from_value({"hosts": [canonical.host]})
        envelope = TargetEnvelope(
            "phase6d", snapshot.digest, snapshot,
            (TargetSelector(canonical, "any", "fixture"),), (canonical,), False,
            RedirectPolicy(True, 2),
        )
        effects = ActionEffects(traffic=frozenset({"authorized_target"}), replay_safety=Idempotency.NON_IDEMPOTENT)
        providers = (ProviderRoute.from_values("direct", None),)
    else:
        envelope = empty_target_envelope("phase6d")
        effects = ActionEffects(
            local_writes=frozenset({"workspace"}) if output else frozenset(),
            local_change=bool(output),
            replay_safety=Idempotency.IDEMPOTENT_WRITE if output else Idempotency.PURE_READ,
        )
        providers = ()
    intent = AuthorizationIntent(
        "fixture.observe", "phase6d", envelope, methods=("GET",) if target else (),
        providers=providers,
        local_outputs=(LocalOutputDestination(str(output), "fixture.output", False, "create"),) if output else (),
        lineage=ContinuationLineage(origin_action_id="fixture.observe", origin_correlation_id="phase6d"),
    )
    return ExecutionPlan.create(
        action_id="fixture.observe", correlation_id="phase6d", intent=intent,
        effects=effects, arguments={"fixture": True},
    )


def _dispatch(plan: ExecutionPlan) -> tuple[WorkspaceAuthorityRepository, object]:
    repository = WorkspaceAuthorityRepository("phase6d")
    repository.create_grant(_grant(plan, grant_id="grant-phase6d"))
    result = repository.authorize(
        plan, risk_class=RiskClass.NONE, profile="full_delegated",
        authority_session_id="phase6d-session", selected_grant_id="grant-phase6d",
        idempotency_key="phase6d-one-dispatch",
    )
    assert result.receipt is not None
    repository.mark_dispatched(result.receipt)
    return repository, result.receipt


class SynchronousObservationTests(unittest.TestCase):
    def test_capabilities_declare_only_owned_synchronous_boundaries(self) -> None:
        self.assertEqual(REGISTRY.get("crawler.crawl").observed_effect_classes, ("http", "local_output"))
        self.assertEqual(REGISTRY.get("cors.execute_test").observed_effect_classes, ("http",))
        self.assertEqual(REGISTRY.get("ffuf.run_profile").observed_effect_classes, ("child_process",))
        self.assertEqual(REGISTRY.get("workspace.summary").observed_effect_classes, ())

    def test_http_observation_is_durable_and_contains_no_query_or_header_value(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6d", hosts=["target.example"])
            plan = _plan(target="https://target.example/start")
            repository, receipt = _dispatch(plan)
            observer = SynchronousExecutionObserver()
            def responder(request: httpx.Request) -> httpx.Response:
                return httpx.Response(200, text="ok")
            client = httpx.Client(transport=httpx.MockTransport(responder))
            with patch("synapse_mcp.core.http.backends._build_client", return_value=client):
                with observer.bind(receipt.execution_run_id, plan):
                    response = http_client.send(
                        HttpRequest("https://target.example/start?token=hidden"),
                        policy=HttpClientPolicy(backend="direct", execution_plan=plan),
                    )
            self.assertEqual(response.status, 200)
            repository.transition_dispatch(receipt.dispatch_id, "succeeded", outcome_kind="success", observer=observer)
            run = repository.inspect_execution_run(receipt.execution_run_id)
            self.assertEqual(run["state"], "outcome_committed")
            observations = repository.snapshot()["executionObservations"]
            self.assertEqual(len(observations), 1)
            serialized = str(observations)
            self.assertNotIn("hidden", serialized)
            self.assertNotIn("token=", serialized)
            self.assertIn("target.example", serialized)

    def test_redirect_outside_plan_becomes_unknown_without_second_request(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6d", hosts=["target.example"])
            plan = _plan(target="https://target.example/start")
            repository, receipt = _dispatch(plan)
            observer = SynchronousExecutionObserver()
            seen: list[str] = []
            def responder(request: httpx.Request) -> httpx.Response:
                seen.append(str(request.url))
                return httpx.Response(302, headers={"location": "https://outside.example/"})
            client = httpx.Client(transport=httpx.MockTransport(responder))
            with patch("synapse_mcp.core.http.backends._build_client", return_value=client):
                with observer.bind(receipt.execution_run_id, plan):
                    response = http_client.send(
                        HttpRequest("https://target.example/start"),
                        policy=HttpClientPolicy(backend="direct", execution_plan=plan),
                    )
            self.assertIsNone(response.status)
            self.assertEqual(len(seen), 1)
            state = repository.transition_dispatch(
                receipt.dispatch_id, "succeeded", outcome_kind="success", observer=observer,
            )
            self.assertEqual(state["state"], "unknown")
            run = repository.inspect_execution_run(receipt.execution_run_id)
            self.assertEqual(run["state"], "execution_unknown")

    def test_proxy_credential_category_is_recorded_without_value(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6d", hosts=["target.example"])
            original = _plan(target="https://target.example/start")
            proxy = "http://proxy.example:8080"
            plan = replace(
                original,
                intent=replace(
                    original.intent, providers=(ProviderRoute.from_values("proxy", proxy, "proxy-ref"),),
                    credential_refs=("proxy-ref",),
                ),
                effects=replace(original.effects, credential_use=True),
                plan_fingerprint="",
            )._sealed()
            repository, receipt = _dispatch(plan)
            observer = SynchronousExecutionObserver()
            client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, text="ok")))
            with patch("synapse_mcp.core.http.backends._build_client", return_value=client):
                with observer.bind(receipt.execution_run_id, plan):
                    response = http_client.send(
                        HttpRequest("https://target.example/start"),
                        policy=HttpClientPolicy(
                            backend="proxy", proxy_url=proxy, proxy_credential_ref="proxy-ref",
                            proxy_headers={"Proxy-Authorization": "secret-value"}, execution_plan=plan,
                        ),
                    )
            self.assertEqual(response.status, 200)
            repository.transition_dispatch(receipt.dispatch_id, "succeeded", outcome_kind="success", observer=observer)
            observations = str(repository.snapshot()["executionObservations"])
            self.assertIn("'backend': 'proxy'", observations)
            self.assertIn("credentialCategory", observations)
            self.assertNotIn("secret-value", observations)

    def test_forbidden_method_stops_before_network_and_requires_reconciliation(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6d", hosts=["target.example"])
            plan = _plan(target="https://target.example/start")
            repository, receipt = _dispatch(plan)
            observer = SynchronousExecutionObserver()
            seen: list[str] = []
            client = httpx.Client(transport=httpx.MockTransport(lambda request: (
                seen.append(str(request.url)) or httpx.Response(200)
            )))
            with patch("synapse_mcp.core.http.backends._build_client", return_value=client):
                with observer.bind(receipt.execution_run_id, plan):
                    response = http_client.send(
                        HttpRequest("https://target.example/start", method="POST"),
                        policy=HttpClientPolicy(backend="direct", execution_plan=plan),
                    )
            self.assertIsNone(response.status)
            self.assertFalse(seen)
            dispatch = repository.transition_dispatch(
                receipt.dispatch_id, "succeeded", outcome_kind="success", observer=observer,
            )
            self.assertEqual(dispatch["state"], "unknown")

    def test_planned_output_records_digest_and_command_coverage_stays_partial(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6d", hosts=["target.example"])
            path = Path(temporary) / "observed.txt"
            plan = _plan(output=path)
            repository, receipt = _dispatch(plan)
            observer = SynchronousExecutionObserver()
            with observer.bind(receipt.execution_run_id, plan):
                write_planned_text(plan, "fixture.output", "private content")
                command_started(["/bin/true"])
                command_finished(return_code=0, timed_out=False)
            repository.transition_dispatch(receipt.dispatch_id, "succeeded", outcome_kind="success", observer=observer)
            snapshot = repository.snapshot()
            details = str(snapshot["executionObservations"])
            self.assertIn(hashlib.sha256(b"private content").hexdigest(), details)
            self.assertNotIn("private content", details)
            validation = next(iter(snapshot["effectValidations"].values()))
            self.assertEqual(validation["verdict"], "unobservable")

    def test_overwrite_requires_destruction_effect_and_records_disposition(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6d", hosts=["target.example"])
            path = Path(temporary) / "existing.txt"
            path.write_text("old", encoding="utf-8")
            original = _plan(output=path)
            intent = replace(original.intent, local_outputs=(
                LocalOutputDestination(str(path), "fixture.output", False, "overwrite"),
            ))
            denied = replace(original, intent=intent, plan_fingerprint="")._sealed()
            repository, receipt = _dispatch(denied)
            observer = SynchronousExecutionObserver()
            with observer.bind(receipt.execution_run_id, denied):
                with self.assertRaises(ExecutionPlanError):
                    write_planned_text(denied, "fixture.output", "new")
            self.assertEqual(path.read_text(encoding="utf-8"), "old")
            state = repository.transition_dispatch(
                receipt.dispatch_id, "succeeded", outcome_kind="success", observer=observer,
            )
            self.assertEqual(state["state"], "unknown")

            allowed = replace(
                denied, effects=replace(denied.effects, local_destruction=True), plan_fingerprint="",
            )._sealed()
            second_repository = WorkspaceAuthorityRepository("phase6d")
            second_repository.create_grant(_grant(allowed, grant_id="grant-phase6d-overwrite"))
            authorized = second_repository.authorize(
                allowed, risk_class=RiskClass.NONE, profile="full_delegated",
                authority_session_id="phase6d-session", selected_grant_id="grant-phase6d-overwrite",
                idempotency_key="phase6d-overwrite",
            )
            self.assertIsNotNone(authorized.receipt)
            second_repository.mark_dispatched(authorized.receipt)
            observer = SynchronousExecutionObserver()
            with observer.bind(authorized.receipt.execution_run_id, allowed):
                write_planned_text(allowed, "fixture.output", "new")
            state = second_repository.transition_dispatch(
                authorized.receipt.dispatch_id, "succeeded", outcome_kind="success", observer=observer,
            )
            self.assertEqual(state["state"], "succeeded")
            observations = str(second_repository.snapshot()["executionObservations"])
            self.assertIn("'disposition': 'overwrite'", observations)
            self.assertEqual(path.read_text(encoding="utf-8"), "new")

    def test_symlink_output_is_refused_before_write_and_marks_run_unknown(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6d", hosts=["target.example"])
            real = Path(temporary) / "real"
            real.mkdir()
            link = Path(temporary) / "link"
            link.symlink_to(real, target_is_directory=True)
            output = link / "observed.txt"
            plan = _plan(output=output)
            repository, receipt = _dispatch(plan)
            observer = SynchronousExecutionObserver()
            with observer.bind(receipt.execution_run_id, plan):
                with self.assertRaises(ExecutionPlanError):
                    write_planned_text(plan, "fixture.output", "should not write")
            self.assertFalse((real / "observed.txt").exists())
            state = repository.transition_dispatch(
                receipt.dispatch_id, "succeeded", outcome_kind="success", observer=observer,
            )
            self.assertEqual(state["state"], "unknown")

    def test_retention_refuses_unplanned_delete_without_removing_old_file(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6d", hosts=["target.example"])
            directory = Path(temporary) / "retention"
            directory.mkdir()
            old = directory / "2025-map.json"
            current = directory / "2026-map.json"
            old.write_text("old", encoding="utf-8")
            current.write_text("current", encoding="utf-8")
            plan = _plan(output=current)
            repository, receipt = _dispatch(plan)
            observer = SynchronousExecutionObserver()
            with observer.bind(receipt.execution_run_id, plan):
                with self.assertRaises(ExecutionPlanError):
                    workspace.retain_latest_artifacts(
                        directory, "map.json", keep=1, execution_plan=plan,
                    )
            self.assertTrue(old.exists())
            state = repository.transition_dispatch(
                receipt.dispatch_id, "succeeded", outcome_kind="success", observer=observer,
            )
            self.assertEqual(state["state"], "unknown")

    def test_exact_planned_delete_is_observed(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6d", hosts=["target.example"])
            directory = Path(temporary) / "retention"
            directory.mkdir()
            old = directory / "2025-map.json"
            current = directory / "2026-map.json"
            old.write_text("old", encoding="utf-8")
            current.write_text("current", encoding="utf-8")
            original = _plan(output=current)
            plan = replace(
                original,
                intent=replace(original.intent, local_outputs=(
                    *original.intent.local_outputs,
                    LocalOutputDestination(str(old), "fixture.old", False, "overwrite", True),
                )),
                effects=replace(original.effects, local_destruction=True),
                plan_fingerprint="",
            )._sealed()
            repository, receipt = _dispatch(plan)
            observer = SynchronousExecutionObserver()
            with observer.bind(receipt.execution_run_id, plan):
                removed = workspace.retain_latest_artifacts(
                    directory, "map.json", keep=1, execution_plan=plan,
                )
            self.assertEqual(removed, [str(old)])
            state = repository.transition_dispatch(
                receipt.dispatch_id, "succeeded", outcome_kind="success", observer=observer,
            )
            self.assertEqual(state["state"], "succeeded")
            validation = repository.execution_validation_for_run(receipt.execution_run_id)
            self.assertEqual(str(validation.verdict), "within_envelope")

    def test_command_target_preflight_stops_unplanned_child(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6d", hosts=["target.example"])
            plan = _plan(target="https://target.example/start")
            repository, receipt = _dispatch(plan)
            observer = SynchronousExecutionObserver()
            with observer.bind(receipt.execution_run_id, plan), patch(
                "synapse_mcp.adapters.command_utils.subprocess.Popen"
            ) as popen:
                with self.assertRaises(ExecutionPlanError):
                    run_command(
                        ["/bin/true"], timeout_seconds=2, event_type="fixture.command",
                        summary="fixture", event_data={"target": "https://outside.example/"},
                    )
                popen.assert_not_called()
            state = repository.transition_dispatch(
                receipt.dispatch_id, "succeeded", outcome_kind="success", observer=observer,
            )
            self.assertEqual(state["state"], "unknown")

    def test_action_and_facade_return_validation_reference(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6d", hosts=["target.example"])
            descriptor = REGISTRY.get("workspace.summary")
            def request(key: str) -> ActionRequest:
                return ActionRequest(
                    descriptor.input_model.model_validate({"workspaceId": "phase6d"}),
                    ExecutionContext(
                        "phase6d", "phase6d-summary", 45.0, None,
                        execution_profile="full_delegated", authority_session_id="phase6d-session",
                        selected_grant_id="grant-phase6d", idempotency_key=key,
                    ),
                )
            plan = REGISTRY.resolve_execution_plan("workspace.summary", request("first"))
            WorkspaceAuthorityRepository("phase6d").create_grant(_grant(plan, grant_id="grant-phase6d"))
            outcome = REGISTRY.execute("workspace.summary", request("first"))
            self.assertIsInstance(outcome, Success)
            self.assertTrue(outcome.execution_run_id)
            self.assertEqual(str(outcome.effect_validation.verdict), "unobservable")
            envelope = CompactFacadeService().execution.run(
                operation="actions.execute", action_id="workspace.summary",
                arguments={"workspaceId": "phase6d"},
                context=FacadeCallContext(
                    principal_id="operator:phase6d", workspace_id="phase6d",
                    execution_profile="full_delegated", authority_session_id="phase6d-session",
                    selected_grant_id="grant-phase6d", correlation_id="phase6d-summary",
                ),
                passive_only=False, idempotency_key="second",
            )
            self.assertEqual(envelope.outcome_kind, "success")
            self.assertEqual(envelope.diagnostics["effectValidation"]["verdict"], "unobservable")
            self.assertTrue(envelope.diagnostics["executionRunId"])

    def test_observation_commit_failure_cannot_return_success_or_replay(self) -> None:
        with TemporaryDirectory() as temporary, isolated_state(Path(temporary), store_version="sqlite-v2"):
            workspace.create_workspace("phase6d", hosts=["target.example"])
            descriptor = REGISTRY.get("workspace.summary")
            request = ActionRequest(
                descriptor.input_model.model_validate({"workspaceId": "phase6d"}),
                ExecutionContext(
                    "phase6d", "phase6d-failure", 45.0, None,
                    execution_profile="full_delegated", authority_session_id="phase6d-session",
                    selected_grant_id="grant-phase6d", idempotency_key="phase6d-failure",
                ),
            )
            plan = REGISTRY.resolve_execution_plan("workspace.summary", request)
            repository = WorkspaceAuthorityRepository("phase6d")
            repository.create_grant(_grant(plan, grant_id="grant-phase6d"))
            with patch.object(REGISTRY._policy_evaluator.observer, "finalize", side_effect=OSError("storage-failure")):
                outcome = REGISTRY.execute("workspace.summary", request)
            self.assertIsInstance(outcome, ExecutionUnknown)
            dispatch = next(iter(repository.snapshot()["dispatches"].values()))
            self.assertEqual(dispatch["state"], "unknown")
            self.assertTrue(outcome.execution_run_id)


if __name__ == "__main__":
    unittest.main()
