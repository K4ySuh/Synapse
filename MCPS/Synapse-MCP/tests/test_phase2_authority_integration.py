from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
import sys
import unittest
from unittest.mock import patch

from helpers import isolated_state
from synapse_mcp.adapters.command_utils import require_confirmed
from synapse_mcp.app.actions import (
    ActionRequest,
    ApprovalRequired,
    ExecutionContext,
    ExecutionUnknown,
    PolicyDenial,
    REGISTRY,
    RiskClass,
    Success,
)
from synapse_mcp.app.actions.policies import LocalWriteDomain
from synapse_mcp.core import background_jobs, credentials, evidence, scope, workspace
from synapse_mcp.core.errors import McpError
from synapse_mcp.core.execution import EffectEnvelope, ExecutionPlan
from synapse_mcp.policy import (
    AuthorityGrant,
    AuthorityMode,
    AuthorityOperatorService,
    AuthorityRepositoryError,
    BudgetLimits,
    OperatorPrincipal,
    StateChangePolicy,
    WorkspaceAuthorityRepository,
)


class ProbeHandler(BaseHTTPRequestHandler):
    requests: list[dict[str, object]] = []

    def do_GET(self) -> None:
        type(self).requests.append({"path": self.path, "headers": dict(self.headers)})
        body = b"<html><body><a href='/next'>next</a></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def _request(
    action_id: str,
    arguments: dict[str, object],
    *,
    profile: str = "legacy",
    grant_id: str = "",
    correlation: str = "authority-integration",
    idempotency_key: str = "",
    request_state_id: str = "",
    context_workspace: str | None = None,
) -> ActionRequest:
    descriptor = REGISTRY.get(action_id)
    return ActionRequest(
        descriptor.input_model.model_validate(arguments),
        ExecutionContext(
            str(arguments.get("workspaceId") or "authority") if context_workspace is None else context_workspace,
            correlation,
            descriptor.task_policy.deadline_tier.value,
            arguments.get("confirm") if isinstance(arguments.get("confirm"), bool) else None,
            execution_profile=profile,
            authority_session_id="session-test",
            selected_grant_id=grant_id,
            idempotency_key=idempotency_key,
            request_state_id=request_state_id,
        ),
    )


def _grant_for_plan(
    plan,
    *,
    grant_id: str,
    mode: AuthorityMode,
    limit: int | None = None,
    observation_domains: frozenset[LocalWriteDomain] = frozenset(),
) -> AuthorityGrant:
    now = datetime.now(timezone.utc)
    return AuthorityGrant(
        grant_id=grant_id,
        workspace_id=plan.intent.workspace_id,
        revision=1,
        mode=mode,
        scope_digest=plan.intent.target_envelope.scope_digest,
        target_envelope=plan.intent.target_envelope,
        allowed_action_patterns=(plan.action_id,),
        allowed_methods=plan.intent.methods,
        allowed_effects=plan.effects,
        risk_ceiling=RiskClass.HIGH,
        credential_refs=plan.intent.credential_refs,
        provider_routes=plan.intent.providers,
        third_party_providers=(),
        local_outputs=plan.intent.local_outputs,
        budgets=BudgetLimits(limit, None, None, None),
        state_change_policy=StateChangePolicy.ALLOW,
        created_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        approved_by="replaced-by-service",
        observation_write_domains=observation_domains,
    )


class AuthorityRegistryIntegrationTests(unittest.TestCase):
    def test_fabricated_worker_fields_cannot_bypass_legacy_confirmation(self) -> None:
        with self.assertRaises(McpError) as raised:
            require_confirmed(
                {
                    "_authorityCompatibilityShim": True,
                    "_authorityReceipt": {
                        "authoritySource": "grant",
                        "grantId": "fabricated",
                        "dispatchId": "fabricated",
                    },
                },
                "confirmation required",
            )
        self.assertEqual(raised.exception.code, -32001)

    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.state = isolated_state(Path(self.tmp.name))
        self.state.__enter__()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
        ProbeHandler.requests = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        scope.save_scope(["127.0.0.1", "second.example"])
        workspace.create_workspace("authority", hosts=["127.0.0.1", "second.example"])
        self.principal = OperatorPrincipal("operator:test", "test_fixture", True)
        self.service = AuthorityOperatorService("authority", self.principal)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.state.__exit__(None, None, None)
        self.tmp.cleanup()

    def _create_grant(self, action_id: str, request: ActionRequest, grant_id: str, mode: AuthorityMode, **kwargs):
        effects = REGISTRY.resolve_effects(action_id, request)
        plan = REGISTRY.resolve_execution_plan(action_id, request, effects=effects)
        return self.service.create_grant(
            _grant_for_plan(plan, grant_id=grant_id, mode=mode, **kwargs)
        )

    def test_observe_workspace_read_and_explicit_observation_write(self) -> None:
        summary = _request("workspace.summary", {"workspaceId": "authority"})
        self._create_grant("workspace.summary", summary, "grant-observe-read", AuthorityMode.OBSERVE)
        allowed = _request(
            "workspace.summary",
            {"workspaceId": "authority"},
            profile="observe",
            grant_id="grant-observe-read",
        )
        outcome = REGISTRY.execute("workspace.summary", allowed)
        self.assertIsInstance(outcome, Success)

        context_args = {
            "workspaceId": "authority",
            "target": "127.0.0.1",
            "maxTokens": 500,
        }
        context_plan = _request("workspace.prepare_target_context", context_args)
        self._create_grant(
            "workspace.prepare_target_context",
            context_plan,
            "grant-observe-context",
            AuthorityMode.OBSERVE,
        )
        context_request = _request(
            "workspace.prepare_target_context",
            context_args,
            profile="observe",
            grant_id="grant-observe-context",
        )
        self.assertIsInstance(REGISTRY.execute("workspace.prepare_target_context", context_request), Success)

        analysis_args = {
            "workspaceId": "authority",
            "target": "127.0.0.1",
            "ingest": False,
        }
        analysis = _request("headers_cookies.analyze_workspace", analysis_args)
        self._create_grant(
            "headers_cookies.analyze_workspace",
            analysis,
            "grant-observe-evidence",
            AuthorityMode.OBSERVE,
            observation_domains=frozenset({LocalWriteDomain.EVIDENCE}),
        )
        covered = _request(
            "headers_cookies.analyze_workspace",
            analysis_args,
            profile="observe",
            grant_id="grant-observe-evidence",
        )
        self.assertIsInstance(REGISTRY.execute("headers_cookies.analyze_workspace", covered), Success)

    def test_full_delegated_cors_runs_without_caller_confirmation(self) -> None:
        arguments = {
            "workspaceId": "authority",
            "url": f"{self.base_url}/cors",
            "method": "GET",
            "followRedirects": False,
            "confirm": False,
        }
        planning = _request("cors.execute_test", arguments)
        self._create_grant("cors.execute_test", planning, "grant-cors", AuthorityMode.FULL_DELEGATED)
        execution = _request(
            "cors.execute_test",
            arguments,
            profile="full_delegated",
            grant_id="grant-cors",
            idempotency_key="cors-1",
        )
        outcome = REGISTRY.execute("cors.execute_test", execution)
        self.assertIsInstance(outcome, Success)
        self.assertEqual(len(ProbeHandler.requests), 1)
        payload = outcome.payload.model_dump(mode="json", by_alias=True)
        approval = payload["test"].get("approval", {})
        self.assertEqual(approval.get("authoritySource"), "grant")
        self.assertNotIn("operatorApproved", approval)
        dispatch = self.service.inspect_usage("grant-cors")["dispatches"][0]
        self.assertEqual(dispatch["state"], "succeeded")
        state = WorkspaceAuthorityRepository("authority").snapshot()
        linked = [item for item in state["decisions"] if item.get("dispatchId") == dispatch["dispatchId"]]
        self.assertTrue(any(item["kind"] == "allow" for item in linked))
        self.assertTrue(any(item["kind"] == "dispatch_transition" for item in linked))
        evidence_text = evidence.EVIDENCE_LOG.read_text(encoding="utf-8")
        self.assertIn(dispatch["dispatchId"], evidence_text)

    def test_uncovered_or_cross_workspace_request_does_not_dispatch(self) -> None:
        arguments = {
            "workspaceId": "authority",
            "url": f"{self.base_url}/denied",
            "method": "GET",
            "followRedirects": False,
            "confirm": False,
        }
        uncovered = _request("cors.execute_test", arguments, profile="full_delegated")
        result = REGISTRY.execute("cors.execute_test", uncovered)
        self.assertIsInstance(result, ApprovalRequired)
        self.assertEqual(ProbeHandler.requests, [])
        self.assertTrue(result.details["requestStateId"].startswith("request-"))

        planning = _request("cors.execute_test", arguments)
        self._create_grant("cors.execute_test", planning, "grant-cross", AuthorityMode.FULL_DELEGATED)
        crossed = _request(
            "cors.execute_test",
            arguments,
            profile="full_delegated",
            grant_id="grant-cross",
            context_workspace="different",
        )
        result = REGISTRY.execute("cors.execute_test", crossed)
        self.assertIsInstance(result, PolicyDenial)
        self.assertEqual(result.legacy_code, -32002)
        self.assertEqual(ProbeHandler.requests, [])

    def test_expiry_and_revocation_block_the_next_registry_dispatch(self) -> None:
        arguments = {
            "workspaceId": "authority",
            "url": f"{self.base_url}/lifecycle",
            "method": "GET",
            "followRedirects": False,
            "confirm": False,
        }
        planning = _request("cors.execute_test", arguments, correlation="lifecycle-plan")
        effects = REGISTRY.resolve_effects("cors.execute_test", planning)
        plan = REGISTRY.resolve_execution_plan("cors.execute_test", planning, effects=effects)
        now = datetime.now(timezone.utc)
        expired = replace(
            _grant_for_plan(
                plan,
                grant_id="grant-expired",
                mode=AuthorityMode.FULL_DELEGATED,
            ),
            created_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )
        self.service.create_grant(expired)
        expired_request = _request(
            "cors.execute_test",
            arguments,
            profile="full_delegated",
            grant_id=expired.grant_id,
            correlation="lifecycle-plan",
        )
        expired_outcome = REGISTRY.execute("cors.execute_test", expired_request)
        self.assertIsInstance(expired_outcome, ApprovalRequired)
        self.assertEqual(expired_outcome.reason_code, "grant_expired")
        self.assertEqual(self.service.inspect_usage(expired.grant_id)["dispatches"], [])

        active = self.service.create_grant(
            _grant_for_plan(
                plan,
                grant_id="grant-revoked-before-dispatch",
                mode=AuthorityMode.FULL_DELEGATED,
            )
        )
        self.service.revoke_grant(active.grant_id, expected_grant_revision=1)
        revoked_request = _request(
            "cors.execute_test",
            arguments,
            profile="full_delegated",
            grant_id=active.grant_id,
            correlation="lifecycle-plan",
        )
        revoked_outcome = REGISTRY.execute("cors.execute_test", revoked_request)
        self.assertIsInstance(revoked_outcome, ApprovalRequired)
        self.assertEqual(revoked_outcome.reason_code, "grant_revoked")
        self.assertEqual(self.service.inspect_usage(active.grant_id)["dispatches"], [])
        self.assertEqual(ProbeHandler.requests, [])

    def test_supervised_step_up_resumes_exact_opaque_request(self) -> None:
        arguments = {
            "workspaceId": "authority",
            "url": f"{self.base_url}/supervised",
            "method": "GET",
            "followRedirects": False,
            "confirm": False,
        }
        planning = _request("cors.execute_test", arguments, correlation="supervised-plan")
        grant = self._create_grant(
            "cors.execute_test",
            planning,
            "grant-supervised",
            AuthorityMode.SUPERVISED,
        )
        first = _request(
            "cors.execute_test",
            arguments,
            profile="supervised",
            grant_id=grant.grant_id,
            correlation="supervised-plan",
            idempotency_key="supervised-key",
        )
        denied = REGISTRY.execute("cors.execute_test", first)
        self.assertIsInstance(denied, ApprovalRequired)
        self.assertEqual(denied.reason_code, "step_up_required")
        self.assertEqual(ProbeHandler.requests, [])
        request_state_id = denied.details["requestStateId"]
        plan_fingerprint = denied.details["planFingerprint"]
        self.service.issue_step_up(
            grant_id=grant.grant_id,
            grant_revision=grant.revision,
            plan_fingerprint=plan_fingerprint,
            idempotency_key="supervised-key",
        )
        binding = self.service.resume_request_state(request_state_id)
        self.assertEqual(binding["planFingerprint"], plan_fingerprint)
        resumed = _request(
            "cors.execute_test",
            arguments,
            profile="supervised",
            correlation="supervised-plan",
            idempotency_key="supervised-key",
            request_state_id=request_state_id,
        )
        self.assertIsInstance(REGISTRY.execute("cors.execute_test", resumed), Success)
        self.assertEqual(len(ProbeHandler.requests), 1)

    def test_exact_target_denial_and_whole_scope_credentialed_execution(self) -> None:
        secret = "stage-b-secret-never-persist"
        credentials.save_credential(
            {
                "id": "target-header",
                "type": "header",
                "targetOrigins": [self.base_url],
                "headerName": "X-Stage-B-Auth",
                "secret": secret,
            }
        )
        first_args = {
            "workspaceId": "authority",
            "url": f"{self.base_url}/exact",
            "method": "GET",
            "credentialId": "target-header",
            "followRedirects": False,
            "confirm": False,
        }
        first = _request("cors.execute_test", first_args, correlation="target-plan")
        effects = REGISTRY.resolve_effects("cors.execute_test", first)
        plan = REGISTRY.resolve_execution_plan("cors.execute_test", first, effects=effects)
        exact = self.service.create_grant(
            _grant_for_plan(
                plan,
                grant_id="grant-exact-target",
                mode=AuthorityMode.FULL_DELEGATED,
            )
        )
        second_args = {**first_args, "url": f"{self.base_url}/second"}
        denied = _request(
            "cors.execute_test",
            second_args,
            profile="full_delegated",
            grant_id=exact.grant_id,
            correlation="target-second",
        )
        self.assertIsInstance(REGISTRY.execute("cors.execute_test", denied), ApprovalRequired)
        self.assertEqual(ProbeHandler.requests, [])

        whole_envelope = replace(plan.intent.target_envelope, entire_workspace_scope=True)
        whole = self.service.create_grant(
            replace(
                _grant_for_plan(
                    plan,
                    grant_id="grant-whole-scope",
                    mode=AuthorityMode.FULL_DELEGATED,
                ),
                target_envelope=whole_envelope,
            )
        )
        allowed = _request(
            "cors.execute_test",
            second_args,
            profile="full_delegated",
            grant_id=whole.grant_id,
            correlation="target-second",
        )
        self.assertIsInstance(REGISTRY.execute("cors.execute_test", allowed), Success)
        self.assertEqual(ProbeHandler.requests[-1]["headers"].get("X-Stage-B-Auth"), secret)
        authority_bytes = WorkspaceAuthorityRepository("authority").path.read_text(encoding="utf-8")
        self.assertNotIn(secret, authority_bytes)

    def test_evaluator_failure_fails_closed_before_executor(self) -> None:
        request = _request(
            "workspace.summary",
            {"workspaceId": "authority"},
            profile="observe",
        )
        with patch.object(
            WorkspaceAuthorityRepository,
            "authorize",
            side_effect=RuntimeError("repository unavailable"),
        ), patch.object(workspace, "workspace_summary", side_effect=AssertionError("executor bypass")):
            outcome = REGISTRY.execute("workspace.summary", request)
        self.assertIsInstance(outcome, ApprovalRequired)
        self.assertEqual(outcome.reason_code, "authority_evaluator_failed")

    def test_dispatch_commit_failure_fails_closed_before_executor(self) -> None:
        planning = _request("workspace.summary", {"workspaceId": "authority"})
        self._create_grant(
            "workspace.summary",
            planning,
            "grant-commit-failure",
            AuthorityMode.OBSERVE,
        )
        request = _request(
            "workspace.summary",
            {"workspaceId": "authority"},
            profile="observe",
            grant_id="grant-commit-failure",
        )
        with patch.object(
            WorkspaceAuthorityRepository,
            "mark_dispatched",
            side_effect=RuntimeError("commit unavailable"),
        ), patch.object(workspace, "workspace_summary", side_effect=AssertionError("executor bypass")):
            outcome = REGISTRY.execute("workspace.summary", request)
        self.assertIsInstance(outcome, ApprovalRequired)
        self.assertEqual(outcome.reason_code, "authority_dispatch_commit_failed")

    def test_invalid_executor_output_is_unknown_not_a_false_success(self) -> None:
        planning = _request("workspace.summary", {"workspaceId": "authority"})
        self._create_grant(
            "workspace.summary",
            planning,
            "grant-invalid-output",
            AuthorityMode.OBSERVE,
        )
        request = _request(
            "workspace.summary",
            {"workspaceId": "authority"},
            profile="observe",
            grant_id="grant-invalid-output",
        )
        with patch.object(workspace, "workspace_summary", return_value={}):
            outcome = REGISTRY.execute("workspace.summary", request)
        self.assertIsInstance(outcome, ExecutionUnknown)
        self.assertEqual(outcome.reason_code, "invalid_output_contract_unknown")
        dispatch = self.service.inspect_usage("grant-invalid-output")["dispatches"][0]
        self.assertEqual(dispatch["state"], "unknown")

    def test_uncovered_method_effect_risk_credential_provider_and_output_never_dispatch(self) -> None:
        arguments = {
            "workspaceId": "authority",
            "url": f"{self.base_url}/dimensions",
            "method": "GET",
            "credentialId": "opaque-missing-credential",
            "followRedirects": False,
            "confirm": False,
        }
        planning = _request("cors.execute_test", arguments, correlation="dimension-plan")
        effects = REGISTRY.resolve_effects("cors.execute_test", planning)
        plan = REGISTRY.resolve_execution_plan("cors.execute_test", planning, effects=effects)
        base = _grant_for_plan(
            plan,
            grant_id="placeholder",
            mode=AuthorityMode.FULL_DELEGATED,
        )
        variants = {
            "method": replace(base, grant_id="grant-deny-method", allowed_methods=()),
            "effect": replace(base, grant_id="grant-deny-effect", allowed_effects=EffectEnvelope()),
            "risk": replace(base, grant_id="grant-deny-risk", risk_ceiling=RiskClass.LOW),
            "credential": replace(base, grant_id="grant-deny-credential", credential_refs=()),
            "provider": replace(base, grant_id="grant-deny-provider", provider_routes=()),
        }
        for label, grant in variants.items():
            with self.subTest(dimension=label):
                self.service.create_grant(grant)
                request = _request(
                    "cors.execute_test",
                    arguments,
                    profile="full_delegated",
                    grant_id=grant.grant_id,
                    correlation="dimension-plan",
                )
                self.assertIsInstance(REGISTRY.execute("cors.execute_test", request), ApprovalRequired)
                self.assertEqual(self.service.inspect_usage(grant.grant_id)["dispatches"], [])
        self.assertEqual(ProbeHandler.requests, [])

        crawler_args = {
            "workspaceId": "authority",
            "target": f"{self.base_url}/output",
            "maxPages": 1,
            "background": True,
            "confirm": False,
        }
        with patch.object(workspace, "timestamped_filename", side_effect=lambda suffix: f"deny-{suffix}"):
            crawler_planning = _request("crawler.crawl", crawler_args, correlation="output-plan")
            crawler_effects = REGISTRY.resolve_effects("crawler.crawl", crawler_planning)
            crawler_plan = REGISTRY.resolve_execution_plan(
                "crawler.crawl",
                crawler_planning,
                effects=crawler_effects,
            )
            output_grant = self.service.create_grant(
                replace(
                    _grant_for_plan(
                        crawler_plan,
                        grant_id="grant-deny-output",
                        mode=AuthorityMode.FULL_DELEGATED,
                    ),
                    local_outputs=(),
                )
            )
            output_request = _request(
                "crawler.crawl",
                crawler_args,
                profile="full_delegated",
                grant_id=output_grant.grant_id,
                correlation="output-plan",
            )
            self.assertIsInstance(REGISTRY.execute("crawler.crawl", output_request), ApprovalRequired)
        self.assertEqual(self.service.inspect_usage("grant-deny-output")["dispatches"], [])

    def test_background_crawler_continuation_survives_revocation_without_second_budget(self) -> None:
        arguments = {
            "workspaceId": "authority",
            "target": f"{self.base_url}/crawl",
            "maxPages": 1,
            "maxDepth": 0,
            "includeInScopeHosts": False,
            "analyzeScripts": False,
            "followGetForms": False,
            "background": True,
            "confirm": False,
        }
        with patch.object(workspace, "timestamped_filename", side_effect=lambda suffix: f"fixed-{suffix}"):
            planning = _request("crawler.crawl", arguments, correlation="crawler-authority")
            self._create_grant(
                "crawler.crawl",
                planning,
                "grant-crawler",
                AuthorityMode.FULL_DELEGATED,
                limit=1,
            )
            execution = _request(
                "crawler.crawl",
                arguments,
                profile="full_delegated",
                grant_id="grant-crawler",
                correlation="crawler-authority",
                idempotency_key="crawler-one",
            )
            started = REGISTRY.execute("crawler.crawl", execution)
        self.assertIsInstance(started, Success)
        payload = started.payload.model_dump(mode="json", by_alias=True)
        job_id = payload["job"]["jobId"]
        dispatch = self.service.inspect_usage("grant-crawler")["dispatches"][0]
        self.assertEqual(dispatch["state"], "dispatched")
        self.assertEqual(dispatch["continuation"]["jobId"], job_id)

        wrong_session = _request(
            "jobs.status",
            {"jobId": job_id},
            profile="full_delegated",
            grant_id="grant-crawler",
            correlation="crawler-status",
        )
        wrong_session = replace(
            wrong_session,
            context=replace(wrong_session.context, authority_session_id="different-session"),
        )
        self.assertIsInstance(REGISTRY.execute("jobs.status", wrong_session), ApprovalRequired)

        self.service.revoke_grant("grant-crawler", expected_grant_revision=1)
        deadline = time.monotonic() + 10
        status_payload = {}
        while time.monotonic() < deadline:
            status_request = _request(
                "jobs.status",
                {"jobId": job_id, "includeResult": True},
                profile="full_delegated",
                grant_id="grant-crawler",
                correlation="crawler-status",
            )
            status_outcome = REGISTRY.execute("jobs.status", status_request)
            self.assertIsInstance(status_outcome, Success)
            status_payload = status_outcome.payload.model_dump(mode="json", by_alias=True)
            if status_payload["status"] in {"completed", "failed", "timed_out", "canceled"}:
                break
            time.sleep(0.05)
        self.assertEqual(status_payload.get("status"), "completed", status_payload)
        usage = self.service.inspect_usage("grant-crawler")
        self.assertEqual(usage["usage"]["dispatchesUsed"], 1)
        self.assertEqual(usage["dispatches"][0]["state"], "succeeded")

    def test_legacy_profile_keeps_per_call_confirmation(self) -> None:
        arguments = {
            "workspaceId": "authority",
            "url": f"{self.base_url}/legacy",
            "method": "GET",
            "followRedirects": False,
            "confirm": False,
        }
        denied = REGISTRY.execute("cors.execute_test", _request("cors.execute_test", arguments))
        self.assertIsInstance(denied, ApprovalRequired)
        self.assertEqual(ProbeHandler.requests, [])
        arguments["confirm"] = True
        allowed = REGISTRY.execute("cors.execute_test", _request("cors.execute_test", arguments))
        self.assertIsInstance(allowed, Success)
        self.assertEqual(len(ProbeHandler.requests), 1)

    def test_legacy_job_requires_explicit_operator_adoption_in_authority_profile(self) -> None:
        result_path = Path(self.tmp.name) / "legacy-result.json"
        job = background_jobs.start_command(
            [sys.executable, "-c", "pass"],
            timeout_seconds=30,
            event_type="legacy.fixture",
            summary="legacy fixture",
            tool="legacy.fixture",
            workspace_id="authority",
            output_path=str(result_path),
            finalizer_name="worker.result",
            finalizer_data={"resultPath": str(result_path)},
        )
        job_id = job["jobId"]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            record = background_jobs.status(job_id, include_result=True)
            if record["status"] in {"completed", "failed", "timed_out", "canceled"} and record["finalized"]:
                break
            time.sleep(0.02)
        record = background_jobs.snapshot_record(job_id)
        job_plan = ExecutionPlan.from_dict(record["executionPlan"])
        self.service.create_grant(
            _grant_for_plan(
                job_plan,
                grant_id="grant-legacy-adoption",
                mode=AuthorityMode.FULL_DELEGATED,
            )
        )

        status_request = _request(
            "jobs.status",
            {"jobId": job_id, "includeResult": True},
            profile="full_delegated",
            grant_id="grant-legacy-adoption",
        )
        self.assertIsInstance(REGISTRY.execute("jobs.status", status_request), ApprovalRequired)
        adopted = self.service.adopt_legacy_job(
            job_id,
            "grant-legacy-adoption",
            authority_session_id="session-test",
        )
        self.assertTrue(adopted["adoptedLegacy"])
        self.assertIsInstance(REGISTRY.execute("jobs.status", status_request), Success)

    def test_authority_is_not_exposed_as_model_executable_actions(self) -> None:
        self.assertFalse(any(str(item.id).startswith("authority.") for item in REGISTRY.descriptors()))
        with self.assertRaises(PermissionError):
            OperatorPrincipal("model:caller", "action_input", True)


if __name__ == "__main__":
    unittest.main()
