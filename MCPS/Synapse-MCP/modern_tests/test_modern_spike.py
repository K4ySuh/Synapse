import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
import socket
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from helpers import isolated_state
from mcp import Client, StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError
from mcp.types import InputRequiredResult

from synapse_mcp.app.actions import ActionRequest, ExecutionContext, REGISTRY, RiskClass
from synapse_mcp.core import workspace
from synapse_mcp.policy import (
    AuthorityGrant,
    AuthorityMode,
    AuthorityOperatorService,
    BudgetLimits,
    OperatorPrincipal,
    StateChangePolicy,
    WorkspaceAuthorityRepository,
)
from synapse_mcp.core.errors import McpError
from synapse_mcp.transport.modern_spike import (
    ACTIVE_ACTION_ID,
    MODERN_ACTION_IDS,
    MODERN_AUTHORITY_GRANT_ENV,
    MODERN_AUTHORITY_PROFILE_ENV,
    MODERN_AUTHORITY_SESSION_ENV,
    MODERN_PROTOCOL_REVISION,
    MODERN_SDK_VERSION,
    MODERN_SPIKE_ENV,
    build_server,
)


PROXY_ENVIRONMENT_KEYS = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
}


class ResumeProbeHandler(BaseHTTPRequestHandler):
    requests = 0

    def do_GET(self) -> None:
        type(self).requests += 1
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class ModernSpikeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._feature = patch.dict(os.environ, {MODERN_SPIKE_ENV: "1"})
        self._feature.start()

    def tearDown(self) -> None:
        self._feature.stop()

    async def test_exact_action_surface_schemas_annotations_and_negotiation(self) -> None:
        server = build_server()
        async with Client(server) as client:
            discovered = await client.list_tools()
            self.assertEqual(client.protocol_version, MODERN_PROTOCOL_REVISION)
            self.assertEqual([tool.name for tool in discovered.tools], list(MODERN_ACTION_IDS))
            schema_bytes = 0
            for tool in discovered.tools:
                with self.subTest(tool=tool.name):
                    self.assertEqual(tool.input_schema["type"], "object")
                    self.assertNotIn("confirm", tool.input_schema.get("properties", {}))
                    self.assertEqual(tool.output_schema["type"], "object")
                    self.assertGreater(len(tool.output_schema.get("properties", {})), 2)
                    self.assertIsNotNone(tool.annotations)
                    schema_bytes += len(
                        json.dumps(
                            {"input": tool.input_schema, "output": tool.output_schema},
                            separators=(",", ":"),
                        ).encode("utf-8")
                    )
            self.assertGreater(schema_bytes, 3_000)
            self.assertLess(schema_bytes, 30_000)

    async def test_structured_success_typed_error_and_active_input_required_without_dispatch(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("modern", hosts=["app.example.test"])
                descriptor = REGISTRY.get("workspace.summary")
                planning_request = ActionRequest(
                    descriptor.input_model.model_validate({"workspaceId": "modern"}),
                    ExecutionContext("modern", "modern-grant-plan", 45.0, None),
                )
                plan = REGISTRY.resolve_execution_plan("workspace.summary", planning_request)
                now = datetime.now(timezone.utc)
                grant = AuthorityGrant(
                    grant_id="modern-observe",
                    workspace_id="modern",
                    revision=1,
                    mode=AuthorityMode.OBSERVE,
                    scope_digest=plan.intent.target_envelope.scope_digest,
                    target_envelope=plan.intent.target_envelope,
                    allowed_action_patterns=("workspace.summary",),
                    allowed_methods=(),
                    allowed_effects=plan.effects,
                    risk_ceiling=RiskClass.NONE,
                    credential_refs=(),
                    provider_routes=(),
                    third_party_providers=(),
                    local_outputs=(),
                    budgets=BudgetLimits(None, None, None, None),
                    state_change_policy=StateChangePolicy.DENY,
                    created_at=now - timedelta(minutes=1),
                    expires_at=now + timedelta(hours=1),
                    approved_by="operator:fixture",
                )
                AuthorityOperatorService(
                    "modern",
                    OperatorPrincipal("operator:fixture", "test_fixture", True),
                ).create_grant(grant)
                authority_environment = {
                    MODERN_AUTHORITY_PROFILE_ENV: "observe",
                    MODERN_AUTHORITY_GRANT_ENV: grant.grant_id,
                }
                os.environ.update(authority_environment)
                server = build_server()
                async with Client(server, raise_exceptions=False) as client:
                    result = await client.call_tool("workspace.summary", {"workspaceId": "modern"})
                    self.assertFalse(result.is_error)
                    self.assertIsInstance(result.structured_content, dict)
                    self.assertEqual(result.structured_content["targetCount"], 1)
                    self.assertEqual(result.content[0].text, "Workspace summary: completed")
                    REGISTRY.get("workspace.summary").output_model.model_validate(result.structured_content)

                    with patch.object(
                        workspace,
                        "workspace_summary",
                        side_effect=McpError(-32000, "deterministic fixture failure"),
                    ):
                        error = await client.call_tool("workspace.summary", {"workspaceId": "modern"})
                    self.assertTrue(error.is_error)
                    self.assertIsNone(error.structured_content)
                    self.assertIn("execution_failure", error.content[0].text)

                    required = await client.session.call_tool(
                        ACTIVE_ACTION_ID,
                        {
                            "workspaceId": "modern",
                            "url": "https://app.example.test/active",
                            "method": "GET",
                        },
                        allow_input_required=True,
                    )
                    self.assertIsInstance(required, InputRequiredResult)
                    self.assertEqual(required.result_type, "input_required")
                    self.assertEqual(required.meta["synapse/status"], "approval_required")
                    self.assertEqual(required.meta["synapse/dispatch"], "not_started")

    async def test_stdio_transport(self) -> None:
        environment = dict(os.environ)
        environment[MODERN_SPIKE_ENV] = "1"
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "synapse_mcp.transport.modern_spike", "--transport", "stdio"],
            env=environment,
        )
        async with Client(stdio_client(parameters)) as client:
            discovered = await client.list_tools()
            self.assertEqual(client.protocol_version, MODERN_PROTOCOL_REVISION)
            self.assertEqual([tool.name for tool in discovered.tools], list(MODERN_ACTION_IDS))

    async def test_official_sdk_supervised_request_state_resumes_exactly_once(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            server_http = ThreadingHTTPServer(("127.0.0.1", 0), ResumeProbeHandler)
            server_thread = threading.Thread(target=server_http.serve_forever, daemon=True)
            server_thread.start()
            ResumeProbeHandler.requests = 0
            try:
                workspace.create_workspace("modern-resume", hosts=["127.0.0.1"])
                arguments = {
                    "workspaceId": "modern-resume",
                    "url": f"http://127.0.0.1:{server_http.server_port}/supervised",
                    "method": "GET",
                    "followRedirects": False,
                }
                descriptor = REGISTRY.get(ACTIVE_ACTION_ID)
                planning_request = ActionRequest(
                    descriptor.input_model.model_validate({**arguments, "confirm": False}),
                    ExecutionContext("modern-resume", "planning-only", 45.0, None),
                )
                plan = REGISTRY.resolve_execution_plan(ACTIVE_ACTION_ID, planning_request)
                now = datetime.now(timezone.utc)
                grant = AuthorityGrant(
                    grant_id="modern-supervised",
                    workspace_id="modern-resume",
                    revision=1,
                    mode=AuthorityMode.SUPERVISED,
                    scope_digest=plan.intent.target_envelope.scope_digest,
                    target_envelope=plan.intent.target_envelope,
                    allowed_action_patterns=(ACTIVE_ACTION_ID,),
                    allowed_methods=plan.intent.methods,
                    allowed_effects=plan.effects,
                    risk_ceiling=RiskClass.HIGH,
                    credential_refs=plan.intent.credential_refs,
                    provider_routes=plan.intent.providers,
                    third_party_providers=(),
                    local_outputs=plan.intent.local_outputs,
                    budgets=BudgetLimits(4, None, None, 1),
                    state_change_policy=StateChangePolicy.REQUIRE_STEP_UP,
                    created_at=now - timedelta(minutes=1),
                    expires_at=now + timedelta(hours=1),
                    approved_by="operator:fixture",
                )
                operator = AuthorityOperatorService(
                    "modern-resume",
                    OperatorPrincipal("operator:fixture", "test_fixture", True),
                )
                operator.create_grant(grant)
                authority_environment = {
                    MODERN_AUTHORITY_PROFILE_ENV: "supervised",
                    MODERN_AUTHORITY_GRANT_ENV: grant.grant_id,
                    MODERN_AUTHORITY_SESSION_ENV: "modern-session",
                }
                with patch.dict(os.environ, authority_environment):
                    server = build_server()
                    async with Client(server, raise_exceptions=False) as client:
                        first = await client.session.call_tool(
                            ACTIVE_ACTION_ID,
                            arguments,
                            allow_input_required=True,
                        )
                        self.assertIsInstance(first, InputRequiredResult)
                        self.assertEqual(first.meta["synapse/reason"], "step_up_required")
                        self.assertTrue(first.request_state.startswith("v1."))
                        self.assertEqual(ResumeProbeHandler.requests, 0)

                        pending = operator.list_required_authority()
                        self.assertEqual(len(pending), 1)
                        raw_state_id = pending[0]["requestStateId"]
                        self.assertNotEqual(first.request_state, raw_state_id)
                        self.assertTrue(pending[0]["correlationId"].startswith("modern-spike-"))
                        self.assertTrue(pending[0]["idempotencyKey"].startswith("modern-"))

                        with self.assertRaises(MCPError):
                            await client.session.call_tool(
                                ACTIVE_ACTION_ID,
                                {**arguments, "method": "POST"},
                                request_state=first.request_state,
                                allow_input_required=True,
                            )
                        with self.assertRaises(MCPError):
                            await client.session.call_tool(
                                ACTIVE_ACTION_ID,
                                {**arguments, "workspaceId": "wrong-workspace"},
                                request_state=first.request_state,
                                allow_input_required=True,
                            )
                        with self.assertRaises(MCPError):
                            await client.session.call_tool(
                                "workspace.summary",
                                {"workspaceId": "modern-resume"},
                                request_state=first.request_state,
                                allow_input_required=True,
                            )
                        self.assertEqual(ResumeProbeHandler.requests, 0)

                        with patch.dict(
                            os.environ,
                            {MODERN_AUTHORITY_SESSION_ENV: "wrong-session"},
                        ):
                            wrong_session = await client.session.call_tool(
                                ACTIVE_ACTION_ID,
                                arguments,
                                request_state=first.request_state,
                                allow_input_required=True,
                            )
                        self.assertTrue(wrong_session.is_error)
                        self.assertIn("request_state_mismatch", wrong_session.content[0].text)
                        self.assertEqual(ResumeProbeHandler.requests, 0)

                        operator.issue_request_step_up(raw_state_id)
                        resumed = await client.session.call_tool(
                            ACTIVE_ACTION_ID,
                            arguments,
                            request_state=first.request_state,
                            allow_input_required=True,
                        )
                        self.assertFalse(resumed.is_error)
                        self.assertIsInstance(resumed.structured_content, dict)
                        self.assertEqual(ResumeProbeHandler.requests, 1)

                        replayed = await client.session.call_tool(
                            ACTIVE_ACTION_ID,
                            arguments,
                            request_state=first.request_state,
                            allow_input_required=True,
                        )
                        self.assertTrue(replayed.is_error)
                        self.assertIn("request_state_replayed", replayed.content[0].text)

                        known_request_ids = {raw_state_id}

                        async def new_pending_request():
                            pending_result = await client.session.call_tool(
                                ACTIVE_ACTION_ID,
                                arguments,
                                allow_input_required=True,
                            )
                            self.assertIsInstance(pending_result, InputRequiredResult)
                            current = {
                                item["requestStateId"]: item
                                for item in operator.list_required_authority()
                            }
                            new_ids = set(current) - known_request_ids
                            self.assertEqual(len(new_ids), 1)
                            raw_id = new_ids.pop()
                            known_request_ids.add(raw_id)
                            return pending_result, raw_id

                        expiring, expiring_raw = await new_pending_request()
                        operator.issue_request_step_up(expiring_raw, expires_in_seconds=1)
                        await asyncio.sleep(1.1)
                        expired = await client.session.call_tool(
                            ACTIVE_ACTION_ID,
                            arguments,
                            request_state=expiring.request_state,
                            allow_input_required=True,
                        )
                        self.assertIsInstance(expired, InputRequiredResult)
                        self.assertEqual(expired.meta["synapse/reason"], "step_up_required")
                        self.assertEqual(ResumeProbeHandler.requests, 1)

                        revised_request, revised_raw = await new_pending_request()
                        operator.issue_request_step_up(revised_raw)
                        operator.revise_grant(replace(grant, revision=2), expected_grant_revision=1)
                        revised_resume = await client.session.call_tool(
                            ACTIVE_ACTION_ID,
                            arguments,
                            request_state=revised_request.request_state,
                            allow_input_required=True,
                        )
                        self.assertTrue(revised_resume.is_error)
                        self.assertIn("request_state_grant_revised", revised_resume.content[0].text)

                        revoked_request, revoked_raw = await new_pending_request()
                        operator.issue_request_step_up(revoked_raw)
                        operator.revoke_grant(grant.grant_id, expected_grant_revision=2)
                        revoked_resume = await client.session.call_tool(
                            ACTIVE_ACTION_ID,
                            arguments,
                            request_state=revoked_request.request_state,
                            allow_input_required=True,
                        )
                        self.assertTrue(revoked_resume.is_error)
                        self.assertIn("request_state_grant_revoked", revoked_resume.content[0].text)
                        self.assertIsNotNone(operator.inspect_grant(grant.grant_id).revoked_at)
                        self.assertEqual(ResumeProbeHandler.requests, 1)

                repository = WorkspaceAuthorityRepository("modern-resume")
                dispatches = repository.list_dispatches()
                self.assertEqual(len(dispatches), 1)
                self.assertEqual(dispatches[0]["state"], "succeeded")
                self.assertEqual(repository.budget_usage(grant.grant_id).dispatches_used, 1)
                decisions = repository.snapshot()["decisions"]
                self.assertEqual(sum(item.get("kind") == "allow" for item in decisions), 1)
                self.assertEqual(sum(item.get("kind") == "step_up_issued" for item in decisions), 4)
                self.assertEqual(ResumeProbeHandler.requests, 1)
            finally:
                server_http.shutdown()
                server_http.server_close()
                server_thread.join(timeout=3)

    async def test_streamable_http_loopback_transport(self) -> None:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in PROXY_ENVIRONMENT_KEYS
        }
        environment[MODERN_SPIKE_ENV] = "1"
        with patch.dict(os.environ, environment, clear=True):
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "synapse_mcp.transport.modern_spike",
                    "--transport",
                    "streamable-http",
                    "--port",
                    str(port),
                ],
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                last_error = None
                for _ in range(100):
                    try:
                        async with Client(f"http://127.0.0.1:{port}/mcp") as client:
                            discovered = await client.list_tools()
                            self.assertEqual(client.protocol_version, MODERN_PROTOCOL_REVISION)
                            self.assertEqual([tool.name for tool in discovered.tools], list(MODERN_ACTION_IDS))
                            return
                    except Exception as exc:
                        last_error = exc
                        await asyncio.sleep(0.02)
                self.fail(f"Streamable HTTP spike did not become ready: {last_error}")
            finally:
                process.terminate()
                process.wait(timeout=10)


class ModernSpikeFeatureFlagTests(unittest.TestCase):
    def test_feature_flag_and_exact_sdk_pin(self) -> None:
        self.assertEqual(version("mcp"), MODERN_SDK_VERSION)
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, MODERN_SPIKE_ENV):
                build_server()


if __name__ == "__main__":
    unittest.main()
