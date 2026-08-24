from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from helpers import isolated_state
import httpx2
from jsonschema import Draft202012Validator
from mcp import Client, StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import Context
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, Implementation, InputRequiredResult, ResourceLink, TextContent
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS

from synapse_mcp.app.actions import ActionRequest, ExecutionContext, REGISTRY, RiskClass
from synapse_mcp.app.facade.contracts import FacadeCallContext, FacadeEnvelope, ResourceReference
from synapse_mcp.app.facade.projections import SurfaceMode
from synapse_mcp.core import paths, workspace
from synapse_mcp.policy import (
    AuthorityGrant,
    AuthorityMode,
    AuthorityOperatorService,
    BudgetLimits,
    OperatorPrincipal,
    StateChangePolicy,
)
from synapse_mcp.policy.repository import WorkspaceAuthorityRepository
from synapse_mcp.transport.modern.config import ModernAdapterConfig, ModernConfigurationError
from synapse_mcp.transport.modern.http_security import AuthenticatedHTTPMiddleware
from synapse_mcp.transport.modern.identity import (
    CURRENT_HTTP_PRINCIPAL,
    TokenPrincipalResolver,
)
from synapse_mcp.transport.modern.server import (
    MODERN_PROTOCOL_REVISION,
    MODERN_SDK_VERSION,
    _tool_result,
    build_runtime,
)


ACTIVE_ACTION_ID = "cors.execute_test"
TEST_TOKEN = "test-bearer-token-with-at-least-thirty-two-characters"
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
SUPPORTED_PROTOCOL_VERSIONS = (*MODERN_PROTOCOL_VERSIONS, *HANDSHAKE_PROTOCOL_VERSIONS)


def protocol_client_cases() -> list[tuple[str, str]]:
    return [
        *((version, version) for version in MODERN_PROTOCOL_VERSIONS),
        *(("legacy", version) for version in HANDSHAKE_PROTOCOL_VERSIONS),
    ]


def input_roundtrip(value: str, ctx: Context) -> CallToolResult | InputRequiredResult:
    if not ctx.request_state:
        return InputRequiredResult(requestState="test-state")
    return CallToolResult(content=[TextContent(text=value)], structuredContent={"result": value})


class ProbeHandler(BaseHTTPRequestHandler):
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


class ModernAdapterFixture:
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.state = isolated_state(self.root / "runtime")
        self.state.__enter__()
        self.paths_patch = patch.object(paths, "DATA_DIR", self.data)
        self.paths_patch.start()
        self.bindings_path = self.root / "bindings.json"
        self.tokens_path = self.root / "tokens.json"
        self.keyring_path = self.root / "keyring.json"
        self._write_bindings()
        self._write_private(
            self.tokens_path,
            {
                "version": 1,
                "tokenDigests": {sha256(TEST_TOKEN.encode()).hexdigest(): "operator:test"},
            },
        )
        self._write_keyring("11" * 32)

    def tearDown(self) -> None:
        self.paths_patch.stop()
        self.state.__exit__(None, None, None)
        self.tmp.cleanup()

    def _write_private(self, path: Path, value: object) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)

    def _write_keyring(self, *hex_keys: str) -> None:
        self._write_private(
            self.keyring_path,
            {"version": 1, "keys": [f"hex:{value}" for value in hex_keys]},
        )

    def _write_bindings(self, *, selected_grant_id: str = "") -> None:
        binding = {
            "executionProfile": "supervised" if selected_grant_id else "observe",
            "authoritySessionId": "session-test",
            "selectedGrantId": selected_grant_id,
        }
        other = {
            "executionProfile": "observe",
            "authoritySessionId": "session-other",
        }
        self._write_private(
            self.bindings_path,
            {
                "version": 1,
                "principals": {
                    "operator:test": {
                        "defaultWorkspace": "modern",
                        "default": binding,
                        "workspaces": {"*": binding},
                    },
                    "operator:other": {
                        "defaultWorkspace": "modern",
                        "default": other,
                        "workspaces": {"*": other},
                    },
                },
            },
        )

    def config(
        self,
        *,
        surface: SurfaceMode = SurfaceMode.MODERN_COMPACT,
        transport: str = "stdio",
        principal: str = "operator:test",
        audience: str = "synapse-modern-test",
        server_name: str = "synapse-modern-test",
        ttl: float = 600.0,
        keyring: bool = True,
        **changes: object,
    ) -> ModernAdapterConfig:
        values: dict[str, object] = {
            "surface": surface,
            "transport": transport,
            "server_name": server_name,
            "audience": audience,
            "identity_bindings_path": self.bindings_path,
            "stdio_principal": principal if transport == "stdio" else "",
            "http_token_map_path": self.tokens_path if transport == "streamable-http" else None,
            "request_state_keyring_path": self.keyring_path if keyring else None,
            "allow_ephemeral_request_state": not keyring,
            "request_state_ttl_seconds": ttl,
            "state_dir": self.data / "adapter-state",
        }
        values.update(changes)
        return ModernAdapterConfig(**values)


class ModernConfigurationTests(ModernAdapterFixture, unittest.TestCase):
    def test_exact_sdk_pin_and_remote_startup_fail_closed_matrix(self) -> None:
        self.assertEqual(version("mcp"), MODERN_SDK_VERSION)
        with self.assertRaises(ModernConfigurationError):
            self.config(surface=SurfaceMode.LEGACY)
        with self.assertRaises(ModernConfigurationError):
            self.config(keyring=False, allow_ephemeral_request_state=False)
        with self.assertRaises(ModernConfigurationError):
            self.config(
                transport="streamable-http",
                host="0.0.0.0",
                remote_enabled=False,
            )
        with self.assertRaises(ModernConfigurationError):
            self.config(
                transport="streamable-http",
                host="0.0.0.0",
                remote_enabled=True,
                allowed_hosts=("mcp.example.test",),
                allowed_origins=("https://mcp.example.test",),
                tls_termination="local",
            )
        with self.assertRaises(ModernConfigurationError):
            self.config(
                transport="streamable-http",
                host="0.0.0.0",
                remote_enabled=True,
                allowed_hosts=("mcp.example.test",),
                allowed_origins=("https://mcp.example.test",),
                tls_termination="trusted-proxy",
            )
        with self.assertRaises(ModernConfigurationError):
            self.config(
                transport="streamable-http",
                host="0.0.0.0",
                remote_enabled=True,
                allowed_hosts=("*",),
                allowed_origins=("http://mcp.example.test",),
                tls_termination="trusted-proxy",
                trusted_proxies=("127.0.0.1/32",),
            )
        disabled = build_runtime(self.config(observability="disabled"))
        self.assertNotIn(
            "OpenTelemetryMiddleware",
            {type(middleware).__name__ for middleware in disabled.server._lowlevel_server.middleware},
        )


class ModernDiscoveryTests(ModernAdapterFixture, unittest.IsolatedAsyncioTestCase):
    async def test_both_surfaces_are_deterministic_on_modern_and_legacy_negotiation(self) -> None:
        expected_versions = set(SUPPORTED_PROTOCOL_VERSIONS)
        manifest = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "tests"
                / "fixtures"
                / "phase3d"
                / "payload-manifest.json"
            ).read_text(encoding="utf-8")
        )
        for surface, count in (
            (SurfaceMode.MODERN_COMPACT, 11),
            (SurfaceMode.MODERN_DIRECT, 174),
        ):
            runtime = build_runtime(self.config(surface=surface))
            observed_versions: set[str] = set()
            modern_names: list[str] = []
            for mode, version in protocol_client_cases():
                with patch("mcp.client.session.LATEST_HANDSHAKE_VERSION", version):
                    async with Client(runtime.server, mode=mode) as client:
                        discovered = await client.list_tools()
                        observed_versions.add(str(client.protocol_version))
                        names = [tool.name for tool in discovered.tools]
                        wire = [
                            tool.model_dump(mode="json", by_alias=True, exclude_none=True)
                            for tool in discovered.tools
                        ]
                        wire_payload = json.dumps(wire, separators=(",", ":")).encode("utf-8")
                        recorded = manifest["officialSdkWire"]["surfaces"][surface.value]["revisions"][
                            str(client.protocol_version)
                        ]
                        fixture = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "phase3d" / recorded[
                            "fixture"
                        ]
                        self.assertEqual(wire_payload + b"\n", fixture.read_bytes())
                        self.assertEqual(len(wire_payload), recorded["compactUtf8Bytes"])
                        self.assertEqual(sha256(wire_payload).hexdigest(), recorded["sha256"])
                        self.assertEqual(len(names), count)
                        if not modern_names:
                            modern_names = names
                        else:
                            self.assertEqual(names, modern_names)
                        for tool in discovered.tools:
                            self.assertNotIn("confirm", tool.input_schema.get("properties", {}))
                            self.assertEqual(tool.output_schema["type"], "object")
                            Draft202012Validator.check_schema(tool.output_schema)
                            self.assertIsNotNone(tool.annotations)
            self.assertEqual(observed_versions, expected_versions)
        self.assertEqual(modern_names, [str(descriptor.id) for descriptor in REGISTRY.descriptors()])

    async def test_standard_wire_schemas_are_action_specific_and_validate_returned_content(self) -> None:
        workspace.create_workspace("modern", hosts=["example.test"])
        direct_runtime = build_runtime(self.config(surface=SurfaceMode.MODERN_DIRECT))
        async with Client(direct_runtime.server) as client:
            discovered = await client.list_tools()
            schemas = {tool.name: tool.output_schema for tool in discovered.tools}
            self.assertEqual(len(schemas), 174)
            self.assertEqual(
                len({json.dumps(schema, sort_keys=True) for schema in schemas.values()}),
                174,
            )
            for action_id, schema in schemas.items():
                self.assertEqual(schema["properties"]["operation"]["const"], action_id)
                self.assertEqual(schema["properties"]["actionId"]["const"], action_id)
            result = await client.session.call_tool(
                "adapters.list",
                {},
                allow_input_required=True,
            )
            self.assertIsInstance(result, InputRequiredResult)
            handle = result.meta["synapse/operationHandle"]
            direct_runtime.operations.pending(
                handle,
                context=FacadeCallContext(
                    principal_id="operator:test",
                    workspace_id="modern",
                    execution_profile="observe",
                    authority_session_id="session-test",
                ),
            )
            planning = ActionRequest(
                REGISTRY.get("adapters.list").input_model.model_validate({}),
                ExecutionContext("modern", "planning", 45.0, None),
            )
            plan = REGISTRY.resolve_execution_plan("adapters.list", planning)
            now = datetime.now(timezone.utc)
            grant = AuthorityGrant(
                grant_id="modern-adapters-list",
                workspace_id="modern",
                revision=1,
                mode=AuthorityMode.SUPERVISED,
                scope_digest=plan.intent.target_envelope.scope_digest,
                target_envelope=plan.intent.target_envelope,
                allowed_action_patterns=("adapters.list",),
                allowed_methods=plan.intent.methods,
                allowed_effects=plan.effects,
                risk_ceiling=RiskClass.LOW,
                credential_refs=(),
                provider_routes=(),
                third_party_providers=(),
                local_outputs=(),
                budgets=BudgetLimits(4, None, None, 1),
                state_change_policy=StateChangePolicy.ALLOW,
                created_at=now - timedelta(minutes=1),
                expires_at=now + timedelta(hours=1),
                approved_by="operator:test",
            )
            operator = AuthorityOperatorService(
                "modern",
                OperatorPrincipal("operator:test", "test_fixture", True),
            )
            operator.create_grant(grant)
            self._write_bindings(selected_grant_id=grant.grant_id)
            direct_runtime.operations.mark_terminal(handle, "replaced_by_authorized_retry")
            authorized = build_runtime(self.config(surface=SurfaceMode.MODERN_DIRECT))
            async with Client(authorized.server) as authorized_client:
                result = await authorized_client.call_tool("adapters.list", {})
            self.assertFalse(result.is_error)
            self.assertEqual(result.structured_content["outcomeKind"], "success")
            Draft202012Validator(schemas["adapters.list"]).validate(result.structured_content)
            validator = Draft202012Validator(schemas["adapters.list"])
            for outcome_kind in (
                "success",
                "approval_required",
                "validation_failure",
                "unavailable_capability",
                "policy_denial",
                "execution_failure",
                "execution_unknown",
            ):
                envelope = FacadeEnvelope(
                    operation="adapters.list",
                    action_id="adapters.list",
                    outcome_kind=outcome_kind,
                    summary=outcome_kind,
                    result={} if outcome_kind == "success" else None,
                    requested_input={"review": "operator_authority"}
                    if outcome_kind == "approval_required"
                    else None,
                    trace_id="wire-schema-variant",
                    operation_handle="opaque-operation"
                    if outcome_kind == "approval_required"
                    else None,
                )
                validator.validate(envelope.model_dump(mode="json", by_alias=True))

        compact_runtime = build_runtime(self.config())
        async with Client(compact_runtime.server) as client:
            discovered = await client.list_tools()
            schemas = {tool.name: tool.output_schema for tool in discovered.tools}
            success = await client.call_tool("capabilities.search", {"query": "workspace"})
            self.assertFalse(success.is_error)
            Draft202012Validator(schemas["capabilities.search"]).validate(success.structured_content)
            with patch("synapse_mcp.app.actions.catalog.shutil.which", return_value=None):
                unavailable = await client.call_tool(
                    "actions.run_active",
                    {
                        "actionId": "ffuf.run_profile",
                        "arguments": {
                            "workspaceId": "modern",
                            "target": "https://example.test",
                            "wordlist": "/tmp/not-used",
                        },
                    },
                )
            Draft202012Validator(schemas["actions.run_active"]).validate(unavailable.structured_content)

    async def test_compact_discovery_cache_scope_schema_and_size_gate(self) -> None:
        runtime = build_runtime(self.config())
        async with Client(runtime.server) as client:
            discovered = await client.list_tools()
            payload = [
                tool.model_dump(mode="json", by_alias=True, exclude_none=True)
                for tool in discovered.tools
            ]
            self.assertLessEqual(
                len(json.dumps(payload, separators=(",", ":")).encode()),
                24_834,
            )
            self.assertEqual(discovered.ttl_ms, 60_000)
            self.assertEqual(discovered.cache_scope, "public")
            self.assertLessEqual(len(runtime.server.instructions), 1_000)
            self.assertIn("server-held scope and authority", runtime.server.instructions[:512])
            self.assertIn("tasks.control", [tool.name for tool in discovered.tools])
            self.assertFalse(getattr(client.server_capabilities, "extensions", None))

    async def test_client_info_and_nested_action_data_cannot_select_authority(self) -> None:
        workspace.create_workspace("modern", hosts=["example.test"])
        runtime = build_runtime(self.config())
        spoofed = Implementation(name="operator:other", version="full_delegated")
        async with Client(runtime.server, client_info=spoofed) as client:
            success = await client.call_tool("capabilities.search", {})
            self.assertFalse(success.is_error)
            self.assertEqual(success.structured_content["outcomeKind"], "success")
            nested = await client.session.call_tool(
                "actions.run_active",
                {
                    "actionId": "workspace.summary",
                    "arguments": {
                        "workspaceId": "modern",
                        "metadata": {
                            "profile": "nginx",
                            "principal": "target-user",
                            "grant": "oauth-fixture",
                        },
                    },
                },
                allow_input_required=True,
            )
            self.assertIsInstance(nested, InputRequiredResult)
            self.assertNotIn("operator:other", nested.model_dump_json(by_alias=True))
            self.assertNotIn("full_delegated", nested.model_dump_json(by_alias=True))
            outer = await client.call_tool(
                "actions.run_active",
                {
                    "actionId": "workspace.summary",
                    "arguments": {"workspaceId": "modern"},
                    "grantId": "fabricated",
                },
            )
            self.assertTrue(outer.is_error)
            self.assertNotIn("operationHandle", outer.model_dump_json(by_alias=True))

    async def test_typed_unavailable_failure_has_schema_conformant_structured_content(self) -> None:
        runtime = build_runtime(self.config())
        async with Client(runtime.server) as client:
            with patch("synapse_mcp.app.actions.catalog.shutil.which", return_value=None):
                result = await client.call_tool(
                    "actions.run_active",
                    {
                        "actionId": "ffuf.run_profile",
                        "arguments": {
                            "workspaceId": "modern",
                            "target": "https://example.test",
                            "wordlist": "/tmp/not-used",
                        },
                    },
                )
            self.assertTrue(result.is_error)
            envelope = FacadeEnvelope.model_validate(result.structured_content)
            self.assertEqual(envelope.outcome_kind, "unavailable_capability")
            self.assertTrue(envelope.diagnostics["reasonCode"])

    async def test_request_state_expiry_fails_before_handler_resume(self) -> None:
        runtime = build_runtime(self.config(ttl=0.05))
        runtime.server.add_tool(input_roundtrip, name="test.input_roundtrip")
        async with Client(runtime.server) as client:
            first = await client.session.call_tool(
                "test.input_roundtrip",
                {"value": "safe"},
                allow_input_required=True,
            )
            self.assertIsInstance(first, InputRequiredResult)
            await asyncio.sleep(0.08)
            with self.assertRaises(MCPError):
                await client.session.call_tool(
                    "test.input_roundtrip",
                    {"value": "safe"},
                    request_state=first.request_state,
                    allow_input_required=True,
                )


class ModernPersistenceAndResourceTests(ModernAdapterFixture, unittest.IsolatedAsyncioTestCase):
    async def test_resource_links_and_reads_survive_restart_and_reject_cross_principal(self) -> None:
        artifact = self.data / "artifact.txt"
        artifact.write_text("durable artifact", encoding="utf-8")
        runtime = build_runtime(self.config())
        context = FacadeCallContext(
            principal_id="operator:test",
            workspace_id="modern",
            execution_profile="observe",
            authority_session_id="session-test",
        )
        reference = runtime.resources.issue(
            artifact,
            workspace_id="modern",
            context=context,
            artifact_type="evidence",
        )
        restarted = build_runtime(self.config())
        async with Client(restarted.server) as client:
            result = await client.read_resource(f"synapse://artifact/{reference.reference}")
            self.assertEqual(result.contents[0].text, "durable artifact")

        other = build_runtime(self.config(principal="operator:other"))
        async with Client(other.server) as client:
            with self.assertRaises(MCPError):
                await client.read_resource(f"synapse://artifact/{reference.reference}")

        envelope = FacadeEnvelope(
            operation="reports.render",
            outcome_kind="success",
            summary="report ready",
            resource_references=[reference],
            trace_id="trace-test",
        )
        sdk = __import__("synapse_mcp.transport.modern.server", fromlist=["_require_sdk"])._require_sdk()
        rendered = _tool_result(
            envelope,
            type("Context", (), {"protocol_version": MODERN_PROTOCOL_REVISION})(),
            sdk,
            surface=SurfaceMode.MODERN_COMPACT.value,
        )
        self.assertTrue(any(isinstance(item, ResourceLink) for item in rendered.content))
        self.assertNotIn(str(artifact), rendered.model_dump_json(by_alias=True))


class ModernResumeTests(ModernAdapterFixture, unittest.IsolatedAsyncioTestCase):
    async def test_protocol_native_disabled_traffic_smoke_passes_three_repetitions(self) -> None:
        for repetition in range(1, 4):
            workspace_id = f"native-smoke-{repetition}"
            workspace.create_workspace(workspace_id, hosts=["app.acme-demo.test"])
            arguments = {
                "workspaceId": workspace_id,
                "url": "https://app.acme-demo.test/api/items",
                "method": "GET",
                "probeOrigin": "https://phase3.invalid",
                "httpBackend": "disabled",
                "disableTraffic": True,
                "followRedirects": False,
            }
            descriptor = REGISTRY.get(ACTIVE_ACTION_ID)
            planning = ActionRequest(
                descriptor.input_model.model_validate({**arguments, "confirm": False}),
                ExecutionContext(workspace_id, "planning", 45.0, None),
            )
            plan = REGISTRY.resolve_execution_plan(ACTIVE_ACTION_ID, planning)
            now = datetime.now(timezone.utc)
            grant = AuthorityGrant(
                grant_id=f"native-smoke-{repetition}",
                workspace_id=workspace_id,
                revision=1,
                mode=AuthorityMode.SUPERVISED,
                scope_digest=plan.intent.target_envelope.scope_digest,
                target_envelope=plan.intent.target_envelope,
                allowed_action_patterns=(ACTIVE_ACTION_ID,),
                allowed_methods=plan.intent.methods,
                allowed_effects=plan.effects,
                risk_ceiling=RiskClass.HIGH,
                credential_refs=(),
                provider_routes=plan.intent.providers,
                third_party_providers=(),
                local_outputs=plan.intent.local_outputs,
                budgets=BudgetLimits(4, None, None, 1),
                state_change_policy=StateChangePolicy.REQUIRE_STEP_UP,
                created_at=now - timedelta(minutes=1),
                expires_at=now + timedelta(hours=1),
                approved_by="operator:test",
            )
            operator = AuthorityOperatorService(
                workspace_id,
                OperatorPrincipal("operator:test", "test_fixture", True),
            )
            operator.create_grant(grant)
            self._write_bindings(selected_grant_id=grant.grant_id)
            payload = {
                "actionId": ACTIVE_ACTION_ID,
                "arguments": arguments,
                "idempotencyKey": f"native-smoke-{repetition}",
            }
            initial = build_runtime(self.config())
            async with Client(initial.server) as client:
                first = await client.session.call_tool(
                    "actions.run_active",
                    payload,
                    allow_input_required=True,
                )
            self.assertIsInstance(first, InputRequiredResult)
            self.assertEqual(first.meta["synapse/protocolVersion"], MODERN_PROTOCOL_REVISION)
            self.assertEqual(first.meta["synapse/dispatch"], "not_started")
            pending = operator.list_required_authority()
            self.assertEqual(len(pending), 1)
            operator.issue_request_step_up(pending[0]["requestStateId"])
            restarted = build_runtime(self.config())
            async with Client(restarted.server) as client:
                resumed = await client.session.call_tool(
                    "actions.run_active",
                    payload,
                    request_state=first.request_state,
                    allow_input_required=True,
                )
                self.assertFalse(resumed.is_error)
                self.assertEqual(resumed.structured_content["outcomeKind"], "success")
                self.assertIsNone(
                    resumed.structured_content["result"]["test"]["response"]["status"]
                )
                with self.assertRaises(MCPError):
                    await client.session.call_tool(
                        "actions.run_active",
                        payload,
                        request_state=first.request_state,
                        allow_input_required=True,
                    )
            snapshot = WorkspaceAuthorityRepository(workspace_id).snapshot()
            dispatches = list(snapshot["dispatches"].values())
            self.assertEqual(len(dispatches), 1)
            self.assertEqual(dispatches[0]["state"], "succeeded")

    async def test_legacy_protocol_resumes_with_compact_operation_handle_after_restart(self) -> None:
        probe = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
        thread = threading.Thread(target=probe.serve_forever, daemon=True)
        thread.start()
        ProbeHandler.requests = 0
        try:
            workspace.create_workspace("legacy-resume", hosts=["127.0.0.1"])
            arguments = {
                "workspaceId": "legacy-resume",
                "url": f"http://127.0.0.1:{probe.server_port}/resume",
                "method": "GET",
                "followRedirects": False,
            }
            descriptor = REGISTRY.get(ACTIVE_ACTION_ID)
            planning = ActionRequest(
                descriptor.input_model.model_validate({**arguments, "confirm": False}),
                ExecutionContext("legacy-resume", "planning", 45.0, None),
            )
            plan = REGISTRY.resolve_execution_plan(ACTIVE_ACTION_ID, planning)
            now = datetime.now(timezone.utc)
            grant = AuthorityGrant(
                grant_id="legacy-protocol-supervised",
                workspace_id="legacy-resume",
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
                approved_by="operator:test",
            )
            operator = AuthorityOperatorService(
                "legacy-resume",
                OperatorPrincipal("operator:test", "test_fixture", True),
            )
            operator.create_grant(grant)
            self._write_bindings(selected_grant_id=grant.grant_id)
            payload = {
                "actionId": ACTIVE_ACTION_ID,
                "arguments": arguments,
                "idempotencyKey": "legacy-protocol-resume-key",
            }

            initial_runtime = build_runtime(self.config())
            with patch("mcp.client.session.LATEST_HANDSHAKE_VERSION", "2025-06-18"):
                async with Client(initial_runtime.server, mode="legacy") as client:
                    first = await client.call_tool("actions.run_active", payload)
            self.assertIsInstance(first, CallToolResult)
            self.assertTrue(first.is_error)
            first_envelope = FacadeEnvelope.model_validate(first.structured_content)
            self.assertEqual(first_envelope.outcome_kind, "approval_required")
            self.assertEqual(first_envelope.diagnostics["dispatch"], "not_started")
            self.assertTrue(first_envelope.operation_handle.startswith("operation-"))
            self.assertNotIn(grant.grant_id, first.model_dump_json(by_alias=True))
            self.assertEqual(ProbeHandler.requests, 0)

            raw_request = operator.list_required_authority()[0]["requestStateId"]
            operator.issue_request_step_up(raw_request)
            restarted = build_runtime(self.config())
            resume_payload = {
                "operation": "resume",
                "operationHandle": first_envelope.operation_handle,
            }
            with patch("mcp.client.session.LATEST_HANDSHAKE_VERSION", "2025-06-18"):
                async with Client(restarted.server, mode="legacy") as client:
                    resumed = await client.call_tool("tasks.control", resume_payload)
                    self.assertFalse(resumed.is_error)
                    resumed_envelope = FacadeEnvelope.model_validate(resumed.structured_content)
                    self.assertEqual(resumed_envelope.outcome_kind, "success")
                    self.assertEqual(resumed_envelope.trace_id, first_envelope.trace_id)
                    with self.assertRaises(MCPError):
                        await client.call_tool("tasks.control", resume_payload)
            self.assertEqual(ProbeHandler.requests, 1)
        finally:
            probe.shutdown()
            probe.server_close()
            thread.join(timeout=3)

    async def test_rotation_restart_principal_audience_tamper_retirement_and_exactly_once(self) -> None:
        probe = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
        thread = threading.Thread(target=probe.serve_forever, daemon=True)
        thread.start()
        ProbeHandler.requests = 0
        try:
            workspace.create_workspace("modern-resume", hosts=["127.0.0.1"])
            arguments = {
                "workspaceId": "modern-resume",
                "url": f"http://127.0.0.1:{probe.server_port}/resume",
                "method": "GET",
                "followRedirects": False,
            }
            descriptor = REGISTRY.get(ACTIVE_ACTION_ID)
            planning = ActionRequest(
                descriptor.input_model.model_validate({**arguments, "confirm": False}),
                ExecutionContext("modern-resume", "planning", 45.0, None),
            )
            plan = REGISTRY.resolve_execution_plan(ACTIVE_ACTION_ID, planning)
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
                approved_by="operator:test",
            )
            operator = AuthorityOperatorService(
                "modern-resume",
                OperatorPrincipal("operator:test", "test_fixture", True),
            )
            operator.create_grant(grant)
            self._write_bindings(selected_grant_id=grant.grant_id)
            payload = {
                "actionId": ACTIVE_ACTION_ID,
                "arguments": arguments,
                "idempotencyKey": "modern-resume-key",
            }
            old_runtime = build_runtime(self.config())
            async with Client(old_runtime.server) as client:
                first = await client.session.call_tool(
                    "actions.run_active",
                    payload,
                    allow_input_required=True,
                )
            self.assertIsInstance(first, InputRequiredResult)
            self.assertTrue(first.request_state.startswith("v1."))
            self.assertNotIn(grant.grant_id, first.model_dump_json(by_alias=True))
            raw_request = operator.list_required_authority()[0]["requestStateId"]
            self.assertEqual(ProbeHandler.requests, 0)

            tampered = first.request_state[:-1] + ("A" if first.request_state[-1] != "A" else "B")
            for config, request_state in (
                (self.config(principal="operator:other"), first.request_state),
                (self.config(audience="other-audience", server_name="other-server"), first.request_state),
                (self.config(), tampered),
            ):
                denied = build_runtime(config)
                async with Client(denied.server) as client:
                    with self.assertRaises(MCPError):
                        await client.session.call_tool(
                            "actions.run_active",
                            payload,
                            request_state=request_state,
                            allow_input_required=True,
                        )
            self.assertEqual(ProbeHandler.requests, 0)

            self._write_keyring("22" * 32, "11" * 32)
            operator.issue_request_step_up(raw_request)
            async def resume_once() -> CallToolResult | Exception:
                rotated = build_runtime(self.config())
                try:
                    async with Client(rotated.server) as client:
                        return await client.session.call_tool(
                            "actions.run_active",
                            payload,
                            request_state=first.request_state,
                            allow_input_required=True,
                        )
                except Exception as exc:
                    return exc

            concurrent = await asyncio.gather(resume_once(), resume_once())
            successes = [item for item in concurrent if isinstance(item, CallToolResult)]
            failures = [item for item in concurrent if isinstance(item, Exception)]
            self.assertEqual(len(successes), 1)
            self.assertEqual(len(failures), 1)
            resumed = successes[0]
            self.assertFalse(resumed.is_error)
            original_trace = first.meta["synapse/traceId"]
            self.assertEqual(resumed.structured_content["traceId"], original_trace)
            replay_failure = repr(failures[0])
            self.assertTrue(
                any(
                    reason in replay_failure
                    for reason in ("request_state_replayed", "operation_replayed")
                ),
                replay_failure,
            )
            sequential = build_runtime(self.config())
            async with Client(sequential.server) as client:
                with self.assertRaises(MCPError):
                    await client.session.call_tool(
                        "actions.run_active",
                        payload,
                        request_state=first.request_state,
                        allow_input_required=True,
                    )
            self.assertEqual(ProbeHandler.requests, 1)

            self._write_keyring("22" * 32)
            retired = build_runtime(self.config())
            async with Client(retired.server) as client:
                with self.assertRaises(MCPError):
                    await client.session.call_tool(
                        "actions.run_active",
                        payload,
                        request_state=first.request_state,
                        allow_input_required=True,
                    )
            self.assertEqual(ProbeHandler.requests, 1)
        finally:
            probe.shutdown()
            probe.server_close()
            thread.join(timeout=3)


class HTTPSecurityMiddlewareTests(ModernAdapterFixture, unittest.IsolatedAsyncioTestCase):
    async def test_authentication_duplicate_and_forwarded_header_policy(self) -> None:
        seen: list[str | None] = []

        async def downstream(scope, receive, send):
            seen.append(CURRENT_HTTP_PRINCIPAL.get())
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        config = self.config(transport="streamable-http")
        middleware = AuthenticatedHTTPMiddleware(
            downstream,
            config=config,
            tokens=TokenPrincipalResolver(self.tokens_path),
        )

        async def invoke(headers):
            messages = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                messages.append(message)

            await middleware(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/mcp",
                    "headers": [(name.encode(), value.encode()) for name, value in headers],
                    "client": ("127.0.0.1", 1234),
                },
                receive,
                send,
            )
            return messages[0]["status"]

        self.assertEqual(await invoke([]), 401)
        self.assertEqual(
            await invoke([("authorization", f"Bearer {TEST_TOKEN}"), ("authorization", f"Bearer {TEST_TOKEN}")]),
            401,
        )
        self.assertEqual(
            await invoke([("authorization", f"Bearer {TEST_TOKEN}"), ("x-forwarded-proto", "https")]),
            400,
        )
        self.assertEqual(await invoke([("authorization", f"Bearer {TEST_TOKEN}")]), 204)

        middleware = AuthenticatedHTTPMiddleware(
            downstream,
            config=self.config(
                transport="streamable-http",
                host="0.0.0.0",
                remote_enabled=True,
                allowed_hosts=("mcp.example.test",),
                allowed_origins=("https://mcp.example.test",),
                tls_termination="trusted-proxy",
                trusted_proxies=("127.0.0.1/32",),
            ),
            tokens=TokenPrincipalResolver(self.tokens_path),
        )
        self.assertEqual(
            await invoke(
                [
                    ("authorization", f"Bearer {TEST_TOKEN}"),
                    ("x-forwarded-proto", "https"),
                    ("x-forwarded-for", "192.0.2.1"),
                ]
            ),
            400,
        )
        self.assertEqual(
            await invoke(
                [
                    ("authorization", f"Bearer {TEST_TOKEN}"),
                    ("forwarded", "for=192.0.2.1;proto=https;proto=http"),
                ]
            ),
            400,
        )
        self.assertEqual(
            await invoke(
                [
                    ("authorization", f"Bearer {TEST_TOKEN}"),
                    ("forwarded", "for=192.0.2.1;proto=https"),
                ]
            ),
            204,
        )
        self.assertEqual(seen, ["operator:test", "operator:test"])


class ModernWireTransportTests(ModernAdapterFixture, unittest.IsolatedAsyncioTestCase):
    def _environment(self) -> dict[str, str]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in PROXY_ENVIRONMENT_KEYS
        }
        environment.update(
            {
                "SYNAPSE_ROOT": str(self.root),
                "SYNAPSE_DATA_DIR": str(self.data),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        return environment

    def _base_arguments(self, transport: str, *, surface: str = "modern-compact") -> list[str]:
        return [
            "-m",
            "synapse_mcp.transport.modern",
            "--surface",
            surface,
            "--transport",
            transport,
            "--server-name",
            "synapse-wire-test",
            "--audience",
            "synapse-wire-test",
            "--identity-bindings",
            str(self.bindings_path),
            "--request-state-keyring",
            str(self.keyring_path),
            "--state-dir",
            str(self.data / "wire-state"),
        ]

    async def test_production_stdio_entry_point(self) -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=[*self._base_arguments("stdio"), "--stdio-principal", "operator:test"],
            env=self._environment(),
        )
        for mode, version in protocol_client_cases():
            with patch("mcp.client.session.LATEST_HANDSHAKE_VERSION", version):
                async with Client(stdio_client(parameters), mode=mode) as client:
                    discovered = await client.list_tools()
                    self.assertEqual(client.protocol_version, version)
                    self.assertEqual(len(discovered.tools), 11)

    async def test_loopback_http_and_origin_host_header_body_consistency(self) -> None:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        process = subprocess.Popen(
            [
                sys.executable,
                *self._base_arguments("streamable-http"),
                "--http-token-map",
                str(self.tokens_path),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            env=self._environment(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        url = f"http://127.0.0.1:{port}/mcp"
        try:
            last_error: Exception | None = None
            for _ in range(100):
                try:
                    async with httpx2.AsyncClient(
                        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
                        trust_env=False,
                    ) as http:
                        async with Client(streamable_http_client(url, http_client=http)) as client:
                            discovered = await client.list_tools()
                            self.assertEqual(len(discovered.tools), 11)
                    break
                except Exception as exc:
                    last_error = exc
                    await asyncio.sleep(0.02)
            else:
                self.fail(f"production Streamable HTTP did not become ready: {last_error}")

            for mode, version in protocol_client_cases():
                with patch("mcp.client.session.LATEST_HANDSHAKE_VERSION", version):
                    async with httpx2.AsyncClient(
                        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
                        trust_env=False,
                    ) as http:
                        async with Client(streamable_http_client(url, http_client=http), mode=mode) as client:
                            discovered = await client.list_tools()
                            self.assertEqual(client.protocol_version, version)
                            self.assertEqual(len(discovered.tools), 11)

            discover_body = {
                "jsonrpc": "2.0",
                "id": "discover-test",
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "protocolVersion": MODERN_PROTOCOL_REVISION,
                        "clientCapabilities": {},
                    }
                },
            }
            base_headers = {
                "Authorization": f"Bearer {TEST_TOKEN}",
                "MCP-Protocol-Version": MODERN_PROTOCOL_REVISION,
                "Mcp-Method": "server/discover",
            }
            async with httpx2.AsyncClient(trust_env=False) as http:
                invalid_host = await http.post(
                    url,
                    headers={**base_headers, "Host": "evil.example.test"},
                    json=discover_body,
                )
                self.assertEqual(invalid_host.status_code, 421)
                invalid_origin = await http.post(
                    url,
                    headers={**base_headers, "Origin": "https://evil.example.test"},
                    json=discover_body,
                )
                self.assertEqual(invalid_origin.status_code, 403)
                mismatched_method = await http.post(
                    url,
                    headers={**base_headers, "Mcp-Method": "tools/list"},
                    json=discover_body,
                )
                self.assertEqual(mismatched_method.status_code, 400)
                mismatched_version = await http.post(
                    url,
                    headers=base_headers,
                    json={
                        **discover_body,
                        "params": {
                            "_meta": {
                                "protocolVersion": "2025-11-25",
                                "clientCapabilities": {},
                            }
                        },
                    },
                )
                self.assertEqual(mismatched_version.status_code, 400)
        finally:
            process.terminate()
            process.wait(timeout=10)

    async def test_production_direct_surface_over_stdio_and_http(self) -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=[
                *self._base_arguments("stdio", surface="modern-direct"),
                "--stdio-principal",
                "operator:test",
            ],
            env=self._environment(),
        )
        async with Client(stdio_client(parameters)) as client:
            self.assertEqual(len((await client.list_tools()).tools), 174)

        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        process = subprocess.Popen(
            [
                sys.executable,
                *self._base_arguments("streamable-http", surface="modern-direct"),
                "--http-token-map",
                str(self.tokens_path),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            env=self._environment(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            url = f"http://127.0.0.1:{port}/mcp"
            last_error: Exception | None = None
            for _ in range(100):
                try:
                    async with httpx2.AsyncClient(
                        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
                        trust_env=False,
                    ) as http:
                        async with Client(streamable_http_client(url, http_client=http)) as client:
                            self.assertEqual(len((await client.list_tools()).tools), 174)
                    break
                except Exception as exc:
                    last_error = exc
                    await asyncio.sleep(0.02)
            else:
                self.fail(f"production direct HTTP did not become ready: {last_error}")
        finally:
            process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
