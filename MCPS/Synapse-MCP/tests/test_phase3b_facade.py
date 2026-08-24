"""Phase 3B gates for compact/direct protocol-independent application services."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from synapse_mcp.app.actions import (
    ActionEffects,
    ActionRequest,
    ActionRegistry,
    ExecutionContext,
    LocalWriteDomain,
    PassThroughPolicyEvaluator,
    REGISTRY,
    RiskClass,
    Success,
    TrafficDestination,
)
from synapse_mcp.app.facade import (
    ActionCatalogService,
    ActionExecutionService,
    CompactFacadeService,
    CompactProjection,
    DirectProjection,
    FacadeCallContext,
    ResourceAccessError,
    ResourceReferenceService,
    SurfaceMode,
    build_application_projection,
    passive_gate_reasons,
)
from synapse_mcp.app.facade.contracts import CapabilitiesSearchInput
from synapse_mcp.app.facade.catalog import model_facing_action_input_schema
from synapse_mcp.core import scope, workspace
from synapse_mcp.core.execution import ExecutionPlan
from synapse_mcp.policy import (
    AuthorityGrant,
    AuthorityMode,
    AuthorityOperatorService,
    BudgetLimits,
    OperatorPrincipal,
    StateChangePolicy,
)
from synapse_mcp.transport import stdio_server  # Binds the frozen retained implementation adapter.

from helpers import isolated_state


PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "synapse_mcp"
COMPACT_NAMES = (
    "engagement.open",
    "engagement.inspect",
    "context.query",
    "capabilities.search",
    "actions.describe",
    "actions.run_passive",
    "actions.run_active",
    "reviews.apply",
    "artifacts.inspect",
    "reports.render",
    "tasks.control",
)


class ResumeHandler(BaseHTTPRequestHandler):
    requests = 0

    def do_GET(self) -> None:
        type(self).requests += 1
        body = b"facade-resume-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def _call_context(
    *,
    workspace_id: str = "facade",
    profile: str = "legacy",
    session: str = "",
    grant_id: str = "",
    correlation: str = "phase3b-test",
    principal: str = "operator:test",
) -> FacadeCallContext:
    return FacadeCallContext(
        principal_id=principal,
        workspace_id=workspace_id,
        execution_profile=profile,
        authority_session_id=session,
        selected_grant_id=grant_id,
        correlation_id=correlation,
    )


class Phase3BProjectionTests(unittest.TestCase):
    def test_compact_surface_is_exact_ordered_and_under_phase_wide_budget(self) -> None:
        first = CompactProjection().operations()
        second = CompactProjection().operations()
        self.assertEqual(tuple(item.name for item in first), COMPACT_NAMES)
        self.assertEqual(first, second)
        compact = json.dumps(
            [item.model_dump(mode="json", by_alias=True) for item in first],
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertLessEqual(len(compact), 24_834)

    def test_surface_mode_is_explicit_operator_configuration(self) -> None:
        self.assertIsNone(build_application_projection(SurfaceMode.LEGACY))
        self.assertIsInstance(build_application_projection("modern-compact"), CompactProjection)
        self.assertIsInstance(build_application_projection("modern-direct"), DirectProjection)
        with self.assertRaises(ValueError):
            build_application_projection("client-selected")

    def test_direct_surface_has_all_174_canonical_actions_in_registry_order(self) -> None:
        operations = DirectProjection().operations()
        self.assertEqual(len(operations), 174)
        self.assertEqual(
            tuple(item.name for item in operations),
            tuple(str(descriptor.id) for descriptor in REGISTRY.descriptors()),
        )

    def test_direct_catalog_and_descriptor_schemas_are_equivalent(self) -> None:
        direct = {item.name: item for item in DirectProjection().operations()}
        catalog = ActionCatalogService()
        for descriptor in REGISTRY.descriptors():
            action_id = str(descriptor.id)
            with self.subTest(action=action_id):
                described = catalog.describe(action_id)
                projected = direct[action_id]
                self.assertEqual(projected.input_schema, described.input_schema)
                self.assertEqual(projected.action_output_schema, described.output_schema)
                self.assertEqual(projected.annotations, described.annotations)

    def test_application_facade_has_no_mcp_or_transport_imports(self) -> None:
        failures = []
        for path in sorted((PACKAGE_ROOT / "app" / "facade").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [item.name for item in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                else:
                    continue
                for name in names:
                    if name == "mcp" or name.startswith("mcp.") or name.startswith("synapse_mcp.transport"):
                        failures.append(f"{path.name}:{node.lineno}:{name}")
        self.assertEqual(failures, [])


class Phase3BCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = ActionCatalogService()

    def test_catalog_paginates_all_actions_without_duplicates(self) -> None:
        cursor = None
        action_ids = []
        while True:
            page = self.catalog.search(CapabilitiesSearchInput(limit=17, cursor=cursor))
            action_ids.extend(item.action_id for item in page.items)
            cursor = page.next_cursor
            if cursor is None:
                break
        self.assertEqual(action_ids, [str(item.id) for item in REGISTRY.descriptors()])
        self.assertEqual(len(set(action_ids)), 174)

    def test_catalog_filters_every_reviewed_dimension(self) -> None:
        cases = (
            (
                {"query": "workspace summary"},
                lambda item: all(
                    term in f"{item.action_id} {item.title} {item.description}".lower()
                    for term in ("workspace", "summary")
                ),
            ),
            ({"pack": "cors"}, lambda item: item.pack == "cors"),
            ({"intent": "reporting"}, lambda item: item.intent == "reporting"),
            ({"effect": "traffic"}, lambda item: bool(item.effects.traffic)),
            ({"risk": "high"}, lambda item: item.risk == "high"),
            ({"availability": "runtime_resolved"}, lambda item: item.availability == "runtime_resolved"),
            ({"credentialNeed": "required"}, lambda item: item.credential_need == "required"),
            ({"scope": "required"}, lambda item: item.scope == "required"),
        )
        for values, predicate in cases:
            with self.subTest(values=values):
                page = self.catalog.search(CapabilitiesSearchInput.model_validate({**values, "limit": 100}))
                self.assertTrue(page.items)
                self.assertTrue(all(predicate(item) for item in page.items))

    def test_catalog_cursor_is_query_bound_and_limits_are_enforced(self) -> None:
        first = self.catalog.search(CapabilitiesSearchInput(pack="workspace", limit=2))
        self.assertIsNotNone(first.next_cursor)
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.catalog.search(
                CapabilitiesSearchInput(pack="cors", limit=2, cursor=first.next_cursor)
            )
        with self.assertRaises(Exception):
            CapabilitiesSearchInput(limit=101)

    def test_describe_exposes_public_input_and_exact_output_schemas_for_every_action(self) -> None:
        for descriptor in REGISTRY.descriptors():
            action_id = str(descriptor.id)
            with self.subTest(action=action_id):
                described = self.catalog.describe(action_id)
                schemas = REGISTRY.contract_schema(action_id)
                self.assertEqual(
                    described.input_schema,
                    model_facing_action_input_schema(schemas["inputSchema"]),
                )
                self.assertNotIn("confirm", described.input_schema.get("properties", {}))
                self.assertNotIn("allowExternalOutput", described.input_schema.get("properties", {}))
                self.assertEqual(described.output_schema, schemas["outputSchema"])
                self.assertFalse(described.approval["callerAuthorityFieldsAccepted"])
                self.assertTrue(described.examples)


class Phase3BExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.state = isolated_state(Path(self.tmp.name))
        self.state.__enter__()
        workspace.create_workspace("facade", hosts=["example.test"])
        self.service = CompactFacadeService()
        self.context = _call_context()

    def tearDown(self) -> None:
        self.state.__exit__(None, None, None)
        self.tmp.cleanup()

    def test_compact_mapped_services_call_real_canonical_actions(self) -> None:
        opened = self.service.invoke(
            "engagement.open",
            {"organization": "facade-open", "hosts": ["example.test"], "workspaceId": "facade-open"},
            context=_call_context(workspace_id=""),
        )
        self.assertEqual(opened.outcome_kind, "success")
        inspected = self.service.invoke(
            "engagement.inspect",
            {"workspaceId": "facade-open"},
            context=_call_context(workspace_id="facade-open"),
        )
        self.assertEqual(inspected.outcome_kind, "success")
        self.assertEqual(inspected.action_id, "workspace.summary")

    def test_malformed_ids_nested_arguments_and_outputs_are_typed(self) -> None:
        malformed = self.service.invoke(
            "actions.run_active",
            {"actionId": "not-an-action", "arguments": {}},
            context=self.context,
        )
        self.assertEqual(malformed.outcome_kind, "validation_failure")
        nested = self.service.invoke(
            "actions.run_active",
            {
                "actionId": "workspace.create",
                "arguments": {"workspaceId": "facade", "hosts": [1]},
            },
            context=self.context,
        )
        self.assertEqual(nested.outcome_kind, "validation_failure")
        self.assertEqual(nested.diagnostics["reasonCode"], "invalid_action_arguments")

        descriptor = REGISTRY.get("workspace.summary")

        class InvalidOutputExecutor:
            input_model = descriptor.input_model
            output_model = descriptor.output_model

            def __call__(self, request):
                return Success(payload={"workspace": {"workspaceId": "facade"}})

        registry = ActionRegistry(PassThroughPolicyEvaluator())
        registry.register(replace(descriptor, executor=InvalidOutputExecutor()))
        invalid_output = ActionExecutionService(registry=registry).run(
            operation="workspace.summary",
            action_id="workspace.summary",
            arguments={"workspaceId": "facade"},
            context=self.context,
            passive_only=False,
        )
        self.assertEqual(invalid_output.outcome_kind, "execution_failure")
        self.assertEqual(invalid_output.diagnostics["reasonCode"], "invalid_output_contract")

    def test_passive_gate_rejects_every_forbidden_dimension_and_combinations(self) -> None:
        cases = (
            (ActionEffects(traffic=frozenset({TrafficDestination.THIRD_PARTY})), ("traffic",)),
            (ActionEffects(credential_use=True), ("credential_use",)),
            (ActionEffects(secret_use=True), ("secret_use",)),
            (ActionEffects(remote_state_change=True), ("remote_state_change",)),
            (ActionEffects(local_destruction=True), ("local_destruction",)),
            (
                ActionEffects(
                    traffic=frozenset({TrafficDestination.AUTHORIZED_TARGET}),
                    credential_use=True,
                    secret_use=True,
                    remote_state_change=True,
                    local_destruction=True,
                ),
                ("traffic", "credential_use", "secret_use", "remote_state_change", "local_destruction"),
            ),
        )
        for effects, expected in cases:
            with self.subTest(effects=effects):
                self.assertEqual(passive_gate_reasons(effects), expected)
        allowed = ActionEffects(
            local_writes=frozenset({LocalWriteDomain.WORKSPACE, LocalWriteDomain.EVIDENCE}),
            local_change=True,
        )
        self.assertEqual(passive_gate_reasons(allowed), ())

    def test_passive_rejection_occurs_before_registry_dispatch(self) -> None:
        with patch.object(REGISTRY, "execute") as dispatch:
            denied = self.service.invoke(
                "actions.run_passive",
                {"actionId": "cors.execute_test", "arguments": {"url": "https://example.test"}},
                context=self.context,
            )
        self.assertEqual(denied.outcome_kind, "policy_denial")
        self.assertEqual(denied.diagnostics["reasonCode"], "passive_gate_effect_denied")
        dispatch.assert_not_called()

    def test_active_dispatch_preserves_authority_and_workspace_policy(self) -> None:
        authority_context = _call_context(
            profile="full_delegated",
            session="facade-session",
            grant_id="",
        )
        uncovered = self.service.invoke(
            "actions.run_active",
            {
                "actionId": "cors.execute_test",
                "arguments": {
                    "workspaceId": "facade",
                    "url": "https://example.test/api",
                    "followRedirects": False,
                },
                "idempotencyKey": "uncovered-1",
            },
            context=authority_context,
        )
        self.assertEqual(uncovered.outcome_kind, "approval_required")
        self.assertIsNotNone(uncovered.operation_handle)

        crossed = self.service.invoke(
            "actions.run_active",
            {"actionId": "workspace.summary", "arguments": {"workspaceId": "different"}},
            context=authority_context,
        )
        self.assertEqual(crossed.outcome_kind, "policy_denial")
        self.assertEqual(crossed.diagnostics["reasonCode"], "facade_workspace_mismatch")

        out_of_scope = self.service.invoke(
            "actions.run_active",
            {
                "actionId": "cors.execute_test",
                "arguments": {"workspaceId": "facade", "url": "https://outside.test/api"},
            },
            context=authority_context,
        )
        self.assertEqual(out_of_scope.outcome_kind, "policy_denial")
        self.assertEqual(out_of_scope.diagnostics["reasonCode"], "target_out_of_scope")

        missing_credential = self.service.invoke(
            "actions.run_active",
            {
                "actionId": "crawler.extended",
                "arguments": {"workspaceId": "facade", "target": "https://example.test"},
            },
            context=authority_context,
        )
        self.assertEqual(missing_credential.outcome_kind, "validation_failure")
        self.assertEqual(missing_credential.diagnostics["reasonCode"], "invalid_action_arguments")
        self.assertTrue(
            any(
                error["location"] == "credentialId"
                for error in missing_credential.diagnostics["errors"]
            )
        )

    def test_control_plane_authority_is_top_level_and_nested_security_data_is_preserved(self) -> None:
        denied = self.service.invoke(
            "actions.run_active",
            {
                "actionId": "workspace.summary",
                "arguments": {"workspaceId": "facade"},
                "grantId": "fabricated",
            },
            context=self.context,
        )
        self.assertEqual(denied.outcome_kind, "validation_failure")

        nested_metadata = {
            "profile": "nginx",
            "principal": "target-user",
            "grant": "oauth-authorization-grant",
            "authorization": "Bearer redacted-fixture",
        }
        observed_requests = []

        def observe_dispatch(_action_id, request):
            observed_requests.append(request)
            return Success(payload={"accepted": True})

        with patch.object(REGISTRY, "execute", side_effect=observe_dispatch):
            accepted = self.service.invoke(
                "actions.run_active",
                {
                    "actionId": "workspace.ingest_data",
                    "arguments": {
                        "workspaceId": "facade",
                        "target": "example.test",
                        "source": "operator_note",
                        "dataType": "note",
                        "format": "json",
                        "rawData": "{}",
                        "metadata": nested_metadata,
                    },
                },
                context=self.context,
            )
        self.assertEqual(accepted.outcome_kind, "success")
        self.assertEqual(len(observed_requests), 1)
        request = observed_requests[0]
        self.assertEqual(request.input.metadata.model_dump(), nested_metadata)
        self.assertEqual(request.context.execution_profile, self.context.execution_profile)
        self.assertEqual(request.context.authority_session_id, self.context.authority_session_id)
        self.assertEqual(request.context.selected_grant_id, self.context.selected_grant_id)
        self.assertEqual(self.context.principal_id, "operator:test")

        confirmation = self.service.invoke(
            "actions.run_active",
            {
                "actionId": "cors.execute_test",
                "arguments": {"url": "https://example.test", "confirm": True},
            },
            context=self.context,
        )
        self.assertEqual(confirmation.diagnostics["reasonCode"], "legacy_confirmation_forbidden")

    def test_opaque_dump_reference_is_reauthorized_as_server_internal_input(self) -> None:
        dump = workspace.target_path("facade", "example.test") / "evidence" / "burp-dumps" / "fixture"
        dump.mkdir(parents=True)
        (dump / "history.jsonl").write_text("", encoding="utf-8")
        reference = self.service.resources.issue(
            dump,
            workspace_id="facade",
            context=self.context,
            artifact_type="burp_dump",
        )
        result = self.service.invoke(
            "actions.run_active",
            {
                "actionId": "sitemap.from_dump",
                "arguments": {
                    "dumpPath": {"resourceRef": reference.reference},
                    "workspaceId": "facade",
                },
            },
            context=self.context,
        )
        self.assertEqual(result.outcome_kind, "success")
        self.assertNotIn(str(dump), result.model_dump_json(by_alias=True))

        crossed = self.service.invoke(
            "actions.run_active",
            {
                "actionId": "sitemap.from_dump",
                "arguments": {"dumpPath": {"resourceRef": reference.reference}},
            },
            context=_call_context(workspace_id="facade", principal="other"),
        )
        self.assertEqual(crossed.outcome_kind, "policy_denial")
        self.assertEqual(crossed.diagnostics["reasonCode"], "resource_principal_mismatch")

    def test_passive_external_output_boolean_cannot_authorize_arbitrary_overwrite(self) -> None:
        outside = Path(self.tmp.name).parent / "phase3r-external-output.txt"
        outside.write_text("operator-owned", encoding="utf-8")
        self.addCleanup(outside.unlink, missing_ok=True)
        with patch.object(REGISTRY, "execute") as dispatch:
            denied = self.service.invoke(
                "actions.run_passive",
                {
                    "actionId": "sitemap.from_dump",
                    "arguments": {
                        "dumpPath": str(Path(self.tmp.name) / "dump"),
                        "output": str(outside),
                        "allowExternalOutput": True,
                    },
                },
                context=self.context,
            )
        self.assertEqual(denied.outcome_kind, "validation_failure")
        self.assertEqual(denied.diagnostics["reasonCode"], "external_output_authority_forbidden")
        self.assertEqual(outside.read_text(encoding="utf-8"), "operator-owned")
        dispatch.assert_not_called()

    def test_typed_unavailability_and_compact_input_errors(self) -> None:
        context = _call_context(profile="observe", session="facade-session")
        with patch("synapse_mcp.app.actions.catalog.shutil.which", return_value=None):
            unavailable = self.service.invoke(
                "actions.run_active",
                {
                    "actionId": "ffuf.run_profile",
                    "arguments": {"target": "https://example.test", "wordlist": "/tmp/list"},
                },
                context=context,
            )
        self.assertEqual(unavailable.outcome_kind, "unavailable_capability")
        self.assertEqual(unavailable.diagnostics["reasonCode"], "missing_optional_binary")
        unknown_field = self.service.invoke(
            "actions.describe",
            {"actionId": "workspace.summary", "grantId": "fabricated"},
            context=self.context,
        )
        self.assertEqual(unknown_field.outcome_kind, "validation_failure")


class Phase3BResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name) / "allowed"
        self.root.mkdir()
        self.path = self.root / "report.md"
        self.path.write_text("version one", encoding="utf-8")
        self.resources = ResourceReferenceService(allowed_roots=(self.root,))
        self.context = _call_context(
            workspace_id="resource-workspace",
            profile="observe",
            session="resource-session",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_resource_reference_is_opaque_bound_and_reauthorized(self) -> None:
        reference = self.resources.issue(
            self.path,
            workspace_id="resource-workspace",
            context=self.context,
            artifact_type="report",
        )
        serialized = reference.model_dump_json(by_alias=True)
        self.assertNotIn(str(self.path), serialized)
        resolved = self.resources.resolve(reference.reference, context=self.context)
        self.assertEqual(resolved.content, "version one")
        mismatches = (
            (_call_context(workspace_id="resource-workspace", profile="observe", session="resource-session", principal="other"), "resource_principal_mismatch"),
            (_call_context(workspace_id="resource-workspace", profile="observe", session="other-session"), "resource_authority_mismatch"),
            (_call_context(workspace_id="other", profile="observe", session="resource-session"), "resource_workspace_mismatch"),
        )
        for context, reason in mismatches:
            with self.subTest(reason=reason), self.assertRaises(ResourceAccessError) as raised:
                self.resources.resolve(reference.reference, context=context)
            self.assertEqual(raised.exception.reason_code, reason)

    def test_resource_traversal_tampering_and_stale_versions_fail_closed(self) -> None:
        outside = Path(self.tmp.name) / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        with self.assertRaises(ResourceAccessError) as traversal:
            self.resources.issue(
                outside,
                workspace_id="resource-workspace",
                context=self.context,
                artifact_type="evidence",
            )
        self.assertEqual(traversal.exception.reason_code, "resource_outside_allowed_roots")
        with self.assertRaises(ResourceAccessError) as tampered:
            self.resources.resolve("resource-tampered", context=self.context)
        self.assertEqual(tampered.exception.reason_code, "resource_reference_invalid")
        reference = self.resources.issue(
            self.path,
            workspace_id="resource-workspace",
            context=self.context,
            artifact_type="report",
        )
        self.path.write_text("version two", encoding="utf-8")
        with self.assertRaises(ResourceAccessError) as stale:
            self.resources.resolve(reference.reference, context=self.context)
        self.assertEqual(stale.exception.reason_code, "resource_version_stale")

    def test_model_facing_results_replace_raw_paths(self) -> None:
        sanitized, references = self.resources.sanitize_result(
            {"reportPath": str(self.path), "status": "complete"},
            workspace_id="resource-workspace",
            context=self.context,
        )
        self.assertEqual(len(references), 1)
        self.assertNotIn(str(self.path), json.dumps(sanitized))
        self.assertEqual(sanitized["reportPath"]["resourceRef"], references[0].reference)

    def test_directory_reference_is_opaque_manifested_and_stale_checked(self) -> None:
        dump = self.root / "burp-dumps" / "fixture"
        dump.mkdir(parents=True)
        history = dump / "history.jsonl"
        history.write_text("", encoding="utf-8")
        sanitized, references = self.resources.sanitize_result(
            {"path": str(dump), "historyJsonl": str(history)},
            workspace_id="resource-workspace",
            context=self.context,
        )
        self.assertEqual(len(references), 2)
        self.assertNotIn(str(dump), json.dumps(sanitized))
        directory_ref = sanitized["path"]["resourceRef"]
        resolved = self.resources.resolve(directory_ref, context=self.context)
        self.assertEqual(json.loads(resolved.content), {
            "type": "directory",
            "files": [{"name": "history.jsonl", "bytes": 0}],
        })
        self.assertEqual(self.resources.resolve_path(directory_ref, context=self.context), dump)
        history.write_text("{}\n", encoding="utf-8")
        with self.assertRaises(ResourceAccessError) as stale:
            self.resources.resolve_path(directory_ref, context=self.context)
        self.assertEqual(stale.exception.reason_code, "resource_version_stale")

    def test_directory_references_reject_symlinks_and_bound_manifest_size(self) -> None:
        dump = self.root / "burp-dumps" / "bounded"
        dump.mkdir(parents=True)
        outside = Path(self.tmp.name) / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        (dump / "escape").symlink_to(outside)
        with self.assertRaises(ResourceAccessError) as symlinked:
            self.resources.issue(
                dump,
                workspace_id="resource-workspace",
                context=self.context,
                artifact_type="dump",
            )
        self.assertEqual(symlinked.exception.reason_code, "resource_symlink_forbidden")

        (dump / "escape").unlink()
        (dump / "empty-one").write_text("", encoding="utf-8")
        (dump / "empty-two").write_text("", encoding="utf-8")
        bounded = ResourceReferenceService(allowed_roots=(self.root,), max_read_bytes=20)
        reference = bounded.issue(
            dump,
            workspace_id="resource-workspace",
            context=self.context,
            artifact_type="dump",
        )
        with self.assertRaises(ResourceAccessError) as oversized:
            bounded.resolve(reference.reference, context=self.context)
        self.assertEqual(oversized.exception.reason_code, "resource_too_large")

    def test_directory_reference_limits_fail_before_content_hashing(self) -> None:
        cases = (
            (
                "file_count",
                {"max_directory_files": 1},
                (("one", b""), ("two", b"")),
                "resource_directory_file_count_limit",
            ),
            (
                "total_bytes",
                {"max_directory_total_bytes": 3},
                (("one", b"aa"), ("two", b"bb")),
                "resource_directory_total_bytes_limit",
            ),
            (
                "per_file_bytes",
                {"max_directory_file_bytes": 1},
                (("large", b"aa"),),
                "resource_directory_file_bytes_limit",
            ),
            (
                "path_bytes",
                {"max_directory_path_bytes": 4},
                (("long-name", b""),),
                "resource_directory_path_limit",
            ),
            (
                "depth",
                {"max_directory_depth": 1},
                (("nested/file", b""),),
                "resource_directory_depth_limit",
            ),
        )
        for name, limits, files, reason_code in cases:
            with self.subTest(name=name):
                dump = self.root / "burp-dumps" / name
                dump.mkdir(parents=True)
                for relative, content in files:
                    destination = dump / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(content)
                bounded = ResourceReferenceService(allowed_roots=(self.root,), **limits)
                with patch.object(Path, "open", side_effect=AssertionError("content hashing began")):
                    with self.assertRaises(ResourceAccessError) as rejected:
                        bounded.issue(
                            dump,
                            workspace_id="resource-workspace",
                            context=self.context,
                            artifact_type="dump",
                        )
                self.assertEqual(rejected.exception.reason_code, reason_code)


class Phase3BResumeTests(unittest.TestCase):
    def test_supervised_facade_resume_is_exactly_once(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            server = ThreadingHTTPServer(("127.0.0.1", 0), ResumeHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            ResumeHandler.requests = 0
            thread.start()
            try:
                scope.save_scope(["127.0.0.1"])
                workspace.create_workspace("facade-resume", hosts=["127.0.0.1"])
                arguments = {
                    "workspaceId": "facade-resume",
                    "url": f"http://127.0.0.1:{server.server_port}/resume",
                    "method": "GET",
                    "followRedirects": False,
                    "confirm": False,
                }
                descriptor = REGISTRY.get("cors.execute_test")
                planning_input = descriptor.input_model.model_validate(arguments)
                planning_request = ActionRequest(
                    planning_input,
                    ExecutionContext("facade-resume", "facade-resume-correlation", 45.0, None),
                )
                plan: ExecutionPlan = REGISTRY.resolve_execution_plan("cors.execute_test", planning_request)
                now = datetime.now(timezone.utc)
                grant = AuthorityGrant(
                    grant_id="facade-supervised",
                    workspace_id="facade-resume",
                    revision=1,
                    mode=AuthorityMode.SUPERVISED,
                    scope_digest=plan.intent.target_envelope.scope_digest,
                    target_envelope=plan.intent.target_envelope,
                    allowed_action_patterns=("cors.execute_test",),
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
                    "facade-resume",
                    OperatorPrincipal("operator:test", "test_fixture", True),
                )
                operator.create_grant(grant)
                context = _call_context(
                    workspace_id="facade-resume",
                    profile="supervised",
                    session="facade-session",
                    grant_id=grant.grant_id,
                    correlation="facade-resume-correlation",
                )
                facade = CompactFacadeService()
                first = facade.invoke(
                    "actions.run_active",
                    {
                        "actionId": "cors.execute_test",
                        "arguments": {key: value for key, value in arguments.items() if key != "confirm"},
                        "idempotencyKey": "facade-resume-key",
                    },
                    context=context,
                )
                self.assertEqual(first.outcome_kind, "approval_required")
                self.assertTrue(first.operation_handle.startswith("operation-"))
                self.assertNotIn(grant.grant_id, first.model_dump_json(by_alias=True))
                self.assertEqual(ResumeHandler.requests, 0)
                mismatched_contexts = (
                    (
                        _call_context(
                            workspace_id="facade-resume",
                            profile="supervised",
                            session="facade-session",
                            grant_id=grant.grant_id,
                            principal="operator:other",
                        ),
                        "operation_principal_mismatch",
                    ),
                    (
                        _call_context(
                            workspace_id="facade-resume",
                            profile="supervised",
                            session="other-session",
                            grant_id=grant.grant_id,
                        ),
                        "operation_authority_mismatch",
                    ),
                    (
                        _call_context(
                            workspace_id="other-workspace",
                            profile="supervised",
                            session="facade-session",
                            grant_id=grant.grant_id,
                        ),
                        "operation_workspace_mismatch",
                    ),
                )
                for mismatched, reason in mismatched_contexts:
                    denied_resume = facade.invoke(
                        "tasks.control",
                        {"operation": "resume", "operationHandle": first.operation_handle},
                        context=mismatched,
                    )
                    self.assertEqual(denied_resume.outcome_kind, "validation_failure")
                    self.assertEqual(denied_resume.diagnostics["reasonCode"], reason)
                self.assertEqual(ResumeHandler.requests, 0)
                pending = operator.list_required_authority()
                self.assertEqual(len(pending), 1)
                operator.issue_request_step_up(pending[0]["requestStateId"])

                resume_payload = {
                    "operation": "resume",
                    "operationHandle": first.operation_handle,
                }
                with ThreadPoolExecutor(max_workers=2) as pool:
                    resumed_attempts = list(
                        pool.map(
                            lambda _: facade.invoke(
                                "tasks.control",
                                resume_payload,
                                context=context,
                            ),
                            range(2),
                        )
                    )
                self.assertEqual(
                    sorted(item.outcome_kind for item in resumed_attempts),
                    ["success", "validation_failure"],
                )
                successful = next(
                    item for item in resumed_attempts if item.outcome_kind == "success"
                )
                self.assertEqual(successful.trace_id, first.trace_id)
                denied = next(
                    item
                    for item in resumed_attempts
                    if item.outcome_kind == "validation_failure"
                )
                self.assertIn(
                    denied.diagnostics["reasonCode"],
                    {"operation_replayed", "request_state_replayed"},
                )
                self.assertEqual(ResumeHandler.requests, 1)
                replayed = facade.invoke(
                    "tasks.control",
                    resume_payload,
                    context=context,
                )
                self.assertEqual(replayed.outcome_kind, "validation_failure")
                self.assertEqual(replayed.diagnostics["reasonCode"], "operation_replayed")
                self.assertEqual(ResumeHandler.requests, 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
