"""Phase 5B gates for pack-aware discovery and selected startup surfaces."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from synapse_mcp.app.actions import (
    ActionRequest,
    CAPABILITY_PACKS,
    ExecutionContext,
    REGISTRY,
)
from synapse_mcp.app.actions.inventory import action_inventory
from synapse_mcp.app.capability_packs import (
    CapabilityPackValidationError,
    assemble_capability_packs,
)
from synapse_mcp.app.facade import (
    ActionCatalogService,
    CompactFacadeService,
    CompactProjection,
    DirectProjection,
    FacadeCallContext,
)
from synapse_mcp.app.facade.contracts import CapabilitiesSearchInput
from synapse_mcp.transport import stdio_server


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = REPOSITORY_ROOT / "MCPS" / "Synapse-MCP"
LEGACY_TOOLS_FIXTURE = (
    PACKAGE_ROOT / "tests" / "fixtures" / "legacy_contracts" / "tools_list.json"
)


def _all_catalog_items(service: ActionCatalogService):
    items = []
    cursor = None
    while True:
        page = service.search(CapabilitiesSearchInput(limit=100, cursor=cursor))
        items.extend(page.items)
        cursor = page.next_cursor
        if cursor is None:
            return items


class Phase5BCapabilityMigrationTests(unittest.TestCase):
    def test_public_pack_api_is_importable_before_the_action_package(self) -> None:
        script = (
            "from synapse_mcp.app.capability_packs import assemble_capability_packs;"
            "value=assemble_capability_packs(('core',),discover_external=False);"
            "print(len(value.registry.descriptors()))"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(PACKAGE_ROOT)
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=REPOSITORY_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "42")

    def test_explicit_empty_selection_is_rejected_instead_of_becoming_standard(self) -> None:
        with self.assertRaisesRegex(CapabilityPackValidationError, "non-empty"):
            assemble_capability_packs((), discover_external=False)

    def test_default_profiles_preserve_frozen_legacy_and_direct_contracts(self) -> None:
        expected_ids = tuple(str(item["actionId"]) for item in action_inventory())
        expected_legacy = json.loads(LEGACY_TOOLS_FIXTURE.read_text(encoding="utf-8"))[
            "result"
        ]["tools"]

        self.assertEqual(stdio_server.TOOL_SCHEMAS, expected_legacy)
        self.assertEqual(len(expected_legacy), 174)
        self.assertEqual(
            tuple(operation.name for operation in DirectProjection().operations()),
            expected_ids,
        )
        self.assertEqual(len(CompactProjection().operations()), 11)
        self.assertEqual(
            tuple(str(item.id) for item in CAPABILITY_PACKS.manifests),
            ("core", "web", "infra", "reporting", "purple", "intelligence"),
        )

    def test_pack_aware_search_filters_canonical_operational_properties(self) -> None:
        catalog = ActionCatalogService()
        cases = (
            (
                {"capabilityPack": "web"},
                lambda item: item.capability_pack == "web",
            ),
            ({"pack": "cors"}, lambda item: item.pack == "cors"),
            ({"effect": "credential_use"}, lambda item: item.credential_use),
            ({"availability": "available"}, lambda item: item.availability == "available"),
            (
                {"availability": "runtime_resolved"},
                lambda item: item.availability == "runtime_resolved",
            ),
            ({"targetType": "url"}, lambda item: "url" in item.target_types),
            (
                {"taskSuitability": "background"},
                lambda item: "background" in item.task_suitability,
            ),
            (
                {"taskSuitability": "passive"},
                lambda item: "passive" in item.task_suitability,
            ),
            ({"risk": "high"}, lambda item: item.risk == "high"),
            (
                {"credentialNeed": "required"},
                lambda item: item.credential_need == "required",
            ),
        )
        for values, predicate in cases:
            with self.subTest(values=values):
                first = catalog.search(
                    CapabilitiesSearchInput.model_validate({**values, "limit": 100})
                )
                second = catalog.search(
                    CapabilitiesSearchInput.model_validate({**values, "limit": 100})
                )
                self.assertTrue(first.items)
                self.assertEqual(first, second)
                self.assertTrue(all(predicate(item) for item in first.items))

        described = catalog.describe("cors.execute_test")
        self.assertEqual(described.pack, "cors")
        self.assertEqual(described.capability_pack, "web")
        web = catalog.search(
            CapabilitiesSearchInput(capability_pack="web", limit=100)
        )
        self.assertTrue(
            all(
                item.methodology_resources == ["synapse://capability-packs/web"]
                for item in web.items
            )
        )

    def test_standard_isolated_assembly_preserves_every_contract_effect_and_outcome(self) -> None:
        assembled = assemble_capability_packs(discover_external=False)
        for expected in REGISTRY.descriptors():
            action_id = str(expected.id)
            with self.subTest(action=action_id):
                observed = assembled.registry.get(action_id)
                self.assertEqual(observed.id, expected.id)
                self.assertEqual(observed.pack, expected.pack)
                self.assertEqual(observed.title, expected.title)
                self.assertEqual(observed.summary, expected.summary)
                self.assertEqual(observed.risk_class, expected.risk_class)
                self.assertEqual(observed.scope_policy, expected.scope_policy)
                self.assertEqual(observed.credential_policy, expected.credential_policy)
                self.assertEqual(observed.task_policy, expected.task_policy)
                self.assertEqual(observed.legacy_aliases, expected.legacy_aliases)
                self.assertEqual(observed.legacy_serializer, expected.legacy_serializer)
                self.assertEqual(observed.implementation_ref, expected.implementation_ref)
                self.assertEqual(observed.approval_required, expected.approval_required)
                self.assertEqual(observed.idempotency_policy, expected.idempotency_policy)
                self.assertEqual(
                    assembled.registry.contract_schema(action_id),
                    REGISTRY.contract_schema(action_id),
                )
                self.assertEqual(observed.effects, expected.effects)

        action_id = "documentation.list_templates"
        expected_descriptor = REGISTRY.get(action_id)
        observed_descriptor = assembled.registry.get(action_id)
        context = ExecutionContext(None, "phase5b-equivalence", 45.0, None)
        expected_outcome = REGISTRY.execute(
            action_id,
            ActionRequest(expected_descriptor.input_model.model_validate({}), context),
        )
        observed_outcome = assembled.registry.execute(
            action_id,
            ActionRequest(observed_descriptor.input_model.model_validate({}), context),
        )
        self.assertEqual(observed_outcome.kind, expected_outcome.kind)
        self.assertEqual(observed_outcome.payload_signals_error, expected_outcome.payload_signals_error)
        self.assertEqual(
            observed_outcome.payload.model_dump(mode="json", by_alias=True),
            expected_outcome.payload.model_dump(mode="json", by_alias=True),
        )

    def test_core_only_catalog_and_surfaces_reject_unselected_actions(self) -> None:
        assembled = assemble_capability_packs(("core",), discover_external=False)
        catalog = ActionCatalogService(assembled.registry, assembled)
        items = _all_catalog_items(catalog)
        self.assertEqual(len(items), 42)
        self.assertTrue(all(item.capability_pack == "core" for item in items))
        self.assertEqual(len(DirectProjection(registry=assembled.registry).operations()), 42)
        self.assertEqual(
            len(
                CompactProjection(
                    registry=assembled.registry,
                    capability_packs=assembled,
                ).operations()
            ),
            11,
        )
        with self.assertRaises(LookupError):
            catalog.describe("cors.execute_test")

        service = CompactFacadeService(
            registry=assembled.registry,
            capability_packs=assembled,
        )
        context = FacadeCallContext(principal_id="operator:test", execution_profile="legacy")
        described = service.invoke(
            "actions.describe",
            {"actionId": "cors.execute_test"},
            context=context,
        )
        executed = service.invoke(
            "actions.run_active",
            {"actionId": "cors.execute_test", "arguments": {}},
            context=context,
        )
        self.assertEqual(described.outcome_kind, "validation_failure")
        self.assertEqual(executed.outcome_kind, "validation_failure")
        self.assertEqual(described.diagnostics["reasonCode"], "action_id_invalid")
        self.assertEqual(executed.diagnostics["reasonCode"], "action_id_invalid")

    def test_real_core_only_modern_startup_imports_no_unselected_implementation(self) -> None:
        script = r'''
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from synapse_mcp.app.capability_packs.bootstrap import select_startup_capability_packs
select_startup_capability_packs(("core",))

from synapse_mcp.app.facade.projections import SurfaceMode
from synapse_mcp.app.facade.contracts import FacadeCallContext
from synapse_mcp.core import paths
from synapse_mcp.transport.modern.config import ModernAdapterConfig
from synapse_mcp.transport.modern.server import build_runtime

with TemporaryDirectory() as temporary:
    root = Path(temporary)
    data = root / "data"
    data.mkdir()
    bindings = root / "bindings.json"
    bindings.write_text(json.dumps({
        "version": 1,
        "principals": {
            "operator:test": {
                "defaultWorkspace": "",
                "default": {"executionProfile": "observe", "authoritySessionId": "session-test"},
                "workspaces": {"*": {"executionProfile": "observe", "authoritySessionId": "session-test"}},
            }
        },
    }), encoding="utf-8")
    bindings.chmod(0o600)
    with patch.object(paths, "DATA_DIR", data):
        runtime = build_runtime(ModernAdapterConfig(
            surface=SurfaceMode.MODERN_DIRECT,
            transport="stdio",
            server_name="phase5b-core",
            audience="phase5b-core",
            capability_packs=("core",),
            identity_bindings_path=bindings,
            stdio_principal="operator:test",
            allow_ephemeral_request_state=True,
            state_dir=data / "adapter-state",
        ))
        outcome = runtime.execution.run(
            operation="adapters.list",
            action_id="adapters.list",
            arguments={},
            context=FacadeCallContext(
                principal_id="operator:test",
                execution_profile="legacy",
            ),
            passive_only=False,
        )

blocked_prefixes = (
    "synapse_mcp.adapters.web",
    "synapse_mcp.adapters.infra",
    "synapse_mcp.adapters.social",
    "synapse_mcp.core.documentation",
    "synapse_mcp.core.fingerprint",
    "synapse_mcp.core.perimeter",
    "synapse_mcp.transport.stdio_server",
)
print(json.dumps({
    "packs": [str(item.id) for item in runtime.capability_packs.manifests],
    "actions": [item.name for item in runtime.projection.operations()],
    "outcome": outcome.outcome_kind,
    "blocked": sorted(name for name in sys.modules if name.startswith(blocked_prefixes)),
}))
'''
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(PACKAGE_ROOT)
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=REPOSITORY_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        observed = json.loads(completed.stdout)
        self.assertEqual(observed["packs"], ["core"])
        self.assertEqual(len(observed["actions"]), 42)
        self.assertEqual(observed["outcome"], "success")
        self.assertEqual(observed["blocked"], [])

    def test_startup_selection_is_one_shot_and_deterministic_in_fresh_processes(self) -> None:
        script = r'''
import json
from synapse_mcp.app.capability_packs.bootstrap import select_startup_capability_packs
select_startup_capability_packs(("core",))
from synapse_mcp.app.actions import CAPABILITY_PACKS, REGISTRY
error = ""
try:
    select_startup_capability_packs(("web",))
except Exception as exc:
    error = f"{type(exc).__name__}:{exc}"
print(json.dumps({
    "packs": [str(item.id) for item in CAPABILITY_PACKS.manifests],
    "actions": [str(item.id) for item in REGISTRY.descriptors()],
    "error": error,
}, separators=(",", ":")))
'''
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(PACKAGE_ROOT)
        outputs = []
        for _ in range(3):
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=REPOSITORY_ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            outputs.append(completed.stdout.strip())
        self.assertEqual(len(set(outputs)), 1)
        observed = json.loads(outputs[0])
        self.assertEqual(observed["packs"], ["core"])
        self.assertEqual(len(observed["actions"]), 42)
        self.assertIn("already sealed", observed["error"])


if __name__ == "__main__":
    unittest.main()
