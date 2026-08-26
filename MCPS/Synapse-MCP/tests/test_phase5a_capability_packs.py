"""Phase 5A deterministic capability-pack lifecycle gates."""

from __future__ import annotations

from dataclasses import replace
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
    PolicyDenial,
    PolicyEvaluationResult,
    REGISTRY,
)
from synapse_mcp.app.actions.inventory import action_inventory
from synapse_mcp.app.capability_packs import (
    BUILTIN_PACK_ORDER,
    CapabilityPackCatalogService,
    CapabilityPackCompatibilityError,
    CapabilityPackDiscoveryError,
    CapabilityPackId,
    CapabilityPackManifest,
    CapabilityPackOrigin,
    CapabilityPackValidationError,
    assemble_capability_packs,
    builtin_action_owners,
    builtin_manifests,
    discover_external_manifests,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = REPOSITORY_ROOT / "MCPS" / "Synapse-MCP"


class _BrokenEntryPoint:
    name = "broken"
    value = "broken.package:manifest"

    @staticmethod
    def load():
        raise ImportError("fictional pack import failed")


class _DenyEvaluator:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def evaluate(self, descriptor, request, effects):
        del request, effects
        self.calls.append(str(descriptor.id))
        return PolicyEvaluationResult(
            False,
            PolicyDenial(
                message="test stopped before execution",
                reason_code="test_policy_denial",
            ),
        )


class Phase5ACapabilityPackTests(unittest.TestCase):
    def test_standard_assembly_is_frozen_complete_and_preserves_inventory_order(self) -> None:
        expected = tuple(str(item["actionId"]) for item in action_inventory())
        self.assertTrue(REGISTRY.frozen)
        self.assertEqual(tuple(str(item.id) for item in REGISTRY.descriptors()), expected)
        self.assertEqual(tuple(str(item.id) for item in CAPABILITY_PACKS.manifests), BUILTIN_PACK_ORDER)
        self.assertEqual(dict(CAPABILITY_PACKS.action_owners), builtin_action_owners())
        self.assertEqual(len(CAPABILITY_PACKS.action_owners), 174)

    def test_core_only_assembly_is_isolated_and_complete_for_its_declared_ownership(self) -> None:
        assembled = assemble_capability_packs(("core",), discover_external=False)
        expected = tuple(
            action_id
            for action_id, owner in builtin_action_owners().items()
            if owner == "core"
        )
        self.assertTrue(assembled.registry.frozen)
        self.assertEqual(tuple(str(item.id) for item in assembled.registry.descriptors()), expected)
        self.assertEqual(len(expected), 42)
        self.assertEqual(tuple(str(item.id) for item in assembled.manifests), ("core",))
        with self.assertRaises(LookupError):
            assembled.registry.get("cors.execute_test")

    def test_fresh_process_standard_assembly_is_byte_identical(self) -> None:
        script = (
            "import hashlib,json;"
            "from synapse_mcp.app.actions import CAPABILITY_PACKS;"
            "payload=json.dumps(CAPABILITY_PACKS.as_document(),sort_keys=True,separators=(',',':')).encode();"
            "print(hashlib.sha256(payload).hexdigest())"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(PACKAGE_ROOT)
        values = []
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
            values.append(completed.stdout.strip())
        self.assertEqual(len(set(values)), 1)

    def test_post_freeze_registration_and_reordering_fail(self) -> None:
        assembled = assemble_capability_packs(("core",), discover_external=False)
        descriptor = assembled.registry.get("workspace.summary")
        with self.assertRaisesRegex(ValueError, "frozen"):
            assembled.registry.register(descriptor)
        order = tuple(str(item.id) for item in assembled.registry.descriptors())
        with self.assertRaisesRegex(ValueError, "frozen"):
            assembled.registry.set_descriptor_order(order)

    def test_duplicate_pack_action_alias_and_incomplete_contributions_fail(self) -> None:
        core = builtin_manifests()[0]
        duplicate_pack = replace(core, origin=CapabilityPackOrigin.EXTERNAL)
        with self.assertRaisesRegex(CapabilityPackValidationError, "duplicate capability pack id"):
            assemble_capability_packs(
                ("core",),
                external_manifests=(duplicate_pack,),
                discover_external=False,
            )

        source = REGISTRY.get("workspace.summary")
        duplicate_action_descriptor = replace(source, legacy_aliases=())
        duplicate_action = CapabilityPackManifest(
            id=CapabilityPackId("duplicate_action"),
            title="Duplicate action",
            summary="Fictional invalid ownership contribution.",
            contract_version=1,
            origin=CapabilityPackOrigin.EXTERNAL,
            distribution_id="fictional-duplicate",
            descriptor_provider=lambda: (duplicate_action_descriptor,),
            action_ids=("workspace.summary",),
            dependencies=(CapabilityPackId("core"),),
        )
        with self.assertRaisesRegex(CapabilityPackValidationError, "owned by both"):
            assemble_capability_packs(
                ("duplicate_action",),
                external_manifests=(duplicate_action,),
                discover_external=False,
            )

        alias_descriptor = replace(
            source,
            id=source.id.parse("external.summary"),
            pack="external",
        )
        alias_manifest = replace(
            duplicate_action,
            id=CapabilityPackId("duplicate_alias"),
            descriptor_provider=lambda: (alias_descriptor,),
            action_ids=("external.summary",),
        )
        with self.assertRaisesRegex(CapabilityPackValidationError, "modern-only actions cannot"):
            assemble_capability_packs(
                ("duplicate_alias",),
                external_manifests=(alias_manifest,),
                discover_external=False,
            )

        incomplete = replace(
            core,
            descriptor_provider=lambda: core.descriptor_provider()[:-1],
        )
        with self.assertRaisesRegex(CapabilityPackValidationError, "does not match"):
            self._assemble_invalid_manifest(incomplete)

    @staticmethod
    def _assemble_invalid_manifest(manifest: CapabilityPackManifest) -> None:
        external = replace(
            manifest,
            id=CapabilityPackId("incomplete"),
            origin=CapabilityPackOrigin.EXTERNAL,
            distribution_id="fictional-incomplete",
            dependencies=(),
        )
        assemble_capability_packs(
            ("incomplete",),
            external_manifests=(external,),
            discover_external=False,
        )

    def test_incompatible_invalid_and_broken_installed_packs_fail_explicitly(self) -> None:
        core = builtin_manifests()[0]
        incompatible = replace(
            core,
            id=CapabilityPackId("future"),
            origin=CapabilityPackOrigin.EXTERNAL,
            distribution_id="fictional-future",
            application_min="9.0.0",
            application_max_exclusive="10.0.0",
            dependencies=(),
        )
        with self.assertRaises(CapabilityPackCompatibilityError):
            assemble_capability_packs(
                ("future",),
                external_manifests=(incompatible,),
                discover_external=False,
            )
        invalid_provider = replace(
            core,
            id=CapabilityPackId("invalid_provider"),
            origin=CapabilityPackOrigin.EXTERNAL,
            distribution_id="fictional-invalid",
            descriptor_provider=lambda: list(core.descriptor_provider()),
            dependencies=(),
        )
        with self.assertRaisesRegex(CapabilityPackValidationError, "must return a tuple"):
            assemble_capability_packs(
                ("invalid_provider",),
                external_manifests=(invalid_provider,),
                discover_external=False,
            )
        self.assertEqual(discover_external_manifests(entry_points=()), ())
        with self.assertRaisesRegex(CapabilityPackDiscoveryError, "broken.package:manifest"):
            discover_external_manifests(entry_points=(_BrokenEntryPoint(),))

    def test_catalog_resource_is_read_only_and_self_consistent(self) -> None:
        service = CapabilityPackCatalogService(CAPABILITY_PACKS)
        catalog = service.list()
        self.assertEqual(catalog["packCount"], 6)
        self.assertEqual(catalog["actionCount"], 174)
        media_type, rendered = service.read_resource("synapse://capability-packs/web")
        self.assertEqual(media_type, "application/json")
        web = json.loads(rendered)
        self.assertEqual(web["packId"], "web")
        self.assertEqual(web["actionCount"], 78)
        with self.assertRaises(LookupError):
            service.read_resource("synapse://capability-packs/missing")

    def test_each_selected_pack_crosses_one_shared_policy_evaluator_once(self) -> None:
        # Bind the retained implementation availability seam; denial prevents
        # every executor from running and therefore sends no traffic or writes.
        from synapse_mcp.transport import stdio_server  # noqa: F401

        evaluator = _DenyEvaluator()
        assembled = assemble_capability_packs(
            policy_evaluator=evaluator,
            discover_external=False,
        )
        samples = {
            "core": ("workspace.summary", {"workspaceId": "fixture"}),
            "web": (
                "headers_cookies.analyze_workspace",
                {"workspaceId": "fixture", "target": "example.test"},
            ),
            "infra": ("fingerprint.read_host", {"workspaceId": "fixture", "target": "example.test"}),
            "reporting": ("documentation.list_templates", {}),
            "purple": (
                "purple_team.mark_detection_outcome",
                {
                    "workspaceId": "fixture",
                    "target": "example.test",
                    "actionKey": "action-fixture",
                    "detected": False,
                },
            ),
            "intelligence": ("cve.capabilities", {}),
        }
        for pack_id, (action_id, arguments) in samples.items():
            with self.subTest(pack=pack_id, action=action_id):
                descriptor = assembled.registry.get(action_id)
                request = ActionRequest(
                    input=descriptor.input_model.model_validate(arguments),
                    context=ExecutionContext("fixture", f"phase5a-{pack_id}", 45.0, None),
                )
                outcome = assembled.registry.execute(action_id, request)
                self.assertIsInstance(outcome, PolicyDenial)
                self.assertEqual(evaluator.calls.count(action_id), 1)

    def test_checked_ownership_artifact_is_reproducible(self) -> None:
        completed = subprocess.run(
            [str(REPOSITORY_ROOT / "bin" / "generate-capability-pack-ownership"), "--check"],
            cwd=REPOSITORY_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        self.assertIn("174 actions, 6 packs", completed.stdout)


if __name__ == "__main__":
    unittest.main()
