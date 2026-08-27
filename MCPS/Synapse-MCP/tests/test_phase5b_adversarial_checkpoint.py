"""Adversarial checkpoint for the Phase 5B capability-pack boundary."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from synapse_mcp.app.actions import CAPABILITY_PACKS, REGISTRY
from synapse_mcp.app.capability_packs import (
    AssembledCapabilityPacks,
    CapabilityPackId,
    CapabilityPackManifest,
    CapabilityPackOrigin,
    CapabilityPackValidationError,
    CapabilityResource,
    assemble_capability_packs,
    builtin_action_owners,
    builtin_manifests,
)
from synapse_mcp.app.facade import ActionCatalogService
from synapse_mcp.app.facade.projections import SurfaceMode
from synapse_mcp.core import paths
from synapse_mcp.transport.modern.config import ModernAdapterConfig, ModernConfigurationError
from synapse_mcp.transport.modern.server import build_runtime


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = REPOSITORY_ROOT / "MCPS" / "Synapse-MCP"


class Phase5BAdversarialCheckpointTests(unittest.TestCase):
    def test_manifest_sequence_fields_reject_mutable_containers(self) -> None:
        core = builtin_manifests()[0]
        cases = (
            {"action_ids": list(core.action_ids)},
            {"dependencies": list(core.dependencies)},
            {"resources": list(core.resources)},
            {"availability": list(core.availability)},
        )
        for values in cases:
            with self.subTest(field=next(iter(values))):
                with self.assertRaisesRegex(ValueError, "immutable"):
                    replace(core, **values)

    def test_builtin_ownership_cannot_be_poisoned_between_assemblies(self) -> None:
        owners = builtin_action_owners()
        with self.assertRaises(TypeError):
            owners["cors.execute_test"] = "core"  # type: ignore[index]
        assembled = assemble_capability_packs(discover_external=False)
        self.assertEqual(len(assembled.registry.descriptors()), 174)
        self.assertEqual(assembled.owner_for("cors.execute_test"), "web")

    def test_caller_supplied_external_manifest_cannot_assert_builtin_origin(self) -> None:
        descriptor = REGISTRY.get("cors.execute_test")
        spoofed = CapabilityPackManifest(
            id=CapabilityPackId("spoofed"),
            title="Spoofed built-in",
            summary="Attempts to acquire built-in alias compatibility.",
            contract_version=1,
            origin=CapabilityPackOrigin.BUILTIN,
            distribution_id="fictional-external-distribution",
            descriptor_provider=lambda: (descriptor,),
            action_ids=("cors.execute_test",),
        )
        with self.assertRaisesRegex(CapabilityPackValidationError, "external origin"):
            assemble_capability_packs(
                ("spoofed",),
                external_manifests=(spoofed,),
                discover_external=False,
            )

    def test_malformed_external_contributions_fail_with_pack_errors(self) -> None:
        with self.assertRaisesRegex(CapabilityPackValidationError, "must be manifests"):
            assemble_capability_packs(
                ("core",),
                external_manifests=(object(),),  # type: ignore[arg-type]
                discover_external=False,
            )

        malformed = CapabilityPackManifest(
            id=CapabilityPackId("malformed"),
            title="Malformed provider",
            summary="Returns an object that is not an action descriptor.",
            contract_version=1,
            origin=CapabilityPackOrigin.EXTERNAL,
            distribution_id="fictional-malformed-distribution",
            descriptor_provider=lambda: (object(),),  # type: ignore[return-value]
            action_ids=("external.malformed",),
        )
        with self.assertRaisesRegex(CapabilityPackValidationError, "non-ActionDescriptor"):
            assemble_capability_packs(
                ("malformed",),
                external_manifests=(malformed,),
                discover_external=False,
            )

    def test_unselected_installed_manifest_graph_fails_closed(self) -> None:
        source = REGISTRY.get("workspace.summary")
        descriptor = replace(
            source,
            id=source.id.parse("external.summary"),
            pack="external",
            legacy_aliases=(),
        )
        missing_dependency = CapabilityPackManifest(
            id=CapabilityPackId("missing_dependency"),
            title="Missing dependency",
            summary="Declares a dependency that is not installed.",
            contract_version=1,
            origin=CapabilityPackOrigin.EXTERNAL,
            distribution_id="fictional-missing-dependency",
            descriptor_provider=lambda: (descriptor,),
            action_ids=("external.summary",),
            dependencies=(CapabilityPackId("not_installed"),),
        )
        with self.assertRaisesRegex(CapabilityPackValidationError, "requires not_installed"):
            assemble_capability_packs(
                external_manifests=(missing_dependency,),
                discover_external=False,
            )

        first = replace(
            missing_dependency,
            id=CapabilityPackId("first"),
            distribution_id="fictional-first",
            dependencies=(CapabilityPackId("second"),),
            resources=(
                CapabilityResource(
                    "synapse://fictional/shared",
                    "Shared resource",
                    "Fictional shared resource.",
                ),
            ),
        )
        second = replace(
            missing_dependency,
            id=CapabilityPackId("second"),
            distribution_id="fictional-second",
            dependencies=(CapabilityPackId("first"),),
            resources=first.resources,
        )
        with self.assertRaisesRegex(CapabilityPackValidationError, "owned by both"):
            assemble_capability_packs(
                external_manifests=(first, second),
                discover_external=False,
            )

        distinct_descriptor = replace(
            descriptor,
            id=descriptor.id.parse("external.second"),
        )
        second = replace(
            second,
            descriptor_provider=lambda: (distinct_descriptor,),
            action_ids=("external.second",),
        )
        with self.assertRaisesRegex(CapabilityPackValidationError, "contributed by both"):
            assemble_capability_packs(
                external_manifests=(first, second),
                discover_external=False,
            )

        second = replace(second, resources=())
        with self.assertRaisesRegex(CapabilityPackValidationError, "dependency cycle"):
            assemble_capability_packs(
                external_manifests=(first, second),
                discover_external=False,
            )

    def test_assembled_catalog_and_discovery_reject_registry_mix_and_match(self) -> None:
        core = assemble_capability_packs(("core",), discover_external=False)
        with self.assertRaisesRegex(CapabilityPackValidationError, "Registry order"):
            AssembledCapabilityPacks(
                registry=core.registry,
                manifests=core.manifests,
                action_owners=core.action_owners[:-1],
            )
        with self.assertRaisesRegex(ValueError, "selected capability-pack Registry"):
            ActionCatalogService(REGISTRY, core)

    def test_launcher_selection_snapshots_mutable_caller_input(self) -> None:
        script = r'''
import json
from synapse_mcp.app.capability_packs.bootstrap import select_startup_capability_packs
selected = ["core"]
select_startup_capability_packs(selected)
selected[0] = "web"
from synapse_mcp.app.actions import CAPABILITY_PACKS
print(json.dumps([str(item.id) for item in CAPABILITY_PACKS.manifests]))
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
        self.assertEqual(json.loads(completed.stdout), ["core"])

    def test_runtime_cannot_assemble_a_second_process_registry(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            data.mkdir()
            bindings = root / "bindings.json"
            bindings.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "principals": {
                            "operator:test": {
                                "defaultWorkspace": "",
                                "default": {
                                    "executionProfile": "observe",
                                    "authoritySessionId": "session-test",
                                },
                                "workspaces": {
                                    "*": {
                                        "executionProfile": "observe",
                                        "authoritySessionId": "session-test",
                                    }
                                },
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            bindings.chmod(0o600)
            with patch.object(paths, "DATA_DIR", data):
                selected = ["core"]
                config = ModernAdapterConfig(
                    surface=SurfaceMode.MODERN_DIRECT,
                    transport="stdio",
                    server_name="phase5b-adversarial",
                    audience="phase5b-adversarial",
                    capability_packs=selected,  # type: ignore[arg-type]
                    identity_bindings_path=bindings,
                    stdio_principal="operator:test",
                    allow_ephemeral_request_state=True,
                    state_dir=data / "adapter-state",
                )
                selected[0] = "web"
                self.assertEqual(config.capability_packs, ("core",))
                with self.assertRaisesRegex(ModernConfigurationError, "process Registry"):
                    build_runtime(config)

        self.assertEqual(len(CAPABILITY_PACKS.registry.descriptors()), 174)


if __name__ == "__main__":
    unittest.main()
