"""Service regression tests for single-agent default."""

from __future__ import annotations

from importlib.machinery import SourceFileLoader
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

from synapse_mcp.app.actions import CAPABILITY_PACKS, REGISTRY
from synapse_mcp.app.facade.projections import CompactProjection, DirectProjection
from synapse_mcp import guidance
from synapse_mcp.integrations import codex


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ROOT = ROOT / "skills" / "codex" / "default"
WEB_METHOD_ROOT = ROOT / "skills" / "codex" / "web-methods"
COMPAT_ROOT = ROOT / "skills" / "codex" / "multi-agent-compat"
DEVELOPMENT_ROOT = ROOT / "skills" / "codex" / "development"


def _validator():
    path = ROOT / "bin" / "validate-codex-skills"
    loader = SourceFileLoader("phase6b_skill_validator", str(path))
    specification = importlib.util.spec_from_loader(loader.name, loader)
    if specification is None or specification.loader is None:
        raise RuntimeError("Could not load the Codex skill validator.")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class SingleAgentDefaultTests(unittest.TestCase):
    def test_default_guidance_keeps_heuristic_helpers_optional(self) -> None:
        prompt = (ROOT / "MCPS" / "Synapse-MCP" / "synapse_mcp" / "operational_prompt.md").read_text(
            encoding="utf-8"
        )
        web = (DEFAULT_ROOT / "synapse-web-pentesting" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Do not batch-run analyzers", prompt)
        self.assertIn("do not batch-run analyzers", web)
        self.assertIn("automatically ingest candidates", prompt)
        methods = {
            package["id"]: package["description"]
            for package in guidance.build_guidance_snapshot().packages
            if package["kind"] == "method"
        }
        self.assertEqual(set(methods), set(codex.WEB_METHOD_SKILLS))
        for method_id, description in methods.items():
            self.assertTrue(
                "optional" in description or "no dedicated heuristic helper" in description,
                method_id,
            )

    def test_default_profile_is_exactly_three_operating_skills(self) -> None:
        expected = {
            "operate-synapse",
            "synapse-web-pentesting",
            "synapse-cve-intelligence",
        }
        actual = {
            path.name for path in DEFAULT_ROOT.iterdir() if (path / "SKILL.md").is_file()
        }
        self.assertEqual(actual, expected)
        self.assertEqual(set(codex.OPERATING_SKILLS), expected)
        self.assertNotIn("synapse-developing", actual)
        self.assertTrue((DEVELOPMENT_ROOT / "synapse-developing" / "SKILL.md").is_file())

    def test_default_and_compatibility_profiles_validate_independently(self) -> None:
        validator = _validator()
        validator._select_profile("default")
        self.assertEqual(validator.validate(), [])
        validator._select_profile("multi-agent-compat")
        self.assertEqual(validator.validate(), [])
        self.assertEqual(
            {path.name for path in COMPAT_ROOT.iterdir() if (path / "SKILL.md").is_file()},
            set(codex.MULTI_AGENT_COMPAT_SKILLS),
        )

    def test_default_router_is_single_agent_and_routes_only_two_methods(self) -> None:
        router = (DEFAULT_ROOT / "operate-synapse" / "SKILL.md").read_text(encoding="utf-8")
        prompt = (ROOT / "MCPS" / "Synapse-MCP" / "synapse_mcp" / "operational_prompt.md").read_text(
            encoding="utf-8"
        )
        root_instructions = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        combined = "\n".join((router, prompt, root_instructions))
        self.assertIn("$synapse-web-pentesting", combined)
        self.assertIn("$synapse-cve-intelligence", combined)
        self.assertIn("Do not spawn sub-agents", combined)
        for compatibility_skill in set(codex.MULTI_AGENT_COMPAT_SKILLS) - {"operate-synapse"}:
            self.assertNotIn(f"${compatibility_skill}", router)

    def test_web_and_cve_methods_cover_sequential_operational_decisions(self) -> None:
        web = (DEFAULT_ROOT / "synapse-web-pentesting" / "SKILL.md").read_text(encoding="utf-8")
        cve = (DEFAULT_ROOT / "synapse-cve-intelligence" / "SKILL.md").read_text(encoding="utf-8")
        selection = (
            DEFAULT_ROOT / "synapse-web-pentesting" / "references" / "selection-and-resumption.md"
        ).read_text(encoding="utf-8")
        for phrase in (
            "Establish the engagement picture",
            "Select the current method",
            "Form and prioritize hypotheses",
            "Persist and converge",
            "$synapse-cve-intelligence",
        ):
            self.assertIn(phrase, web)
        for phrase in (
            "Normalize the component claim",
            "Decide applicability",
            "Analyze public PoCs safely",
            "Plan bounded validation and return",
            "$synapse-web-pentesting",
        ):
            self.assertIn(phrase, cve)
        self.assertIn("Do not execute, import, install, build", (
            DEFAULT_ROOT / "synapse-cve-intelligence" / "references" / "source-and-poc-analysis.md"
        ).read_text(encoding="utf-8"))
        for heading in (
            "## Short normal workflow",
            "## Explicit selection examples",
            "## Missing method remedy",
            "## Digest mismatch remedy",
        ):
            self.assertIn(heading, selection)
        for phrase in (
            "Honor an explicit operator method choice",
            "version 1.1 contribution route",
            "Web assessment can select",
            "Continue or create a work item only when durable",
            "do not rewrite old contributions",
        ):
            self.assertIn(phrase, selection)
        self.assertIn("methodRef", cve)
        self.assertIn("selection-and-resumption.md", cve)

    def test_main_web_method_routes_to_complete_optional_procedures(self) -> None:
        web = (DEFAULT_ROOT / "synapse-web-pentesting" / "SKILL.md").read_text(encoding="utf-8")
        contract = (
            DEFAULT_ROOT / "synapse-web-pentesting" / "references" / "method-contract.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Honor an explicit operator method choice", web)
        self.assertIn("specific coverage gap", web)
        for heading in (
            "## Recover and bound the question",
            "## Use live capabilities",
            "## Contribute to canonical workspace truth",
            "## Stop and hand back",
        ):
            self.assertIn(heading, contract)
        for phrase in (
            "supporting and contrary evidence IDs",
            "version 1.1",
            "methodRef",
            "receipt",
        ):
            self.assertIn(phrase, contract)
        for method in codex.WEB_METHOD_SKILLS:
            self.assertIn(f"${method}", web)
            procedure = (WEB_METHOD_ROOT / method / "references" / "selection.md").read_text(
                encoding="utf-8"
            )
            for heading in (
                "## Select this method",
                "## Required context",
                "## Test alternative explanations",
                "## Weigh evidence and unknowns",
                "## Stop or hand back",
            ):
                self.assertIn(heading, procedure)
            self.assertIn("method ID", procedure)
            self.assertIn(f"`{method}`", procedure)
            self.assertIn("references/method-contract.md", procedure)

    def test_assets_are_selected_explicitly_and_application_stays_provider_neutral(self) -> None:
        self.assertEqual(codex.validate_assets(), [])
        self.assertEqual(codex.codex_skills_dir(), DEFAULT_ROOT)
        self.assertEqual(codex.codex_skills_dir("web-methods"), ROOT / "skills" / "codex" / "web-methods")
        self.assertEqual(codex.codex_skills_dir("multi-agent-compat"), COMPAT_ROOT)
        compat_config = (codex.codex_config_dir() / "multi-agent-compat.toml").read_text(encoding="utf-8")
        self.assertIn("multi_agent = true", compat_config)

        forbidden = ("synapse_mcp.integrations.codex", "multi-agent-compat", "codex-single")
        for relative in ("app", "policy", "state", "core", "adapters"):
            for path in (ROOT / "MCPS" / "Synapse-MCP" / "synapse_mcp" / relative).rglob("*.py"):
                text = path.read_text(encoding="utf-8")
                for marker in forbidden:
                    self.assertNotIn(marker, text, path)

    def test_asset_cli_defaults_to_three_skills_and_requires_compat_selection(self) -> None:
        code = "from synapse_mcp.integrations.codex import main; raise SystemExit(main())"
        environment = {"PYTHONPATH": str(ROOT / "MCPS" / "Synapse-MCP")}
        default = subprocess.run(
            [sys.executable, "-c", code, "--skills-dir"],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        compatibility = subprocess.run(
            [sys.executable, "-c", code, "--skills-profile", "multi-agent-compat"],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        methods = subprocess.run(
            [sys.executable, "-c", code, "--skills-profile", "web-methods"],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertEqual(compatibility.returncode, 0, compatibility.stderr)
        self.assertEqual(methods.returncode, 0, methods.stderr)
        self.assertEqual(Path(default.stdout.strip()), DEFAULT_ROOT)
        self.assertEqual(Path(compatibility.stdout.strip()), COMPAT_ROOT)
        self.assertEqual(Path(methods.stdout.strip()), ROOT / "skills" / "codex" / "web-methods")

    def test_application_surfaces_and_registry_are_unchanged(self) -> None:
        self.assertEqual(len(REGISTRY.descriptors()), 174)
        self.assertEqual(len(CompactProjection().operations()), 11)
        self.assertEqual(
            tuple(operation.name for operation in DirectProjection().operations()),
            tuple(str(descriptor.id) for descriptor in REGISTRY.descriptors()),
        )

    def test_method_selection_does_not_select_packs_or_authority(self) -> None:
        method_ids = {
            package.id for package in guidance.GUIDANCE_PACKAGES
            if package.kind == "method"
        }
        pack_ids = {str(manifest.id) for manifest in CAPABILITY_PACKS.manifests}
        self.assertEqual(pack_ids, {"core", "web", "infra", "reporting", "purple", "intelligence"})
        self.assertTrue(method_ids.isdisjoint(pack_ids))
        self.assertEqual(CAPABILITY_PACKS.pack("web").action_ids, tuple(
            action_id for action_id, owner in CAPABILITY_PACKS.action_owners
            if owner == "web"
        ))
        self.assertIn("graphql.analyze_workspace", CAPABILITY_PACKS.pack("web").action_ids)
        self.assertNotIn("authority", " ".join(method_ids))

    def test_adapter_guide_documents_replaceable_interpretation_boundary(self) -> None:
        adapter_guide = (ROOT / "docs" / "Adapter-Development.md").read_text(encoding="utf-8")
        operations = (ROOT / "docs" / "Operations.md").read_text(encoding="utf-8")
        for phrase in (
            "deterministic input/output contracts, parsers, extraction",
            "Replaceable methodology content owns interpretation",
            "selection is separate from startup",
            "does not grant authority",
        ):
            self.assertIn(phrase, adapter_guide)
        self.assertIn("The default web route starts with saved workspace evidence", operations)
        self.assertIn("A method package selects guidance.", operations)
        self.assertIn("packs and Authority Grants remain separate server controls", operations)
        self.assertIn("Removing an optional package leaves", operations)


if __name__ == "__main__":
    unittest.main()
