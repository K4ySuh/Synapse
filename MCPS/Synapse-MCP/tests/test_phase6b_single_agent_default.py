"""Phase 6B gates for the single-agent default and compatibility assets."""

from __future__ import annotations

from importlib.machinery import SourceFileLoader
import importlib.util
from pathlib import Path
import runpy
import subprocess
import sys
import unittest

from synapse_mcp.app.actions import REGISTRY
from synapse_mcp.app.facade.projections import CompactProjection
from synapse_mcp.integrations import codex


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ROOT = ROOT / "skills" / "codex" / "default"
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


class Phase6BSingleAgentDefaultTests(unittest.TestCase):
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
        for phrase in (
            "Establish the engagement picture",
            "Model the application",
            "Form and prioritize hypotheses",
            "Validate within the envelope",
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

    def test_assets_are_selected_explicitly_and_application_stays_provider_neutral(self) -> None:
        self.assertEqual(codex.validate_assets(), [])
        self.assertEqual(codex.codex_skills_dir(), DEFAULT_ROOT)
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
        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertEqual(compatibility.returncode, 0, compatibility.stderr)
        self.assertEqual(Path(default.stdout.strip()), DEFAULT_ROOT)
        self.assertEqual(Path(compatibility.stdout.strip()), COMPAT_ROOT)

    def test_single_agent_live_diagnostic_is_bounded_and_multi_agent_is_opt_in(self) -> None:
        diagnostic = runpy.run_path(str(ROOT / "bin" / "run-phase6b-codex-diagnostic"))
        self.assertEqual(diagnostic["DEFAULT_MODEL"], "gpt-5.6-terra")
        self.assertEqual(diagnostic["DEFAULT_REASONING_EFFORT"], "medium")
        self.assertEqual(diagnostic["REPETITIONS"], 1)
        diagnostic["_assert_objective_prompt"]()
        with self.subTest("single-agent command"):
            command = diagnostic["_codex_command"](
                Path("/tmp/phase6b-fixture"),
                Path("/tmp/phase6b-schema.json"),
                Path("/tmp/phase6b-final.json"),
                diagnostic["DEFAULT_MODEL"],
                diagnostic["DEFAULT_REASONING_EFFORT"],
            )
            self.assertIn("features.multi_agent=false", command)
            self.assertNotIn("agents.default_subagent_model", "\n".join(command))
        compatibility = (ROOT / "bin" / "run-phase5-codex-benchmark").read_text(encoding="utf-8")
        self.assertIn("--profile multi-agent-compat", compatibility)

    def test_application_surfaces_and_registry_are_unchanged(self) -> None:
        self.assertEqual(len(REGISTRY.descriptors()), 174)
        self.assertEqual(len(CompactProjection().operations()), 11)


if __name__ == "__main__":
    unittest.main()
