"""Phase 5E gates for scoped instructions, runtime guidance, and Codex assets."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from synapse_mcp.integrations import codex
from synapse_mcp.transport import stdio_server


ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = ROOT / "MCPS" / "Synapse-MCP" / "synapse_mcp"
OPERATIONAL_PROMPT = PACKAGE_ROOT / "operational_prompt.md"
PHASE4_ROOT_PROMPT_BYTES = 27_633
NESTED_INSTRUCTIONS = (
    ROOT / "MCPS" / "Synapse-MCP" / "AGENTS.md",
    PACKAGE_ROOT / "policy" / "AGENTS.md",
    PACKAGE_ROOT / "state" / "AGENTS.md",
    PACKAGE_ROOT / "adapters" / "AGENTS.md",
    ROOT / "MCPS" / "Synapse-MCP" / "tests" / "AGENTS.md",
)


class Phase5EDistributionTests(unittest.TestCase):
    def test_root_instructions_are_scoped_and_under_150_physical_lines(self) -> None:
        root = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertLess(len(root.splitlines()), 150)
        for path in NESTED_INSTRUCTIONS:
            self.assertTrue(path.is_file(), path)
            self.assertIn(str(path.relative_to(ROOT)), root)
        self.assertNotIn("This repository-level `AGENTS.md` is exposed", root)

    def test_operational_prompt_is_package_owned_concise_and_development_free(self) -> None:
        prompt = OPERATIONAL_PROMPT.read_text(encoding="utf-8")
        prompt_bytes = len(prompt.encode())
        self.assertLess(prompt_bytes, PHASE4_ROOT_PROMPT_BYTES // 4)
        for phrase in (
            "Operate as one agent by default",
            "Do not spawn sub-agents",
            "scope",
            "execution authority",
            "revision-aware context",
            "capability search",
            "work item",
            "passive",
            "active validation",
            "candidate",
            "finding",
            "evidence",
            "background jobs",
            "At completion",
        ):
            self.assertIn(phrase, prompt)
        for development_only in (
            "bin/test",
            "CHANGELOG.md",
            "docs/Version-Log.md",
            "apply_patch",
            "repository-development",
            "test fixture",
        ):
            self.assertNotIn(development_only, prompt)

    def test_repository_and_outside_launches_read_the_same_package_prompt(self) -> None:
        expected = OPERATIONAL_PROMPT.read_text(encoding="utf-8")
        self.assertEqual(stdio_server.PROMPT_PATH.resolve(), OPERATIONAL_PROMPT.resolve())
        self.assertEqual(stdio_server.read_main_prompt(), expected)
        with TemporaryDirectory() as temporary:
            code = (
                "from synapse_mcp.transport.stdio_server import read_main_prompt; "
                "print(read_main_prompt(), end='')"
            )
            environment = dict(os.environ)
            environment.pop("SYNAPSE_PROMPT_PATH", None)
            environment["SYNAPSE_ROOT"] = temporary
            environment["SYNAPSE_DATA_DIR"] = str(Path(temporary) / "DATA")
            environment["SYNAPSE_DUMP_DIR"] = str(Path(temporary) / "DATA" / "workspaces")
            environment["SYNAPSE_REPORTS_DIR"] = str(Path(temporary) / "reports")
            environment["PYTHONPATH"] = str(ROOT / "MCPS" / "Synapse-MCP")
            result = subprocess.run(
                [sys.executable, "-c", code],
                cwd=temporary,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, expected)

    def test_legacy_prompt_and_resource_discovery_shape_is_unchanged(self) -> None:
        self.assertEqual(
            [item for item in stdio_server.PROMPTS if item["name"] == "synapse-main"],
            [{"name": "synapse-main", "description": "Shared Synapse operating prompt.", "arguments": []}],
        )
        resource = next(item for item in stdio_server.RESOURCES if item["uri"] == "synapse://prompt/main")
        self.assertEqual(resource["mimeType"], "text/markdown")
        self.assertEqual(stdio_server.read_resource(resource["uri"])[1], stdio_server.read_main_prompt())
        self.assertEqual(
            stdio_server.get_prompt("synapse-main")["messages"][0]["content"]["text"],
            stdio_server.read_main_prompt(),
        )

    def test_codex_distribution_assets_and_all_local_references_resolve(self) -> None:
        self.assertEqual(codex.validate_assets(), [])
        self.assertEqual(
            codex.codex_skills_dir().resolve(),
            (ROOT / "skills" / "codex" / "default").resolve(),
        )
        self.assertEqual(
            codex.codex_skills_dir("multi-agent-compat").resolve(),
            (ROOT / "skills" / "codex" / "multi-agent-compat").resolve(),
        )
        self.assertEqual(codex.codex_config_dir().resolve(), (ROOT / "config" / "codex").resolve())
        self.assertEqual(len(codex.OPERATING_SKILLS), 3)
        self.assertEqual(len(codex.MULTI_AGENT_COMPAT_SKILLS), 8)
        for profile in codex.CONFIG_PROFILES:
            config = (codex.codex_config_dir() / f"{profile}.toml").read_text(encoding="utf-8")
            self.assertIn("[mcp_servers.synapse]", config)
            self.assertNotIn("SHODAN_API_KEY", config)

    def test_generated_codex_profiles_select_standard_core_direct_and_legacy(self) -> None:
        script = ROOT / "bin" / "print-mcp-config"
        outputs = {}
        for profile in ("--standard", "--core-only", "--modern-direct", "--legacy"):
            result = subprocess.run(
                [str(script), profile],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs[profile] = result.stdout
        self.assertIn('"--surface", "modern-compact"', outputs["--standard"])
        self.assertNotIn('"--capability-pack"', outputs["--standard"])
        self.assertIn('"--capability-pack", "core"', outputs["--core-only"])
        self.assertIn('"--surface", "modern-direct"', outputs["--modern-direct"])
        self.assertIn("MCPS/Synapse-MCP/bin/synapse-mcp", outputs["--legacy"])

    def test_distribution_metadata_packages_prompt_skills_configs_and_no_codex_sdk(self) -> None:
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"operational_prompt.md"', metadata)
        self.assertIn('[tool.setuptools.data-files]', metadata)
        self.assertIn('"share/synapse-mcp/codex/config"', metadata)
        for profile, skills in codex.PROFILE_SKILLS.items():
            for name in skills:
                self.assertIn(f'codex/skills/{profile}/{name}', metadata)
        dependencies = metadata.split("dependencies = [", 1)[1].split("]", 1)[0].lower()
        self.assertNotIn("codex", dependencies)

        code = """
import sys
import synapse_mcp.app
import synapse_mcp.policy
import synapse_mcp.state
assert not any(name.startswith('synapse_mcp.integrations.codex') for name in sys.modules)
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT / "MCPS" / "Synapse-MCP")},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
