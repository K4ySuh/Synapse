"""Phase 4 entry-gate SQLite runtime and package-boundary tests."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest

from synapse_mcp.state.readiness import select_sqlite_runtime


ROOT = Path(__file__).resolve().parents[3]
STATE_PACKAGE = ROOT / "MCPS" / "Synapse-MCP" / "synapse_mcp" / "state"
ADR_DIR = ROOT / "docs" / "modernization" / "adr"


class Phase4EntryReadinessTests(unittest.TestCase):
    def test_runtime_floor_accepts_stdlib_or_reviewed_fallback(self) -> None:
        stdlib = select_sqlite_runtime(stdlib_sqlite_version="3.51.3")
        self.assertTrue(stdlib.ready)
        self.assertEqual(stdlib.selected_binding, "sqlite3")

        fallback = select_sqlite_runtime(
            stdlib_sqlite_version="3.50.4",
            apsw_sqlite_version="3.53.4",
            apsw_binding_version="3.53.4.0",
        )
        self.assertTrue(fallback.ready)
        self.assertEqual(fallback.selected_binding, "apsw")
        self.assertEqual(fallback.selected_sqlite_version, "3.53.4")

        unsupported = select_sqlite_runtime(
            stdlib_sqlite_version="3.50.4",
            apsw_sqlite_version="3.51.2",
        )
        self.assertFalse(unsupported.ready)
        self.assertEqual(unsupported.reason_code, "sqlite_runtime_too_old")

    def test_readiness_probe_prints_actual_stdlib_sqlite_version(self) -> None:
        environment = dict(os.environ)
        environment["SYNAPSE_PYTHON"] = sys.executable
        result = subprocess.run(
            [str(ROOT / "bin" / "check-state-v2-readiness")],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertIn(f"sqlite3.sqlite_version: {sqlite3.sqlite_version}", result.stdout)
        expected_ready = tuple(
            int(part) for part in sqlite3.sqlite_version.split(".")
        ) >= (3, 51, 3)
        if expected_ready:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("STATE STORE V2 READY", result.stdout)

    def test_state_runtime_package_has_no_mcp_imports(self) -> None:
        for path in STATE_PACKAGE.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse(
                        str(node.module or "").startswith("mcp"),
                        f"{path.name} imports MCP at line {node.lineno}",
                    )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertFalse(
                            alias.name.startswith("mcp"),
                            f"{path.name} imports MCP at line {node.lineno}",
                        )

    def test_entry_decisions_and_ci_runtime_evidence_are_sealed(self) -> None:
        store_adr = (ADR_DIR / "ADR-0005-sqlite-artifact-store.md").read_text(
            encoding="utf-8"
        )
        context_adr = (
            ADR_DIR / "ADR-0006-context-revisions-budget-behaviour.md"
        ).read_text(encoding="utf-8")
        self.assertIn("- Status: Accepted", store_adr)
        self.assertIn("one SQLite database", store_adr)
        self.assertIn("State-engine rollback", store_adr)
        self.assertIn("Credential bodies", store_adr)
        self.assertIn("- Status: Accepted", context_adr)
        self.assertIn("utf8_bytes_v1", context_adr)
        self.assertIn("budget_too_small", context_adr)
        self.assertIn("fullRefreshRequired=true", context_adr)

        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('"apsw==3.53.4.0"', pyproject)
        self.assertIn('python-version: ["3.10", "3.11", "3.12", "3.13"]', workflow)
        self.assertGreaterEqual(workflow.count("bin/check-state-v2-readiness"), 2)
        self.assertGreaterEqual(workflow.count("sqlite3.sqlite_version"), 2)


if __name__ == "__main__":
    unittest.main()
