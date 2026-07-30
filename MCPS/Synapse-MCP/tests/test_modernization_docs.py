from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import unittest

from synapse_mcp.transport import stdio_server


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
MODERNIZATION_DOCS = REPOSITORY_ROOT / "docs" / "modernization"
ADR_DIR = MODERNIZATION_DOCS / "adr"
BASELINE_PATH = MODERNIZATION_DOCS / "baseline.md"
PHASE_ONE_STAGE_A_PATH = MODERNIZATION_DOCS / "phase-1-stage-a.md"
PYPROJECT_PATH = REPOSITORY_ROOT / "pyproject.toml"
CI_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
VALID_ADR_STATUSES = {"Proposed", "Accepted", "Superseded", "Rejected"}
REQUIRED_ADR_SECTIONS = (
    "Context",
    "Decision",
    "Invariants",
    "Alternatives considered",
    "Consequences",
    "Migration and rollback",
    "Verification",
)
PUBLIC_HOST_PATTERN = re.compile(
    r"(?i)\b(?:[a-z0-9-]+\.)+"
    r"(?:com|net|org|io|dev|app|cloud|ai|co|edu|gov|uk|ie|test)\b"
)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ALLOWED_HOSTS = {"app.acme-demo.test", "127.0.0.1", "localhost"}
PLANTED_SECRET_VALUES = (
    "CANARY-SECRET-a1b2c3",
    "CANARY-TOKEN-d4e5f6",
    "CANARY-PASSWORD-g7h8i9",
)


def _baseline_integer(label: str, text: str) -> int:
    match = re.search(
        rf"^\|\s*{re.escape(label)}\s*\|\s*([\d,]+)\s*\|$",
        text,
        flags=re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"Could not parse baseline metric {label!r}")
    return int(match.group(1).replace(",", ""))


def _baseline_string(label: str, text: str) -> str:
    match = re.search(
        rf"^\|\s*{re.escape(label)}\s*\|\s*`([^`]+)`\s*\|$",
        text,
        flags=re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"Could not parse baseline metric {label!r}")
    return match.group(1)


class ModernizationDocumentationTests(unittest.TestCase):
    def test_baseline_metrics_match_runtime(self) -> None:
        baseline = BASELINE_PATH.read_text(encoding="utf-8")
        tools = stdio_server.TOOL_SCHEMAS
        names = [tool["name"] for tool in tools]
        compact_bytes = len(
            json.dumps(tools, separators=(",", ":")).encode()
        )
        pretty_bytes = len(json.dumps(tools, indent=2).encode())
        confirm_tools = sum(
            "confirm" in tool.get("inputSchema", {}).get("properties", {})
            for tool in tools
        )
        namespaces = len({name.split(".", 1)[0] for name in names})
        output_schemas = sum("outputSchema" in tool for tool in tools)
        annotations = sum("annotations" in tool for tool in tools)
        titles = sum("title" in tool for tool in tools)

        self.assertEqual(_baseline_integer("Tools", baseline), len(tools))
        self.assertEqual(
            _baseline_integer("Unique tool names", baseline),
            len(set(names)),
        )
        self.assertEqual(
            _baseline_integer("Compact schema bytes", baseline),
            compact_bytes,
        )
        self.assertEqual(
            _baseline_integer("Pretty schema bytes", baseline),
            pretty_bytes,
        )
        self.assertEqual(
            _baseline_integer("Tools with `confirm`", baseline),
            confirm_tools,
        )
        self.assertEqual(_baseline_integer("Namespaces", baseline), namespaces)
        self.assertEqual(
            _baseline_integer("Output schemas", baseline),
            output_schemas,
        )
        self.assertEqual(_baseline_integer("Annotations", baseline), annotations)
        self.assertEqual(_baseline_integer("Titles", baseline), titles)
        self.assertEqual(
            _baseline_string("Advertised protocol", baseline),
            stdio_server.PROTOCOL_VERSION,
        )

    def test_ci_matrix_covers_the_declared_requires_python(self) -> None:
        pyproject = PYPROJECT_PATH.read_text(encoding="utf-8")
        workflow = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
        requires_python = re.search(
            r'^requires-python\s*=\s*"[^"]*>=\s*(\d+)\.(\d+)',
            pyproject,
            flags=re.MULTILINE,
        )
        self.assertIsNotNone(
            requires_python,
            "Could not parse requires-python floor",
        )
        matrix = re.search(
            r"python-version:\s*\[([^\]]+)\]",
            workflow,
        )
        self.assertIsNotNone(matrix, "Could not parse CI Python matrix")
        matrix_versions = [
            tuple(int(part) for part in version.split("."))
            for version in re.findall(r"""["'](\d+\.\d+)["']""", matrix.group(1))
        ]
        self.assertTrue(matrix_versions, "CI Python matrix is empty")

        declared_floor = (
            int(requires_python.group(1)),
            int(requires_python.group(2)),
        )
        self.assertEqual(min(matrix_versions), declared_floor)

    def test_every_adr_has_required_sections_and_a_valid_status(self) -> None:
        adr_paths = sorted(ADR_DIR.glob("ADR-*.md"))
        # 6 from Phase 0; ADR-0007 and ADR-0008 added by the Phase 1 Stage A
        # design checkpoint.
        self.assertEqual(len(adr_paths), 8)

        for path in adr_paths:
            text = path.read_text(encoding="utf-8")
            status_match = re.search(
                r"^- Status: ([A-Za-z]+)$",
                text,
                flags=re.MULTILINE,
            )
            self.assertIsNotNone(status_match, f"{path.name} has no Status")
            self.assertIn(
                status_match.group(1),
                VALID_ADR_STATUSES,
                f"{path.name} has invalid Status",
            )
            for section in REQUIRED_ADR_SECTIONS:
                self.assertIn(
                    f"## {section}\n",
                    text,
                    f"{path.name} is missing {section}",
                )

    def test_phase_one_inventory_is_complete_and_reconciled(self) -> None:
        text = PHASE_ONE_STAGE_A_PATH.read_text(encoding="utf-8")
        rows: list[list[str]] = []
        for line in text.splitlines():
            if not line.startswith("| "):
                continue
            cells = [
                cell.strip().strip("`")
                for cell in line.strip().strip("|").split("|")
            ]
            if len(cells) == 15 and cells[0].isdigit():
                rows.append(cells)

        self.assertEqual(len(rows), 174)
        self.assertEqual(
            [row[1] for row in rows],
            [tool["name"] for tool in stdio_server.TOOL_SCHEMAS],
        )
        self.assertTrue(all(row[3] for row in rows), "empty application use case")
        self.assertTrue(all(row[14] for row in rows), "empty implementation target")
        self.assertNotIn("background_submit", {row[4] for row in rows})
        self.assertEqual(
            Counter(row[4] for row in rows),
            Counter(
                {
                    "read_only": 48,
                    "passive_analysis": 39,
                    "workspace_write": 19,
                    "active_probe": 19,
                    "report_build": 18,
                    "third_party_read": 13,
                    "credential_write": 11,
                    "local_destructive": 3,
                    "runtime_config_write": 2,
                    "job_control": 1,
                    "authorization_config_write": 1,
                }
            ),
        )
        self.assertEqual(
            Counter(row[5] for row in rows),
            Counter({"none": 93, "low": 47, "moderate": 19, "high": 15}),
        )
        self.assertEqual(
            Counter(row[6] for row in rows),
            Counter(
                {
                    "not_applicable": 139,
                    "required": 22,
                    "checked_downstream": 13,
                }
            ),
        )
        self.assertEqual(
            Counter(row[7] for row in rows),
            Counter({"none": 142, "optional": 22, "required": 10}),
        )
        self.assertEqual(
            Counter(row[9] for row in rows),
            Counter(
                {
                    "sync/DEFAULT": 142,
                    "sync/FAST": 23,
                    "background_capable/DEFAULT": 8,
                    "sync/STATUS": 1,
                }
            ),
        )
        self.assertEqual(
            Counter(row[8] for row in rows),
            Counter(
                {
                    "none": 137,
                    "credential_use": 22,
                    "secret_state_write": 11,
                    "redacted_metadata_read": 4,
                }
            ),
        )
        self.assertEqual(
            Counter(row[10] for row in rows),
            Counter(
                {
                    "pure_read": 109,
                    "idempotent_write": 23,
                    "non_idempotent": 38,
                    "conditional": 3,
                    "idempotent_control": 1,
                }
            ),
        )

        by_name = {row[1]: row for row in rows}
        for name in (
            "crawler.crawl",
            "crawler.extended",
            "ffuf.run_profile",
            "nuclei.run_profile",
            "nmap.run_profile",
        ):
            self.assertEqual(by_name[name][4], "active_probe")
        self.assertEqual(
            by_name["credentials.browser_auth_check_setup"][4],
            "read_only",
        )
        self.assertEqual(by_name["evidence.log_event"][10], "non_idempotent")
        self.assertEqual(
            by_name["workspace.create_finding"][10],
            "non_idempotent",
        )

    def test_modernization_docs_contain_no_absolute_paths_or_secrets(self) -> None:
        doc_paths = sorted(MODERNIZATION_DOCS.rglob("*.md"))
        forbidden_paths = tuple(
            dict.fromkeys(
                (
                    "/home/",
                    "/Users/",
                    "/tmp/",
                    "/var/",
                    str(Path.home()),
                    str(REPOSITORY_ROOT),
                )
            )
        )

        for path in doc_paths:
            text = path.read_text(encoding="utf-8")
            for marker in forbidden_paths:
                self.assertNotIn(
                    marker,
                    text,
                    f"{path.name} contains absolute path marker {marker!r}",
                )
            for secret in PLANTED_SECRET_VALUES:
                self.assertNotIn(
                    secret,
                    text,
                    f"{path.name} contains planted secret value",
                )
            hosts = {
                match.lower()
                for match in PUBLIC_HOST_PATTERN.findall(text)
            }
            hosts.update(IPV4_PATTERN.findall(text))
            self.assertEqual(
                hosts - ALLOWED_HOSTS,
                set(),
                f"{path.name} contains non-fixture hostnames",
            )


if __name__ == "__main__":
    unittest.main()
