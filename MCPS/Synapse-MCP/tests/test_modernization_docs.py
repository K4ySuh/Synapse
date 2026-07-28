from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

from synapse_mcp.transport import stdio_server


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
MODERNIZATION_DOCS = REPOSITORY_ROOT / "docs" / "modernization"
ADR_DIR = MODERNIZATION_DOCS / "adr"
BASELINE_PATH = MODERNIZATION_DOCS / "baseline.md"
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


class ModernizationDocumentationTests(unittest.TestCase):
    def test_baseline_metrics_match_runtime(self) -> None:
        baseline = BASELINE_PATH.read_text(encoding="utf-8")
        tools = stdio_server.TOOL_SCHEMAS
        names = [tool["name"] for tool in tools]
        compact_bytes = len(
            json.dumps(tools, separators=(",", ":")).encode()
        )
        confirm_tools = sum(
            "confirm" in tool.get("inputSchema", {}).get("properties", {})
            for tool in tools
        )

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
            _baseline_integer("Tools with `confirm`", baseline),
            confirm_tools,
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
        self.assertEqual(len(adr_paths), 6)

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
