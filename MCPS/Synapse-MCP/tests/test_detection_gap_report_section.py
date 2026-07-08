import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import isolated_state
from synapse_mcp.core import workspace
from synapse_mcp.transport import stdio_server


class DetectionGapReportSectionTests(unittest.TestCase):
    def test_operator_report_shows_gap_matrix_sorted_by_criticality(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                _seed_gap("act-medium", "T1087", False, "Medium gap")
                _seed_gap("act-critical", "T1078", False, "Critical gap")
                _seed_gap("act-high", "T1047", None, "Unknown high gap")

                rendered = _render_summary("internal")

                self.assertIn("## Detection Coverage", rendered)
                self.assertLess(rendered.index("| T1078 "), rendered.index("| T1047 "))
                self.assertLess(rendered.index("| T1047 "), rendered.index("| T1087 "))
                self.assertIn("| T1047 | Windows Management Instrumentation | high | unknown | act-high | Unknown high gap |", rendered)

    def test_operator_report_empty_gap_section_renders_no_data_line(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", hosts=["example.com"])

                rendered = _render_summary("internal")

                self.assertIn("## Detection Coverage", rendered)
                self.assertIn("No detection outcomes recorded.", rendered)

    def test_safe_report_excludes_detection_coverage_section_entirely(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                _seed_gap("act-critical", "T1078", False, "Critical gap")

                rendered = _render_summary("high_level")

                self.assertNotIn("Detection Coverage", rendered)
                self.assertNotIn("T1078", rendered)
                self.assertNotIn("Critical gap", rendered)


def _seed_gap(action_id: str, technique_id: str, detected: bool | None, notes: str) -> None:
    workspace.create_workspace("engagement", hosts=["example.com"])
    workspace.record_action(
        "engagement",
        "example.com",
        {
            "type": "tool_run",
            "tool": "manual",
            "actionId": action_id,
            "key": action_id,
            "target": "example.com",
            "summary": f"Action for {technique_id}",
            "mitreTechniqueId": technique_id,
        },
    )
    stdio_server.call_tool(
        "mark_detection_outcome",
        {
            "workspaceId": "engagement",
            "target": "example.com",
            "actionKey": action_id,
            "detected": detected,
            "notes": notes,
        },
    )


def _render_summary(mode: str) -> str:
    return json.loads(
        stdio_server.call_tool(
            "documentation.render_assessment_summary",
            {
                "workspaceId": "engagement",
                "redactionMode": mode,
                "outputPath": f"reports/{mode}-detection-summary.md",
            },
        )
    )["content"]


if __name__ == "__main__":
    unittest.main()
