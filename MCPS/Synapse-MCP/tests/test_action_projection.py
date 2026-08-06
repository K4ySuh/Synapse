from __future__ import annotations

import unittest

from synapse_mcp.app.actions import REGISTRY
from synapse_mcp.transport import projection, stdio_server
from synapse_mcp.transport.legacy_projection_map import LEGACY_PROJECTION_MAP


MIGRATED_ACTIONS = {
    "jobs.status",
    "workspace.summary",
    "workspace.prepare_target_context",
    "headers_cookies.analyze_workspace",
    "cors.execute_test",
    "crawler.crawl",
}


class ActionProjectionTests(unittest.TestCase):
    def test_projection_map_covers_every_migrated_action_and_preserves_legacy_names(self) -> None:
        self.assertEqual(set(LEGACY_PROJECTION_MAP), MIGRATED_ACTIONS)
        projected_by_name = {
            tool["name"]: tool
            for tool in stdio_server.TOOL_SCHEMAS
        }
        raw_by_name = {
            tool["name"]: tool
            for tool in stdio_server._LEGACY_TOOL_SCHEMAS
        }

        for action_id, legacy in LEGACY_PROJECTION_MAP.items():
            self.assertEqual(legacy.legacy_name, action_id)
            self.assertEqual(
                projection.resolved_input_schema(legacy.legacy_name),
                projected_by_name[legacy.legacy_name]["inputSchema"],
            )
            self.assertNotIn("inputSchema", raw_by_name[legacy.legacy_name])

        self.assertEqual(len(REGISTRY.descriptors()), 6)
        self.assertEqual(
            REGISTRY.packs(),
            frozenset({"jobs", "workspace", "headers_cookies", "cors", "crawler"}),
        )


if __name__ == "__main__":
    unittest.main()
