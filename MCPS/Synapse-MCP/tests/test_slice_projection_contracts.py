from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from contract_support import ALLOWED_FIXTURE_HOSTS, result_fixture_bytes
from helpers import isolated_state
from synapse_mcp.adapters.web import headers_cookies as headers_cookies_adapter
from synapse_mcp.app.actions import REGISTRY
from synapse_mcp.app.actions.packs import workspace as workspace_pack
from synapse_mcp.transport import projection, stdio_server
from synapse_mcp.transport.legacy_projection_map import LEGACY_PROJECTION_MAP


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
STAGE_A_PATH = REPOSITORY_ROOT / "docs" / "modernization" / "phase-1-stage-a.md"


def _stage_a_inventory() -> dict[str, list[str]]:
    inventory: dict[str, list[str]] = {}
    for line in STAGE_A_PATH.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| "):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        if len(cells) == 15 and cells[0].isdigit():
            inventory[cells[1]] = cells
    return inventory


def _stage_a_recordable_tools() -> set[str]:
    return {
        name
        for name, cells in _stage_a_inventory().items()
        if cells[12] == "Y"
    }


def _tool_call(request_id: int, name: str, arguments: dict) -> dict:
    response = stdio_server.handle(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    if response is None:
        raise AssertionError(f"{name} unexpectedly returned no response")
    return response


class SliceProjectionContractTests(unittest.TestCase):
    def test_descriptor_deadline_matches_legacy_for_all_tools(self) -> None:
        inventory = _stage_a_inventory()
        tier_seconds = {"FAST": 15.0, "STATUS": 30.0, "DEFAULT": 45.0}
        expected_by_name = {
            name: tier_seconds[cells[9].split("/", 1)[1]]
            for name, cells in inventory.items()
        }
        runtime_names = {tool["name"] for tool in stdio_server.TOOL_SCHEMAS}
        self.assertEqual(len(expected_by_name), 174)
        self.assertEqual(set(expected_by_name), runtime_names)
        self.assertEqual(
            stdio_server.FAST_TOOLS,
            {name for name, cells in inventory.items() if cells[9].endswith("/FAST")},
        )
        for name, expected in expected_by_name.items():
            self.assertEqual(stdio_server._tool_deadline_seconds(name, {}), expected)

        for action_id, legacy in LEGACY_PROJECTION_MAP.items():
            descriptor = REGISTRY.get(action_id)
            self.assertEqual(
                descriptor.task_policy.deadline_tier.value,
                expected_by_name[legacy.legacy_name],
            )

    def test_passive_recording_unchanged_for_the_fifteen_recordable_tools(self) -> None:
        expected_recordable = _stage_a_recordable_tools()
        self.assertEqual(len(expected_recordable), 15)
        actual_recordable = {
            tool["name"]
            for tool in stdio_server.TOOL_SCHEMAS
            if stdio_server._is_recordable_passive_analysis_tool(tool["name"])
        }
        self.assertEqual(actual_recordable, expected_recordable)

        for action_id, legacy in LEGACY_PROJECTION_MAP.items():
            descriptor = REGISTRY.get(action_id)
            self.assertEqual(
                descriptor.task_policy.passive_recordable,
                legacy.legacy_name in expected_recordable,
            )

    def test_slice_input_models_match_legacy_runtime_validation_semantics(self) -> None:
        valid_inputs = {
            "jobs.status": {"jobId": "job-fixture"},
            "workspace.summary": {"workspaceId": "acme"},
            "workspace.prepare_target_context": {
                "workspaceId": "acme",
                "target": ALLOWED_FIXTURE_HOSTS[0],
            },
            "headers_cookies.analyze_workspace": {
                "workspaceId": "acme",
                "target": ALLOWED_FIXTURE_HOSTS[0],
            },
            "cors.execute_test": {},
            "crawler.crawl": {"target": f"http://{ALLOWED_FIXTURE_HOSTS[0]}"},
        }
        strict_fields = {
            "jobs.status": ("includeResult", "false"),
            "workspace.summary": ("limit", "50"),
            "workspace.prepare_target_context": ("maxTokens", "1500"),
            "headers_cookies.analyze_workspace": ("maxCandidates", "100"),
            "cors.execute_test": ("requestTimeout", "10"),
            "crawler.crawl": ("maxPages", "200"),
        }

        for action_id, arguments in valid_inputs.items():
            model = REGISTRY.get(action_id).input_model
            instance = model.model_validate({**arguments, "futurePublicField": "accepted"})
            self.assertEqual(instance.futurePublicField, "accepted")
            with self.assertRaises(ValidationError):
                model.model_validate({**arguments, "_workerField": "rejected"})
            field, string_value = strict_fields[action_id]
            with self.assertRaises(ValidationError):
                model.model_validate({**arguments, field: string_value})

        cors_input = REGISTRY.get("cors.execute_test").input_model.model_validate({})
        crawler_input = REGISTRY.get("crawler.crawl").input_model.model_validate(
            {"target": f"http://{ALLOWED_FIXTURE_HOSTS[0]}"}
        )
        self.assertIsNone(cors_input.confirm)
        self.assertIsNone(crawler_input.confirm)

        context_model = REGISTRY.get("workspace.prepare_target_context").input_model
        context_input = context_model.model_validate(
            {
                "workspaceId": "acme",
                "target": ALLOWED_FIXTURE_HOSTS[0],
            }
        )
        self.assertNotIn("maxTokens", context_input.model_dump(exclude_unset=True))
        with patch.object(
            workspace_pack.workspace,
            "prepare_target_context",
            return_value={"context": "fixture"},
        ) as prepare_target_context:
            projection.project_call(
                "workspace.prepare_target_context",
                {
                    "workspaceId": "acme",
                    "target": ALLOWED_FIXTURE_HOSTS[0],
                },
            )
        prepare_target_context.assert_called_once_with(
            "acme",
            ALLOWED_FIXTURE_HOSTS[0],
            "next_step_planning",
            1500,
        )

        endpoint_entities = {
            "endpoints": [
                {
                    "url": f"https://{ALLOWED_FIXTURE_HOSTS[0]}/item-{index}",
                    "responseHeaders": {"content-type": "text/html"},
                    "responseCookieFlags": [],
                }
                for index in range(101)
            ]
        }
        with (
            patch.object(
                headers_cookies_adapter.workspace,
                "prepare_target_context",
                return_value={},
            ),
            patch.object(
                headers_cookies_adapter.workspace,
                "_load_target_entities",
                return_value=endpoint_entities,
            ),
            patch.object(headers_cookies_adapter.evidence, "log_event"),
        ):
            serialized = projection.project_call(
                "headers_cookies.analyze_workspace",
                {
                    "workspaceId": "acme",
                    "target": ALLOWED_FIXTURE_HOSTS[0],
                    "dedupeScope": "endpoint",
                    "ingest": False,
                },
            )
        self.assertIsNotNone(serialized)
        self.assertEqual(json.loads(serialized)["candidateCount"], 100)

    def test_outcome_projection_preserves_legacy_error_taxonomy(self) -> None:
        expected = {
            name: json.loads(result_fixture_bytes(f"{name}.json"))["error"]
            for name in (
                "cors_execute_test_unconfirmed",
                "crawler_crawl_unconfirmed",
                "crawler_crawl_out_of_scope",
            )
        }

        with TemporaryDirectory() as temporary_root:
            root = Path(temporary_root)
            with isolated_state(root):
                for setup_response in (
                    _tool_call(
                        1,
                        "scope.set",
                        {
                            "hosts": [ALLOWED_FIXTURE_HOSTS[0], ALLOWED_FIXTURE_HOSTS[1]],
                            "organization": "Acme Demo",
                        },
                    ),
                    _tool_call(2, "workspace.create", {"workspaceId": "acme"}),
                    _tool_call(
                        3,
                        "workspace.add_target",
                        {
                            "workspaceId": "acme",
                            "target": ALLOWED_FIXTURE_HOSTS[0],
                        },
                    ),
                ):
                    self.assertNotIn("error", setup_response)

                responses = {
                    "cors_execute_test_unconfirmed": _tool_call(
                        216,
                        "cors.execute_test",
                        {
                            "workspaceId": "acme",
                            "url": f"http://{ALLOWED_FIXTURE_HOSTS[0]}/api",
                            "method": "GET",
                            "disableTraffic": True,
                        },
                    ),
                    "crawler_crawl_unconfirmed": _tool_call(
                        211,
                        "crawler.crawl",
                        {
                            "target": f"http://{ALLOWED_FIXTURE_HOSTS[0]}",
                            "workspaceId": "acme",
                        },
                    ),
                    "crawler_crawl_out_of_scope": _tool_call(
                        212,
                        "crawler.crawl",
                        {
                            "target": f"http://{ALLOWED_FIXTURE_HOSTS[3]}",
                            "workspaceId": "acme",
                            "confirm": True,
                            "disableTraffic": True,
                        },
                    ),
                }

        self.assertEqual(
            {name: response["error"] for name, response in responses.items()},
            expected,
        )


if __name__ == "__main__":
    unittest.main()
