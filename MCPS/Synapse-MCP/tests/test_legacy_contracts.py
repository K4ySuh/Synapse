"""Byte-exact Tier-1 contract tests for the legacy Synapse MCP server.

Regenerate the committed fixtures deliberately with:

    SYNAPSE_UPDATE_CONTRACTS=1 bin/test --core -k legacy_contracts

Normal tests load expected bytes directly from disk; fixture regeneration is a
separate capture path in ``contract_support``. Tier 1 performs no normalization.
The generic ``-32000`` response is shape-asserted instead of frozen because its
reachable prompt-file trigger embeds an environment-specific absolute path.
Environment-dependent tool results and their normalization belong to Tier 2.
"""

from __future__ import annotations

import copy
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from contract_support import (
    all_contract_fixture_paths,
    assert_response_matches_fixture,
    assert_tools_list_matches_fixture,
    capture_confirm_omission_contract,
    compact_json_bytes,
    environment_path_values,
    fixture_bytes,
    regenerate_contract_fixtures,
)
from helpers import isolated_state
from synapse_mcp.transport import stdio_server


def _require_response(response: dict | None, method: str) -> dict:
    if response is None:
        raise AssertionError(f"{method} unexpectedly returned no response")
    return response


def _parse_error_for_comparison() -> dict:
    stdout = io.StringIO()
    with patch.object(stdio_server.sys, "stdin", ["{bad json\n"]), patch.object(
        stdio_server.sys,
        "stdout",
        stdout,
    ):
        exit_code = stdio_server.main()
    if exit_code != 0:
        raise AssertionError(f"stdio main returned {exit_code} while testing parse error")
    return json.loads(stdout.getvalue())


def _error_contracts_for_comparison() -> dict[str, dict]:
    real_call_tool = stdio_server.call_tool

    def delayed_call_tool(name: str, arguments: dict) -> str:
        if name in {"workspace.summary", "jobs.status"}:
            time.sleep(0.05)
        return real_call_tool(name, arguments)

    with patch.object(
        stdio_server,
        "_tool_deadline_seconds",
        return_value=0.001,
    ), patch.object(
        stdio_server,
        "call_tool",
        side_effect=delayed_call_tool,
    ):
        tool_timeout = _require_response(
            stdio_server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": "tools/call",
                    "params": {
                        "name": "workspace.summary",
                        "arguments": {"workspaceId": "acme"},
                    },
                }
            ),
            "tools/call timeout",
        )
        jobs_status_tool_timeout = _require_response(
            stdio_server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 12,
                    "method": "tools/call",
                    "params": {
                        "name": "jobs.status",
                        "arguments": {"jobId": "does-not-exist"},
                    },
                }
            ),
            "jobs.status timeout",
        )

    return {
        "parse_error": _parse_error_for_comparison(),
        "unsupported_method": _require_response(
            stdio_server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "resources/templates/list",
                }
            ),
            "resources/templates/list",
        ),
        "unknown_tool": _require_response(
            stdio_server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {"name": "nope.nope", "arguments": {}},
                }
            ),
            "tools/call unknown tool",
        ),
        "missing_required_field": _require_response(
            stdio_server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {"name": "workspace.summary", "arguments": {}},
                }
            ),
            "tools/call missing required field",
        ),
        "unknown_resource": _require_response(
            stdio_server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "resources/read",
                    "params": {"uri": "synapse://nope"},
                }
            ),
            "resources/read unknown resource",
        ),
        "unknown_background_job": _require_response(
            stdio_server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {
                        "name": "jobs.status",
                        "arguments": {"jobId": "does-not-exist"},
                    },
                }
            ),
            "tools/call unknown background job",
        ),
        "tool_timeout": tool_timeout,
        "jobs_status_tool_timeout": jobs_status_tool_timeout,
    }


def _capture_tier_one_output() -> bytes:
    output = {
        "initialize": _require_response(
            stdio_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            "initialize",
        ),
        "tools_list": _require_response(
            stdio_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            "tools/list",
        ),
        "resources_list": _require_response(
            stdio_server.handle({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}),
            "resources/list",
        ),
        "prompts_list": _require_response(
            stdio_server.handle({"jsonrpc": "2.0", "id": 4, "method": "prompts/list"}),
            "prompts/list",
        ),
        "errors": _error_contracts_for_comparison(),
    }
    return compact_json_bytes(output)


class LegacyContractTests(unittest.TestCase):
    fixtures_regenerated = False

    def setUp(self) -> None:
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        temporary_root = self.stack.enter_context(TemporaryDirectory())
        self.synapse_root = Path(temporary_root)
        self.stack.enter_context(
            patch.dict(os.environ, {"SYNAPSE_ROOT": str(self.synapse_root)}, clear=False)
        )
        self.stack.enter_context(isolated_state(self.synapse_root))

        if (
            os.environ.get("SYNAPSE_UPDATE_CONTRACTS") == "1"
            and not type(self).fixtures_regenerated
        ):
            regenerate_contract_fixtures()
            type(self).fixtures_regenerated = True

    def test_initialize_envelope_matches_fixture(self) -> None:
        actual = _require_response(
            stdio_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            "initialize",
        )
        assert_response_matches_fixture("initialize.json", actual)

    def test_tools_list_matches_fixture_and_pins_count_and_bytes(self) -> None:
        actual = _require_response(
            stdio_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            "tools/list",
        )
        assert_tools_list_matches_fixture(actual)

        tools = actual["result"]["tools"]
        self.assertEqual(len(tools), 174)
        self.assertEqual(len(json.dumps(tools, separators=(",", ":")).encode()), 99337)
        self.assertEqual(len({tool["name"] for tool in tools}), 174)

    def test_resources_list_matches_fixture(self) -> None:
        actual = _require_response(
            stdio_server.handle({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}),
            "resources/list",
        )
        assert_response_matches_fixture("resources_list.json", actual)

    def test_prompts_list_matches_fixture(self) -> None:
        actual = _require_response(
            stdio_server.handle({"jsonrpc": "2.0", "id": 4, "method": "prompts/list"}),
            "prompts/list",
        )
        assert_response_matches_fixture("prompts_list.json", actual)

    def test_error_envelopes_match_fixture(self) -> None:
        exact_errors = _error_contracts_for_comparison()
        assert_response_matches_fixture("errors.json", exact_errors)

        missing_prompt = self.synapse_root / "missing-main-prompt.md"
        with patch.object(stdio_server, "PROMPT_PATH", missing_prompt), patch.dict(
            os.environ,
            {"SYNAPSE_PROMPT_PATH": str(missing_prompt)},
            clear=False,
        ):
            generic_failure = _require_response(
                stdio_server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 10,
                        "method": "prompts/get",
                        "params": {"name": "synapse-main", "arguments": {}},
                    }
                ),
                "prompts/get generic failure",
            )

        error = generic_failure["error"]
        self.assertEqual(error["code"], -32000)
        self.assertIsInstance(error["message"], str)
        self.assertTrue(error["message"])

    def test_tool_timeout_envelope_matches_fixture(self) -> None:
        actual = _error_contracts_for_comparison()["tool_timeout"]
        expected = json.loads(fixture_bytes("errors.json"))["tool_timeout"]

        self.assertEqual(compact_json_bytes(actual), compact_json_bytes(expected))

    def test_jobs_status_timeout_message_variant_is_frozen(self) -> None:
        actual = _error_contracts_for_comparison()["jobs_status_tool_timeout"]
        expected = json.loads(fixture_bytes("errors.json"))[
            "jobs_status_tool_timeout"
        ]

        self.assertEqual(compact_json_bytes(actual), compact_json_bytes(expected))

    def test_required_confirm_omission_contract_for_all_tools(self) -> None:
        expected = json.loads(fixture_bytes("confirm_omission.json"))
        expected_names = [case["name"] for case in expected["tools"]]
        runtime_names = [
            tool["name"]
            for tool in stdio_server.TOOL_SCHEMAS
            if "confirm" in tool.get("inputSchema", {}).get("required", [])
        ]

        self.assertEqual(runtime_names, expected_names)
        self.assertEqual(len(runtime_names), 44)
        self.assertEqual(capture_confirm_omission_contract(), expected)

    def test_fixture_inventory_is_pinned(self) -> None:
        fixture_root = Path(__file__).parent / "fixtures" / "legacy_contracts"
        discovered = tuple(
            sorted(
                path.relative_to(fixture_root).as_posix()
                for path in fixture_root.rglob("*.json")
            )
        )
        expected = tuple(
            sorted(
                path.relative_to(fixture_root).as_posix()
                for path in all_contract_fixture_paths()
            )
        )

        self.assertEqual(discovered, expected)

    def test_contract_output_is_identical_across_two_distinct_synapse_roots(self) -> None:
        captures = []
        for _ in range(2):
            with TemporaryDirectory() as temporary_root:
                root = Path(temporary_root)
                with patch.dict(os.environ, {"SYNAPSE_ROOT": str(root)}, clear=False):
                    with isolated_state(root):
                        captures.append(_capture_tier_one_output())

        self.assertEqual(captures[0], captures[1])

    def test_fixtures_contain_no_environment_leakage(self) -> None:
        for path in all_contract_fixture_paths():
            text = path.read_text(encoding="utf-8")
            for value in environment_path_values():
                self.assertNotIn(
                    value,
                    text,
                    f"{path.name} contains environment value {value!r}",
                )

    def test_renaming_a_tool_fails_the_contract_test(self) -> None:
        renamed_tools = copy.deepcopy(stdio_server.TOOL_SCHEMAS)
        renamed_name = f"{renamed_tools[0]['name']}.renamed"
        renamed_tools[0]["name"] = renamed_name
        renamed_response = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"tools": renamed_tools},
        }

        with self.assertRaises(AssertionError) as caught:
            assert_tools_list_matches_fixture(renamed_response)
        self.assertIn(renamed_name, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
