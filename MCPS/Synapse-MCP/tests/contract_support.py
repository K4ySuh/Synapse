from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from synapse_mcp.transport import stdio_server


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "legacy_contracts"
FIXTURE_NAMES = (
    "initialize.json",
    "tools_list.json",
    "resources_list.json",
    "prompts_list.json",
    "errors.json",
)


def fixture_path(name: str) -> Path:
    if name not in FIXTURE_NAMES:
        raise ValueError(f"Unknown legacy contract fixture: {name}")
    return FIXTURE_DIR / name


def fixture_bytes(name: str) -> bytes:
    return fixture_path(name).read_bytes()


def compact_json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def assert_response_matches_fixture(name: str, actual: dict[str, Any]) -> None:
    expected_bytes = fixture_bytes(name)
    actual_bytes = compact_json_bytes(actual)
    if actual_bytes == expected_bytes:
        return
    expected_digest = hashlib.sha256(expected_bytes).hexdigest()
    actual_digest = hashlib.sha256(actual_bytes).hexdigest()
    raise AssertionError(
        f"{name} contract mismatch: "
        f"expected {len(expected_bytes)} bytes sha256={expected_digest}, "
        f"got {len(actual_bytes)} bytes sha256={actual_digest}"
    )


def _response_tools(response: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        tools = response["result"]["tools"]
    except (KeyError, TypeError) as exc:
        raise AssertionError("tools/list response does not contain result.tools") from exc
    if not isinstance(tools, list) or not all(isinstance(tool, dict) for tool in tools):
        raise AssertionError("tools/list result.tools must be a list of objects")
    return tools


def _tool_names(tools: list[dict[str, Any]]) -> list[str]:
    return [str(tool.get("name", "<missing-name>")) for tool in tools]


def assert_tools_list_matches_fixture(actual: dict[str, Any]) -> None:
    expected_bytes = fixture_bytes("tools_list.json")
    actual_bytes = compact_json_bytes(actual)
    if actual_bytes == expected_bytes:
        return

    try:
        expected = json.loads(expected_bytes)
    except json.JSONDecodeError as exc:
        raise AssertionError("tools_list.json is not valid JSON") from exc

    expected_tools = _response_tools(expected)
    actual_tools = _response_tools(actual)
    expected_names = _tool_names(expected_tools)
    actual_names = _tool_names(actual_tools)
    expected_by_name = {name: tool for name, tool in zip(expected_names, expected_tools)}
    actual_by_name = {name: tool for name, tool in zip(actual_names, actual_tools)}

    added = set(actual_by_name) - set(expected_by_name)
    removed = set(expected_by_name) - set(actual_by_name)
    changed = {
        name
        for name in set(expected_by_name) & set(actual_by_name)
        if expected_by_name[name] != actual_by_name[name]
    }

    expected_positions = {name: index for index, name in enumerate(expected_names)}
    actual_positions = {name: index for index, name in enumerate(actual_names)}
    changed.update(
        name
        for name in set(expected_positions) & set(actual_positions)
        if expected_positions[name] != actual_positions[name]
    )

    expected_duplicates = {name for name in expected_names if expected_names.count(name) > 1}
    actual_duplicates = {name for name in actual_names if actual_names.count(name) > 1}
    changed.update(expected_duplicates | actual_duplicates)

    def render(names: set[str]) -> str:
        return ", ".join(sorted(names)) if names else "<none>"

    raise AssertionError(
        "tools/list contract mismatch\n"
        f"added: {render(added)}\n"
        f"removed: {render(removed)}\n"
        f"changed: {render(changed)}"
    )


def _require_response(response: dict[str, Any] | None, method: str) -> dict[str, Any]:
    if response is None:
        raise AssertionError(f"{method} unexpectedly returned no response")
    return response


def _parse_error_for_regeneration() -> dict[str, Any]:
    stdout = io.StringIO()
    with patch.object(stdio_server.sys, "stdin", ["{bad json\n"]), patch.object(
        stdio_server.sys,
        "stdout",
        stdout,
    ):
        exit_code = stdio_server.main()
    if exit_code != 0:
        raise AssertionError(f"stdio main returned {exit_code} while capturing parse error")
    return json.loads(stdout.getvalue())


def _error_contracts_for_regeneration() -> dict[str, dict[str, Any]]:
    return {
        "parse_error": _parse_error_for_regeneration(),
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
    }


def regenerate_contract_fixtures() -> None:
    """Capture fixtures independently from the normal comparison code path."""

    captures = {
        "initialize.json": _require_response(
            stdio_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            "initialize",
        ),
        "tools_list.json": _require_response(
            stdio_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            "tools/list",
        ),
        "resources_list.json": _require_response(
            stdio_server.handle({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}),
            "resources/list",
        ),
        "prompts_list.json": _require_response(
            stdio_server.handle({"jsonrpc": "2.0", "id": 4, "method": "prompts/list"}),
            "prompts/list",
        ),
        "errors.json": _error_contracts_for_regeneration(),
    }

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    for name, capture in captures.items():
        fixture_path(name).write_bytes(json.dumps(capture, separators=(",", ":")).encode())
