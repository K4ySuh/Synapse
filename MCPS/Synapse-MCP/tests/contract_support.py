"""Shared helpers for the frozen legacy MCP contracts.

Tier-2 responses are normalized by exactly five ordered rules: the Synapse
root, ISO-8601 UTC timestamps, generated identifiers, PID values, and compact
run stamps. The residual-absolute-path check remains a final guard.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import time
from typing import Any
from unittest.mock import patch

import httpx

from http_stub import stub_httpx
from helpers import wait_for_job
from synapse_mcp.transport import stdio_server


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "legacy_contracts"
RESULT_FIXTURE_DIR = FIXTURE_DIR / "results"
FIXTURE_NAMES = (
    "initialize.json",
    "tools_list.json",
    "resources_list.json",
    "prompts_list.json",
    "errors.json",
)
RESULT_FIXTURE_NAMES = (
    "workspace_summary.json",
    "workspace_prepare_target_context.json",
    "credentials_set_confirmed.json",
    "credentials_set_unconfirmed.json",
    "credentials_list.json",
    "headers_cookies_analyze_workspace.json",
    "cors_execute_test_disabled_traffic.json",
    "cache_inspect_scope_data.json",
    "cache_clean_out_of_scope.json",
    "shodan_internetdb.json",
    "crawler_crawl_unconfirmed.json",
    "crawler_crawl_out_of_scope.json",
    "crawler_crawl_background_submitted.json",
    "jobs_status_terminal.json",
)
PATH_BEARING_RESULT_FIXTURES = (
    "workspace_summary.json",
    "credentials_set_confirmed.json",
    "credentials_list.json",
    "cors_execute_test_disabled_traffic.json",
    "cache_inspect_scope_data.json",
    "cache_clean_out_of_scope.json",
    "crawler_crawl_background_submitted.json",
    "jobs_status_terminal.json",
)
# This tuple must contain exactly the values seeded into the fixture-generation
# scenario; nothing may be added unless it is actually planted there.
CANARY_VALUES = ("CANARY-SECRET-a1b2c3",)
ALLOWED_FIXTURE_HOSTS = (
    "app.acme-demo.test",
    "127.0.0.1",
    "localhost",
    "not-authorized.acme-demo.test",
)
IDENTIFIER_KEYS = frozenset(
    {
        "jobId",
        "evidenceId",
        "evidenceIds",
        "ingestId",
        "actionId",
        "findingId",
        "candidateId",
        "replayId",
        "contextId",
        "matrixId",
        "approvalId",
        "runId",
        "exchangeEvidenceId",
    }
)
TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z"
)
PID_PATTERN = re.compile(r'"pid":\s*(?:\d+|null)')
RUN_STAMP_PATTERN = re.compile(r"\d{8}-\d{6}")
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ENVIRONMENT_PATH_VALUES = (
    "/home/",
    "/Users/",
    "/tmp/",
    "/var/",
    "/private/",
    str(REPOSITORY_ROOT),
    str(Path.home()),
)


def fixture_path(name: str) -> Path:
    if name not in FIXTURE_NAMES:
        raise ValueError(f"Unknown legacy contract fixture: {name}")
    return FIXTURE_DIR / name


def fixture_bytes(name: str) -> bytes:
    return fixture_path(name).read_bytes()


def result_fixture_path(name: str) -> Path:
    if name not in RESULT_FIXTURE_NAMES:
        raise ValueError(f"Unknown legacy result contract fixture: {name}")
    return RESULT_FIXTURE_DIR / name


def result_fixture_bytes(name: str) -> bytes:
    return result_fixture_path(name).read_bytes()


def all_contract_fixture_paths() -> tuple[Path, ...]:
    return tuple(fixture_path(name) for name in FIXTURE_NAMES) + tuple(
        result_fixture_path(name) for name in RESULT_FIXTURE_NAMES
    )


def environment_path_values() -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in ENVIRONMENT_PATH_VALUES if value))


def compact_json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def _contract_digest_message(name: str, expected_bytes: bytes, actual_bytes: bytes) -> str:
    expected_digest = hashlib.sha256(expected_bytes).hexdigest()
    actual_digest = hashlib.sha256(actual_bytes).hexdigest()
    return (
        f"{name} contract mismatch: "
        f"expected {len(expected_bytes)} bytes sha256={expected_digest}, "
        f"got {len(actual_bytes)} bytes sha256={actual_digest}"
    )


def _parse_json_container(value: str) -> dict[str, Any] | list[Any] | None:
    stripped = value.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


def _render_difference_value(value: Any) -> str:
    if value is _MISSING:
        return "<missing>"
    try:
        rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        rendered = repr(value)
    if len(rendered) > 80:
        return f"{rendered[:77]}..."
    return rendered


_MISSING = object()


def describe_json_difference(expected: Any, actual: Any, max_entries: int = 20) -> str:
    differences: list[str] = []

    def child_path(path: str, key: Any) -> str:
        if isinstance(key, int):
            return f"{path}[{key}]" if path else f"[{key}]"
        return f"{path}.{key}" if path else str(key)

    def walk(expected_value: Any, actual_value: Any, path: str) -> None:
        if isinstance(expected_value, str) and isinstance(actual_value, str):
            expected_nested = _parse_json_container(expected_value)
            actual_nested = _parse_json_container(actual_value)
            if expected_nested is not None and actual_nested is not None:
                walk(expected_nested, actual_nested, path)
                return

        if isinstance(expected_value, dict) and isinstance(actual_value, dict):
            for key in expected_value:
                next_path = child_path(path, key)
                if key not in actual_value:
                    differences.append(
                        f"{next_path}: expected "
                        f"{_render_difference_value(expected_value[key])}, got <missing>"
                    )
                else:
                    walk(expected_value[key], actual_value[key], next_path)
            for key in actual_value:
                if key not in expected_value:
                    next_path = child_path(path, key)
                    differences.append(
                        f"{next_path}: expected <missing>, got "
                        f"{_render_difference_value(actual_value[key])}"
                    )
            return

        if isinstance(expected_value, list) and isinstance(actual_value, list):
            shared_length = min(len(expected_value), len(actual_value))
            for index in range(shared_length):
                walk(expected_value[index], actual_value[index], child_path(path, index))
            for index in range(shared_length, len(expected_value)):
                next_path = child_path(path, index)
                differences.append(
                    f"{next_path}: expected "
                    f"{_render_difference_value(expected_value[index])}, got <missing>"
                )
            for index in range(shared_length, len(actual_value)):
                next_path = child_path(path, index)
                differences.append(
                    f"{next_path}: expected <missing>, got "
                    f"{_render_difference_value(actual_value[index])}"
                )
            return

        if expected_value != actual_value:
            differences.append(
                f"{path or '<root>'}: expected {_render_difference_value(expected_value)}, "
                f"got {_render_difference_value(actual_value)}"
            )

    walk(expected, actual, "")
    if not differences:
        return ""
    entry_limit = max(0, max_entries)
    rendered = differences[:entry_limit]
    remaining = len(differences) - len(rendered)
    if remaining:
        rendered.append(f"… and {remaining} more")
    return "\n".join(rendered)


def _json_contract_mismatch_message(
    name: str,
    expected_bytes: bytes,
    actual_bytes: bytes,
) -> str:
    try:
        expected = json.loads(expected_bytes)
        actual = json.loads(actual_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _contract_digest_message(name, expected_bytes, actual_bytes)
    difference = describe_json_difference(expected, actual)
    if difference:
        return f"{name} contract mismatch\n{difference}"
    return _contract_digest_message(name, expected_bytes, actual_bytes)


def assert_response_matches_fixture(name: str, actual: dict[str, Any]) -> None:
    expected_bytes = fixture_bytes(name)
    actual_bytes = compact_json_bytes(actual)
    if actual_bytes == expected_bytes:
        return
    raise AssertionError(_json_contract_mismatch_message(name, expected_bytes, actual_bytes))


def _identifier_values_in_document_order(value: Any) -> list[str]:
    identifiers: list[str] = []

    def append_identifier(key: str, identifier: str) -> None:
        if not identifier.strip():
            return
        if len(identifier) < 8:
            raise AssertionError(
                f"Identifier value for key {key!r} is unsafe for textual "
                f"normalization because it is shorter than 8 characters: "
                f"{identifier!r}"
            )
        identifiers.append(identifier)

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                if key in IDENTIFIER_KEYS:
                    if isinstance(nested, str):
                        append_identifier(key, nested)
                    elif isinstance(nested, list):
                        for element in nested:
                            if isinstance(element, str):
                                append_identifier(key, element)
                walk(nested)
            return
        if isinstance(item, list):
            for nested in item:
                walk(nested)
            return
        if isinstance(item, str):
            nested_json = _parse_json_container(item)
            if nested_json is not None:
                walk(nested_json)

    walk(value)
    return identifiers


def _replace_pid_values(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _replace_pid_values(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_replace_pid_values(nested) for nested in value]
    if isinstance(value, str):
        return PID_PATTERN.sub('"pid":"<PID>"', value)
    return value


def normalize_result_response(response_text: str, synapse_root: str | Path) -> str:
    parsed = json.loads(response_text)
    normalized = response_text.replace(str(synapse_root), "<ROOT>")
    normalized = TIMESTAMP_PATTERN.sub("<TS>", normalized)

    identifier_map: dict[str, str] = {}
    for identifier in _identifier_values_in_document_order(parsed):
        if identifier not in identifier_map:
            identifier_map[identifier] = f"<ID:{len(identifier_map) + 1}>"
    for identifier in sorted(identifier_map, key=len, reverse=True):
        normalized = normalized.replace(identifier, identifier_map[identifier])

    normalized = PID_PATTERN.sub('"pid":"<PID>"', normalized)
    # Tool payloads are serialized JSON strings inside the MCP envelope, so the
    # same key-anchored rule must also run within parsed string values.
    normalized = json.dumps(
        _replace_pid_values(json.loads(normalized)),
        separators=(",", ":"),
    )
    normalized = RUN_STAMP_PATTERN.sub("<STAMP>", normalized)

    residual = [value for value in environment_path_values() if value in normalized]
    if residual:
        raise AssertionError(
            "Normalized result contains residual absolute path marker(s): "
            + ", ".join(repr(value) for value in residual)
        )
    return normalized


def assert_result_response_matches_fixture(
    name: str,
    actual_response_text: str,
    synapse_root: str | Path,
) -> None:
    expected_bytes = result_fixture_bytes(name)
    actual_bytes = normalize_result_response(actual_response_text, synapse_root).encode()
    if actual_bytes == expected_bytes:
        return
    raise AssertionError(_json_contract_mismatch_message(name, expected_bytes, actual_bytes))


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
    real_call_tool = stdio_server.call_tool

    def delayed_call_tool(name: str, arguments: dict[str, Any]) -> str:
        if name == "workspace.summary":
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
        "tool_timeout": tool_timeout,
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


def _result_tool_call_for_regeneration(
    request_id: int,
    name: str,
    arguments: dict[str, Any],
    *,
    expect_error: bool = False,
) -> dict[str, Any]:
    response = _require_response(
        stdio_server.handle(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        ),
        name,
    )
    if expect_error:
        if "error" not in response:
            raise AssertionError(f"{name} unexpectedly succeeded during result regeneration")
    elif "error" in response:
        raise AssertionError(
            f"{name} failed during result regeneration: {response['error']}"
        )
    return response


def _result_contracts_for_regeneration() -> dict[str, str]:
    _result_tool_call_for_regeneration(
        101,
        "scope.set",
        {
            "hosts": [ALLOWED_FIXTURE_HOSTS[0], ALLOWED_FIXTURE_HOSTS[1]],
            "organization": "Acme Demo",
        },
    )
    _result_tool_call_for_regeneration(
        102,
        "workspace.create",
        {"workspaceId": "acme"},
    )
    _result_tool_call_for_regeneration(
        103,
        "workspace.add_target",
        {
            "workspaceId": "acme",
            "target": ALLOWED_FIXTURE_HOSTS[0],
        },
    )

    credential_arguments = {
        "id": "c1",
        "type": "header",
        "scopes": [ALLOWED_FIXTURE_HOSTS[0]],
        "secret": CANARY_VALUES[0],
        "headerName": "Authorization",
        "username": "svc-demo",
    }
    captures = {
        "workspace_summary.json": _result_tool_call_for_regeneration(
            201,
            "workspace.summary",
            {"workspaceId": "acme"},
        ),
        "workspace_prepare_target_context.json": _result_tool_call_for_regeneration(
            202,
            "workspace.prepare_target_context",
            {
                "workspaceId": "acme",
                "target": ALLOWED_FIXTURE_HOSTS[0],
            },
        ),
        "credentials_set_confirmed.json": _result_tool_call_for_regeneration(
            203,
            "credentials.set",
            {**credential_arguments, "confirm": True},
        ),
        "credentials_set_unconfirmed.json": _result_tool_call_for_regeneration(
            204,
            "credentials.set",
            credential_arguments,
            expect_error=True,
        ),
        "credentials_list.json": _result_tool_call_for_regeneration(
            205,
            "credentials.list",
            {},
        ),
    }

    analyzer_seed = json.dumps(
        {
            "hosts": [
                {
                    "host": ALLOWED_FIXTURE_HOSTS[0],
                    "urls": [
                        {
                            "url": f"https://{ALLOWED_FIXTURE_HOSTS[0]}/app",
                            "methods": ["GET"],
                            "statusCodes": [200],
                            "responseHeaders": {"content-type": "text/html"},
                            "responseCookieFlags": [
                                {
                                    "name": "sessionid",
                                    "httpOnly": False,
                                    "secure": False,
                                    "sameSite": "",
                                }
                            ],
                        }
                    ],
                }
            ],
            "summary": {"hostCount": 1, "urlCount": 1, "formCount": 0},
        },
        separators=(",", ":"),
    )
    _result_tool_call_for_regeneration(
        106,
        "workspace.ingest_data",
        {
            "workspaceId": "acme",
            "target": ALLOWED_FIXTURE_HOSTS[0],
            "source": "sitemap",
            "dataType": "tool_output",
            "format": "json",
            "rawData": analyzer_seed,
        },
    )

    cache_fixture_dir = (
        Path(os.environ["SYNAPSE_ROOT"]) / "workspaces" / "cache-fixture"
    )
    cache_fixture_dir.mkdir(parents=True)
    (cache_fixture_dir / "history.jsonl").write_text(
        json.dumps(
            {"host": ALLOWED_FIXTURE_HOSTS[3]},
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )

    captures["headers_cookies_analyze_workspace.json"] = (
        _result_tool_call_for_regeneration(
            206,
            "headers_cookies.analyze_workspace",
            {
                "workspaceId": "acme",
                "target": ALLOWED_FIXTURE_HOSTS[0],
                "ingest": False,
            },
        )
    )
    captures["cors_execute_test_disabled_traffic.json"] = (
        _result_tool_call_for_regeneration(
            207,
            "cors.execute_test",
            {
                "workspaceId": "acme",
                "url": f"http://{ALLOWED_FIXTURE_HOSTS[0]}/api",
                "method": "GET",
                "disableTraffic": True,
                "confirm": True,
            },
        )
    )
    captures["cache_inspect_scope_data.json"] = (
        _result_tool_call_for_regeneration(
            208,
            "cache.inspect_scope_data",
            {},
        )
    )
    captures["cache_clean_out_of_scope.json"] = (
        _result_tool_call_for_regeneration(
            209,
            "cache.clean_out_of_scope",
            {"confirm": True},
        )
    )

    def internetdb_response(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "ip": ALLOWED_FIXTURE_HOSTS[1],
                "hostnames": [ALLOWED_FIXTURE_HOSTS[0]],
                "ports": [80, 443],
                "cpes": ["cpe:2.3:a:acme:demo:1.0:*:*:*:*:*:*:*"],
                "vulns": ["CVE-2025-0001"],
                "tags": ["fixture"],
            },
        )

    with stub_httpx(internetdb_response):
        captures["shodan_internetdb.json"] = (
            _result_tool_call_for_regeneration(
                210,
                "shodan.internetdb",
                {
                    "ip": ALLOWED_FIXTURE_HOSTS[1],
                    "ingest": False,
                    "confirm": True,
                },
            )
        )
    captures["crawler_crawl_unconfirmed.json"] = (
        _result_tool_call_for_regeneration(
            211,
            "crawler.crawl",
            {
                "target": f"http://{ALLOWED_FIXTURE_HOSTS[0]}",
                "workspaceId": "acme",
            },
            expect_error=True,
        )
    )
    captures["crawler_crawl_out_of_scope.json"] = (
        _result_tool_call_for_regeneration(
            212,
            "crawler.crawl",
            {
                "target": f"http://{ALLOWED_FIXTURE_HOSTS[3]}",
                "workspaceId": "acme",
                "confirm": True,
                "disableTraffic": True,
            },
            expect_error=True,
        )
    )
    background_root = Path(os.environ["SYNAPSE_ROOT"])
    background_environment = {
        "SYNAPSE_DATA_DIR": str(background_root),
        "SYNAPSE_DUMP_DIR": str(background_root / "workspaces"),
        "SYNAPSE_REPORTS_DIR": str(background_root / "reports"),
        "SYNAPSE_PROMPT_PATH": str(background_root / "AGENTS.md"),
    }
    with patch.dict(os.environ, background_environment, clear=False):
        background_submission = _result_tool_call_for_regeneration(
            213,
            "crawler.crawl",
            {
                "target": f"http://{ALLOWED_FIXTURE_HOSTS[0]}",
                "workspaceId": "acme",
                "confirm": True,
                "disableTraffic": True,
                "background": True,
            },
        )
        try:
            background_payload = json.loads(
                background_submission["result"]["content"][0]["text"]
            )
            job_id = background_payload["job"]["jobId"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise AssertionError(
                "crawler.crawl returned an invalid background submission payload"
            ) from exc
        if not isinstance(job_id, str) or len(job_id) < 8:
            raise AssertionError("crawler.crawl returned an unsafe background jobId")
        wait_for_job(job_id, timeout_seconds=60)
        captures["crawler_crawl_background_submitted.json"] = background_submission
        captures["jobs_status_terminal.json"] = _result_tool_call_for_regeneration(
            214,
            "jobs.status",
            {"jobId": job_id},
        )
    return {
        name: stdio_server.json_line(response)
        for name, response in captures.items()
    }


def regenerate_result_contract_fixtures(synapse_root: str | Path) -> None:
    """Capture Tier-2 fixtures independently from their comparison scenario."""

    captures = _result_contracts_for_regeneration()
    normalized: dict[str, str] = {}
    for name, response_text in captures.items():
        try:
            fixture_text = normalize_result_response(response_text, synapse_root)
        except AssertionError as exc:
            raise AssertionError(f"{name}: {exc}") from exc
        leaked_canaries = [canary for canary in CANARY_VALUES if canary in fixture_text]
        if leaked_canaries:
            raise AssertionError(
                f"{name} contains planted canary value(s): "
                + ", ".join(leaked_canaries)
            )
        normalized[name] = fixture_text

    RESULT_FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    for name, fixture_text in normalized.items():
        result_fixture_path(name).write_text(fixture_text, encoding="utf-8")
