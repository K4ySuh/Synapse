"""Normalized-exact Tier-2 result contracts for the legacy Synapse MCP server.

Regenerate both contract tiers deliberately with:

    SYNAPSE_UPDATE_CONTRACTS=1 bin/test --core -k contracts

The comparison scenario below is deliberately separate from the regeneration
scenario in ``contract_support``. Fixtures preserve the serialized MCP response
and the indented JSON inside text content, modulo only the three declared
normalization rules.
"""

from __future__ import annotations

import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from contract_support import (
    ALLOWED_FIXTURE_HOSTS,
    CANARY_VALUES,
    PATH_BEARING_RESULT_FIXTURES,
    RESULT_FIXTURE_NAMES,
    assert_response_matches_fixture,
    assert_result_response_matches_fixture,
    describe_json_difference,
    fixture_bytes,
    normalize_result_response,
    regenerate_result_contract_fixtures,
    result_fixture_path,
)
from helpers import isolated_state
from synapse_mcp.transport import stdio_server


FORBIDDEN_PUBLIC_HOST_PATTERN = re.compile(
    r"(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|org|io)\b"
)
HOST_VALUE_KEYS = frozenset({"target", "host", "hostname"})
HOST_LIST_KEYS = frozenset({"hosts", "scopes"})


def _require_response(response: dict | None, method: str) -> dict:
    if response is None:
        raise AssertionError(f"{method} unexpectedly returned no response")
    return response


def _result_tool_call_for_comparison(
    request_id: int,
    name: str,
    arguments: dict,
    *,
    expect_error: bool = False,
) -> dict:
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
            raise AssertionError(f"{name} unexpectedly succeeded during comparison")
    elif "error" in response:
        raise AssertionError(f"{name} failed during comparison: {response['error']}")
    return response


def _result_contracts_for_comparison() -> dict[str, str]:
    _result_tool_call_for_comparison(
        101,
        "scope.set",
        {
            "hosts": [ALLOWED_FIXTURE_HOSTS[0]],
            "organization": "Acme Demo",
        },
    )
    _result_tool_call_for_comparison(
        102,
        "workspace.create",
        {"workspaceId": "acme"},
    )
    _result_tool_call_for_comparison(
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
        "workspace_summary.json": _result_tool_call_for_comparison(
            201,
            "workspace.summary",
            {"workspaceId": "acme"},
        ),
        "workspace_prepare_target_context.json": _result_tool_call_for_comparison(
            202,
            "workspace.prepare_target_context",
            {
                "workspaceId": "acme",
                "target": ALLOWED_FIXTURE_HOSTS[0],
            },
        ),
        "credentials_set_confirmed.json": _result_tool_call_for_comparison(
            203,
            "credentials.set",
            {**credential_arguments, "confirm": True},
        ),
        "credentials_set_unconfirmed.json": _result_tool_call_for_comparison(
            204,
            "credentials.set",
            credential_arguments,
            expect_error=True,
        ),
        "credentials_list.json": _result_tool_call_for_comparison(
            205,
            "credentials.list",
            {},
        ),
    }
    return {
        name: stdio_server.json_line(response)
        for name, response in captures.items()
    }


def _parse_nested_json(value):
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


def _host_value(value: str) -> str:
    parsed = urlsplit(value if "://" in value else f"//{value}")
    return parsed.hostname or value


def _fixture_hosts(value) -> set[str]:
    hosts: set[str] = set()

    def walk(item) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                if key in HOST_VALUE_KEYS and isinstance(nested, str):
                    hosts.add(_host_value(nested))
                elif key in HOST_LIST_KEYS and isinstance(nested, list):
                    hosts.update(
                        _host_value(element)
                        for element in nested
                        if isinstance(element, str)
                    )
                walk(nested)
            return
        if isinstance(item, list):
            for nested in item:
                walk(nested)
            return
        nested_json = _parse_nested_json(item)
        if nested_json is not None:
            walk(nested_json)

    walk(value)
    return hosts


class LegacyResultContractTests(unittest.TestCase):
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
            with TemporaryDirectory() as regeneration_root:
                root = Path(regeneration_root)
                with patch.dict(os.environ, {"SYNAPSE_ROOT": str(root)}, clear=False):
                    with isolated_state(root):
                        regenerate_result_contract_fixtures(root)
            type(self).fixtures_regenerated = True

    def test_normalizer_replaces_root_timestamps_and_ids_in_declared_order(self) -> None:
        timestamp = "2026-07-28T18:24:33.125Z"
        root_with_timestamp = f"/tmp/{timestamp}"
        response = json.dumps(
            {
                "path": f"{root_with_timestamp}/workspaces/acme",
                "createdAt": timestamp,
                "jobId": root_with_timestamp,
                "evidenceIds": [timestamp, "evidence-generated-456"],
            },
            separators=(",", ":"),
        )

        normalized = normalize_result_response(response, root_with_timestamp)

        self.assertEqual(
            normalized,
            '{"path":"<ROOT>/workspaces/acme","createdAt":"<TS>",'
            '"jobId":"<ROOT>","evidenceIds":["<TS>","<ID:3>"]}',
        )

    def test_normalizer_raises_on_residual_absolute_path(self) -> None:
        response = json.dumps(
            {
                "path": f"{self.synapse_root}/workspaces/acme",
                "unexpectedPath": "/private/unexpected/result.json",
            },
            separators=(",", ":"),
        )

        with self.assertRaisesRegex(AssertionError, "residual absolute path"):
            normalize_result_response(response, self.synapse_root)

    def test_normalizer_is_stable_for_repeated_identifiers(self) -> None:
        payload = json.dumps(
            {
                "jobId": "generated-job",
                "evidenceIds": ["generated-job", "generated-evidence"],
                "related": "generated-job",
            },
            indent=2,
        )
        response = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [{"type": "text", "text": payload}],
                    "isError": False,
                },
            },
            separators=(",", ":"),
        )

        normalized = normalize_result_response(response, self.synapse_root)

        self.assertEqual(normalized.count("<ID:1>"), 3)
        self.assertEqual(normalized.count("<ID:2>"), 1)
        self.assertNotIn("generated-job", normalized)
        normalized_payload = json.loads(json.loads(normalized)["result"]["content"][0]["text"])
        self.assertEqual(normalized_payload["jobId"], "<ID:1>")

    def test_result_fixtures_match_after_normalization(self) -> None:
        captures = _result_contracts_for_comparison()

        for name, response_text in captures.items():
            assert_result_response_matches_fixture(
                name,
                response_text,
                self.synapse_root,
            )

    def test_result_output_is_identical_across_two_distinct_synapse_roots(self) -> None:
        normalized_captures = []
        for _ in range(2):
            with TemporaryDirectory() as temporary_root:
                root = Path(temporary_root)
                with patch.dict(os.environ, {"SYNAPSE_ROOT": str(root)}, clear=False):
                    with isolated_state(root):
                        captures = _result_contracts_for_comparison()
                        normalized_captures.append(
                            {
                                name: normalize_result_response(response_text, root)
                                for name, response_text in captures.items()
                            }
                        )

        self.assertEqual(normalized_captures[0], normalized_captures[1])

    def test_no_fixture_contains_a_canary_value(self) -> None:
        for name in RESULT_FIXTURE_NAMES:
            text = result_fixture_path(name).read_text(encoding="utf-8")
            for canary in CANARY_VALUES:
                self.assertNotIn(canary, text, f"{name} contains planted canary")

    def test_path_bearing_fixtures_contain_the_root_placeholder(self) -> None:
        for name in PATH_BEARING_RESULT_FIXTURES:
            text = result_fixture_path(name).read_text(encoding="utf-8")
            self.assertIn("<ROOT>", text, f"{name} did not exercise root normalization")

    def test_fixtures_only_reference_allowed_fictional_hosts(self) -> None:
        allowed_hosts = set(ALLOWED_FIXTURE_HOSTS)
        for name in RESULT_FIXTURE_NAMES:
            text = result_fixture_path(name).read_text(encoding="utf-8")
            forbidden_hosts = FORBIDDEN_PUBLIC_HOST_PATTERN.findall(text)
            self.assertEqual(
                forbidden_hosts,
                [],
                f"{name} contains forbidden public-looking hostnames",
            )
            fixture_hosts = _fixture_hosts(json.loads(text))
            self.assertEqual(
                fixture_hosts - allowed_hosts,
                set(),
                f"{name} contains hosts outside the fixture allowlist",
            )

    def test_describe_json_difference_reports_changed_key_paths(self) -> None:
        expected = json.loads(fixture_bytes("initialize.json"))
        actual = copy.deepcopy(expected)
        actual["result"]["serverInfo"]["version"] = "changed-version"

        difference = describe_json_difference(expected, actual)
        self.assertIn("result.serverInfo.version", difference)
        with self.assertRaises(AssertionError) as caught:
            assert_response_matches_fixture("initialize.json", actual)
        self.assertIn("result.serverInfo.version", str(caught.exception))

    def test_changed_result_payload_fails_the_contract_test(self) -> None:
        captures = _result_contracts_for_comparison()
        response = json.loads(captures["workspace_summary.json"])
        payload = json.loads(response["result"]["content"][0]["text"])
        payload["targetCount"] = 99
        response["result"]["content"][0]["text"] = json.dumps(payload, indent=2)
        mutated_response = json.dumps(response, separators=(",", ":"))

        with self.assertRaises(AssertionError) as caught:
            assert_result_response_matches_fixture(
                "workspace_summary.json",
                mutated_response,
                self.synapse_root,
            )
        self.assertIn(
            "result.content[0].text.targetCount",
            str(caught.exception),
        )


if __name__ == "__main__":
    unittest.main()
