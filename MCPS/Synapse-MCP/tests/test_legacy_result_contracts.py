"""Normalized-exact Tier-2 result contracts for the legacy Synapse MCP server.

Regenerate both contract tiers deliberately with:

    SYNAPSE_UPDATE_CONTRACTS=1 bin/test --core -k contracts

The comparison scenario below is deliberately separate from the regeneration
scenario in ``contract_support``. Fixtures preserve the serialized MCP response
and the indented JSON inside text content, modulo only the five declared
normalization rules.

The environment-dependent ``-32000`` response and
``jobs.status(includeResult=True)`` are shape-asserted rather than frozen. The
latter embeds the interpreter path in ``run.command`` and ``run.shellCommand``.
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

import httpx

from contract_support import (
    ALLOWED_FIXTURE_HOSTS,
    CANARY_VALUES,
    PATH_BEARING_RESULT_FIXTURES,
    RESULT_FIXTURE_NAMES,
    all_contract_fixture_paths,
    assert_response_matches_fixture,
    assert_result_response_matches_fixture,
    describe_json_difference,
    fixture_bytes,
    normalize_result_response,
    regenerate_result_contract_fixtures,
    result_fixture_path,
)
from helpers import isolated_state, wait_for_job
from http_stub import stub_httpx
from synapse_mcp.transport import stdio_server


FORBIDDEN_PUBLIC_HOST_PATTERN = re.compile(
    r"(?i)\b(?:[a-z0-9-]+\.)+"
    r"(?:com|net|org|io|dev|app|cloud|ai|co|edu|gov|uk|ie)\b"
)
RESIDUAL_GENERATED_IDENTIFIER_PATTERN = re.compile(
    r"(?:"
    r"(?:ev|ing|act|job)_\d{8}-\d{6}"
    r"|finding-\d{8}-\d{6}"
    r"|acr_[0-9a-f]+_[0-9a-f]{8}\b"
    r")"
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
            "hosts": [ALLOWED_FIXTURE_HOSTS[0], ALLOWED_FIXTURE_HOSTS[1]],
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
    _result_tool_call_for_comparison(
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
        _result_tool_call_for_comparison(
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
        _result_tool_call_for_comparison(
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
    captures["cache_inspect_scope_data.json"] = _result_tool_call_for_comparison(
        208,
        "cache.inspect_scope_data",
        {},
    )
    captures["cache_clean_out_of_scope.json"] = _result_tool_call_for_comparison(
        209,
        "cache.clean_out_of_scope",
        {"confirm": True},
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
        captures["shodan_internetdb.json"] = _result_tool_call_for_comparison(
            210,
            "shodan.internetdb",
            {
                "ip": ALLOWED_FIXTURE_HOSTS[1],
                "ingest": False,
                "confirm": True,
            },
        )
    captures["crawler_crawl_unconfirmed.json"] = (
        _result_tool_call_for_comparison(
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
        _result_tool_call_for_comparison(
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
        background_submission = _result_tool_call_for_comparison(
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
        captures["jobs_status_terminal.json"] = _result_tool_call_for_comparison(
            214,
            "jobs.status",
            {"jobId": job_id},
        )
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

    def test_normalizer_replaces_pid_and_run_stamps_after_identifiers(self) -> None:
        job_id = "job_20260729-161430_crawler-crawl_fixture"
        response = json.dumps(
            {
                "jobId": job_id,
                "pid": 12345,
                "resultPath": "/fixture/20260729-161430-result.json",
                "related": job_id,
            },
            separators=(",", ":"),
        )

        normalized = normalize_result_response(response, self.synapse_root)

        self.assertEqual(
            normalized,
            '{"jobId":"<ID:1>","pid":"<PID>",'
            '"resultPath":"/fixture/<STAMP>-result.json","related":"<ID:1>"}',
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

    def test_normalizer_skips_empty_identifier_values(self) -> None:
        response = json.dumps(
            {
                "candidateId": "",
                "evidenceIds": ["   "],
                "note": "unchanged",
            },
            separators=(",", ":"),
        )

        normalized = normalize_result_response(response, self.synapse_root)

        self.assertEqual(normalized, response)
        self.assertEqual(json.loads(normalized), json.loads(response))
        self.assertNotIn("<ID:", normalized)

    def test_normalizer_raises_on_unsafely_short_identifier(self) -> None:
        response = json.dumps(
            {
                "jobId": "c1",
                "note": "account c1 is a specific c1 reference",
            },
            separators=(",", ":"),
        )

        with self.assertRaises(AssertionError) as caught:
            normalize_result_response(response, self.synapse_root)

        self.assertIn("jobId", str(caught.exception))
        self.assertIn("'c1'", str(caught.exception))

    def test_normalizer_does_not_rewrite_unrelated_text(self) -> None:
        response = json.dumps(
            {
                "jobId": "generated-job-123",
                "note": "account c1 is a specific c1 reference",
            },
            separators=(",", ":"),
        )

        normalized = normalize_result_response(response, self.synapse_root)

        self.assertEqual(
            normalized,
            '{"jobId":"<ID:1>","note":"account c1 is a specific c1 reference"}',
        )

    def test_result_fixtures_match_after_normalization(self) -> None:
        captures = _result_contracts_for_comparison()

        for name, response_text in captures.items():
            assert_result_response_matches_fixture(
                name,
                response_text,
                self.synapse_root,
            )

    def test_background_submission_matches_fixture(self) -> None:
        captures = _result_contracts_for_comparison()

        assert_result_response_matches_fixture(
            "crawler_crawl_background_submitted.json",
            captures["crawler_crawl_background_submitted.json"],
            self.synapse_root,
        )

    def test_jobs_status_terminal_matches_fixture(self) -> None:
        captures = _result_contracts_for_comparison()

        assert_result_response_matches_fixture(
            "jobs_status_terminal.json",
            captures["jobs_status_terminal.json"],
            self.synapse_root,
        )

    def test_jobs_status_include_result_shape_is_asserted_not_frozen(self) -> None:
        captures = _result_contracts_for_comparison()
        submission_response = json.loads(
            captures["crawler_crawl_background_submitted.json"]
        )
        submission = json.loads(
            submission_response["result"]["content"][0]["text"]
        )
        terminal_response = json.loads(captures["jobs_status_terminal.json"])
        terminal = json.loads(terminal_response["result"]["content"][0]["text"])
        included_response = _result_tool_call_for_comparison(
            215,
            "jobs.status",
            {
                "jobId": submission["job"]["jobId"],
                "includeResult": True,
            },
        )
        included = json.loads(included_response["result"]["content"][0]["text"])

        self.assertNotIn("result", terminal)
        self.assertIn("result", included)
        command = included["run"]["command"]
        self.assertIsInstance(command, list)
        self.assertTrue(command)
        self.assertIsInstance(command[0], str)
        # The interpreter path here makes the full includeResult envelope unfreezable.
        self.assertTrue(command[0])
        self.assertEqual(included["result"]["summary"], terminal["resultSummary"])

    def test_live_background_fields_have_expected_types(self) -> None:
        captures = _result_contracts_for_comparison()
        submission_response = json.loads(
            captures["crawler_crawl_background_submitted.json"]
        )
        submission = json.loads(
            submission_response["result"]["content"][0]["text"]
        )
        terminal_response = json.loads(captures["jobs_status_terminal.json"])
        terminal = json.loads(terminal_response["result"]["content"][0]["text"])
        job_id = submission["job"]["jobId"]

        self.assertIsInstance(terminal["pid"], int)
        self.assertIsInstance(job_id, str)
        self.assertGreaterEqual(len(job_id), 8)
        self.assertEqual(terminal["jobId"], job_id)

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

    def test_no_fixture_contains_a_residual_generated_identifier(self) -> None:
        for path in all_contract_fixture_paths():
            text = path.read_text(encoding="utf-8")
            matches = RESIDUAL_GENERATED_IDENTIFIER_PATTERN.findall(text)
            self.assertEqual(
                matches,
                [],
                f"{path.name} contains residual generated identifier(s): {matches}",
            )

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

    def test_active_tool_gates_are_frozen(self) -> None:
        approval = json.loads(
            result_fixture_path("crawler_crawl_unconfirmed.json").read_text(
                encoding="utf-8"
            )
        )
        out_of_scope = json.loads(
            result_fixture_path("crawler_crawl_out_of_scope.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertIn("error", approval)
        self.assertIn("error", out_of_scope)
        self.assertEqual(approval["error"]["code"], -32001)
        self.assertEqual(out_of_scope["error"]["code"], -32002)
        self.assertIn("confirm=true", approval["error"]["message"])

    def test_third_party_fixture_uses_no_real_network(self) -> None:
        real_client = httpx.Client

        def guarded_client(*args, **kwargs):
            if not isinstance(kwargs.get("transport"), httpx.MockTransport):
                raise AssertionError("httpx.Client constructed without MockTransport")
            return real_client(*args, **kwargs)

        with patch.object(httpx, "Client", guarded_client):
            captures = _result_contracts_for_comparison()

        self.assertIn("shodan_internetdb.json", captures)

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

        cors_response = json.loads(
            captures["cors_execute_test_disabled_traffic.json"]
        )
        cors_payload = json.loads(cors_response["result"]["content"][0]["text"])
        cors_payload["test"]["assessment"] = "changed-assessment"
        cors_response["result"]["content"][0]["text"] = json.dumps(
            cors_payload,
            indent=2,
        )
        mutated_cors_response = json.dumps(cors_response, separators=(",", ":"))

        with self.assertRaises(AssertionError) as cors_caught:
            assert_result_response_matches_fixture(
                "cors_execute_test_disabled_traffic.json",
                mutated_cors_response,
                self.synapse_root,
            )
        self.assertIn(
            "result.content[0].text.test.assessment",
            str(cors_caught.exception),
        )


if __name__ == "__main__":
    unittest.main()
