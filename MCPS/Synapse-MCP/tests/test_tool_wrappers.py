import io
import json
import os
import re
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from helpers import isolated_state, wait_for_job
from synapse_mcp.adapters.infra import nmap_adapter
from synapse_mcp.adapters import command_utils
from synapse_mcp.adapters.web import ffuf_adapter, nuclei_adapter
from synapse_mcp.core import background_jobs, credentials, scope, workspace
from synapse_mcp.core.errors import McpError
from synapse_mcp.transport import stdio_server
from synapse_mcp.transport.stdio_server import TOOL_SCHEMAS


class ToolWrapperTests(unittest.TestCase):
    def test_mcp_tools_call_validates_required_arguments(self) -> None:
        response = stdio_server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "workspace.summary", "arguments": {}},
            }
        )

        self.assertEqual(response["error"]["code"], -32602)
        self.assertIn("workspaceId", response["error"]["message"])

    def test_mcp_main_returns_parse_error_for_malformed_json(self) -> None:
        stdout = io.StringIO()
        with patch.object(stdio_server.sys, "stdin", ["{bad json\n"]), patch.object(stdio_server.sys, "stdout", stdout):
            self.assertEqual(stdio_server.main(), 0)

        response = json.loads(stdout.getvalue())
        self.assertIsNone(response["id"])
        self.assertEqual(response["error"]["code"], -32700)

    def test_mcp_tools_call_allows_extra_arguments_on_valid_call(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["example.com"])
                response = stdio_server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "workspace.summary",
                            "arguments": {"workspaceId": "engagement", "unusedExtra": True},
                        },
                    }
                )

        self.assertNotIn("error", response)
        self.assertFalse(response["result"]["isError"])

    def test_mcp_tool_validation_enforces_shapes_bounds_enums_and_reserved_fields(self) -> None:
        with self.assertRaisesRegex(McpError, "must be >= 1"):
            stdio_server.validate_tool_arguments("crawler.crawl", {"target": "https://example.com", "maxPages": 0})
        with self.assertRaisesRegex(McpError, "must be one of"):
            stdio_server.validate_tool_arguments(
                "documentation.render_layer_report",
                {"workspaceId": "engagement", "layer": "perimeter", "format": "pdf"},
            )
        with self.assertRaisesRegex(McpError, "allowed shape"):
            stdio_server.validate_tool_arguments(
                "shodan.resolve", {"hostnames": {"host": "example.com"}}
            )
        with self.assertRaisesRegex(McpError, r"hosts\[0\] must be string"):
            stdio_server.validate_tool_arguments(
                "workspace.create", {"workspaceId": "engagement", "hosts": [123]}
            )
        with self.assertRaisesRegex(McpError, "reserved for internal workers"):
            stdio_server.validate_tool_arguments(
                "crawler.crawl", {"target": "https://example.com", "_extendedMode": True}
            )

    def test_mcp_readme_tool_list_matches_runtime_schema(self) -> None:
        readme = Path("MCPS/Synapse-MCP/README.md").read_text(encoding="utf-8")
        tool_section = readme.split("## Exposed Tools", 1)[1].split("\n## ", 1)[0]
        documented = {
            line.split("`", 2)[1]
            for line in tool_section.splitlines()
            if line.startswith("- `") and line.count("`") >= 2
        }
        runtime = {str(schema["name"]) for schema in TOOL_SCHEMAS}

        self.assertEqual(runtime - documented, set())
        self.assertEqual(documented - runtime, set())

    def test_main_prompt_uses_configured_prompt_path(self) -> None:
        with TemporaryDirectory() as tmp:
            prompt = Path(tmp) / "prompt.md"
            prompt.write_text("# Configured Prompt\n", encoding="utf-8")

            with patch.object(stdio_server, "PROMPT_PATH", prompt):
                self.assertEqual(stdio_server.read_main_prompt(), "# Configured Prompt\n")

    def test_main_prompt_missing_configured_path_is_error(self) -> None:
        with TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.md"

            with patch.object(stdio_server, "PROMPT_PATH", missing), patch.dict(
                os.environ,
                {"SYNAPSE_PROMPT_PATH": str(missing)},
                clear=False,
            ):
                response = stdio_server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "prompts/get",
                        "params": {"name": "synapse-main", "arguments": {}},
                    }
                )

            self.assertEqual(response["error"]["code"], -32000)
            self.assertIn("Main prompt file not found", response["error"]["message"])

    def test_main_prompt_uses_package_guidance_outside_repository_cwd(self) -> None:
        with TemporaryDirectory() as tmp:
            packaged = Path(stdio_server.__file__).resolve().parents[1] / "operational_prompt.md"
            old_cwd = Path.cwd()
            try:
                os.chdir(tmp)
                with patch.object(stdio_server, "PROMPT_PATH", packaged), patch.dict(os.environ, {}, clear=True):
                    prompt = stdio_server.read_main_prompt()
            finally:
                os.chdir(old_cwd)

        self.assertIn("Synapse is a local-first MCP control plane", prompt)
        self.assertIn("Lease expiry makes a claim reclaimable", prompt)
        self.assertNotIn("repository-development", prompt)

    def test_implementation_map_documents_every_registered_adapter(self) -> None:
        from synapse_mcp.core.adapters import default_registry

        doc = Path("docs/Implementation-Map.md").read_text(encoding="utf-8")
        section = doc.split("### Registered Adapters", 1)[1]
        section = re.split(r"\n#{2,3} ", section, maxsplit=1)[0]
        documented = {
            line.split("`", 2)[1]
            for line in section.splitlines()
            if line.startswith("- `") and line.count("`") >= 2
        }
        registered = {str(entry["name"]) for entry in default_registry.list()}

        self.assertEqual(registered - documented, set())
        self.assertEqual(documented - registered, set())

    def test_ffuf_uses_credential_without_returning_secret(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                wordlist = tmp_path / "words.txt"
                wordlist.write_text("admin\n", encoding="utf-8")
                scope.save_scope(["example.com"], "test")
                credentials.save_credential(
                    {
                        "id": "bearer-prod",
                        "type": "bearer",
                        "scopes": ["example.com"],
                        "secret": "token-abcdef123456",
                    }
                )
                built = ffuf_adapter.build_command(
                    {
                        "target": "https://example.com/",
                        "wordlist": str(wordlist),
                        "credentialId": "bearer-prod",
                    }
                )
                serialized = json.dumps({key: value for key, value in built.items() if not key.startswith("_")})
                self.assertIn('"secret": "***"', serialized)
                self.assertNotIn("token-abcdef123456", serialized)
                self.assertIn("token-abcdef123456", json.dumps(built["_executionCommand"]))

    def test_active_scope_guard_uses_workspace_scope_before_global_scope(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                scope.save_scope(["a.example.com", "b.example.com"], "test", "Example Client")
                workspace.create_workspace("workspace-a", organization="Example Client", hosts=["a.example.com"])
                workspace.create_workspace("workspace-b", organization="Example Client", hosts=["b.example.com"])
                wordlist = tmp_path / "words.txt"
                wordlist.write_text("admin\n", encoding="utf-8")

                with self.assertRaisesRegex(McpError, "workspace workspace-a"):
                    command_utils.require_in_scope("https://b.example.com/", "workspace-a")

                with self.assertRaisesRegex(McpError, "workspace workspace-a"):
                    ffuf_adapter.build_command(
                        {
                            "target": "https://b.example.com/FUZZ",
                            "wordlist": str(wordlist),
                            "workspaceId": "workspace-a",
                        }
                    )

                built = ffuf_adapter.build_command(
                    {
                        "target": "https://b.example.com/FUZZ",
                        "wordlist": str(wordlist),
                        "workspaceId": "workspace-b",
                    }
                )
                self.assertEqual(built["scope"]["host"], "b.example.com")

    def test_ffuf_run_profile_ingests_output_file(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                scope.save_scope(["example.com"], "test", "Example Client")
                wordlist = tmp_path / "words.txt"
                output = tmp_path / "ffuf.json"
                wordlist.write_text("admin\n", encoding="utf-8")

                def fake_run_command(cmd: list[str], **_: object) -> dict[str, object]:
                    self.assertIn("-o", cmd)
                    output.write_text(
                        json.dumps({"results": [{"url": "https://example.com/admin", "status": 200}]}),
                        encoding="utf-8",
                    )
                    return {"returnCode": 0, "stdout": "", "stderr": "", "timeoutSeconds": 1}

                with patch.object(ffuf_adapter, "run_command", side_effect=fake_run_command):
                    result = json.loads(
                        ffuf_adapter.run_profile(
                            {
                                "target": "https://example.com/",
                                "wordlist": str(wordlist),
                                "workspaceId": "engagement",
                                "output": str(output),
                                "allowExternalOutput": True,
                                "background": False,
                                "confirm": True,
                            }
                        )
                    )

                self.assertEqual(result["ingestion"]["entitiesCreated"]["endpoints"], 1)
                self.assertEqual(result["ingestion"]["interestingObservations"][0]["type"], "interesting_endpoint")
                actions = json.loads(workspace.target_entity_path("engagement", "example.com", "actions").read_text(encoding="utf-8"))
                self.assertEqual(actions[0]["tool"], "ffuf")
                self.assertEqual(actions[0]["returnCode"], 0)

    def test_tool_run_without_output_persists_transcript_evidence(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                scope.save_scope(["example.com"], "test", "Example Client")
                wordlist = tmp_path / "words.txt"
                output = tmp_path / "missing-ffuf.json"
                wordlist.write_text("admin\n", encoding="utf-8")

                def fake_run_command(cmd: list[str], **_: object) -> dict[str, object]:
                    return {
                        "command": cmd,
                        "shellCommand": "ffuf -redacted",
                        "returnCode": None,
                        "stdout": "partial stdout",
                        "stderr": "tool failed",
                        "timeoutSeconds": 1,
                        "timedOut": True,
                    }

                with patch.object(ffuf_adapter, "run_command", side_effect=fake_run_command):
                    result = json.loads(
                        ffuf_adapter.run_profile(
                            {
                                "target": "https://example.com/",
                                "wordlist": str(wordlist),
                                "workspaceId": "engagement",
                                "output": str(output),
                                "allowExternalOutput": True,
                                "background": False,
                                "approvalReason": "Approved bounded failure-path test",
                                "riskTier": "T1",
                                "confirm": True,
                            }
                        )
                    )

                self.assertEqual(result["ingestion"]["entitiesCreated"]["endpoints"], 0)
                self.assertEqual(result["ingestion"]["evidenceId"], result["action"]["action"]["evidenceId"])
                self.assertEqual(result["action"]["action"]["approval"]["riskTier"], "T1")
                self.assertTrue(result["action"]["action"]["timedOut"])
                self.assertEqual(result["action"]["action"]["timeoutSeconds"], 1)
                raw_path = Path(result["ingestion"]["rawPath"])
                raw = json.loads(raw_path.read_text(encoding="utf-8"))
                self.assertIsNone(raw["returnCode"])
                self.assertEqual(raw["stderr"], "tool failed")
                self.assertTrue(raw["timedOut"])
                self.assertEqual(raw["timeoutSeconds"], 1)

    def test_nmap_run_profile_ingests_xml_output(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                scope.save_scope(["example.com"], "test", "Example Client")
                output_base = tmp_path / "nmap-result"

                def fake_run_command(cmd: list[str], **_: object) -> dict[str, object]:
                    self.assertIn("-oA", cmd)
                    Path(f"{output_base}.xml").write_text(
                        (
                            "<nmaprun><host><address addr=\"203.0.113.10\"/>"
                            "<ports><port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/>"
                            "<service name=\"https\" product=\"nginx\"/></port></ports>"
                            "</host></nmaprun>"
                        ),
                        encoding="utf-8",
                    )
                    return {"returnCode": 0, "stdout": "", "stderr": "", "timeoutSeconds": 1}

                with patch.object(nmap_adapter, "run_command", side_effect=fake_run_command):
                    result = json.loads(
                        nmap_adapter.run_profile(
                            {
                                "target": "example.com",
                                "workspaceId": "engagement",
                                "outputBase": str(output_base),
                                "allowExternalOutput": True,
                                "background": False,
                                "confirm": True,
                            }
                        )
                    )

                self.assertEqual(result["ingestion"]["entitiesCreated"]["services"], 1)
                context = workspace.prepare_target_context("engagement", "example.com")
                self.assertEqual(context["knownServices"][0]["name"], "https")
                actions = json.loads(workspace.target_entity_path("engagement", "example.com", "actions").read_text(encoding="utf-8"))
                self.assertEqual(actions[0]["tool"], "nmap")
                self.assertEqual(actions[0]["returnCode"], 0)

    def test_ffuf_and_nmap_run_profiles_default_to_background_jobs(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                scope.save_scope(["example.com"], "test", "Example Client")
                wordlist = tmp_path / "words.txt"
                wordlist.write_text("admin\n", encoding="utf-8")

                def fake_start_background_command(cmd: list[str], **kwargs: object) -> dict[str, object]:
                    tool_name = str(kwargs["tool"])
                    expected_flag = "-o" if tool_name == "ffuf.run_profile" else "-oA"
                    self.assertIn(expected_flag, cmd)
                    return {"jobId": f"job_{tool_name.split('.')[0]}", "status": "running", "createdAt": "2026-06-03T00:00:00Z"}

                cases = [
                    (
                        ffuf_adapter,
                        {"target": "https://example.com/", "wordlist": str(wordlist), "workspaceId": "engagement", "confirm": True},
                        "job_ffuf",
                    ),
                    (
                        nmap_adapter,
                        {"target": "example.com", "workspaceId": "engagement", "confirm": True},
                        "job_nmap",
                    ),
                ]
                for adapter, args, job_id in cases:
                    with self.subTest(tool=job_id), patch.object(adapter, "start_background_command", side_effect=fake_start_background_command):
                        result = json.loads(adapter.run_profile(args))

                    self.assertTrue(result["background"])
                    self.assertEqual(result["job"]["jobId"], job_id)

    def test_nuclei_build_command_adapts_to_workspace_context(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                raw = json.dumps(
                    {
                        "hosts": [
                            {
                                "host": "example.com",
                                "urls": [
                                    {
                                        "url": "https://example.com/api/graphql?debug=true",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                        "apiRoute": True,
                                        "jsonEndpoint": True,
                                        "graphqlEndpoint": True,
                                    },
                                    {
                                        "url": "https://example.com/login",
                                        "methods": ["POST"],
                                        "statusCodes": [403],
                                        "authBoundary": True,
                                        "stateChanging": True,
                                    },
                                ],
                                "forms": [
                                    {
                                        "pageUrl": "https://example.com/login",
                                        "method": "POST",
                                        "action": "https://example.com/login",
                                        "inputs": [{"name": "username"}, {"name": "password"}],
                                    }
                                ],
                            }
                        ],
                        "summary": {"hostCount": 1, "urlCount": 2, "formCount": 1},
                    }
                )
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)

                low = nuclei_adapter.build_command(
                    {
                        "target": "https://example.com/",
                        "workspaceId": "engagement",
                        "profile": "low_noise",
                    }
                )
                medium = nuclei_adapter.build_command(
                    {
                        "target": "https://example.com/",
                        "workspaceId": "engagement",
                        "profile": "medium",
                    }
                )
                aggressive = nuclei_adapter.build_command(
                    {
                        "target": "https://example.com/",
                        "workspaceId": "engagement",
                        "profile": "pentest_aggressive",
                    }
                )

                self.assertIn("https://example.com/api/graphql?debug=true", low["targets"])
                self.assertNotIn("https://example.com/login", low["targets"])
                self.assertIn("graphql", medium["tags"])
                self.assertIn("api", medium["tags"])
                self.assertIn("default-login", medium["tags"])
                self.assertIn("https://example.com/login", aggressive["targets"])
                self.assertIn("fuzz", aggressive["tags"])
                self.assertIn("-jsonl", medium["command"])
                self.assertIn("-l", medium["command"])
                self.assertIn("/workspaces/engagement/targets/example.com/outputs/nuclei/", medium["output"])
                self.assertTrue(Path(medium["targetList"]).exists())
                self.assertTrue(medium["adaptation"]["targetSelection"]["contextUsed"])
                self.assertEqual(low["executionPolicy"]["processTimeoutSeconds"], 900)
                self.assertEqual(medium["executionPolicy"]["processTimeoutSeconds"], 1800)
                self.assertEqual(aggressive["executionPolicy"]["processTimeoutSeconds"], 3600)

    def test_nuclei_explicit_target_urls_use_workspace_scope(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com", "other.example.com"], "test", "Example Client")
                workspace.create_workspace("engagement", organization="Example Client", hosts=["example.com"])

                with self.assertRaisesRegex(McpError, "workspace engagement"):
                    nuclei_adapter.build_command(
                        {
                            "target": "https://example.com/",
                            "workspaceId": "engagement",
                            "targetUrls": ["https://other.example.com/admin"],
                        }
                    )

                built = nuclei_adapter.build_command(
                    {
                        "target": "https://example.com/",
                        "workspaceId": "engagement",
                        "targetUrls": ["https://example.com/admin"],
                    }
                )
                self.assertEqual(built["targets"], ["https://example.com/admin"])

    def test_active_scan_profiles_are_canonical_and_default_to_medium(self) -> None:
        expected = {"low_noise", "medium", "pentest_aggressive"}
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                scope.save_scope(["example.com"], "test", "Example Client")
                wordlist = tmp_path / "words.txt"
                wordlist.write_text("admin\n", encoding="utf-8")

                self.assertEqual(set(ffuf_adapter.PROFILES), expected)
                self.assertEqual(set(nmap_adapter.PROFILES), expected)
                self.assertEqual(set(nuclei_adapter.PROFILES), expected)
                self.assertEqual(
                    ffuf_adapter.build_command({"target": "https://example.com/", "wordlist": str(wordlist)})["profile"],
                    "medium",
                )
                self.assertEqual(nmap_adapter.build_command({"target": "example.com"})["profile"], "medium")
                self.assertEqual(nuclei_adapter.build_command({"target": "https://example.com/"})["profile"], "medium")
                tool_names = {
                    "ffuf.build_command",
                    "ffuf.run_profile",
                    "nuclei.build_command",
                    "nuclei.run_profile",
                    "nmap.build_command",
                    "nmap.run_profile",
                }
                schema_profiles = {
                    schema["name"]: schema["inputSchema"]["properties"]["profile"]
                    for schema in TOOL_SCHEMAS
                    if schema.get("name") in tool_names
                }
                self.assertEqual(set(schema_profiles), tool_names)
                self.assertTrue(all(profile["default"] == "medium" for profile in schema_profiles.values()))
                self.assertTrue(all(set(profile["enum"]) == expected for profile in schema_profiles.values()))

    def test_nuclei_run_profile_ingests_jsonl_candidates(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                scope.save_scope(["example.com"], "test", "Example Client")
                output = tmp_path / "nuclei.jsonl"

                def fake_run_command(cmd: list[str], **kwargs: object) -> dict[str, object]:
                    self.assertIn("-jsonl", cmd)
                    self.assertEqual(kwargs["timeout_seconds"], 1800)
                    output.write_text(
                        json.dumps(
                            {
                                "template-id": "exposed-panel",
                                "template-path": "http/exposures/panel.yaml",
                                "matched-at": "https://example.com/admin",
                                "matcher-name": "status",
                                "info": {
                                    "name": "Exposed Admin Panel",
                                    "severity": "medium",
                                    "description": "Admin panel responded to the probe.",
                                    "tags": ["panel", "exposure"],
                                },
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    return {"returnCode": 0, "stdout": "", "stderr": "", "timeoutSeconds": 1}

                with patch.object(nuclei_adapter, "run_command", side_effect=fake_run_command):
                    result = json.loads(
                        nuclei_adapter.run_profile(
                            {
                                "target": "https://example.com/",
                                "workspaceId": "engagement",
                                "profile": "medium",
                                "output": str(output),
                                "allowExternalOutput": True,
                                "background": False,
                                "approvalReason": "Approved medium Nuclei profile for test",
                                "riskTier": "medium",
                                "confirm": True,
                            }
                        )
                    )

                self.assertEqual(result["ingestion"]["entitiesCreated"]["observations"], 1)
                self.assertEqual(result["ingestion"]["entitiesCreated"]["findings"], 1)
                context = workspace.prepare_target_context("engagement", "example.com")
                self.assertEqual(context["candidateFindings"][0]["templateId"], "exposed-panel")
                self.assertFalse(context["candidateFindings"][0]["operatorReviewed"])
                actions = json.loads(workspace.target_entity_path("engagement", "example.com", "actions").read_text(encoding="utf-8"))
                self.assertEqual(actions[0]["tool"], "nuclei")
                self.assertEqual(actions[0]["approval"]["riskTier"], "medium")
                self.assertEqual(actions[0]["timeoutSeconds"], 1)
                self.assertFalse(actions[0]["timedOut"])
                self.assertEqual(result["executionPolicy"]["processTimeoutSeconds"], 1800)

    def test_nuclei_run_profile_starts_long_runs_as_background_job(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                scope.save_scope(["example.com"], "test", "Example Client")

                def fake_start_background_command(cmd: list[str], **kwargs: object) -> dict[str, object]:
                    self.assertIn("-jsonl", cmd)
                    self.assertEqual(kwargs["timeout_seconds"], 1800)
                    return {
                        "jobId": "job_test",
                        "status": "running",
                        "createdAt": "2026-06-03T00:00:00Z",
                        "shellCommand": "nuclei ...",
                    }

                with patch.object(nuclei_adapter, "start_background_command", side_effect=fake_start_background_command):
                    result = json.loads(
                        nuclei_adapter.run_profile(
                            {
                                "target": "https://example.com/",
                                "workspaceId": "engagement",
                                "profile": "medium",
                                "approvalReason": "Approved background Nuclei profile for test",
                                "riskTier": "medium",
                                "confirm": True,
                            }
                        )
                    )

                self.assertTrue(result["background"])
                self.assertEqual(result["job"]["jobId"], "job_test")
                self.assertEqual(result["status"], "started")
                self.assertIn("jobs.status", result["message"])

    def test_background_jobs_persist_command_status_and_output(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                job = background_jobs.start_command(
                    ["/bin/sh", "-c", "printf synapse-job-ok"],
                    timeout_seconds=10,
                    event_type="test.job",
                    summary="Ran test background command",
                    display_cmd=["test-command"],
                    tool="test.tool",
                    workspace_id="engagement",
                    target="example.com",
                )
                job = wait_for_job(job["jobId"])

                self.assertEqual(job["status"], "completed")
                self.assertEqual(job["returnCode"], 0)
                self.assertEqual(job["run"]["stdout"], "synapse-job-ok")
                self.assertIn("test-tool", job["jobId"])
                self.assertIn("example-com", job["jobId"])
                job_dir = tmp_path / "workspaces" / "engagement" / "jobs" / job["jobId"]
                self.assertTrue((job_dir / "job.json").exists())
                self.assertEqual(sorted(path.name for path in job_dir.iterdir()), ["job.json"])
                self.assertEqual(job["stdoutPath"], "")
                self.assertEqual(job["stderrPath"], "")
                self.assertEqual(job["returnCodePath"], "")
                self.assertFalse((tmp_path / "jobs").exists())
                listed = background_jobs.list_jobs()
                self.assertEqual(listed["count"], 1)
                self.assertEqual(listed["jobs"][0]["jobId"], job["jobId"])

                other = background_jobs.start_command(
                    ["/bin/sh", "-c", "true"],
                    timeout_seconds=30,
                    event_type="test.job",
                    summary="Ran other workspace command",
                    tool="test.tool",
                    workspace_id="other-engagement",
                    target="other.example.com",
                )
                other = wait_for_job(other["jobId"])

                filtered = background_jobs.list_jobs(workspace_id="engagement")
                self.assertEqual(filtered["count"], 1)
                self.assertEqual(filtered["jobs"][0]["workspaceId"], "engagement")

    def test_worker_result_finalizer_reports_missing_and_corrupt_files(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                missing_path = tmp_path / "missing-result.json"
                missing = background_jobs.start_command(
                    ["/bin/sh", "-c", "true"],
                    timeout_seconds=30,
                    event_type="test.worker",
                    summary="Ran worker missing result test",
                    tool="test.worker",
                    workspace_id="engagement",
                    target="example.com",
                    finalizer_name="worker.result",
                    finalizer_data={"resultPath": str(missing_path)},
                )
                missing = wait_for_job(missing["jobId"])

                self.assertEqual(missing["status"], "failed")
                self.assertTrue(missing["finalized"])
                self.assertTrue(missing["result"]["isError"])
                self.assertIn("missing", missing["result"]["error"])

                corrupt_path = tmp_path / "corrupt-result.json"
                corrupt_path.write_text("{not json", encoding="utf-8")
                corrupt = background_jobs.start_command(
                    ["/bin/sh", "-c", "true"],
                    timeout_seconds=30,
                    event_type="test.worker",
                    summary="Ran worker corrupt result test",
                    tool="test.worker",
                    workspace_id="engagement",
                    target="example.com",
                    finalizer_name="worker.result",
                    finalizer_data={"resultPath": str(corrupt_path)},
                )
                corrupt = wait_for_job(corrupt["jobId"])

                self.assertEqual(corrupt["status"], "failed")
                self.assertTrue(corrupt["finalized"])
                self.assertTrue(corrupt["result"]["isError"])
                self.assertIn("corrupt", corrupt["result"]["error"])

    def test_background_job_nonzero_exit_and_finalizer_failures_are_terminal(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                nonzero = background_jobs.start_command(
                    ["/bin/sh", "-c", "exit 7"],
                    timeout_seconds=30,
                    event_type="test.nonzero",
                    summary="Ran nonzero job",
                    tool="test.nonzero",
                    workspace_id="engagement",
                    target="example.com",
                )
                nonzero = wait_for_job(nonzero["jobId"])
                self.assertEqual(nonzero["status"], "failed")
                self.assertEqual(nonzero["returnCode"], 7)
                self.assertTrue(nonzero["finalized"])

                unregistered = background_jobs.start_command(
                    ["/bin/sh", "-c", "true"],
                    timeout_seconds=30,
                    event_type="test.finalizer",
                    summary="Ran missing finalizer job",
                    tool="test.finalizer",
                    workspace_id="engagement",
                    target="example.com",
                    finalizer_name="test.not-registered",
                )
                unregistered = wait_for_job(unregistered["jobId"])
                self.assertEqual(unregistered["status"], "failed")
                self.assertTrue(unregistered["finalized"])
                self.assertIn("not registered", unregistered["error"])

                finalizer_name = "test.raises"

                def raising_finalizer(*_: object) -> dict[str, object]:
                    raise RuntimeError("finalizer failed")

                background_jobs.register_finalizer(finalizer_name, raising_finalizer)
                try:
                    raised = background_jobs.start_command(
                        ["/bin/sh", "-c", "true"],
                        timeout_seconds=30,
                        event_type="test.finalizer",
                        summary="Ran raising finalizer job",
                        tool="test.finalizer",
                        workspace_id="engagement",
                        target="example.com",
                        finalizer_name=finalizer_name,
                    )
                    raised = wait_for_job(raised["jobId"])
                finally:
                    background_jobs._FINALIZERS.pop(finalizer_name, None)
                self.assertEqual(raised["status"], "failed")
                self.assertTrue(raised["finalized"])
                self.assertIn("RuntimeError: finalizer failed", raised["error"])

    def test_background_job_timeouts_are_clamped(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                low = background_jobs.start_command(
                    ["/bin/sh", "-c", "true"],
                    timeout_seconds=5,
                    event_type="test.timeout",
                    summary="Ran low timeout clamp test",
                    tool="test.timeout",
                    workspace_id="engagement",
                    target="example.com",
                )
                high = background_jobs.start_command(
                    ["/bin/sh", "-c", "true"],
                    timeout_seconds=10**9,
                    event_type="test.timeout",
                    summary="Ran high timeout clamp test",
                    tool="test.timeout",
                    workspace_id="engagement",
                    target="example.com",
                )
                self.assertEqual(low["timeoutSeconds"], 30)
                self.assertEqual(high["timeoutSeconds"], 86400)

    def test_background_job_watchdog_marks_unpolled_timeout(self) -> None:
        old_min = background_jobs.MIN_TIMEOUT_SECONDS
        background_jobs.MIN_TIMEOUT_SECONDS = 1
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    job = background_jobs.start_command(
                        ["/bin/sh", "-c", "sleep 5"],
                        timeout_seconds=1,
                        event_type="test.timeout",
                        summary="Ran watchdog timeout test",
                        tool="test.timeout",
                        workspace_id="engagement",
                        target="example.com",
                    )
                    deadline = time.monotonic() + 5
                    record = background_jobs._read_record(job["jobId"])
                    while time.monotonic() < deadline:
                        record = background_jobs._read_record(job["jobId"])
                        if record["status"] == "timed_out":
                            break
                        time.sleep(0.05)

                    self.assertEqual(record["status"], "timed_out")
                    self.assertTrue(record["timedOut"])
                    self.assertIn("watchdog", record["error"])
                    finalized = background_jobs.status(job["jobId"])
                    self.assertTrue(finalized["finalized"])
        finally:
            background_jobs.MIN_TIMEOUT_SECONDS = old_min

    def test_background_job_timeout_after_restart_does_not_kill_unknown_process_group(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                job = background_jobs.start_command(
                    ["/bin/sh", "-c", "sleep 2"],
                    timeout_seconds=1,
                    event_type="test.timeout",
                    summary="Ran timeout restart simulation",
                    tool="test.timeout",
                    workspace_id="engagement",
                    target="example.com",
                )
                proc = background_jobs._PROCESSES.pop(job["jobId"])
                try:
                    record = background_jobs._read_record(job["jobId"])
                    record["startedAt"] = "2000-01-01T00:00:00Z"
                    background_jobs._write_record(record)
                    timed_out = background_jobs.status(job["jobId"])
                finally:
                    proc.wait(timeout=3)

                self.assertEqual(timed_out["status"], "timed_out")
                self.assertTrue(timed_out["timedOut"])
                self.assertIn("process handle is unavailable", timed_out["error"])
                self.assertIn("lastObservedAt", timed_out)
                self.assertTrue(timed_out["reconciliationRequired"])
                self.assertEqual(timed_out["reconciliationReason"], "timeout_process_handle_unavailable")

    def test_run_command_timeout_kills_process_group(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                started_at = time.monotonic()
                result = command_utils.run_command(
                    ["/bin/sh", "-c", "sleep 5 & wait"],
                    timeout_seconds=1,
                    event_type="test.command_timeout",
                    summary="Ran command timeout process-group test",
                )
                elapsed = time.monotonic() - started_at

        self.assertTrue(result["timedOut"])
        self.assertIsNone(result["returnCode"])
        self.assertLess(elapsed, 3)

    def test_tool_default_outputs_are_workspace_scoped(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                scope.save_scope(["example.com"], "test", "Example Client")
                wordlist = tmp_path / "words.txt"
                wordlist.write_text("admin\n", encoding="utf-8")

                ffuf_built = ffuf_adapter.build_command(
                    {
                        "target": "https://example.com/",
                        "wordlist": str(wordlist),
                        "workspaceId": "engagement",
                    }
                )
                self.assertIn("/workspaces/engagement/targets/example.com/outputs/ffuf/", ffuf_built["output"])
                self.assertNotIn("/runs/", ffuf_built["output"])

                nmap_built = nmap_adapter.build_command({"target": "example.com", "workspaceId": "engagement"})
                self.assertIn("/workspaces/engagement/targets/example.com/outputs/nmap/", nmap_built["outputBase"])
                self.assertNotIn("/runs/", nmap_built["outputBase"])

                with self.assertRaisesRegex(Exception, "allowExternalOutput"):
                    ffuf_adapter.build_command(
                        {
                            "target": "https://example.com/",
                            "wordlist": str(wordlist),
                            "workspaceId": "engagement",
                            "output": str(tmp_path / "external.json"),
                        }
                    )



class ToolExecutorConcurrencyTests(unittest.TestCase):
    def test_executor_keeps_spare_worker_for_recovery_calls(self) -> None:
        # A timed-out tool keeps running in its worker thread (Python cannot kill
        # it). With spare workers, an orphaned thread must not starve later calls
        # such as jobs.status / jobs.cancel.
        self.assertGreaterEqual(stdio_server._TOOL_EXECUTOR_MAX_WORKERS, 2)
        started = threading.Event()
        release = threading.Event()

        def blocked() -> None:
            started.set()
            release.wait(5)

        busy = stdio_server._TOOL_EXECUTOR.submit(blocked)
        try:
            self.assertTrue(started.wait(2), "blocking task did not start")
            recovery = stdio_server._TOOL_EXECUTOR.submit(lambda: "ok")
            self.assertEqual(recovery.result(timeout=2), "ok")
        finally:
            release.set()
            busy.result(timeout=5)


if __name__ == "__main__":
    unittest.main()
