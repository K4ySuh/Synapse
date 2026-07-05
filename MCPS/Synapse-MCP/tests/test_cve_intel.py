import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from helpers import isolated_state
from synapse_mcp.adapters.web import cve_intel
from synapse_mcp.core import scope, workspace
from synapse_mcp.core.adapters import default_registry
from synapse_mcp.core.errors import McpError
from synapse_mcp.core.http.models import HttpResponse
from synapse_mcp.transport import stdio_server


def seed_component(version_precision: str = "exact") -> None:
    workspace.create_workspace("engagement", organization="Example", hosts=["app.example.com"])
    workspace.ingest_data(
        "engagement",
        "app.example.com",
        "adapter_result",
        "adapter_result",
        "json",
        json.dumps(
            {
                "entities": {
                    "observations": [
                        {
                            "type": "technology_component",
                            "value": "Apache httpd 2.4.49",
                            "name": "Apache httpd",
                            "version": "2.4.49",
                            "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                            "versionPrecision": version_precision,
                            "confidence": "high",
                        }
                    ]
                }
            }
        ),
    )


def nvd_record() -> dict[str, object]:
    return {
        "cveId": "CVE-2021-41773",
        "cvss": 7.5,
        "severity": "high",
        "summary": "Apache path traversal.",
        "references": [{"source": "nvd", "url": "https://nvd.example/CVE-2021-41773", "tags": []}],
        "exploitReferences": [],
        "publishedDate": "2021-10-05T00:00:00.000",
        "component": "Apache httpd",
        "version": "2.4.49",
        "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        "versionPrecision": "exact",
        "source": "nvd",
        "discoverySources": ["nvd"],
    }


class FakeSession:
    def __init__(self, response: HttpResponse):
        self.response = response
        self.requests = []

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def send(self, request):
        self.requests.append(request)
        return self.response


class CveIntelTests(unittest.TestCase):
    def setUp(self) -> None:
        cve_intel._ENDPOINT_OVERRIDES.clear()
        cve_intel._SESSION_KEYS.clear()
        cve_intel._LAST_SOURCE_STATUS.clear()
        cve_intel._LAST_FETCH_CONTEXT.clear()

    def test_correlate_requires_confirm(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                with patch.object(cve_intel, "_discover_nvd", return_value=[]) as discover:
                    with self.assertRaisesRegex(McpError, "confirm=true"):
                        cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd"]})
                discover.assert_not_called()

    def test_correlate_merges_discovery_and_enrichment(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                with patch.object(cve_intel, "_discover_nvd", return_value=[nvd_record()]), patch.object(
                    cve_intel,
                    "_enrich_cisa_kev",
                    return_value={"CVE-2021-41773": {"knownExploited": True, "source": "cisa_kev"}},
                ), patch.object(
                    cve_intel,
                    "_enrich_poc_github_index",
                    return_value={
                        "CVE-2021-41773": {
                            "pocReferences": [
                                {"source": "poc_github_index", "url": "https://github.example/poc-one", "stars": 10},
                                {"source": "poc_github_index", "url": "https://github.example/poc-two", "stars": 3},
                            ],
                            "source": "poc_github_index",
                        }
                    },
                ):
                    first = json.loads(
                        cve_intel.correlate(
                            {
                                "workspaceId": "engagement",
                                "target": "app.example.com",
                                "sources": ["nvd", "cisa_kev", "poc_github_index"],
                                "confirm": True,
                            }
                        )
                    )
                    cve_intel.correlate(
                        {
                            "workspaceId": "engagement",
                            "target": "app.example.com",
                            "sources": ["nvd", "cisa_kev", "poc_github_index"],
                            "confirm": True,
                        }
                    )

                self.assertEqual(first["candidateCount"], 1)
                candidate = first["candidates"][0]
                self.assertEqual(candidate["confidence"], "high")
                self.assertTrue(candidate["knownExploited"])
                self.assertEqual(candidate["exploitMaturity"], "in_the_wild")
                self.assertEqual(candidate["priority"], "critical")
                self.assertEqual(candidate["pocCount"], 2)
                observations = workspace._load_target_entities("engagement", "app.example.com")["observations"]
                cve_candidates = [item for item in observations if item.get("type") == "cve_candidate"]
                self.assertEqual(len(cve_candidates), 1)
                self.assertEqual(cve_candidates[0]["candidateId"], "cve_CVE-2021-41773_apache-httpd_2.4.49")

    def test_discover_nvd_parses_2_0_reference_list_exploit_tags(self) -> None:
        # Exercises the real _discover_nvd/_references_from_nvd path (not stubbed) against the
        # NVD 2.0 schema, where cve.references is a list (not the 1.0 references.referenceData
        # dict). An Exploit-tagged reference must surface and drive exploitMaturity.
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                nvd_payload = {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2021-41773",
                                "published": "2021-10-05T00:00:00.000",
                                "descriptions": [{"lang": "en", "value": "Apache path traversal."}],
                                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
                                "references": [
                                    {"url": "https://exploit.example/poc", "tags": ["Exploit"]},
                                    {"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]},
                                ],
                            }
                        }
                    ]
                }
                with patch.object(cve_intel, "_fetch_nvd", return_value=nvd_payload), patch.object(
                    cve_intel, "_enrich_cisa_kev", return_value={}
                ), patch.object(cve_intel, "_enrich_poc_github_index", return_value={}):
                    result = json.loads(
                        cve_intel.correlate(
                            {
                                "workspaceId": "engagement",
                                "target": "app.example.com",
                                "sources": ["nvd", "cisa_kev", "poc_github_index"],
                                "confirm": True,
                            }
                        )
                    )
                candidate = result["candidates"][0]
                self.assertEqual(candidate["cvssScore"], 7.5)
                exploit_urls = [ref.get("url") for ref in candidate["exploitReferences"]]
                self.assertIn("https://exploit.example/poc", exploit_urls)
                self.assertNotIn("https://vendor.example/advisory", exploit_urls)
                self.assertEqual(candidate["exploitMaturity"], "exploit_referenced")

    def test_public_poc_bumps_priority_without_kev(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                record = {**nvd_record(), "cvss": 5.0, "severity": "medium"}
                with patch.object(cve_intel, "_discover_nvd", return_value=[record]), patch.object(cve_intel, "_enrich_cisa_kev", return_value={}), patch.object(
                    cve_intel,
                    "_enrich_poc_github_index",
                    return_value={"CVE-2021-41773": {"pocReferences": [{"source": "poc_github_index", "url": "https://github.example/poc"}], "source": "poc_github_index"}},
                ):
                    result = json.loads(cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "cisa_kev", "poc_github_index"], "confirm": True}))

                candidate = result["candidates"][0]
                self.assertEqual(candidate["exploitMaturity"], "public_poc")
                self.assertEqual(candidate["priority"], "high")
                self.assertIn("public-poc", candidate["tags"])

    def test_correlate_degrades_per_source(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                with patch.object(cve_intel, "_discover_nvd", return_value=[nvd_record()]), patch.object(cve_intel, "_enrich_cisa_kev", return_value={}), patch.object(
                    cve_intel, "_enrich_poc_github_index", side_effect=RuntimeError("rate limited")
                ):
                    result = json.loads(cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "cisa_kev", "poc_github_index"], "confirm": True}))

                self.assertEqual(result["sourceStatus"]["poc_github_index"]["status"], "error")
                self.assertTrue(result["cveDataAvailable"])
                self.assertEqual(result["candidateCount"], 1)

    def test_github_search_skipped_without_token(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                with patch.object(cve_intel, "_discover_nvd", return_value=[nvd_record()]):
                    result = json.loads(cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "github_search"], "confirm": True}))
                self.assertEqual(result["sourceStatus"]["github_search"]["status"], "skipped: no token")

    def test_searchsploit_skipped_when_absent(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                with patch.object(cve_intel, "_discover_nvd", return_value=[nvd_record()]), patch.object(cve_intel.shutil, "which", return_value=None):
                    result = json.loads(cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "searchsploit"], "confirm": True}))
                self.assertEqual(result["sourceStatus"]["searchsploit"]["status"], "skipped: searchsploit not installed")

    def test_source_endpoint_resolution_precedence(self) -> None:
        cve_intel._ENDPOINT_OVERRIDES.clear()
        with patch.dict(cve_intel.os.environ, {"SYNAPSE_CVE_NVD_URL": "https://env.example/nvd"}, clear=False):
            self.assertEqual(cve_intel._resolve_source_config("nvd")["resolvedFrom"], "env")
            cve_intel.set_source_endpoint({"source": "nvd", "url": "https://override.example/nvd", "confirm": True})
            resolved = cve_intel._resolve_source_config("nvd")
            self.assertEqual(resolved["url"], "https://override.example/nvd")
            self.assertEqual(resolved["resolvedFrom"], "override")
            cve_intel.reset_source_endpoint({"source": "nvd", "confirm": True})
            resolved = cve_intel._resolve_source_config("nvd")
            self.assertEqual(resolved["url"], "https://env.example/nvd")
            self.assertEqual(resolved["resolvedFrom"], "env")

    def test_source_status_reports_url_and_http_status_on_failure(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps({"entities": {"observations": [{"type": "possible_cve", "value": "CVE-2024-0001"}]}}),
                )
                with patch.object(cve_intel, "_fetch_nvd", return_value={"httpStatus": 404, "detail": "path moved"}):
                    result = json.loads(cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "shodan"], "confirm": True}))

                self.assertEqual(result["sourceStatus"]["nvd"]["status"], "error")
                self.assertEqual(result["sourceStatus"]["nvd"]["httpStatus"], 404)
                self.assertIn("url", result["sourceStatus"]["nvd"])
                self.assertEqual(result["candidateCount"], 1)

    def test_cve_sources_tool_reflects_override(self) -> None:
        cve_intel.set_source_endpoint({"source": "nvd", "url": "https://override.example/nvd", "confirm": True})
        result = json.loads(cve_intel.sources({}))
        self.assertEqual(result["sources"]["nvd"]["url"], "https://override.example/nvd")
        self.assertEqual(result["sources"]["nvd"]["resolvedFrom"], "override")

    def test_cve_adapter_is_registered(self) -> None:
        names = {entry["name"] for entry in default_registry.list()}
        self.assertIn("cve", names)

    def test_plan_and_prepare_replay_send_no_traffic(self) -> None:
        candidate = {
            "candidateId": "cve_CVE-2021-41773_apache-httpd_2.4.49",
            "cveId": "CVE-2021-41773",
            "component": "Apache httpd",
            "version": "2.4.49",
            "exploitMaturity": "public_poc",
            "knownExploited": False,
            "pocReferences": [{"source": "poc_github_index", "url": "https://github.example/poc"}],
            "nucleiTemplate": "cves/2021/CVE-2021-41773.yaml",
        }
        with patch.object(cve_intel.http_client, "session") as session:
            plan = json.loads(cve_intel.plan_tests({"candidate": candidate, "workspaceId": "engagement", "target": "https://app.example.com/"}))
            replay = json.loads(cve_intel.prepare_replay({"candidate": candidate, "target": "https://app.example.com/"}))
        session.assert_not_called()
        self.assertEqual(plan["exploitMaturity"], "public_poc")
        self.assertIn("poc_github_index", plan["pocReferencesBySource"])
        self.assertEqual(plan["nucleiTemplate"], "cves/2021/CVE-2021-41773.yaml")
        self.assertTrue(any("Do not fetch" in item for item in plan["guardrails"]))
        self.assertEqual(replay["request"]["method"], "GET")
        self.assertIn("pocReferences", replay)

    def test_execute_test_requires_confirm_and_scope(self) -> None:
        candidate = {"candidateId": "cve_CVE-2021-41773_apache-httpd_2.4.49", "cveId": "CVE-2021-41773", "component": "Apache httpd", "version": "2.4.49"}
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["app.example.com"], "test")
                with patch.object(cve_intel.http_client, "session") as session:
                    with self.assertRaisesRegex(McpError, "confirm=true"):
                        cve_intel.execute_test({"workspaceId": "engagement", "target": "https://app.example.com/", "candidate": candidate})
                    with self.assertRaisesRegex(McpError, "not in authorized scope"):
                        cve_intel.execute_test({"workspaceId": "engagement", "target": "https://other.example.com/", "candidate": candidate, "confirm": True})
                session.assert_not_called()

    def test_execute_test_records_evidence_and_action(self) -> None:
        candidate = {"candidateId": "cve_CVE-2021-41773_apache-httpd_2.4.49", "cveId": "CVE-2021-41773", "component": "Apache httpd", "version": "2.4.49"}
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test")
                workspace.create_workspace("engagement", organization="Example", hosts=["example.com"])
                fake_session = FakeSession(HttpResponse(status=200, headers={"Server": "Apache/2.4.49"}, body="Apache httpd 2.4.49"))
                with patch.object(cve_intel.http_client, "session", return_value=fake_session):
                    result = json.loads(cve_intel.execute_test({"workspaceId": "engagement", "target": "https://example.com/", "candidate": candidate, "confirm": True}))

                self.assertEqual(result["test"]["assessment"], "possible_cve")
                self.assertTrue(result["test"]["exchangeEvidence"]["evidenceId"].startswith("ev_"))
                actions = workspace._load_target_entities("engagement", "example.com")["actions"]
                self.assertTrue(any(action.get("tool") == "cve.execute_test" for action in actions))
                self.assertEqual(len(fake_session.requests), 1)

    def test_cve_dispatch_tools_are_reachable(self) -> None:
        result = json.loads(stdio_server.call_tool("cve.session_key.status", {}))
        self.assertIn("providers", result)
