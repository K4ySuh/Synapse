import fcntl
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import isolated_state
from synapse_mcp.core import cache, evidence, perimeter, scope, workspace
from synapse_mcp.core.errors import McpError
from synapse_mcp.transport import stdio_server


class WorkspaceIngestionTests(unittest.TestCase):
    def test_workspace_lock_times_out_contending_entity_writer(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "entities": {
                            "endpoints": [
                                {
                                    "type": "endpoint",
                                    "url": "https://example.com/locked",
                                    "method": "GET",
                                }
                            ]
                        }
                    }
                )
                old_timeout = workspace.DEFAULT_WORKSPACE_LOCK_TIMEOUT_SECONDS
                workspace.DEFAULT_WORKSPACE_LOCK_TIMEOUT_SECONDS = 0.1
                try:
                    lock_path = workspace.workspace_path("engagement") / ".lock"
                    lock_path.parent.mkdir(parents=True, exist_ok=True)
                    with lock_path.open("a+", encoding="utf-8") as handle:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        with self.assertRaises(McpError) as raised:
                            workspace.ingest_data("engagement", "example.com", "adapter_result", "tool_output", "json", raw)
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                    self.assertIn("Timed out waiting for workspace lock for engagement", str(raised.exception))
                finally:
                    workspace.DEFAULT_WORKSPACE_LOCK_TIMEOUT_SECONDS = old_timeout

                result = workspace.ingest_data("engagement", "example.com", "adapter_result", "tool_output", "json", raw)
                self.assertEqual(result["entitiesCreated"]["endpoints"], 1)

    def test_workspace_ingests_ffuf_and_prepares_target_context(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                scope.save_scope(["example.com"], "test", "Example Client")
                raw = json.dumps(
                    {
                        "results": [
                            {
                                "url": "https://example.com/backup.zip",
                                "status": 200,
                                "length": 120000,
                                "words": 3,
                                "lines": 1,
                            },
                            {"url": "https://example.com/search?q=abc", "status": 200},
                        ]
                    }
                )
                result = workspace.ingest_data(
                    "client_a_external_2026",
                    "https://example.com",
                    "ffuf",
                    "tool_output",
                    "json",
                    raw,
                    {"command": "ffuf ..."},
                )
                self.assertEqual(result["entitiesCreated"]["endpoints"], 2)
                self.assertEqual(result["entitiesCreated"]["parameters"], 1)
                self.assertEqual(result["interestingObservations"][0]["type"], "sensitive_file_candidate")

                context = workspace.prepare_target_context("client_a_external_2026", "example.com")
                self.assertEqual(context["scopeStatus"], "in_scope")
                self.assertEqual(context["knownEndpoints"]["total"], 2)
                self.assertEqual(context["parameters"]["total"], 1)
                self.assertIn("request_operator_review", {item["action"] for item in context["recommendedNextActions"]})
                target_dir = workspace.target_path("client_a_external_2026", "example.com")
                self.assertTrue(workspace.target_entity_path("client_a_external_2026", "example.com", "endpoints").exists())
                self.assertFalse((target_dir / "endpoints.json").exists())

    def test_sitemap_parameters_capture_value_preview_for_query_and_form(self) -> None:
        # Regression: value-based candidate scoring (SSRF/open-redirect/LFI/SSTI)
        # and access-control value-shape detection read parameter "valuePreview".
        # Before this fix no ingestion path populated it, so those branches were
        # dead. Query values live in the stored URL already; form previews come
        # from the crawler. Both must reach the persisted parameter entity.
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "hosts": [
                            {
                                "host": "example.com",
                                "urls": [
                                    {
                                        "url": "https://example.com/fetch?url=https://internal.example/feed",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                    }
                                ],
                                "forms": [
                                    {
                                        "pageUrl": "https://example.com/import",
                                        "method": "POST",
                                        "action": "https://example.com/import",
                                        "inputs": [
                                            {"name": "source_url", "type": "url", "valuePreview": "https://partner.example/x"}
                                        ],
                                    }
                                ],
                            }
                        ],
                        "summary": {"hostCount": 1, "urlCount": 1, "formCount": 1},
                    }
                )
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)
                parameters = workspace._load_target_entities("engagement", "example.com")["parameters"]
                by_name = {item["name"]: item for item in parameters}
                self.assertEqual(by_name["url"]["valuePreview"], "https://internal.example/feed")
                self.assertEqual(by_name["source_url"]["valuePreview"], "https://partner.example/x")

    def test_workspace_create_summary_resources_and_findings(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                created = workspace.create_workspace(
                    "Client A External 2026",
                    organization="Client A",
                    notes="External test",
                    hosts=["https://app.example.com", "api.example.com"],
                )
                self.assertEqual(created["workspaceId"], "client-a-external-2026")

                workspaces = workspace.list_workspaces()
                self.assertEqual(workspaces["workspaces"][0]["organization"], "Client A")

                summary = workspace.workspace_summary("client-a-external-2026")
                self.assertEqual(summary["targetCount"], 2)
                self.assertEqual({item["target"] for item in summary["targets"]}, {"app.example.com", "api.example.com"})
                self.assertTrue(workspace.target_entity_path("client-a-external-2026", "app.example.com", "services").exists())
                self.assertFalse((workspace.target_path("client-a-external-2026", "app.example.com") / "services.json").exists())

                finding = workspace.create_finding(
                    "client-a-external-2026",
                    "app.example.com",
                    "Potential exposed backup",
                    severity="medium",
                    confidence="medium",
                    description="Operator-reviewed candidate.",
                    evidence_ids=["ev_1"],
                )
                self.assertTrue(finding["created"])

                mime_type, resource_text = workspace.read_workspace_resource(
                    "synapse://workspace/client-a-external-2026/target/app.example.com/findings"
                )
                self.assertEqual(mime_type, "application/json")
                resource = json.loads(resource_text)
                self.assertEqual(resource[0]["title"], "Potential exposed backup")
                findings_doc = Path(finding["findingsDocument"]["path"])
                self.assertTrue(findings_doc.exists())
                self.assertIn("Potential exposed backup", findings_doc.read_text(encoding="utf-8"))
                self.assertIn("Operator-reviewed candidate.", findings_doc.read_text(encoding="utf-8"))

    def test_finding_affected_assets_preserve_http_urls(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                finding = workspace.create_finding(
                    "engagement",
                    "app.example.com",
                    "Reflected input candidate",
                    affected_assets=["https://app.example.com/search?q=alpha#fragment"],
                )["finding"]

                self.assertEqual(finding["affectedAssets"], ["https://app.example.com/search?q=alpha"])

                updated = workspace.update_finding(
                    "engagement",
                    "app.example.com",
                    finding["id"],
                    {"affectedAssets": ["http://app.example.com/rest/products/search?q=banana"]},
                )["finding"]
                self.assertEqual(updated["affectedAssets"], ["http://app.example.com/rest/products/search?q=banana"])

    def test_workspace_delete_requires_confirmation_and_erases_workspace(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                created = workspace.create_workspace("Engagement", organization="Client", hosts=["app.example.com"])
                path = Path(created["path"])
                self.assertTrue(path.exists())

                plan = workspace.delete_workspace("Engagement")
                self.assertFalse(plan["deleted"])
                self.assertTrue(plan["requiresConfirmation"])
                self.assertTrue(plan["exists"])
                self.assertEqual(plan["workspaceId"], "engagement")
                self.assertEqual(plan["targetCount"], 1)
                self.assertGreater(plan["fileCount"], 0)
                self.assertTrue(path.exists())

                old_timeout = workspace.DEFAULT_WORKSPACE_LOCK_TIMEOUT_SECONDS
                workspace.DEFAULT_WORKSPACE_LOCK_TIMEOUT_SECONDS = 0.1
                try:
                    lock_path = path / ".lock"
                    with lock_path.open("a+", encoding="utf-8") as handle:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        with self.assertRaises(McpError):
                            workspace.delete_workspace("Engagement", confirm=True)
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                    self.assertTrue(path.exists())
                finally:
                    workspace.DEFAULT_WORKSPACE_LOCK_TIMEOUT_SECONDS = old_timeout

                deleted = workspace.delete_workspace("Engagement", confirm=True)
                self.assertTrue(deleted["deleted"])
                self.assertFalse(path.exists())
                event_types = [item["type"] for item in evidence.tail_events(10)]
                self.assertIn("workspace.delete", event_types)

    def test_workspace_ingest_deduplicates_repeated_entities(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps({"results": [{"url": "https://example.com/search?q=abc", "status": 200}]})
                first = workspace.ingest_data("engagement", "example.com", "ffuf", "tool_output", "json", raw)
                second = workspace.ingest_data("engagement", "example.com", "ffuf", "tool_output", "json", raw)

                self.assertEqual(first["entitiesCreated"]["endpoints"], 1)
                self.assertEqual(first["entitiesCreated"]["parameters"], 1)
                self.assertEqual(second["entitiesCreated"]["endpoints"], 0)
                self.assertEqual(second["entitiesCreated"]["parameters"], 0)

                context = workspace.prepare_target_context("engagement", "example.com")
                endpoint = context["knownEndpoints"]["interesting"][0]
                self.assertEqual(endpoint["queryParameters"], ["q"])

    def test_replaceable_ingestion_prunes_old_generated_evidence(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "hosts": [
                            {
                                "host": "example.com",
                                "urls": [{"url": "https://example.com/app.js", "methods": ["GET"], "contentTypes": ["application/javascript"]}],
                                "forms": [],
                            }
                        ],
                        "summary": {"hostCount": 1},
                    }
                )
                first = workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)
                second = workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)

                self.assertFalse(Path(first["rawPath"]).exists())
                self.assertFalse((workspace.target_path("engagement", "example.com") / "evidence" / f"{first['evidenceId']}.json").exists())
                self.assertTrue(Path(second["rawPath"]).exists())
                self.assertEqual(second["retention"]["removedEvidenceIds"], [first["evidenceId"]])
                endpoints = json.loads(workspace.target_entity_path("engagement", "example.com", "endpoints").read_text(encoding="utf-8"))
                self.assertTrue(endpoints)
                self.assertEqual(endpoints[0]["evidenceIds"], [second["evidenceId"]])

    def test_retain_latest_artifacts_removes_old_timestamped_siblings(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_json = root / "20260608-100000-example-sitemap.json"
            old_flow = root / "20260608-100000-example-sitemap.flow.svg"
            new_json = root / "20260608-100001-example-sitemap.json"
            for path in (old_json, old_flow, new_json):
                path.write_text("x", encoding="utf-8")

            removed = workspace.retain_latest_artifacts(root, "example-sitemap.json", sibling_suffixes=(".flow.svg",))

            self.assertFalse(old_json.exists())
            self.assertFalse(old_flow.exists())
            self.assertTrue(new_json.exists())
            self.assertEqual(set(removed), {str(old_json), str(old_flow)})

    def test_cache_generated_artifact_cleanup_is_inspect_first(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                output_dir = workspace.target_output_dir("engagement", "example.com", "sitemap")
                old_path = output_dir / "20260608-100000-example-sitemap.json"
                new_path = output_dir / "20260608-100001-example-sitemap.json"
                old_path.write_text("old", encoding="utf-8")
                new_path.write_text("new", encoding="utf-8")

                plan = cache.inspect_generated_artifacts()
                self.assertEqual(plan["outputRemoveCount"], 1)
                preview = cache.clean_generated_artifacts(confirm=False)
                self.assertTrue(preview["requiresConfirmation"])
                self.assertTrue(old_path.exists())

                cleaned = cache.clean_generated_artifacts(confirm=True)
                self.assertTrue(cleaned["cleaned"])
                self.assertFalse(old_path.exists())
                self.assertTrue(new_path.exists())

    def test_workspace_ingests_nmap_xml_services(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = """
                <nmaprun>
                  <host>
                    <address addr="203.0.113.10" addrtype="ipv4"/>
                    <hostnames><hostname name="app.example.com"/></hostnames>
                    <ports>
                      <port protocol="tcp" portid="443">
                        <state state="open"/>
                        <service name="https" product="nginx" version="1.24"/>
                      </port>
                      <port protocol="tcp" portid="22"><state state="closed"/></port>
                    </ports>
                  </host>
                </nmaprun>
                """
                result = workspace.ingest_data("engagement", "app.example.com", "nmap", "tool_output", "xml", raw)
                context = workspace.prepare_target_context("engagement", "app.example.com")

                self.assertEqual(result["entitiesCreated"]["services"], 1)
                self.assertEqual(context["knownServices"][0]["port"], 443)
                self.assertEqual(context["knownServices"][0]["product"], "nginx")

    def test_workspace_ingests_shodan_domain_and_port_models(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "target": "example.com",
                        "domain": {
                            "domain": "example.com",
                            "records": [
                                {"subdomain": "api", "type": "A", "value": "203.0.113.10"},
                                {"subdomain": "www", "type": "CNAME", "value": "example.net"},
                            ],
                        },
                        "internetdb": {
                            "203.0.113.10": {
                                "ip": "203.0.113.10",
                                "hostnames": ["api.example.com"],
                                "ports": [80, 443],
                                "cpes": ["cpe:/a:nginx:nginx"],
                                "vulns": ["CVE-2024-0001"],
                            }
                        },
                        "ipLeakageCandidates": ["203.0.113.10"],
                        "possibleCves": ["CVE-2024-0001"],
                    }
                )

                result = workspace.ingest_data("engagement", "example.com", "shodan.target_summary", "osint", "json", raw)
                context = workspace.prepare_target_context("engagement", "example.com")

                self.assertEqual(result["entitiesCreated"]["services"], 2)
                self.assertGreaterEqual(result["entitiesCreated"]["observations"], 4)
                self.assertEqual({item["port"] for item in context["knownServices"]}, {80, 443})
                observation_types = {item["type"] for item in context["observations"]}
                self.assertIn("ip_leakage_candidate", observation_types)
                self.assertIn("possible_cve", observation_types)
                self.assertIn("cpe_observed", observation_types)

    def test_nuclei_reingest_does_not_duplicate_findings(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "template-id": "exposed-panel",
                        "info": {"name": "Exposed Panel", "severity": "medium"},
                        "matched-at": "https://example.com/admin",
                    }
                )
                first = workspace.ingest_data("engagement", "example.com", "nuclei", "tool_output", "jsonl", raw)
                second = workspace.ingest_data("engagement", "example.com", "nuclei", "tool_output", "jsonl", raw)

                self.assertEqual(first["entitiesCreated"]["findings"], 1)
                self.assertEqual(second["entitiesCreated"]["findings"], 0)
                findings = json.loads(workspace.target_entity_path("engagement", "example.com", "findings").read_text(encoding="utf-8"))
                self.assertEqual(len(findings), 1)
                self.assertIn(first["evidenceId"], findings[0]["evidenceIds"])
                self.assertIn(second["evidenceId"], findings[0]["evidenceIds"])
                self.assertTrue(findings[0]["key"].startswith("finding:nuclei:exposed-panel"))

    def test_adapter_result_actions_with_distinct_ids_do_not_collide(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "entities": {
                            "actions": [
                                {"type": "action", "actionId": "act_one", "tool": "demo", "summary": "First run"},
                                {"type": "action", "actionId": "act_two", "tool": "demo", "summary": "Second run"},
                            ]
                        }
                    }
                )
                result = workspace.ingest_data("engagement", "example.com", "adapter_result", "tool_output", "json", raw)

                self.assertEqual(result["entitiesCreated"]["actions"], 2)
                actions = json.loads(workspace.target_entity_path("engagement", "example.com", "actions").read_text(encoding="utf-8"))
                self.assertEqual({item["actionId"] for item in actions}, {"act_one", "act_two"})
                self.assertEqual({item["key"] for item in actions}, {"act_one", "act_two"})

    def test_adapter_result_finding_merges_by_key_unions_evidence_and_escalates_severity(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                def payload(severity: str, evidence_ids: list[str]) -> str:
                    return json.dumps(
                        {
                            "entities": {
                                "findings": [
                                    {
                                        "type": "finding",
                                        "key": "finding:custom:exposed-admin",
                                        "title": "Exposed admin route",
                                        "severity": severity,
                                        "evidenceIds": evidence_ids,
                                    }
                                ]
                            }
                        }
                    )

                first = workspace.ingest_data("engagement", "example.com", "adapter_result", "tool_output", "json", payload("low", ["ev_x"]))
                second = workspace.ingest_data("engagement", "example.com", "adapter_result", "tool_output", "json", payload("high", ["ev_y"]))
                third = workspace.ingest_data("engagement", "example.com", "adapter_result", "tool_output", "json", payload("low", []))

                self.assertEqual(first["entitiesCreated"]["findings"], 1)
                self.assertEqual(second["entitiesCreated"]["findings"], 0)
                self.assertEqual(third["entitiesCreated"]["findings"], 0)
                findings = json.loads(workspace.target_entity_path("engagement", "example.com", "findings").read_text(encoding="utf-8"))
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertIn("ev_x", finding["evidenceIds"])
                self.assertIn("ev_y", finding["evidenceIds"])
                self.assertEqual(set(finding["missingEvidenceIds"]), {"ev_x", "ev_y"})
                self.assertEqual(finding["severity"], "high")
                self.assertTrue(finding["id"])
                self.assertTrue(finding["createdAt"])

    def test_adapter_result_clamps_invalid_finding_enums_and_defaults_assets(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "entities": {
                            "findings": [
                                {
                                    "type": "finding",
                                    "title": "Weird scanner output",
                                    "severity": "URGENT",
                                    "status": "wat",
                                    "confidence": "sure",
                                }
                            ]
                        }
                    }
                )
                workspace.ingest_data("engagement", "example.com", "adapter_result", "tool_output", "json", raw)

                findings = json.loads(workspace.target_entity_path("engagement", "example.com", "findings").read_text(encoding="utf-8"))
                finding = findings[0]
                self.assertEqual(finding["severity"], "info")
                self.assertEqual(finding["status"], "candidate")
                self.assertEqual(finding["confidence"], "low")
                self.assertEqual(finding["affectedAssets"], ["example.com"])
                self.assertEqual(finding["key"], "finding:title:Weird scanner output")

    def test_endpoint_list_fields_union_on_reingest(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                def payload(status_code: int) -> str:
                    return json.dumps(
                        {
                            "entities": {
                                "endpoints": [
                                    {
                                        "type": "endpoint",
                                        "url": "https://example.com/api/items",
                                        "method": "get",
                                        "statusCodes": [status_code],
                                    }
                                ]
                            }
                        }
                    )

                first = workspace.ingest_data("engagement", "example.com", "adapter_result", "tool_output", "json", payload(200))
                second = workspace.ingest_data("engagement", "example.com", "adapter_result", "tool_output", "json", payload(302))

                self.assertEqual(first["entitiesCreated"]["endpoints"], 1)
                self.assertEqual(second["entitiesCreated"]["endpoints"], 0)
                endpoints = json.loads(workspace.target_entity_path("engagement", "example.com", "endpoints").read_text(encoding="utf-8"))
                self.assertEqual(len(endpoints), 1)
                self.assertEqual(endpoints[0]["statusCodes"], [200, 302])
                self.assertEqual(endpoints[0]["method"], "GET")
                self.assertEqual(endpoints[0]["host"], "example.com")
                self.assertEqual(endpoints[0]["path"], "/api/items")

    def test_observation_promotion_by_observation_id(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "entities": {
                            "observations": [
                                {
                                    "type": "custom_signal",
                                    "id": "obs-custom-1",
                                    "value": "https://example.com/debug",
                                    "reason": "Custom adapter flagged a debug endpoint.",
                                }
                            ]
                        }
                    }
                )
                workspace.ingest_data("engagement", "example.com", "adapter_result", "tool_output", "json", raw)

                promoted = workspace.promote_observation_to_finding(
                    "engagement",
                    "example.com",
                    {"observationId": "obs-custom-1"},
                    severity="medium",
                )
                self.assertEqual(promoted["observation"]["id"], "obs-custom-1")
                self.assertEqual(promoted["finding"]["status"], "candidate")

    def test_workspace_finding_lifecycle(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data(
                    "engagement",
                    "example.com",
                    "sitemap",
                    "tool_output",
                    "json",
                    json.dumps(
                        {
                            "hosts": [
                                {
                                    "host": "example.com",
                                    "urls": [{"url": "https://example.com/admin", "methods": ["GET"], "statusCodes": [200]}],
                                    "forms": [],
                                }
                            ],
                            "summary": {"hostCount": 1, "urlCount": 1, "formCount": 0},
                        }
                    ),
                )

                promoted = workspace.promote_observation_to_finding(
                    "engagement",
                    "example.com",
                    {"type": "sitemap_finding_candidate", "value": "https://example.com/admin"},
                    severity="medium",
                    confidence="low",
                )
                finding_id = promoted["finding"]["id"]
                self.assertEqual(promoted["finding"]["status"], "candidate")
                self.assertFalse(promoted["finding"]["operatorReviewed"])

                updated = workspace.update_finding(
                    "engagement",
                    "example.com",
                    finding_id,
                    {"impact": "Administrative surface may need access-control review.", "reproductionSteps": ["Browse to /admin."]},
                )
                self.assertIn("Administrative surface", updated["finding"]["impact"])

                linked = workspace.link_evidence_to_finding("engagement", "example.com", finding_id, ["ev_external"])
                self.assertEqual(linked["finding"]["missingEvidenceIds"], ["ev_external"])

                reviewed = workspace.mark_finding_reviewed("engagement", "example.com", finding_id, status="confirmed")
                self.assertTrue(reviewed["finding"]["operatorReviewed"])
                self.assertEqual(reviewed["finding"]["status"], "confirmed")

                exported = workspace.export_finding_context("engagement", "example.com", finding_id)
                self.assertEqual(exported["finding"]["id"], finding_id)
                context = workspace.prepare_target_context("engagement", "example.com")
                self.assertEqual(context["confirmedFindings"][0]["id"], finding_id)



class ReportabilityTests(unittest.TestCase):
    OEMBED_URL = "https://example.com/wp-json/oembed/1.0/embed?url=x"
    GENUINE_URL = "https://example.com/go?next=https://evil.example"

    def _observations_payload(self, observations: list[dict]) -> str:
        return json.dumps({"entities": {"observations": observations}})

    def _seed(self) -> None:
        scope.save_scope(["example.com"], "test", "Example Client")
        workspace.create_workspace("engagement", organization="Example Client", hosts=["example.com"])
        workspace.ingest_data(
            "engagement",
            "example.com",
            "adapter_result",
            "tool_output",
            "json",
            self._observations_payload(
                [
                    {
                        "type": "open_redirect_candidate",
                        "candidateId": "cand-oembed",
                        "value": self.OEMBED_URL,
                        "parameter": "url",
                        "method": "GET",
                        "reason": "WordPress oEmbed URL parameter.",
                    },
                    {
                        "type": "open_redirect_candidate",
                        "candidateId": "cand-genuine",
                        "value": self.GENUINE_URL,
                        "parameter": "next",
                        "method": "GET",
                        "reason": "Reflected redirect target.",
                    },
                ]
            ),
        )

    def _observations_on_disk(self) -> list[dict]:
        return json.loads(
            workspace.target_entity_path("engagement", "example.com", "observations").read_text(encoding="utf-8")
        )

    def test_ingested_entities_default_to_reportable(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                self._seed()
                observations = self._observations_on_disk()
                self.assertEqual(len(observations), 2)
                self.assertTrue(all(item["isReportable"] is True for item in observations))

    def test_set_entity_reportable_excludes_from_reports_but_keeps_state(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                self._seed()
                result = json.loads(
                    stdio_server.call_tool(
                        "workspace.set_entity_reportable",
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "entityType": "observations",
                            "isReportable": False,
                            "selector": {"candidateId": "cand-oembed"},
                            "reason": "WordPress oEmbed URL-parameter false positive.",
                        },
                    )
                )
                self.assertEqual(result["matched"], 1)

                observations = {item["candidateId"]: item for item in self._observations_on_disk()}
                self.assertIs(observations["cand-oembed"]["isReportable"], False)
                self.assertEqual(observations["cand-oembed"]["reportableDecision"]["isReportable"], False)
                self.assertIs(observations["cand-genuine"]["isReportable"], True)

                # Report boundary drops the suppressed candidate but keeps the genuine one.
                report = stdio_server.call_tool(
                    "documentation.build_report_context",
                    {"workspaceId": "engagement"},
                )
                self.assertIn(self.GENUINE_URL, report)
                self.assertNotIn(self.OEMBED_URL, report)

                coverage = stdio_server.call_tool(
                    "documentation.summarize_coverage",
                    {"workspaceId": "engagement"},
                )
                self.assertIn(self.GENUINE_URL, coverage)
                self.assertNotIn(self.OEMBED_URL, coverage)

                # Perimeter candidate inventory (report path) excludes it too.
                inventory = perimeter.candidate_inventory(
                    workspace.load_reportable_target_entities("engagement", "example.com"), "example.com"
                )
                inventory_values = {item.get("value") for item in inventory["items"]}
                self.assertIn(self.GENUINE_URL, inventory_values)
                self.assertNotIn(self.OEMBED_URL, inventory_values)

                # Workspace/agent state stays complete: both records remain loadable.
                full = workspace._load_target_entities("engagement", "example.com")
                self.assertEqual(len(full["observations"]), 2)

                # Decision is archived compactly.
                decisions = workspace.read_report_decisions("engagement")
                self.assertEqual(len(decisions), 1)
                self.assertEqual(decisions[0]["matched"], 1)
                self.assertEqual(decisions[0]["entityType"], "observations")
                self.assertIs(decisions[0]["isReportable"], False)

    def test_reingest_does_not_resurrect_non_reportable_decision(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                self._seed()
                stdio_server.call_tool(
                    "workspace.set_entity_reportable",
                    {
                        "workspaceId": "engagement",
                        "target": "example.com",
                        "entityType": "observations",
                        "isReportable": False,
                        "selector": {"candidateId": "cand-oembed"},
                        "reason": "False positive.",
                    },
                )
                # Re-ingest the identical adapter output; the default True must not clobber the decision.
                workspace.ingest_data(
                    "engagement",
                    "example.com",
                    "adapter_result",
                    "tool_output",
                    "json",
                    self._observations_payload(
                        [
                            {
                                "type": "open_redirect_candidate",
                                "candidateId": "cand-oembed",
                                "value": self.OEMBED_URL,
                                "parameter": "url",
                                "method": "GET",
                                "reason": "WordPress oEmbed URL parameter.",
                            }
                        ]
                    ),
                )
                observations = {item["candidateId"]: item for item in self._observations_on_disk()}
                self.assertIs(observations["cand-oembed"]["isReportable"], False)

    def test_set_entity_reportable_bulk_by_attribute_selector(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                workspace.create_workspace("engagement", organization="Example Client", hosts=["example.com"])
                workspace.ingest_data(
                    "engagement",
                    "example.com",
                    "adapter_result",
                    "tool_output",
                    "json",
                    self._observations_payload(
                        [
                            {"type": "open_redirect_candidate", "candidateId": "o1", "value": "https://example.com/a/wp-json/oembed/1.0/embed?url=1"},
                            {"type": "open_redirect_candidate", "candidateId": "o2", "value": "https://example.com/b/wp-json/oembed/1.0/embed?url=2"},
                            {"type": "open_redirect_candidate", "candidateId": "o3", "value": "https://example.com/go?next=3"},
                        ]
                    ),
                )
                result = workspace.set_entity_reportable(
                    "engagement",
                    "example.com",
                    "observations",
                    {"type": "open_redirect_candidate", "urlContains": "oembed"},
                    False,
                    reason="Bulk oEmbed URL-parameter false positives.",
                )
                self.assertEqual(result["matched"], 2)
                flags = {item["candidateId"]: item.get("isReportable") for item in self._observations_on_disk()}
                self.assertIs(flags["o1"], False)
                self.assertIs(flags["o2"], False)
                self.assertIs(flags["o3"], True)


if __name__ == "__main__":
    unittest.main()
