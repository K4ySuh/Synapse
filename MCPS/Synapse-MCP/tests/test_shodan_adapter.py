import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from helpers import isolated_state
from synapse_mcp.adapters.infra import shodan_adapter
from synapse_mcp.core import workspace
from synapse_mcp.core.adapters import default_registry
from synapse_mcp.transport import stdio_server


class ShodanAdapterTests(unittest.TestCase):
    def test_shodan_internetdb_schema_requires_confirm(self) -> None:
        schema = next(schema for schema in stdio_server.TOOL_SCHEMAS if schema["name"] == "shodan.internetdb")

        self.assertIn("confirm", schema["inputSchema"]["properties"])
        self.assertEqual(schema["inputSchema"]["required"], ["ip", "confirm"])

        capabilities = default_registry.capabilities("shodan")
        self.assertTrue(capabilities["sendsTraffic"])
        self.assertTrue(capabilities["touchesThirdParty"])
        self.assertTrue(capabilities["requiresConfirmation"])

    def test_shodan_internetdb_lookup_requires_confirmation_before_http(self) -> None:
        with patch.object(shodan_adapter, "http_get_json") as http_get_json:
            with self.assertRaisesRegex(Exception, "confirm=true"):
                shodan_adapter.internetdb_lookup({"ip": "203.0.113.10"})
            with self.assertRaisesRegex(Exception, "confirm=true"):
                shodan_adapter.internetdb_lookup({"ip": "203.0.113.10", "confirm": False})

        http_get_json.assert_not_called()

    def test_shodan_host_lookup_ingests_compact_workspace_model(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                payload = {
                    "ip_str": "203.0.113.10",
                    "org": "Example Org",
                    "hostnames": ["api.example.com"],
                    "domains": ["example.com"],
                    "ports": [443],
                    "cpes": ["cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*"],
                    "vulns": {
                        "CVE-2024-0001": {
                            "verified": True,
                            "cvss": 9.1,
                            "summary": "Example exposure",
                        }
                    },
                    "data": [
                        {
                            "port": 443,
                            "transport": "tcp",
                            "product": "nginx",
                            "version": "1.24",
                            "hostnames": ["api.example.com"],
                            "domains": ["example.com"],
                            "_shodan": {"module": "https"},
                            "cpe23": ["cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*"],
                            "ssl": {
                                "cert": {
                                    "subject": {"CN": "api.example.com"},
                                    "issuer": {"CN": "Example CA"},
                                    "expired": False,
                                },
                                "versions": ["TLSv1.2", "TLSv1.3"],
                            },
                            "http": {"title": "API", "server": "nginx", "status": 200},
                        }
                    ],
                }

                with patch.object(shodan_adapter, "_SESSION_API_KEY", "test-key"):
                    with patch.object(shodan_adapter, "http_get_json", return_value=payload):
                        result = json.loads(
                            shodan_adapter.host_lookup(
                                {
                                    "ip": "203.0.113.10",
                                    "workspaceId": "engagement",
                                    "confirm": True,
                                }
                            )
                        )

                self.assertEqual(result["ingestion"]["entitiesCreated"]["services"], 1)
                context = workspace.prepare_target_context("engagement", "203.0.113.10")
                self.assertEqual(context["knownServices"][0]["product"], "nginx")
                self.assertEqual(context["knownEndpoints"]["total"], 1)
                observation_types = {item["type"] for item in context["observations"]}
                self.assertIn("exposed_service", observation_types)
                self.assertIn("possible_cve", observation_types)
                self.assertIn("cpe_observed", observation_types)
                entities = workspace._load_target_entities("engagement", "203.0.113.10")
                self.assertEqual(entities["services"][0]["module"], "https")
                self.assertEqual(entities["services"][0]["ssl"]["subjectCN"], "api.example.com")
                cve = next(item for item in entities["observations"] if item.get("type") == "possible_cve")
                self.assertTrue(cve["providerVerified"])
                self.assertEqual(cve["cvssScore"], 9.1)

    def test_shodan_search_ingests_port_enumeration_results(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                payload = {
                    "total": 1,
                    "matches": [
                        {
                            "ip_str": "203.0.113.20",
                            "port": 8080,
                            "hostnames": ["admin.example.com"],
                            "domains": ["example.com"],
                            "org": "Example Org",
                            "asn": "AS64500",
                            "transport": "tcp",
                            "product": "Jetty",
                            "version": "11",
                            "http": {"title": "Admin"},
                        }
                    ],
                }

                with patch.object(shodan_adapter, "_SESSION_API_KEY", "test-key"):
                    with patch.object(shodan_adapter, "http_get_json", return_value=payload):
                        result = json.loads(
                            shodan_adapter.search(
                                {
                                    "query": "hostname:example.com port:8080",
                                    "target": "example.com",
                                    "workspaceId": "engagement",
                                    "confirm": True,
                                }
                            )
                        )

                self.assertEqual(result["ingestion"]["target"], "example.com")
                self.assertEqual(result["ingestion"]["entitiesCreated"]["services"], 0)
                ingestions = {item["target"]: item for item in result["ingestions"]}
                self.assertEqual(ingestions["admin.example.com"]["entitiesCreated"]["services"], 1)

                seed_context = workspace.prepare_target_context("engagement", "example.com")
                self.assertEqual(seed_context["knownServices"], [])
                relation = next(
                    item
                    for item in seed_context["observations"]
                    if item.get("type") == "asset_relation" and item.get("relationType") == "discovered_via_shodan_query"
                )
                self.assertEqual(relation["targetAsset"], "admin.example.com")

                context = workspace.prepare_target_context("engagement", "admin.example.com")
                self.assertEqual(context["knownServices"][0]["port"], 8080)
                self.assertEqual(context["knownServices"][0]["product"], "Jetty")
                self.assertEqual(context["knownEndpoints"]["total"], 1)

    def test_shodan_raw_host_response_still_ingests_canonical_data(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                payload = {
                    "ip_str": "203.0.113.30",
                    "ports": [22],
                    "data": [{"port": 22, "transport": "tcp", "product": "OpenSSH", "_shodan": {"module": "ssh"}}],
                }
                with patch.object(shodan_adapter, "_SESSION_API_KEY", "test-key"), patch.object(
                    shodan_adapter, "http_get_json", return_value=payload
                ):
                    result = json.loads(
                        shodan_adapter.host_lookup(
                            {
                                "ip": "203.0.113.30",
                                "workspaceId": "engagement",
                                "raw": True,
                                "confirm": True,
                            }
                        )
                    )

                self.assertEqual(result["ip_str"], "203.0.113.30")
                self.assertEqual(result["ingestion"]["entitiesCreated"]["services"], 1)
                context = workspace.prepare_target_context("engagement", "203.0.113.30")
                self.assertEqual(context["knownServices"][0]["product"], "OpenSSH")
                self.assertEqual(context["knownEndpoints"]["total"], 0)

    def test_shodan_internetdb_infers_only_likely_web_endpoints(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                payload = {
                    "ip": "203.0.113.40",
                    "hostnames": ["edge.example.com"],
                    "ports": [22, 443],
                    "cpes": [],
                    "vulns": [],
                    "tags": [],
                }
                with patch.object(shodan_adapter, "http_get_json", return_value=payload):
                    result = json.loads(
                        shodan_adapter.internetdb_lookup(
                            {
                                "ip": "203.0.113.40",
                                "workspaceId": "engagement",
                                "confirm": True,
                            }
                        )
                    )

                self.assertEqual(result["ingestion"]["entitiesCreated"]["services"], 2)
                context = workspace.prepare_target_context("engagement", "203.0.113.40")
                self.assertEqual({item["port"] for item in context["knownServices"]}, {22, 443})
                endpoints = workspace._load_target_entities("engagement", "203.0.113.40")["endpoints"]
                self.assertEqual([item["url"] for item in endpoints], ["https://edge.example.com/"])

    def test_shodan_target_summary_resolves_hostname_before_host_lookup(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                requested_urls: list[str] = []

                def fake_http_get_json(url: str, _timeout: int = 30) -> dict[str, object]:
                    requested_urls.append(url)
                    if "/dns/domain/example.com" in url:
                        return {
                            "domain": "example.com",
                            "data": [{"subdomain": "api", "type": "A", "value": "203.0.113.50"}],
                        }
                    if "/dns/resolve" in url:
                        return {"api.example.com": "203.0.113.50"}
                    if "/shodan/host/203.0.113.50" in url:
                        return {
                            "ip_str": "203.0.113.50",
                            "hostnames": ["api.example.com"],
                            "domains": ["example.com"],
                            "ports": [443],
                            "data": [{"port": 443, "transport": "tcp", "product": "nginx", "_shodan": {"module": "https"}}],
                        }
                    if url.endswith("/203.0.113.50"):
                        return {
                            "ip": "203.0.113.50",
                            "hostnames": ["api.example.com"],
                            "ports": [443],
                            "cpes": [],
                            "vulns": [],
                            "tags": [],
                        }
                    self.fail(f"Unexpected Shodan URL: {url}")

                with patch.object(shodan_adapter, "_SESSION_API_KEY", "test-key"), patch.object(
                    shodan_adapter, "http_get_json", side_effect=fake_http_get_json
                ):
                    result = json.loads(
                        shodan_adapter.target_summary(
                            {
                                "target": "api.example.com",
                                "domain": "example.com",
                                "workspaceId": "engagement",
                                "confirm": True,
                            }
                        )
                    )

                self.assertTrue(any("/shodan/host/203.0.113.50" in url for url in requested_urls))
                self.assertEqual(result["resolvedIps"], ["203.0.113.50"])
                self.assertEqual(result["ipLeakageCandidates"], [])
                self.assertEqual(result["ingestion"]["target"], "api.example.com")
                context = workspace.prepare_target_context("engagement", "api.example.com")
                self.assertEqual({item["port"] for item in context["knownServices"]}, {443})
                observation_types = {item["type"] for item in context["observations"]}
                self.assertIn("dns_resolution", observation_types)
                self.assertIn("asset_relation", observation_types)

    def test_shodan_target_summary_can_resolve_for_internetdb_without_host_details(self) -> None:
        requested_urls: list[str] = []

        def fake_http_get_json(url: str, _timeout: int = 30) -> dict[str, object]:
            requested_urls.append(url)
            if "/dns/resolve" in url:
                return {"api.example.com": "203.0.113.51"}
            if url.endswith("/203.0.113.51"):
                return {
                    "ip": "203.0.113.51",
                    "hostnames": ["api.example.com"],
                    "ports": [443],
                    "cpes": [],
                    "vulns": [],
                    "tags": [],
                }
            self.fail(f"Unexpected Shodan URL: {url}")

        with patch.object(shodan_adapter, "_SESSION_API_KEY", "test-key"), patch.object(
            shodan_adapter, "http_get_json", side_effect=fake_http_get_json
        ):
            result = json.loads(
                shodan_adapter.target_summary(
                    {
                        "target": "api.example.com",
                        "includeHost": False,
                        "includeDomain": False,
                        "includeInternetDb": True,
                        "ingest": False,
                        "confirm": True,
                    }
                )
            )

        self.assertEqual(result["resolvedIps"], ["203.0.113.51"])
        self.assertIn("203.0.113.51", result["internetdb"])
        self.assertTrue(any("/dns/resolve" in url for url in requested_urls))
        self.assertFalse(any("/shodan/host/" in url for url in requested_urls))

    def test_shodan_rejects_invalid_ip_before_http(self) -> None:
        with patch.object(shodan_adapter, "http_get_json") as http_get_json:
            with self.assertRaisesRegex(Exception, "valid IPv4 or IPv6"):
                shodan_adapter.host_lookup({"ip": "not-an-ip", "confirm": True})
        http_get_json.assert_not_called()



if __name__ == "__main__":
    unittest.main()
