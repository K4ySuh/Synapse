import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from helpers import isolated_state
from synapse_mcp.adapters.infra import shodan_adapter
from synapse_mcp.core import workspace
from synapse_mcp.transport import stdio_server


class ShodanAdapterTests(unittest.TestCase):
    def test_shodan_internetdb_schema_requires_confirm(self) -> None:
        schema = next(schema for schema in stdio_server.TOOL_SCHEMAS if schema["name"] == "shodan.internetdb")

        self.assertIn("confirm", schema["inputSchema"]["properties"])
        self.assertEqual(schema["inputSchema"]["required"], ["ip", "confirm"])

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
                    "vulns": {"CVE-2024-0001": {}},
                    "data": [
                        {
                            "port": 443,
                            "transport": "tcp",
                            "product": "nginx",
                            "version": "1.24",
                            "hostnames": ["api.example.com"],
                            "domains": ["example.com"],
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

                self.assertEqual(result["ingestion"]["entitiesCreated"]["services"], 1)
                context = workspace.prepare_target_context("engagement", "example.com")
                self.assertEqual(context["knownServices"][0]["port"], 8080)
                self.assertEqual(context["knownServices"][0]["product"], "Jetty")
                self.assertEqual(context["knownEndpoints"]["total"], 1)



if __name__ == "__main__":
    unittest.main()
