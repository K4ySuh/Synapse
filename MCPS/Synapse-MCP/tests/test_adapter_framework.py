import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import isolated_state
from synapse_mcp.core import workspace
from synapse_mcp.core.adapters import (
    AdapterMetadata,
    AdapterRegistry,
    AdapterResult,
    AdapterUnsupportedMethod,
    EndpointEntity,
    ParameterEntity,
    RecommendedTest,
    SynapseAdapter,
    WorkspaceEntityBundle,
    candidate_observation,
)
from synapse_mcp.transport import stdio_server


class AdapterFrameworkTests(unittest.TestCase):
    def test_adapter_discovery_tools_expose_registered_metadata(self) -> None:
        listing = json.loads(stdio_server.call_tool("adapters.list", {}))
        names = {adapter["name"] for adapter in listing["adapters"]}
        self.assertIn("ssrf", names)
        self.assertIn("nmap", names)

        ssrf_summary = next(adapter for adapter in listing["adapters"] if adapter["name"] == "ssrf")
        self.assertEqual(ssrf_summary["category"], "web")
        self.assertIn("passive_analysis", ssrf_summary["capabilities"])
        self.assertIn("active_testing", ssrf_summary["capabilities"])
        self.assertTrue(ssrf_summary["sendsTraffic"])
        self.assertTrue(ssrf_summary["requiresConfirmation"])
        self.assertTrue(ssrf_summary["requiresScope"])
        self.assertFalse(ssrf_summary["touchesThirdParty"])
        self.assertEqual(ssrf_summary["defaultRiskTier"], "low")
        self.assertEqual(ssrf_summary["executionMode"], "sync_only")
        self.assertEqual(ssrf_summary["executorTool"], "ssrf.execute_test")
        self.assertIn("candidate_observations", ssrf_summary["produces"])

        csrf_summary = next(adapter for adapter in listing["adapters"] if adapter["name"] == "csrf")
        self.assertNotIn("active_testing", csrf_summary["capabilities"])
        self.assertFalse(csrf_summary["sendsTraffic"])
        self.assertFalse(csrf_summary["requiresConfirmation"])
        self.assertEqual(csrf_summary["executionMode"], "passive_only")
        self.assertEqual(csrf_summary["executorTool"], "")

        capabilities = json.loads(stdio_server.call_tool("adapters.capabilities", {"adapter": "command_injection"}))
        self.assertEqual(capabilities["name"], "command_injection")
        self.assertTrue(capabilities["sendsTraffic"])
        self.assertTrue(capabilities["requiresConfirmation"])
        self.assertIn("active_testing", capabilities["capabilities"])
        self.assertEqual(capabilities["executionMode"], "sync_only")
        self.assertEqual(capabilities["executorTool"], "command_injection.execute_test")
        self.assertNotIn("candidate_findings", capabilities["produces"])
        self.assertIn("limitations", capabilities)

        nmap_capabilities = json.loads(stdio_server.call_tool("adapters.capabilities", {"adapter": "nmap"}))
        self.assertEqual(nmap_capabilities["executionMode"], "async_default")
        self.assertEqual(nmap_capabilities["backgroundJobProvider"], "jobs")
        self.assertEqual(nmap_capabilities["executorTool"], "nmap.run_profile")

        js_capabilities = json.loads(stdio_server.call_tool("adapters.capabilities", {"adapter": "js_intelligence"}))
        self.assertEqual(js_capabilities["executionMode"], "async_default")
        self.assertEqual(js_capabilities["backgroundJobProvider"], "jobs")
        self.assertEqual(js_capabilities["executorTool"], "")

        shodan_summary = next(adapter for adapter in listing["adapters"] if adapter["name"] == "shodan")
        self.assertTrue(shodan_summary["touchesThirdParty"])
        self.assertFalse(shodan_summary["requiresScope"])

    def test_active_adapter_executor_metadata_points_to_mcp_tool(self) -> None:
        listing = json.loads(stdio_server.call_tool("adapters.list", {}))
        tool_names = {schema["name"] for schema in stdio_server.TOOL_SCHEMAS}
        active_adapters = [adapter for adapter in listing["adapters"] if "active_testing" in adapter["capabilities"]]

        self.assertGreater(len(active_adapters), 0)
        for adapter in active_adapters:
            with self.subTest(adapter=adapter["name"]):
                self.assertTrue(adapter["executorTool"])
                self.assertIn(adapter["executorTool"], tool_names)

    def test_unknown_adapter_capabilities_returns_mcp_error(self) -> None:
        response = stdio_server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "adapters.capabilities", "arguments": {"adapter": "missing"}},
            }
        )
        self.assertIsNotNone(response)
        self.assertEqual(response["error"]["code"], -32602)
        self.assertIn("Unknown adapter", response["error"]["message"])

    def test_adapter_registry_rejects_duplicates_and_base_methods_are_controlled(self) -> None:
        class MinimalAdapter(SynapseAdapter):
            metadata = AdapterMetadata(
                name="minimal",
                category="custom",
                description="Minimal test adapter.",
                capabilities=["passive_analysis"],
            )

        registry = AdapterRegistry()
        adapter = MinimalAdapter()
        registry.register(adapter)
        with self.assertRaises(ValueError):
            registry.register(adapter)

        with self.assertRaises(AdapterUnsupportedMethod) as raised:
            adapter.plan()
        self.assertEqual(raised.exception.to_response()["error"], "unsupported_adapter_method")
        self.assertEqual(raised.exception.to_response()["adapter"], "minimal")

    def test_adapter_result_schema_uses_workspace_native_entities(self) -> None:
        result = AdapterResult(
            adapter="ssti",
            mode="passive_analysis",
            workspace_id="engagement",
            target="example.com",
            summary="Identified one template-like parameter.",
            entities=WorkspaceEntityBundle(
                endpoints=[EndpointEntity(url="https://example.com/render?template=home", method="GET", path="/render")],
                parameters=[
                    ParameterEntity(
                        name="template",
                        location="query",
                        method="GET",
                        url="https://example.com/render?template=home",
                        path="/render",
                    )
                ],
                observations=[
                    candidate_observation(
                        candidate_type="ssti_candidate",
                        value="https://example.com/render?template=home",
                        url="https://example.com/render?template=home",
                        method="GET",
                        parameter="template",
                        location="query",
                        confidence="medium",
                        priority="medium",
                        priority_score=70,
                        reason="Parameter name suggests server-side template rendering surface.",
                        tags=["ssti", "template-parameter"],
                    )
                ],
            ),
            recommended_tests=[
                RecommendedTest(
                    name="arithmetic_expression_reflection_probe",
                    description="Compare response behavior for a benign arithmetic template expression.",
                    sends_traffic=True,
                    requires_confirmation=True,
                    risk_tier="low",
                )
            ],
        )

        payload = result.as_ingest_payload()
        self.assertEqual(payload["workspaceId"], "engagement")
        self.assertEqual(payload["entities"]["observations"][0]["priorityScore"], 70)
        self.assertEqual(payload["entities"]["observations"][0]["parameter"], "template")
        self.assertEqual(payload["recommendedTests"][0]["requiresConfirmation"], True)

    def test_workspace_ingests_generic_adapter_result_entities(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                result = AdapterResult(
                    adapter="ssti",
                    mode="passive_analysis",
                    workspace_id="engagement",
                    target="example.com",
                    summary="Identified one SSTI candidate.",
                    entities=WorkspaceEntityBundle(
                        endpoints=[EndpointEntity(url="https://example.com/render?template=home", method="GET")],
                        parameters=[
                            ParameterEntity(
                                name="template",
                                location="query",
                                method="GET",
                                url="https://example.com/render?template=home",
                            )
                        ],
                        observations=[
                            candidate_observation(
                                candidate_type="ssti_candidate",
                                value="https://example.com/render?template=home",
                                reason="Parameter name suggests server-side template rendering surface.",
                                parameter="template",
                                method="GET",
                                location="query",
                                priority="medium",
                                priority_score=70,
                                confidence="medium",
                            )
                        ],
                    ),
                )
                ingested = workspace.ingest_data(
                    "engagement",
                    "example.com",
                    "adapter_result",
                    "passive_analysis",
                    "json",
                    json.dumps(result.as_ingest_payload()),
                )

                self.assertEqual(ingested["entitiesCreated"]["endpoints"], 1)
                self.assertEqual(ingested["entitiesCreated"]["parameters"], 1)
                self.assertEqual(ingested["entitiesCreated"]["observations"], 1)
                context = workspace.prepare_target_context("engagement", "example.com")
                observation_types = {item["type"] for item in context["observations"]}
                self.assertIn("ssti_candidate", observation_types)



if __name__ == "__main__":
    unittest.main()
