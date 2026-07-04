import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlsplit

from helpers import isolated_state
import base64
import hashlib
import hmac

from synapse_mcp.adapters.web import command_injection_adapter, graphql, jwt_analysis, lfi_rfi, sqlmap_adapter, ssi, ssti, xss_adapter
from synapse_mcp.core import fingerprint, scope, workspace
from synapse_mcp.core.errors import McpError
from synapse_mcp.transport import stdio_server


class ReferenceWebAdapterTests(unittest.TestCase):
    def test_xss_and_sqli_workspace_analyzers_ingest_passive_candidates(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "hosts": [
                            {
                                "host": "example.com",
                                "urls": [
                                    {
                                        "url": "https://example.com/search?q=alpha",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                        "contentTypes": ["text/html"],
                                    },
                                    {
                                        "url": "https://example.com/rest/products/search?id=1",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                        "contentTypes": ["application/json"],
                                    },
                                    {
                                        "url": "https://twitter.com/intent/tweet?text=hello",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                        "contentTypes": ["text/html"],
                                    },
                                    {
                                        "url": "https://api.example.net/items?id=1",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                        "contentTypes": ["application/json"],
                                    },
                                ],
                            }
                        ],
                        "summary": {"hostCount": 1},
                    }
                )
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)

                xss_result = json.loads(xss_adapter.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))
                sqli_result = json.loads(sqlmap_adapter.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))

                self.assertGreaterEqual(xss_result["candidateCount"], 1)
                self.assertGreaterEqual(sqli_result["candidateCount"], 1)
                self.assertTrue(all(urlsplit(item["url"]).hostname == "example.com" for item in xss_result["candidates"]))
                self.assertTrue(all(urlsplit(item["url"]).hostname == "example.com" for item in sqli_result["candidates"]))
                context = workspace.prepare_target_context("engagement", "example.com")
                observation_types = {item["type"] for item in context["observations"]}
                self.assertIn("xss_candidate", observation_types)
                self.assertIn("test_candidate", observation_types)
                sqli_classes = set()
                for item in context["observations"]:
                    if item.get("type") == "test_candidate":
                        sqli_classes.update(item.get("candidateFor", []))
                self.assertIn("sqli", sqli_classes)

    def test_sqlmap_build_command_promotes_all_interesting_params_and_routes(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                raw = json.dumps(
                    {
                        "hosts": [
                            {
                                "host": "example.com",
                                "urls": [
                                    {"url": "https://example.com/rest/products/search?id=1&owner=2", "methods": ["GET"], "statusCodes": [200], "contentTypes": ["application/json"]},
                                    {"url": "https://example.com/orders?order=5", "methods": ["GET"], "statusCodes": [200], "contentTypes": ["application/json"]},
                                ],
                            }
                        ],
                        "summary": {"hostCount": 1},
                    }
                )
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)
                # Create the surface test_candidates so promotion can mark them under testing.
                sqlmap_adapter.analyze_workspace({"workspaceId": "engagement", "target": "example.com"})

                result = json.loads(sqlmap_adapter.build_command({"workspaceId": "engagement", "target": "example.com", "level": 2, "risk": 1}))

                # Multiple routes are promoted, and the multi-parameter route lists all its params.
                self.assertGreaterEqual(result["targetCount"], 2)
                by_url = {t["url"]: t for t in result["targets"]}
                multi = next(t for t in result["targets"] if t["url"].endswith("id=1&owner=2"))
                self.assertEqual(sorted(multi["parameters"]), ["id", "owner"])
                self.assertIn("-p", multi["command"])
                self.assertIn("id,owner", multi["shellCommand"])
                self.assertGreater(result["promotedCandidates"], 0)
                # Promoted sqli candidates are recorded as under testing.
                entities = workspace._load_target_entities("engagement", "example.com")
                statuses = [
                    obs["candidateDetails"]["sqli"]["validationStatus"]
                    for obs in entities["observations"]
                    if obs.get("type") == "test_candidate" and "sqli" in obs.get("candidateDetails", {})
                ]
                self.assertIn("testing", statuses)

    def test_ssti_template_error_signal_ignores_common_words(self) -> None:
        # Regression: the SSTI error signal must not fire on ordinary prose that
        # merely contains words like "template", "velocity", or "liquid", or
        # benign pages would be reported as possible SSTI.
        self.assertFalse(ssti.template_error_signal("Choose a template for your liquid velocity report."))
        self.assertFalse(ssti.template_error_signal(""))
        # Distinctive engine error fingerprints remain signals.
        self.assertTrue(ssti.template_error_signal("jinja2.exceptions.TemplateSyntaxError: unexpected '}'"))
        self.assertTrue(ssti.template_error_signal("PHP Fatal error: Twig\\Error\\SyntaxError"))

    def test_reference_adapters_expose_capabilities_and_ingest_passive_candidates(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "hosts": [
                            {
                                "host": "example.com",
                                "urls": [
                                    {
                                        "url": "https://example.com/render?template=home",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                        "contentTypes": ["text/html"],
                                    },
                                    {
                                        "url": "https://example.com/download?file=report.pdf",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                        "contentTypes": ["application/pdf"],
                                    },
                                    {
                                        "url": "https://example.com/legacy/page.shtml?content=welcome",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                        "contentTypes": ["text/html"],
                                    },
                                ],
                            }
                        ],
                        "summary": {"hostCount": 1},
                    }
                )
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)

                self.assertTrue(json.loads(stdio_server.call_tool("ssti.capabilities", {}))["requiresConfirmation"])
                self.assertTrue(json.loads(stdio_server.call_tool("lfi.capabilities", {}))["requiresConfirmation"])
                self.assertTrue(json.loads(stdio_server.call_tool("ssi.capabilities", {}))["requiresConfirmation"])

                ssti_result = json.loads(ssti.passive_analyze({"workspaceId": "engagement", "target": "example.com"}))
                lfi_result = json.loads(lfi_rfi.passive_analyze({"workspaceId": "engagement", "target": "example.com"}))
                ssi_result = json.loads(ssi.passive_analyze({"workspaceId": "engagement", "target": "example.com"}))

                self.assertGreaterEqual(ssti_result["candidateCount"], 1)
                self.assertGreaterEqual(lfi_result["candidateCount"], 1)
                self.assertGreaterEqual(ssi_result["candidateCount"], 1)

                context = workspace.prepare_target_context("engagement", "example.com")
                observation_types = {item["type"] for item in context["observations"]}
                self.assertIn("test_candidate", observation_types)
                self.assertIn("ssi_candidate", observation_types)
                candidate_classes: set[str] = set()
                for item in context["observations"]:
                    if item.get("type") == "test_candidate":
                        candidate_classes.update(item.get("candidateFor", []))
                self.assertIn("ssti", candidate_classes)
                self.assertIn("lfi", candidate_classes)

                ssti_plan = json.loads(ssti.plan_tests({"candidate": ssti_result["candidates"][0]}))
                self.assertTrue(ssti_plan["recommendedTests"][0]["requiresConfirmation"])
                self.assertIn("{{7*7}}", ssti_plan["safePayloads"])

    def test_reference_prepare_replay_builds_no_traffic_requests(self) -> None:
        candidate = {
            "candidateId": "ssti_get_render_template",
            "url": "https://example.com/render?template=home",
            "method": "GET",
            "parameter": "template",
            "location": "query",
        }

        ssti_replay = json.loads(ssti.prepare_replay({"candidate": candidate, "payload": "{{7*7}}"}))
        ssi_replay = json.loads(
            ssi.prepare_replay(
                {
                    "url": "https://example.com/legacy/page.shtml?content=hello",
                    "method": "GET",
                    "parameter": "content",
                    "location": "query",
                    "payload": "<!-- synapse-ssi-marker -->",
                }
            )
        )

        self.assertFalse(ssti_replay["sendsTraffic"])
        self.assertIn("%7B%7B7%2A7%7D%7D", ssti_replay["request"]["url"])
        self.assertFalse(ssi_replay["sendsTraffic"])
        self.assertIn("synapse-ssi-marker", ssi_replay["request"]["url"])
        with self.assertRaisesRegex(Exception, "built-in benign payloads"):
            ssti.prepare_replay({"candidate": candidate, "payload": "{{ self.__init__ }}"})

    def test_workspace_os_inference_uses_technology_components(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data(
                    "engagement",
                    "iis.example.com",
                    "adapter_result",
                    "passive_analysis",
                    "json",
                    json.dumps({"entities": {"observations": [{"type": "technology_component", "name": "Microsoft-IIS", "value": "Microsoft-IIS"}]}}),
                )
                iis_result = fingerprint.analyze_workspace({"workspaceId": "engagement", "target": "iis.example.com", "ingest": False})
                self.assertGreaterEqual(iis_result["fingerprint"]["possibleOs"].get("windows", 0), 1)

                workspace.ingest_data(
                    "juice",
                    "juice.example.com",
                    "adapter_result",
                    "passive_analysis",
                    "json",
                    json.dumps({"entities": {"observations": [{"type": "technology_component", "name": "OWASP Juice Shop", "value": "OWASP Juice Shop"}]}}),
                )
                juice_result = fingerprint.analyze_workspace({"workspaceId": "juice", "target": "juice.example.com", "ingest": False})
                self.assertEqual(juice_result["fingerprint"]["possibleOs"], {})

    def test_command_injection_unknown_os_uses_portable_markers(self) -> None:
        self.assertEqual(
            command_injection_adapter.benign_payloads("unknown", "SYNAPSE_T"),
            ["; echo SYNAPSE_T", "& echo SYNAPSE_T", "| echo SYNAPSE_T"],
        )
        candidate = command_injection_adapter.candidate_from_parameter(
            {"name": "cmd", "url": "https://example.com/admin/run?cmd=id", "method": "GET", "location": "query"},
            {"method": "GET", "path": "/admin/run"},
            {"family": "unknown", "confidence": "low"},
        )
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate["osFamily"], "unknown")
        self.assertEqual(candidate["payloadPreview"], ["; echo SYNAPSE_TOKEN", "& echo SYNAPSE_TOKEN", "| echo SYNAPSE_TOKEN"])

    def test_reference_active_tests_require_confirm(self) -> None:
        candidate = {
            "candidateId": "ssti_get_render_template",
            "url": "https://example.com/render?template=home",
            "method": "GET",
            "parameter": "template",
            "location": "query",
        }
        response = stdio_server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "ssti.execute_test", "arguments": {"candidate": candidate}},
            }
        )
        self.assertIsNotNone(response)
        self.assertEqual(response["error"]["code"], -32001)

    def test_reference_active_tests_are_scoped_approved_and_record_actions(self) -> None:
        class ReferenceHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urlsplit(self.path)
                params = parse_qs(parsed.query)
                if parsed.path == "/render":
                    template = params.get("template", [""])[0]
                    body = "49" if template == "{{7*7}}" else template
                elif parsed.path == "/download":
                    file_value = params.get("file", [""])[0]
                    body = "public robots" if file_value in {"robots.txt", "./robots.txt"} else "normalized public robots"
                elif parsed.path == "/ssi":
                    content = params.get("content", [""])[0]
                    body = "DATE_LOCAL_VALUE" if content.startswith("<!--#echo") else content
                else:
                    body = "ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), ReferenceHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    base = f"http://127.0.0.1:{server.server_port}"
                    scope.save_scope([base], "test")

                    ssti_result = json.loads(
                        ssti.execute_test(
                            {
                                "candidate": {
                                    "candidateId": "ssti_local",
                                    "url": f"{base}/render?template=home",
                                    "method": "GET",
                                    "parameter": "template",
                                    "location": "query",
                                },
                                "workspaceId": "engagement",
                                "confirm": True,
                                "approvalReason": "unit test approved benign SSTI probe",
                                "maxPayloads": 1,
                            }
                        )
                    )
                    self.assertEqual(ssti_result["test"]["assessment"], "possible_ssti")
                    ssti_test = ssti_result["test"]["tests"][0]
                    self.assertIn("bodySha256", ssti_test["response"])
                    self.assertNotIn("body", ssti_test["response"])
                    ssti_exchange = Path(ssti_test["exchangeEvidence"]["rawPath"])
                    self.assertTrue(ssti_exchange.exists())
                    self.assertIn('"body": "49"', ssti_exchange.read_text(encoding="utf-8"))

                    lfi_result = json.loads(
                        lfi_rfi.execute_test(
                            {
                                "candidate": {
                                    "candidateId": "lfi_local",
                                    "url": f"{base}/download?file=report.pdf",
                                    "method": "GET",
                                    "parameter": "file",
                                    "location": "query",
                                },
                                "workspaceId": "engagement",
                                "confirm": True,
                                "approvalReason": "unit test approved benign LFI probe",
                            }
                        )
                    )
                    self.assertEqual(lfi_result["test"]["assessment"], "file_handling_behavior_observed")
                    lfi_exchange = Path(lfi_result["test"]["tests"][0]["exchangeEvidence"]["rawPath"])
                    self.assertTrue(lfi_exchange.exists())
                    self.assertIn("public robots", lfi_exchange.read_text(encoding="utf-8"))

                    ssi_result = json.loads(
                        ssi.execute_test(
                            {
                                "candidate": {
                                    "candidateId": "ssi_local",
                                    "url": f"{base}/ssi?content=hello",
                                    "method": "GET",
                                    "parameter": "content",
                                    "location": "query",
                                },
                                "workspaceId": "engagement",
                                "confirm": True,
                                "approvalReason": "unit test approved benign SSI probe",
                            }
                        )
                    )
                    self.assertEqual(ssi_result["test"]["assessment"], "possible_ssi")
                    ssi_exchange = Path(ssi_result["test"]["tests"][-1]["exchangeEvidence"]["rawPath"])
                    self.assertTrue(ssi_exchange.exists())
                    self.assertIn("DATE_LOCAL_VALUE", ssi_exchange.read_text(encoding="utf-8"))

                    context = workspace.prepare_target_context("engagement", "127.0.0.1")
                    observation_types = {item["type"] for item in context["observations"]}
                    self.assertIn("possible_ssti", observation_types)
                    self.assertIn("file_handling_behavior_observed", observation_types)
                    self.assertIn("possible_ssi", observation_types)
                    self.assertGreaterEqual(len(context["recentActions"]), 3)
        finally:
            server.shutdown()
            server.server_close()

    def test_ssi_execute_test_does_not_flag_non_reflecting_endpoint(self) -> None:
        class StaticHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                # Static page that never renders the parameter: neither the marker
                # comment nor the echo directive is reflected, so SSI execution is
                # unprovable and the verdict must stay inconclusive (not possible_ssi).
                self.wfile.write(b"<html><body>static catalog page</body></html>")

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), StaticHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    base = f"http://127.0.0.1:{server.server_port}"
                    scope.save_scope([base], "test")
                    result = json.loads(
                        ssi.execute_test(
                            {
                                "candidate": {
                                    "candidateId": "ssi_static",
                                    "url": f"{base}/page?content=hello",
                                    "method": "GET",
                                    "parameter": "content",
                                    "location": "query",
                                },
                                "workspaceId": "engagement",
                                "confirm": True,
                                "approvalReason": "unit test non-reflecting SSI endpoint",
                            }
                        )
                    )
                    self.assertEqual(result["test"]["assessment"], "inconclusive")
        finally:
            server.shutdown()
            server.server_close()


class GraphqlAdapterTests(unittest.TestCase):
    def test_passive_flags_graphql_endpoint_without_traffic(self) -> None:
        raw = json.dumps(
            {
                "hosts": [
                    {
                        "host": "example.com",
                        "urls": [
                            {
                                "url": "https://example.com/graphql",
                                "methods": ["POST"],
                                "statusCodes": [200],
                                "graphqlEndpoint": True,
                            }
                        ],
                    }
                ],
                "summary": {"hostCount": 1, "urlCount": 1},
            }
        )
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)
                result = json.loads(graphql.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))
                self.assertEqual(result["candidateCount"], 1)
                observation_types = {item["type"] for item in result["entities"]["observations"]}
                self.assertIn("graphql_endpoint", observation_types)
                self.assertIn("introspection_candidate", observation_types)

    def test_execute_test_requires_confirmation_before_traffic(self) -> None:
        seen: list[str] = []

        class GraphqlHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                seen.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), GraphqlHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    base = f"http://127.0.0.1:{server.server_port}"
                    with self.assertRaises(McpError):
                        graphql.execute_test({"url": f"{base}/graphql", "workspaceId": "engagement"})
                    self.assertEqual(seen, [])
        finally:
            server.shutdown()
            server.server_close()

    def test_execute_test_normalizes_enabled_introspection_schema(self) -> None:
        class GraphqlHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                body = {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "mutationType": {"name": "Mutation"},
                            "types": [
                                {
                                    "name": "Query",
                                    "kind": "OBJECT",
                                    "fields": [
                                        {"name": "user", "args": [{"name": "id", "type": {"name": "ID", "kind": "SCALAR"}}]}
                                    ],
                                },
                                {
                                    "name": "Mutation",
                                    "kind": "OBJECT",
                                    "fields": [
                                        {"name": "updateUser", "args": [{"name": "id", "type": {"name": "ID", "kind": "SCALAR"}}]}
                                    ],
                                },
                            ],
                        }
                    }
                }
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode("utf-8"))

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), GraphqlHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    base = f"http://127.0.0.1:{server.server_port}"
                    scope.save_scope([base], "test")
                    result = json.loads(
                        graphql.execute_test(
                            {
                                "url": f"{base}/graphql",
                                "workspaceId": "engagement",
                                "confirm": True,
                                "approvalReason": "unit test approved GraphQL introspection probe",
                            }
                        )
                    )
                    self.assertEqual(result["test"]["assessment"], "introspection_enabled")
                    self.assertTrue(result["action"]["created"])
                    self.assertEqual(result["action"]["action"]["tool"], "graphql.execute_test")
                    self.assertNotIn("Authorization", result["test"]["requestHeaders"])
                    graphql_exchange = Path(result["test"]["exchangeEvidence"]["rawPath"])
                    self.assertTrue(graphql_exchange.exists())
                    self.assertIn("__schema", graphql_exchange.read_text(encoding="utf-8"))
                    context = workspace._load_target_entities("engagement", "127.0.0.1")
                    graphql_endpoints = [item for item in context["endpoints"] if item.get("source") == "graphql"]
                    graphql_parameters = [item for item in context["parameters"] if item.get("location") == "graphql"]
                    observation_types = {item["type"] for item in context["observations"]}
                    self.assertGreaterEqual(len(graphql_endpoints), 2)
                    self.assertGreaterEqual(len(graphql_parameters), 2)
                    self.assertIn("graphql_introspection_enabled", observation_types)
        finally:
            server.shutdown()
            server.server_close()

    def test_execute_test_disabled_introspection_creates_no_schema_entities(self) -> None:
        class DisabledGraphqlHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"errors":[{"message":"Introspection disabled"}]}')

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), DisabledGraphqlHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    base = f"http://127.0.0.1:{server.server_port}"
                    scope.save_scope([base], "test")
                    result = json.loads(
                        graphql.execute_test(
                            {
                                "url": f"{base}/graphql",
                                "workspaceId": "engagement",
                                "confirm": True,
                                "approvalReason": "unit test approved disabled GraphQL introspection check",
                            }
                        )
                    )
                    self.assertEqual(result["test"]["assessment"], "introspection_disabled")
                    context = workspace._load_target_entities("engagement", "127.0.0.1")
                    self.assertFalse([item for item in context["endpoints"] if item.get("source") == "graphql"])
        finally:
            server.shutdown()
            server.server_close()



def _b64(payload: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")


def _hs256_token(header: dict, payload: dict, secret: str) -> str:
    signing_input = f"{_b64(header)}.{_b64(payload)}"
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
    return f"{signing_input}.{base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')}"


class JwtAdapterTests(unittest.TestCase):
    def test_alg_none_and_privileged_claim_flagged(self) -> None:
        token = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': '1', 'role': 'admin'})}."
        result = json.loads(jwt_analysis.analyze({"token": token}))
        types = {item["type"] for item in result["findings"]}
        self.assertIn("jwt_alg_none", types)
        self.assertIn("jwt_dangerous_claim", types)
        self.assertIn("jwt_missing_expiry", types)
        self.assertGreaterEqual(result["highSeverityCount"], 1)

    def test_weak_secret_detected_without_echoing_secret(self) -> None:
        token = _hs256_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999}, "qwerty")
        raw = jwt_analysis.analyze({"token": token})
        result = json.loads(raw)
        weak = [item for item in result["findings"] if item["type"] == "jwt_weak_secret"]
        self.assertEqual(len(weak), 1)
        self.assertEqual(weak[0]["severity"], "high")
        self.assertNotIn("qwerty", raw)

    def test_kid_injection_surface_flagged(self) -> None:
        token = f"{_b64({'alg': 'HS256', 'kid': '../../keys/pub.pem'})}.{_b64({'sub': '1', 'exp': 9999999999})}.sig"
        result = json.loads(jwt_analysis.analyze({"token": token}))
        self.assertIn("jwt_kid_injection_surface", {item["type"] for item in result["findings"]})

    def test_sane_rs256_token_has_no_high_severity(self) -> None:
        token = f"{_b64({'alg': 'RS256', 'typ': 'JWT'})}.{_b64({'sub': '1', 'exp': 9999999999})}.sig"
        result = json.loads(jwt_analysis.analyze({"token": token}))
        self.assertEqual(result["highSeverityCount"], 0)

    def test_malformed_token_raises(self) -> None:
        with self.assertRaises(McpError):
            jwt_analysis.analyze({"token": "not-a-jwt"})

    def test_optional_ingest_stores_redacted_observation(self) -> None:
        token = f"{_b64({'alg': 'none'})}.{_b64({'sub': '1'})}."
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                jwt_analysis.analyze({"token": token, "workspaceId": "engagement", "target": "api.example.com", "ingest": True})
                observations = workspace._load_target_entities("engagement", "api.example.com")["observations"]
                self.assertIn("jwt_alg_none", {o["type"] for o in observations})


if __name__ == "__main__":
    unittest.main()
