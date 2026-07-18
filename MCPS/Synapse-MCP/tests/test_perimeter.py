import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from helpers import assert_shared_html_shell, isolated_state
from synapse_mcp.core import fingerprint, perimeter, workspace
from synapse_mcp.core.errors import McpError
from synapse_mcp.core.http.models import HttpResponse
from synapse_mcp.transport import stdio_server


class FakeSession:
    def __init__(self, responses: list[HttpResponse]):
        self.responses = list(responses)
        self.requests = []

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def send(self, request):
        self.requests.append(request)
        if self.responses:
            return self.responses.pop(0)
        return HttpResponse(status=200, headers={}, body="")


class PerimeterTests(unittest.TestCase):
    def test_perimeter_reads_canonical_target_model(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com"])
                canonical_report = {
                    "workspaceId": "engagement",
                    "target": "app.example.com",
                    "asset": {"host": "app.example.com", "ports": []},
                    "services": [],
                    "webApplications": [],
                    "technologyComponents": [],
                    "loginPortals": [],
                    "protectedResources": [],
                    "findingCandidates": [],
                    "siteMap": {"endpointCount": 0},
                }
                workspace._write_json(workspace.target_model_path("engagement", "app.example.com", "perimeter.json"), canonical_report)
                workspace._write_json(
                    workspace.workspace_path("engagement") / "perimeter-summary.json",
                    {"workspaceId": "engagement", "targets": [{"target": "app.example.com"}], "counts": {"targets": 1}},
                )

                summary = perimeter.build_summary({"workspaceId": "engagement", "target": "app.example.com"})

                self.assertEqual(summary["targetCount"], 1)
                self.assertEqual(summary["targets"][0]["target"], "app.example.com")
                self.assertEqual(summary["targets"][0]["asset"]["host"], "app.example.com")

    def test_perimeter_filters_external_endpoints_and_canonicalizes_login_paths(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["localhost"])
                workspace.ingest_data(
                    "engagement",
                    "localhost",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "endpoints": [
                                    {"type": "endpoint", "url": "http://localhost:3000/ACCOUNT", "path": "/ACCOUNT", "method": "GET"},
                                    {"type": "endpoint", "url": "http://localhost:3000/account", "path": "/account", "method": "GET"},
                                    {
                                        "type": "endpoint",
                                        "url": "http://localhost:3000/2fa/assets/public/assets/public/assets/public/main.js",
                                        "path": "/2fa/assets/public/assets/public/assets/public/main.js",
                                        "method": "GET",
                                    },
                                    {"type": "endpoint", "url": "https://accounts.google.com/o/oauth2/v2/auth", "path": "/o/oauth2/v2/auth", "method": "GET"},
                                ],
                                "observations": [
                                    {
                                        "type": "possible_cors_misconfiguration",
                                        "value": "http://localhost:3000/2fa/assets/public/assets/public/assets/public/main.js",
                                        "reason": "Old polluted crawler URL should be hidden from perimeter report candidates.",
                                    },
                                    {
                                        "type": "possible_cors_misconfiguration",
                                        "value": "https://accounts.google.com/o/oauth2/v2/auth",
                                        "reason": "External host should be hidden from target-owned perimeter report candidates.",
                                    },
                                ],
                            }
                        }
                    ),
                )

                report = perimeter.analyze_workspace({"workspaceId": "engagement", "target": "localhost", "includeTargets": True})["targets"][0]

                self.assertEqual([app["baseUrl"] for app in report["webApplications"]], ["http://localhost:3000/"])
                self.assertEqual(report["siteMap"]["endpointCount"], 2)
                self.assertEqual(report["webApplications"][0]["routeCount"], 2)
                self.assertEqual(len(report["loginPortals"]), 1)
                self.assertEqual(report["loginPortals"][0]["representativeUrl"], "http://localhost:3000/account")
                self.assertNotIn("accounts.google.com", json.dumps(report))
                self.assertNotIn("assets/public/assets/public/assets/public", json.dumps(report))

    def test_perimeter_analyzes_workspace_and_renders_reports(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com", "edge.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "services": [
                                    {
                                        "type": "service",
                                        "host": "app.example.com",
                                        "address": "203.0.113.10",
                                        "port": 443,
                                        "protocol": "tcp",
                                        "name": "https",
                                        "product": "nginx",
                                        "version": "1.22.1",
                                    }
                                ],
                                "endpoints": [
                                    {
                                        "type": "endpoint",
                                        "url": "https://app.example.com/",
                                        "path": "/",
                                        "method": "GET",
                                        "title": "Easy!Appointments",
                                        "cookieNames": ["PHPSESSID"],
                                    },
                                    {
                                        "type": "endpoint",
                                        "url": "https://app.example.com/login",
                                        "path": "/login",
                                        "method": "POST",
                                        "inputNames": ["username", "password", "csrfToken"],
                                    },
                                    {
                                        "type": "endpoint",
                                        "url": "https://app.example.com/api/users?id=42",
                                        "path": "/api/users",
                                        "method": "GET",
                                        "status": 200,
                                        "queryParameters": ["id"],
                                        "title": "Users",
                                        "apiRoute": True,
                                    },
                                ],
                                "observations": [
                                    {
                                        "type": "open_redirect_candidate",
                                        "value": "https://app.example.com/login?next=/",
                                        "priorityScore": 70,
                                        "confidence": "low",
                                        "testPlanSummary": "Validate harmless off-site redirect behavior.",
                                    }
                                ],
                            }
                        }
                    ),
                )
                workspace.ingest_data(
                    "engagement",
                    "edge.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "services": [
                                    {
                                        "type": "service",
                                        "host": "edge.example.com",
                                        "port": 443,
                                        "protocol": "tcp",
                                        "name": "https",
                                        "product": "Cloudflare http proxy",
                                    }
                                ],
                                "endpoints": [
                                    {
                                        "type": "endpoint",
                                        "url": "https://edge.example.com/",
                                        "path": "/",
                                        "method": "GET",
                                        "status": 403,
                                    }
                                ],
                            }
                        }
                    ),
                )

                analyzed = json.loads(stdio_server.call_tool("perimeter.analyze_workspace", {"workspaceId": "engagement"}))
                self.assertEqual(analyzed["summary"]["counts"]["targets"], 2)
                self.assertGreaterEqual(analyzed["summary"]["counts"]["technologyComponents"], 3)
                self.assertEqual(analyzed["summary"]["counts"]["loginPortals"], 1)
                self.assertNotIn("targets", analyzed)
                self.assertTrue(Path(analyzed["reportPath"]).exists())

                app_perimeter = Path(tmp) / "workspaces" / "engagement" / "targets" / "app.example.com" / "models" / "perimeter.json"
                summary_path = Path(tmp) / "workspaces" / "engagement" / "perimeter-summary.json"
                self.assertTrue(app_perimeter.exists())
                self.assertTrue(summary_path.exists())

                target_report = json.loads(app_perimeter.read_text(encoding="utf-8"))
                tech_names = {item["name"] for item in target_report["technologyComponents"]}
                self.assertIn("Easy!Appointments", tech_names)
                self.assertIn("PHP", tech_names)
                self.assertTrue(target_report["loginPortals"])
                self.assertTrue(target_report["findingCandidates"])
                self.assertEqual(target_report["siteMap"]["endpointCount"], 3)
                self.assertEqual(target_report["siteMap"]["tree"]["children"][0]["name"], "api")

                summary = perimeter.build_summary({"workspaceId": "engagement"})
                matrix_names = {item["technology"] for item in summary["summary"]["technologyMatrix"]}
                self.assertIn("Cloudflare http proxy", matrix_names)

                markdown = json.loads(
                    stdio_server.call_tool(
                        "perimeter.render_report",
                        {"workspaceId": "engagement", "format": "markdown", "outputPath": "reports/perimeter.md"},
                    )
                )
                self.assertIn("# External Perimeter Assessment", markdown["content"])
                self.assertIn("Easy!Appointments", markdown["content"])
                self.assertTrue(Path(markdown["path"]).exists())

                html = json.loads(
                    stdio_server.call_tool(
                        "perimeter.render_report",
                        {"workspaceId": "engagement", "format": "html", "outputPath": "reports/perimeter.html"},
                    )
                )
                self.assertIn("<table>", html["content"])
                self.assertIn("External Perimeter Assessment", html["content"])
                self.assertIn('class="banner"', html["content"])
                self.assertIn('class="banner-art"', html["content"])
                self.assertIn("agentic operations layer", html["content"])
                self.assertIn("mode-badge", html["content"])
                assert_shared_html_shell(self, html["content"])
                self.assertIn("Login Portals", html["content"])
                self.assertIn("<section><h2>Site Map</h2>", html["content"])
                self.assertIn("synapseToggleSiteMap", html["content"])
                self.assertIn("api", html["content"])
                self.assertIn("users ?id", html["content"])
                self.assertIn("Expand all", html["content"])
                self.assertIn("Request URL", html["content"])
                self.assertIn("Open redirect candidate", html["content"])
                self.assertIn("https://app.example.com/login?next=/", html["content"])
                self.assertTrue(Path(html["path"]).exists())

                single_target = json.loads(
                    stdio_server.call_tool(
                        "perimeter.render_report",
                        {"workspaceId": "engagement", "target": "app.example.com", "format": "html", "outputPath": "reports/application-surface.html"},
                    )
                )
                self.assertIn("Application Surface Assessment", single_target["content"])
                self.assertNotIn("External Perimeter Assessment", single_target["content"])

                default_report = json.loads(
                    stdio_server.call_tool(
                        "perimeter.render_report",
                        {"workspaceId": "engagement", "format": "markdown"},
                    )
                )
                self.assertEqual(Path(default_report["path"]).name, "perimeter.md")
                self.assertEqual(Path(default_report["path"]).parent.name, "engagement")
                # Reports live in the workspace-owned reports root, never inside workspace state.
                default_path = Path(default_report["path"]).resolve()
                self.assertTrue(default_path.is_relative_to(workspace.REPORTS_DIR.resolve()))
                self.assertFalse(default_path.is_relative_to(workspace.WORKSPACES_DIR.resolve()))

                nested_data = stdio_server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "perimeter.render_report",
                            "arguments": {
                                "workspaceId": "engagement",
                                "format": "markdown",
                                "outputPath": "DATA/workspaces/engagement/reports/perimeter.md",
                            },
                        },
                    }
                )
                self.assertIsNotNone(nested_data)
                self.assertEqual(nested_data["error"]["code"], -32602)
                self.assertIn("workspace-relative", nested_data["error"]["message"])

                sibling = stdio_server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "perimeter.render_report",
                            "arguments": {
                                "workspaceId": "engagement",
                                "format": "markdown",
                                "outputPath": str(workspace.workspace_path("engagement").parent / "engagement-malicious" / "perimeter.md"),
                            },
                        },
                    }
                )
                self.assertIsNotNone(sibling)
                self.assertEqual(sibling["error"]["code"], -32602)
                self.assertIn("allowExternalOutput", sibling["error"]["message"])

    def test_seuelectronica_login_variants_collapse_and_404_auth_path_is_excluded(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                login_urls = [
                    f"https://seuelectronica.example/sta/CarpetaPrivate/Login?PAGE_CODE={code}&lang=es"
                    for code in ("HOME", "DOCS", "TAX", "PROFILE")
                ]
                endpoints = [
                    {
                        "type": "endpoint",
                        "url": url,
                        "path": "/sta/CarpetaPrivate/Login",
                        "method": "GET",
                        "status": 200,
                        "title": "Login",
                        "inputNames": ["username", "password"],
                    }
                    for url in login_urls
                ]
                endpoints.append(
                    {
                        "type": "endpoint",
                        "url": "https://seuelectronica.example/reg/auth/",
                        "path": "/reg/auth/",
                        "method": "GET",
                        "status": 404,
                        "title": "404 Not Found",
                    }
                )
                workspace.ingest_data(
                    "engagement",
                    "seuelectronica.example",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps({"entities": {"endpoints": endpoints}}),
                )

                analyzed = perimeter.analyze_workspace({"workspaceId": "engagement", "target": "seuelectronica.example", "includeTargets": True})
                report = analyzed["targets"][0]

                self.assertEqual(len(report["loginPortals"]), 1)
                portal = report["loginPortals"][0]
                self.assertEqual(portal["representativeUrl"], "https://seuelectronica.example/sta/CarpetaPrivate/Login")
                self.assertEqual(portal["variantCount"], 4)
                self.assertEqual(len([item for item in report["findingCandidates"] if item.get("source") == "login_portal"]), 1)
                self.assertNotIn("/reg/auth/", json.dumps(report["loginPortals"]))

    def test_perimeter_candidate_report_rows_include_request_context_and_merge_duplicates(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
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
                                        "type": "post_form_candidate",
                                        "value": "form:/account/upload#file",
                                        "url": "https://app.example.com/account/upload",
                                        "method": "POST",
                                        "inputNames": ["file", "csrf"],
                                        "confidence": "medium",
                                        "reason": "POST form was identified but not submitted to avoid mutating application state.",
                                    },
                                    {
                                        "type": "post_form_candidate",
                                        "value": "form:/account/upload#csrf",
                                        "url": "https://app.example.com/account/upload",
                                        "method": "POST",
                                        "inputNames": ["file", "csrf"],
                                        "confidence": "medium",
                                        "reason": "POST form was identified but not submitted to avoid mutating application state.",
                                    },
                                    {
                                        "type": "lfi_candidate",
                                        "value": "https://app.example.com/download?file=manual.pdf",
                                        "url": "https://app.example.com/download?file=manual.pdf",
                                        "method": "GET",
                                        "parameter": "file",
                                        "location": "query",
                                        "priorityScore": 70,
                                        "reason": "Parameter name suggests file, path, include, view, download, locale, theme, or resource behavior.",
                                    },
                                ]
                            }
                        }
                    ),
                )

                report = perimeter.analyze_workspace({"workspaceId": "engagement", "target": "app.example.com", "includeTargets": True})["targets"][0]
                post_rows = [item for item in report["findingCandidates"] if item.get("category") == "State-changing POST form candidate"]
                self.assertEqual(len(post_rows), 1)
                self.assertEqual(post_rows[0]["url"], "https://app.example.com/account/upload")
                self.assertEqual(post_rows[0]["method"], "POST")
                self.assertEqual(post_rows[0]["occurrenceCount"], 2)

                html = perimeter.render_report({"workspaceId": "engagement", "format": "html"})["content"]
                self.assertIn("State-changing POST form candidate", html)
                self.assertIn("https://app.example.com/account/upload", html)
                self.assertIn("File handling candidate", html)
                self.assertIn("<td>file</td>", html)

    def test_perimeter_surfaces_tier1_adapter_observations_as_candidates(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
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
                                        "type": "missing_security_header",
                                        "value": "https://app.example.com/",
                                        "url": "https://app.example.com/",
                                        "method": "GET",
                                        "header": "content-security-policy",
                                        "priority": "medium",
                                        "priorityScore": 60,
                                        "reason": "No Content-Security-Policy is set.",
                                    },
                                    {
                                        "type": "missing_security_header",
                                        "value": "https://app.example.com/account",
                                        "url": "https://app.example.com/account",
                                        "method": "GET",
                                        "header": "content-security-policy",
                                        "priority": "medium",
                                        "priorityScore": 60,
                                        "reason": "No Content-Security-Policy is set.",
                                    },
                                    {
                                        "type": "insecure_cookie_flag",
                                        "value": "https://app.example.com/",
                                        "url": "https://app.example.com/",
                                        "method": "GET",
                                        "cookie": "SESSIONID",
                                        "flag": "httponly",
                                        "priorityScore": 70,
                                        "reason": "Session-like cookie is missing HttpOnly.",
                                    },
                                    {
                                        "type": "possible_cors_misconfiguration",
                                        "value": "https://app.example.com/api",
                                        "url": "https://app.example.com/api",
                                        "method": "GET",
                                        "priorityScore": 80,
                                        "reason": "Approved probe origin was reflected.",
                                    },
                                    {
                                        "type": "jwt_missing_expiry",
                                        "value": "alg=HS256",
                                        "priorityScore": 50,
                                        "reason": "JWT payload does not include exp.",
                                    },
                                ]
                            }
                        }
                    ),
                )

                report = perimeter.analyze_workspace({"workspaceId": "engagement", "target": "app.example.com", "includeTargets": True})["targets"][0]
                categories = {item.get("category") for item in report["findingCandidates"]}
                self.assertIn("Security header hygiene candidate", categories)
                self.assertIn("Cookie hygiene candidate", categories)
                self.assertIn("CORS candidate", categories)
                self.assertIn("JWT candidate", categories)
                header_rows = [item for item in report["findingCandidates"] if item.get("category") == "Security header hygiene candidate"]
                self.assertEqual(len(header_rows), 1)
                self.assertEqual(header_rows[0]["occurrenceCount"], 2)
                self.assertEqual(header_rows[0]["url"], "")
                self.assertIn("Content-Security-Policy", header_rows[0]["request"])
                self.assertEqual(header_rows[0]["sampleValues"], ["GET observed response"])

                html = perimeter.render_report({"workspaceId": "engagement", "format": "html"})["content"]
                self.assertIn("Security header hygiene candidate", html)
                self.assertIn("Cookie hygiene candidate", html)
                self.assertIn("CORS candidate", html)
                self.assertIn("JWT candidate", html)

    def test_workspace_fingerprint_and_perimeter_normalize_technologies(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "services": [
                                    {"type": "service", "host": "app.example.com", "port": 80, "protocol": "tcp", "name": "http"},
                                    {"type": "service", "host": "app.example.com", "port": 443, "protocol": "tcp", "name": "https"},
                                    {"type": "service", "host": "app.example.com", "port": 8443, "protocol": "tcp", "name": "https", "product": "nginx", "version": "1.22.1"},
                                    {"type": "service", "host": "app.example.com", "port": 8080, "protocol": "tcp", "name": "http", "product": "Apache httpd", "version": "2.4.67"},
                                ],
                                "endpoints": [
                                    {
                                        "type": "endpoint",
                                        "url": "https://app.example.com/",
                                        "path": "/",
                                        "method": "GET",
                                        "responseHeaders": {"x-powered-by": "Express", "x-recruiting": "OWASP Juice Shop"},
                                    }
                                ],
                            }
                        }
                    ),
                )

                fp = fingerprint.analyze_workspace({"workspaceId": "engagement", "target": "app.example.com", "ingest": True})
                components = {(item["name"], item.get("version", "")) for item in fp["fingerprint"]["technologyComponents"]}
                self.assertNotIn(("http", ""), components)
                self.assertNotIn(("https", ""), components)
                self.assertIn(("nginx", "1.22.1"), components)
                self.assertIn(("Apache httpd", "2.4.67"), components)
                self.assertIn(("Express", ""), components)
                self.assertIn(("Node.js", ""), components)
                self.assertIn(("OWASP Juice Shop", ""), components)

                report = perimeter.analyze_workspace({"workspaceId": "engagement", "target": "app.example.com", "includeTargets": True})["targets"][0]
                matrix = perimeter.build_summary({"workspaceId": "engagement", "target": "app.example.com"})["summary"]["technologyMatrix"]
                matrix_names = {(item["name"], item.get("version", "")) for item in matrix}
                self.assertIn(("nginx", "1.22.1"), matrix_names)
                self.assertIn(("Apache httpd", "2.4.67"), matrix_names)
                self.assertIn(("OWASP Juice Shop", ""), matrix_names)
                self.assertNotIn("http", {item["name"] for item in report["technologyComponents"]})

    def test_component_gets_synthesized_cpe_and_exact_precision(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "services": [
                                    {
                                        "type": "service",
                                        "host": "app.example.com",
                                        "port": 8080,
                                        "protocol": "tcp",
                                        "name": "http",
                                        "product": "Apache httpd",
                                        "version": "2.4.49",
                                    }
                                ]
                            }
                        }
                    ),
                )

                fp = fingerprint.analyze_workspace({"workspaceId": "engagement", "target": "app.example.com", "ingest": True})
                component = next(item for item in fp["fingerprint"]["technologyComponents"] if item["name"] == "Apache httpd")
                expected_cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
                self.assertEqual(component["cpe"], expected_cpe)
                self.assertEqual(component["versionPrecision"], "exact")

                observations = workspace._load_target_entities("engagement", "app.example.com")["observations"]
                observed = next(item for item in observations if item.get("type") == "technology_component" and item.get("name") == "Apache httpd")
                self.assertEqual(observed["cpe"], expected_cpe)
                self.assertEqual(observed["versionPrecision"], "exact")

    def test_versionless_component_gets_wildcard_cpe_and_unknown_precision(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "endpoints": [
                                    {
                                        "type": "endpoint",
                                        "url": "https://app.example.com/wp-content/themes/site/style.css",
                                        "path": "/wp-content/themes/site/style.css",
                                        "method": "GET",
                                    }
                                ]
                            }
                        }
                    ),
                )

                fp = fingerprint.analyze_workspace({"workspaceId": "engagement", "target": "app.example.com", "ingest": True})
                component = next(item for item in fp["fingerprint"]["technologyComponents"] if item["name"] == "WordPress")
                self.assertEqual(component["cpe"], "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*")
                self.assertEqual(component["versionPrecision"], "unknown")

    def test_unknown_product_has_empty_cpe(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "services": [
                                    {
                                        "type": "service",
                                        "host": "app.example.com",
                                        "port": 9443,
                                        "protocol": "tcp",
                                        "name": "https",
                                        "product": "Unmapped Product",
                                    }
                                ]
                            }
                        }
                    ),
                )

                fp = fingerprint.analyze_workspace({"workspaceId": "engagement", "target": "app.example.com", "ingest": True})
                component = next(item for item in fp["fingerprint"]["technologyComponents"] if item["name"] == "Unmapped Product")
                self.assertEqual(component["cpe"], "")
                self.assertEqual(component["versionPrecision"], "unknown")

    def test_perimeter_merges_versionless_and_cross_layer_technology_duplicates(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                # The same product seen with and without a version, and a product two
                # code paths classify into different layers, must collapse to a single
                # component (regression: duplicate "Apache httpd" / "Gencat server").
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
                                    {"type": "technology_component", "name": "Apache httpd", "version": "2.4.57", "layer": "web_server", "source": "response_header", "confidence": "high"},
                                    {"type": "technology_component", "name": "Apache httpd", "version": "", "layer": "web_server", "source": "response_header", "confidence": "high"},
                                    {"type": "technology_component", "name": "Gencat server", "version": "", "layer": "component", "source": "response_header", "confidence": "high"},
                                    {"type": "technology_component", "name": "Gencat server", "version": "", "layer": "service", "source": "response_header", "confidence": "high"},
                                ]
                            }
                        }
                    ),
                )
                report = perimeter.analyze_workspace({"workspaceId": "engagement", "target": "app.example.com", "includeTargets": True})["targets"][0]
                comps = report["technologyComponents"]
                apache = [c for c in comps if c["name"] == "Apache httpd"]
                gencat = [c for c in comps if c["name"] == "Gencat server"]
                self.assertEqual(len(apache), 1)
                self.assertEqual(apache[0]["version"], "2.4.57")
                self.assertEqual(len(gencat), 1)
                matrix = perimeter.build_summary({"workspaceId": "engagement", "target": "app.example.com"})["summary"]["technologyMatrix"]
                self.assertEqual(len([m for m in matrix if m["name"] == "Apache httpd"]), 1)

    def test_bare_nmap_service_name_is_not_a_technology_component(self) -> None:
        # nmap labels port 3000 "ppp" by default (a port-table guess, not a fingerprint). A bare
        # service name with no detected product/version must not be promoted to a technology
        # component in either the perimeter model or the fingerprint.
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["app.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "services": [
                                    {"type": "service", "host": "app.example.com", "port": 3000, "protocol": "tcp", "name": "ppp"},
                                    {"type": "service", "host": "app.example.com", "port": 443, "protocol": "tcp", "name": "https", "product": "nginx", "version": "1.25.0"},
                                ]
                            }
                        }
                    ),
                )
                report = perimeter.analyze_workspace({"workspaceId": "engagement", "target": "app.example.com", "includeTargets": True})["targets"][0]
                tech_names = {item["name"] for item in report["technologyComponents"]}
                self.assertNotIn("ppp", tech_names)
                self.assertIn("nginx", tech_names)

                fp = fingerprint.analyze_workspace({"workspaceId": "engagement", "target": "app.example.com"})
                self.assertNotIn("ppp", {item["name"] for item in fp["fingerprint"]["technologyComponents"]})

    def test_probe_versions_requires_confirm_and_scope(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["app.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps({"entities": {"observations": [{"type": "technology_component", "name": "Apache httpd", "layer": "web_server", "source": "response_header", "confidence": "high"}]}}),
                )

                with patch.object(fingerprint.http_client, "session") as session:
                    with self.assertRaisesRegex(McpError, "confirm=true"):
                        fingerprint.probe_versions({"workspaceId": "engagement", "target": "https://app.example.com/"})
                    session.assert_not_called()

                with patch.object(fingerprint.http_client, "session") as session:
                    with self.assertRaisesRegex(McpError, "not in authorized scope"):
                        fingerprint.probe_versions({"workspaceId": "engagement", "target": "https://other.example.com/", "confirm": True})
                    session.assert_not_called()

    def test_probe_versions_upgrades_precision(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["app.example.com"])
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
                                        "name": "Apache httpd",
                                        "version": "",
                                        "layer": "web_server",
                                        "source": "response_header",
                                        "confidence": "high",
                                    }
                                ]
                            }
                        }
                    ),
                )
                fake_session = FakeSession([HttpResponse(status=200, headers={"Server": "Apache/2.4.49"}, body="")])

                with patch.object(fingerprint.http_client, "session", return_value=fake_session):
                    result = fingerprint.probe_versions({"workspaceId": "engagement", "target": "https://app.example.com/", "confirm": True})

                expected_cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
                self.assertEqual(len(fake_session.requests), 1)
                self.assertEqual(result["requestCount"], 1)
                upgraded = result["upgradedComponents"][0]
                self.assertEqual(upgraded["name"], "Apache httpd")
                self.assertEqual(upgraded["version"], "2.4.49")
                self.assertEqual(upgraded["versionPrecision"], "exact")
                self.assertEqual(upgraded["cpe"], expected_cpe)
                self.assertTrue(result["probes"][0]["exchangeEvidence"]["evidenceId"])

                observations = workspace._load_target_entities("engagement", "app.example.com")["observations"]
                active = [item for item in observations if item.get("source") == "active_fingerprint_probe" and item.get("name") == "Apache httpd"]
                self.assertEqual(active[0]["version"], "2.4.49")
                self.assertEqual(active[0]["cpe"], expected_cpe)

                components = result["fingerprint"]["technologyComponents"]
                exact = next(item for item in components if item["name"] == "Apache httpd" and item.get("version") == "2.4.49")
                self.assertEqual(exact["versionPrecision"], "exact")
                self.assertEqual(exact["cpe"], expected_cpe)

                actions = workspace._load_target_entities("engagement", "app.example.com")["actions"]
                self.assertTrue(any(item.get("tool") == "fingerprint.probe_versions" for item in actions))

    def test_probe_versions_respects_request_budget(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["app.example.com"])
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
                                    {"type": "technology_component", "name": "WordPress", "layer": "web_application", "source": "endpoint", "confidence": "medium"},
                                    {"type": "technology_component", "name": "Drupal", "layer": "web_application", "source": "endpoint", "confidence": "medium"},
                                ]
                            }
                        }
                    ),
                )
                fake_session = FakeSession([HttpResponse(status=200, headers={}, body="")])

                with patch.object(fingerprint.http_client, "session", return_value=fake_session):
                    result = fingerprint.probe_versions({"workspaceId": "engagement", "target": "https://app.example.com/", "confirm": True, "maxRequests": 1})

                self.assertEqual(len(fake_session.requests), 1)
                self.assertEqual(result["requestCount"], 1)
                self.assertTrue(fake_session.requests[0].url.endswith("/"))

    def test_candidate_category_labels_injection_and_missing_header_findings(self) -> None:
        # SQLi/XSS candidates must not fall through to the generic "Candidate finding"
        # bucket, and a promoted "Missing ..." finding must not be mislabeled "SSI
        # candidate" via the bare-substring match on "mi-ssi-ng".
        self.assertEqual(perimeter._candidate_category("sqli_candidate"), "SQL injection candidate")
        self.assertEqual(perimeter._candidate_category("xss_candidate"), "XSS candidate")
        self.assertEqual(
            perimeter._candidate_category("finding", "Missing Content-Security-Policy Header"),
            "Security header hygiene candidate",
        )
        self.assertEqual(
            perimeter._candidate_category("finding", "Reflected Cross-Site Scripting in search"),
            "XSS candidate",
        )
        # Genuine SSI candidates still categorize correctly.
        self.assertEqual(perimeter._candidate_category("possible_ssi"), "SSI candidate")
        self.assertEqual(perimeter._candidate_category("html_sink_observed"), "SSI candidate")
        # Existing header/cookie hygiene mapping is preserved.
        self.assertEqual(perimeter._candidate_category("missing_security_header"), "Security header hygiene candidate")


if __name__ == "__main__":
    unittest.main()
