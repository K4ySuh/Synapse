import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import isolated_state
from synapse_mcp.adapters.web import crawler_adapter, sqlmap_adapter, sqlmap_analysis, xss_adapter, xss_analysis
from synapse_mcp.core import scope, workspace


class DumpAnalysisTests(unittest.TestCase):
    def test_sqli_dump_analysis_uses_request_files_without_burp(self) -> None:
        with TemporaryDirectory() as tmp:
            dump_dir = Path(tmp)
            requests_dir = dump_dir / "requests"
            responses_dir = dump_dir / "responses"
            requests_dir.mkdir()
            responses_dir.mkdir()
            request_file = requests_dir / "7.http"
            response_file = responses_dir / "7.http"
            request_file.write_text("GET /search?id=7 HTTP/1.1\r\nHost: example.com\r\n\r\n", encoding="utf-8")
            response_file.write_text(
                "HTTP/1.1 200 OK\r\nServer: Apache\r\nX-Powered-By: PHP/8.2\r\n\r\n",
                encoding="utf-8",
            )
            (dump_dir / "history.jsonl").write_text(
                (
                    '{"id":7,"host":"example.com","requestLine":"GET /search?id=7 HTTP/1.1",'
                    f'"requestFile":"{request_file}","responseFile":"{response_file}"}}\n'
                ),
                encoding="utf-8",
            )

            result = json.loads(
                sqlmap_analysis.analyze_burp_dump(
                    {
                        "dumpPath": str(dump_dir),
                        "level": 3,
                        "risk": 2,
                        "maxCandidatesPerRequest": 3,
                        "onlyInteresting": True,
                    }
                )
            )

            self.assertEqual(result["analyzedRequests"], 1)
            self.assertEqual(result["results"][0]["candidates"][0]["name"], "id")
            self.assertIn("PHP", result["aggregateTechnologies"])
            self.assertIn("MySQL", result["aggregatePossibleDbms"])

    def test_sqlmap_command_build_blocks_high_risk_options(self) -> None:
        with self.assertRaisesRegex(Exception, "Blocked sqlmap option"):
            sqlmap_analysis.build_sqlmap_command(1, 1, {"os-shell": True})

    def test_sqli_dump_analysis_can_ingest_workspace_observations(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                dump_dir = tmp_path / "dump"
                requests_dir = dump_dir / "requests"
                responses_dir = dump_dir / "responses"
                requests_dir.mkdir(parents=True)
                responses_dir.mkdir()
                request_file = requests_dir / "7.http"
                response_file = responses_dir / "7.http"
                request_file.write_text("GET /search?id=7 HTTP/1.1\r\nHost: example.com\r\n\r\n", encoding="utf-8")
                response_file.write_text("HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n", encoding="utf-8")
                (dump_dir / "history.jsonl").write_text(
                    json.dumps({"id": 7, "host": "example.com", "requestFile": str(request_file), "responseFile": str(response_file)}) + "\n",
                    encoding="utf-8",
                )

                result = json.loads(
                    sqlmap_adapter.analyze_dump(
                        {
                            "dumpPath": str(dump_dir),
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "ingest": True,
                            "level": 1,
                            "risk": 1,
                        }
                    )
                )
                context = workspace.prepare_target_context("engagement", "example.com")
                observation_types = {item["type"] for item in context["observations"]}

                self.assertIn("ingestion", result)
                self.assertIn("test_candidate", observation_types)
                sqli_surfaces = [
                    item
                    for item in context["observations"]
                    if item.get("type") == "test_candidate" and "sqli" in item.get("candidateFor", [])
                ]
                self.assertTrue(sqli_surfaces)

    def test_xss_generate_test_code_returns_payloads(self) -> None:
        result = json.loads(xss_analysis.generate_test_code({"parameter": "q", "context": "html"}))
        self.assertEqual(result["parameter"], "q")
        self.assertIn("<img src=x onerror=alert(1)>", result["payloads"])

    def test_xss_dump_analysis_can_ingest_workspace_observations(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                dump_dir = tmp_path / "dump"
                requests_dir = dump_dir / "requests"
                responses_dir = dump_dir / "responses"
                requests_dir.mkdir(parents=True)
                responses_dir.mkdir()
                request_file = requests_dir / "1.http"
                response_file = responses_dir / "1.http"
                request_file.write_text("GET /search?q=needle HTTP/1.1\r\nHost: example.com\r\n\r\n", encoding="utf-8")
                response_file.write_text(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>needle</body></html>",
                    encoding="utf-8",
                )
                (dump_dir / "history.jsonl").write_text(
                    json.dumps({"id": 1, "host": "example.com", "requestFile": str(request_file), "responseFile": str(response_file)}) + "\n",
                    encoding="utf-8",
                )

                result = json.loads(
                    xss_adapter.analyze_dump(
                        {
                            "dumpPath": str(dump_dir),
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "ingest": True,
                        }
                    )
                )
                context = workspace.prepare_target_context("engagement", "example.com")
                observation_types = {item["type"] for item in context["observations"]}

                self.assertIn("ingestion", result)
                self.assertIn("xss_candidate", observation_types)
                self.assertIn("xss_reflection", observation_types)

    def test_sitemap_from_dump_extracts_urls_links_and_forms(self) -> None:
        with TemporaryDirectory() as tmp:
            dump_dir = Path(tmp)
            requests_dir = dump_dir / "requests"
            responses_dir = dump_dir / "responses"
            requests_dir.mkdir()
            responses_dir.mkdir()
            request_file = requests_dir / "1.http"
            response_file = responses_dir / "1.http"
            patch_request_file = requests_dir / "2.http"
            patch_response_file = responses_dir / "2.http"
            request_file.write_text("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", encoding="utf-8")
            response_file.write_text(
                (
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                    "<html><head><title>Home</title></head><body>"
                    '<a href="/account?id=7">Account</a>'
                    '<form method="post" action="/search"><input name="q" value=""></form>'
                    "</body></html>"
                ),
                encoding="utf-8",
            )
            patch_request_file.write_text(
                (
                    "PATCH /api/profile HTTP/1.1\r\n"
                    "Host: example.com\r\n"
                    "Content-Type: application/json\r\n"
                    "\r\n"
                    '{"displayName":"Alice"}'
                ),
                encoding="utf-8",
            )
            patch_response_file.write_text("HTTP/1.1 204 No Content\r\nContent-Type: application/json\r\n\r\n", encoding="utf-8")
            (dump_dir / "history.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps({"id": 1, "host": "example.com", "requestFile": str(request_file), "responseFile": str(response_file)}),
                        json.dumps({"id": 2, "host": "example.com", "requestFile": str(patch_request_file), "responseFile": str(patch_response_file)}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            result = json.loads(
                crawler_adapter.sitemap_from_dump(
                    {
                        "dumpPath": str(dump_dir),
                        "onlyInScope": False,
                        "output": str(dump_dir / "sitemap.json"),
                        "allowExternalOutput": True,
                    }
                )
            )

            self.assertEqual(result["summary"]["hostCount"], 1)
            self.assertEqual(result["summary"]["formCount"], 1)
            urls = {item["url"]: item for item in result["hosts"][0]["urls"]}
            self.assertIn("https://example.com/", urls)
            self.assertIn("https://example.com/account?id=7", urls)
            self.assertIn("https://example.com/search", urls)
            self.assertIn("https://example.com/api/profile", urls)
            self.assertEqual(urls["https://example.com/"]["title"], "Home")
            self.assertIn("PATCH", urls["https://example.com/api/profile"]["methods"])
            self.assertTrue(urls["https://example.com/api/profile"]["stateChanging"])
            graph = result["flowGraph"]
            self.assertGreaterEqual(graph["summary"]["nodeCount"], 4)
            self.assertIn("PATCH", graph["summary"]["methodCounts"])
            self.assertTrue(any(edge["type"] == "request" and edge["method"] == "PATCH" and edge["observed"] for edge in graph["edges"]))
            self.assertTrue(any(edge["type"] == "form_action" and edge["method"] == "POST" and not edge["submitted"] for edge in graph["edges"]))
            mermaid_path = Path(graph["mermaidPath"])
            self.assertTrue(mermaid_path.exists())
            self.assertIn("flowchart LR", mermaid_path.read_text(encoding="utf-8"))
            svg_path = Path(graph["svgPath"])
            self.assertTrue(svg_path.exists())
            self.assertIn("<svg", svg_path.read_text(encoding="utf-8"))

    def test_sitemap_from_dump_can_ingest_workspace_entities(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                dump_dir = tmp_path / "dump"
                requests_dir = dump_dir / "requests"
                responses_dir = dump_dir / "responses"
                requests_dir.mkdir(parents=True)
                responses_dir.mkdir()
                request_file = requests_dir / "1.http"
                response_file = responses_dir / "1.http"
                request_file.write_text("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", encoding="utf-8")
                response_file.write_text(
                    (
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                        '<a href="/admin?next=/">Admin</a>'
                        '<form method="post" action="/login"><input name="username"></form>'
                    ),
                    encoding="utf-8",
                )
                (dump_dir / "history.jsonl").write_text(
                    f'{{"id":1,"host":"example.com","requestFile":"{request_file}","responseFile":"{response_file}"}}\n',
                    encoding="utf-8",
                )

                result = json.loads(
                    crawler_adapter.sitemap_from_dump(
                        {
                            "dumpPath": str(dump_dir),
                            "onlyInScope": False,
                            "workspaceId": "engagement",
                        }
                    )
                )
                context = workspace.prepare_target_context("engagement", "example.com")

                self.assertEqual(len(result["ingestions"]), 1)
                self.assertEqual(context["knownEndpoints"]["total"], 3)
                parameter_names = {item["name"] for item in context["parameters"]["sample"]}
                self.assertEqual(parameter_names, {"next", "username"})

    def test_sitemap_from_dump_extracts_rich_burp_request_context(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                scope.save_scope(["example.com"], "test", "Example Client")
                dump_dir = tmp_path / "dump"
                requests_dir = dump_dir / "requests"
                responses_dir = dump_dir / "responses"
                requests_dir.mkdir(parents=True)
                responses_dir.mkdir()

                graphql_request = requests_dir / "1.http"
                graphql_response = responses_dir / "1.http"
                graphql_request.write_text(
                    (
                        "POST /api/graphql?debug=true HTTP/1.1\r\n"
                        "Host: example.com\r\n"
                        "Content-Type: application/json\r\n"
                        "Cookie: SESSIONID=abcdef; PREF=light\r\n"
                        "Authorization: Bearer secret-token\r\n"
                        "\r\n"
                        '{"operationName":"GetUser","query":"query GetUser { user { name } }","variables":{"id":"1"}}'
                    ),
                    encoding="utf-8",
                )
                graphql_response.write_text(
                    (
                        "HTTP/1.1 500 Internal Server Error\r\n"
                        "Content-Type: application/json\r\n"
                        "\r\n"
                        '{"error":"Internal Server Error","detail":"Traceback hidden"}'
                    ),
                    encoding="utf-8",
                )

                form_request = requests_dir / "2.http"
                form_response = responses_dir / "2.http"
                form_request.write_text(
                    (
                        "POST /login HTTP/1.1\r\n"
                        "Host: example.com\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "\r\n"
                        "username=alice&password=super-secret"
                    ),
                    encoding="utf-8",
                )
                form_response.write_text(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\nForbidden",
                    encoding="utf-8",
                )

                redirect_request = requests_dir / "3.http"
                redirect_response = responses_dir / "3.http"
                redirect_request.write_text("GET /old HTTP/1.1\r\nHost: example.com\r\n\r\n", encoding="utf-8")
                redirect_response.write_text(
                    "HTTP/1.1 302 Found\r\nContent-Type: text/html\r\nLocation: /login\r\n\r\n",
                    encoding="utf-8",
                )

                (dump_dir / "history.jsonl").write_text(
                    "\n".join(
                        [
                            json.dumps({"id": 1, "host": "example.com", "requestFile": str(graphql_request), "responseFile": str(graphql_response)}),
                            json.dumps({"id": 2, "host": "example.com", "requestFile": str(form_request), "responseFile": str(form_response)}),
                            json.dumps({"id": 3, "host": "example.com", "requestFile": str(redirect_request), "responseFile": str(redirect_response)}),
                        ]
                    )
                    + "\n",
                    encoding="utf-8",
                )

                result = json.loads(
                    crawler_adapter.sitemap_from_dump(
                        {
                            "dumpPath": str(dump_dir),
                            "workspaceId": "engagement",
                        }
                    )
                )
                serialized = json.dumps(result)
                self.assertNotIn("secret-token", serialized)
                self.assertNotIn("super-secret", serialized)

                urls = {item["url"]: item for item in result["hosts"][0]["urls"]}
                graphql_url = "https://example.com/api/graphql?debug=true"
                self.assertTrue(urls[graphql_url]["apiRoute"])
                self.assertTrue(urls[graphql_url]["jsonEndpoint"])
                self.assertTrue(urls[graphql_url]["graphqlEndpoint"])
                self.assertTrue(urls[graphql_url]["stateChanging"])
                self.assertTrue(urls[graphql_url]["hasAuthorization"])
                self.assertEqual(urls[graphql_url]["authorizationSchemes"], ["Bearer"])
                self.assertEqual(urls[graphql_url]["cookieNames"], ["PREF", "SESSIONID"])
                self.assertIn("operationName", urls[graphql_url]["jsonParameters"])
                self.assertIn("variables.id", urls[graphql_url]["jsonParameters"])
                self.assertIn("http_500", urls[graphql_url]["errorSignals"])

                self.assertEqual(set(urls["https://example.com/login"]["bodyParameters"]), {"password", "username"})
                self.assertTrue(urls["https://example.com/login"]["authBoundary"])
                self.assertEqual(urls["https://example.com/old"]["redirectLocations"], ["https://example.com/login"])
                self.assertTrue(urls["https://example.com/old"]["authBoundary"])

                context = workspace.prepare_target_context("engagement", "example.com")
                parameter_locations = {(item["name"], item["location"]) for item in context["inputParameters"]}
                self.assertIn(("debug", "query"), parameter_locations)
                self.assertIn(("operationName", "json"), parameter_locations)
                self.assertIn(("variables.id", "json"), parameter_locations)
                self.assertIn(("SESSIONID", "cookie"), parameter_locations)
                self.assertIn(("username", "body"), parameter_locations)
                observation_types = {item["type"] for item in context["observations"]}
                self.assertIn("api_route", observation_types)
                self.assertIn("json_endpoint", observation_types)
                self.assertIn("graphql_endpoint", observation_types)
                self.assertIn("authorization_header_observed", observation_types)
                self.assertIn("cookie_names_observed", observation_types)
                self.assertIn("interesting_error", observation_types)
                self.assertIn("auth_boundary", observation_types)
                self.assertIn("state_changing_method", observation_types)
                self.assertIn("redirect_observed", observation_types)



if __name__ == "__main__":
    unittest.main()
