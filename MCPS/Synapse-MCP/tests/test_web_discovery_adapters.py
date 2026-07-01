import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import parse_qs

from helpers import isolated_state, wait_for_job
from synapse_mcp.adapters.web import (
    command_injection_adapter,
    cors,
    crawler_adapter,
    csrf,
    headers_cookies,
    insecure_deser,
    lfi_rfi,
    open_redirect_adapter,
    spec_import,
    ssrf_adapter,
    ssti,
    tls_posture,
    xss_adapter,
    xxe,
)
from synapse_mcp.core import background_jobs, credentials, evidence, scope, workspace
from synapse_mcp.core.errors import McpError


class WebDiscoveryAdapterTests(unittest.TestCase):
    def test_crawler_prunes_spa_shell_phantom_assets_and_junk_paths(self) -> None:
        # A static/script URL the SPA answered with its HTML shell is a phantom endpoint;
        # the real asset (served as application/javascript) and real routes are kept.
        sitemap = crawler_adapter.new_sitemap({"target": "http://localhost:3000/"})
        crawler_adapter.upsert_url(sitemap, "http://localhost:3000/2fa/chunk-AAAA.js", status=200, content_type="text/html", fetched=True)
        crawler_adapter.upsert_url(sitemap, "http://localhost:3000/2fa/chunk-BBBB.js", discovered_from="http://localhost:3000/2fa/chunk-AAAA.js")
        crawler_adapter.upsert_url(sitemap, "http://localhost:3000/2fa/assets/public/app.js", discovered_from="http://localhost:3000/2fa")
        crawler_adapter.upsert_url(sitemap, "http://localhost:3000/160", status=200, content_type="text/html", fetched=True, discovered_from="http://localhost:3000/main.js")
        crawler_adapter.upsert_url(sitemap, "http://localhost:3000/chunk-AAAA.js", status=200, content_type="application/javascript", fetched=True)
        crawler_adapter.upsert_url(sitemap, "http://localhost:3000/rest/user/whoami", status=200, content_type="application/json", fetched=True)
        flat = crawler_adapter.flatten_sitemap(sitemap)
        urls = {record["url"] for host in flat["hosts"] for record in host["urls"]}
        self.assertNotIn("http://localhost:3000/2fa/chunk-AAAA.js", urls)
        self.assertNotIn("http://localhost:3000/2fa/chunk-BBBB.js", urls)
        self.assertNotIn("http://localhost:3000/2fa/assets/public/app.js", urls)
        self.assertNotIn("http://localhost:3000/160", urls)
        self.assertIn("http://localhost:3000/chunk-AAAA.js", urls)
        self.assertIn("http://localhost:3000/rest/user/whoami", urls)
        # A fetched .js that returns JS is not a phantom; a lone punctuation path is junk.
        self.assertTrue(crawler_adapter.is_spa_shell_asset({"url": "http://localhost:3000/x/a.js", "fetched": True, "contentTypes": ["text/html"]}))
        self.assertFalse(crawler_adapter.is_spa_shell_asset({"url": "http://localhost:3000/x/a.js", "fetched": True, "contentTypes": ["application/javascript"]}))
        self.assertFalse(crawler_adapter.valid_discovered_url("http://localhost:3000/2fa/assets/public/app.js"))
        self.assertFalse(crawler_adapter.valid_discovered_url("http://localhost:3000/assets/i18n/assets/public/app.js"))
        self.assertFalse(crawler_adapter.valid_discovered_url("http://localhost:3000/("))
        self.assertTrue(crawler_adapter.is_junk_path("http://localhost:3000/g,"))
        self.assertFalse(crawler_adapter.valid_discovered_url("http://localhost:3000/g,"))
        self.assertFalse(crawler_adapter.is_junk_path("http://localhost:3000/api/Users"))
        self.assertTrue(crawler_adapter.valid_discovered_url("http://localhost:3000/rest/products"))

    def test_crawler_respects_base_href_and_does_not_accumulate_asset_paths(self) -> None:
        seen_paths: list[str] = []

        class CrawlHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                seen_paths.append(self.path)
                if self.path == "/2fa":
                    body = (
                        '<html><head><base href="/"><title>Two Factor</title>'
                        '<script src="assets/public/app.js"></script></head>'
                        '<body><a href="rest/order-history">Orders</a></body></html>'
                    )
                    content_type = "text/html"
                elif self.path == "/assets/public/app.js":
                    body = "const route = '/rest/order-history';"
                    content_type = "application/javascript"
                elif self.path == "/rest/order-history":
                    body = '{"orders":[]}'
                    content_type = "application/json"
                else:
                    body = "<html><head><base href=\"/\"><script src=\"assets/public/app.js\"></script></head></html>"
                    content_type = "text/html"
                self.send_response(200 if self.path in {"/2fa", "/assets/public/app.js", "/rest/order-history"} else 404)
                self.send_header("Content-Type", content_type)
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), CrawlHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    target = f"http://127.0.0.1:{server.server_port}/2fa"
                    scope.save_scope([target], "test", "Example Client")
                    crawler_adapter.crawl(
                        {
                            "target": target,
                            "workspaceId": "engagement",
                            "maxDepth": 3,
                            "maxPages": 10,
                            "delayMillis": 0,
                            "background": False,
                            "confirm": True,
                        }
                    )

                    self.assertIn("/assets/public/app.js", seen_paths)
                    self.assertIn("/rest/order-history", seen_paths)
                    self.assertNotIn("/2fa/assets/public/app.js", seen_paths)
                    self.assertFalse(any("assets/public/assets/public" in path for path in seen_paths))
                    context = workspace.prepare_target_context("engagement", "127.0.0.1")
                    endpoint_urls = {item["url"] for item in workspace._load_target_entities("engagement", "127.0.0.1")["endpoints"]}
                    self.assertTrue(any(url.endswith("/assets/public/app.js") for url in endpoint_urls))
                    self.assertEqual(context["knownEndpoints"]["total"], len(endpoint_urls))
        finally:
            server.shutdown()
            server.server_close()

    def test_crawler_resolves_common_spa_assets_from_root_without_base_href(self) -> None:
        seen_paths: list[str] = []

        class CrawlHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                seen_paths.append(self.path)
                if self.path == "/2fa/enter":
                    body = '<html><head><script src="assets/public/app.js"></script></head><body>2FA</body></html>'
                    content_type = "text/html"
                    status = 200
                elif self.path == "/assets/public/app.js":
                    body = "fetch('/rest/user/whoami'); const noise = ['/10', '/160'];"
                    content_type = "application/javascript"
                    status = 200
                elif self.path == "/rest/user/whoami":
                    body = '{"user":{}}'
                    content_type = "application/json"
                    status = 200
                else:
                    body = "<html><body>missing</body></html>"
                    content_type = "text/html"
                    status = 404
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), CrawlHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    target = f"http://127.0.0.1:{server.server_port}/2fa/enter"
                    scope.save_scope([target], "test", "Example Client")
                    crawler_adapter.crawl(
                        {
                            "target": target,
                            "workspaceId": "engagement",
                            "maxDepth": 3,
                            "maxPages": 10,
                            "delayMillis": 0,
                            "background": False,
                            "confirm": True,
                        }
                    )

                    self.assertIn("/assets/public/app.js", seen_paths)
                    self.assertIn("/rest/user/whoami", seen_paths)
                    self.assertNotIn("/2fa/enter/assets/public/app.js", seen_paths)
                    self.assertNotIn("/2fa/assets/public/app.js", seen_paths)
                    self.assertNotIn("/10", seen_paths)
                    self.assertNotIn("/160", seen_paths)
                    endpoint_urls = {item["url"] for item in workspace._load_target_entities("engagement", "127.0.0.1")["endpoints"]}
                    self.assertFalse(any(url.endswith("/10") for url in endpoint_urls))
                    self.assertFalse(any(url.endswith("/160") for url in endpoint_urls))
        finally:
            server.shutdown()
            server.server_close()

    def test_crawler_crawl_follows_second_level_navigation_and_get_forms(self) -> None:
        seen_paths: list[str] = []

        class CrawlHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                seen_paths.append(self.path)
                pages = {
                    "/": (
                        '<html><head><title>Root</title></head><body>'
                        '<a href="/level1">Level 1</a>'
                        '<script src="/static/app.js"></script>'
                        '<button onclick="location.href=\'/click-target\'">Open</button>'
                        '<form method="get" action="/search"><input name="q" value="alpha"></form>'
                        '<form method="post" action="/login"><input name="username"><input name="password" type="password"></form>'
                        "</body></html>"
                    ),
                    "/level1": '<html><body><div data-href="/level2">Level 2</div></body></html>',
                    "/level2": '<html><head><meta http-equiv="refresh" content="0; url=/level3"></head><body>Level 2</body></html>',
                    "/level3": "<html><body>Level 3</body></html>",
                    "/click-target": "<html><body>Clicked</body></html>",
                    "/search?q=alpha": "<html><body>Search</body></html>",
                    "/static/app.js": "const api = '/api/v1/users?active=1';",
                    "/api/v1/users?active=1": '{"users":[]}',
                }
                body = pages.get(self.path, "<html><body>missing</body></html>")
                self.send_response(200 if self.path in pages else 404)
                self.send_header("Content-Type", "application/javascript" if self.path.endswith(".js") else "text/html")
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), CrawlHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                with isolated_state(tmp_path):
                    target = f"http://127.0.0.1:{server.server_port}/"
                    scope.save_scope([target], "test", "Example Client")
                    result = json.loads(
                        crawler_adapter.crawl(
                            {
                                "target": target,
                                "workspaceId": "engagement",
                                "maxDepth": 3,
                                "maxPages": 10,
                                "delayMillis": 0,
                                "background": False,
                                "confirm": True,
                            }
                        )
                    )

                    self.assertIn("/level1", seen_paths)
                    self.assertIn("/level2", seen_paths)
                    self.assertIn("/level3", seen_paths)
                    self.assertIn("/click-target", seen_paths)
                    self.assertIn("/search?q=alpha", seen_paths)
                    self.assertIn("/static/app.js", seen_paths)
                    self.assertIn("/api/v1/users?active=1", seen_paths)
                    self.assertNotIn("/login", seen_paths)
                    self.assertGreaterEqual(result["crawl"]["visitedCount"], 6)
                    self.assertTrue(result["crawl"]["analyzeScripts"])
                    self.assertTrue(result["crawl"]["includeInScopeHosts"])
                    context = workspace.prepare_target_context("engagement", "127.0.0.1")
                    self.assertGreaterEqual(context["knownEndpoints"]["total"], 7)
                    self.assertGreaterEqual(context["parameters"]["total"], 1)
                    observation_types = {item["type"] for item in context["observations"]}
                    self.assertIn("form_endpoint", observation_types)
                    self.assertIn("post_form_candidate", observation_types)
                    self.assertTrue(context["interestingCandidates"])
                    candidate_categories = {item["category"] for item in context["interestingCandidates"]}
                    self.assertIn("high_value_form", candidate_categories)
                    observations = json.loads(workspace.target_entity_path("engagement", "127.0.0.1", "observations").read_text(encoding="utf-8"))
                    self.assertTrue(any(item.get("type") == "sitemap_finding_candidate" for item in observations))
                    graph = result["flowGraph"]
                    self.assertIn("GET", graph["summary"]["methodCounts"])
                    self.assertTrue(any(edge["type"] == "navigation" and edge["method"] == "GET" for edge in graph["edges"]))
                    self.assertTrue(any(edge["type"] == "form_action" and edge["method"] == "POST" and not edge["submitted"] for edge in graph["edges"]))
                    mermaid_path = Path(graph["mermaidPath"])
                    self.assertTrue(mermaid_path.exists())
                    self.assertIn("flowchart LR", mermaid_path.read_text(encoding="utf-8"))
                    svg_path = Path(graph["svgPath"])
                    self.assertTrue(svg_path.exists())
                    self.assertIn("<svg", svg_path.read_text(encoding="utf-8"))
        finally:
            server.shutdown()
            server.server_close()

    def test_passive_analyzers_normalize_method_prefixed_urls_and_skip_numeric_spa_routes(self) -> None:
        file_candidate = lfi_rfi.candidate_from_observation(
            {
                "type": "form_endpoint",
                "value": "GET http://localhost:3000/profile/image/file",
                "method": "GET",
                "inputNames": ["file"],
            }
        )
        self.assertIsNotNone(file_candidate)
        self.assertEqual(file_candidate["url"], "http://localhost:3000/profile/image/file")

        template_candidate = ssti.candidate_from_parameter(
            {
                "name": "template",
                "url": "POST http://localhost:3000/profile/render",
                "method": "POST",
                "location": "form",
            },
            None,
        )
        self.assertIsNotNone(template_candidate)
        self.assertEqual(template_candidate["url"], "http://localhost:3000/profile/render")

        numeric_template = ssti.candidate_from_parameter(
            {"name": "template", "url": "http://localhost:3000/160", "method": "GET", "location": "query"},
            None,
        )
        self.assertIsNone(numeric_template)

        cors_candidates = cors.find_candidates(
            {
                "endpoints": [
                    {
                        "url": "http://localhost:3000/160",
                        "method": "GET",
                        "responseHeaders": {"Access-Control-Allow-Origin": "*"},
                    },
                    {
                        "url": "GET http://localhost:3000/rest/products/search",
                        "method": "GET",
                        "responseHeaders": {"Access-Control-Allow-Origin": "*"},
                    },
                ],
                "parameters": [],
                "observations": [],
            }
        )
        self.assertEqual([item["url"] for item in cors_candidates], ["http://localhost:3000/rest/products/search"])

        header_candidates = headers_cookies.find_candidates(
            {
                "endpoints": [
                    {
                        "url": "GET https://localhost:3000/profile",
                        "method": "GET",
                        "responseHeaders": {"Server": "test"},
                    }
                ],
                "parameters": [],
                "observations": [],
            },
            dedupe_scope="endpoint",
        )
        self.assertTrue(header_candidates)
        self.assertTrue(all(item["url"] == "https://localhost:3000/profile" for item in header_candidates))

    def test_ssti_skips_parameterless_collection_endpoints(self) -> None:
        raw = json.dumps(
            {
                "hosts": [
                    {
                        "host": "example.com",
                        "urls": [
                            {"url": "https://example.com/api/Users", "methods": ["GET"], "statusCodes": [200]},
                            {
                                "url": "https://example.com/rest/user/security-question?email=user@example.com",
                                "methods": ["GET"],
                                "statusCodes": [200],
                            },
                        ],
                    }
                ],
                "summary": {"hostCount": 1, "urlCount": 2},
            }
        )
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)

                result = json.loads(ssti.passive_analyze({"workspaceId": "engagement", "target": "example.com", "ingest": False}))

                self.assertEqual(result["candidateCount"], 1)
                self.assertEqual(result["candidates"][0]["parameter"], "email")

    def test_lfi_requires_param_or_file_signal(self) -> None:
        candidates = lfi_rfi.find_candidates(
            {
                "endpoints": [],
                "parameters": [
                    {"name": "csrf", "url": "https://example.com/login", "method": "POST", "location": "form"},
                    {"name": "file", "url": "https://example.com/download?file=report.pdf", "method": "GET", "location": "query"},
                ],
                "observations": [{"type": "form_endpoint", "value": "https://example.com/download", "method": "GET"}],
            },
            35,
        )

        urls = {item["url"] for item in candidates}
        self.assertIn("https://example.com/download?file=report.pdf", urls)
        self.assertIn("https://example.com/download", urls)
        self.assertNotIn("https://example.com/login", urls)

    def test_open_redirect_requires_redirect_signal(self) -> None:
        candidates = open_redirect_adapter.find_candidates(
            {
                "endpoints": [],
                "parameters": [
                    {"name": "username", "url": "https://example.com/login", "method": "POST", "location": "form"},
                    {"name": "continue", "url": "https://example.com/login?continue=/home", "method": "GET", "location": "query"},
                ],
                "observations": [
                    {"type": "form_endpoint", "value": "https://example.com/accounting", "method": "POST", "inputNames": ["username"]},
                    {"type": "form_endpoint", "value": "https://example.com/callback", "method": "POST", "inputNames": []},
                ],
            },
            35,
        )

        urls = {item["url"] for item in candidates}
        self.assertIn("https://example.com/login?continue=/home", urls)
        self.assertIn("https://example.com/callback", urls)
        self.assertNotIn("https://example.com/login", urls)
        self.assertNotIn("https://example.com/accounting", urls)

    def test_crawler_crawl_defaults_to_background_worker_and_ingests_result(self) -> None:
        class CrawlHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("X-Powered-By", "PHP/8.2")
                self.end_headers()
                self.wfile.write(b'<html><body><a href="/next">Next</a></body></html>')

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), CrawlHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    target = f"http://127.0.0.1:{server.server_port}/"
                    scope.save_scope([target], "test", "Example Client")
                    started = json.loads(
                        crawler_adapter.crawl(
                            {
                                "target": target,
                                "workspaceId": "engagement",
                                "maxDepth": 1,
                                "maxPages": 3,
                                "delayMillis": 0,
                                "timeoutSeconds": 30,
                                "confirm": True,
                            }
                        )
                    )

                    job = wait_for_job(started["job"]["jobId"])

                    self.assertEqual(job["status"], "completed")
                    self.assertGreaterEqual(job["result"]["crawl"]["visitedCount"], 2)
                    self.assertTrue(job["result"]["workflowRefresh"])
                    context = workspace.prepare_target_context("engagement", "127.0.0.1")
                    self.assertGreaterEqual(context["knownEndpoints"]["total"], 2)
                    observations = json.loads(workspace.target_entity_path("engagement", "127.0.0.1", "observations").read_text(encoding="utf-8"))
                    self.assertTrue(any(item.get("type") == "technology_component" and item.get("name") == "PHP" for item in observations))
                    self.assertTrue((workspace.target_path("engagement", "127.0.0.1") / "models" / "perimeter.json").exists())
        finally:
            server.shutdown()
            server.server_close()

    def test_crawler_background_worker_uses_synapse_python(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                target = "https://example.com/"
                scope.save_scope([target], "test", "Example Client")

                def fake_start_background_command(cmd: list[str], **_: object) -> dict[str, object]:
                    self.assertEqual(cmd[0], "/tmp/synapse-venv-python")
                    return {"jobId": "job_crawler", "status": "running", "createdAt": "2026-06-08T00:00:00Z"}

                with patch.object(crawler_adapter, "synapse_python", return_value="/tmp/synapse-venv-python"), patch.object(
                    crawler_adapter,
                    "start_background_command",
                    side_effect=fake_start_background_command,
                ):
                    result = json.loads(
                        crawler_adapter.crawl(
                            {
                                "target": target,
                                "workspaceId": "engagement",
                                "maxDepth": 1,
                                "maxPages": 1,
                                "timeoutSeconds": 30,
                                "confirm": True,
                            }
                        )
                    )

                self.assertTrue(result["background"])
                self.assertEqual(result["job"]["jobId"], "job_crawler")

    def test_crawler_crawl_uses_disabled_http_backend_policy(self) -> None:
        seen_paths: list[str] = []

        class CrawlHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                seen_paths.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<html><body>ok</body></html>")

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), CrawlHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    target = f"http://127.0.0.1:{server.server_port}/"
                    scope.save_scope([target], "test", "Example Client")
                    result = json.loads(
                        crawler_adapter.crawl(
                            {
                                "target": target,
                                "workspaceId": "engagement",
                                "httpBackend": "disabled",
                                "delayMillis": 0,
                                "background": False,
                                "confirm": True,
                            }
                        )
                    )

                    self.assertEqual(seen_paths, [])
                    self.assertEqual(result["crawl"]["visitedCount"], 1)
                    self.assertIn("disabled", result["crawl"]["errors"][0]["error"])
        finally:
            server.shutdown()
            server.server_close()

    def test_crawler_extended_submits_post_forms_with_credentials_and_records_actions(self) -> None:
        seen_gets: list[str] = []
        seen_posts: list[dict[str, object]] = []

        class ExtendedCrawlHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                seen_gets.append(self.path)
                pages = {
                    "/": (
                        '<html><body>'
                        '<form method="post" action="/advanced-search">'
                        '<input type="hidden" name="csrf_token" value="token123">'
                        '<input name="q">'
                        "</form>"
                        '<form method="post" action="/admin/delete"><input name="id" value="7"></form>'
                        "</body></html>"
                    ),
                    "/result": "<html><body>Result</body></html>",
                }
                body = pages.get(self.path, "<html><body>missing</body></html>")
                self.send_response(200 if self.path in pages else 404)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
                seen_posts.append({"path": self.path, "body": body, "cookie": self.headers.get("Cookie", "")})
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b'<html><body><a href="/result">Result</a></body></html>')

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), ExtendedCrawlHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    target = f"http://127.0.0.1:{server.server_port}/"
                    scope.save_scope([target], "test", "Example Client")
                    credentials.save_credential({"id": "auth-cookie", "type": "cookie", "secret": "sid=abc123", "scopes": [target]})
                    crawler_adapter.crawl(
                        {
                            "target": target,
                            "workspaceId": "engagement",
                            "maxDepth": 1,
                            "maxPages": 5,
                            "delayMillis": 0,
                            "background": False,
                            "confirm": True,
                        }
                    )

                    result = json.loads(
                        crawler_adapter.crawl_extended(
                            {
                                "target": target,
                                "workspaceId": "engagement",
                                "credentialId": "auth-cookie",
                                "maxDepth": 1,
                                "maxPages": 8,
                                "delayMillis": 0,
                                "background": False,
                                "confirm": True,
                            }
                        )
                    )

                    self.assertEqual([item["path"] for item in seen_posts], ["/advanced-search"])
                    submitted = parse_qs(str(seen_posts[0]["body"]))
                    self.assertEqual(submitted["csrf_token"], ["token123"])
                    self.assertEqual(submitted["q"], ["synapse"])
                    self.assertEqual(seen_posts[0]["cookie"], "sid=abc123")
                    self.assertIn("/result", seen_gets)
                    self.assertEqual(result["crawl"]["postSubmissionCount"], 1)
                    self.assertEqual(result["crawl"]["postSubmissions"][0]["submittedValues"]["csrf_token"], "[REDACTED]")
                    self.assertTrue(any("Skipped sensitive POST form" in item.get("warning", "") for item in result["crawl"]["errors"]))
                    actions = json.loads(workspace.target_entity_path("engagement", "127.0.0.1", "actions").read_text(encoding="utf-8"))
                    post_actions = [item for item in actions if item.get("tool") == "crawler.extended" and item.get("method") == "POST"]
                    self.assertEqual(len(post_actions), 1)
                    self.assertEqual(post_actions[0]["parameterNames"], ["csrf_token", "q"])
                    self.assertEqual(post_actions[0]["submittedValues"]["csrf_token"], "[REDACTED]")
                    self.assertTrue(any(item.get("tool") == "crawler.extended" and item.get("type") == "tool_run" for item in actions))
                    graph = result["flowGraph"]
                    self.assertTrue(any(edge["type"] == "form_action" and edge["method"] == "POST" and edge["submitted"] for edge in graph["edges"]))
        finally:
            server.shutdown()
            server.server_close()

    def test_crawler_extended_requires_previous_crawl(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                target = "http://127.0.0.1/"
                scope.save_scope([target], "test", "Example Client")
                credentials.save_credential({"id": "auth-cookie", "type": "cookie", "secret": "sid=abc123", "scopes": [target]})

                with self.assertRaises(McpError) as caught:
                    crawler_adapter.crawl_extended(
                        {
                            "target": target,
                            "workspaceId": "engagement",
                            "credentialId": "auth-cookie",
                            "background": False,
                            "confirm": True,
                        }
                    )

                self.assertIn("requires a previous crawler.crawl", str(caught.exception))

    def test_ssrf_analyze_workspace_ingests_candidates_from_parameters_and_forms(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "hosts": [
                            {
                                "host": "example.com",
                                "urls": [
                                    {
                                        "url": "https://example.com/api/fetch?url=https://partner.example/feed",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                    }
                                ],
                                "forms": [
                                    {
                                        "pageUrl": "https://example.com/admin/import",
                                        "method": "POST",
                                        "action": "https://example.com/admin/import",
                                        "inputs": [{"name": "source_url", "type": "url"}],
                                    }
                                ],
                            }
                        ],
                        "summary": {"hostCount": 1, "urlCount": 1, "formCount": 1},
                    }
                )
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)

                result = json.loads(
                    ssrf_adapter.analyze_workspace(
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "minScore": 35,
                            "ingest": True,
                        }
                    )
                )

                self.assertGreaterEqual(result["candidateCount"], 2)
                parameters = {item["parameter"] for item in result["candidates"]}
                self.assertIn("url", parameters)
                self.assertIn("source_url", parameters)
                context = workspace.prepare_target_context("engagement", "example.com")
                observation_types = {item["type"] for item in context["observations"]}
                self.assertIn("ssrf_candidate", observation_types)
                self.assertGreaterEqual(result["ingestion"]["entitiesCreated"]["observations"], 1)

    def test_open_redirect_analyze_workspace_ingests_candidates(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "hosts": [
                            {
                                "host": "example.com",
                                "urls": [
                                    {
                                        "url": "https://example.com/login?next=/dashboard",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                    },
                                    {
                                        "url": "https://example.com/oauth/callback?redirect_uri=https://client.example/cb",
                                        "methods": ["GET"],
                                        "statusCodes": [302],
                                    },
                                ],
                                "forms": [
                                    {
                                        "pageUrl": "https://example.com/logout",
                                        "method": "POST",
                                        "action": "https://example.com/logout",
                                        "inputs": [{"name": "return_url", "type": "hidden"}],
                                    }
                                ],
                            }
                        ],
                        "summary": {"hostCount": 1, "urlCount": 2, "formCount": 1},
                    }
                )
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)

                result = json.loads(
                    open_redirect_adapter.analyze_workspace(
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "minScore": 35,
                            "ingest": True,
                        }
                    )
                )

                self.assertGreaterEqual(result["candidateCount"], 2)
                parameters = {item["parameter"] for item in result["candidates"]}
                self.assertIn("redirect_uri", parameters)
                self.assertIn("return_url", parameters)
                context = workspace.prepare_target_context("engagement", "example.com")
                observation_types = {item["type"] for item in context["observations"]}
                self.assertIn("open_redirect_candidate", observation_types)

    def test_generated_web_test_plans_are_manual_and_guarded(self) -> None:
        cases = [
            (
                ssrf_adapter.generate_test_plan,
                {
                    "candidate": {
                        "candidateId": "ssrf_get_fetch_url",
                        "url": "https://example.com/api/fetch",
                        "method": "GET",
                        "parameter": "url",
                        "location": "query",
                        "priority": "high",
                        "reasons": ["Parameter name suggests a URL target."],
                    },
                    "callbackBaseUrl": "https://canary.example",
                },
                "ssrf_get_fetch_url",
                "https://canary.example/ssrf/url",
                "Do not probe cloud metadata",
            ),
            (
                open_redirect_adapter.generate_test_plan,
                {
                    "candidate": {
                        "candidateId": "open_redirect_get_login_next",
                        "url": "https://example.com/login",
                        "method": "GET",
                        "parameter": "next",
                        "location": "query",
                        "priority": "high",
                        "reasons": ["Parameter name suggests continuation behavior."],
                    },
                    "externalUrl": "https://redirect-test.example/",
                },
                "open_redirect_get_login_next",
                "https://redirect-test.example/",
                "credential theft",
            ),
        ]
        for generator, args, candidate_id, payload, guardrail in cases:
            with self.subTest(candidate_id=candidate_id):
                plan = json.loads(generator(args))
                self.assertEqual(plan["candidateId"], candidate_id)
                self.assertIn(payload, plan["safeManualPayloads"])
                self.assertTrue(any(guardrail in item for item in plan["guardrails"]))

    def test_command_injection_analyze_workspace_uses_fingerprint_os(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                evidence.ensure_project("Client", ["example.com"])
                fingerprint_path = evidence.host_path("Client", "example.com") / "fingerprint.json"
                fingerprint_path.write_text(
                    json.dumps(
                        {
                            "host": "example.com",
                            "possibleOs": {"windows": 4},
                            "technologies": {"Microsoft-IIS/10.0": 4, "ASP.NET": 2},
                        }
                    ),
                    encoding="utf-8",
                )
                raw = json.dumps(
                    {
                        "hosts": [
                            {
                                "host": "example.com",
                                "urls": [
                                    {
                                        "url": "https://example.com/admin/ping?host=127.0.0.1",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                    }
                                ],
                                "forms": [],
                            }
                        ],
                        "summary": {"hostCount": 1, "urlCount": 1, "formCount": 0},
                    }
                )
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)

                result = json.loads(
                    command_injection_adapter.analyze_workspace(
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "organization": "Client",
                            "minScore": 35,
                            "ingest": True,
                        }
                    )
                )

                self.assertEqual(result["osContext"]["family"], "windows")
                self.assertGreaterEqual(result["candidateCount"], 1)
                candidate = result["candidates"][0]
                self.assertEqual(candidate["osFamily"], "windows")
                self.assertIn("& echo SYNAPSE_TOKEN", candidate["payloadPreview"])
                context = workspace.prepare_target_context("engagement", "example.com")
                observation_types = {item["type"] for item in context["observations"]}
                self.assertIn("command_injection_candidate", observation_types)

    def test_command_injection_prepare_replay_is_no_traffic_and_allowlisted(self) -> None:
        args = {
            "url": "https://example.com/admin/ping?host=127.0.0.1",
            "method": "GET",
            "parameter": "host",
            "location": "query",
            "osFamily": "unix",
            "marker": "SYNAPSE_TEST",
        }

        replay = json.loads(command_injection_adapter.prepare_replay(args))

        self.assertFalse(replay["sendsTraffic"])
        self.assertEqual(replay["marker"], "SYNAPSE_SYNAPSE_TEST")
        self.assertIn("%3B+echo+SYNAPSE_SYNAPSE_TEST", replay["request"]["url"])
        self.assertTrue(any("does not send traffic" in item for item in replay["guardrails"]))
        with self.assertRaisesRegex(Exception, "built-in benign payloads"):
            command_injection_adapter.prepare_replay({**args, "payload": "; id"})

    def test_command_injection_execute_test_requires_confirmation_and_records_marker(self) -> None:
        class EchoHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                query = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                value = query.get("host", [""])[0]
                self.send_response(200)
                self.end_headers()
                # Simulate a vulnerable diagnostic endpoint: a "; echo <marker>"
                # injection is executed by the shell, emitting the marker as command
                # output (without the literal "echo " prefix) rather than reflecting
                # the payload verbatim.
                body = ("ping ok\n" + value.split("; echo ", 1)[1]) if "; echo " in value else value
                self.wfile.write(body.encode("utf-8"))

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), EchoHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    target = f"http://127.0.0.1:{server.server_port}/diag?host=127.0.0.1"
                    scope.save_scope([target], "test", "Example Client")
                    base_args = {
                        "workspaceId": "engagement",
                        "url": target,
                        "method": "GET",
                        "parameter": "host",
                        "location": "query",
                        "osFamily": "unix",
                        "marker": "SYNAPSE_TEST",
                    }
                    with self.assertRaisesRegex(Exception, "confirm=true"):
                        command_injection_adapter.execute_test({**base_args, "confirm": False})
                    with self.assertRaisesRegex(Exception, "built-in benign payloads"):
                        command_injection_adapter.execute_test(
                            {
                                **base_args,
                                "payload": "; id",
                                "confirm": True,
                                "approvalReason": "Unit test rejected non-benign payload",
                                "riskTier": "low",
                            }
                        )

                    result = json.loads(
                        command_injection_adapter.execute_test(
                            {
                                **base_args,
                                "confirm": True,
                                "approvalReason": "Unit test benign echo marker",
                                "riskTier": "low",
                            }
                        )
                    )

                    self.assertTrue(result["test"]["observedMarker"])
                    self.assertEqual(result["test"]["assessment"], "possible_command_injection")
                    self.assertIn("bodySha256", result["test"]["response"])
                    self.assertNotIn("body", result["test"]["response"])
                    exchange_path = Path(result["test"]["exchangeEvidence"]["rawPath"])
                    self.assertTrue(exchange_path.exists())
                    self.assertIn("SYNAPSE_SYNAPSE_TEST", exchange_path.read_text(encoding="utf-8"))
                    context = workspace.prepare_target_context("engagement", "127.0.0.1")
                    observation_types = {item["type"] for item in context["observations"]}
                    self.assertIn("possible_command_injection", observation_types)
        finally:
            server.shutdown()
            server.server_close()

    def test_command_injection_execute_test_does_not_flag_pure_reflection(self) -> None:
        class ReflectHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                query = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                self.send_response(200)
                self.end_headers()
                # Reflect the parameter verbatim: the marker appears only as part of
                # the literal "echo <marker>" payload, which is reflection, not
                # command execution, and must not be flagged.
                self.wfile.write(f"searched for: {query.get('host', [''])[0]}".encode("utf-8"))

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), ReflectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    target = f"http://127.0.0.1:{server.server_port}/diag?host=127.0.0.1"
                    scope.save_scope([target], "test", "Example Client")
                    result = json.loads(
                        command_injection_adapter.execute_test(
                            {
                                "workspaceId": "engagement",
                                "url": target,
                                "method": "GET",
                                "parameter": "host",
                                "location": "query",
                                "osFamily": "unix",
                                "marker": "SYNAPSE_TEST",
                                "confirm": True,
                                "approvalReason": "Unit test reflection-only response",
                                "riskTier": "low",
                            }
                        )
                    )
                    self.assertFalse(result["test"]["observedMarker"])
                    self.assertEqual(result["test"]["assessment"], "inconclusive")
        finally:
            server.shutdown()
            server.server_close()

    def test_xss_execute_test_requires_confirmation_and_records_reflection(self) -> None:
        class ReflectHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                query = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                body = f"<html><body>{query.get('q', [''])[0]}</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", "returned=server-secret; Path=/")
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), ReflectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    target = f"http://127.0.0.1:{server.server_port}/search?q=hello"
                    scope.save_scope([target], "test", "Example Client")
                    credentials.save_credential({"id": "xss-cookie", "type": "cookie", "secret": "sid=xss-secret", "scopes": [target]})
                    base_args = {
                        "workspaceId": "engagement",
                        "url": target,
                        "method": "GET",
                        "parameter": "q",
                        "location": "query",
                        "marker": "UNIT",
                        "credentialId": "xss-cookie",
                    }
                    with self.assertRaisesRegex(Exception, "confirm=true"):
                        xss_adapter.execute_test({**base_args, "confirm": False})

                    result = json.loads(
                        xss_adapter.execute_test(
                            {
                                **base_args,
                                "confirm": True,
                                "approvalReason": "Unit test benign XSS reflection probe",
                                "riskTier": "low",
                            }
                        )
                    )

                    self.assertEqual(result["test"]["assessment"], "possible_xss")
                    self.assertTrue(result["test"]["tests"][0]["rawPayloadReflected"])
                    exchange_path = Path(result["test"]["tests"][0]["exchangeEvidence"]["rawPath"])
                    self.assertTrue(exchange_path.exists())
                    exchange_text = exchange_path.read_text(encoding="utf-8")
                    self.assertIn("synapse-xss", exchange_text)
                    self.assertIn('"Cookie": "<redacted>"', exchange_text)
                    self.assertIn('"set-cookie": "<redacted>"', exchange_text)
                    self.assertNotIn("xss-secret", exchange_text)
                    self.assertNotIn("server-secret", exchange_text)
                    context = workspace.prepare_target_context("engagement", "127.0.0.1")
                    action_tools = {item["tool"] for item in context["recentActions"]}
                    self.assertIn("xss.execute_test", action_tools)

                    workspace.ingest_data(
                        "engagement",
                        "127.0.0.1",
                        "adapter_result",
                        "passive_analysis",
                        "json",
                        json.dumps(
                            {
                                "entities": {
                                    "observations": [
                                        {
                                            "type": "xss_candidate",
                                            "candidateId": "xss_stored_search_q",
                                            "url": target,
                                            "method": "GET",
                                            "parameter": "q",
                                            "location": "query",
                                            "reason": "Stored candidate for candidateId execution.",
                                        }
                                    ]
                                }
                            }
                        ),
                    )
                    stored = json.loads(
                        xss_adapter.execute_test(
                            {
                                "workspaceId": "engagement",
                                "target": "127.0.0.1",
                                "candidateId": "xss_stored_search_q",
                                "confirm": True,
                                "approvalReason": "Unit test benign stored XSS candidate probe",
                                "riskTier": "low",
                            }
                        )
                    )
                    self.assertEqual(stored["test"]["candidate"]["candidateId"], "xss_stored_search_q")
                    self.assertEqual(stored["test"]["assessment"], "possible_xss")
        finally:
            server.shutdown()
            server.server_close()

    def test_open_redirect_execute_test_captures_external_location_without_following(self) -> None:
        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                query = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                self.send_response(302)
                self.send_header("Location", query.get("next", ["/"])[0])
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    target = f"http://127.0.0.1:{server.server_port}/redirect?next=/home"
                    scope.save_scope([target], "test", "Example Client")
                    with self.assertRaisesRegex(Exception, "external host"):
                        open_redirect_adapter.execute_test(
                            {
                                "workspaceId": "engagement",
                                "url": target,
                                "method": "GET",
                                "parameter": "next",
                                "location": "query",
                                "externalUrl": "javascript:alert(1)",
                                "confirm": True,
                                "approvalReason": "Unit test rejected non-http redirect payload",
                                "riskTier": "low",
                            }
                        )
                    result = json.loads(
                        open_redirect_adapter.execute_test(
                            {
                                "workspaceId": "engagement",
                                "url": target,
                                "method": "GET",
                                "parameter": "next",
                                "location": "query",
                                "externalUrl": "https://example.org/",
                                "followRedirects": True,
                                "confirm": True,
                                "approvalReason": "Unit test harmless redirect probe",
                                "riskTier": "low",
                            }
                        )
                    )

                    self.assertEqual(result["test"]["assessment"], "open_redirect_observed")
                    self.assertEqual(result["test"]["response"]["status"], 302)
                    self.assertEqual(result["test"]["response"]["headers"]["location"], "https://example.org/")
                    context = workspace.prepare_target_context("engagement", "127.0.0.1")
                    action_tools = {item["tool"] for item in context["recentActions"]}
                    self.assertIn("open_redirect.execute_test", action_tools)
        finally:
            server.shutdown()
            server.server_close()

    def test_ssrf_execute_test_requires_external_callback_and_records_probe(self) -> None:
        class FetchHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                query = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                target_url = query.get("url", [""])[0]
                body = f"fetch failed getaddrinfo {target_url}"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), FetchHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    target = f"http://127.0.0.1:{server.server_port}/fetch?url=https://initial.example/"
                    scope.save_scope([target], "test", "Example Client")
                    base_args = {
                        "workspaceId": "engagement",
                        "url": target,
                        "method": "GET",
                        "parameter": "url",
                        "location": "query",
                        "confirm": True,
                        "approvalReason": "Unit test SSRF canary probe",
                        "riskTier": "low",
                    }
                    with self.assertRaisesRegex(Exception, "callbackBaseUrl or callbackUrl"):
                        ssrf_adapter.execute_test(base_args)
                    with self.assertRaisesRegex(Exception, "private or special-purpose"):
                        ssrf_adapter.execute_test({**base_args, "callbackBaseUrl": "http://127.0.0.1/cb"})

                    result = json.loads(ssrf_adapter.execute_test({**base_args, "callbackBaseUrl": "https://canary.example.test/base"}))

                    self.assertEqual(result["test"]["assessment"], "possible_ssrf_behavior")
                    self.assertIn("verificationRequired", result["test"])
                    exchange_path = Path(result["test"]["exchangeEvidence"]["rawPath"])
                    self.assertTrue(exchange_path.exists())
                    self.assertIn("canary.example.test", exchange_path.read_text(encoding="utf-8"))
        finally:
            server.shutdown()
            server.server_close()

    def test_xxe_execute_test_uses_benign_in_band_entity_payload(self) -> None:
        class XmlHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(length).decode("utf-8")
                response = "SYNAPSE_XXE_UNIT" if "<!ENTITY synapse" in body else "ok"
                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self.end_headers()
                self.wfile.write(response.encode("utf-8"))

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), XmlHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    target = f"http://127.0.0.1:{server.server_port}/xml"
                    scope.save_scope([target], "test", "Example Client")
                    result = json.loads(
                        xxe.execute_test(
                            {
                                "workspaceId": "engagement",
                                "url": target,
                                "method": "POST",
                                "marker": "UNIT",
                                "confirm": True,
                                "approvalReason": "Unit test benign XXE entity probe",
                                "riskTier": "low",
                            }
                        )
                    )

                    self.assertEqual(result["test"]["assessment"], "xml_entity_expansion_observed")
                    exchange_path = Path(result["test"]["exchangeEvidence"]["rawPath"])
                    self.assertTrue(exchange_path.exists())
                    exchange_text = exchange_path.read_text(encoding="utf-8")
                    self.assertIn("<!ENTITY synapse", exchange_text)
                    self.assertNotIn("/etc/passwd", exchange_text)
        finally:
            server.shutdown()
            server.server_close()


class SpecImportAdapterTests(unittest.TestCase):
    def test_openapi_import_normalizes_endpoints_params_and_auth(self) -> None:
        spec = json.dumps(
            {
                "openapi": "3.0.0",
                "servers": [{"url": "https://api.example.com/v1"}],
                "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
                "paths": {
                    "/users": {
                        "get": {
                            "parameters": [
                                {"name": "limit", "in": "query", "schema": {"type": "integer", "example": 25}}
                            ]
                        },
                        "post": {
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "properties": {
                                                "email": {"example": "a@b.test"},
                                                "password": {"example": "super-secret-password"},
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                    "/users/{id}": {
                        "get": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "string"}}]}
                    },
                },
            }
        )
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                result = json.loads(
                    spec_import.import_spec({"workspaceId": "engagement", "target": "api.example.com", "rawData": spec})
                )
                self.assertEqual(result["format"], "openapi")
                self.assertEqual(result["endpointCount"], 3)
                endpoints = workspace._load_target_entities("engagement", "api.example.com")["endpoints"]
                spec_eps = [e for e in endpoints if e.get("source") == "spec_import"]
                self.assertEqual(len(spec_eps), 3)
                self.assertTrue(all(e.get("inferred") and e.get("observed") is False for e in spec_eps))
                self.assertIn("https://api.example.com/v1/users/{id}", {e["url"] for e in spec_eps})
                params = {p["name"]: p for p in workspace._load_target_entities("engagement", "api.example.com")["parameters"]}
                self.assertEqual(params["limit"]["location"], "query")
                self.assertEqual(params["limit"]["valuePreview"], "25")
                self.assertEqual(params["email"]["location"], "json")
                self.assertEqual(params["password"]["valuePreview"], "<redacted>")
                observations = workspace._load_target_entities("engagement", "api.example.com")["observations"]
                self.assertIn("documented_auth_scheme", {o["type"] for o in observations})

    def test_import_does_not_persist_secret_values(self) -> None:
        # apiKey scheme names a header but carries no secret; ensure nothing token-like is stored.
        spec = json.dumps(
            {
                "swagger": "2.0",
                "host": "api.example.com",
                "basePath": "/v2",
                "securityDefinitions": {"apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}},
                "paths": {"/ping": {"get": {}}},
            }
        )
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                spec_import.import_spec({"workspaceId": "engagement", "target": "api.example.com", "rawData": spec})
                target_dir = workspace.target_path("engagement", "api.example.com")
                blob = ""
                for path in (target_dir / "entities").glob("*.json"):
                    blob += path.read_text(encoding="utf-8")
                self.assertIn("X-API-Key", blob)  # the scheme's header name is fine to record
                self.assertNotIn("Bearer ", blob)
                self.assertNotIn("secret", blob.lower())

    def test_postman_import_walks_folders_and_extracts_query_params(self) -> None:
        collection = json.dumps(
            {
                "info": {"name": "demo"},
                "variable": [{"key": "baseUrl", "value": "https://api.example.com"}],
                "item": [
                    {
                        "name": "folder",
                        "item": [
                            {
                                "request": {
                                    "method": "GET",
                                    "url": {"raw": "{{baseUrl}}/search?q=test", "query": [{"key": "q", "value": "test"}]},
                                    "auth": {"type": "bearer"},
                                }
                            }
                        ],
                    }
                ],
            }
        )
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                result = json.loads(
                    spec_import.import_spec({"workspaceId": "engagement", "target": "api.example.com", "rawData": collection})
                )
                self.assertEqual(result["format"], "postman")
                endpoints = workspace._load_target_entities("engagement", "api.example.com")["endpoints"]
                self.assertIn("https://api.example.com/search", {e["url"] for e in endpoints})
                params = {p["name"] for p in workspace._load_target_entities("engagement", "api.example.com")["parameters"]}
                self.assertIn("q", params)
                self.assertIn("http", {s["schemeType"] for s in result["authSchemes"]})

    def test_invalid_document_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                with self.assertRaises(McpError):
                    spec_import.import_spec({"workspaceId": "engagement", "target": "api.example.com", "rawData": "not a spec"})


class HeadersCookiesAdapterTests(unittest.TestCase):
    def test_set_cookie_flags_records_flags_not_values(self) -> None:
        flags = crawler_adapter.set_cookie_flags("sessionid=SECRETVALUE; Path=/; HttpOnly; Secure; SameSite=Strict")
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0], {"name": "sessionid", "httpOnly": True, "secure": True, "sameSite": "strict"})
        self.assertNotIn("SECRETVALUE", json.dumps(flags))
        bare = crawler_adapter.set_cookie_flags("tracker=abc")
        self.assertEqual(bare[0], {"name": "tracker", "httpOnly": False, "secure": False, "sameSite": ""})

    def test_selected_response_headers_capture_security_headers(self) -> None:
        captured = crawler_adapter.selected_response_headers(
            {"content-security-policy": "default-src 'self'", "strict-transport-security": "max-age=1", "set-cookie": "a=b"}
        )
        self.assertIn("content-security-policy", captured)
        self.assertIn("strict-transport-security", captured)
        self.assertNotIn("set-cookie", captured)

    def _ingest(self, tmp: str) -> None:
        raw = json.dumps(
            {
                "hosts": [
                    {
                        "host": "example.com",
                        "urls": [
                            {
                                "url": "https://example.com/app",
                                "methods": ["GET"],
                                "statusCodes": [200],
                                "responseHeaders": {"content-type": "text/html"},
                                "responseCookieFlags": [{"name": "sessionid", "httpOnly": False, "secure": False, "sameSite": ""}],
                            },
                            {
                                "url": "https://example.com/hardened",
                                "methods": ["GET"],
                                "statusCodes": [200],
                                "responseHeaders": {
                                    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                                    "strict-transport-security": "max-age=31536000",
                                    "x-frame-options": "DENY",
                                    "x-content-type-options": "nosniff",
                                    "referrer-policy": "no-referrer",
                                },
                                "responseCookieFlags": [{"name": "sessionid", "httpOnly": True, "secure": True, "sameSite": "strict"}],
                            },
                        ],
                    }
                ],
                "summary": {"hostCount": 1, "urlCount": 2, "formCount": 0},
            }
        )
        workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)

    def test_flags_missing_headers_and_insecure_cookies(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                self._ingest(tmp)
                result = json.loads(headers_cookies.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))
                app = [c for c in result["candidates"] if c["url"].endswith("/app")]
                hardened = [c for c in result["candidates"] if c["url"].endswith("/hardened")]
                self.assertEqual(hardened, [])
                header_details = {c["header"] for c in app if c["type"] == "missing_security_header"}
                self.assertEqual(
                    header_details,
                    {"content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy"},
                )
                httponly = [c for c in app if c["type"] == "insecure_cookie_flag" and c["flag"] == "httponly"]
                self.assertEqual(httponly[0]["priority"], "high")
                self.assertEqual(httponly[0]["cookie"], "sessionid")

    def test_observations_ingested_and_surfaced(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                self._ingest(tmp)
                headers_cookies.analyze_workspace({"workspaceId": "engagement", "target": "example.com"})
                observations = workspace._load_target_entities("engagement", "example.com")["observations"]
                types = {o["type"] for o in observations}
                self.assertIn("missing_security_header", types)
                self.assertIn("insecure_cookie_flag", types)

    def test_default_host_dedupe_collapses_sitewide_header_findings(self) -> None:
        urls = [
            {
                "url": f"https://example.com/page-{index}",
                "methods": ["GET"],
                "statusCodes": [200],
                "responseHeaders": {"content-type": "text/html"},
            }
            for index in range(5)
        ]
        raw = json.dumps({"hosts": [{"host": "example.com", "urls": urls}], "summary": {"hostCount": 1, "urlCount": 5}})
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)
                result = json.loads(headers_cookies.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))
                csp = [
                    item
                    for item in result["candidates"]
                    if item["type"] == "missing_security_header" and item.get("header") == "content-security-policy"
                ]
                self.assertEqual(len(csp), 1)
                self.assertEqual(csp[0]["affectedCount"], 5)
                self.assertEqual(len(csp[0]["affectedUrls"]), 5)

                endpoint = json.loads(
                    headers_cookies.analyze_workspace(
                        {"workspaceId": "engagement", "target": "example.com", "dedupeScope": "endpoint", "ingest": False}
                    )
                )
                endpoint_csp = [
                    item
                    for item in endpoint["candidates"]
                    if item["type"] == "missing_security_header" and item.get("header") == "content-security-policy"
                ]
                self.assertEqual(len(endpoint_csp), 5)


class InsecureDeserAdapterTests(unittest.TestCase):
    def _seed_parameters(self, parameters: list[dict[str, object]]) -> None:
        workspace.ingest_data(
            "engagement",
            "example.com",
            "adapter_result",
            "seed",
            "json",
            json.dumps({"entities": {"parameters": parameters}}),
            {"adapter": "unit_test"},
        )

    def test_detects_java_serialized_preview_without_storing_full_blob(self) -> None:
        blob = "rO0ABXNyAB" + ("A" * 90)
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                self._seed_parameters(
                    [
                        {
                            "type": "parameter",
                            "name": "state",
                            "location": "query",
                            "method": "GET",
                            "url": "https://example.com/app?state=1",
                            "valuePreview": blob,
                        }
                    ]
                )
                result = json.loads(insecure_deser.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))
                self.assertEqual(result["candidateCount"], 1)
                candidate = result["candidates"][0]
                self.assertEqual(candidate["ecosystem"], "java_serialized")
                self.assertEqual(candidate["priority"], "high")
                self.assertLessEqual(len(candidate["valuePreview"]), 32)
                self.assertNotIn(blob, json.dumps(result))

    def test_viewstate_with_integrity_sibling_is_medium_priority(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                self._seed_parameters(
                    [
                        {
                            "type": "parameter",
                            "name": "__VIEWSTATE",
                            "location": "form",
                            "method": "POST",
                            "url": "https://example.com/form",
                            "valuePreview": "/wEPDwUKMTIzNDU2",
                        },
                        {
                            "type": "parameter",
                            "name": "__VIEWSTATEGENERATOR",
                            "location": "form",
                            "method": "POST",
                            "url": "https://example.com/form",
                            "valuePreview": "CA0B0334",
                        },
                    ]
                )
                result = json.loads(insecure_deser.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))
                self.assertEqual(result["candidateCount"], 1)
                self.assertEqual(result["candidates"][0]["ecosystem"], "dotnet_viewstate")
                self.assertEqual(result["candidates"][0]["priority"], "medium")

    def test_benign_preview_emits_no_candidates_and_reruns_dedupe(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                self._seed_parameters(
                    [
                        {
                            "type": "parameter",
                            "name": "message",
                            "location": "query",
                            "method": "GET",
                            "url": "https://example.com/app?message=hello",
                            "valuePreview": "hello world",
                        }
                    ]
                )
                benign = json.loads(insecure_deser.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))
                self.assertEqual(benign["candidateCount"], 0)

                self._seed_parameters(
                    [
                        {
                            "type": "parameter",
                            "name": "blob",
                            "location": "query",
                            "method": "GET",
                            "url": "https://example.com/app?blob=1",
                            "valuePreview": "rO0ABXNyABAAAA",
                        }
                    ]
                )
                insecure_deser.analyze_workspace({"workspaceId": "engagement", "target": "example.com"})
                insecure_deser.analyze_workspace({"workspaceId": "engagement", "target": "example.com"})
                observations = [
                    item
                    for item in workspace._load_target_entities("engagement", "example.com")["observations"]
                    if item.get("type") == "insecure_deser_candidate"
                ]
                self.assertEqual(len(observations), 1)


class XxeAdapterTests(unittest.TestCase):
    def test_openapi_xml_request_body_becomes_xxe_candidate(self) -> None:
        spec = json.dumps(
            {
                "openapi": "3.0.0",
                "servers": [{"url": "https://api.example.com"}],
                "paths": {
                    "/xml": {
                        "post": {
                            "requestBody": {
                                "content": {"application/xml": {"schema": {"properties": {"name": {"example": "alice"}}}}}
                            }
                        }
                    },
                    "/json": {
                        "post": {
                            "requestBody": {
                                "content": {"application/json": {"schema": {"properties": {"name": {"example": "alice"}}}}}
                            }
                        }
                    },
                },
            }
        )
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                spec_import.import_spec({"workspaceId": "engagement", "target": "api.example.com", "rawData": spec})
                result = json.loads(xxe.analyze_workspace({"workspaceId": "engagement", "target": "api.example.com"}))
                self.assertEqual(result["candidateCount"], 1)
                candidate = result["candidates"][0]
                self.assertTrue(candidate["url"].endswith("/xml"))
                self.assertEqual(candidate["priority"], "high")
                self.assertIn("application/xml", candidate["reasons"][0])

    def test_json_only_endpoint_emits_no_xxe_candidate_and_plan_is_manual(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data(
                    "engagement",
                    "api.example.com",
                    "adapter_result",
                    "seed",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "endpoints": [
                                    {
                                        "type": "endpoint",
                                        "url": "https://api.example.com/json",
                                        "method": "POST",
                                        "requestContentTypes": ["application/json"],
                                    }
                                ]
                            }
                        }
                    ),
                )
                result = json.loads(xxe.analyze_workspace({"workspaceId": "engagement", "target": "api.example.com"}))
                self.assertEqual(result["candidateCount"], 0)
                plan = json.loads(xxe.generate_test_plan({"url": "https://api.example.com/xml", "method": "POST"}))
                self.assertFalse(plan["sendsTraffic"])
                self.assertTrue(any("does not send traffic" in item.lower() for item in plan["guardrails"]))


class TlsPostureAdapterTests(unittest.TestCase):
    def _seed_services(self, services: list[dict[str, object]]) -> None:
        workspace.ingest_data(
            "engagement",
            "example.com",
            "adapter_result",
            "seed",
            "json",
            json.dumps({"entities": {"services": services}}),
            {"adapter": "unit_test"},
        )

    def test_expired_and_deprecated_tls_observations_from_existing_ssl_data(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                self._seed_services(
                    [
                        {
                            "type": "service",
                            "host": "example.com",
                            "port": 443,
                            "name": "https",
                            "source": "shodan_host",
                            "ssl": {"expired": True, "subjectCN": "example.com", "issuerCN": "Example CA", "protocols": ["TLSv1.0"]},
                        }
                    ]
                )
                result = json.loads(tls_posture.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))
                types = {item["type"]: item for item in result["candidates"]}
                self.assertEqual(types["tls_expired_certificate"]["priority"], "high")
                self.assertEqual(types["tls_deprecated_protocol"]["priority"], "medium")

    def test_no_ssl_data_or_modern_cert_emits_no_tls_observations(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                self._seed_services(
                    [
                        {"type": "service", "host": "example.com", "port": 80, "name": "http", "source": "shodan_host"},
                        {
                            "type": "service",
                            "host": "example.com",
                            "port": 443,
                            "name": "https",
                            "source": "shodan_host",
                            "ssl": {"expired": False, "subjectCN": "example.com", "issuerCN": "Example CA", "protocols": ["TLSv1.2", "TLSv1.3"]},
                        },
                    ]
                )
                result = json.loads(tls_posture.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))
                self.assertEqual(result["candidateCount"], 0)


class CsrfAdapterTests(unittest.TestCase):
    def _ingest_forms(self) -> None:
        raw = json.dumps(
            {
                "hosts": [
                    {
                        "host": "example.com",
                        "urls": [],
                        "forms": [
                            {
                                "pageUrl": "https://example.com/account",
                                "method": "POST",
                                "action": "https://example.com/account/update",
                                "inputs": [{"name": "email", "type": "email"}, {"name": "save", "type": "submit"}],
                            },
                            {
                                "pageUrl": "https://example.com/comment",
                                "method": "POST",
                                "action": "https://example.com/comment",
                                "inputs": [{"name": "body", "type": "text"}, {"name": "csrf_token", "type": "hidden"}],
                            },
                            {
                                "pageUrl": "https://example.com/search",
                                "method": "GET",
                                "action": "https://example.com/search",
                                "inputs": [{"name": "q", "type": "text"}],
                            },
                        ],
                    }
                ],
                "summary": {"hostCount": 1, "urlCount": 0, "formCount": 3},
            }
        )
        workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)

    def test_flags_state_changing_form_without_token_only(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                self._ingest_forms()
                result = json.loads(csrf.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))
                urls = {c["url"] for c in result["candidates"]}
                self.assertIn("https://example.com/account/update", urls)
                self.assertNotIn("https://example.com/comment", urls)  # has csrf_token field
                self.assertNotIn("https://example.com/search", urls)  # GET, not state-changing
                account = next(c for c in result["candidates"] if c["url"].endswith("/account/update"))
                self.assertEqual(account["method"], "POST")
                self.assertGreaterEqual(account["priorityScore"], 60)  # base + high-value path

    def test_generate_test_plan_is_manual_and_guarded(self) -> None:
        plan = json.loads(csrf.generate_test_plan({"url": "https://example.com/account/update", "method": "POST"}))
        self.assertFalse(plan["sendsTraffic"])
        self.assertTrue(any("does not send traffic" in g.lower() for g in plan["guardrails"]))


class CorsAdapterTests(unittest.TestCase):
    def test_passive_flags_wildcard_with_credentials_and_ignores_same_origin(self) -> None:
        raw = json.dumps(
            {
                "hosts": [
                    {
                        "host": "example.com",
                        "urls": [
                            {
                                "url": "https://example.com/api/data",
                                "methods": ["GET"],
                                "statusCodes": [200],
                                "responseHeaders": {
                                    "access-control-allow-origin": "*",
                                    "access-control-allow-credentials": "true",
                                },
                            },
                            {
                                "url": "https://example.com/api/self",
                                "methods": ["GET"],
                                "statusCodes": [200],
                                "responseHeaders": {"access-control-allow-origin": "https://example.com"},
                            },
                        ],
                    }
                ],
                "summary": {"hostCount": 1, "urlCount": 2, "formCount": 0},
            }
        )
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)
                result = json.loads(cors.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))
                urls = {c["url"] for c in result["candidates"]}
                self.assertIn("https://example.com/api/data", urls)
                self.assertNotIn("https://example.com/api/self", urls)
                wildcard = next(c for c in result["candidates"] if c["url"].endswith("/api/data"))
                self.assertTrue(wildcard["allowCredentials"])
                self.assertEqual(wildcard["priority"], "medium")

    def test_cors_collapses_host_wide_acao(self) -> None:
        raw = json.dumps(
            {
                "hosts": [
                    {
                        "host": "example.com",
                        "urls": [
                            {
                                "url": f"https://example.com/api/{index}",
                                "methods": ["GET"],
                                "statusCodes": [200],
                                "responseHeaders": {"access-control-allow-origin": "*"},
                            }
                            for index in range(5)
                        ],
                    }
                ],
                "summary": {"hostCount": 1, "urlCount": 5, "formCount": 0},
            }
        )
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)

                result = json.loads(cors.analyze_workspace({"workspaceId": "engagement", "target": "example.com"}))

                self.assertEqual(result["candidateCount"], 1)
                self.assertEqual(result["candidates"][0]["affectedCount"], 5)
                self.assertEqual(result["candidates"][0]["dedupeScope"], "host")

    def test_execute_test_requires_confirmation(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                with self.assertRaises(McpError):
                    cors.execute_test({"url": "https://example.com/api", "workspaceId": "engagement"})

    def test_execute_test_detects_origin_reflection(self) -> None:
        class ReflectingHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                origin = self.headers.get("Origin", "")
                self.send_response(200)
                if self.path == "/reflect":
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Credentials", "true")
                else:
                    self.send_header("Access-Control-Allow-Origin", "https://trusted.example")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), ReflectingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    base = f"http://127.0.0.1:{server.server_port}"
                    scope.save_scope([base], "test")
                    reflected = json.loads(
                        cors.execute_test(
                            {
                                "url": f"{base}/reflect",
                                "workspaceId": "engagement",
                                "confirm": True,
                                "approvalReason": "unit test approved CORS probe",
                            }
                        )
                    )
                    self.assertEqual(reflected["test"]["assessment"], "possible_cors_misconfiguration")
                    self.assertTrue(reflected["test"]["originReflected"])
                    self.assertTrue(reflected["action"]["created"])
                    self.assertEqual(reflected["action"]["action"]["tool"], "cors.execute_test")
                    reflected_exchange = Path(reflected["test"]["exchangeEvidence"]["rawPath"])
                    self.assertTrue(reflected_exchange.exists())
                    self.assertIn("access-control-allow-origin", reflected_exchange.read_text(encoding="utf-8"))

                    fixed = json.loads(
                        cors.execute_test(
                            {
                                "url": f"{base}/fixed",
                                "workspaceId": "engagement",
                                "confirm": True,
                                "approvalReason": "unit test approved CORS probe",
                            }
                        )
                    )
                    self.assertEqual(fixed["test"]["assessment"], "inconclusive")
                    observation_types = {
                        o["type"] for o in workspace._load_target_entities("engagement", "127.0.0.1")["observations"]
                    }
                    self.assertIn("possible_cors_misconfiguration", observation_types)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
