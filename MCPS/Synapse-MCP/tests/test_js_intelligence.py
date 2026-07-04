import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import urlsplit

import httpx

from helpers import assert_shared_html_shell, isolated_state, wait_for_job
from http_stub import stub_httpx
from synapse_mcp.adapters.web import js_intel
from synapse_mcp.core import background_jobs, credentials, scope, workspace
from synapse_mcp.core.js import normalizer
from synapse_mcp.core.http.models import HttpResponse
from synapse_mcp.transport import stdio_server


class JsIntelligenceTests(unittest.TestCase):
    def test_js_normalizer_rejects_code_blobs_external_endpoints_and_identifier_params(self) -> None:
        entities = normalizer.build_entities(
            {
                "endpoints": [
                    {
                        "raw": "/]})}return t})();var _o=(()=>{class t{host='/rest/order-history'}",
                        "method": "GET",
                        "sourceAsset": "https://localhost:3000/main.js",
                    },
                    {
                        "raw": "https://accounts.google.com/o/oauth2/v2/auth",
                        "method": "GET",
                        "sourceAsset": "https://localhost:3000/main.js",
                    },
                    {
                        "raw": "/rest/products/search?q=banana",
                        "method": "GET",
                        "sourceAsset": "https://localhost:3000/main.js",
                    },
                ],
                "parameters": [
                    {"name": "orderId", "location": "identifier", "sourceAsset": "https://localhost:3000/main.js"},
                    {
                        "name": "client_id",
                        "location": "query",
                        "endpointRaw": "https://accounts.google.com/o/oauth2/v2/auth",
                        "sourceAsset": "https://localhost:3000/main.js",
                    },
                ],
            },
            target="localhost",
            base_url="http://localhost:3000/",
        )

        endpoint_urls = {item["url"] for item in entities["endpoints"]}
        self.assertEqual(endpoint_urls, {"http://localhost:3000/rest/products/search?q=banana"})
        self.assertTrue(any(item["type"] == "js_external_endpoint_reference" for item in entities["observations"]))
        self.assertFalse(any("return t()" in item.get("url", "") for item in entities["endpoints"]))
        parameter_names = {item["name"] for item in entities["parameters"]}
        self.assertEqual(parameter_names, {"q"})

    def test_js_normalizer_rejects_prose_and_bare_identifier_endpoints(self) -> None:
        base = "http://localhost:3000/"
        # B5: an extracted help/error string (with spaces, embedding a URL) is prose, not a route.
        self.assertEqual(
            normalizer.normalize_candidate_url(
                "It seems you are trying to reach a Socket.IO server https://socket.io/docs/v3/", base
            ),
            "",
        )
        # B6: bare single-token identifiers/constants are not endpoint paths.
        for token in ("admin", "user", "ACCOUNT", "userId"):
            self.assertEqual(normalizer.normalize_candidate_url(token, base), "")
        # Real relative and absolute route literals are still accepted.
        self.assertEqual(normalizer.normalize_candidate_url("rest/user/login", base), "http://localhost:3000/rest/user/login")
        self.assertEqual(normalizer.normalize_candidate_url("/api/Users", base), "http://localhost:3000/api/Users")

    def test_observed_base_url_helper(self) -> None:
        self.assertEqual(
            js_intel._observed_base_url([{"url": "http://localhost:3000/a", "source": "crawler"}], "localhost"),
            "http://localhost:3000/",
        )
        self.assertEqual(js_intel._observed_base_url([], "localhost"), "")

    def test_discover_assets_from_workspace_sitemap_data(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                sitemap = {
                    "hosts": [
                        {
                            "host": "example.com",
                            "urls": [
                                {
                                    "url": "https://example.com/static/app.js",
                                    "methods": ["GET"],
                                    "contentTypes": ["application/javascript"],
                                    "fetched": True,
                                },
                                {
                                    "url": "https://example.com/2fa/assets/public/app.js",
                                    "methods": ["GET"],
                                    "contentTypes": ["text/html"],
                                    "fetched": True,
                                },
                                {
                                    "url": "https://example.com/",
                                    "methods": ["GET"],
                                    "contentTypes": ["text/html"],
                                },
                            ],
                            "forms": [],
                        }
                    ],
                    "summary": {"hostCount": 1},
                }
                workspace.ingest_data("engagement", "example.com", "sitemap", "sitemap", "json", json.dumps(sitemap))

                result = json.loads(js_intel.discover_assets({"workspaceId": "engagement", "target": "example.com"}))

                self.assertEqual(result["assetCount"], 1)
                self.assertEqual(result["assets"][0]["source"], "js_intelligence")
                self.assertEqual(result["assets"][0]["url"], "https://example.com/static/app.js")
                self.assertFalse(any(asset["url"] == "https://example.com/2fa/assets/public/app.js" for asset in result["assets"]))
                self.assertTrue(Path(result["manifestPath"]).exists())
                self.assertIn("/targets/example.com/outputs/js-intelligence/", result["manifestPath"])

    def test_fetch_assets_respects_disabled_http_backend(self) -> None:
        seen_paths: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            # Trap: a disabled backend must never build a client, so this is unreachable.
            seen_paths.append(urlsplit(str(request.url)).path)
            return httpx.Response(200, text="fetch('/api/users')", headers={"content-type": "application/javascript"})

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                target = "http://app.acme-demo.test/"
                scope.save_scope([target], "test", "Example Client")
                with stub_httpx(handler):
                    result = json.loads(
                        js_intel.fetch_assets(
                            {
                                "workspaceId": "engagement",
                                "target": target,
                                "assets": [f"{target}static/app.js"],
                                "httpBackend": "disabled",
                            }
                        )
                    )

                self.assertEqual(seen_paths, [])
                self.assertEqual(result["assetCount"], 0)
                self.assertEqual(result["errors"][0]["error"], "HTTP traffic disabled by client policy.")

    def test_fetch_assets_stops_at_total_budget(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            time.sleep(0.2)
            return httpx.Response(200, text="fetch('/api/users')", headers={"content-type": "application/javascript"})

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                target = "http://app.acme-demo.test/"
                scope.save_scope([target], "test", "Example Client")
                with stub_httpx(handler):
                    result = json.loads(
                        js_intel.fetch_assets(
                            {
                                "workspaceId": "engagement",
                                "target": target,
                                "assets": [f"{target}a.js", f"{target}b.js", f"{target}c.js"],
                                "confirm": True,
                                "totalBudgetSeconds": 0.1,
                            }
                        )
                    )
                # First asset is fetched; the budget trips before the rest,
                # which are recorded as skipped instead of orphaning the call.
                self.assertTrue(result["budgetExceeded"])
                self.assertLess(result["assetCount"], 3)
                self.assertTrue(any("budget" in str(err.get("error", "")) for err in result["errors"]))

    def test_fetch_assets_uses_workspace_scope_for_active_assets(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["global-only.example"], "test", "Example Client")
                workspace.create_workspace("engagement", organization="Example Client", hosts=["workspace.example"])

                result = json.loads(
                    js_intel.fetch_assets(
                        {
                            "workspaceId": "engagement",
                            "target": "https://workspace.example/",
                            "assets": ["https://global-only.example/static/app.js"],
                            "httpBackend": "disabled",
                        }
                    )
                )

                self.assertEqual(result["assetCount"], 0)
                self.assertEqual(len(result["errors"]), 1)
                self.assertIn("workspace engagement", result["errors"][0]["error"])

    def test_fetch_assets_clamps_request_timeout_to_remaining_budget(self) -> None:
        seen_timeouts: list[float | None] = []

        class FakeSession:
            def __enter__(self) -> "FakeSession":
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def send(self, request, *, timeout_seconds: float | None = None):
                seen_timeouts.append(timeout_seconds)
                return HttpResponse(
                    status=200,
                    headers={"content-type": "application/javascript"},
                    body="fetch('/api/users')",
                    url=request.url,
                )

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                with patch.object(js_intel.http_client, "session", return_value=FakeSession()):
                    result = json.loads(
                        js_intel.fetch_assets(
                            {
                                "workspaceId": "engagement",
                                "target": "https://example.com/",
                                "assets": ["https://example.com/static/app.js"],
                                "confirm": True,
                                "requestTimeout": 60,
                                "totalBudgetSeconds": 0.5,
                            }
                        )
                    )

                self.assertEqual(result["assetCount"], 1)
                self.assertEqual(len(seen_timeouts), 1)
                self.assertIsNotNone(seen_timeouts[0])
                self.assertLessEqual(seen_timeouts[0], 0.5)

    def test_fetch_assets_applies_scoped_credential_for_gated_assets(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            # Mirror SSO-gated static assets: unauthenticated requests redirect to a
            # non-JS login page; an authenticated session returns the JS.
            path = urlsplit(str(request.url)).path
            if path.startswith("/login"):
                return httpx.Response(200, text="<html>login</html>", headers={"content-type": "text/html"})
            if "SID=letmein" in (request.headers.get("cookie") or ""):
                return httpx.Response(200, text="fetch('/api/users')", headers={"content-type": "application/javascript"})
            return httpx.Response(302, headers={"location": "/login"})

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                target = "http://app.acme-demo.test/"
                scope.save_scope([target], "test", "Example Client")
                credentials.save_credential(
                    {"id": "web-sess", "type": "cookie", "scopes": ["app.acme-demo.test"], "secret": "SID=letmein", "confirm": True}
                )
                asset = f"{target}app.js"
                with stub_httpx(handler):
                    # Without the session, the gated asset returns the HTML login page.
                    anon = json.loads(
                        js_intel.fetch_assets({"workspaceId": "engagement", "target": target, "assets": [asset], "confirm": True})
                    )
                    self.assertEqual(anon["assetCount"], 0)
                    # With the scoped credential, the cookie is applied and the JS asset is retrieved.
                    authed = json.loads(
                        js_intel.fetch_assets(
                            {"workspaceId": "engagement", "target": target, "assets": [asset], "credentialId": "web-sess", "confirm": True}
                        )
                    )
                self.assertEqual(authed["assetCount"], 1)
                self.assertEqual(authed["credential"]["id"], "web-sess")

    def test_extract_from_source_is_linear_on_backslash_heavy_input(self) -> None:
        import signal
        from synapse_mcp.core.js import extractors

        # A long backslash-heavy region with no closing quote previously caused
        # catastrophic STRING_RE backtracking on large minified bundles. It must
        # now complete quickly and still extract a real endpoint after it.
        payload = '"' + ("\\" * 100000) + ("x" * 50000) + "fetch('/api/v1/users')"

        def _timeout(*_: object) -> None:
            raise TimeoutError("extract_from_source did not complete (catastrophic backtracking?)")

        previous = signal.signal(signal.SIGALRM, _timeout)
        signal.setitimer(signal.ITIMER_REAL, 10)
        try:
            out = extractors.extract_from_source(payload, "probe.js")
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        self.assertTrue(any("/api/v1/users" in str(e.get("raw", "")) for e in out["endpoints"]))

    def test_fetch_analyze_normalize_and_build_app_model(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            body = (
                "const API_BASE = '/api/v1';"
                "fetch('/api/v1/users?active=1', {method: 'POST', headers: {'X-CSRF-Token': csrfToken, Authorization: bearer}});"
                "axios.get('/graphql');"
                "const q = `query GetUser { user { id } }`;"
                "const ws = new WebSocket('wss://example.com/socket');"
                "localStorage.setItem('session_hint', '1');"
                "const tenantId = route.params.tenantId;"
            )
            return httpx.Response(200, text=body, headers={"content-type": "application/javascript"})

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                target = "http://app.acme-demo.test/"
                scope.save_scope([target], "test", "Example Client")
                with stub_httpx(handler):
                    fetched = json.loads(
                        js_intel.fetch_assets(
                            {
                                "workspaceId": "engagement",
                                "target": target,
                                "assets": [f"{target}static/app.js"],
                                "confirm": True,
                            }
                        )
                    )
                self.assertEqual(fetched["assetCount"], 1)
                self.assertTrue(Path(fetched["assets"][0]["localPath"]).exists())
                self.assertIn("/outputs/js-intelligence/assets/", fetched["assets"][0]["localPath"])

                analysis = json.loads(js_intel.analyze_static({"workspaceId": "engagement", "target": target, "manifestPath": fetched["manifestPath"], "background": False}))
                self.assertIn("/outputs/js-intelligence/analysis/", analysis["analysisPath"])
                self.assertGreaterEqual(analysis["summary"]["endpointCount"], 2)
                signal_types = {item["type"] for item in analysis["signals"]}
                self.assertIn("graphql_operation", signal_types)
                self.assertIn("websocket_url", signal_types)
                self.assertIn("storage_key", signal_types)
                self.assertIn("auth_header", signal_types)
                self.assertIn("csrf_signal", signal_types)
                self.assertIn("object_identifier", signal_types)

                normalized = json.loads(
                    js_intel.normalize_endpoints(
                        {
                            "workspaceId": "engagement",
                            "target": target,
                            "analysisPath": analysis["analysisPath"],
                            "background": False,
                        }
                    )
                )
                self.assertGreaterEqual(normalized["ingestion"]["entitiesCreated"]["endpoints"], 2)
                endpoints = json.loads(workspace.target_entity_path("engagement", "app.acme-demo.test", "endpoints").read_text(encoding="utf-8"))
                js_endpoints = [item for item in endpoints if item.get("source") == "js_intelligence"]
                self.assertTrue(js_endpoints)
                self.assertTrue(all(item.get("sourceAsset") for item in js_endpoints))
                self.assertTrue(all(item.get("derived") and item.get("inferred") and item.get("observed") is False for item in js_endpoints))
                self.assertTrue(all(item.get("confidence") in {"low", "medium", "high"} for item in js_endpoints))

                model = json.loads(js_intel.build_app_model({"workspaceId": "engagement", "target": target, "analysisPath": analysis["analysisPath"]}))
                self.assertEqual(model["source"], "js_intelligence")
                self.assertIn("operatorNotes", model)
                self.assertIn("graphql_operation", model["signals"])

                report = json.loads(
                    js_intel.render_app_map(
                        {
                            "workspaceId": "engagement",
                            "target": target,
                            "analysisPath": analysis["analysisPath"],
                        }
                    )
                )
                self.assertGreaterEqual(report["summary"]["endpointCount"], 2)
                self.assertGreaterEqual(report["summary"]["jsInferredEndpointCount"], 2)
                report_path = Path(report["outputPath"])
                self.assertTrue(report_path.exists())
                report_html = report_path.read_text(encoding="utf-8")
                self.assertIn("JavaScript Intelligence Report", report_html)
                self.assertIn('class="banner"', report_html)
                self.assertIn('class="banner-art"', report_html)
                self.assertIn("agentic operations layer", report_html)
                self.assertIn("mode-badge", report_html)
                assert_shared_html_shell(self, report_html)
                self.assertIn("js_inferred", report_html)
                self.assertIn("Request Map", report_html)
                # The HTML app map is the JS layer report; the flat request
                # table must not duplicate the request-map tree.
                self.assertNotIn("Observed And JS-Inferred Requests", report_html)

    def test_normalize_uses_observed_scheme_and_port(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["localhost"], "test", "Example Client")
                observed_payload = {
                    "entities": {
                        "endpoints": [
                            {
                                "type": "endpoint",
                                "url": "http://localhost:3000/rest/products/search",
                                "method": "GET",
                                "source": "crawler",
                                "observed": True,
                            }
                        ]
                    }
                }
                workspace.ingest_data("engagement", "localhost", "adapter_result", "tool_output", "json", json.dumps(observed_payload))
                asset = Path(tmp) / "app.js"
                asset.write_text("fetch('/rest/admin')", encoding="utf-8")
                analysis = json.loads(js_intel.analyze_static({"workspaceId": "engagement", "target": "localhost", "assetPaths": [str(asset)], "background": False}))

                normalized = json.loads(js_intel.normalize_endpoints({"workspaceId": "engagement", "target": "localhost", "analysisPath": analysis["analysisPath"], "background": False}))

                endpoint_urls = {item["url"] for item in normalized["entities"]["endpoints"]}
                self.assertIn("http://localhost:3000/rest/admin", endpoint_urls)
                self.assertFalse(any(url.startswith("https://localhost/") for url in endpoint_urls))

    def test_normalize_does_not_downgrade_observed_endpoint_to_inferred(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                sitemap = {
                    "hosts": [
                        {
                            "host": "example.com",
                            "urls": [{"url": "https://example.com/api/users", "methods": ["GET"], "statusCodes": [200]}],
                            "forms": [],
                        }
                    ],
                    "summary": {"hostCount": 1},
                }
                workspace.ingest_data("engagement", "example.com", "sitemap", "sitemap", "json", json.dumps(sitemap))
                asset = Path(tmp) / "app.js"
                asset.write_text("fetch('/api/users')", encoding="utf-8")
                analysis = json.loads(js_intel.analyze_static({"workspaceId": "engagement", "target": "example.com", "assetPaths": [str(asset)], "background": False}))
                normalized = json.loads(js_intel.normalize_endpoints({"workspaceId": "engagement", "target": "example.com", "analysisPath": analysis["analysisPath"], "background": False}))

                self.assertEqual(normalized["entities"]["endpoints"], [])
                self.assertTrue(any(item.get("type") == "js_endpoint_reference" for item in normalized["entities"]["observations"]))
                endpoints = json.loads(workspace.target_entity_path("engagement", "example.com", "endpoints").read_text(encoding="utf-8"))
                observed = [item for item in endpoints if item.get("url") == "https://example.com/api/users"]
                self.assertEqual(len(observed), 1)
                self.assertFalse(observed[0].get("inferred", False))

    def test_analyze_static_resolves_manifest_relative_local_paths(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                manifest_dir = Path(tmp) / "manifest"
                assets_dir = manifest_dir / "assets"
                assets_dir.mkdir(parents=True)
                asset = assets_dir / "app.js"
                asset.write_text("fetch('/api/relative')", encoding="utf-8")
                manifest = manifest_dir / "fetched-assets.json"
                manifest.write_text(
                    json.dumps(
                        {
                            "assets": [
                                {
                                    "url": "https://example.com/static/app.js",
                                    "localPath": "assets/app.js",
                                    "source": "js_intelligence",
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )

                analysis = json.loads(
                    js_intel.analyze_static(
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "manifestPath": str(manifest),
                            "background": False,
                        }
                    )
                )

                self.assertEqual(analysis["summary"]["assetCount"], 1)
                self.assertFalse(analysis["summary"]["errors"])
                self.assertEqual(Path(analysis["assets"][0]["localPath"]), asset.resolve())

    def test_js_artifact_writer_keeps_latest_generated_json(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                with patch.object(js_intel.workspace, "timestamped_filename", side_effect=["20260608-100000-assets.json", "20260608-100001-assets.json"]):
                    first = js_intel._write_json_artifact("engagement", "example.com", "manifests", "assets.json", {"assets": []})
                    second = js_intel._write_json_artifact("engagement", "example.com", "manifests", "assets.json", {"assets": [{"url": "https://example.com/app.js"}]})

                self.assertFalse(first.exists())
                self.assertTrue(second.exists())
                self.assertEqual(json.loads(second.read_text(encoding="utf-8"))["assets"][0]["url"], "https://example.com/app.js")

    def test_js_analyze_static_defaults_to_background_job(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                asset = Path(tmp) / "app.js"
                asset.write_text("fetch('/api/users')", encoding="utf-8")

                started = json.loads(
                    js_intel.analyze_static(
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "assetPaths": [str(asset)],
                            "timeoutSeconds": 30,
                        }
                    )
                )
                self.assertTrue(started["background"])
                self.assertEqual(started["job"]["tool"], "js.analyze_static")

                job = wait_for_job(started["job"]["jobId"])
                self.assertEqual(job["status"], "completed")
                self.assertTrue(job["finalized"])
                self.assertGreaterEqual(job["result"]["summary"]["endpointCount"], 1)

    def test_js_analyze_static_can_chain_background_normalization(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                asset = Path(tmp) / "app.js"
                asset.write_text("fetch('/api/chained')", encoding="utf-8")

                started = json.loads(
                    js_intel.analyze_static(
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "assetPaths": [str(asset)],
                            "timeoutSeconds": 30,
                            "normalizeAfter": True,
                        }
                    )
                )

                analysis_job = wait_for_job(started["job"]["jobId"])
                self.assertIn("normalizeJob", analysis_job["result"])
                normalize_job_id = analysis_job["result"]["normalizeJob"]["job"]["jobId"]

                normalize_job = wait_for_job(normalize_job_id)
                self.assertEqual(normalize_job["status"], "completed")
                self.assertTrue(Path(normalize_job["result"]["normalizedPath"]).exists())
                self.assertIn("ingestion", normalize_job["result"])
                for _ in range(10):
                    active = background_jobs.list_jobs(active_only=True)["jobs"]
                    if not active:
                        break
                    time.sleep(0.05)

    def test_js_background_job_limit_counts_analyze_and_normalize(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                job_ids = []
                for index in range(3):
                    job = background_jobs.start_command(
                        ["sh", "-c", "sleep 30"],
                        timeout_seconds=60,
                        event_type="js.analyze_static",
                        summary=f"fake js job {index}",
                        tool="js.analyze_static",
                        workspace_id="engagement",
                        target="example.com",
                    )
                    job_ids.append(str(job["jobId"]))

                try:
                    with self.assertRaisesRegex(Exception, "Too many JavaScript analysis/normalization jobs"):
                        js_intel.analyze_static(
                            {
                                "workspaceId": "engagement",
                                "target": "example.com",
                                "assetPaths": [str(Path(tmp) / "app.js")],
                            }
                        )
                finally:
                    for job_id in job_ids:
                        background_jobs.cancel(job_id)

    def test_mcp_tools_are_exposed_and_dispatch(self) -> None:
        tool_names = {tool["name"] for tool in stdio_server.TOOL_SCHEMAS}
        for name in {
            "js.capabilities",
            "js.discover_assets",
            "js.fetch_assets",
            "js.analyze_static",
            "js.normalize_endpoints",
            "js.build_app_model",
            "js.render_app_map",
        }:
            self.assertIn(name, tool_names)
        capabilities = json.loads(stdio_server.call_tool("js.capabilities", {}))
        self.assertEqual(capabilities["source"], "js_intelligence")
