from __future__ import annotations

import http.client
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from helpers import isolated_state
from synapse_mcp.app.actions import ActionRequest, ExecutionContext, REGISTRY, Success
from synapse_mcp.core import credentials, scope, workspace
from synapse_mcp.core.errors import McpError


class _Server:
    def __init__(self, handler: type[BaseHTTPRequestHandler]) -> None:
        self.server = HTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_port

    def __enter__(self) -> "_Server":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _request(action_id: str, arguments: dict) -> ActionRequest:
    descriptor = REGISTRY.get(action_id)
    return ActionRequest(
        descriptor.input_model.model_validate(arguments),
        ExecutionContext(arguments.get("workspaceId"), "stageb-credential-test", 45.0, arguments.get("confirm")),
    )


def _store_header_credential(
    credential_id: str,
    secret: str,
    *,
    target_origins: list[str],
) -> None:
    credentials.save_credential(
        {
            "id": credential_id,
            "type": "header",
            "scopes": ["127.0.0.1", "localhost"],
            "targetOrigins": target_origins,
            "headerName": "X-Fixture-Header",
            "secret": secret,
        }
    )


class CredentialConfinementTests(unittest.TestCase):
    def test_proxy_authorization_credential_cannot_be_target_scoped(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            scope.save_scope(["127.0.0.1"], "fixture")
            with self.assertRaises(McpError) as raised:
                credentials.save_credential(
                    {
                        "id": "misbound-proxy-header",
                        "type": "header",
                        "targetOrigins": ["http://127.0.0.1:8080"],
                        "headerName": "Proxy-Authorization",
                        "secret": "synthetic-proxy-secret",
                    }
                )
            self.assertEqual(raised.exception.code, -32602)

    def test_crawler_resolves_each_destination_and_reports_anonymous_fallback(self) -> None:
        seed_headers: list[dict[str, str]] = []
        destination_headers: list[dict[str, str]] = []
        destination: _Server

        class Destination(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                destination_headers.append({name.lower(): value for name, value in self.headers.items()})
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>done</html>")

            def log_message(self, *_: object) -> None:
                return

        class Seed(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                seed_headers.append({name.lower(): value for name, value in self.headers.items()})
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", "/home")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    f'<html><a href="http://localhost:{destination.port}/second">second</a></html>'.encode()
                )

            def log_message(self, *_: object) -> None:
                return

        with _Server(Destination) as destination, _Server(Seed) as seed, TemporaryDirectory() as tmp:
            root = Path(tmp)
            with isolated_state(root):
                scope.save_scope(["127.0.0.1", "localhost"], "fixture")
                workspace.create_workspace("ws", hosts=["127.0.0.1", "localhost"])
                seed_origin = f"http://127.0.0.1:{seed.port}"
                secret = "stageb-crawler-secret-7bd415"
                _store_header_credential("crawler-seed", secret, target_origins=[seed_origin])

                arguments = {
                    "target": f"{seed_origin}/start",
                    "workspaceId": "ws",
                    "credentialId": "crawler-seed",
                    "background": False,
                    "includeInScopeHosts": True,
                    "maxPages": 4,
                    "maxDepth": 2,
                    "confirm": True,
                }
                request = _request("crawler.crawl", arguments)
                plan = REGISTRY.resolve_execution_plan("crawler.crawl", request)
                outcome = REGISTRY.execute("crawler.crawl", request)

                self.assertIsInstance(outcome, Success)
                payload = json.loads(str(outcome.legacy_payload))
                coverage = payload["crawl"]["credentialCoverage"]
                self.assertIn(
                    {
                        "credentialRef": "crawler-seed",
                        "targetOrigin": seed_origin,
                        "status": "credential_applied",
                        "reasonCode": "credential_target_covered",
                    },
                    coverage,
                )
                self.assertTrue(
                    any(
                        item["targetOrigin"] == f"http://localhost:{destination.port}"
                        and item["status"] == "anonymous_credential_not_scoped"
                        for item in coverage
                    )
                )
                self.assertEqual([item.get("x-fixture-header") for item in seed_headers], [secret, secret])
                self.assertEqual([item.get("x-fixture-header") for item in destination_headers], [None])
                self.assertNotIn(secret, json.dumps(plan.to_dict()))
                self.assertNotIn(secret, str(outcome.legacy_payload))
                for path in [workspace.WORKSPACES_DIR, root / "evidence"]:
                    for file_path in path.rglob("*"):
                        if file_path.is_file():
                            self.assertNotIn(secret, file_path.read_text(encoding="utf-8", errors="replace"))

    def test_crawler_credential_explicitly_scoped_to_both_origins_is_reapplied(self) -> None:
        destination_headers: list[dict[str, str]] = []
        destination: _Server

        class Destination(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                destination_headers.append({name.lower(): value for name, value in self.headers.items()})
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        class Seed(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    f'<a href="http://localhost:{destination.port}/covered">covered</a>'.encode()
                )

            def log_message(self, *_: object) -> None:
                return

        with _Server(Destination) as destination, _Server(Seed) as seed, TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["127.0.0.1", "localhost"], "fixture")
                workspace.create_workspace("ws", hosts=["127.0.0.1", "localhost"])
                seed_origin = f"http://127.0.0.1:{seed.port}"
                destination_origin = f"http://localhost:{destination.port}"
                secret = "stageb-multi-origin-secret-e216"
                _store_header_credential(
                    "crawler-multi",
                    secret,
                    target_origins=[seed_origin, destination_origin],
                )
                outcome = REGISTRY.execute(
                    "crawler.crawl",
                    _request(
                        "crawler.crawl",
                        {
                            "target": f"{seed_origin}/",
                            "workspaceId": "ws",
                            "credentialId": "crawler-multi",
                            "background": False,
                            "includeInScopeHosts": True,
                            "maxPages": 2,
                            "maxDepth": 1,
                            "confirm": True,
                        },
                    ),
                )
                self.assertIsInstance(outcome, Success)
                self.assertEqual([item.get("x-fixture-header") for item in destination_headers], [secret])
                coverage = json.loads(str(outcome.legacy_payload))["crawl"]["credentialCoverage"]
                self.assertTrue(
                    any(
                        item["targetOrigin"] == destination_origin and item["status"] == "credential_applied"
                        for item in coverage
                    )
                )

    def test_cors_cross_origin_redirect_does_not_forward_custom_credential_header(self) -> None:
        source_headers: list[dict[str, str]] = []
        destination_headers: list[dict[str, str]] = []
        destination: _Server

        class Destination(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                destination_headers.append({name.lower(): value for name, value in self.headers.items()})
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        class Source(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                source_headers.append({name.lower(): value for name, value in self.headers.items()})
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{destination.port}/cors")
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        with _Server(Destination) as destination, _Server(Source) as source, TemporaryDirectory() as tmp:
            root = Path(tmp)
            with isolated_state(root):
                scope.save_scope(["127.0.0.1", "localhost"], "fixture")
                workspace.create_workspace("ws", hosts=["127.0.0.1", "localhost"])
                source_origin = f"http://127.0.0.1:{source.port}"
                secret = "stageb-cors-secret-451b"
                _store_header_credential("cors-seed", secret, target_origins=[source_origin])
                outcome = REGISTRY.execute(
                    "cors.execute_test",
                    _request(
                        "cors.execute_test",
                        {
                            "workspaceId": "ws",
                            "url": f"{source_origin}/start",
                            "credentialId": "cors-seed",
                            "followRedirects": True,
                            "confirm": True,
                        },
                    ),
                )
                self.assertIsInstance(outcome, Success)
                self.assertEqual(source_headers[0].get("x-fixture-header"), secret)
                self.assertNotIn("x-fixture-header", destination_headers[0])
                serialized = str(outcome.legacy_payload)
                self.assertNotIn(secret, serialized)
                coverage = json.loads(serialized)["test"]["credentialCoverage"]
                self.assertEqual(
                    [item["status"] for item in coverage],
                    ["credential_applied", "anonymous_credential_not_scoped"],
                )
                for path in [workspace.WORKSPACES_DIR, root / "evidence"]:
                    for file_path in path.rglob("*"):
                        if file_path.is_file():
                            self.assertNotIn(secret, file_path.read_text(encoding="utf-8", errors="replace"))

    def test_proxy_credential_uses_provider_scope_and_reaches_only_proxy(self) -> None:
        proxy_authorization: list[str] = []
        target_proxy_authorization: list[str] = []

        class Target(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                target_proxy_authorization.append(self.headers.get("Proxy-Authorization", ""))
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        class Proxy(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                proxy_authorization.append(self.headers.get("Proxy-Authorization", ""))
                parsed = urlsplit(self.path)
                connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=3)
                forwarded = {
                    name: value
                    for name, value in self.headers.items()
                    if name.lower() not in {"proxy-authorization", "proxy-connection", "host"}
                }
                connection.request("GET", parsed.path or "/", headers=forwarded)
                response = connection.getresponse()
                body = response.read()
                self.send_response(response.status)
                for name, value in response.getheaders():
                    if name.lower() not in {"content-length", "transfer-encoding", "connection"}:
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                connection.close()

            def log_message(self, *_: object) -> None:
                return

        with _Server(Target) as target, _Server(Proxy) as proxy, TemporaryDirectory() as tmp:
            root = Path(tmp)
            with isolated_state(root):
                scope.save_scope(["127.0.0.1"], "fixture")
                workspace.create_workspace("ws", hosts=["127.0.0.1"])
                proxy_url = f"http://127.0.0.1:{proxy.port}"
                proxy_secret = "stageb-proxy-secret-024d"
                credentials.save_credential(
                    {
                        "id": "proxy-basic",
                        "type": "basic",
                        "scopes": [],
                        "providerScopes": [proxy_url],
                        "username": "operator",
                        "secret": proxy_secret,
                    }
                )
                arguments = {
                    "workspaceId": "ws",
                    "url": f"http://127.0.0.1:{target.port}/cors",
                    "httpBackend": "proxy",
                    "proxyUrl": proxy_url,
                    "proxyCredentialId": "proxy-basic",
                    "confirm": True,
                }
                request = _request("cors.execute_test", arguments)
                plan = REGISTRY.resolve_execution_plan("cors.execute_test", request)
                outcome = REGISTRY.execute("cors.execute_test", request)

                self.assertIsInstance(outcome, Success)
                self.assertEqual(len(proxy_authorization), 1)
                self.assertTrue(proxy_authorization[0].startswith("Basic "))
                self.assertEqual(target_proxy_authorization, [""])
                self.assertNotIn(proxy_secret, json.dumps(plan.to_dict()))
                self.assertNotIn(proxy_secret, str(outcome.legacy_payload))
                for path in [workspace.WORKSPACES_DIR, root / "evidence"]:
                    for file_path in path.rglob("*"):
                        if file_path.is_file():
                            self.assertNotIn(proxy_secret, file_path.read_text(encoding="utf-8", errors="replace"))


if __name__ == "__main__":
    unittest.main()
