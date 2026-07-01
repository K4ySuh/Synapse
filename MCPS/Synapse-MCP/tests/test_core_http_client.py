import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from synapse_mcp.adapters.web import active_probe
from synapse_mcp.core.http import HttpClientPolicy, HttpRequest, http_client


class CoreHttpClientTests(unittest.TestCase):
    def test_direct_backend_follows_redirects_and_limits_body(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/large")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"A" * 50)

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            response = http_client.send(
                HttpRequest(url=f"http://127.0.0.1:{server.server_port}/redirect"),
                policy=HttpClientPolicy(max_body_bytes=12),
            )

            self.assertEqual(response.status, 200)
            self.assertTrue(response.url.endswith("/large"))
            self.assertEqual(response.body, "A" * 12)
            self.assertEqual(response.headers["content-type"], "text/plain")
            self.assertEqual(response.error, "")
        finally:
            server.shutdown()
            server.server_close()

    def test_direct_backend_session_reuses_cookie_state(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/set":
                    self.send_response(200)
                    self.send_header("Set-Cookie", "SID=ok; Path=/")
                    self.end_headers()
                    return
                self.send_response(200 if self.headers.get("Cookie") == "SID=ok" else 403)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            policy = HttpClientPolicy()
            with http_client.session(policy) as session:
                first = session.send(HttpRequest(url=f"http://127.0.0.1:{server.server_port}/set"))
                second = session.send(HttpRequest(url=f"http://127.0.0.1:{server.server_port}/check"))

            self.assertEqual(first.status, 200)
            self.assertEqual(second.status, 200)
        finally:
            server.shutdown()
            server.server_close()

    def test_disabled_backend_returns_error_without_sending_traffic(self) -> None:
        seen_paths: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                seen_paths.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            response = http_client.send(
                HttpRequest(url=f"http://127.0.0.1:{server.server_port}/blocked"),
                policy=HttpClientPolicy(backend="disabled"),
            )

            self.assertIsNone(response.status)
            self.assertIn("disabled", response.error)
            self.assertEqual(seen_paths, [])
        finally:
            server.shutdown()
            server.server_close()

    def test_proxy_backend_requires_explicit_proxy_url(self) -> None:
        response = http_client.send(
            HttpRequest(url="http://127.0.0.1/"),
            policy=HttpClientPolicy(backend="proxy"),
        )

        self.assertIsNone(response.status)
        self.assertIn("proxy_url", response.error)

    def test_active_probe_builder_can_feed_http_core_directly(self) -> None:
        built = active_probe.build_http_request(
            "http://127.0.0.1/diag?host=127.0.0.1",
            "GET",
            "host",
            "query",
            "SYNAPSE_MARKER",
        )

        response = http_client.send(
            HttpRequest(url=built["url"], method=built["method"], headers=built["headers"], body=built.get("_bodyBytes")),
            policy=HttpClientPolicy(backend="disabled"),
        )

        self.assertIsNone(response.status)
        self.assertIn("disabled", response.error)


if __name__ == "__main__":
    unittest.main()
