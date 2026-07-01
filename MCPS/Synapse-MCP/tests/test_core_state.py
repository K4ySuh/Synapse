import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import parse_qs

from helpers import isolated_state
from synapse_mcp.core import background_jobs, credentials, dumps, evidence, scope, workspace
from synapse_mcp.transport import stdio_server


class CoreStateTests(unittest.TestCase):
    def test_jobs_status_omits_full_result_by_default(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["example.com"])
                result_path = workspace.workspace_path("engagement") / "job-result.json"
                result_path.write_text(
                    json.dumps({"summary": {"endpointCount": 2}, "items": [{"url": "https://example.com/a"}], "outputPath": "reports/result.json"}),
                    encoding="utf-8",
                )
                started = background_jobs.start_command(
                    ["sh", "-c", "true"],
                    timeout_seconds=30,
                    event_type="unit.job",
                    summary="unit job",
                    tool="unit.job",
                    workspace_id="engagement",
                    target="example.com",
                    finalizer_name="worker.result",
                    finalizer_data={"resultPath": str(result_path)},
                )
                deadline = time.monotonic() + 5
                status = {}
                while time.monotonic() < deadline:
                    status = background_jobs.status(started["jobId"])
                    if status.get("status") == "completed" and status.get("finalized"):
                        break
                    time.sleep(0.05)

                self.assertEqual(status["status"], "completed")
                self.assertNotIn("result", status)
                self.assertEqual(status["resultPath"], str(result_path))
                self.assertEqual(status["outputPath"], "reports/result.json")
                self.assertEqual(status["resultSummary"], {"endpointCount": 2})

                full = background_jobs.status(started["jobId"], include_result=True)
                self.assertIn("result", full)
                self.assertEqual(full["result"]["items"][0]["url"], "https://example.com/a")

    def test_credentials_are_scoped_and_redacted(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["https://example.com"], "test")
                result = credentials.save_credential(
                    {
                        "id": "session-cookie",
                        "type": "cookie",
                        "scopes": ["example.com"],
                        "secret": "SESSIONID=abcdef123456",
                    }
                )
                self.assertEqual(result["credential"]["secret"], "SESS...3456")

                listed = credentials.list_credentials()
                self.assertTrue(listed["redacted"])
                self.assertEqual(listed["credentials"][0]["secret"], "SESS...3456")
                self.assertEqual(credentials.credential_for_target("session-cookie", "https://example.com")["secret"], "SESSIONID=abcdef123456")

    def test_authentication_profile_refreshes_cookie_credential(self) -> None:
        class LoginHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                fields = parse_qs(body)
                if (
                    self.path == "/login"
                    and fields.get("username") == ["alice"]
                    and fields.get("password") == ["secret-password"]
                    and fields.get("csrf") == ["static-token"]
                ):
                    self.send_response(200)
                    self.send_header("Set-Cookie", "SESSIONID=refreshed123; Path=/; HttpOnly")
                    self.send_header("Set-Cookie", "PREF=ignored; Path=/")
                    self.end_headers()
                    self.wfile.write(b"Welcome alice")
                    return
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Invalid login")

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), LoginHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                with isolated_state(tmp_path):
                    login_url = f"http://127.0.0.1:{server.server_port}/login"
                    scope.save_scope([login_url], "test", "Example Client")
                    profile = credentials.save_auth_profile(
                        {
                            "id": "main-login",
                            "credentialId": "prod-cookie",
                            "scopes": ["127.0.0.1"],
                            "loginUrl": login_url,
                            "username": "alice",
                            "password": "secret-password",
                            "extraFields": {"csrf": "static-token"},
                            "cookieNames": ["SESSIONID"],
                            "successPattern": "Welcome",
                        }
                    )
                    self.assertEqual(profile["authProfile"]["password"], "***")

                    result = credentials.authenticate({"profileId": "main-login", "target": login_url})
                    self.assertTrue(result["authenticated"])
                    self.assertEqual(result["credential"]["id"], "prod-cookie")
                    self.assertEqual(result["credential"]["secret"], "SESS...d123")
                    self.assertEqual(result["cookieNames"], ["SESSIONID"])

                    stored = credentials.credential_for_target("prod-cookie", login_url)
                    self.assertEqual(stored["secret"], "SESSIONID=refreshed123")
                    listed = json.dumps(credentials.list_credentials())
                    self.assertNotIn("secret-password", listed)
                    self.assertNotIn("SESSIONID=refreshed123", listed)
        finally:
            server.shutdown()
            server.server_close()

    def test_browser_auth_profile_is_scoped_and_redacted(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")

                result = credentials.save_browser_auth_profile(
                    {
                        "id": "sso-login",
                        "credentialId": "browser-session",
                        "scopes": ["example.com"],
                        "loginUrl": "https://example.com/login",
                        "username": "alice",
                        "password": "secret-password",
                        "steps": [
                            {"action": "goto", "url": "https://example.com/login"},
                            {"action": "fill", "selector": "#user", "value": "{{username}}"},
                            {"action": "fill", "selector": "#pass", "value": "{{password}}"},
                            {"action": "click", "selector": "button[type=submit]"},
                        ],
                        "successUrlPattern": "/dashboard",
                        "cookieNames": ["SESSIONID"],
                    }
                )

                profile = result["authProfile"]
                self.assertEqual(profile["type"], "browser_auth")
                self.assertEqual(profile["password"], "***")
                self.assertEqual(profile["steps"][2]["value"], "[REDACTED]")
                listed = json.dumps(credentials.list_credentials())
                self.assertNotIn("secret-password", listed)

    def test_delete_credential_removes_linked_auth_profiles(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                credentials.save_credential(
                    {
                        "id": "browser-session",
                        "type": "session",
                        "scopes": ["example.com"],
                        "secret": json.dumps({"cookies": [{"name": "SESSIONID", "value": "abc", "domain": "example.com", "path": "/"}]}),
                    }
                )
                credentials.save_browser_auth_profile(
                    {
                        "id": "browser-session-browser",
                        "credentialId": "browser-session",
                        "scopes": ["example.com"],
                        "loginUrl": "https://example.com/login",
                        "manualCompletion": True,
                    }
                )

                result = credentials.delete_credential("browser-session")

                self.assertTrue(result["deletedCredential"])
                self.assertEqual(result["deletedProfiles"], ["browser-session-browser"])
                listed = credentials.list_credentials(include_secrets=True)
                self.assertEqual(listed["credentials"], [])
                self.assertEqual(listed["authProfiles"], [])

    def test_delete_auth_profile_id_succeeds(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                credentials.save_browser_auth_profile(
                    {
                        "id": "sso-login",
                        "credentialId": "browser-session",
                        "scopes": ["example.com"],
                        "loginUrl": "https://example.com/login",
                        "manualCompletion": True,
                    }
                )

                result = credentials.delete_credential("sso-login")

                self.assertFalse(result["deletedCredential"])
                self.assertEqual(result["deletedProfiles"], ["sso-login"])
                self.assertEqual(credentials.list_credentials(include_secrets=True)["authProfiles"], [])

    def test_background_browser_auth_args_are_private_sanitized_and_cleaned_up(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                profile = {"id": "sso-login", "credentialId": "browser-session", "provider": "playwright"}

                def fake_start_command(*_: object, **kwargs: object) -> dict[str, object]:
                    return {
                        "jobId": "job_browser_auth",
                        "status": "running",
                        "finalizerData": kwargs.get("finalizer_data", {}),
                    }

                with patch.object(background_jobs, "start_command", side_effect=fake_start_command):
                    result = credentials._start_background_browser_auth(
                        {
                            "workspaceId": "engagement",
                            "password": "inline-password",
                            "token": "inline-token",
                            "nested": {"secret": "inline-secret", "visible": "ok"},
                        },
                        profile,
                        "https://example.com/login",
                        "example.com",
                    )

                args_path = Path(result["workerArgsPath"])
                state_path = Path(result["workerStatePath"])
                args_payload = json.loads(args_path.read_text(encoding="utf-8"))
                self.assertEqual(args_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(state_path.stat().st_mode & 0o777, 0o600)
                self.assertNotIn("password", args_payload)
                self.assertNotIn("token", args_payload)
                self.assertNotIn("secret", args_payload["nested"])
                self.assertEqual(args_payload["nested"]["visible"], "ok")

                result_path = Path(result["resultPath"])
                result_path.write_text("{}", encoding="utf-8")
                finalized = background_jobs._worker_result_finalizer(
                    {},
                    {},
                    {"resultPath": str(result_path), "cleanupArgsPath": str(args_path)},
                )
                self.assertFalse(args_path.exists())
                self.assertIn("workerCleanup", finalized)

    def test_background_browser_auth_artifacts_are_unique_per_job(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                profile = {"id": "shared-sso", "credentialId": "browser-session", "provider": "playwright"}
                started: list[dict[str, object]] = []

                def fake_start_command(*_: object, **kwargs: object) -> dict[str, object]:
                    started.append(kwargs)
                    return {
                        "jobId": f"job_browser_auth_{len(started)}",
                        "status": "running",
                        "finalizerData": kwargs.get("finalizer_data", {}),
                    }

                with patch.object(workspace, "timestamped_filename", side_effect=lambda suffix: f"20260617-120000-{suffix}"), patch.object(
                    background_jobs,
                    "start_command",
                    side_effect=fake_start_command,
                ):
                    first = credentials._start_background_browser_auth(
                        {"workspaceId": "engagement"},
                        profile,
                        "https://example.com/login",
                        "example.com",
                    )
                    second = credentials._start_background_browser_auth(
                        {"workspaceId": "engagement"},
                        profile,
                        "https://example.com/login",
                        "example.com",
                    )

                self.assertNotEqual(first["artifactStem"], second["artifactStem"])
                self.assertNotEqual(first["workerArgsPath"], second["workerArgsPath"])
                self.assertNotEqual(first["workerStatePath"], second["workerStatePath"])
                self.assertNotEqual(first["resultPath"], second["resultPath"])
                self.assertIn("browser-auth-shared-sso-", Path(first["workerArgsPath"]).name)
                self.assertIn("browser-auth-shared-sso-", Path(second["workerArgsPath"]).name)

    def test_session_credential_resolves_target_cookies_and_authorization(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["app.example.com", "idp.example.com"], "test", "Example Client")
                secret = json.dumps(
                    {
                        "cookies": [
                            {"name": "APPSESS", "value": "aaa", "domain": "app.example.com", "path": "/"},
                            {"name": "IDPSESS", "value": "bbb", "domain": "idp.example.com", "path": "/"},
                            {"name": "ADMIN", "value": "ccc", "domain": "app.example.com", "path": "/admin"},
                            {"name": "UNKNOWN", "value": "leak", "domain": "", "path": "/"},
                        ],
                        "tokens": {"access_token": "token-value"},
                        "authorization": {"scheme": "Bearer", "value": "token-value"},
                        "headers": {"User-Agent": "Browser UA", "Accept-Language": "ca-ES", "Cookie": "SHOULD=skip"},
                    }
                )
                credentials.save_credential({"id": "browser-session", "type": "session", "scopes": ["app.example.com", "idp.example.com"], "secret": secret})

                app_headers = credentials.headers_for_credential_target(
                    credentials.credential_for_target("browser-session", "https://app.example.com"),
                    "https://app.example.com/home",
                )
                self.assertEqual(app_headers["Cookie"], "APPSESS=aaa")
                self.assertEqual(app_headers["Authorization"], "Bearer token-value")
                self.assertEqual(app_headers["User-Agent"], "Browser UA")
                self.assertEqual(app_headers["Accept-Language"], "ca-ES")

                admin_headers = credentials.headers_for_credential_target(
                    credentials.credential_for_target("browser-session", "https://app.example.com"),
                    "https://app.example.com/admin/panel",
                )
                self.assertEqual(admin_headers["Cookie"], "ADMIN=ccc; APPSESS=aaa")

                idp_headers = credentials.headers_for_credential_target(
                    credentials.credential_for_target("browser-session", "https://idp.example.com"),
                    "https://idp.example.com/sso",
                )
                self.assertEqual(idp_headers["Cookie"], "IDPSESS=bbb")

                other_headers = credentials.headers_for_credential_target(
                    credentials.credential_for_target("browser-session", "https://app.example.com"),
                    "https://other.example.com/",
                )
                self.assertNotIn("Cookie", other_headers)

    def test_validate_session_sends_target_aware_headers(self) -> None:
        class ProtectedHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.headers.get("Cookie") == "SESSIONID=ok":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Welcome dashboard")
                    return
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        server = HTTPServer(("127.0.0.1", 0), ProtectedHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    target = f"http://127.0.0.1:{server.server_port}/dashboard"
                    scope.save_scope([target], "test", "Example Client")
                    credentials.save_credential(
                        {
                            "id": "browser-session",
                            "type": "session",
                            "scopes": ["127.0.0.1"],
                            "secret": json.dumps({"cookies": [{"name": "SESSIONID", "value": "ok", "domain": "127.0.0.1", "path": "/"}]}),
                        }
                    )

                    result = credentials.validate_session(
                        {
                            "credentialId": "browser-session",
                            "target": target,
                            "successPattern": "Welcome",
                            "followRedirects": False,
                        }
                    )
                    self.assertTrue(result["validation"]["ok"])
                    self.assertEqual(result["validation"]["status"], 200)
                    self.assertEqual(result["validation"]["appliedSession"]["cookieNames"], ["SESSIONID"])
                    self.assertTrue(result["validation"]["appliedSession"]["hasCookies"])
        finally:
            server.shutdown()
            server.server_close()

    def test_browser_result_preserves_safe_browser_headers(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                result = credentials._browser_result_from_storage_state(
                    "playwright",
                    {
                        "cookieNames": [],
                        "captureStorage": True,
                        "captureBrowserHeaders": True,
                        "tokenStorageKeys": [],
                    },
                    {
                        "cookies": [{"name": "SESSIONID", "value": "ok", "domain": "example.com", "path": "/"}],
                        "origins": [],
                    },
                    "https://example.com/dashboard",
                    {
                        "User-Agent": "Mozilla/5.0 Test",
                        "Accept-Language": "en-US",
                        "Authorization": "Bearer should-not-store",
                    },
                )

                self.assertEqual(result["headers"]["User-Agent"], "Mozilla/5.0 Test")
                self.assertEqual(result["headers"]["Accept-Language"], "en-US")
                self.assertNotIn("Authorization", result["headers"])
                self.assertEqual(result["summary"]["browserHeaderNames"], ["Accept-Language", "User-Agent"])

    def test_stdio_browser_auth_profile_dispatch(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                created = json.loads(
                    stdio_server.call_tool(
                        "credentials.set_browser_auth_profile",
                        {
                            "id": "manual-sso",
                            "credentialId": "manual-session",
                            "scopes": ["example.com"],
                            "loginUrl": "https://example.com/sso",
                            "manualCompletion": True,
                            "headless": False,
                            "confirm": True,
                        },
                    )
                )
                self.assertTrue(created["saved"])
                setup = json.loads(stdio_server.call_tool("credentials.browser_auth_check_setup", {"provider": "selenium_remote"}))
                self.assertEqual(setup["provider"], "selenium_remote")

    def test_browser_auth_background_rejects_execute_time_secrets(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                credentials.save_browser_auth_profile(
                    {
                        "id": "manual-sso",
                        "credentialId": "manual-session",
                        "scopes": ["example.com"],
                        "loginUrl": "https://example.com/sso",
                        "manualCompletion": True,
                    }
                )

                with self.assertRaisesRegex(Exception, "manualValues"):
                    credentials.browser_authenticate(
                        {
                            "profileId": "manual-sso",
                            "target": "https://example.com/sso",
                            "manualValues": {"otp": "123456"},
                            "background": True,
                        }
                    )

    def test_browser_auth_background_worker_uses_synapse_python(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                credentials.save_browser_auth_profile(
                    {
                        "id": "manual-sso",
                        "credentialId": "manual-session",
                        "scopes": ["example.com"],
                        "loginUrl": "https://example.com/sso",
                        "manualCompletion": True,
                    }
                )

                def fake_start_command(cmd: list[str], **_: object) -> dict[str, object]:
                    self.assertEqual(cmd[0], "/tmp/synapse-venv-python")
                    return {"jobId": "job_auth", "status": "running", "createdAt": "2026-06-08T00:00:00Z"}

                with patch.object(credentials, "synapse_python", return_value="/tmp/synapse-venv-python"), patch(
                    "synapse_mcp.core.background_jobs.start_command",
                    side_effect=fake_start_command,
                ):
                    result = credentials.browser_authenticate(
                        {
                            "profileId": "manual-sso",
                            "target": "https://example.com/sso",
                            "background": True,
                            "confirm": True,
                        }
                    )

                self.assertTrue(result["background"])
                self.assertEqual(result["job"]["jobId"], "job_auth")

    def test_browser_auth_can_reuse_valid_existing_session(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")
                credentials.save_browser_auth_profile(
                    {
                        "id": "manual-sso",
                        "credentialId": "manual-session",
                        "scopes": ["example.com"],
                        "loginUrl": "https://example.com/sso",
                        "protectedUrl": "https://example.com/account",
                        "manualCompletion": True,
                    }
                )
                credentials.save_credential(
                    {
                        "id": "manual-session",
                        "type": "session",
                        "scopes": ["example.com"],
                        "secret": json.dumps({"cookies": [{"name": "SESSIONID", "value": "abc", "domain": "example.com", "path": "/"}], "tokens": {}}),
                    }
                )

                with patch.object(credentials, "_run_playwright_browser_auth", side_effect=AssertionError("browser should not launch")), patch.object(
                    credentials,
                    "_validate_session_credential",
                    return_value={"checked": True, "ok": True, "status": 200, "url": "https://example.com/account", "reason": ""},
                ):
                    result = credentials.browser_authenticate(
                        {
                            "profileId": "manual-sso",
                            "target": "https://example.com/sso",
                            "background": False,
                            "validateExistingSessionFirst": True,
                        }
                    )

                self.assertTrue(result["authenticated"])
                self.assertTrue(result["usedExistingSession"])
                self.assertFalse(result["browserLaunched"])
                self.assertEqual(result["finalUrl"], "https://example.com/account")

    def test_browser_auth_pattern_failure_message_preserves_diagnostic_context(self) -> None:
        message = credentials._browser_pattern_failure_message({"id": "tester3-login"}, "failurePattern", "https://example.com/login")

        self.assertIn("tester3-login", message)
        self.assertIn("https://example.com/login", message)
        self.assertIn("credentials.validate_session", message)
        self.assertNotIn("Invalid password", message)

    def test_project_start_returns_authentication_guidance(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                result = json.loads(
                    stdio_server.call_tool(
                        "project.start",
                        {"organization": "Example Client", "hosts": ["example.com"]},
                    )
                )
                guidance = result["authenticationGuidance"]
                self.assertIn("authentication", guidance["message"].lower())
                self.assertIn("login URL", guidance["requestedDetails"][0])
                self.assertIn("credentials.set_auth_profile", json.dumps(guidance))

    def test_scope_matching_supports_explicit_patterns_and_cidrs(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(
                    ["example.com"],
                    "test",
                    "Example Client",
                    patterns=["*.example.com", "exact:api.internal"],
                    cidrs=["10.10.10.0/24"],
                )

                self.assertTrue(scope.check_target("example.com")["inScope"])
                self.assertEqual(scope.check_target("https://api.example.com")["match"]["type"], "pattern")
                self.assertEqual(scope.check_target("api.internal")["match"]["type"], "exact")
                self.assertEqual(scope.check_target("10.10.10.42")["match"]["type"], "cidr")
                self.assertFalse(scope.check_target("other.test")["inScope"])

    def test_lifecycle_events_are_logged_for_scope_project_and_workspace(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                stdio_server.call_tool(
                    "project.start",
                    {
                        "organization": "Example Client",
                        "workspaceId": "example-engagement",
                        "hosts": ["example.com"],
                        "patterns": ["*.example.com"],
                    },
                )
                workspace.add_target("example-engagement", "api.example.com")

                event_types = [event["type"] for event in evidence.tail_events(20)]
                self.assertIn("scope.set", event_types)
                self.assertIn("project.start", event_types)
                self.assertIn("workspace.create", event_types)
                self.assertIn("workspace.add_target", event_types)

    def test_evidence_log_event_uses_workspace_organization_for_indexing(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("juice-shop-local", organization="OWASP Juice Shop Demo", hosts=["localhost"])
                result = evidence.log_event(
                    "demo.failure",
                    "Demo step failed",
                    {"workspaceId": "juice-shop-local", "target": "http://localhost:3000/login"},
                )

                indexed_paths = {Path(path).as_posix() for path in result["indexedPaths"]}
                self.assertTrue(any("/orgs/owasp-juice-shop-demo/hosts/localhost/events.jsonl" in path for path in indexed_paths))
                self.assertFalse(any("/orgs/unknown-org/" in path for path in indexed_paths))

    def test_evidence_log_event_redacts_common_secret_fields(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                self.assertEqual(credentials._redact_value("shortpass123"), "***")
                event = evidence.log_event(
                    "operator.note",
                    "Secret redaction test",
                    {
                        "Authorization": "Bearer secret-token",
                        "nested": {"apiKey": "abc123", "Cookie": "SESSIONID=abc"},
                        "safe": "visible",
                        "stdout": "GET / HTTP/1.1\nAuthorization: Bearer abc123XYZ\nSet-Cookie: SID=secret\npassword=swordfish",
                    },
                )["event"]

                self.assertEqual(event["data"]["Authorization"], "[REDACTED]")
                self.assertEqual(event["data"]["nested"]["apiKey"], "[REDACTED]")
                self.assertEqual(event["data"]["nested"]["Cookie"], "[REDACTED]")
                self.assertEqual(event["data"]["safe"], "visible")
                self.assertNotIn("abc123XYZ", event["data"]["stdout"])
                self.assertNotIn("swordfish", event["data"]["stdout"])
                stored = evidence.EVIDENCE_LOG.read_text(encoding="utf-8")
                self.assertNotIn("abc123XYZ", stored)
                self.assertNotIn("swordfish", stored)

    def test_evidence_tail_reads_recent_events(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                for index in range(5):
                    evidence.log_event("operator.note", f"Event {index}", {"index": index})

                tail = evidence.tail_events(3)
                self.assertEqual([event["summary"] for event in tail], ["Event 2", "Event 3", "Event 4"])

    def test_ingest_reports_scope_status_without_blocking(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                unset = workspace.ingest_data("engagement", "example.com", "operator_note", "note", "text", "passive note")
                self.assertEqual(unset["scopeStatus"], "scope_unset")
                self.assertTrue(unset["warnings"])

                scope.save_scope(["in.example"], "test", "Example Client")
                out = workspace.ingest_data("engagement", "out.example", "operator_note", "note", "text", "passive note")
                self.assertEqual(out["scopeStatus"], "out_of_scope")
                self.assertTrue(out["warnings"])

                inside = workspace.ingest_data("engagement", "in.example", "operator_note", "note", "text", "passive note")
                self.assertEqual(inside["scopeStatus"], "in_scope")
                self.assertEqual(inside["warnings"], [])

    def test_credentials_restrict_get_auth_and_validate_header_credentials(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test", "Example Client")

                with self.assertRaisesRegex(Exception, "GET authentication"):
                    credentials.save_auth_profile(
                        {
                            "id": "get-login",
                            "credentialId": "cookie",
                            "scopes": ["example.com"],
                            "loginUrl": "https://example.com/login",
                            "method": "GET",
                            "username": "alice",
                            "password": "secret",
                        }
                    )

                profile = credentials.save_auth_profile(
                    {
                        "id": "get-login",
                        "credentialId": "cookie",
                        "scopes": ["example.com"],
                        "loginUrl": "https://example.com/login",
                        "method": "GET",
                        "username": "alice",
                        "password": "secret",
                        "allowCredentialInUrl": True,
                    }
                )
                self.assertTrue(profile["authProfile"]["allowCredentialInUrl"])

                with self.assertRaisesRegex(Exception, "headerName"):
                    credentials.save_credential(
                        {
                            "id": "bad-header",
                            "type": "header",
                            "scopes": ["example.com"],
                            "headerName": "X-Test\r\nInjected",
                            "secret": "value",
                        }
                    )

                with self.assertRaisesRegex(Exception, "CR/LF"):
                    credentials.save_credential(
                        {
                            "id": "bad-header-value",
                            "type": "header",
                            "scopes": ["example.com"],
                            "headerName": "X-Test",
                            "secret": "value\r\nInjected: true",
                        }
                    )

    def test_dumps_list_discovers_workspace_dumps(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with isolated_state(tmp_path):
                dump_dir = workspace.target_path("engagement", "example.com") / "evidence" / "burp-dumps" / "export-1"
                dump_dir.mkdir(parents=True)
                (dump_dir / "history.jsonl").write_text('{"id":1,"host":"example.com"}\n', encoding="utf-8")
                (dump_dir / "manifest.json").write_text("{}", encoding="utf-8")

                listed = dumps.list_dumps()
                self.assertEqual(len(listed), 1)
                self.assertEqual(listed[0]["workspaceId"], "engagement")
                self.assertEqual(listed[0]["target"], "example.com")
                self.assertEqual(listed[0]["entryCount"], 1)

    def test_stdio_workspace_tool_dispatch_and_resource_read(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                created = json.loads(
                    stdio_server.call_tool(
                        "workspace.create",
                        {"workspaceId": "engagement", "organization": "Client", "hosts": ["example.com"]},
                    )
                )
                self.assertEqual(created["workspaceId"], "engagement")

                ingested = json.loads(
                    stdio_server.call_tool(
                        "workspace.ingest_data",
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "source": "operator_note",
                            "rawData": "Reviewed login flow with operator.",
                        },
                    )
                )
                self.assertEqual(ingested["entitiesCreated"]["actions"], 1)

                mime_type, resource_text = stdio_server.read_resource("synapse://workspace/engagement/target/example.com/actions")
                self.assertEqual(mime_type, "application/json")
                actions = json.loads(resource_text)
                self.assertEqual(actions[0]["type"], "operator_note")

    def test_stdio_tool_call_timeout_returns_error_and_recovers(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                def slow_call_tool(_name: str, _args: dict[str, object]) -> str:
                    time.sleep(0.2)
                    return "{}"

                with patch.object(stdio_server, "_tool_deadline_seconds", return_value=0.05), patch.object(
                    stdio_server,
                    "call_tool",
                    side_effect=slow_call_tool,
                ):
                    response = stdio_server.handle(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {"name": "test.slow", "arguments": {}},
                        }
                    )

                self.assertIsNotNone(response)
                self.assertEqual(response["error"]["code"], -32003)
                self.assertIn("server recovered", response["error"]["message"])

                recovered = stdio_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
                self.assertIsNotNone(recovered)
                self.assertIn("tools", recovered["result"])



if __name__ == "__main__":
    unittest.main()
