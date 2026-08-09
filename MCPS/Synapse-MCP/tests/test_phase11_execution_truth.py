from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from helpers import isolated_state, wait_for_job
from synapse_mcp.app.actions import (
    ActionEffects,
    ActionRequest,
    ActionRegistry,
    AuthorizationIntent,
    CanonicalTarget,
    ContinuationLineage,
    ExecutionContext,
    ExecutionPlan,
    ExecutionPlanError,
    Idempotency,
    ProviderRoute,
    RedirectPolicy,
    REGISTRY,
    ScopeSnapshot,
    TargetEnvelope,
    TargetSelector,
    ValidationFailure,
)
from synapse_mcp.app.actions.packs.crawler import CRAWLER_CRAWL
from synapse_mcp.core import background_jobs, evidence, job_worker, scope, workspace
from synapse_mcp.core.execution import write_planned_text
from synapse_mcp.core.http import HttpClientPolicy, HttpRequest, http_client


def _request(action_id: str, arguments: dict) -> ActionRequest:
    descriptor = REGISTRY.get(action_id)
    return ActionRequest(
        descriptor.input_model.model_validate(arguments),
        ExecutionContext(arguments.get("workspaceId"), "phase11-test", 45.0, arguments.get("confirm")),
    )


def _http_plan(
    urls: list[str],
    *,
    follow: bool = True,
    max_hops: int = 10,
    provider: ProviderRoute | None = None,
    methods: tuple[str, ...] = ("GET",),
) -> ExecutionPlan:
    targets = tuple(CanonicalTarget.from_url(url) for url in urls)
    snapshot = ScopeSnapshot.from_value({"hosts": sorted({target.host for target in targets})})
    envelope = TargetEnvelope(
        "fixture",
        snapshot.digest,
        snapshot,
        tuple(TargetSelector(target, "any", "test") for target in targets),
        targets[:1],
        False,
        RedirectPolicy(follow, max_hops),
    )
    intent = AuthorizationIntent(
        "fixture.http",
        "fixture",
        envelope,
        methods=methods,
        providers=(provider or ProviderRoute.from_values("direct", None),),
        lineage=ContinuationLineage(origin_action_id="fixture.http", origin_correlation_id="phase11-http"),
    )
    return ExecutionPlan.create(
        action_id="fixture.http",
        correlation_id="phase11-http",
        intent=intent,
        effects=ActionEffects(replay_safety=Idempotency.NON_IDEMPOTENT),
        arguments={"urls": urls},
    )


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


class HttpExecutionEnvelopeTests(unittest.TestCase):
    def test_relative_redirect_is_checked_and_allowed(self) -> None:
        seen: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                seen.append(self.path)
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", "/finish")
                else:
                    self.send_response(200)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        with _Server(Handler) as server:
            start = f"http://127.0.0.1:{server.port}/start"
            plan = _http_plan([start])
            response = http_client.send(
                HttpRequest(start),
                policy=HttpClientPolicy(execution_plan=plan),
            )
        self.assertEqual(response.status, 200)
        self.assertEqual(seen, ["/start", "/finish"])
        self.assertEqual(len(response.redirect_chain), 1)

    def test_cross_origin_redirect_requires_exact_envelope_and_strips_secrets(self) -> None:
        destination_headers: list[dict[str, str]] = []

        class Destination(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                destination_headers.append({name.lower(): value for name, value in self.headers.items()})
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        destination: _Server

        class Source(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{destination.port}/final")
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        with _Server(Destination) as destination, _Server(Source) as source:
            start = f"http://127.0.0.1:{source.port}/start"
            final = f"http://127.0.0.1:{destination.port}/final"
            allowed = _http_plan([start, final])
            response = http_client.send(
                HttpRequest(start, headers={"Authorization": "Bearer secret", "Cookie": "SID=secret"}),
                policy=HttpClientPolicy(execution_plan=allowed),
            )
        self.assertEqual(response.status, 200)
        self.assertEqual(len(destination_headers), 1)
        self.assertNotIn("authorization", destination_headers[0])
        self.assertNotIn("cookie", destination_headers[0])

    def test_unplanned_second_hop_is_rejected_before_connection(self) -> None:
        final_hits: list[str] = []

        class Final(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                final_hits.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        middle: _Server
        final: _Server

        class Start(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{middle.port}/middle")
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        class Middle(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{final.port}/forbidden")
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        with _Server(Final) as final, _Server(Middle) as middle, _Server(Start) as start_server:
            start = f"http://127.0.0.1:{start_server.port}/start"
            middle_url = f"http://127.0.0.1:{middle.port}/middle"
            response = http_client.send(
                HttpRequest(start),
                policy=HttpClientPolicy(execution_plan=_http_plan([start, middle_url])),
            )
        self.assertIsNone(response.status)
        self.assertIn("outside the execution target envelope", response.error)
        self.assertEqual(final_hits, [])

    def test_redirect_loop_and_hop_limit_fail_without_extra_hop(self) -> None:
        hits: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/b" if self.path == "/a" else "/a")
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        with _Server(Handler) as server:
            start = f"http://127.0.0.1:{server.port}/a"
            response = http_client.send(
                HttpRequest(start),
                policy=HttpClientPolicy(max_redirects=5, execution_plan=_http_plan([start], max_hops=5)),
            )
        self.assertIsNone(response.status)
        self.assertIn("loop", response.error.lower())
        self.assertEqual(hits, ["/a", "/b"])

    def test_redirect_userinfo_is_rejected_before_the_next_connection(self) -> None:
        hits: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", f"http://user:secret@127.0.0.1:{self.server.server_port}/forbidden")
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        with _Server(Handler) as server:
            start = f"http://127.0.0.1:{server.port}/start"
            response = http_client.send(
                HttpRequest(start),
                policy=HttpClientPolicy(execution_plan=_http_plan([start])),
            )
        self.assertIsNone(response.status)
        self.assertIn("userinfo", response.error)
        self.assertNotIn("secret", response.error)
        self.assertEqual(hits, ["/start"])

    def test_explicit_proxy_is_fixed_and_environment_proxy_is_ignored(self) -> None:
        proxy_hits: list[str] = []
        proxy_authorization: list[str] = []
        target_hits: list[str] = []

        class Proxy(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                proxy_hits.append(self.path)
                proxy_authorization.append(self.headers.get("Proxy-Authorization", ""))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        class Target(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                target_hits.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return

        with _Server(Proxy) as proxy, _Server(Target) as target:
            target_url = f"http://127.0.0.1:{target.port}/target"
            proxy_url = f"http://127.0.0.1:{proxy.port}"
            proxy_plan = _http_plan(
                [target_url],
                provider=ProviderRoute.from_values("proxy", proxy_url, "proxy-basic"),
            )
            proxied = http_client.send(
                HttpRequest(target_url),
                policy=HttpClientPolicy(
                    backend="proxy",
                    proxy_url=proxy_url,
                    execution_plan=proxy_plan,
                    proxy_credential_ref="proxy-basic",
                    proxy_headers={"Proxy-Authorization": "Basic secret-material"},
                ),
            )
            diverged = http_client.send(
                HttpRequest(target_url),
                policy=HttpClientPolicy(backend="direct", execution_plan=proxy_plan),
            )
            with patch.dict(
                os.environ,
                {"HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url, "NO_PROXY": ""},
                clear=False,
            ):
                direct = http_client.send(
                    HttpRequest(target_url),
                    policy=HttpClientPolicy(execution_plan=_http_plan([target_url])),
                )
        self.assertEqual(proxied.status, 200)
        self.assertIsNone(diverged.status)
        self.assertIn("backend/proxy differs", diverged.error)
        self.assertEqual(direct.status, 200)
        self.assertEqual(len(proxy_hits), 1)
        self.assertEqual(proxy_authorization, ["Basic secret-material"])
        self.assertEqual(target_hits, ["/target"])
        self.assertNotIn("secret-material", json.dumps(proxy_plan.to_dict()))
        with self.assertRaisesRegex(ExecutionPlanError, "proxyCredentialId"):
            ProviderRoute.from_values("proxy", "http://user:secret@127.0.0.1:8080")
        with self.assertRaisesRegex(ExecutionPlanError, "query or fragment"):
            ProviderRoute.from_values("proxy", "http://127.0.0.1:8080/?token=secret")


class IntentAndCrawlerPlanTests(unittest.TestCase):
    def test_registry_policy_and_executor_share_one_plan_and_post_policy_mutation_is_blocked(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with isolated_state(root):
                workspace.create_workspace("ws", hosts=["a.example", "b.example"])
                original_output = root / "approved.json"
                changed_output = root / "changed.json"

                class MutatingPolicy:
                    def evaluate(self, _descriptor, request, _effects):
                        self.plan = request.context.execution_plan
                        request.input.target = "https://b.example/changed"
                        request.input.output = str(changed_output)
                        return True

                class SpyExecutor:
                    input_model = CRAWLER_CRAWL.input_model
                    output_model = CRAWLER_CRAWL.output_model

                    def __call__(self, request):
                        self.plan = request.context.execution_plan
                        return CRAWLER_CRAWL.executor(request)

                policy = MutatingPolicy()
                executor = SpyExecutor()
                registry = ActionRegistry(policy_evaluator=policy)
                registry.register(replace(CRAWLER_CRAWL, executor=executor))
                arguments = {
                    "target": "https://a.example/start",
                    "workspaceId": "ws",
                    "output": str(original_output),
                    "allowExternalOutput": True,
                    "background": False,
                    "disableTraffic": True,
                    "confirm": True,
                }
                outcome = registry.execute("crawler.crawl", _request("crawler.crawl", arguments))
                self.assertIsInstance(outcome, ValidationFailure)
                self.assertEqual(outcome.reason_code, "runtime_input_diverged")
                self.assertIs(policy.plan, executor.plan)
                self.assertFalse(original_output.exists())
                self.assertFalse(changed_output.exists())

    def test_target_envelope_supports_exact_partial_and_explicit_entire_scope(self) -> None:
        snapshot = ScopeSnapshot.from_value({"hosts": ["a.example", "b.example"]})
        exact = TargetEnvelope(
            "ws",
            snapshot.digest,
            snapshot,
            (TargetSelector(CanonicalTarget.from_url("https://a.example/root"), "any"),),
            (CanonicalTarget.from_url("https://a.example/root"),),
        )
        self.assertTrue(exact.allows("https://a.example/next"))
        self.assertFalse(exact.allows("https://b.example/next"))
        self.assertFalse(exact.allows("http://a.example/next"))
        self.assertFalse(exact.allows("https://a.example:444/next"))
        self.assertEqual(
            CanonicalTarget.from_url("HTTPS://A.Example:443/a/../root"),
            CanonicalTarget.from_url("https://a.example/root"),
        )
        expanded = replace(exact, entire_workspace_scope=True, expansion_reasons=("operator_requested_scope",))
        self.assertTrue(expanded.allows("https://b.example/next"))
        changed = ScopeSnapshot.from_value({"hosts": ["a.example", "b.example", "c.example"]})
        self.assertNotEqual(snapshot.digest, changed.digest)

    def test_crawler_foreground_background_intents_and_effects_are_truthful(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with isolated_state(root):
                workspace.create_workspace("ws", hosts=["a.example", "b.example"])
                output = root / "explicit" / "crawl.json"
                common = {
                    "target": "https://a.example/start",
                    "workspaceId": "ws",
                    "includeInScopeHosts": False,
                    "output": str(output),
                    "allowExternalOutput": True,
                    "disableTraffic": True,
                    "confirm": True,
                }
                foreground_request = _request("crawler.crawl", {**common, "background": False})
                background_request = _request("crawler.crawl", {**common, "background": True})
                foreground = REGISTRY.resolve_execution_plan("crawler.crawl", foreground_request)
                background = REGISTRY.resolve_execution_plan("crawler.crawl", background_request)
                self.assertEqual(foreground.intent.target_envelope, background.intent.target_envelope)
                self.assertEqual(foreground.intent.local_outputs[:3], background.intent.local_outputs[:3])
                self.assertEqual(
                    {item.purpose for item in background.intent.local_outputs[3:]},
                    {"crawler.worker_args", "crawler.worker_result", "crawler.worker_state", "crawler.worker_plan"},
                )
                self.assertFalse(foreground.intent.target_envelope.entire_workspace_scope)
                self.assertNotIn("jobs", foreground.effects.local_writes)
                self.assertIn("jobs", background.effects.local_writes)
                self.assertIn("workspace", background.effects.local_writes)
                self.assertTrue(background.effects.local_destruction)

                expanded = REGISTRY.resolve_execution_plan(
                    "crawler.crawl",
                    _request("crawler.crawl", {**common, "includeInScopeHosts": True, "background": False}),
                )
                self.assertTrue(expanded.intent.target_envelope.entire_workspace_scope)
                self.assertIn("crawler_include_in_scope_hosts", expanded.intent.target_envelope.expansion_reasons)

    def test_external_output_is_exact_and_symlink_substitution_cannot_redirect_write(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with isolated_state(root):
                workspace.create_workspace("ws", hosts=["a.example"])
                real_a = root / "a" / "crawl.json"
                real_b = root / "b" / "crawl.json"
                real_a.parent.mkdir()
                real_b.parent.mkdir()
                requested = root / "chosen.json"
                requested.symlink_to(real_a)
                args = {
                    "target": "https://a.example/",
                    "workspaceId": "ws",
                    "output": str(requested),
                    "allowExternalOutput": True,
                    "background": False,
                    "disableTraffic": True,
                    "confirm": True,
                }
                plan = REGISTRY.resolve_execution_plan("crawler.crawl", _request("crawler.crawl", args))
                self.assertEqual(plan.output("crawler.sitemap").path, str(real_a))
                requested.unlink()
                requested.symlink_to(real_b)
                write_planned_text(plan, "crawler.sitemap", "planned")
                self.assertEqual(real_a.read_text(encoding="utf-8"), "planned")
                self.assertFalse(real_b.exists())

                mutated = {**args, "output": str(real_b)}
                with self.assertRaisesRegex(ExecutionPlanError, "differs"):
                    plan.assert_runtime_input(mutated)

                direct = root / "direct.json"
                direct_args = {**args, "output": str(direct)}
                direct_plan = REGISTRY.resolve_execution_plan("crawler.crawl", _request("crawler.crawl", direct_args))
                direct.symlink_to(real_b)
                with self.assertRaisesRegex(ExecutionPlanError, "symlink"):
                    write_planned_text(direct_plan, "crawler.sitemap", "blocked")
                self.assertFalse(real_b.exists())

    def test_output_creation_and_overwrite_are_distinguished_before_dispatch(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with isolated_state(root):
                workspace.create_workspace("ws", hosts=["a.example"])
                output = root / "outside.json"
                args = {
                    "target": "https://a.example/",
                    "workspaceId": "ws",
                    "output": str(output),
                    "allowExternalOutput": True,
                    "background": False,
                    "disableTraffic": True,
                    "confirm": True,
                }
                create = REGISTRY.resolve_execution_plan("crawler.crawl", _request("crawler.crawl", args))
                self.assertEqual(create.output("crawler.sitemap").disposition, "create")
                self.assertFalse(create.effects.local_destruction)
                output.write_text("old", encoding="utf-8")
                overwrite = REGISTRY.resolve_execution_plan("crawler.crawl", _request("crawler.crawl", args))
                self.assertEqual(overwrite.output("crawler.sitemap").disposition, "overwrite")
                self.assertTrue(overwrite.effects.local_destruction)

    def test_background_worker_rejects_mutated_target_and_output_before_running(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with isolated_state(root):
                workspace.create_workspace("ws", hosts=["a.example", "b.example"])
                args = {
                    "target": "https://a.example/",
                    "workspaceId": "ws",
                    "output": str(root / "approved.json"),
                    "allowExternalOutput": True,
                    "background": True,
                    "disableTraffic": True,
                    "confirm": True,
                }
                request = _request("crawler.crawl", args)
                parent = REGISTRY.resolve_execution_plan("crawler.crawl", request)
                worker_args = request.input.model_dump(by_alias=True, exclude_unset=True)
                worker_args["background"] = False
                worker_args["_deferWorkflowRefreshToFinalizer"] = True
                worker_plan = parent.for_continuation(kind="background_worker", runtime_arguments=worker_args)
                plan_path = root / "worker-plan.json"
                plan_path.write_text(json.dumps(worker_plan.to_dict()), encoding="utf-8")
                mutated = {**worker_args, "target": "https://b.example/", "output": str(root / "changed.json")}
                with self.assertRaisesRegex(ExecutionPlanError, "differs"):
                    job_worker._run_tool_with_plan("crawler.crawl", mutated, str(plan_path))
                self.assertFalse((root / "approved.json").exists())
                self.assertFalse((root / "changed.json").exists())


class JobContinuationTests(unittest.TestCase):
    def test_snapshot_is_observational_while_status_has_continuation_effects(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("ws", hosts=["a.example"])
                started = background_jobs.start_command(
                    ["sh", "-c", "sleep 0.15"],
                    timeout_seconds=30,
                    event_type="unit.snapshot",
                    summary="snapshot job",
                    tool="unit.snapshot",
                    workspace_id="ws",
                    target="a.example",
                )
                record_path = background_jobs._find_record_path(started["jobId"])
                assert record_path is not None
                before = record_path.read_bytes()
                first = background_jobs.snapshot(started["jobId"])
                second = background_jobs.snapshot(started["jobId"])
                self.assertEqual(first, second)
                self.assertEqual(record_path.read_bytes(), before)
                effects = REGISTRY.resolve_effects("jobs.status", _request("jobs.status", {"jobId": started["jobId"]}))
                self.assertIn("jobs", {str(item) for item in effects.local_writes})
                wait_for_job(started["jobId"])
                clean_effects = REGISTRY.resolve_effects("jobs.status", _request("jobs.status", {"jobId": started["jobId"]}))
                self.assertEqual(clean_effects.replay_safety, Idempotency.PURE_READ)

    def test_finalizer_cannot_expand_creation_time_effects(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("ws", hosts=["a.example"])
                calls = 0

                def finalizer(_record, _run, _data):
                    nonlocal calls
                    calls += 1
                    return {"summary": {"calls": calls}}

                name = "unit.phase11-finalizer"
                background_jobs.register_finalizer(name, finalizer)
                try:
                    started = background_jobs.start_command(
                        ["sh", "-c", "sleep 0.1"],
                        timeout_seconds=30,
                        event_type="unit.phase11",
                        summary="continuation bound",
                        tool="unit.phase11",
                        workspace_id="ws",
                        target="a.example",
                        finalizer_name=name,
                    )
                    record_path = background_jobs._find_record_path(started["jobId"])
                    assert record_path is not None
                    record = json.loads(record_path.read_text(encoding="utf-8"))
                    record["finalizerEffects"]["credentialUse"] = True
                    record_path.write_text(json.dumps(record), encoding="utf-8")
                    terminal = wait_for_job(started["jobId"])
                    self.assertEqual(terminal["status"], "failed")
                    self.assertIn("finalizer_effects_exceeded", terminal["error"])
                    self.assertEqual(calls, 0)
                finally:
                    background_jobs._FINALIZERS.pop(name, None)

    def test_mutated_continuation_target_and_cleanup_path_are_rejected_before_effect(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with isolated_state(root):
                workspace.create_workspace("ws", hosts=["a.example", "b.example"])
                allowed_cleanup = root / "allowed-args.json"
                protected = root / "protected.json"
                allowed_cleanup.write_text("allowed", encoding="utf-8")
                protected.write_text("protected", encoding="utf-8")
                calls = 0

                def finalizer(_record, _run, _data):
                    nonlocal calls
                    calls += 1
                    return {"summary": {"calls": calls}}

                name = "unit.phase11-binding"
                background_jobs.register_finalizer(name, finalizer)
                try:
                    started = background_jobs.start_command(
                        ["sh", "-c", "sleep 0.1"],
                        timeout_seconds=30,
                        event_type="unit.phase11.binding",
                        summary="continuation metadata bound",
                        tool="unit.phase11.binding",
                        workspace_id="ws",
                        target="a.example",
                        finalizer_name=name,
                        finalizer_data={"cleanupArgsPath": str(allowed_cleanup)},
                    )
                    record_path = background_jobs._find_record_path(started["jobId"])
                    assert record_path is not None
                    record = json.loads(record_path.read_text(encoding="utf-8"))
                    record["target"] = "https://a.example/changed"
                    record["finalizerData"]["cleanupArgsPath"] = str(protected)
                    record_path.write_text(json.dumps(record), encoding="utf-8")
                    terminal = wait_for_job(started["jobId"])
                    self.assertEqual(terminal["status"], "failed")
                    self.assertIn("continuation_binding_diverged", terminal["error"])
                    self.assertEqual(calls, 0)
                    self.assertEqual(protected.read_text(encoding="utf-8"), "protected")
                    self.assertEqual(allowed_cleanup.read_text(encoding="utf-8"), "allowed")
                finally:
                    background_jobs._FINALIZERS.pop(name, None)

    def test_background_crawler_preserves_plan_lineage_and_finalizes_once(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with isolated_state(root):
                workspace.create_workspace("ws", hosts=["a.example"])
                args = {
                    "target": "https://a.example/",
                    "workspaceId": "ws",
                    "background": True,
                    "disableTraffic": True,
                    "maxPages": 1,
                    "confirm": True,
                }
                outcome = REGISTRY.execute("crawler.crawl", _request("crawler.crawl", args))
                job_id = outcome.payload.job["jobId"]
                terminal = wait_for_job(str(job_id))
                self.assertTrue(terminal["finalized"])
                record = background_jobs.snapshot_record(str(job_id))
                plan = ExecutionPlan.from_dict(record["executionPlan"])
                self.assertEqual(plan.intent.lineage.origin_action_id, "crawler.crawl")
                self.assertEqual(plan.intent.lineage.kind, "background_worker")
                self.assertEqual(plan.intent.lineage.job_id, str(job_id))
                self.assertEqual(plan.intent.lineage.handler, "worker.result")
                self.assertEqual(plan.intent.workspace_id, "ws")
                status_plan = REGISTRY.resolve_execution_plan("jobs.status", _request("jobs.status", {"jobId": str(job_id)}))
                self.assertEqual(status_plan.intent.lineage.origin_action_id, "crawler.crawl")
                self.assertEqual(status_plan.intent.lineage.job_id, str(job_id))
                before = len(evidence.tail_events(500))
                first = background_jobs.status(str(job_id), include_result=True)
                second = background_jobs.status(str(job_id), include_result=True)
                after = len(evidence.tail_events(500))
                self.assertEqual(first["result"], second["result"])
                self.assertEqual(before, after)
                for key in ("cleanupArgsPath", "cleanupStatePath", "cleanupPlanPath"):
                    path = record["finalizerData"].get(key)
                    if path:
                        self.assertFalse(Path(path).exists())


if __name__ == "__main__":
    unittest.main()
