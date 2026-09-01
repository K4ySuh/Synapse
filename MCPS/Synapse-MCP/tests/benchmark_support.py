"""Deterministic in-process workflow benchmarks for the legacy MCP server.

These benchmarks measure local server behavior only. Agent benchmarks and
live-client compatibility runs are intentionally out of scope and must not be
added to CI through this module.

Call counts cover MCP dispatches in the measured workflow after deterministic
workspace seeding; the common setup calls and direct ``wait_for_job`` polling
used by the harness are not included.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
from typing import Any, Callable, Iterator, TypeVar
from unittest.mock import patch

from helpers import isolated_state, wait_for_job
from synapse_mcp.transport import stdio_server


WORKSPACE_ID = "benchmark"
TARGET = "app.acme-demo.test"
CONTEXT_BUDGETS = (100, 400, 1500, 6000, 20000)
TERMINAL_JOB_STATUSES = frozenset({"completed", "timed_out", "failed", "canceled"})
WORKFLOW_NAMES = (
    "01_open_workspace_and_summarize",
    "02_prepare_target_context_under_budget",
    "03_passive_headers_cookies_analysis",
    "04_disabled_traffic_cors_probe",
    "05_background_submit_and_inspect",
    "06_resume_after_simulated_timeout_without_duplicating_work",
    "07_render_report_from_fixture_workspace",
)
INGEST_SHAPE = "sitemap JSON with hosts[].urls[]"

_T = TypeVar("_T")


@dataclass(frozen=True)
class ToolResult:
    payload: dict[str, Any]
    text: str
    response: dict[str, Any]


@dataclass(frozen=True)
class SeededWorkspace:
    root: Path
    workspace_id: str
    target: str
    ingest_shape: str
    summary: dict[str, Any]


def timed_call(operation: Callable[[], _T]) -> tuple[_T, float]:
    """Return an operation's value and wall-clock duration in milliseconds."""

    started = time.perf_counter()
    value = operation()
    return value, (time.perf_counter() - started) * 1000


def dispatch_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = stdio_server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    if response is None:
        raise AssertionError(f"{name} unexpectedly returned no response")
    return response


def call_tool(name: str, arguments: dict[str, Any]) -> ToolResult:
    response = dispatch_tool(name, arguments)
    if "error" in response:
        raise AssertionError(f"{name} failed during benchmark: {response['error']}")
    try:
        text = response["result"]["content"][0]["text"]
        payload = json.loads(text)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise AssertionError(f"{name} returned an invalid MCP tool result") from exc
    if not isinstance(payload, dict):
        raise AssertionError(f"{name} benchmark payload must be a JSON object")
    return ToolResult(payload=payload, text=text, response=response)


def _seed_sitemap() -> str:
    return json.dumps(
        {
            "hosts": [
                {
                    "host": TARGET,
                    "urls": [
                        {
                            "url": f"https://{TARGET}/app?view=summary",
                            "methods": ["GET"],
                            "statusCodes": [200],
                            "queryParameters": ["view"],
                            "responseHeaders": {"content-type": "text/html"},
                            "responseCookieFlags": [
                                {
                                    "name": "sessionid",
                                    "httpOnly": False,
                                    "secure": False,
                                    "sameSite": "",
                                }
                            ],
                        },
                        {
                            "url": f"https://{TARGET}/api/items",
                            "methods": ["POST"],
                            "statusCodes": [200],
                            "requestContentTypes": ["application/json"],
                            "responseHeaders": {
                                "content-type": "application/json"
                            },
                        },
                    ],
                }
            ],
            "summary": {"hostCount": 1, "urlCount": 2, "formCount": 0},
        },
        separators=(",", ":"),
    )


def seed_benchmark_workspace() -> dict[str, Any]:
    """Build and verify the deterministic populated workspace used by the corpus."""

    call_tool(
        "scope.set",
        {"hosts": [TARGET], "organization": "Acme Demo"},
    )
    call_tool(
        "workspace.create",
        {"workspaceId": WORKSPACE_ID, "organization": "Acme Demo"},
    )
    call_tool(
        "workspace.add_target",
        {"workspaceId": WORKSPACE_ID, "target": TARGET},
    )
    ingestion = call_tool(
        "workspace.ingest_data",
        {
            "workspaceId": WORKSPACE_ID,
            "target": TARGET,
            "source": "sitemap",
            "dataType": "tool_output",
            "format": "json",
            "rawData": _seed_sitemap(),
        },
    ).payload
    summary = call_tool(
        "workspace.summary",
        {"workspaceId": WORKSPACE_ID},
    ).payload
    entity_totals = summary.get("entityTotals")
    if not isinstance(entity_totals, dict):
        raise AssertionError("workspace.summary did not return entityTotals")
    if int(entity_totals.get("endpoints", 0) or 0) <= 0:
        raise AssertionError(
            f"{INGEST_SHAPE} did not populate workspace endpoints: {entity_totals}"
        )
    if sum(
        int(value or 0)
        for value in entity_totals.values()
        if isinstance(value, (int, float))
    ) <= 0:
        raise AssertionError(
            f"{INGEST_SHAPE} produced an empty workspace: {entity_totals}"
        )
    return {
        "ingestShape": INGEST_SHAPE,
        "ingestion": ingestion,
        "summary": summary,
    }


@contextmanager
def isolated_benchmark_workspace() -> Iterator[SeededWorkspace]:
    """Yield a freshly seeded workspace under an isolated temporary root."""

    with TemporaryDirectory(prefix="synapse-benchmark-") as temporary_root:
        root = Path(temporary_root)
        with patch.dict(os.environ, {"SYNAPSE_ROOT": str(root)}, clear=False):
            with isolated_state(root):
                seed = seed_benchmark_workspace()
                yield SeededWorkspace(
                    root=root,
                    workspace_id=WORKSPACE_ID,
                    target=TARGET,
                    ingest_shape=seed["ingestShape"],
                    summary=seed["summary"],
                )


def _metric(
    name: str,
    wall_clock_ms: float,
    call_count: int,
    **measurements: Any,
) -> dict[str, Any]:
    return {
        "name": name,
        "wallClockMs": round(wall_clock_ms, 3),
        "callCount": call_count,
        **measurements,
    }


def workflow_01_open_workspace_and_summarize() -> dict[str, Any]:
    with isolated_benchmark_workspace() as seeded:
        result, elapsed = timed_call(
            lambda: call_tool(
                "workspace.summary",
                {"workspaceId": seeded.workspace_id},
            )
        )
        expected = seeded.summary
        if result.payload.get("targetCount") != expected.get("targetCount"):
            raise AssertionError("workspace target count changed after seeding")
        if result.payload.get("entityTotals") != expected.get("entityTotals"):
            raise AssertionError("workspace entity totals changed after seeding")
        return _metric(
            WORKFLOW_NAMES[0],
            elapsed,
            1,
            targetCount=result.payload["targetCount"],
            entityTotals=result.payload["entityTotals"],
            ingestShape=seeded.ingest_shape,
        )


def _field_paths_with_budget_markers(value: Any) -> list[str]:
    fields: list[str] = []

    def walk(item: Any, path: str = "") -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                next_path = f"{path}.{key}" if path else str(key)
                lowered = str(key).lower()
                if any(marker in lowered for marker in ("trunc", "omission", "omit", "gap")):
                    fields.append(next_path)
                walk(nested, next_path)
        elif isinstance(item, list):
            for index, nested in enumerate(item):
                walk(nested, f"{path}[{index}]")

    walk(value)
    return sorted(set(fields))


def workflow_02_prepare_target_context_under_budget() -> dict[str, Any]:
    with isolated_benchmark_workspace() as seeded:
        measurements: list[dict[str, Any]] = []

        def measure_all_budgets() -> None:
            for budget in CONTEXT_BUDGETS:
                result = call_tool(
                    "workspace.prepare_target_context",
                    {
                        "workspaceId": seeded.workspace_id,
                        "target": seeded.target,
                        "maxTokens": budget,
                    },
                )
                if result.payload.get("maxTokens") != budget:
                    raise AssertionError(
                        f"prepare_target_context did not echo maxTokens={budget}"
                    )
                response_characters = len(result.text)
                estimated_tokens = response_characters / 4
                measurements.append(
                    {
                        "maxTokens": budget,
                        "responseCharacters": response_characters,
                        "estimatedTokens": round(estimated_tokens, 3),
                        "estimatedToBudgetRatio": round(
                            estimated_tokens / budget,
                            6,
                        ),
                        "truncationOrOmissionFields": (
                            _field_paths_with_budget_markers(result.payload)
                        ),
                    }
                )

        _, elapsed = timed_call(measure_all_budgets)
        entity_totals = seeded.summary["entityTotals"]
        if int(entity_totals.get("endpoints", 0) or 0) <= 0:
            raise AssertionError("context budget benchmark received an empty workspace")
        return _metric(
            WORKFLOW_NAMES[1],
            elapsed,
            len(CONTEXT_BUDGETS),
            estimator="response characters / 4",
            ingestShape=seeded.ingest_shape,
            entityTotals=entity_totals,
            budgets=measurements,
        )


def workflow_03_passive_headers_cookies_analysis() -> dict[str, Any]:
    with isolated_benchmark_workspace() as seeded:
        result, elapsed = timed_call(
            lambda: call_tool(
                "headers_cookies.analyze_workspace",
                {
                    "workspaceId": seeded.workspace_id,
                    "target": seeded.target,
                    "ingest": False,
                },
            )
        )
        candidates = result.payload.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise AssertionError("headers/cookies benchmark produced empty analysis")
        if result.payload.get("mode") != "passive_analysis":
            raise AssertionError("headers/cookies benchmark was not passive analysis")
        return _metric(
            WORKFLOW_NAMES[2],
            elapsed,
            1,
            candidateCount=len(candidates),
            mode=result.payload["mode"],
        )


def workflow_04_disabled_traffic_cors_probe() -> dict[str, Any]:
    with isolated_benchmark_workspace() as seeded:
        target_url = f"http://{seeded.target}/api"

        def plan_and_execute() -> tuple[ToolResult, ToolResult]:
            plan = call_tool(
                "cors.generate_test_plan",
                {"url": target_url, "method": "GET"},
            )
            executed = call_tool(
                "cors.execute_test",
                {
                    "workspaceId": seeded.workspace_id,
                    "url": plan.payload["target"],
                    "method": plan.payload["method"],
                    "probeOrigin": plan.payload["probeOrigin"],
                    "disableTraffic": True,
                    "confirm": True,
                    "approvalReason": (
                        "P0-3 deterministic benchmark with traffic disabled"
                    ),
                    "riskTier": "low",
                },
            )
            return plan, executed

        (plan, executed), elapsed = timed_call(plan_and_execute)
        if plan.payload.get("sendsTraffic") is not False:
            raise AssertionError("CORS plan unexpectedly reports sending traffic")
        test = executed.payload.get("test")
        if not isinstance(test, dict):
            raise AssertionError("CORS execution did not return test details")
        response = test.get("response")
        if not isinstance(response, dict) or response.get("status") is not None:
            raise AssertionError("disabled-traffic CORS probe returned an HTTP status")
        return _metric(
            WORKFLOW_NAMES[3],
            elapsed,
            2,
            planSendsTraffic=plan.payload["sendsTraffic"],
            responseStatus=response["status"],
            assessment=test.get("assessment", ""),
        )


def _background_crawl_arguments(seeded: SeededWorkspace) -> dict[str, Any]:
    return {
        "target": f"http://{seeded.target}",
        "workspaceId": seeded.workspace_id,
        "background": True,
        "disableTraffic": True,
        "maxPages": 1,
        "maxDepth": 0,
        "analyzeScripts": False,
        "followGetForms": False,
        "delayMillis": 0,
        "confirm": True,
        "approvalReason": "P0-3 deterministic disabled-traffic crawl benchmark",
        "riskTier": "low",
    }


def _submitted_job(result: ToolResult) -> tuple[str, str]:
    job = result.payload.get("job")
    if not isinstance(job, dict):
        raise AssertionError("crawler submission did not return result.job")
    job_id = str(job.get("jobId", ""))
    status = str(job.get("status", ""))
    if not job_id:
        raise AssertionError("crawler submission returned an empty jobId")
    if status not in {"running", "completed"}:
        raise AssertionError(f"crawler submission returned unexpected status {status!r}")
    return job_id, status


def workflow_05_background_submit_and_inspect() -> dict[str, Any]:
    with isolated_benchmark_workspace() as seeded:
        workflow_started = time.perf_counter()
        submission, submit_elapsed = timed_call(
            lambda: call_tool(
                "crawler.crawl",
                _background_crawl_arguments(seeded),
            )
        )
        job_id, submitted_status = _submitted_job(submission)
        terminal = wait_for_job(
            job_id,
            timeout_seconds=60,
            require_runtime_quiescent=True,
        )
        time_to_terminal_ms = (time.perf_counter() - workflow_started) * 1000
        if str(terminal.get("status", "")) not in TERMINAL_JOB_STATUSES:
            raise AssertionError(f"crawler job did not reach terminal state: {terminal}")
        if terminal.get("finalized") is not True:
            raise AssertionError("crawler job reached terminal state without finalizing")
        inspected = call_tool(
            "jobs.status",
            {"jobId": job_id, "includeResult": True},
        ).payload
        if "result" not in inspected:
            raise AssertionError("jobs.status(includeResult=true) omitted result")
        active = call_tool(
            "jobs.list",
            {"activeOnly": True},
        ).payload
        if active != {"jobs": [], "count": 0}:
            raise AssertionError(f"active jobs remained after terminal state: {active}")
        workflow_elapsed_ms = (time.perf_counter() - workflow_started) * 1000
        return _metric(
            WORKFLOW_NAMES[4],
            workflow_elapsed_ms,
            3,
            submitLatencyMs=round(submit_elapsed, 3),
            timeToTerminalMs=round(time_to_terminal_ms, 3),
            submittedStatus=submitted_status,
            terminalStatus=terminal["status"],
            finalized=terminal["finalized"],
            resultPresent=True,
            activeJobCount=active["count"],
        )


def workflow_06_resume_after_simulated_timeout_without_duplicating_work() -> dict[str, Any]:
    with isolated_benchmark_workspace() as seeded:
        started = time.perf_counter()
        submission = call_tool(
            "crawler.crawl",
            _background_crawl_arguments(seeded),
        )
        job_id, _ = _submitted_job(submission)
        jobs_before = call_tool(
            "jobs.list",
            {"workspaceId": seeded.workspace_id},
        ).payload
        count_before = int(jobs_before.get("count", -1))
        if count_before <= 0:
            raise AssertionError("submitted background job was not listed")

        real_call_tool = stdio_server.call_tool
        timed_out_call_finished = threading.Event()

        def delayed_call_tool(name: str, arguments: dict[str, Any]) -> str:
            try:
                if name == "workspace.summary":
                    time.sleep(0.05)
                return real_call_tool(name, arguments)
            finally:
                timed_out_call_finished.set()

        with patch.object(
            stdio_server,
            "_tool_deadline_seconds",
            return_value=0.001,
        ), patch.object(
            stdio_server,
            "call_tool",
            side_effect=delayed_call_tool,
        ):
            timeout_response = dispatch_tool(
                "workspace.summary",
                {"workspaceId": seeded.workspace_id},
            )
        try:
            timeout_code = timeout_response["error"]["code"]
        except (KeyError, TypeError) as exc:
            raise AssertionError(
                f"simulated timeout returned no JSON-RPC error: {timeout_response}"
            ) from exc
        if timeout_code != -32003:
            raise AssertionError(
                f"simulated timeout returned {timeout_code}, expected -32003"
            )

        recovery_active = call_tool(
            "jobs.list",
            {"activeOnly": True, "workspaceId": seeded.workspace_id},
        ).payload
        recovered = call_tool(
            "jobs.status",
            {"jobId": job_id},
        ).payload
        if recovered.get("jobId") != job_id:
            raise AssertionError("timeout recovery did not rediscover the original job")
        active_job_ids = {
            str(job.get("jobId", ""))
            for job in recovery_active.get("jobs", [])
            if isinstance(job, dict)
        }
        if active_job_ids - {job_id}:
            raise AssertionError(
                f"timeout recovery discovered unexpected active jobs: {active_job_ids}"
            )

        terminal = wait_for_job(
            job_id,
            timeout_seconds=60,
            require_runtime_quiescent=True,
        )
        if str(terminal.get("status", "")) not in TERMINAL_JOB_STATUSES:
            raise AssertionError(f"recovered job did not reach terminal state: {terminal}")
        if terminal.get("finalized") is not True:
            raise AssertionError("recovered job did not finalize")
        jobs_after = call_tool(
            "jobs.list",
            {"workspaceId": seeded.workspace_id},
        ).payload
        count_after = int(jobs_after.get("count", -1))
        if count_after != count_before:
            observed_jobs = [
                {
                    "jobId": str(job.get("jobId", "")),
                    "tool": str(job.get("tool", "")),
                    "workspaceId": str(job.get("workspaceId", "")),
                    "status": str(job.get("status", "")),
                }
                for job in jobs_after.get("jobs", [])
                if isinstance(job, dict)
            ]
            raise AssertionError(
                f"job count changed during timeout recovery: "
                f"{count_before} -> {count_after}; observed={observed_jobs}"
            )
        matching_jobs = [
            job
            for job in jobs_after.get("jobs", [])
            if isinstance(job, dict) and job.get("jobId") == job_id
        ]
        if len(matching_jobs) != 1:
            raise AssertionError(
                f"expected exactly one record for original job {job_id!r}"
            )
        if not timed_out_call_finished.wait(timeout=1):
            raise AssertionError("timed-out tool worker did not quiesce before benchmark state release")
        elapsed = (time.perf_counter() - started) * 1000
        return _metric(
            WORKFLOW_NAMES[5],
            elapsed,
            6,
            timeoutCode=timeout_code,
            originalJobIdRecovered=True,
            jobCountBefore=count_before,
            jobCountAfter=count_after,
            terminalStatus=terminal["status"],
            finalized=terminal["finalized"],
        )


def workflow_07_render_report_from_fixture_workspace() -> dict[str, Any]:
    with isolated_benchmark_workspace() as seeded:
        result, elapsed = timed_call(
            lambda: call_tool(
                "documentation.render_workspace_report",
                {
                    "workspaceId": seeded.workspace_id,
                    "outputPath": "reports/benchmark-workspace.html",
                },
            )
        )
        output_path = Path(str(result.payload.get("path", ""))).resolve()
        root = seeded.root.resolve()
        if not output_path.is_file():
            raise AssertionError("workspace report was not written")
        if not output_path.is_relative_to(root):
            raise AssertionError(
                f"workspace report escaped isolated root: {output_path}"
            )
        return _metric(
            WORKFLOW_NAMES[6],
            elapsed,
            1,
            format=result.payload.get("format", ""),
            outputBytes=result.payload.get("bytes", 0),
            outputInsideIsolatedRoot=True,
        )


WORKFLOW_RUNNERS: tuple[Callable[[], dict[str, Any]], ...] = (
    workflow_01_open_workspace_and_summarize,
    workflow_02_prepare_target_context_under_budget,
    workflow_03_passive_headers_cookies_analysis,
    workflow_04_disabled_traffic_cors_probe,
    workflow_05_background_submit_and_inspect,
    workflow_06_resume_after_simulated_timeout_without_duplicating_work,
    workflow_07_render_report_from_fixture_workspace,
)


def _print_metrics_table(metrics: list[dict[str, Any]], output_path: Path) -> None:
    print("workflow                                                     calls    wall_ms")
    print("--------------------------------------------------------------------------")
    for metric in metrics:
        print(
            f"{metric['name']:<60} "
            f"{metric['callCount']:>5} "
            f"{metric['wallClockMs']:>10.3f}"
        )
    print(f"metrics: {output_path}")


def run_workflow_corpus(
    output_directory: Path,
    *,
    print_table: bool = True,
) -> dict[str, Any]:
    """Run all seven workflows, write temporary metrics JSON, and return it."""

    metrics = [runner() for runner in WORKFLOW_RUNNERS]
    output_directory = output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    output_path = output_directory / "workflow-benchmarks.json"
    document = {
        "estimator": "response characters / 4",
        "workflows": metrics,
    }
    output_path.write_text(
        json.dumps(document, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    if print_table:
        _print_metrics_table(metrics, output_path)
    return {
        "metrics": metrics,
        "metricsPath": str(output_path),
    }
