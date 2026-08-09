# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any


def _run_tool(tool: str, args: dict[str, Any]) -> str:
    if tool == "crawler.crawl":
        from ..adapters.web import crawler_adapter

        return crawler_adapter.crawl(args)
    if tool == "crawler.extended":
        from ..adapters.web import crawler_adapter

        return crawler_adapter.crawl_extended(args)
    if tool == "credentials.browser_authenticate":
        from . import credentials

        return json.dumps(credentials.browser_authenticate(args), indent=2)
    if tool == "js.analyze_static":
        from ..adapters.web import js_intel

        return js_intel.analyze_static(args)
    if tool == "js.normalize_endpoints":
        from ..adapters.web import js_intel

        return js_intel.normalize_endpoints(args)
    raise ValueError(f"Unsupported worker tool: {tool}")


def _run_tool_with_plan(tool: str, args: dict[str, Any], plan_path: str) -> str:
    if not plan_path:
        return _run_tool(tool, args)
    from .execution import ExecutionPlan

    plan = ExecutionPlan.from_dict(json.loads(Path(plan_path).read_text(encoding="utf-8")))
    plan.assert_runtime_input(args)
    if tool == "crawler.crawl":
        from ..adapters.web import crawler_adapter

        return crawler_adapter.crawl(args, execution_plan=plan)
    raise ValueError(f"Execution plans are not supported for worker tool: {tool}")


def _apply_state_paths(path: str) -> None:
    if not path:
        return
    state = json.loads(Path(path).read_text(encoding="utf-8"))
    from . import credentials, dumps, evidence, scope, workspace

    if state.get("workspacesDir"):
        workspace.WORKSPACES_DIR = Path(state["workspacesDir"])
    if state.get("dumpDir"):
        dumps.DUMP_DIR = Path(state["dumpDir"])
    if state.get("scopeFile"):
        scope.SCOPE_FILE = Path(state["scopeFile"])
    if state.get("credentialsFile"):
        credentials.CREDENTIALS_FILE = Path(state["credentialsFile"])
    if state.get("evidenceDir"):
        evidence.EVIDENCE_DIR = Path(state["evidenceDir"])
    if state.get("evidenceLog"):
        evidence.EVIDENCE_LOG = Path(state["evidenceLog"])
    if state.get("orgsDir"):
        evidence.ORGS_DIR = Path(state["orgsDir"])


def _write_result_atomic(result_path: Path, text: str) -> None:
    tmp = result_path.with_name(f".{result_path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(result_path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an internal Synapse job worker.")
    parser.add_argument("--tool", required=True)
    parser.add_argument("--args", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--state", default="")
    parser.add_argument("--plan", default="")
    parsed = parser.parse_args()
    result_path = Path(parsed.result)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        _apply_state_paths(parsed.state)
        args = json.loads(Path(parsed.args).read_text(encoding="utf-8"))
        result_text = _run_tool_with_plan(parsed.tool, args, parsed.plan)
        _write_result_atomic(result_path, result_text)
        return 0
    except Exception as exc:  # pragma: no cover - exercised through subprocess failures.
        _write_result_atomic(
            result_path,
            json.dumps(
                {
                    "isError": True,
                    "error": f"{type(exc).__name__}: {exc}",
                    "traceback": traceback.format_exc(limit=8),
                },
                indent=2,
            ),
        )
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
