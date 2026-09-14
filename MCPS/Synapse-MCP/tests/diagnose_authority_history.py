"""Local-only SQL/latency diagnostic for the SQLite authority lifecycle path.

Run from MCPS/Synapse-MCP with PYTHONPATH=tests and the project interpreter.
This exercises a passive workspace.summary plan with a no-op observer; it
neither sends traffic nor represents a full MCP client benchmark.
"""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import platform
from statistics import median
from tempfile import TemporaryDirectory
from pathlib import Path
from time import perf_counter

from helpers import isolated_state
from test_execution_lifecycle import NOW, _grant, _plan
from synapse_mcp.app.actions import RiskClass
from synapse_mcp.core import workspace
from synapse_mcp.policy import WorkspaceAuthorityRepository
from synapse_mcp.state.connections import StateConnection
from synapse_mcp.state.readiness import probe_state_store_runtime


@contextmanager
def count_sql():
    counts: Counter[str] = Counter()
    original_execute = StateConnection.execute
    original_many = StateConnection.executemany

    def execute(self, statement, parameters=()):
        counts[statement.lstrip().split(None, 1)[0].upper()] += 1
        return original_execute(self, statement, parameters)

    def executemany(self, statement, parameters):
        values = tuple(parameters)
        counts[statement.lstrip().split(None, 1)[0].upper()] += len(values)
        return original_many(self, statement, values)

    StateConnection.execute = execute
    StateConnection.executemany = executemany
    try:
        yield counts
    finally:
        StateConnection.execute = original_execute
        StateConnection.executemany = original_many


def exercise(authority, plan, key):
    receipt = authority.authorize(
        plan,
        risk_class=RiskClass.NONE,
        profile="full_delegated",
        authority_session_id="phase6r2-session",
        selected_grant_id="grant-phase6c",
        idempotency_key=key,
    ).receipt
    authority.mark_dispatched(receipt)
    authority.transition_dispatch(receipt.dispatch_id, "succeeded", outcome_kind="success")


def measure(root: Path, retained: int) -> tuple[float, Counter[str]]:
    with isolated_state(root, store_version="sqlite-v2"):
        workspace.create_workspace("phase6r2-diagnostic", hosts=["diagnostic.example"])
        plan = _plan("phase6r2-diagnostic")
        authority = WorkspaceAuthorityRepository("phase6r2-diagnostic", clock=lambda: NOW)
        authority.create_grant(_grant(plan))
        for index in range(retained):
            exercise(authority, plan, f"phase6r2-history-{index}")
        durations = []
        aggregate: Counter[str] = Counter()
        for index in range(5):
            with count_sql() as counts:
                start = perf_counter()
                exercise(authority, plan, f"phase6r2-measured-{index}")
                durations.append((perf_counter() - start) * 1000)
            aggregate.update(counts)
        return median(durations), Counter({key: value // 5 for key, value in aggregate.items()})


def main() -> None:
    readiness = probe_state_store_runtime()
    print(f"Python {platform.python_version()}; SQLite {readiness.selected_sqlite_version}; "
          f"binding {readiness.selected_binding}; host {platform.node()}")
    with TemporaryDirectory() as temporary:
        for retained in (8, 256):
            latency, counts = measure(Path(temporary) / str(retained), retained)
            print(f"retained={retained} median_ms={latency:.2f} "
                  f"sql_per_operation={dict(sorted(counts.items()))}")


if __name__ == "__main__":
    main()
