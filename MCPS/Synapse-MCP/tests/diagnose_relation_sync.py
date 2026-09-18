"""Local-only decoded-row/latency diagnostic for incremental relation sync.

Run from MCPS/Synapse-MCP with PYTHONPATH=tests and the project interpreter.
This submits passive observation contributions through the canonical Registry
against fictional saved data. It sends no traffic and is not a benchmark gate.
"""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import json
from pathlib import Path
import platform
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter

from helpers import isolated_state
from synapse_mcp.app.actions import ActionRegistry, ActionRequest, ExecutionContext, PassThroughPolicyEvaluator, REGISTRY, Success
from synapse_mcp.core import workspace
from synapse_mcp.state import runtime as state_runtime
from synapse_mcp.state.connections import StateConnection
from synapse_mcp.state.readiness import probe_state_store_runtime


@contextmanager
def observe_work():
    sql_counts: Counter[str] = Counter()
    decoded_rows = [0]
    original_execute = StateConnection.execute
    original_many = StateConnection.executemany
    original_decode = state_runtime._decode

    def execute(self, statement, parameters=()):
        sql_counts[statement.lstrip().split(None, 1)[0].upper()] += 1
        return original_execute(self, statement, parameters)

    def executemany(self, statement, parameters):
        values = tuple(parameters)
        sql_counts[statement.lstrip().split(None, 1)[0].upper()] += len(values)
        return original_many(self, statement, values)

    def decode(value):
        decoded_rows[0] += 1
        return original_decode(value)

    StateConnection.execute = execute
    StateConnection.executemany = executemany
    state_runtime._decode = decode
    try:
        yield sql_counts, decoded_rows
    finally:
        StateConnection.execute = original_execute
        StateConnection.executemany = original_many
        state_runtime._decode = original_decode


def contribution(request_id: str) -> str:
    return json.dumps({
        "schemaVersion": "1.0",
        "requestId": request_id,
        "producer": {"name": "phase7r1-diagnostic", "version": "1.0.0"},
        "entities": {"observations": [{"type": "saved_note", "value": request_id}]},
    })


def submit(registry: ActionRegistry, request_id: str) -> None:
    descriptor = registry.get("workspace.ingest_data")
    value = descriptor.input_model.model_validate({
        "workspaceId": "phase7r1-diagnostic",
        "target": "diagnostic.example",
        "source": "contribution.v1",
        "format": "json",
        "rawData": contribution(request_id),
    })
    result = registry.execute(
        "workspace.ingest_data",
        ActionRequest(
            value,
            ExecutionContext(
                "phase7r1-diagnostic",
                "phase7r1-diagnostic",
                45.0,
                None,
                principal_id="phase7r1-diagnostic",
                execution_profile="observe",
            ),
        ),
    )
    if not isinstance(result, Success):
        raise RuntimeError(f"diagnostic contribution failed: {result}")


def measure(root: Path, saved_endpoints: int) -> tuple[float, int, Counter[str]]:
    with isolated_state(root, store_version="sqlite-v2"):
        workspace.create_workspace("phase7r1-diagnostic", hosts=["diagnostic.example"])
        repository = workspace._activated_repository("phase7r1-diagnostic")
        repository.replace_collection(
            "diagnostic.example",
            "endpoints",
            tuple(
                {
                    "type": "endpoint",
                    "key": f"saved-{index}",
                    "url": f"https://diagnostic.example/saved/{index}",
                }
                for index in range(saved_endpoints)
            ),
        )
        registry = ActionRegistry(PassThroughPolicyEvaluator())
        registry.register(REGISTRY.get("workspace.ingest_data"))
        registry.freeze()
        durations: list[float] = []
        decode_counts: list[int] = []
        aggregate: Counter[str] = Counter()
        for index in range(5):
            with observe_work() as (sql_counts, decoded_rows):
                start = perf_counter()
                submit(registry, f"measured-{saved_endpoints}-{index}")
                durations.append((perf_counter() - start) * 1000)
            decode_counts.append(decoded_rows[0])
            aggregate.update(sql_counts)
        return (
            median(durations),
            int(median(decode_counts)),
            Counter({key: value // 5 for key, value in aggregate.items()}),
        )


def main() -> None:
    readiness = probe_state_store_runtime()
    print(
        f"Python {platform.python_version()}; SQLite {readiness.selected_sqlite_version}; "
        f"binding {readiness.selected_binding}; host {platform.node()}"
    )
    with TemporaryDirectory() as temporary:
        for saved_endpoints in (100, 2_000):
            latency, decoded_rows, sql_counts = measure(Path(temporary) / str(saved_endpoints), saved_endpoints)
            print(
                f"saved_endpoints={saved_endpoints} median_ms={latency:.2f} "
                f"decoded_rows_per_contribution={decoded_rows} "
                f"sql_per_contribution={dict(sorted(sql_counts.items()))}"
            )


if __name__ == "__main__":
    main()
