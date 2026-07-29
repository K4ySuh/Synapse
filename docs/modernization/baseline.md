# Modernization Baseline

This document records reproducible, non-sensitive facts for the reviewed
Synapse baseline and the Phase 0 compatibility boundary. Stable counts and
sizes are committed; machine-dependent wall-clock timings are intentionally
excluded.

## Baseline identity

| Field | Value |
| --- | --- |
| Reviewed commit | `099ba1aec4873b3ac08ffbecd82a45c06753880f` |
| Package | `synapse-mcp` `0.6.0b0` |
| Python requirement | `>=3.10` |
| Core dependencies | `httpx>=0.28,<1`; `pydantic>=2,<3` |

## Environment used

The Phase 0 measurements were reproduced with:

| Component | Version |
| --- | --- |
| Python | `3.13.14` |
| httpx | `0.28.1` |
| pydantic | `2.13.4` |

These are measurement-environment versions, not changes to the supported
version ranges above.

## Tool surface

| Metric | Value |
| --- | ---: |
| Tools | 174 |
| Unique tool names | 174 |
| Compact schema bytes | 99,337 |
| Pretty schema bytes | 168,671 |
| Tools with `confirm` | 47 |
| Namespaces | 40 |
| Output schemas | 0 |
| Annotations | 0 |
| Titles | 0 |
| Advertised protocol | `2025-03-26` |

The payload measurements serialize the ordered `TOOL_SCHEMAS` list directly:
compact JSON uses `separators=(",", ":")`; pretty JSON uses `indent=2`.

## Code size at the reviewed baseline

| Metric | Value |
| --- | ---: |
| Tracked Python files | 108 |
| Python lines | 56,072 |
| `stdio_server.py` lines | 3,980 |
| `workspace.py` lines | 3,593 |
| Root `AGENTS.md` lines | 619 |

These figures are measured from commit `099ba1a`, not the Phase 0 head, so new
contract and benchmark tests do not rewrite the baseline.

## Test progression

| Point | Core tests | Template tests |
| --- | ---: | ---: |
| Reviewed baseline `099ba1a` | 371 | 2 |
| P0-1 `5eb62df` | 379 | 2 |
| P0-2a `4cd07bb` | 389 | 2 |
| P0-2b `9a8d6c5` | 395 | 2 |
| P0-3 `fc15cff` | 404 | 2 |
| P0-4 `52a200a` | 407 | 2 |
| P0-5 `633e656` | 408 | 2 |
| P0-extra-1 `fe4b61a` | 414 | 2 |
| P0-extra-2 (this change) | 414 | 2 |

## Contract fixtures

Phase 0 commits 5 protocol fixtures (Tier 1) and 14 normalized result fixtures
(Tier 2), for 19 contract fixtures in total. The Tier-1 `errors.json` fixture
contains seven frozen cases, including the `-32003` tool-timeout envelope.

## Error-code taxonomy

| Code | Current use | Occurrences |
| --- | --- | ---: |
| `-32000` | Generic operational error | 23 |
| `-32001` | Authorization or approval required | 10 |
| `-32002` | Scope denial | 8 |

The distinct authorization and scope codes are observable safety semantics, not
interchangeable labels.

## Context budget baseline

Measured at `fc15cff` on the populated benchmark workspace. Estimated tokens use
the documented `characters / 4` estimator.

| `maxTokens` | Characters | Estimated tokens | Ratio | Truncation/omission fields |
| ---: | ---: | ---: | ---: | --- |
| 100 | 4,024 | 1,006 | 10.06x | none |
| 400 | 4,024 | 1,006 | 2.52x | none |
| 1,500 | 4,025 | 1,006 | 0.67x | none |
| 6,000 | 4,025 | 1,006 | 0.17x | none |
| 20,000 | 4,026 | 1,006 | 0.05x | none |

Response size is invariant across a 200× budget range, so `maxTokens` is not
enforced, and no field lets a caller detect the overrun. Budget adherence is
currently **0%** against the directive KPI.

## Benchmark corpus

The deterministic Phase 0 corpus measures:

1. opening and summarizing a populated workspace;
2. preparing target context at five budgets;
3. passive headers/cookies analysis;
4. planning and executing a disabled-traffic CORS probe;
5. background crawler submission and terminal inspection;
6. recovery after a simulated client timeout without duplicate work; and
7. report rendering inside an isolated runtime root.

The working ingest shape is sitemap JSON with `hosts[].urls[]`. It creates 2
endpoints and 1 parameter, verified through `workspace.summary` before context
measurement. Benchmark JSON is written to a temporary location at runtime;
wall-clock values are printed but not committed.

## Credential-result behavior

Credential results are redacted rather than omitted. For values of at least 20
characters, the current implementation returns the first four and last four
characters separated by an ellipsis. The confirmed credential fixture therefore
contains `CANA...b2c3`. This is a measured legacy result contract, not a claim
that partial disclosure is an authorization boundary.

## Integrity prerequisite

A tracked Phase 0 integrity prerequisite must land before Phase 2 persists
authority state.

## Baseline tag proposal

The proposed local tag is `v0.6.0-beta-modernization-baseline`, pointing at
`099ba1aec4873b3ac08ffbecd82a45c06753880f`. It is **not created** by this task.
At the Phase 0 gate, the operator may create it locally; it must not be pushed.

## Reproduction commands

Run all commands from the repository root.

### Package and environment

```bash
baseline_commit=099ba1aec4873b3ac08ffbecd82a45c06753880f
git show "${baseline_commit}:pyproject.toml"
.venv/bin/python --version
.venv/bin/python - <<'PY'
from importlib.metadata import version

for package in ("httpx", "pydantic"):
    print(package, version(package))
PY
```

### Tool surface

```bash
PYTHONPATH=MCPS/Synapse-MCP .venv/bin/python - <<'PY'
import json
from collections import Counter

from synapse_mcp.transport.stdio_server import PROTOCOL_VERSION, TOOL_SCHEMAS

names = [item["name"] for item in TOOL_SCHEMAS]
compact = json.dumps(TOOL_SCHEMAS, separators=(",", ":")).encode()
pretty = json.dumps(TOOL_SCHEMAS, indent=2).encode()
print("tools", len(names))
print("unique_tool_names", len(set(names)))
print("compact_schema_bytes", len(compact))
print("pretty_schema_bytes", len(pretty))
print(
    "confirm_tools",
    sum(
        "confirm" in item.get("inputSchema", {}).get("properties", {})
        for item in TOOL_SCHEMAS
    ),
)
print("namespaces", len(Counter(name.split(".", 1)[0] for name in names)))
print("output_schemas", sum("outputSchema" in item for item in TOOL_SCHEMAS))
print("annotations", sum("annotations" in item for item in TOOL_SCHEMAS))
print("titles", sum("title" in item for item in TOOL_SCHEMAS))
print("protocol", PROTOCOL_VERSION)
PY
```

### Code size

```bash
baseline_commit=099ba1aec4873b3ac08ffbecd82a45c06753880f
git ls-tree -r --name-only "$baseline_commit" | grep '\.py$' | wc -l
git ls-tree -r --name-only "$baseline_commit" |
  grep '\.py$' |
  while IFS= read -r source_file; do
    git show "${baseline_commit}:${source_file}"
  done |
  wc -l
git show "${baseline_commit}:MCPS/Synapse-MCP/synapse_mcp/transport/stdio_server.py" | wc -l
git show "${baseline_commit}:MCPS/Synapse-MCP/synapse_mcp/core/workspace.py" | wc -l
git show "${baseline_commit}:AGENTS.md" | wc -l
```

### Historical test progression

```bash
measurement_root=$(git rev-parse --show-toplevel)
measurement_python="$measurement_root/.venv/bin/python"
for revision in 099ba1a 5eb62df 4cd07bb 9a8d6c5 fc15cff; do
  checkout_dir=$(mktemp -d)
  git worktree add --detach "$checkout_dir" "$revision"
  (
    cd "$checkout_dir"
    SYNAPSE_PYTHON="$measurement_python" bin/test --core
  )
  git worktree remove --force "$checkout_dir"
done
```

### Contract fixtures

```bash
find MCPS/Synapse-MCP/tests/fixtures/legacy_contracts -type f |
  grep -v '/results/' |
  wc -l
find MCPS/Synapse-MCP/tests/fixtures/legacy_contracts/results -type f | wc -l
```

### Error-code taxonomy

```bash
find MCPS/Synapse-MCP/synapse_mcp -name '*.py' -type f \
  -exec grep -ho 'McpError(-32000' {} + | wc -l
find MCPS/Synapse-MCP/synapse_mcp -name '*.py' -type f \
  -exec grep -ho 'McpError(-32001' {} + | wc -l
find MCPS/Synapse-MCP/synapse_mcp -name '*.py' -type f \
  -exec grep -ho 'McpError(-32002' {} + | wc -l
```

### Context budget and benchmark corpus

```bash
PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python - <<'PY'
import json

from benchmark_support import workflow_02_prepare_target_context_under_budget

metric = workflow_02_prepare_target_context_under_budget()
print(json.dumps(
    {
        "ingestShape": metric["ingestShape"],
        "entityTotals": metric["entityTotals"],
        "estimator": metric["estimator"],
        "budgets": metric["budgets"],
    },
    indent=2,
))
PY

PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=MCPS/Synapse-MCP \
.venv/bin/python -m unittest discover \
  MCPS/Synapse-MCP/tests \
  -p 'test_workflow_benchmarks.py'
```
