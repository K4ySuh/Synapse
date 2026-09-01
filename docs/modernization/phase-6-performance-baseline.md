# Phase 6A performance baseline

Phase 6A freezes the pre-observed-effect instrumentation cost of the existing
control plane. The fixture is local, fictional, provider-neutral, and blocks
external traffic. Raw timings are not engagement state and the checked evidence
contains no prompts, arguments, credentials, local paths, or host identity.

## Reproduction

Run the same fixture and compare it with the checked environment baseline:

```bash
bin/run-phase6-performance --check
```

The default run uses 12 fresh-process cold starts and 40 warm samples. It
creates 500 minimal work items in a private temporary SQLite-v2 workspace,
measures one complete context query, measures the first 50-item summary page,
and exercises Registry planning, the policy seam, no-op dispatch, and output
validation without provider I/O. Setup and fixture creation are outside timed
samples.

The runner reports median, nearest-rank p95, sample count, Python, SQLite, MCP
SDK, operating-system, machine, and filesystem class. A matching environment
must stay within 20% of the checked p95 values. An environment mismatch remains
visible and falls back to the proposed absolute ceilings; it is never silently
classified as a relative pass.

## Checked environment and results

The baseline used CPython 3.14.7, SQLite 3.53.4, MCP SDK 2.0.0, Linux x86_64,
and a private local temporary directory.

| Measurement | Samples | p50 | p95 | Proposed ceiling | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| Standard selected-pack cold start | 12 | 1,119.739 ms | 1,165.226 ms | 1,250 / 2,000 ms | pass |
| Core-only cold start | 12 | 792.572 ms | 875.567 ms | 500 / 900 ms | p50 miss; p95 pass |
| Context query with 500 work items | 40 | 12.814 ms | 13.200 ms | 25 / 50 ms | pass |
| First 50 work-item summaries | 40 | 3.487 ms | 3.760 ms | 25 / 60 ms | pass |
| Registry control overhead | 40 | 0.032 ms | 0.051 ms | 20 / 50 ms | pass |

The proposed core-only p50 is not achievable on this captured environment when
the measurement includes interpreter process creation, import, and selected
pack assembly. Phase 6A does not hide or weaken that absolute result. It accepts
this environment fingerprint as the explicit starting baseline and applies the
20% relative regression ceiling on matching future runs, while preserving the
900 ms absolute p95 result. A later ADR is required to change that policy.

`registryControlOverhead` is deliberately a pre-instrumentation control. It is
not evidence that observation or effect validation already exists. Task 6I will
add the complete intent/authorization/observation/validation measurement and
compare it with this control without relabeling the Phase 6A evidence.

The exact sanitized source is
[`evidence/phase-6/performance-baseline.json`](evidence/phase-6/performance-baseline.json).
