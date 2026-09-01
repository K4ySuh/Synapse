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

The accepted method runs three complete repetitions. Each repetition uses 12
fresh-process cold starts and 40 warm samples. It creates 500 minimal work
items once in a private temporary SQLite-v2 workspace, measures complete
context queries in batches of four, measures the first 50-item summary page in
batches of ten, and exercises Registry planning, the policy seam, no-op
dispatch, and output validation in batches of 1,000 without provider I/O.
Reported warm latencies remain per operation. Setup and fixture creation are
outside timed samples, and the accepted p50/p95 is the median of the three
per-repetition percentiles.

The runner reports median, nearest-rank p95, sample and operation counts,
per-repetition results, Python, SQLite, MCP SDK, kernel, CPU model/count/
affinity, CPU governor, load class, operating system, machine, and filesystem
class. Relative comparison also binds the versioned measurement method and
fixture shape. A matching environment and method must stay within 20% of the
checked p95 values. A mismatch remains visible and falls back to the proposed
absolute ceilings; it is never silently classified as a relative pass.

## Checked environment and results

The accepted v3 baseline used CPython 3.14.7, SQLite 3.53.4, MCP SDK 2.0.0,
Linux 7.1.9 x86_64, an Intel i9-14900HX with 32 available CPUs under the
`powersave` governor and low load class, and a private local temporary
directory.

| Measurement | Operations | p50 | p95 | Proposed ceiling | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| Standard selected-pack cold start | 36 | 1,308.130 ms | 1,469.503 ms | 1,250 / 2,000 ms | p50 miss; p95 pass |
| Core-only cold start | 36 | 854.639 ms | 984.972 ms | 500 / 900 ms | p50/p95 miss |
| Context query with 500 work items | 480 | 14.446 ms | 22.154 ms | 25 / 50 ms | pass |
| First 50 work-item summaries | 1,200 | 3.907 ms | 7.177 ms | 25 / 60 ms | pass |
| Registry control overhead | 120,000 | 0.036 ms | 0.038 ms | 20 / 50 ms | pass |

The proposed cold-start p50 ceilings and the captured core-only p95 ceiling are
not achievable consistently on this environment when the measurement includes
interpreter process creation, import, and selected-pack assembly. Phase 6A does
not hide or weaken those absolute results. It accepts this environment and
method fingerprint as the explicit starting baseline and applies the 20%
relative p95 ceiling on matching future runs. A later ADR is required to change
that policy.

The initial single-run v1 gate passed during implementation but failed twice
from the unchanged review tree, including warm p95 variations of 22–120%.
Median-of-three v2 still failed on short individual work-list and Registry
timings. Those results are the adversarial counterexample, not regressions in
application code. The v3 method batches warm operations before applying the
same three-repetition median and 20% relative rule. Its immediate exact replay
passed all relative comparisons; the absolute core-only p50 miss remained
visible. The original
[`performance-baseline.json`](evidence/phase-6/performance-baseline.json) and
intermediate
[`performance-baseline-v2.json`](evidence/phase-6/performance-baseline-v2.json)
remain historical evidence rather than being regenerated.

`registryControlOverhead` is deliberately a pre-instrumentation control. It is
not evidence that observation or effect validation already exists. Task 6I will
add the complete intent/authorization/observation/validation measurement and
compare it with this control without relabeling the Phase 6A evidence.

The accepted sanitized source is
[`evidence/phase-6/performance-baseline-v3.json`](evidence/phase-6/performance-baseline-v3.json).
