# Phase 5 operational acceptance method

Phase 5 acceptance is deterministic and provider-neutral. It uses only fresh
fictional local workspaces named `benchmark` with the host
`app.acme-demo.test`. A process network guard disables external target traffic,
no credentials or third-party providers are configured, and generated runtime
data stays under gitignored `DATA/` or a private temporary root.

## Reproducible gate

Run the complete closure gate with:

```bash
bin/run-phase5-acceptance
```

The runner performs three isolated repetitions through public application and
repository contracts. It covers direct context and revision deltas, concurrent
independent-consumer claims from separate processes, an exclusive two-process claim
race, dependency-gated reporting, distinct evidence convergence, stale-worker
recovery without replay, covered and uncovered authority outcomes, pack
assembly, surface budgets, installed distribution, and legacy rollback.

The eight independent verdicts are capability-pack compatibility,
multi-client state concurrency, authority/execution linkage, compact/context
budgets, direct operational workflow, coordinated operational workflow,
package cold start, and legacy rollback integrity. Compact remains eleven
operations and at or below the accepted 24,834-byte official-SDK wire ceiling.
Standard pack assembly remains 174 actions with one owner each; core-only
remains 42 actions.

Every deterministic repetition must prove one exclusive claim winner, no lost
updates, no automatic replay of active or outcome-unknown work, distinct
consumer evidence, dependency-respecting reporting, a covered execution, an
uncovered `approval_required` result, and zero external target connections.
Tests and distribution must also pass; explicitly skipping either produces a
`partial` diagnostic result.

## Optional live Codex diagnostic

Live multi-agent model behavior is not a Phase 5 acceptance dependency. A
single subscription simulating several agents measures account allowance as
much as Synapse behavior, while Synapse is designed to coordinate independent
clients through canonical workspace state.

Operators who specifically need a Codex client diagnostic can run one explicit
repetition:

```bash
bin/run-phase5-codex-benchmark --preflight
bin/run-phase5-codex-benchmark --run --profile multi-agent-compat
```

The optional runner defaults to the bounded `gpt-5.6-luna`/`low` profile for
both the coordinator and every spawned specialist. It selects low model
verbosity, disables reasoning summaries, caps each retained tool output at
4,096 tokens, requests minimal context/work-item responses, and keeps one
repetition as the default. Multiple repetitions or a non-default Phase 5 model
or effort require `--allow-high-usage`; use `--resume` to retain completed clean
runs under gitignored `DATA/phase5-codex-benchmark/`. It fails fast and blocks
external target traffic. These controls reduce allowance pressure but do not
turn the multi-agent diagnostic into a cheap acceptance gate: repeated cached
prefixes across tool turns and agent threads are still included in client token
totals. Its output may diagnose one tested client/model combination, but it does
not change Phase 5 acceptance evidence or support a generic client-conformance
claim.

This profile follows OpenAI's designation of
[GPT-5.6 Luna](https://developers.openai.com/api/docs/models/gpt-5.6-luna) for
cost-sensitive, high-volume workloads and uses the documented Codex
[parent/subagent model and effort settings](https://developers.openai.com/codex/config-reference).

The older Phase 3 live entry points use the same Luna/low, low-verbosity,
no-reasoning-summary, 4,096-token tool-history defaults and now default to one
repetition. Their checked historical evidence remains the exact previously
captured Sol batches; changing a runner default never relabels that evidence.

## Evidence and retained baselines

The checked evidence under `docs/modernization/evidence/phase-5/` contains only
deterministic aggregate results and no prompts, transcripts, raw arguments,
opaque handles, credentials, or local paths. Phase 3/4 modern-compact
measurements remain historical context and are not relabeled by Phase 5. The
retained generic MCP conformance classification remains `partial_fail`; MCP
Inspector and other clients are optional diagnostics.
