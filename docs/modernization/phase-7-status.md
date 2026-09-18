# Phase 7 status

Phase 7 is baselined at reviewed Beta commit
`8134673a386ad00eed786d3d3ba841f00fcb28de` on branch `Beta`. The reviewed SHA
was the actual branch HEAD at 7R0.1; no later implementation changes required
reassessment. Phase 6 remains complete, with its existing
[checkpoint ledger](phase-6-checkpoints.md) and
[direct-client exercise](phase-6-client-exercise.md) retained as historical
evidence. Completed-phase acceptance and benchmark gates remain retired.

The compatibility baseline is one external Codex agent using the default
eleven-operation `modern-compact` surface. The canonical Registry owns 174
actions across six selected packs in the standard profile; core-only owns 42.
The hosted operating prompt remains `synapse://prompt/main`, and the default
guidance profile contains `operate-synapse`, `synapse-web-pentesting`, and
`synapse-cve-intelligence`. Consumer submissions use `contribution.v1`.
The recorded, historical client pass used Codex CLI 0.154.0, Daybreak Blue at
High reasoning, `mcp==2.0.0`, MCP protocol `2025-06-18`, Synapse `0.6.0b0`,
`modern-compact` over stdio, Python 3.14.7, SQLite-v2, and one agent. These are
compatibility observations, not values to hardcode into application behavior.

## Current repair and delivery boundary

- F1 is repaired at checkpoint 7R1.1. New curated candidates materialize one
  stable key before their first write, and SQLite-v2 changes one current row in
  a repository transaction rather than replaying a stale collection snapshot.
  JSON-v1 remains compatible. Adapter rescans cannot revive a refuted class;
  explicit curation can reconsider it without leaving contradictory retirement
  or reportability flags. Pre-fix duplicates are detected but never merged or
  deleted automatically.
- F4 is repaired at checkpoint 7R1.2. Contribution retries compare the current
  normalized action target with the durable receipt target inside the same
  transaction before accepting replay. Same-target retries remain idempotent;
  target or payload changes conflict without canonical state mutation. Receipt
  uniqueness and the historical envelope fingerprint remain compatible.
- F5 is repaired at checkpoint 7R1.3. Collection and contribution ingestion
  pass touched canonical entity IDs into relation synchronization. Ordinary
  writes decode touched rows rather than the target's full entity history;
  changed sources still replace their relations, and a newly written
  destination resolves matching older forward references without rewriting
  unrelated relation rows. Existing entity-ID and natural-key indexes handle
  normal destination resolution, with a compatibility fallback for historical
  payload aliases; no migration or graph subsystem was added.
- F2-F3 remain correctness repairs: usable bounded context continuation and
  truthful compact-context provenance.
- F6 adds the smallest typed, evidence-backed methodology contribution through
  the existing `contribution.v1`, candidate, evidence, workspace, and report
  paths. It does not create another submission API or source of truth.

Small isolated installation, saved-data, and restart testing can begin now.
Candidate identity is reliable for records created or curated after 7R1.1;
historical duplicate diagnostics still require operator review. Complete
larger-context recovery and provenance-dependent conclusions require 7R2.
The exact next action is 7R2.1 in the
[checkpoint ledger](phase-7-checkpoints.md). The full serial scope and deferred
boundaries are in the [Phase 7 plan](phase-7-plan.md).
