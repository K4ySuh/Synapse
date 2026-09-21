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
- F2 is repaired at checkpoint 7R2.1. `context.query` now exposes an opaque
  continuation cursor and structured metadata without adding an operation.
  The cursor binds normalized filters and deterministic repository-source
  positions to one workspace revision; changed filters fail typed, while a
  changed revision requires an explicit refresh. `sinceRevision` remains a
  separate delta boundary. Protected contradiction rows are queried
  independently of ordinary entity pages, so warnings beyond a page cutoff
  cannot become a false zero.
- F3 is repaired at checkpoint 7R2.2. Compact entity/finding context now
  separates knowledge state from generic lifecycle, preserving explicit
  documented, inferred, reported, observed, and unknown distinctions plus
  saved source and contribution producer attribution. Imported specs and
  consumer submissions are not runtime-observed claims merely because their
  entity-table lifecycle is `observed`; historical records without a positive
  method signal remain unknown. Evidence links and available contrary evidence
  remain visible without a parallel provenance store.
- F6 is repaired at checkpoint 7R3.2. The existing `contribution.v1`
  action/source now publishes a strict version 1.1 typed analysis extension
  alongside unchanged 1.0. Candidate and coverage-gap analyses normalize to
  canonical observations with stable surface identity, explicit inferred or
  reported state, supporting/contrary evidence references, and method/producer
  attribution. Optional saved subject IDs and evidence references are checked
  against the existing workspace/target transaction boundary. Later analysis
  updates the stable candidate without overwriting validation or reportability
  decisions; a fresh process recovers the result through context and internal
  report projections. Analysis cannot assert observation, execution, validation,
  or operator review. No second submission API or source of truth was added.
- 7R4.1 adds a static hosted guidance package manifest with the existing three
  entry skills and two optional web methods for authentication/session and
  access-control selection. The modern MCP catalog advertises package and
  document metadata without loading bodies; content-derived digests and bytes
  come from one server-start snapshot. Wheel and sdist ship the same method
  files.
- 7R4.2 adds an optional native `web-methods` Codex asset profile. Operators
  can copy either method beside the three default skills and invoke it by name,
  or allow description-based selection. The profile and two `agents/openai.yaml`
  files come from the same shipped assets as hosted guidance; wheel and sdist
  checks verify both forms. No multi-agent mode or server behavior changed.
  Detailed method procedures remain in 7R5.
- 7R5 completes the main Web method, eight focused optional web packages, and
  the saved-data Web/CVE/Web resumption workflow. Typed version 1.1 method
  contributions keep package ID and digest with canonical evidence and receipts.
- 7R6.1 publishes an [operation transition map](phase-7-operation-transition-map.md)
  covering all 174 built-in actions by ownership and operation category. Its
  41 heuristic interpretation operations map to a relevant optional web method;
  CVE applicability continues through the CVE entry skill. Default guidance
  now selects from saved evidence and the current question, keeps retained
  heuristic helpers explicit and optional, and avoids bulk candidate ingestion.
  A saved-spec regression reaches a canonical method contribution with no
  heuristic action available.
- 7R6.2 preserves the 174-action Registry, exact legacy projection,
  `modern-direct`, and eleven-operation `modern-compact` surface. Explicitly
  selected retained helpers still cross the Registry and write canonical
  evidence/state; removing an optional method package does not prevent context
  recovery of saved data or its historical method attribution. Method packages
  remain separate from capability-pack startup and server-held authority.
  There is no concrete discovery-ranking requirement yet, so any additive
  preference is deferred to the bounded 7R7 client exercise.
- 7R7.1 validates the installed release boundary. One wheel and one sdist were
  each installed outside the checkout; both resolved all 3 default, 8 optional
  web-method, and 8 compatibility skills and their local references. Installed
  standard and core-only runtimes constructed with 174 and 42 selected actions.
  The focused 7R1–7R3 set passed 250 tests. The one 830-test core run reported
  three test-environment/stale-assertion failures, all of which passed together
  in one isolated rerun. The one 17-test modern run reported one stale generated
  schema error; the isolated ten-case negotiation rerun passed after updating
  only the intentional 7R2 compact cursor and 7R3 direct contribution-v1.1
  schemas. Frozen legacy fixtures remain unchanged, modern-direct retains all
  174 ordered actions, and modern-compact remains eleven operations. Backup,
  export, and import now explicitly preserve the v1.1 receipt, method digest,
  model label, knowledge state, contrary evidence, and coverage-gap conclusion.
  No migration, rollback engine, discovery-ranking change, or client comparison
  was added.
- 7R7.2 has a bounded but unfinished
  [six-case client comparison](phase-7-client-comparison.md). Codex CLI 0.154.0
  with Daybreak Blue/High analyzed all six fictional cases on both routes and
  the selected method covered all 220 C5 endpoints without a material
  conclusion, coverage, or evidence-attribution regression. The retained
  helper persisted five unnecessary confirmed findings in C3/C6; the method
  route avoided those conclusions. The method route did not persist its four
  useful C1/C4/C5/C6 results because of a too-low grant risk ceiling, one
  strict outer-contract error followed by idempotency conflict, and a grant
  that expired during an interrupted interval. Its required live restart was
  therefore not run. The 120-call/350,000 non-cached-token budget stopped at
  83 calls and 328,700 tokens because a fresh session's observed baseline
  exceeded the 21,300-token remainder. The checkpoint remains pending.

Candidate identity is reliable for records created or curated after 7R1.1;
historical duplicate diagnostics still require operator review. The default
route is saved evidence, one current method question, and an evidence-backed
canonical contribution. The documented setup begins with the standard
`modern-compact` profile and keeps browsers, scanner binaries, Java/Burp, and
the maintained SQLite fallback workflow-specific.

The Python 3.14 official-SDK synchronous resource-read stall recorded at 7R5.3
did not reproduce in the bounded 7R7.1 attempt: the previously failing prompt
and guidance resource test completed in 0.121 seconds. That single pass does not
establish that the earlier environment-sensitive behavior is universally
resolved; independent repository resource, archive, installed-content/digest,
skill/reference, runtime-construction, and negotiation checks also pass.

No discovery-ranking change is justified by the comparison. For the tested
configuration family, retain the explicit helper as an operational fallback
until the method contribution path completes; this does not reverse the
method-first documentation for other families. Default installation remains
the three skills returned by `synapse-codex-assets --skills-dir`. Optional
methods remain separately copied from `--skills-profile web-methods`; removing
one optional folder leaves canonical state and historical attribution readable.

The [checkpoint ledger](phase-7-checkpoints.md) records the exact results. The
full serial scope and deferred boundaries are in the
[Phase 7 plan](phase-7-plan.md). The exact next action remains 7R7.2: declare a
new bounded continuation, preflight a long-enough low-risk grant and fresh
idempotency keys, persist only unfinished C1/C4/C5/C6 method outputs, then run
one fresh C6 restart recovery. Do not repeat the completed helper cases. After
that, Beta testing order is fresh setup, supplied-data import, context
traversal, method contribution, restart/second consumer, report and bundle
recovery, then separately authorized real integration testing.
