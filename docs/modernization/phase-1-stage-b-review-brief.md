# Phase 1 Stage B — Independent adversarial review brief

A brief for an **independent reviewer** to gate Phase 1 Stage B (the Action
Registry and six-action vertical slice). Execute it in a **fresh context that did
not write the spec and did not implement the code** — a new Codex or Claude
session. Its purpose is to try to *break* Stage B's compatibility and safety
claims, not to confirm them.

- Under review: commits `fbc6949..HEAD` on `modernization/phase-1-action-registry`
  (five commits: `f34074b` gate promotion, `c8ec933` registry, `e3be89f`
  projection, `6951ded` contract proof, `66ca6a0` migration doc).
- Immutable reference: the Phase 0 frozen fixtures under
  `tests/fixtures/legacy_contracts/` and the design at `phase-1-stage-a.md` /
  ADR-0002 / ADR-0007 / ADR-0008. The task brief is
  `phase-1-stage-b-tasks.md`.
- Verdict required: **PASS / CONDITIONAL (numbered conditions) / REJECT
  (blockers)**, mirroring the Phase 0 adversarial-review format.

## Independence rules

- **Do not trust the architect's verification report or the implementer's commit
  messages.** Re-derive every claim from the frozen fixtures and the code.
- Re-run `bin/test` yourself; reproduce the byte measurements yourself.
- For every finding, give `file:line`, a concrete reproduction (inputs → observed
  vs expected), and a severity (BLOCKER / HIGH / MEDIUM / LOW). A green suite is
  not evidence a contract holds — check that the tests assert the *right* thing
  with the *specified* inputs, not merely that they pass.
- Where you agree with a claim, say so and state the evidence. Strong independent
  agreement is the point; disagreement marks exactly where a human decision is
  owed.

## Exit criteria you are trying to break

Phase 1 changes **no** observable behaviour except freezing the already-frozen
`jobs.status` `-32003` variant. Concretely: `tools/list` is byte-identical; every
migrated action's success payload and every error envelope match the frozen
fixtures; the six actions dispatch **only** through `ActionRegistry.execute()`;
each migrated `inputSchema` has exactly one home (the descriptor); and no
guardrail was crossed. Attack each of these.

---

## Review targets, by blast radius

### R1 — Public-surface byte-equality (highest blast radius)
**Claim.** `tools/list` is 174 ordered tools at exactly 99,337 compact bytes,
identical to `tools_list.json`.
**Attack.** The six migrated `inputSchema`s are now re-projected from
`InputContractDocument.source` strings. A single reordered key, changed default,
or `true`/`True` slip in any `source` drifts the bytes.
**Check.** Confirm `tools_list.json` was **not** modified in the range
(`git diff fbc6949..HEAD -- .../tools_list.json` is empty). Import
`transport.stdio_server`, compute
`len(json.dumps(projection.projected_tools_list(), separators=(",",":")).encode())`
== 99,337 and count == 174. Independently diff each of the six descriptors'
`input_model.contract_document.parsed()` against the corresponding `inputSchema`
in the frozen `tools_list.json` (deep-equal **and** key-order identical).
**Pass.** Byte count, tool count, and per-tool schema all match the frozen fixture.

### R2 — Error-taxonomy preservation and exception leakage (priority)
**Claim.** For the six actions, every `-32602 / -32001 / -32002 / -32000 / -32003`
wire envelope is byte-identical to legacy, and no new exception type reaches the
wire.
**Context you must verify, not assume.** The executor wraps the legacy call in
`except McpError` only, translating via `outcome_from_mcp_error` (which always
sets `legacy_code=exc.code`); `project_call` re-raises `McpError(legacy_code,
message)`; `handle()` turns any *other* exception into `-32000, str(exc)`. This
*should* mean a non-`McpError` raised inside a legacy callable propagates to the
**same** `-32000` handler as the legacy path, with the same message.
**Attack.** Prove or break that equivalence with fault injection:
- Patch `workspace.workspace_summary` (and one adapter callable) to raise a plain
  `ValueError("boom")`. Drive it through `handle()` on the **migrated** path and
  confirm the envelope equals what the *legacy* branch would emit (`-32000`,
  `"boom"`). A divergence here is a BLOCKER.
- Confirm `project_call`'s `TypeError` (non-`str` executor payload) and
  `RuntimeError` (missing `legacy_code` / `ExecutionUnknown`) cannot be reached by
  any accepted input for the three executor-serialized actions — i.e. the
  adapters always return `str`. If reachable, it becomes an observable `-32000`
  that legacy never produced.
- Reproduce the three frozen error fixtures (`cors_execute_test_unconfirmed`
  `-32001`, `crawler_crawl_unconfirmed` `-32001`, `crawler_crawl_out_of_scope`
  `-32002`) through `handle()` and byte-compare the `error` block.
**Pass.** All error envelopes match; no accepted input yields a leaked
`ValidationError`/`LookupError`/`PermissionError`/`TypeError`/`RuntimeError`.

### R3 — Legacy-vs-typed validation divergence (priority)
**Claim.** The typed `input_model` rejects nothing legacy accepts and accepts
nothing legacy rejects, for the six.
**Context you must verify.** `validate_tool_arguments` runs **first** and enforces
type, `enum`, `minimum`/`maximum`, array items, and nested properties as `-32602`
(`_validate_schema_value`), plus leading-underscore rejection and the required-
`confirm` skip. So most stricter-typed-model cases are pre-empted. The residual
gap is inputs that **pass** legacy validation yet **fail** `model_validate`,
surfacing as `-32000` instead of the legacy code.
**Attack.** Find such an input for any of the six. Known candidate seams:
- **Nested `required`.** Legacy validates nested *values* but does **not** enforce
  nested `required`; a generated nested object model does. Confirm none of the six
  schemas has a nested object carrying `required` (cors `candidate` is
  `additionalProperties:true`, no `required` — verify). If one exists, it is a
  real divergence.
- Explicit `null` on an optional field; `number`-typed fields given `bool`;
  objects with `additionalProperties` under strict mode. For each, check whether
  legacy and typed agree on accept/reject.
**Pass.** No input passes `validate_tool_arguments` but raises from
`model_validate` for any of the six. Report any residual as a finding even if
inert for the slice — it is a pattern risk for actions 7–174 and belongs in the
migration guide.

### R4 — Default-application fidelity
**Claim.** Schema defaults (`maxTokens=1500`, `maxCandidates=100`, cors
`method=GET`/`requestTimeout=10`, the crawler defaults, HTTP-policy defaults)
still execute at their existing legacy layer and are not double-applied.
**Attack.** For each migrated action, omit each defaulted field and assert
`request.input.model_dump(by_alias=True, exclude_unset=True)` does **not** contain
it (so the legacy `.get(field, default)` still fires). Then confirm the value
reaching the legacy callable equals the legacy path's. Watch for any field whose
schema default differs from the adapter's internal default — that is where
double-application would change output.
**Pass.** No default is injected into the dumped args; observed effect matches
legacy.

### R5 — Single source, no duplicate schema (ADR-0002)
**Claim.** Each migrated `inputSchema` lives only in its descriptor.
**Attack.** Grep the transport for any residual literal for the six; confirm
`_LEGACY_TOOL_SCHEMAS` entries for the six carry **no** `inputSchema`
(`test_action_projection.py` asserts this — verify it actually runs over
`_LEGACY_TOOL_SCHEMAS`, not the projected list). Confirm both `tools/list` **and**
`validate_tool_arguments` resolve through `projection.resolved_input_schema`, so
there is no second validation schema.
**Pass.** Exactly one schema source per migrated action; both discovery and
validation read it.

### R6 — No-bypass execution invariant (ADR-0002)
**Claim.** No protocol path reaches an executor except through
`ActionRegistry.execute()`, which runs the policy evaluator first.
**Attack.** Grep for any direct `.executor(` call outside `execute()`; confirm
`project_call` is the only transport entry to the registry and always calls
`execute()`. Confirm the Phase 1 evaluator is a pass-through that enforces nothing
(so the registry is not masquerading as an authority engine) **and** that it is
genuinely invoked before the executor (not short-circuited).
**Pass.** Executors are unreachable without `execute()`; evaluator runs first;
enforces nothing.

### R7 — Passive-recording and background-job paths
**Claim.** `headers_cookies.analyze_workspace` still records passively; the
`crawler.crawl` background-submit path is unchanged.
**Attack.** Confirm `_record_passive_analysis_action` still fires on the projected
string for `headers_cookies.analyze_workspace` and is suppressed identically on an
error payload (the projected string must equal the legacy string, since recording
keys off it). Drive `crawler.crawl` with `background=true` and confirm the
submission envelope matches `crawler_crawl_background_submitted.json` through the
registry path.
**Pass.** Recording side-effect and background submission are behaviourally
identical.

### R8 — Architecture import boundary (and test soundness)
**Claim.** `app/` never imports `transport/`; `core/`+`adapters/` never import
`app/`/`transport/`.
**Attack.** The AST test is the enforcement — audit the test itself: does it walk
every `*.py` under `app/` (including the pack modules), catch **deferred**
in-function imports, and resolve relative imports? Note that a string-based
`importlib.import_module("...transport...")` would evade AST detection — confirm
none exists. Independently grep for `transport` imports under `app/`.
**Pass.** Boundary holds and the test genuinely enforces it.

### R9 — Governance and ledger integrity (Task 1)
**Claim.** The Phase 0 gate promotion and Stage A approval are recorded honestly.
**Attack.** Confirm `phase-0-handoff.md` reads **PASS**, the CI-backfill
placeholder is retired with the local-attestation framing (no fabricated run
URL), and every `contract-changes.md` row (three fixtures + the ADR-0002
amendment + the new `fbc6949` ratification) names a real approver, not `pending`.
Confirm **no fixture was changed** in the range without a ledger row (D-6): the
range should touch **zero** files under `tests/fixtures/`. Judge whether "gate
PASS on operator local attestation, no remote CI" is acceptable under the
program's own rules — flag it if you believe it is not, but note it is the
operator's recorded decision.
**Pass.** Gate/ledger are internally consistent and evidence-backed; no silent
fixture change.

### R10 — Scope discipline
**Attack.** `git diff --stat fbc6949..HEAD` — confirm only the files the task
brief authorised changed, and that `stdio_server.py`'s edits are limited to the
seam (rename to `_LEGACY_TOOL_SCHEMAS`, remove the six literals, route
`_call_tool_impl`/`validate_tool_arguments`/`tools/list` through `projection`). Any
production edit beyond the seam — even an improvement — is a finding.
**Pass.** No out-of-scope change.

---

## Required evidence (run these; paste real output)

```bash
git -C . diff --stat fbc6949..HEAD
git -C . diff fbc6949..HEAD -- MCPS/Synapse-MCP/tests/fixtures/    # must be empty
bin/test                                                            # whole suite green
bin/test --core -k contracts                                        # frozen contracts
# byte-equality, single source, registry shape:
SYNAPSE_ROOT=$(mktemp -d) .venv/bin/python -c "import json;from synapse_mcp.transport import stdio_server,projection;from synapse_mcp.app.actions import REGISTRY;tl=projection.projected_tools_list();print(len(tl),len(json.dumps(tl,separators=(',',':')).encode()));print(sorted(REGISTRY.packs()),len(REGISTRY.descriptors()))"
```
Add your own fault-injection scripts for R2/R3/R4 (patch a legacy callable to
raise `ValueError`; feed a nested-`required` / out-of-bounds / null input past
`validate_tool_arguments` into `model_validate`).

## Verdict

Return **PASS**, **CONDITIONAL** (numbered conditions, each with severity + the
smallest fix), or **REJECT** (blockers). Base the verdict on R1–R10. Anything that
changes an observable wire response for the six actions is a BLOCKER; a latent
pattern risk that is inert for the slice but will bite actions 7–174 is at most
MEDIUM and should be routed to `action-migration-pattern.md` rather than blocking
the gate. State explicitly whether the six-action slice may be promoted and
whether the migration of actions 7–174 may begin on this foundation.
