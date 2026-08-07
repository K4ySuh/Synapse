# Phase 1 Stage B — Codex task brief

Action Registry, the six-action vertical slice, contract-equivalence proof, and
gate reconciliation. This brief turns the closed Stage A design into an ordered,
mechanically executable batch. **Every architectural decision is already made —
here, in `phase-1-stage-a.md`, and in ADR-0002 / ADR-0007 / ADR-0008. Make no
architectural judgment calls. If a task appears to need one that is not written
down, STOP and report rather than improvise.**

- Author: architectural lead (Javier Roldán Ortiz)
- Implementer: OpenAI Codex
- Branch: `modernization/phase-1-action-registry`
- Baseline HEAD: `fbc6949` (Stage B commit 1 — typed contracts — already landed)
- Design baseline: `4bcba55`; governing ADR `ADR-0002` (Accepted); supporting
  `ADR-0007`, `ADR-0008`
- Authoritative Stage B sequence: `phase-1-stage-a.md` §12

---

## 0. Operating rules (read once, apply to every task)

**Green baseline.** At `fbc6949`, `bin/test` is green: **430 core tests + 2
template tests**. Run `bin/test` (never bare `pytest`; it uses the repo `.venv`)
after every task. The suite must stay green and only grow — no existing test may
be deleted, skipped, or weakened. Record the before/after counts in each commit
body.

**One commit per task**, using the exact commit subject given in each task.
Inspect before editing: line numbers in this brief were true at `fbc6949` but the
file shifts as you work — re-grep the symbol, do not trust a stale line number.

**Fixtures are frozen.** Do **not** edit, regenerate, or delete any file under
`tests/fixtures/legacy_contracts/` to make a test pass. If a byte pin, count pin,
or normalized-exact result comparison fails, that is a real regression — STOP and
report. A deliberate fixture change requires a `contract-changes.md` ledger row
plus operator sign-off (D-6); it is never a way to get to green.

**Guardrails (architecture.md §4 + §12 non-goals).** No database, no new report
engine, no RBAC/ABAC engine, no MCP SDK adoption, no compact public surface, no
new adapters, no AGENTS/skills restructuring, no autonomous loop, no broad
rewrite. No Authority Grants, no durable authority enforcement, no publicly
exposed generic action execution, no legacy-removal date, **no migration beyond
the six-action slice.** Keep changes small and legible; extend existing helpers
rather than inventing abstractions. Never commit real client data — fictional
placeholders only (e.g. `app.acme-demo.test`). Redaction happens only at the
report boundary, which this brief does not touch.

**The load-bearing invariant (ADR-0002).** Every protocol call for a migrated
action routes through `ActionRegistry.execute()`, which runs the policy evaluator
before the executor. In Phase 1 that evaluator is an explicit **compatibility
pass-through**: it enforces nothing new. The wrapped legacy implementation keeps
its existing confirm/scope/credential gates and remains authoritative. Every
policy is `DECLARED_NOT_ENFORCED`. Do not make the registry look like an authority
engine.

**Public behaviour is unchanged.** Phase 1 changes no tool name, schema bytes,
protocol version, error code, message text, authority behaviour, or storage
format. The Tier-1 (`tools_list.json`, 174 count, 99,337 compact bytes) and
Tier-2 result fixtures are the proof. The one exception is the `jobs.status`
`-32003` message variant that Phase 1 *freezes without altering* — already landed.

### Execution order and rationale

Strict dependency order; the recorded gates come first because they currently
forbid Stage B from proceeding at all.

1. **Task 1 — Reconcile the recorded phase gates.** Governance precondition.
2. **Task 2 — Action registry, consistency checks, architecture tests** (Stage B
   commit 2; "P1-B-2"). Everything downstream imports the registry.
3. **Task 3 — Project the six-action vertical slice from the registry** (Stage B
   commit 3). Needs the registry.
4. **Task 4 — Prove vertical-slice contract equivalence** (Stage B commit 4).
   Needs the descriptors and projection to assert against.
5. **Task 5 — Document the action migration pattern** (Stage B commit 5).
   Describes what Tasks 2–4 built.

### What already landed (do not rebuild or duplicate)

- `app/actions/{identity,contracts,descriptor,outcomes,policies}.py` and their
  `__init__.py` exports — the full 14-field `ActionDescriptor` and the seven
  outcomes. `tests/test_action_contracts.py` pins them.
- `test_jobs_status_timeout_message_variant_is_frozen` (D-5),
  `test_required_confirm_omission_contract_for_all_tools`,
  `test_fixture_inventory_is_pinned` — in `tests/test_legacy_contracts.py`.
- Fixtures `confirm_omission.json`, the `jobs.status` `-32003` case in
  `errors.json`, `cors_execute_test_unconfirmed.json`, `crawler_crawl_unconfirmed.json`,
  `crawler_crawl_out_of_scope.json`, and the six slice result fixtures.

**Build against the landed API, not the Stage A prose sketch.** The landed policy
submodels are leaner than §4's illustrative snippet — there is no
`ScopePolicy.target_fields`, no `CredentialPolicy.reference_fields`; the
idempotency field is `IdempotencyPolicy.behaviour` (not `mode`), `Availability`
carries `available: bool` + `reason` (not `state`), and `InputContractDocument`
holds a single `source: str` (not `json_bytes`/`sha256`). `make_input_model` takes
`(name, document)`. `outcome_from_mcp_error(exc, *, confirm_declared, confirm_value)`
already exists — reuse it; do not reimplement the reverse map.

---

## Task 1 — Reconcile the recorded phase gates

**Commit:** `docs(modernization): promote phase 0 gate and open stage B`

### FILES
- `docs/modernization/phase-0-handoff.md`
- `docs/modernization/phase-1-stage-a.md` (status/precondition header only)
- `docs/modernization/contract-changes.md`
- `docs/modernization/README.md`

### PROBLEM / WRONG BEHAVIOR
The documented gates contradict the tree. `phase-0-handoff.md` records
**Recommended gate: CONDITIONAL** and a **"Run reference: _to be backfilled_"**
line for the Python 3.10–3.13 matrix. `phase-1-stage-a.md` header says Stage B
**"requires both this approval and the Phase 0 program gate"** and is **"awaiting
checkpoint approval."** `contract-changes.md` carries three fixture rows at
**"pending checkpoint approver"** and an ADR-0002 amendment row at **"pending
operator sign-off."** Yet Stage B commit 1 (`fbc6949`, typed contracts) has
already landed on this branch, and Tasks 2–5 below continue Stage B. The gates
must be reconciled before more Stage B work lands, or the program's own audit
trail is false.

### WHY IT MATTERS
The gate records and the contract-change ledger are the modernization program's
integrity mechanism: they are what let a later phase prove compatibility against
evidence rather than assertion. Leaving them stale while Stage B proceeds
silently defeats that mechanism and makes every downstream "passing" gate
unauditable. A `pending` approver also literally blocks merge by the ledger's own
rule.

### EXPECTED BEHAVIOR
The operator (architectural lead **Javier Roldán Ortiz**) has decided to
**promote**. Apply exactly that decision; invent nothing.

1. **`phase-0-handoff.md` — retire the backfill placeholder honestly.** Replace
   the "Known limitations" bullet's **"Run reference: _to be backfilled_ …"**
   sentences with a statement of the evidence of record: the operator's local
   3.10–3.13 full-matrix attestation dated 2026-07-30 is the evidence; **no remote
   CI run URL exists or is expected, because remote CI is deliberately deferred
   for this project.** Do not imply a URL is forthcoming. Keep the two genuine
   shape-assertion caveats (`jobs.status(includeResult=True)`, generic `-32000`)
   unchanged.
2. **`phase-0-handoff.md` — promote the gate.** Change **Recommended gate:
   CONDITIONAL** to **PASS**, and rewrite the paragraph beneath it so it states
   the gate is promoted on the recorded local compatibility/determinism/benchmark
   evidence plus the operator's matrix attestation and checkpoint sign-off, with
   remote CI explicitly out of scope by decision. Leave every green verification
   row and measurement intact.
3. **`phase-1-stage-a.md` header (lines ~3–12).** Update the precondition and
   **Status** lines to record that the Phase 0 program gate is **PASS** and the
   Stage A checkpoint is **approved** by Javier Roldán Ortiz on the reconciliation
   date, so Stage B is cleared. Do not touch the technical body (§1–§12,
   Appendix A).
4. **`contract-changes.md`.** Replace all three **"pending checkpoint approver"**
   fixture-row approvers and the ADR-0002 amendment row's **"pending operator
   sign-off"** with **Javier Roldán Ortiz**. Add one new row recording this
   reconciliation itself: that Stage B commit 1 (`fbc6949`) landed as a code-only
   change with no public-surface delta, ratified under this promotion.
5. **`README.md`.** Update the Phase 1 line that says Stage B "is gated on its
   approval and the Phase 0 program gate" to reflect that both are now satisfied.

Use the reconciliation date consistently (the date you run the task). Do not
alter any ADR body, any test, or any fixture in this task.

### REGRESSION TESTS
- `bin/test --core -k modernization_docs` stays green. If a doc guard
  (`test_modernization_docs.py`) asserts specific gate wording, update the guard
  to the promoted wording in this same commit and note it in the commit body;
  if a guard instead forbids absolute paths / planted canaries / non-fixture
  hosts, keep satisfying it (introduce none).
- `bin/test` remains green (430 + 2). This task adds no production code.

### NON-GOALS
Do not promote or re-status any Proposed ADR (0003–0008 stay Proposed). Do not
stand up remote CI. Do not touch the separately-tracked Phase 0 integrity
prerequisite noted for Phase 2, or the safe-report `credential_metadata` follow-up
— neither is in scope here. Do not begin Task 2 work in this commit.

---

## Task 2 — Action registry, consistency checks, and architecture tests

**Commit:** `refactor(core): add action registry and consistency checks`

### FILES
- `MCPS/Synapse-MCP/synapse_mcp/app/actions/registry.py` (new)
- `MCPS/Synapse-MCP/synapse_mcp/app/actions/packs/__init__.py` (new; empty
  registration surface for now — pack modules arrive in Task 3)
- `MCPS/Synapse-MCP/synapse_mcp/app/actions/__init__.py` (export the registry)
- `MCPS/Synapse-MCP/tests/test_action_registry.py` (new)
- `MCPS/Synapse-MCP/tests/test_architecture_boundaries.py` (new)

### PROBLEM / WRONG BEHAVIOR
The typed contracts exist but nothing registers or dispatches them, and no test
pins the `app/ ⇏ transport/` import boundary that ADR-0002 and ADR-0007 declare.
Without a registry that fails loudly at import time, inconsistent descriptors
would only surface as runtime surprises, and the boundary could silently reverse.

### WHY IT MATTERS
The registry is the single dispatch entry that guarantees policy evaluation
cannot be bypassed (ADR-0002) and the place where a malformed descriptor becomes a
startup/test failure instead of a production incident. The import-boundary test is
the only thing preventing the application layer from re-acquiring a hard JSON-RPC
dependency, since Python cannot make that edge structurally impossible.

### EXPECTED BEHAVIOR

**`ActionRegistry`** (a class; module also exposes one process-wide instance,
e.g. `REGISTRY`). It stores descriptors keyed by `str(descriptor.id)`.

`register(descriptor)` runs the §6 consistency checks and **raises at
registration/import time** (a `ValueError`, message naming the offending id) on
any of:
1. duplicate `ActionId` (same `str(id)` already registered);
2. `descriptor.pack != descriptor.id.pack`;
3. `descriptor.input_model` is not a subclass of `ActionInput`, or
   `descriptor.output_model` is not a subclass of `ActionOutput`;
4. `descriptor.executor` is not callable, or its `input_model` / `output_model`
   properties are not **identically** `descriptor.input_model` /
   `descriptor.output_model` (`is`, not `==`);
5. `descriptor.scope_policy.requirement is ScopeRequirement.REQUIRED` while
   `descriptor.side_effect_class` is `READ_ONLY` or `REPORT_BUILD`;
6. `descriptor.side_effect_class is ACTIVE_PROBE` but not all of:
   `risk_class in {MODERATE, HIGH}`, `scope_policy.requirement is REQUIRED`, and
   `idempotency_policy.behaviour is NON_IDEMPOTENT`;
7. `descriptor.scope_policy.enforcement is ENFORCED_BY_EXECUTOR` or
   `descriptor.credential_policy.enforcement is ENFORCED_BY_EXECUTOR` (Phase 1
   forbids `ENFORCED_BY_EXECUTOR`). Note only these two submodels carry an
   `enforcement` field; `IdempotencyPolicy` and `TaskPolicy` do not — do not
   invent one.

   The eighth Stage A check ("`availability=unavailable` without a reason") is
   **already guaranteed at construction** by `Availability.__post_init__`; do not
   add a redundant registry check for it and do not claim a test for an
   unconstructable state.

`execute(request)` is the **only** supported dispatch entry:
- Resolve the descriptor for `request` (carry the target `ActionId`/name on the
  request path however is cleanest internally — the registry, not the caller,
  looks up the descriptor).
- Invoke the **policy evaluator**, then the executor. The evaluator is a Phase 1
  **pass-through**: implement it as a named, replaceable seam
  (e.g. `PassThroughPolicyEvaluator`) that returns "allow" for every request and
  enforces nothing. Its existence — not its logic — is what satisfies the
  no-bypass invariant. Protocol projections must be unable to reach an executor
  except through `execute()`.
- Return the executor's `ActionOutcome` unchanged.

`get(action_id)` / `descriptors()` accessors for projection and tests. Packs are
declared in `app/actions/packs/*.py` and registered when the `packs` package is
imported; `packs/__init__.py` imports each pack module for its
side-effect registration. In this task `packs/` is empty (no modules yet), so the
registry is empty at import — that is expected.

**Architecture tests** (`test_architecture_boundaries.py`):
- `test_application_layer_has_no_transport_imports`: walk every `*.py` under
  `synapse_mcp/app/` with `ast`; collect all `Import` / `ImportFrom` targets
  **including imports nested inside function/method bodies**; assert none resolves
  to `synapse_mcp.transport` (nor a relative import that lands there). Resolve
  relative imports against each module's package so `from ..transport import x` is
  caught.
- `test_core_and_adapters_do_not_import_app_or_transport`: same AST walk over
  `synapse_mcp/core/` and `synapse_mcp/adapters/`; assert none imports
  `synapse_mcp.app` or `synapse_mcp.transport`. Pins today's true direction so
  Phase 1 cannot quietly reverse it.

**Registry tests** (`test_action_registry.py`) — use tiny in-test descriptors
built from trivial `make_input_model` documents and stub executors; do **not**
depend on the Task 3 packs:
- `test_duplicate_action_id_fails_registration`;
- one test per §6 check (2–7) asserting `register()` raises with a message naming
  the id — including a valid `active_probe` descriptor registering cleanly and
  each individually-broken variant raising;
- `test_action_ids_are_well_formed_pack_and_local_name`: registering an id whose
  `pack != id.pack` raises; well-formed ids (including a three-segment
  `pack.session_key.set` local name) register;
- `test_execute_routes_through_policy_evaluator_before_executor`: a spy evaluator
  and spy executor prove the evaluator is called first and the executor is
  unreachable without it;
- `test_registry_pack_count_matches_registered_actions`: with N stub actions
  across K packs, `packs()`/pack-count equals K. **Do not** assert 40 — see below.

**Deferred, decided here so you don't hit the wall:** ADR-0008's
`test_registry_has_forty_canonical_packs` and the "registry contains exactly 40
packs" invariant describe the **fully migrated** surface. Phase 1 registers only
the six-action slice (five packs — see Task 3), so a 40-pack assertion is false in
Phase 1 by construction. Assert the actual registered pack count instead; leave a
`# deferred until full migration (ADR-0008)` comment at the pack-count test.

### REGRESSION TESTS
Named above. `bin/test` green; suite grows by the new registry/architecture
tests. `test_action_contracts.py` still passes unchanged (the 14-field descriptor
is untouched).

### NON-GOALS
No pack modules, no descriptors for real tools, no transport wiring, no schema
projection in this task. Do not add fields to `ActionDescriptor` or any policy
submodel (`test_descriptor_has_exactly_the_fourteen_fields` pins the field list).
The pass-through evaluator enforces nothing — do not add real authority/scope/
credential checks (that is ADR-0003, Phase 2).

---

## Task 3 — Project the six-action vertical slice from the registry

**Commit:** `refactor(mcp): project legacy vertical slice from registry`

### FILES
- `MCPS/Synapse-MCP/synapse_mcp/app/actions/packs/jobs.py` (new)
- `MCPS/Synapse-MCP/synapse_mcp/app/actions/packs/workspace.py` (new)
- `MCPS/Synapse-MCP/synapse_mcp/app/actions/packs/headers_cookies.py` (new)
- `MCPS/Synapse-MCP/synapse_mcp/app/actions/packs/cors.py` (new)
- `MCPS/Synapse-MCP/synapse_mcp/app/actions/packs/crawler.py` (new)
- `MCPS/Synapse-MCP/synapse_mcp/app/actions/packs/__init__.py` (import the five)
- `MCPS/Synapse-MCP/synapse_mcp/transport/projection.py` (new)
- `MCPS/Synapse-MCP/synapse_mcp/transport/legacy_projection_map.py` (new)
- `MCPS/Synapse-MCP/synapse_mcp/transport/stdio_server.py` (wire the seam)

### PROBLEM / WRONG BEHAVIOR
Six actions are still reached only through the hand-written `_call_tool_impl`
name-dispatch and inline `TOOL_SCHEMAS` literals. Nothing proves the descriptor
can be the single source for schema, metadata, dispatch, and outcome projection
end-to-end.

### WHY IT MATTERS
The vertical slice is the proof-of-mechanism for the entire 174-action migration:
if a descriptor cannot reproduce the frozen surface byte-for-byte for six real
actions spanning both serializer shapes and all four outcome-relevant gates
(none / approval / scope / passive-recording), the pattern is not safe to repeat.
This slice is exactly what makes Task 5's migration guide real rather than
aspirational.

### EXPECTED BEHAVIOR

**The six actions, with their exact legacy wiring** (from `_call_tool_impl` at
`fbc6949`; re-grep to confirm before editing). Serializer "transport" means the
branch returns `json.dumps(<dict>, indent=2)`; "executor" means the callable
already returns a pre-serialized string.

| Action id | Pack / local | Legacy callable (import source) | Serializer | Effect / risk / scope / idem | confirm | passive-rec | deadline |
| --- | --- | --- | --- | --- | :-: | :-: | --- |
| `jobs.status` | jobs / status | `background_jobs.status(jobId, includeResult)` (`core.background_jobs`) | transport | read_only / none / n-a / pure_read | no | no | STATUS |
| `workspace.summary` | workspace / summary | `workspace.workspace_summary(workspaceId, cursor=, limit=50, include_inventory=False)` (`core.workspace`) | transport | read_only / none / n-a / pure_read | no | no | DEFAULT |
| `workspace.prepare_target_context` | workspace / prepare_target_context | `workspace.prepare_target_context(workspaceId, target, purpose="next_step_planning", maxTokens=1500)` (`core.workspace`) | transport | read_only / none / n-a / pure_read | no | no | DEFAULT |
| `headers_cookies.analyze_workspace` | headers_cookies / analyze_workspace | `headers_cookies.analyze_workspace(args)` (`adapters.web.headers_cookies`) | executor | passive_analysis / none / n-a / pure_read | no | **yes** | DEFAULT |
| `cors.execute_test` | cors / execute_test | `cors.execute_test(args)` (`adapters.web.cors`) | executor | active_probe / moderate / **required** / non_idempotent | **yes** | no | DEFAULT |
| `crawler.crawl` | crawler / crawl | `crawler_adapter.crawl(args)` (`adapters.web.crawler_adapter`) | executor | active_probe / moderate / **required** / non_idempotent | **yes** | no | DEFAULT (background_capable) |

Credential policy for the two `active_probe` actions and `headers_cookies` follows
Appendix A: `cors.execute_test` and `crawler.crawl` are `requirement=optional`,
`access=credential_use`; the read/passive actions are `none`/`none`. Every policy
`enforcement=DECLARED_NOT_ENFORCED`. `crawler.crawl` sets
`TaskPolicy.background_capable=True`; the others `False`. Only
`headers_cookies.analyze_workspace` sets `passive_recordable=True`.

**Descriptor + models per action (in the pack module):**
- `InputContractDocument(source=<exact inputSchema JSON of that tool>)`. The
  `source` string must be the tool's current `inputSchema` **verbatim** — same
  keys, same order, same values as the `TOOL_SCHEMAS` entry at `fbc6949` — because
  it becomes the single source for both the Pydantic model and the projected
  `inputSchema`. Build the model with `make_input_model("<Pack><Local>Input", doc)`.
- `output_model`: a per-action `ActionOutput` subclass with
  `model_config = ConfigDict(extra="allow")`. It exists to satisfy the descriptor
  and the executor-identity check; **it is not used to re-serialize output** (see
  the fidelity rule below).
- `executor`: an object exposing `input_model` / `output_model` properties
  (returning those exact classes) and `__call__(request) -> ActionOutcome`. It:
  1. computes the legacy arguments from `request.input.model_dump(by_alias=True,
     exclude_unset=True)` — `exclude_unset` is required so omitted-vs-supplied is
     preserved and defaults still execute at their existing layer (transport
     `maxTokens=1500`; adapter `maxCandidates=100`), never duplicated in the model;
  2. calls the **exact** legacy callable above with the **same** argument
     adaptation the legacy branch used (same defaults, same `int()`/`bool()`
     coercions, same keyword names);
  3. on success, returns `Success(payload=<the raw legacy result>,
     payload_signals_error=_tool_result_has_error(<serialized form>))`;
  4. wraps the legacy call in `try/except McpError` and returns
     `outcome_from_mcp_error(exc, confirm_declared=<True only for cors/crawler>,
     confirm_value=request.input... )` so a translated error carries `legacy_code`
     verbatim. `confirm_declared` is `True` exactly for the two actions whose
     schema declares `confirm` (`cors.execute_test`, `crawler.crawl`).

   Import the legacy callables from `core`/`adapters` (per the table). **Never
   import from `synapse_mcp.transport`** — that would break
   `test_application_layer_has_no_transport_imports`. `_tool_result_has_error` and
   the `indent=2` serialization are transport concerns; keep them on the transport
   side of the seam (below), not in the pack module — the executor may return the
   raw dict/string and let the projection compute the flag and serialize.

**`legacy_projection_map.py` (transport-owned).** A mapping, per migrated action,
of: legacy public name (identical to `str(id)` here, but stored explicitly — never
derived), and the serializer choice (`"transport"` or `"executor"`). This is the
only place protocol-specific facts live. No schema literal here.

**`projection.py` (transport-owned).** Exposes:
- `project_call(name, args) -> str | None`: returns `None` if `name` is not a
  migrated action. Otherwise: build the validated input via
  `descriptor.input_model.model_validate(args)`; build `ExecutionContext`
  (`workspace_id=args.get("workspaceId")`, a fresh `correlation_id`,
  `deadline_seconds=_tool_deadline_seconds(name, args)`,
  `legacy_approval_asserted=` the caller's `confirm` value or `None`); call
  `REGISTRY.execute(ActionRequest(input, context))`; then:
  - `Success` → serialize per the map: `"transport"` →
    `json.dumps(outcome.payload, indent=2)`; `"executor"` → `outcome.payload`
    (already a string) verbatim. Return that string.
  - any error outcome → `raise McpError(outcome.legacy_code, outcome.message)` so
    the existing `handle()` `except McpError` emits the **identical** wire
    envelope. (`legacy_code` is never `None` for a translated error.)
  - `ExecutionUnknown` cannot occur here — it is only constructed by the transport
    timeout path, which runs in `call_tool_with_deadline` before any outcome.
- `resolved_input_schema(name) -> dict`: for a migrated action, return
  `descriptor.input_model.contract_document.parsed()`; else the legacy
  `TOOL_SCHEMAS` literal.
- `projected_tools_list() -> list[dict]`: the 174 ordered tool entries with each
  migrated entry's `inputSchema` sourced from the descriptor and every other entry
  from the legacy literal, preserving order, `name`, and `description`.

**Single source — remove the duplicate schema literal (ADR-0002 verification).**
For the six migrated tools, the `inputSchema` must live **only** in the
descriptor's `InputContractDocument`. Edit the seam so the transport no longer
keeps a second copy:
- `tools/list` returns `projected_tools_list()` rather than raw `TOOL_SCHEMAS`.
- `validate_tool_arguments(name, args)` resolves the schema via
  `resolved_input_schema(name)` so validation for migrated tools reads the
  descriptor's schema (keeping the legacy validator first and authoritative, with
  its required-`confirm` skip and leading-underscore rejection intact).
- `_call_tool_impl(name, args)`: as the very first statement,
  `projected = projection.project_call(name, args); if projected is not None:
  return projected`. Leave the six legacy branches in place beneath it as the
  rollback path (they become unreachable for the migrated names while registered —
  that is the intended, reversible transitional state; rollback for any action is
  to drop it from the projection map).

**Byte-equality is the gate, not the goal.** Because each `source` is the verbatim
frozen `inputSchema`, `parsed()` yields an equal ordered dict and the compact
projection reproduces 99,337 bytes. If `tools_list.json` byte/count pins do **not**
match after wiring, STOP and report — do not touch the fixture.

**Recording is preserved for free.** `call_tool` still calls
`_record_passive_analysis_action` on the returned string, and `project_call`
returns the identical legacy string for `headers_cookies.analyze_workspace`, so
passive recording is byte-for-byte unchanged. Do not move recording into the
registry.

### REGRESSION TESTS
- All six §8.3 result fixtures still pass through the existing
  `test_legacy_result_contracts.py` (normalized-exact), now exercising the
  registry path via `stdio_server.handle`: `workspace_summary`,
  `workspace_prepare_target_context`, `headers_cookies_analyze_workspace`,
  `cors_execute_test_disabled_traffic`, `cors_execute_test_unconfirmed` (`-32001`),
  `crawler_crawl_background_submitted`, `crawler_crawl_unconfirmed` (`-32001`),
  `crawler_crawl_out_of_scope` (`-32002`), `jobs_status_terminal`. If any needs a
  new invocation added to the existing test module, add it there; do not add a new
  fixture.
- `tools_list.json` byte + 174-count pins pass unchanged.
- `test_projection_map_covers_every_migrated_action_and_preserves_legacy_names`
  (new): the map covers exactly the six ids; each stored legacy name equals the
  frozen tool name; and for each, `resolved_input_schema(name)` deep-equals the
  frozen `TOOL_SCHEMAS` `inputSchema` **and** no residual `inputSchema` literal for
  that tool remains in the raw transport list (proves no duplicate).
- `bin/test` green; the packs import and register five packs / six actions
  (extend the Task 2 pack-count test or assert it here).

### NON-GOALS
Do not migrate a seventh action. Do not change any legacy callable, default, or
argument order. Do not re-serialize output through `model_dump` (that reorders
keys and breaks the normalized-exact/`indent=2` contract — serialize the raw
legacy result). Do not fix `isError` being hard-coded `false` (Phase 3). Do not
add real policy enforcement.

---

## Task 4 — Prove vertical-slice contract equivalence

**Commit:** `test(mcp): prove vertical-slice contract equivalence`

### FILES
- `MCPS/Synapse-MCP/tests/test_slice_projection_contracts.py` (new; or extend
  `test_legacy_contracts.py` if that reads more naturally — keep the already-landed
  tests there untouched either way)

### PROBLEM / WRONG BEHAVIOR
The slice runs, but nothing yet pins the descriptor-derived facts against legacy
for the whole surface, so a future descriptor edit could drift deadlines,
recordability, validation semantics, or error projection without failing a test.

### WHY IT MATTERS
These are the tests that let actions 7–174 migrate mechanically: each proves a
descriptor-derived value equals the frozen legacy behaviour, so a wrong migration
fails loudly instead of shipping a behavioural change inside a "structural" phase.

### EXPECTED BEHAVIOR
Add exactly the owed tests (do **not** duplicate the already-landed
`test_jobs_status_timeout_message_variant_is_frozen`,
`test_required_confirm_omission_contract_for_all_tools`, or
`test_fixture_inventory_is_pinned`):

- `test_descriptor_deadline_matches_legacy_for_all_tools`: for every one of the
  174 names in `TOOL_SCHEMAS`, assert `_tool_deadline_seconds(name, {})` equals the
  pure name-based expectation (`30.0` if `name == "jobs.status"`, else `15.0` if
  `name in FAST_TOOLS`, else `45.0`). Separately assert each of the six migrated
  descriptors' `task_policy.deadline_tier.value` equals that expectation for its
  name. This closes the 23 `FAST` tools now even though none is in the slice.
- `test_passive_recording_unchanged_for_the_fifteen_recordable_tools`: assert
  `_is_recordable_passive_analysis_tool` returns `True` for exactly the 15 frozen
  tools and `False` elsewhere across the 174; and that each migrated descriptor's
  `task_policy.passive_recordable` equals `_is_recordable_passive_analysis_tool`
  for its name (True only for `headers_cookies.analyze_workspace`).
- `test_slice_input_models_match_legacy_runtime_validation_semantics`: for the six
  input models, assert non-coercion (integer strings rejected), permissive unknown
  public fields, leading-underscore rejection, `confirm` runtime-optional for the
  two that declare it, and the omitted-field defaults executing at the legacy layer
  (`maxTokens` → 1500 for `workspace.prepare_target_context`; `maxCandidates` → 100
  for `headers_cookies.analyze_workspace`).
- `test_outcome_projection_preserves_legacy_error_taxonomy`: drive the migrated
  actions through `handle` (or `project_call`) for the frozen `-32001`/`-32002`
  cases and assert the emitted `{code, message}` equals the legacy fixture — i.e.
  the translated outcome's `legacy_code`/message round-trips verbatim. Reuse the
  `cors_execute_test_unconfirmed`, `crawler_crawl_unconfirmed`, and
  `crawler_crawl_out_of_scope` fixtures.

### REGRESSION TESTS
The four tests above, all green, plus the full suite green. Each test derives its
expectation from the frozen surface / fixtures, never from a value you typed by
hand.

### NON-GOALS
No new fixtures (every needed fixture already exists). Do not re-freeze anything
Phase 0 owns. Do not assert a 40-pack registry (deferred). Do not weaken any check
to accommodate a descriptor — if a descriptor and legacy disagree, the descriptor
is wrong; fix it in the Task 3 files (and note it), never the test.

---

## Task 5 — Document the action migration pattern

**Commit:** `docs(modernization): document action migration pattern`

### FILES
- `docs/modernization/action-migration-pattern.md` (new)
- `docs/modernization/README.md` (add a pointer under Phase 1)

### PROBLEM / WRONG BEHAVIOR
The six-action slice encodes a repeatable procedure, but it lives only in code and
this brief. Actions 7–174 need a written contributor guide or the pattern will be
re-derived (and drift) at each migration.

### WHY IT MATTERS
The migration guide is the deliverable that lets the rest of the surface move
without re-litigating the architecture each time — it is what turns a proven slice
into a program.

### EXPECTED BEHAVIOR
Write a concise contributor guide that captures the **now-proven** pattern, citing
the real files from Tasks 2–3. Cover, in order:
1. Choose the `ActionId` (split once at first dot; assign the two dotless orphans
   to `social` / `purple_team`; three-segment locals stay whole) — ADR-0008.
2. Author the `InputContractDocument` from the verbatim frozen `inputSchema`;
   generate the model with `make_input_model`.
3. Declare the descriptor: fill the five judgment columns from Appendix A's ordered
   rules (never from the tool name); every policy `DECLARED_NOT_ENFORCED`.
4. Write the executor wrapping the exact legacy callable; success →
   `Success(payload_signals_error=...)`, `McpError` → `outcome_from_mcp_error`.
5. Add the `legacy_projection_map` row (legacy name + serializer). Remove the
   duplicate `inputSchema` literal so the descriptor is the single source.
6. Prove it: which fixture(s) gate the action; run the all-174 deadline and
   passive-recording pins; `bin/test` green.
7. Rollback: drop the action from the projection map to restore the legacy branch;
   no storage or public-name involvement.

State the standing guardrails (no authority enforcement yet; no output
re-serialization via `model_dump`; fixtures are frozen; one action per commit) and
note the two items deferred to full migration: the 40-pack invariant and physical
retirement of legacy dispatch branches. Keep it to a couple of pages; link
`phase-1-stage-a.md` and the ADRs rather than restating them.

### REGRESSION TESTS
`bin/test --core -k modernization_docs` green (satisfy the doc guards: no absolute
paths, no planted canary, no non-fixture hosts). No production code changes.

### NON-GOALS
Do not migrate any action in this task. Do not set a legacy-removal date. Do not
document Phase 2+ mechanisms (Authority Grants, compatibility profiles, budgets,
storage) beyond a one-line "next" pointer.

---

## Definition of done (session-wide)

- Tasks 1–5 committed in order, one commit each, with the given subjects.
- `bin/test` green after every task; final suite ≥ 432 tests, growing only by the
  new registry/architecture/slice tests; nothing deleted, skipped, or weakened.
- Tier-1 `tools_list.json` (174 count, 99,337 compact bytes), `errors.json`,
  `confirm_omission.json`, and all six slice Tier-2 result fixtures pass unchanged.
- The six actions dispatch through `ActionRegistry.execute()`; their `inputSchema`
  has exactly one home (the descriptor); the `app/ ⇏ transport/` boundary is
  test-enforced.
- Gate records, the contract-change ledger, and README reflect the promotion, with
  Javier Roldán Ortiz named as approver.
- No guardrail crossed: no DB/engine/framework, no authority enforcement, no
  seventh action, no fixture edited to reach green.

**Standing instruction:** if any task cannot be completed within its Non-Goals, or
a fixture pin fails in a way that looks like it "just needs" a fixture edit, STOP
and report with the specific diff and failing pin. Do not improvise across a
guardrail.
