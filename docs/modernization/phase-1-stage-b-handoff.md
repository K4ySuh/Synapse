# Phase 1 Stage B Handoff

> Historical gate record. The 2026-08-09 correction gate supersedes the
> input-model uniqueness workaround, singular effect metadata, descriptive-only
> outputs, and crash-atomic-only credential locking described below. Current
> authority is ADR-0009 and `correction-gate-handoff.md`; the legacy wire
> compatibility evidence in this document remains valid.

## Identity

- Phase: 1 — Action Registry; Stage B (registry and the six-action vertical
  slice)
- Branch: `modernization/phase-1-action-registry`
- Design baseline: `4bcba55`; governing ADR: ADR-0002 (Accepted)
- Stage B commits: seven, `fbc6949` (typed contracts) through `33691ff`
  (adversarial-review remediation)
- Implementer/model: OpenAI Codex
- Independent review and verification: architectural lead (Javier Roldán Ortiz)
- Date: 2026-08-07

## Objective

Prove, on six real actions spanning both serializer shapes and all four
outcome-relevant gates (none, approval, scope, passive-recording), that a typed
`ActionDescriptor` can be the single source for schema, dispatch, metadata, and
outcome projection — reproducing the frozen legacy surface byte-for-byte and
routing every migrated call through `ActionRegistry.execute()` — without changing
any observable behaviour. This is the proof-of-mechanism that the remaining
migration and the Phase 2 authority work build on.

## Delivered

- A typed application action layer under `app/actions/`: identity, contracts,
  descriptor, outcomes, and policies (Stage B commit 1), plus the
  `ActionRegistry`, its registration consistency checks, and the
  `PassThroughPolicyEvaluator` seam that makes policy evaluation unbypassable
  while enforcing nothing in Phase 1.
- The six-action slice projected from descriptors: `jobs.status`,
  `workspace.summary`, `workspace.prepare_target_context`,
  `headers_cookies.analyze_workspace`, `cors.execute_test`, and `crawler.crawl` —
  five packs, six descriptors.
- The transport seam `transport/projection.py` and
  `transport/legacy_projection_map.py`; `stdio_server` routes `tools/list`,
  `validate_tool_arguments`, and `_call_tool_impl` through the projection, with
  each migrated `inputSchema` removed from the renamed `_LEGACY_TOOL_SCHEMAS` so
  the descriptor is its single home.
- Contract-equivalence proof tests, and an AST-based import-boundary test pinning
  `app/ ⇏ transport/` and `core`/`adapters ⇏ app`/`transport`.
- The `action-migration-pattern.md` contributor guide.
- The reconciled Phase 0 gate (PASS) and contract-change ledger (Stage B Task 1).

## Explicitly not changed

- No public tool name, `inputSchema` bytes, protocol version, error code, message
  text, authority behaviour, or storage format changed.
- No file under `tests/fixtures/` was added, removed, or edited across the Stage B
  range.
- No new database, report engine, RBAC/ABAC engine, MCP SDK, adapter, or public
  generic-action-execution tool. Every policy is `DECLARED_NOT_ENFORCED`; the
  legacy confirm/scope/credential gates remain authoritative.
- The six legacy `_call_tool_impl` branches remain in place as the reversible
  rollback path.

## Adversarial review and remediation

The Stage B review brief (`phase-1-stage-b-review-brief.md`) was executed against
`fbc6949..66ca6a0` and its findings were closed in `33691ff` (446 → 450 core
tests). None altered an observable wire response; each is a latent-correctness or
test-soundness fix.

| Finding | Fix | Test |
| --- | --- | --- |
| `ActionRegistry.execute()` resolves the descriptor by input-model type, so two actions sharing an input-model class would dispatch ambiguously. | `register()` rejects a descriptor whose `input_model` class is already registered, as a loud registration-time `ValueError`. | `test_duplicate_input_model_fails_registration` |
| `Success.payload_signals_error` was left default in the executor and recomputed transport-side with `replace()`, so the application-layer outcome carried an untruthful signal. | `success_from_legacy_payload()` computes the signal at the application layer from the raw payload; `_tool_result_has_error` delegates to the same helper — one source. | `test_registry_success_preserves_legacy_payload_error_signal`, `test_legacy_success_payload_signal_handles_raw_and_serialized_results` |
| Rollback advice ("remove the map row") would also strip the descriptor-owned `inputSchema`, since one map fed both dispatch and schema projection — a public-surface break. | A separate `LEGACY_DISPATCH_ACTIONS` switch splits routing from schema ownership; disabling dispatch keeps the descriptor schema and legacy validation intact. | `test_dispatch_rollback_preserves_schema_and_legacy_validation` |
| The deadline pin derived its expectation from `stdio_server` itself, so it could not catch drift. | The expectation now derives from the Stage A design inventory table, and `FAST_TOOLS` is additionally pinned to that design. | `test_descriptor_deadline_matches_legacy_for_all_tools` (strengthened) |

## Independent verification (architectural lead)

Re-derived from the code and the frozen fixtures at `33691ff`, not from commit
messages.

| Check | Result |
| --- | --- |
| `bin/test` | PASS — 450 core and 2 template tests |
| Projected tool surface | 174 tools; 99,337 compact bytes; deep-equal and byte-identical to `tools_list.json` |
| Registry shape | 5 packs (`cors`, `crawler`, `headers_cookies`, `jobs`, `workspace`); 6 descriptors |
| Single-source schema | the six migrated tools carry no `inputSchema` in `_LEGACY_TOOL_SCHEMAS`; all six appear in the projected list |
| Fixture integrity | zero files under `tests/fixtures/` changed across `fbc6949..33691ff` or in `33691ff` |
| Scope | the range touches only `app/actions/`, the transport seam, tests, and docs |

## Measurements

| Metric | Stage A baseline | Stage B | Delta |
| --- | ---: | ---: | ---: |
| Tool count | 174 | 174 | 0 |
| Compact schema bytes | 99,337 | 99,337 | 0 |
| Core tests | 430 (at `fbc6949`) | 450 | +20 |

## Known limitations and deferred items

- The 40-pack canonical registry invariant (ADR-0008) and physical retirement of
  the legacy dispatch branches are deferred to full migration; Phase 1 registers
  five packs and six actions by construction.
- The safe-report `credential_metadata` auth table still renders credential IDs
  and usernames under `safe` mode. It remains a tracked follow-up against the
  future `client_export` boundary (DR-6), not a current-contract violation.
- A tracked Phase 0 integrity prerequisite must land before Phase 2 persists
  authority state.

## Risks for the next phase

- Phase 2 (Authority Grants, ADR-0003) must map its authority decisions onto the
  observable `-32001` approval and `-32002` scope taxonomy and onto the descriptor
  policy fields that Stage B declares but does not enforce, or explicitly supersede
  that contract.
- Migrating actions 7–174 would land many authority classifications while
  enforcement is off; those are only validated once Phase 2 turns enforcement on.
  Sequencing the bulk migration into or after Phase 2 lets real enforcement
  validate each classification instead of trusting it blind.

## Worktree status

After this handoff commit, tracked files are clean. The two Stage B briefs are now
tracked under `docs/modernization/`. The `Modernization/` planning and review pack
remains gitignored local source material and is not part of the committed phase
output.

## Recommended gate

PASS

Stage B changed no observable behaviour, its adversarial-review findings are
closed, and the surface is byte-identical on independent re-derivation. The gate
is promoted on that record and on Javier Roldán Ortiz's sign-off dated 2026-08-07.
The program advances to the Phase 2 track: land the tracked Phase 0 integrity
prerequisite, then open Authority Grants (ADR-0003) design. Bulk migration of
actions 7–174 is deferred so it can land into the enforced-authority shape.
