# Modernization contract-change ledger

This ledger makes every legacy fixture addition, removal, or content change
review-visible. `same commit` is the canonical reference for an atomic fixture
and ledger update because a Git commit cannot contain its own hash. A `pending`
approver blocks merge; replace it with the named checkpoint approver during
approval.

| Fixture | Change reference | Classification | Justification | Approver |
| --- | --- | --- | --- | --- |
| `MCPS/Synapse-MCP/tests/fixtures/legacy_contracts/errors.json` | same commit | exact | Adds the previously unfrozen existing `jobs.status` timeout-message variant; all prior cases remain byte-identical. | pending checkpoint approver |
| `MCPS/Synapse-MCP/tests/fixtures/legacy_contracts/confirm_omission.json` | same commit | exact | Freezes the current outcomes for all 44 schemas whose required list contains `confirm`: 42 approval errors and two successful dry-run cache cleanups. | pending checkpoint approver |
| `MCPS/Synapse-MCP/tests/fixtures/legacy_contracts/results/cors_execute_test_unconfirmed.json` | same commit | exact | Adds the missing `-32001` approval fixture for the CORS operation in the Phase 1 vertical slice. | pending checkpoint approver |

## Amendments to Accepted ADRs

An Accepted ADR is a binding standard that later work is judged against. Amending
one in place can make any review passable, so every amendment is recorded here
and requires the operator's sign-off — the same bar as a fixture change.

| ADR | Change reference | What changed | Justification | Approver |
| --- | --- | --- | --- | --- |
| `adr/ADR-0002-typed-core-action-registry.md` | same commit | Decision gained the `InputContractDocument` single-source rule; the invariant "An executor cannot bypass policy evaluation" restated as routing through `ActionRegistry.execute()` with an explicit Phase 1 compatibility pass-through. | Independent review of Phase 1 Stage A found the original invariant unaddressed (MEDIUM-6) and the schema-literal home self-contradictory (BLOCKER-2). The restatement is narrower and more honest: it names the enforcement point and states plainly that Phase 1 enforces nothing, rather than implying policy is already evaluated. | pending operator sign-off |
