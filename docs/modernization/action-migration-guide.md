# Canonical action migration guide

This is the current contributor procedure for the complete canonical Action
Registry. It supersedes the Phase 1 one-action-at-a-time rule in
[`action-migration-pattern.md`](action-migration-pattern.md) without rewriting
the history that established the first six actions.

## Batch unit

Migrate a bounded, coherent capability pack or closely related pack group.
Every batch must remain reviewable and reversible through manifest accounting,
per-action contract rows, focused parity tests, and the retained legacy
implementation adapter. Do not combine unrelated refactors with a migration
batch.

For each action:

1. Start from the frozen `tools/list` fixture and its reviewed Appendix A row.
2. Preserve the explicit canonical ID and legacy alias, including the two
   dotless exceptions.
3. Generate the strict Pydantic input from the exact frozen JSON Schema and
   declare a distinct typed JSON-object output contract.
4. Record maximum/request-effective effects, risk, scope, credential access,
   task/deadline behavior, approval, availability, serializer ownership, and
   the exact retained implementation target.
5. Route execution through `ActionRegistry.execute()` before the implementation
   adapter. Application code must not import MCP transport types.
6. Keep the frozen implementation branch callable through the per-action
   dispatch switch until physical retirement receives a separate decision.

## Manifest accounting

`bin/generate-action-inventory` joins the frozen legacy fixture to the reviewed
Appendix A classifications and writes
`synapse_mcp/app/actions/action_inventory.json`. The checked-in manifest is the
ordered migration ledger and runtime source for generated descriptors and
legacy projections. Never edit it by hand.

Run `bin/generate-action-inventory --check` in CI and review its source diffs.
The inventory gate rejects missing or duplicate names/IDs, orphan descriptors,
pack mismatches, stale generated content, a total other than 174, or a compact
legacy payload other than 99,337 bytes.

## Parity and rollback

Each batch must prove:

- exact legacy names, order, descriptions, schemas, and compact payload;
- strict input validation and runtime-optional legacy `confirm` omission;
- result serialization and legacy error taxonomy;
- truthful typed unavailability for optional executables or providers;
- policy, approval, idempotency, exactly-once, job, worker, and ledger behavior;
- full core and isolated official-SDK modern suites.

To roll back one action's registry dispatch, remove only its canonical ID from
`LEGACY_DISPATCH_ACTIONS`. Discovery and validation remain descriptor-owned,
while execution falls through to `_retained_legacy_call_impl`. Do not delete
the inventory row, alias, descriptor, or frozen fixture.

## Change discipline

Use small coherent pack commits when commits are authorized. Preserve
bisectability with a green inventory/parity gate at every boundary. A fixture
change is not a migration fix: record and approve it separately in
`contract-changes.md`.

## Phase 3D adoption state

The complete Registry migration did not by itself authorize a surface switch.
Phase 3D separately adopted `modern-compact` stdio as the stable-Codex default
after the live approval/restart/resume gate passed 3/3. The frozen
`synapse-mcp` legacy launcher remains the rollback/bootstrap profile and
`modern-direct` remains explicit diagnostic compatibility. All surfaces must
continue using the same descriptors, schemas, execution, and policy path.

Future compatibility changes must regenerate the exact payload fixtures with
`bin/measure-phase3-surfaces --check` and pass
`bin/run-phase3d-codex --run --repetitions 3`. An under-development client
protocol feature cannot substitute for the stable gate. Additional model
clients become adoption requirements only through an explicit operator
amendment.
