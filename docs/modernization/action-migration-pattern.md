# Action migration pattern

This guide is the contributor procedure for moving one legacy MCP tool into the
typed application Action Registry. It records the pattern proven by the Phase 1
six-action slice; it does not change the architecture established by the
[Stage A checkpoint](phase-1-stage-a.md),
[ADR-0002](adr/ADR-0002-typed-core-action-registry.md),
[ADR-0007](adr/ADR-0007-application-outcome-model-and-error-boundary.md), or
[ADR-0008](adr/ADR-0008-action-identity-and-packs.md).

Migrate one action per commit. Start from its reviewed Appendix A row and its
frozen contract fixtures, not from assumptions based on the tool name.

## 1. Choose the application identity

Create an `ActionId` by splitting the public name once at the first dot. The
first segment is the canonical pack; the entire remainder is the local name.
For example, `cve.session_key.set` becomes pack `cve` and local name
`session_key.set`.

The two dotless legacy names are explicit exceptions in the projection only:

- `approve_pretext_candidate` maps to `social.approve_pretext_candidate`.
- `mark_detection_outcome` maps to
  `purple_team.mark_detection_outcome`.

Never derive a public legacy name from the `ActionId`. The explicit mapping is
what preserves those exceptions without weakening the canonical identity.

## 2. Move the input contract beside the action

Copy the action's frozen `inputSchema` verbatim, retaining key order, values,
required fields, and defaults, into an `InputContractDocument` in the relevant
module under `synapse_mcp/app/actions/packs/`. Generate the typed model with
`make_input_model(name, document)`.

The contract document is the one input-schema source. After the action is
projected, remove its duplicate `inputSchema` from the raw transport list.
`transport/projection.py` uses the document for both legacy argument validation
and `tools/list` projection. Pydantic-generated JSON Schema is not a substitute:
it does not preserve the frozen legacy bytes.

Generated inputs deliberately retain the compatibility semantics established by
`contracts.py`:

- strict, non-coercing known fields;
- unknown public fields accepted;
- leading-underscore worker fields rejected;
- a required `confirm` discovery field runtime-optional;
- omitted fields retained as omitted through `model_dump(exclude_unset=True)`.

## 3. Declare the descriptor

Follow the examples in `packs/jobs.py`, `packs/workspace.py`, and the active
`packs/cors.py` and `packs/crawler.py` modules. Define a per-action
`ActionOutput` subclass with `ConfigDict(extra="allow")`, then fill all fifteen
`ActionDescriptor` fields.

Assign the side-effect, risk, scope, credential, and idempotency policies from
the ordered judgment rules and reviewed implementation target in Stage A
Appendix A. Do not infer them from a namespace or verb. Set the task deadline,
background capability, and passive-recordability to the audited legacy values.

Every Phase 1 scope and credential policy remains
`DECLARED_NOT_ENFORCED`. `ActionRegistry.register()` rejects a descriptor that
claims executor enforcement, and `ActionRegistry.execute()` invokes the named
pass-through policy evaluator before the executor. Legacy implementations remain
authoritative for confirmation, scope, and credential checks until a later
phase.

For an action with targets, methods, providers, credentials, local outputs, or
continuations, provide a pure `intent_resolver`. It canonicalizes those
dimensions into `AuthorizationIntent` without traffic, credential resolution,
or writes. Registry seals the intent, request-effective effects, and validated
input fingerprint into an immutable `ExecutionPlan`; the executor consumes
`request.context.execution_plan` for every policy-relevant target and output.
Resolver input requests coverage but never grants it.

## 4. Wrap the exact legacy callable

The executor exposes `input_model` and `output_model` properties that are the
same class objects carried by the descriptor. Its call path is:

1. Use `request.input.model_dump(by_alias=True, exclude_unset=True)` and verify
   it against the sealed execution plan when the descriptor has an intent.
2. Invoke the exact callable and argument adaptation recorded in Appendix A,
   including the same positional/keyword arrangement, defaults, and explicit
   `int()` or `bool()` conversions.
3. Return the raw legacy dict or serialized string through
   `success_from_legacy_payload()` so `Success.payload_signals_error` truthfully
   records an error-bearing legacy payload. Do not run an output through
   `model_dump()` or otherwise reorder it.
4. Catch only `McpError` and return `outcome_from_mcp_error`, supplying
   `confirm_declared` and the caller's `confirm` value when the frozen schema
   declares confirmation.

The protocol-independent helper computes the legacy payload signal for both raw
dicts and serialized strings. The transport projection serializes raw dicts with
the frozen `indent=2` shape and leaves executor-owned strings verbatim.
Application pack modules must not import transport helpers; the AST boundary
test enforces that direction.

## 5. Add the legacy projection row

Add the canonical action id to
`synapse_mcp/transport/legacy_projection_map.py`. Store both protocol facts
explicitly:

- the unchanged public legacy name;
- serializer ownership: `transport` for raw legacy results or `executor` for an
  already-serialized legacy string.

Import the new pack module from `app/actions/packs/__init__.py` so registration
occurs during application-action discovery. Do not add a public generic action
execution tool.

Add the action id to `LEGACY_DISPATCH_ACTIONS` while registry dispatch is
enabled. The projection row remains the durable schema/name/serializer record;
the dispatch set is the reversible routing switch.

Once the mapping is active, remove only that action's raw transport
`inputSchema`. Leave its old `_call_tool_impl` branch in place as the reversible
compatibility path. The projection call at the top of `_call_tool_impl` makes
the branch unreachable while the mapping exists.

## 6. Prove equivalence

Identify the existing Tier-1 and Tier-2 fixture or fixtures that gate the action.
Add no fixture merely to make a migration pass. The required proof is:

1. `tools/list` remains 174 ordered entries and 99,337 compact schema bytes.
2. `resolved_input_schema()` deep-equals the frozen public schema and the raw
   transport row contains no second `inputSchema`.
3. The action's result, approval, scope, timeout, and background fixtures remain
   unchanged as applicable.
4. The descriptor deadline and passive-recordability values agree with the
   all-surface checks in `tests/test_slice_projection_contracts.py`.
5. Strict validation, omitted-field defaults, serializer ownership, and legacy
   error translation retain their current behavior.
6. `bin/test` is green and the test count only grows.

If a frozen byte pin or normalized-exact result fails, correct the descriptor,
wrapper, or projection. Do not edit or regenerate the fixture without a separate
reviewed contract change recorded in `contract-changes.md`.

## 7. Roll back one migration

Remove the action id from `LEGACY_DISPATCH_ACTIONS`. Dispatch then falls through
to the retained legacy `_call_tool_impl` branch while discovery and validation
continue to resolve the descriptor-owned schema through
`LEGACY_PROJECTION_MAP`. Do not remove the projection row or restore a duplicate
raw transport `inputSchema` for a dispatch-only rollback.

Rollback changes no public tool name and requires no storage migration. Run the
same fixture and full-suite proof after the reversal.

## Standing guardrails and deferred work

- Migrate one action per commit; fixtures stay frozen unless separately approved.
- Do not add authority enforcement during this migration phase.
- Do not re-serialize legacy output through a Pydantic output model.
- Do not migrate beyond the operator-approved slice or batch.
- Keep the legacy branch until physical retirement is separately approved.

The exact 40-pack invariant and physical removal of legacy dispatch branches are
deferred until the full action surface has migrated.

Next: after Phase 1 closes, later phases may introduce the separately reviewed
authority and compatibility mechanisms; those mechanisms are not part of this
procedure.
