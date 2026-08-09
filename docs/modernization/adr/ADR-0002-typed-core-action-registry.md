# ADR-0002: Typed application core and Action Registry

- Status: Accepted
- Date: 2026-07-28
- Owners: Synapse architectural lead
- Applies from: Phase 1
- Supersedes: None
- Amended: 2026-07-30, during the Phase 1 Stage A design checkpoint. Two changes:
  the Decision gained the `InputContractDocument` single-source rule, and the
  invariant "An executor cannot bypass policy evaluation" was restated as a
  routing requirement through `ActionRegistry.execute()` with an explicit Phase 1
  compatibility pass-through. Rationale and the amendment record are in
  `../contract-changes.md`; the design that motivated it is `../phase-1-stage-a.md`
  and ADR-0007. **An Accepted ADR is a binding standard; amending one requires
  the operator's sign-off, recorded in the ledger — not a silent edit.**
- Amended: 2026-08-09 by the operator-directed correction gate (ADR-0009):
  routing is explicit by canonical action ID, output contracts are executable,
  and multidimensional maximum/effective effects replace the singular
  side-effect label as policy authority.

## Context

The legacy MCP surface is defined by an ordered list of 174 hand-authored tool
schemas and a large name-based dispatch function in
`transport/stdio_server.py`. Input schemas, safety metadata, discovery, and
dispatch are maintained in separate code locations. There are no output schemas
or tool annotations, and application operations are frequently reached through
transport-shaped dictionaries and JSON strings.

Phase 0 froze the legacy surface with five protocol fixtures, twelve result
fixtures, and behavioral benchmarks. Phase 1 needs an application boundary and
one authoritative source for each action without changing those public
contracts.

## Decision

Extract use-case services that accept typed commands and return typed results, with exactly one authoritative `ActionDescriptor` per action. MCP becomes one protocol adapter over those services. Protocol schemas, annotations, discovery results, and dispatch wiring are generated or projected from the descriptor rather than hand-maintained.

Execution resolves the descriptor by direct `action_id` lookup, verifies that
the request carries that descriptor's input model, evaluates runtime
availability, resolves request-effective effects within the declared maximum,
evaluates policy, invokes the executor, and validates the canonical output
model. Input-model classes may be shared because they are not routing keys.

For legacy byte equality, the descriptor's `input_model` is generated from one
typed `InputContractDocument` retained on the model class. The transport projects
that document; it does not keep a second schema literal. The transport map owns
only the legacy public name and serializer/argument-adapter choice.

## Invariants

- Application services must not import MCP request, result, context, or content classes; an architecture test enforces this.
- Duplicate action IDs or inconsistent descriptors fail at registration.
- Risk, multidimensional maximum/effective effects, scope, credentials,
  availability, replay safety, and task behaviour are descriptor data, never
  inferred from a tool name at dispatch time. `SideEffectClass` is at most a
  legacy display projection.
- Protocol adapters cannot invoke descriptor executors directly:
  `ActionRegistry.execute(action_id, request)` evaluates availability and policy
  before invocation. In Phase 1 the
  evaluator is an explicit compatibility pass-through and the wrapped legacy
  implementation retains its existing confirm/scope/credential gates; durable
  authority enforcement begins only after ADR-0003 is accepted.
- Phase 1 changes no public tool name, protocol version, authority behaviour, or storage. The Tier-1 and Tier-2 contract fixtures are the proof.
- A successful action payload is an instance of the descriptor's validated
  output model; legacy serialization is retained only in an explicit
  compatibility field.

## Alternatives considered

### Keep the hand-written schema list and dispatch chain

- Benefits: No extraction cost and no immediate compatibility risk.
- Costs: Every action remains represented multiple times, allowing metadata and
  dispatch behavior to drift.
- Reason rejected/deferred: It cannot provide one enforceable action model for
  later authority and protocol work.

### Put MCP types directly into use-case services

- Benefits: Reduces adapter mapping and can reuse SDK validation types.
- Costs: Makes MCP the application architecture and blocks clean CLI, test, or
  future protocol entry points.
- Reason rejected/deferred: MCP is one adapter, not the core dependency
  direction.

### Maintain separate input, policy, and dispatch registries

- Benefits: Each concern can evolve independently.
- Costs: Recreates multiple sources of truth and permits inconsistent action
  definitions.
- Reason rejected/deferred: Exactly one descriptor must own the action's
  operational metadata.

## Consequences

- Positive: Input, output, policy, task, and protocol projections share one
  authoritative action identity.
- Negative: Phase 1 requires adapters around legacy operations and careful
  projection tests before simplification is possible.
- Operational: Registration failures become startup/test failures rather than
  runtime surprises.
- Security: Policy-relevant attributes become explicit data and executors must
  be reached through policy evaluation. Phase 1 does not claim the declared
  metadata is already enforced.
- Compatibility: The legacy profile remains byte-checked against the Phase 0
  fixtures.

## Migration and rollback

Migrate actions incrementally behind the unchanged legacy surface. For each
action, add typed command/result models, register one descriptor, project the
legacy schema and dispatch entry, and compare both contract tiers. Keep the
legacy implementation available until its projection is proven. A failed
migration rolls back that action to the legacy path without changing storage or
public names.

## Verification

- Add architecture tests preventing MCP-type imports in application services.
- Fail registration on duplicate IDs and inconsistent descriptors.
- Assert projected schema, metadata, and dispatch all resolve from the same
  descriptor/input contract, with no transport-owned schema duplicate.
- Assert protocol projection calls `ActionRegistry.execute()` rather than the
  executor field.
- Reject ID/model mismatches and invalid executor outputs, and prove shared
  input models route correctly by ID.
- Run all Tier-1 and Tier-2 fixtures and the P0-3 corpus after every migrated
  action.
- Confirm Phase 1 changes no protocol version, authority behavior, or storage.
