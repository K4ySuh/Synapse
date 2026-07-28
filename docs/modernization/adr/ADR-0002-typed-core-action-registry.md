# ADR-0002: Typed application core and Action Registry

- Status: Accepted
- Date: 2026-07-28
- Owners: Synapse architectural lead
- Applies from: Phase 1
- Supersedes: None

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

## Invariants

- Application services must not import MCP request, result, context, or content classes; an architecture test enforces this.
- Duplicate action IDs or inconsistent descriptors fail at registration.
- Risk, side-effect class, scope, credentials, idempotency, and task behaviour are descriptor data, never inferred from a tool name at dispatch time.
- An executor cannot bypass policy evaluation.
- Phase 1 changes no public tool name, protocol version, authority behaviour, or storage. The Tier-1 and Tier-2 contract fixtures are the proof.

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
  pass through policy evaluation.
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
  descriptor.
- Run all Tier-1 and Tier-2 fixtures and the P0-3 corpus after every migrated
  action.
- Confirm Phase 1 changes no protocol version, authority behavior, or storage.
