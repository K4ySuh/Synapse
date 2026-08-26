# ADR-0010: Deterministic capability-pack lifecycle

- Status: Accepted
- Date: 2026-08-26
- Owners: Synapse architectural lead
- Applies from: Phase 5A
- Supersedes: None

## Context

The canonical Action Registry contains 174 stable built-in actions across 40
first-segment action namespaces. Those namespaces are useful action identities,
but they are too granular to express the operational domains an agent needs to
discover and select. Descriptor construction also relied on import side effects
against a mutable process-global Registry, preventing isolated assembly and a
real core-only mode.

Phase 5 needs high-level capability ownership without changing action IDs,
legacy aliases, authority evaluation, workspace truth, or executor behavior.
It also needs a bounded future extension point without runtime installation or
hot reload.

## Decision

Add immutable `CapabilityPackId` and `CapabilityPackManifest` contracts under
`synapse_mcp.app.capability_packs`. A manifest declares stable identity,
distribution origin, application compatibility, exact ordered action
ownership, dependencies, descriptor provider, availability declarations, and
read-only resource contributions. It cannot carry authority, credentials,
target data, engagement state, or client behavior.

The six built-in high-level packs are `core`, `web`, `infra`, `reporting`,
`purple`, and `intelligence`. The checked
`capability-pack-ownership.json` artifact assigns exactly one of them to every
built-in action while preserving `ActionDescriptor.pack` as the first action-ID
segment. Pack dependencies currently converge on `core`.

Startup assembly:

1. discovers the `synapse_mcp.capability_packs` Python entry-point group once;
2. validates unique pack IDs, compatibility, dependencies, contribution shape,
   exact ordered ownership, action IDs, and aliases;
3. resolves an explicit selection deterministically;
4. registers every descriptor through the existing `ActionRegistry.register`
   validation path;
5. restores selected built-ins to frozen legacy inventory order and sorts
   external actions by canonical ID;
6. freezes both the selected catalog and Registry before requests.

The default selection is all built-ins. `core` can be assembled independently.
External actions are modern-only and must not declare legacy aliases. Valid
installed external manifests are not selected implicitly, preserving the
default 174-action direct and frozen legacy surfaces. Broken installed entry
points fail startup explicitly. Runtime executable/provider availability
remains descriptor-owned and never removes an otherwise valid action.

Native descriptor modules and the generated descriptor factory now return
values; they do not mutate a Registry during import. `REGISTRY` remains the
fully assembled frozen standard compatibility facade for current callers.

## Invariants

- There is one selected Action Registry and one policy/effect/execution path.
- Every selected action has exactly one high-level capability-pack owner.
- High-level pack identity never changes `ActionId` or `ActionDescriptor.pack`.
- Pack identity, selection, and dependencies grant no scope or authority.
- Built-in descriptors preserve frozen inventory order; external descriptors
  are modern-only and deterministically ordered.
- The selected catalog and Registry are immutable before request handling.
- Workspace, evidence, authority, and credential truth never enter manifests.

## Consequences

- Operational discovery can name a small high-level domain while exact action
  identity and policy remain unchanged.
- Tests can build isolated registries and prove core-only behavior.
- Duplicate ownership, aliases, incompatible versions, invalid contributions,
  and post-start mutation fail loudly.
- There remains one policy/effect/execution path; packs cannot override it.
- Entry-point discovery is a startup boundary, not a marketplace, installer,
  or hot-reload mechanism.
- Explicit modern startup selection and pack-aware capability search are the
  Phase 5B adoption step.

## Alternatives considered

### Reuse `ActionDescriptor.pack`

This would rename or reinterpret stable first-segment action identity and make
the frozen legacy contract ambiguous.

### One Registry per pack

This would create secondary policy and execution paths and make cross-pack
authority/evidence behavior difficult to prove equivalent.

### Import-time registration or runtime hot reload

Both make selected capabilities and ordering depend on process history. Hot
reload would also require unresolved concurrency and authority semantics.

### Implicitly load every installed external pack

That would change the default modern-direct surface beyond 174 actions and make
installed environment accidents alter compatibility behavior.

## Verification

- `MCPS/Synapse-MCP/tests/test_phase5a_capability_packs.py`
- `bin/generate-capability-pack-ownership --check`
- `bin/generate-action-inventory --check`
- `bin/generate-action-output-contracts --check`
- existing registry, inventory, facade, and architecture-boundary suites

## Migration and rollback

Rollback restores import-owned descriptor registration and removes the
capability-pack assembly layer; no action ID, legacy fixture, workspace state,
authority record, or output contract changes are required.
