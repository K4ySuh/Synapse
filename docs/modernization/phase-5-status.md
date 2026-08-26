# Phase 5 implementation status

Phase 5 turns the accepted Registry, authority, modern MCP, State Store v2, and
Context Compiler foundations into capability-pack discovery and shared
multi-agent operations. Codex is the only Phase 5 implementation and acceptance
client; application contracts remain provider-neutral.

## Task 5A — capability-pack contract

Status: implemented on 2026-08-26; focused gate pass.

Delivered:

- immutable high-level pack IDs, manifests, availability/resource
  contributions, dependency and application-compatibility declarations;
- deterministic startup discovery through
  `synapse_mcp.capability_packs`, explicit selection, dependency resolution,
  exact contribution validation, and frozen catalog/Registry assembly;
- standard six-pack assembly preserving all 174 canonical action IDs and
  inventory order;
- isolated 42-action `core` assembly;
- native and generated descriptor providers without registration side effects;
- read-only pack catalog/resource application contract;
- checked 174-action ownership artifact and generator;
- explicit failure for duplicate pack/action/alias ownership, incompatible
  versions, invalid providers, broken entry points, and post-freeze mutation.

Focused verification:

```text
64 tests passed
action inventory current: 174 actions
action output contracts current: 168 retained actions
capability-pack ownership current: 174 actions, 6 packs
git diff --check: pass
```

Compatibility result: the default global Registry remains 174 actions across
40 canonical action namespaces in frozen inventory order. No action ID, legacy
alias, tool schema, output contract, authority behavior, workspace state, or
fixture changed.

## Task 5B — built-in capability migration

Status: implemented on 2026-08-26; compatibility gates passed.

Delivered:

- one-shot trusted modern startup selection, defaulting to all built-ins and
  supporting the independently loadable 42-action `core` profile;
- a protocol-free core retained dispatcher, with fresh-process proof that a
  real modern core startup imports no unselected implementation or frozen
  transport module;
- selected Registry propagation through compact/direct projections, search,
  describe, execution, and adapter metadata;
- deterministic pack-aware discovery with distinct high-level
  `capabilityPack` and stable action namespace `pack` fields plus canonical
  effects, availability, target, risk, credential, scope, and task filters;
- on-demand selected catalog and methodology resources at
  `synapse://capability-packs` and
  `synapse://capability-packs/{pack_id}`;
- unchanged legacy 174-action discovery and default direct 174-action order,
  with compact fixed at eleven operations and 23,482 application bytes;
- refreshed compact-only official-SDK fixtures. The largest supported compact
  wire is 24,824 bytes against the 24,834-byte ceiling; legacy and direct
  fixtures remain unchanged.

Verification:

```text
17 focused Phase 5A/5B tests passed
701 core tests passed (JSON-v1 and SQLite-v2 paths)
16 official-SDK modern tests passed
2 custom adapter template tests passed
58 Phase 4 storage/context acceptance tests passed
MCP Inspector legacy discovery: 174 tools, pass
action inventory current: 174 actions
action output contracts current: 168 retained actions
capability-pack ownership current: 174 actions, 6 packs
compact surfaces current: 23,482 application bytes; 24,824 maximum SDK wire
compile and git diff checks: pass
```

This implementation stops before the Phase 5B adversarial checkpoint. The
checkpoint review has not been performed and remains the next explicit task.
