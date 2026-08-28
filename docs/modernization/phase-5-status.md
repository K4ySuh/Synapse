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

## Phase 5B adversarial checkpoint

Status: completed on 2026-08-27; gate pass.

The checkpoint reproduced and corrected startup-boundary failures rather than
advancing to Task 5C with unverified assumptions:

- manifest sequence fields and the cached built-in ownership maps are now
  genuinely immutable; callers cannot mutate a frozen catalog or poison a
  later assembly into silently omitting a built-in action;
- every installed manifest graph is validated before selection for missing or
  cyclic dependencies and duplicate action/resource ownership, including
  manifests that are installed but not selected;
- caller-supplied external manifests cannot assert built-in origin to acquire
  legacy aliases or replace canonical built-in ownership;
- malformed external manifest/provider contributions fail through typed pack
  validation instead of escaping as raw attribute errors;
- assembled ownership is checked against the exact frozen Registry and manifest
  declarations, and discovery refuses a Registry/catalog mix-and-match;
- launcher/config selections are copied into immutable tuples, and modern
  runtime construction refuses to assemble a second capability Registry after
  the process selection has been sealed.

Verification:

```text
25 focused Phase 5 lifecycle/migration/adversarial tests passed
709 core tests passed (JSON-v1 and SQLite-v2 paths)
16 official-SDK modern tests passed
2 custom adapter template tests passed
58 Phase 4 storage/context acceptance tests passed
legacy stdio exact transport smoke: pass; external target traffic disabled
action inventory current: 174 actions
action output contracts current: 168 retained actions
capability-pack ownership current: 174 actions, 6 packs
surface fixtures current: legacy 99,337 bytes; compact 23,482 bytes
compile and git diff checks: pass
```

Compatibility result: the default/frozen surfaces, action and alias identity,
schemas, output contracts, authority path, workspace truth, compact fixtures,
and core-only import boundary are unchanged. The adversarial checkpoint is
closed; Task 5C is the next explicit implementation task.

## Task 5C — multi-agent operational coordination

Status: implemented on 2026-08-27; compatibility gates passed.

Delivered:

- application-level operational work items distinct from background jobs and
  supervised operation handles, with objectives, role/pack hints, target/context
  boundaries, completion contracts, progress/results, blockers, gaps, and
  workspace revision/version truth;
- SQLite-v2 migration/repository contracts for dependencies, exclusive or
  explicitly non-exclusive claims, heartbeat leases, references, and durable
  handoff/recovery events, including bundle export/import and in-place upgrade
  from the prior two-migration schema;
- atomic process-safe claim CAS, stale-version diagnostics, trusted
  principal/session/optional agent-run binding, dependency unlock, and restart
  reconstruction;
- recovery that expires stale claims while preserving active/unknown execution
  and explicitly never cancels or replays it;
- backward-compatible `tasks.control` `work.*` operations and work-item-aware
  `context.query` recovery, with eleven compact operations and a 23,297-byte
  application descriptor under the 24,834-byte ceiling;
- non-authoritative work-item linkage through the unchanged action Registry,
  effects, scope, Authority Engine, dispatch/job, result, evidence/artifact, and
  workspace revision path.

Focused verification:

```text
17 Phase 5C work-item tests passed
49 Phase 3B/4D/5C facade and context tests passed
24 Phase 4 migration/runtime adoption tests passed
726 core tests passed (JSON-v1 and SQLite-v2 paths)
2 custom adapter template tests passed
16 official-SDK modern tests passed
58 Phase 4 storage/context acceptance tests passed
legacy stdio exact transport smoke: pass; external target traffic disabled
action inventory current: 174 actions
action output contracts current: 168 retained actions
capability-pack ownership current: 174 actions, 6 packs
compact application descriptor: 23,297 bytes; 11 operations
largest official-SDK compact wire: 24,639 bytes
compile and git diff checks: pass
```

Optional environment result: the committed-private modern identity binding,
request-state keyring, and persistent state directory were not provisioned in
this clone, so `bin/check-setup` reported modern runtime setup unavailable. The
self-provisioned isolated `bin/test-modern` gate passed. MCP Inspector was also
unavailable to the Phase 4 runner; its exact built-in legacy stdio smoke passed.

Compatibility result: frozen legacy and default direct action identity remain
174 actions, compact remains eleven operations, existing job and operation-
handle control remains available, and JSON-v1 remains the explicit compatibility
and migration engine. JSON-v1 work-item mutations fail closed instead of
creating parallel coordination truth.

Task 5C stops here. On 2026-08-27 the operator explicitly deferred the
adversarial review to the complete Phase 5 implementation and authorized Task
5D to proceed from the clean committed Phase 5C checkpoint.

## Task 5D — Codex multi-agent Synapse playbooks

Status: implemented on 2026-08-27; compatibility gates passed, with adversarial
review deferred by the operator to the complete Phase 5 review.

Delivered:

- a Codex-native `$operate-synapse` router that recovers durable state and
  handles simple context reads or bounded operations without unnecessary
  decomposition;
- `$synapse-coordinate-engagement` for bounded independent/dependency work,
  claim collision rerouting, durable blocker recovery, and convergence from
  workspace truth instead of agent transcripts;
- bootstrap, perimeter, web, access-control, CVE, and reporting specialist
  skills with Codex `agents/openai.yaml` metadata and live Synapse MCP
  dependencies;
- shared operational invariants and a claim/context/recovery/progress/handoff
  specialist workflow, referenced by every role instead of copied into eight
  divergent prompts;
- live capability search/description as the action-catalog boundary, with no
  copied action schemas, provider-specific app behavior, real engagement data,
  reasoning traces, or prose-based authority;
- `bin/validate-codex-skills --check` for required skill/role/pack metadata,
  interface prompts, MCP dependencies, shared references, stale links, copied
  schemas/catalogs, and contradictory authority/reporting/candidate language;
- fictional scenario coverage for direct single-agent context, three bounded
  specialists, exclusive-claim rerouting, active-job polling without rerun,
  missing-authority blocking, evidence-visible reporting dependencies, and
  final completed/candidate/finding/contradiction/gap convergence.

Focused verification:

```text
8 Phase 5D Codex skill and fictional coordination scenarios passed
8 operating skills passed the skill-creator structural validator
Codex operating skills current: 8 skills, 2 shared references
734 core tests passed (JSON-v1 and SQLite-v2 paths)
2 custom adapter template tests passed
16 official-SDK modern tests passed
58 Phase 4 storage/context acceptance tests passed
legacy stdio exact transport smoke: pass; external target traffic disabled
action inventory current: 174 actions
action output contracts current: 168 retained actions
capability-pack ownership current: 174 actions, 6 packs
surface fixtures current: legacy 99,337 bytes; compact 23,297 bytes
compile and git diff checks: pass
```

Optional environment result: MCP Inspector was unavailable to the Phase 4
runner, whose exact built-in legacy stdio smoke passed instead.

Compatibility result: Phase 5D changes client-side Codex methodology and
documentation only. It adds no compact/direct operation, action ID/schema,
provider implementation, authority path, workspace entity, or generated
surface fixture. SQLite-v2 workspace state, jobs, work items, evidence, scope,
and server-held authority remain canonical.

Task 5D stops here. Per the operator's direction, its adversarial review is
deferred and will be performed as part of the complete Phase 5 implementation
review; this checkpoint does not claim that review has passed.

## Task 5E — operational instructions and Codex distribution

Status: implemented on 2026-08-28; focused packaging and compatibility gates
passed, with full Phase 5 adversarial review still deferred to Task 5F.

Delivered:

- a 94-line root repository policy containing stable identity, architecture
  invariants, primary commands, change hygiene, safety, and scoped-instruction
  links instead of the former 640-line combined development/operations manual;
- nested MCP, policy, state, adapter, and test instructions that carry local
  implementation, migration, authority, fixture, and packaging constraints;
- a provider-neutral 5,941-byte package-owned operational prompt covering
  recovery, compact context and live capability discovery, work-item handoff,
  passive/active separation, scope/authority, evidence/candidate/finding
  semantics, timeout recovery, and completion reporting;
- identical repository and installed-package prompt sourcing with an explicit
  fail-closed `SYNAPSE_PROMPT_PATH` override and unchanged legacy prompt/resource
  discovery shapes;
- wheel/sdist Codex integration data containing all operating skills, shared
  references, the separate development skill, and standard/core-only/direct/
  legacy configuration templates;
- `synapse-codex-assets` for installed asset discovery/verification and
  `bin/print-mcp-config` selection for the four repository profiles;
- an offline `bin/validate-phase5-distribution` gate that builds and installs
  wheel and sdist outside the checkout, validates exact prompt/skill/config
  contents, and constructs installed standard and core-only official-SDK
  runtimes without Codex integration imports.

Focused verification:

```text
7 Phase 5E instruction/prompt/config/distribution regressions passed
3 legacy configured/package prompt wrapper regressions passed
8 operating skills and 2 shared references passed from installed wheel/sdist trees
wheel and sdist isolated build/install gate: pass
standard installed modern runtime start: 174 actions
core-only installed modern runtime start: 42 actions; no Codex integration import
root instructions: 94 lines, 5,150 bytes
operational prompt: 5,941 bytes (78.5% below the Phase 4 root prompt)
741 core tests passed (JSON-v1 and SQLite-v2 paths)
2 custom adapter template tests passed
16 official-SDK modern tests passed
58 Phase 4 storage/context acceptance tests passed
legacy stdio exact transport smoke: pass; external target traffic disabled
action inventory current: 174 actions
action output contracts current: 168 retained actions
capability-pack ownership current: 174 actions, 6 packs
surface fixtures current: legacy 99,337 bytes; compact 23,297 bytes
compile and git diff checks: pass
```

Optional environment result: the repository's private modern identity binding,
request-state keyring, and persistent state directory are not provisioned, so
the default `bin/check-setup` reports `MODERN NOT READY`. Legacy and State Store
v2 readiness pass. The distribution gate self-provisions isolated private
material and passes both installed modern runtime starts. MCP Inspector remains
unavailable to the Phase 4 runner; its exact built-in legacy stdio smoke passed.

Compatibility result: no action ID/schema, compact/direct operation, Registry,
effect, authority, workspace entity, migration, execution, or report behavior
changed. Modern server instructions and compact wire fixtures are unchanged.
Frozen legacy prompt/resource list shapes remain exact; the main prompt content
now comes from package data instead of repository development policy.

Task 5E stops here. Task 5F operational acceptance, the deferred complete-phase
adversarial review, final handoff/evidence, and rollback closure are next.
