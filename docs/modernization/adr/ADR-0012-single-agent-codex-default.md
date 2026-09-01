# ADR-0012: Single-agent Codex default, multi-consumer Synapse core

- Status: Accepted
- Date: 2026-09-01
- Owners: Synapse architectural lead
- Applies from: Phase 6B
- Supersedes: Phase 5D Codex default topology; retained as compatibility

## Context

Phase 5 proved durable work coordination with one router, a coordinator, six
specialist skills, and real independent processes. That correctly established
provider-neutral concurrency and recovery, but its default Codex methodology
could imply that a single client should spawn specialists merely because an
assessment has several phases. Agent topology is not Synapse application truth,
and simulated agent handoffs add context, cost, and recovery ambiguity without
improving every engagement.

Synapse must continue to support independent clients, processes, humans, and
future agent topologies over one workspace while keeping the Action Registry,
scope, authority, state, evidence, jobs, and reports canonical.

## Decision

One Codex agent is the default operational unit. It starts with
`$operate-synapse` and loads `$synapse-web-pentesting` or
`$synapse-cve-intelligence` when the current objective needs that methodology.
The same agent may move between both methods while retaining workspace revision,
execution/evidence references, authorization boundaries, candidates, and gaps.
It does not simulate a handoff to itself.

The default distributed operating profile contains exactly those three skills.
`synapse-developing` remains a separate development profile. The Phase 5 router,
coordinator, bootstrap, perimeter, web, access-control, CVE-validation, and
reporting skills remain installable only from the explicit
`multi-agent-compat` profile. Compatibility selection is client-side integration
configuration; no application, policy, state, executor, adapter, or transport
module branches on it.

Work items are defined as a durable multi-consumer coordination ledger. One
agent may use them for restart recovery, dependencies, or long-running
responsibility. Independent consumers may use them for claims and handoffs.
Their identities and prose remain non-authoritative.

The default optional live diagnostic runs one agent with the three default
skills and checks direct work, both skill selections in sequence, restart
recovery, no duplicate execution, and report convergence. It is not a Phase 6
acceptance dependency. Offline multi-process gates remain the proof of shared
state and claim concurrency.

## Invariants

- Workspace state and evidence outrank conversation memory.
- Default Codex operation does not spawn sub-agents.
- Skill selection is methodology, never scope, authority, or execution truth.
- Work items coordinate durable work and independent consumers; they do not
  imply or schedule an agent topology.
- Compatibility assets do not alter server-core behavior.
- The one Action Registry and existing scope, Authority Engine, execution,
  evidence, job, and report paths remain unchanged.
- Modern compact stays at eleven operations; modern direct, frozen legacy,
  action identity/order, six capability packs, and JSON-v1 compatibility remain.

## Consequences

- The common operating path has lower prompt and orchestration overhead and a
  simpler recovery identity.
- Web methodology absorbs bootstrap, perimeter, application, authentication,
  access-control, validation, and convergence decisions; CVE Intelligence adds
  version-aware authoritative and public-PoC applicability analysis.
- Operators needing Phase 5 coordinator/specialist behavior must select and
  install the compatibility profile explicitly.
- Existing workspace work items remain valid because this decision changes
  integration assets and terminology, not their application contracts.

## Alternatives considered

### Remove multi-agent support

Rejected. Independent consumers and compatibility playbooks remain useful, and
the provider-neutral SQLite-v2 coordination guarantees are not a defect.

### Add a server-side planner or model router

Rejected. It would make model topology part of the control plane, duplicate
client judgment, and violate the provider-neutral architecture.

### Keep all skills in one install and rely on prose

Rejected. Codex discovery would still expose coordinator/specialist routing by
default. Separate profile roots make selection observable and testable.

## Verification

- `bin/validate-codex-skills --check`
- `bin/validate-codex-skills --check --profile multi-agent-compat`
- `MCPS/Synapse-MCP/tests/test_phase6b_single_agent_default.py`
- `bin/validate-phase6b-distribution`
- retained Phase 5 multi-process, compact/direct/legacy, inventory, and package
  gates

## Migration and rollback

Select the `multi-agent-compat` skill/config profile. This changes Codex client
methodology only and requires no workspace migration, state rollback, action
surface change, or authority change.
