# Synapse Architecture & Contracts

Read this before reviewing or specifying anything non-trivial. The contracts here are what
make a task spec safe to hand to an implementer — a change that violates one is wrong even if
its tests pass.

## Contents
1. What Synapse is
2. Repository layout
3. Load-bearing contracts
4. Global guardrails

---

## 1. What Synapse is

A local-first MCP server for authorized offensive-security agentic operations. Properties
that constrain every design decision:

- **Agent-agnostic, operator-controlled.** The operator authorizes; the agent acts through
  guarded adapters. Active traffic requires explicit confirmation.
- **Workspace-centric.** Durable state lives in a workspace on local disk as inspectable JSON.
- **Adapter-based.** Adapters fetch/parse external data and normalize it into Synapse's model;
  they do not replace external MCPs.
- **Entity hierarchy:** Workspace → Target → Finding. Evidence, observations, endpoints,
  services, and actions hang off targets with provenance back to the evidence that produced them.

Version line at time of writing: `0.5.0a0`. The runtime tool count and test
count move quickly; verify them from `TOOL_SCHEMAS` and `bin/test` instead of
copying this reference by memory.

## 2. Repository layout

Package root: `MCPS/Synapse-MCP/synapse_mcp/`

```
core/
  workspace.py        # workspace state, ingest, entity merge, finding lifecycle (large)
  perimeter.py        # perimeter/surface model
  credentials.py      # credential store (secrets resolved by reference, never inline)
  scope.py            # global + workspace scope
  adapters/
    base.py registry.py models.py results.py   # adapter framework + typed entity models
  http/
    backends.py client.py compare.py models.py # HTTP abstraction + response comparison
  js/
    extractors.py models.py normalizer.py      # JS intelligence; normalizer = entity boundary
  documentation/
    builder.py exporters.py renderer.py
    layer_renderer.py layers.py redaction.py   # report generation + redaction
adapters/
  web/      access_control.py crawler_adapter.py ...   # web adapters
  infra/    nmap_adapter.py shodan_adapter.py ...       # infra adapters
transport/
  stdio_server.py     # MCP transport + tool registration (large)
```

Other: `bin/test` (harness, uses `.venv`), `tests/`, `pyproject.toml`,
`docs/{Architecture,Implementation-Map,Operations,Adapter-Development,Reporting-Model}.md`,
committed root `CHANGELOG.md` (shared shipped history), the local gitignored
`docs/Version-Log.md` (per-developer dev notes, provisioned from
`docs/Version-Log.template.md`; not for grounding), and `DATA/` (gitignored real engagement data).

## 3. Load-bearing contracts

### 3.1 Two-phase normalization
Entities are normalized in two distinct phases with a hard boundary:

```
parse_adapter_result()  → structural normalization, CONTEXT-FREE
                          (canonical field names, entity `type`, obvious ids/keys, list shapes,
                           valid severity/confidence/status). Must NOT require workspace_id/target.
                           Must NOT compute missingEvidenceIds or validate evidence existence.

ingest_data()           → workspace-aware normalization (has workspace_id, target, existing state):
                          timestamps, default affectedAssets, evidence validation,
                          missingEvidenceIds, stable keys.

_merge_entities()       → pure merge/deduplication. Does NOT synthesize missing authoritative fields.
```
Consequence for specs: anything needing workspace context (e.g. `missingEvidenceIds`) belongs
in phase 2. Never thread `workspace_id` into a parser — that breaks the boundary and is an
architecture decision an implementer must not make.

### 3.2 `_entity_key()` stability
Deduplication depends on stable keys. The contract per type:
- **finding:** prefer `key` → `id` → fallback `finding:{title}|{evidenceIds}`. Keys must not
  change when evidence is linked (mutable key = duplicate entities).
- **action:** prefer `key` → `actionId` → meaningful `tool|target|summary|createdAt`. Without
  this, distinct adapter actions collide as `action:action|`.
- **observation:** prefer `key` → `id` → `candidateId` → non-empty `type/value` → JSON hash.
  Avoid weak keys like `type:|` that collide unrelated observations.

### 3.3 Typed entity models must match persisted shape
`FindingEntity`, `EndpointEntity`, `ObservationEntity`, `ActionEntity` in
`core/adapters/results.py` must declare the fields the workspace actually persists and that
`prepare_target_context()` reads back (e.g. endpoint `status`, `statusCodes`, `inputNames`,
`flags`, `pageUrl`; finding `key`, timestamps, review metadata, `missingEvidenceIds`).
Models use `extra="allow"` + camelCase aliasing, so missing fields are not *dropped* — they are
simply never *synthesized* for adapter-generated entities. That is the real failure mode.

### 3.4 Operator-control gates
- Active replay/traffic requires `confirm=true`; state-changing methods require an extra flag.
- Targets are checked against scope before any active action; **workspace scope is preferred
  over global scope** (reports must use the same precedence — see 3.6).
- Secrets flow through the credential store by reference (`credentialId`). Never pass raw
  `Authorization`/`Cookie`/`Set-Cookie` (and ideally other secret-like headers) as inline args.
- Adapter metadata (`requires_confirmation`, `sends_traffic`, `risk_tier`) is the control
  surface; coverage/active-vs-passive logic should consult it rather than counting every action.

### 3.5 Access-control semantics (BOLA/BFLA/BOPLA)
- BOLA needs **ownership assertions**, not array position. `ownedObjectTypes`/ownership must
  feed substitutions and the allowed-baseline decision; positional "index 0 = allowed" is wrong.
- A `3xx` redirect is **not** an access grant. Success = `200–299`; treating `200–399` as
  success creates false positives on redirect-to-login auth.
- BOPLA should differ behaviorally from BOLA (property-level / mass-assignment probing), not be
  a relabeled BOLA.
- Authenticated contexts with missing/invalid credentials should fail by default, not silently
  downgrade to anonymous; explicit anonymous opt-in only.

### 3.6 The two-report model + presentation boundary
Reporting consolidates into exactly **two** audience reports over the same workspace state:
- **Operator report** (`internal` mode): all layers, operational references (evidence IDs,
  approval IDs, relative paths, credential *references*) — but no raw secret values.
- **High-Level report** (`high_level` mode): concise internal summary with less operational
  noise. It is not client-facing, not redacted, and not safe for external sharing.

Rules: presentation-density hiding happens **only at the report/export/render boundary** —
workspace and agent-facing data stay rich and complete. Every canonical section always renders;
an empty section shows an explicit "no data" line rather than being dropped. Coverage in reports
uses workspace scope first (matching execution) and must not label passive actions as active
testing. A future client export would be a separate feature, not the current High-Level view.

## 4. Global guardrails

Apply to every change unless a spec explicitly overrides with reason:
- No database, no new report engine, no frontend framework, no plugin system, no RBAC/ABAC
  engine, no autonomous agent loop, no broad rewrite.
- Keep changes small and legible; prefer extending existing helpers over new abstractions.
- Local-first and self-contained (reports embed assets; no external CDNs required at runtime).
- Never commit real client data; fictional placeholders only.
- Workspace/agent context is never weakened to satisfy a report concern.
