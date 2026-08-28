# Phase 5 Codex distribution and instruction architecture

Phase 5E separates repository-development policy from the operational guidance
served by Synapse and makes the Codex integration available from built Python
artifacts. Application, policy, state, executor, and transport behavior remain
provider-neutral.

## Instruction architecture

| Surface | Purpose |
| --- | --- |
| `AGENTS.md` | Repository identity, cross-cutting invariants, primary commands, change hygiene, and links |
| `MCPS/Synapse-MCP/AGENTS.md` | MCP application, transport, prompt, surface, and packaging constraints |
| `synapse_mcp/policy/AGENTS.md` | Scope/authority, trusted identity, dispatch, and resume constraints |
| `synapse_mcp/state/AGENTS.md` | SQLite-v2, JSON-v1 migration, transaction, artifact, and recovery constraints |
| `synapse_mcp/adapters/AGENTS.md` | Adapter effects, credentials, active traffic, jobs, results, and candidate semantics |
| `tests/AGENTS.md` | Fictional fixtures, frozen contracts, concurrency, package, and acceptance constraints |
| `synapse_mcp/operational_prompt.md` | Target-neutral runtime guidance returned by MCP prompt/resource calls |
| `skills/codex/` | On-demand Codex router, coordinator, and specialist methodology |

The root file is no longer an engagement manual and is not the MCP runtime
prompt. The packaged operational prompt covers recovery, compact context,
capability discovery, work-item handoff, scope/authority separation,
passive/active execution, evidence semantics, timeout recovery, and completion
reporting. It contains no repository test, changelog, editing, or implementation
instructions. `SYNAPSE_PROMPT_PATH` remains an explicit operator override; a
missing override fails instead of silently selecting another file.

Measured against the accepted Phase 4 root prompt:

| Measure | Phase 4 | Phase 5E |
| --- | ---: | ---: |
| Root instruction lines | 640 | 94 |
| Root instruction bytes | 27,633 | 5,150 |
| MCP operational prompt bytes | 27,633 | 5,941 |

The runtime prompt is 78.5% smaller than the Phase 4 root prompt. Legacy
`prompts/list`, `prompts/get`, `resources/list`, and
`synapse://prompt/main` shapes are unchanged; only the returned target-neutral
guidance source changes.

## Installed Codex assets

Wheel and sdist builds contain:

```text
share/synapse-mcp/codex/
|-- config/
|   |-- standard.toml
|   |-- core-only.toml
|   |-- modern-direct.toml
|   `-- legacy.toml
`-- skills/
    |-- operate-synapse/
    |-- synapse-coordinate-engagement/
    |-- synapse-engagement-bootstrap/
    |-- synapse-perimeter-triage/
    |-- synapse-web-assessment/
    |-- synapse-access-control/
    |-- synapse-cve-validation/
    |-- synapse-reporting/
    `-- synapse-developing/
```

After installing the distribution, locate or verify these files with:

```bash
synapse-codex-assets --skills-dir
synapse-codex-assets --verify
synapse-codex-assets --config standard
```

Copy the complete returned skills directory into a Codex skill location so the
specialist links to `operate-synapse/references/` remain intact. The eight
operating skills require the MCP server name `synapse`; the separate development
skill does not change server behavior.

For a repository-local Codex installation:

```bash
SYNAPSE_SKILL_SOURCE="$(synapse-codex-assets --skills-dir)"
mkdir -p .agents/skills
cp -R "$SYNAPSE_SKILL_SOURCE"/. .agents/skills/
```

## Codex MCP profiles

| Profile | Launcher selection | Use |
| --- | --- | --- |
| `standard` | `modern-compact`, all six built-in packs | Default Codex operation |
| `core-only` | `modern-compact --capability-pack core` | 42-action minimal operational core |
| `modern-direct` | `modern-direct`, all built-ins | 174-action diagnostic compatibility |
| `legacy` | `synapse-mcp` | Frozen rollback/bootstrap profile |

Repository configurations are printed with `bin/print-mcp-config`; installed
templates are printed with `synapse-codex-assets --config PROFILE`. Replace the
placeholder runtime, private identity/keyring, and operator-owned data paths.
The Codex host approval setting permits invocation of the trusted MCP server; it
does not create Synapse scope or execution authority.

## Shared coordinator and specialists

One coordinator and several Codex specialists connect to the same installed
Synapse service and workspace under the trusted principal/session binding. They
use distinct non-authoritative work-item claim identities. The coordinator
creates bounded objectives and dependencies; specialists claim, request
revision-aware context, link evidence/results, and explicitly complete, block,
or hand off. All participants recover from SQLite-v2 workspace truth. They do
not exchange authority through role labels and do not aggregate chat transcripts
into the report.

Run active specialists only when their exact Registry plans are within scope
and covered by server-held authority. If a worker disappears, the next worker
inspects linked dispatches/jobs and polls existing execution instead of
repeating it.

## Reproducible verification

```bash
bin/validate-codex-skills --check
bin/validate-phase5-distribution
bin/test --core -k phase5e
```

The distribution validator copies current source to an isolated tree, builds a
wheel and sdist with no network access, checks archive contents, installs both
outside the checkout, verifies the exact packaged prompt and every skill link,
and constructs installed standard 174-action and core-only 42-action official-
SDK runtimes. Core startup also asserts that no Codex integration module is
imported.

The current repository gate also passes 741 core tests, 2 adapter-template
tests, 16 official-SDK modern tests, and the 58-test Phase 4 acceptance runner.
The repository-local private modern binding/keyring/state files remain
unprovisioned, so default setup readiness reports `MODERN NOT READY`; the
distribution gate uses isolated private fixtures instead. MCP Inspector is
unavailable, while the exact built-in legacy stdio smoke passes with external
target traffic disabled.
