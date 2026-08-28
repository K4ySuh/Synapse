# Synapse Agent Skills

Skills that teach an AI agent to drive Synapse correctly — safe operation of,
and development against, the local-first MCP control plane. They are grouped by
the agent runtime that consumes them:

- **[`claude/`](claude)** — Claude Code skills.
  - `synapse-ops` — running an authorized engagement through Synapse.
  - `synapse-dev` — reviewing, spec'ing, and modifying the Synapse codebase.
- **[`codex/`](codex)** — Codex skills (each also ships `agents/openai.yaml`).
  - `operate-synapse` — route simple work or select a bounded playbook.
  - `synapse-coordinate-engagement` — coordinate independent specialists and
    converge durable results.
  - `synapse-engagement-bootstrap` — recover or initialize authorized
    engagement state.
  - `synapse-perimeter-triage` — perform passive-first perimeter and
    infrastructure triage.
  - `synapse-web-assessment` — model web applications and triage candidates.
  - `synapse-access-control` — model actor/object/function/property access.
  - `synapse-cve-validation` — correlate versioned components and plan bounded
    CVE validation.
  - `synapse-reporting` — render coherent internal reports from workspace
    truth.
  - `synapse-developing` — codebase work; mirrors `synapse-dev`.

Both runtimes expect the Synapse MCP server to be registered as `synapse` — see
the repo [README](../README.md) and [Operations](../docs/Operations.md) for
setup.

## Claude Code

Copy a skill directory into your skills path — user-wide or project-scoped:

```sh
# user-wide (available in every session)
cp -r skills/claude/synapse-ops ~/.claude/skills/synapse-ops
cp -r skills/claude/synapse-dev ~/.claude/skills/synapse-dev

# or project-scoped (loads only inside this clone)
cp -r skills/claude/synapse-ops .claude/skills/synapse-ops
```

Claude Code discovers each skill from its `SKILL.md` frontmatter and invokes it
by name when a task matches the description.

## Codex

Each Codex skill is a `SKILL.md` plus `agents/openai.yaml` that declares the
required `synapse` MCP tool. Install the complete `skills/codex/` package in a
Codex skill directory so specialist links can resolve the two shared references
owned by `operate-synapse`. Then invoke `$operate-synapse`; use a specialist
skill directly only when its bounded role is already clear.

The operating skills contain methodology, not a copy of Synapse's action
catalog or schemas. They search and describe the selected live Registry at run
time. Work claims, role names, and skill selection are coordination metadata;
they do not grant scope or execution authority.

Validate an authored or updated checkout before installation:

```sh
bin/validate-codex-skills --check
```

Wheel and sdist installations ship the same Codex tree and configuration
examples. Locate or verify the installed assets with:

```sh
synapse-codex-assets --skills-dir
synapse-codex-assets --verify
synapse-codex-assets --config standard
```

Copy the entire returned directory, not individual specialists, so both shared
references remain resolvable. For a repository-local Codex install, copy its
contents into `.agents/skills/`:

```sh
SYNAPSE_SKILL_SOURCE="$(synapse-codex-assets --skills-dir)"
mkdir -p .agents/skills
cp -R "$SYNAPSE_SKILL_SOURCE"/. .agents/skills/
```

See the [official Codex skill documentation](https://developers.openai.com/codex/skills)
for the other supported scopes. Standard uses modern compact with all built-in
packs; the other installed templates cover core-only compact, direct diagnostic,
and frozen legacy rollback.

The validator covers the eight operating skills, their interface metadata and
shared links, and rejects copied contracts or terminology that contradicts the
server-held authority and candidate/finding boundaries.
