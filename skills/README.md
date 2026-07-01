# Synapse Agent Skills

Skills that teach an AI agent to drive Synapse correctly — safe operation of,
and development against, the local-first MCP control plane. They are grouped by
the agent runtime that consumes them. The two runtimes carry the same intent in
their native skill format:

- **[`claude/`](claude)** — Claude Code skills.
  - `synapse-ops` — running an authorized engagement through Synapse.
  - `synapse-dev` — reviewing, spec'ing, and modifying the Synapse codebase.
- **[`codex/`](codex)** — Codex skills (each also ships `agents/openai.yaml`).
  - `operate-synapse` — engagement operation; mirrors `synapse-ops`.
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
required `synapse` MCP tool. Install it wherever your Codex configuration loads
skills from, then reference it by name (for example `$operate-synapse`).
