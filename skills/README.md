# Synapse Agent Skills

Skills teach an AI client to operate or develop Synapse without copying the
live Action Registry or moving scope, authority, state, or evidence into client
prompts.

## Codex profiles

Codex is the currently tested model client. The package is split into explicit
profiles under [`codex/`](codex):

- `default/` contains exactly three operating skills:
  - `operate-synapse` recovers workspace truth, keeps simple work direct,
    maintains durable progress, and selects methodology;
  - `synapse-web-pentesting` covers bootstrap, perimeter and application
    mapping, JavaScript, authentication, access control, vulnerability
    hypotheses, bounded validation, and convergence;
  - `synapse-cve-intelligence` covers component/version/CPE normalization,
    authoritative vulnerability intelligence, public-PoC applicability, and
    bounded validation recommendations.
- `multi-agent-compat/` preserves the Phase 5 coordinator and seven supporting
  router/specialist skills. Install it only when the operator explicitly wants
  that compatibility topology.
- `development/` contains `synapse-developing`, which is repository guidance
  rather than an engagement skill.

The default is one Codex agent. Start with `$operate-synapse`, do not spawn
sub-agents, and load either methodology when needed. The same agent can move
from Web Pentesting to CVE Intelligence and back while preserving workspace
revision, execution/evidence references, authority state, candidates, and gaps.

Work items are durable multi-consumer coordination records. They support
restarts, long-running responsibility, dependencies, humans, and independently
connected clients; their claims and role labels never grant authority.

## Skill authoring

Keep method selection and short recovery guidance in `operate-synapse`; put
detailed Web and CVE methodology in the respective on-demand skills and their
local `references/` files. Relative Markdown links in each `SKILL.md` must
resolve within that skill directory. Keep provider instructions out of the
application Registry and the package-owned operating prompt. The modern MCP
guidance catalog serves the three default `SKILL.md` files and their four
referenced Markdown documents from the same files used by the local installer.
Update the small hosted manifest in `synapse_mcp/guidance.py` when a selected
reference changes, then run the skill and distribution validators.

## Install and validate

Each skill contains `SKILL.md` plus `agents/openai.yaml` declaring the local
`synapse` MCP dependency. Validate authored profiles with:

```sh
bin/validate-codex-skills --check
bin/validate-codex-skills --check --profile multi-agent-compat
```

After installing a wheel or sdist, locate the selected profile with:

```sh
synapse-codex-assets --skills-dir
synapse-codex-assets --skills-profile multi-agent-compat
synapse-codex-assets --skills-profile development
synapse-codex-assets --verify
synapse-codex-assets --config standard
```

Copy only the returned profile directory into the Codex skill location. A
repository-local default install is:

```sh
SYNAPSE_SKILL_SOURCE="$(synapse-codex-assets --skills-dir)"
mkdir -p .agents/skills
cp -R "$SYNAPSE_SKILL_SOURCE"/. .agents/skills/
```

Modern clients can discover the same text at `synapse://guidance/catalog` and
read individual `synapse://guidance/skills/...` resources. MCP resource
discovery does not install or activate Codex skills; local installation remains
the supported skill-loading path.

Selecting `multi-agent-compat` requires both its skill directory and the
explicit client config profile. It does not change Synapse server behavior.
See the [Codex skill documentation](https://developers.openai.com/codex/skills)
for other installation scopes.

## Claude Code compatibility

The retained [`claude/`](claude) directory provides `synapse-ops` and
`synapse-dev`. Phase 6 does not claim Claude acceptance; those assets remain
compatibility material and still expect the server name `synapse`.
