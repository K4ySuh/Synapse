# Synapse MCP Development Instructions

These instructions apply to the Python MCP package and are additive to the
repository root policy.

## Boundaries

- Keep application contracts under `synapse_mcp/app/`, durable policy under
  `synapse_mcp/policy/`, storage under `synapse_mcp/state/`, operational modules
  under `synapse_mcp/core/`, adapters under `synapse_mcp/adapters/`, and protocol
  mapping under `synapse_mcp/transport/`.
- Transport code validates and projects application contracts; it must not own
  new authority, workspace, work-item, evidence, or lifecycle rules.
- Every executable action enters the same frozen Action Registry, canonical
  effect resolution, scope/authority evaluation, dispatcher, result, and audit
  path. Keep action IDs and legacy aliases stable.
- Capability-pack selection is trusted startup configuration. Catalog and
  Registry assembly are deterministic and freeze before requests; unselected
  actions must remain unreachable.
- Keep `modern-compact` at eleven application operations and within its accepted
  wire-size gate. Default direct and frozen legacy retain their reviewed action
  identity and order.
- Provider-specific integration assets belong under integration or skill paths.
  Core modules must not import a model/client SDK or read Codex-specific config.

## Runtime and packaging

- The package-owned `synapse_mcp/operational_prompt.md` is the runtime MCP
  guidance. Do not expose root repository-development instructions as the main
  operational prompt.
- Package data, repository launches, wheels, and sdists must expose equivalent
  operational guidance. Preserve the legacy prompt/resource discovery shape.
- Keep the Python package and `synapse-mcp-modern` launcher canonical. Document
  standard, core-only, modern-direct diagnostic, and legacy rollback profiles.
- Package Codex skills as integration data without making application behavior
  depend on them.

## Change procedure

- Read `README.md`, `docs/Architecture.md`, `docs/Implementation-Map.md`,
  `docs/Operations.md`, and the relevant implementation before editing.
- Prefer typed protocol-independent services and repository contracts. Avoid a
  new frontend, report engine, database, migration, plugin marketplace, or agent
  scheduler unless explicitly requested.
- Preserve opaque resource binding, request-state replay protection, timeout
  recovery, exact approval outcomes, and local evidence linkage.
- Run focused tests plus inventory/surface checks appropriate to the change.
  Packaging changes must build and validate both a wheel and an sdist.
