---
name: synapse-developing
description: Develop the Synapse repository, MCP server, adapters, workspace/evidence model, documentation layer, tests, and project docs. Use when Codex is asked to modify or review Synapse code, tool schemas, adapter behavior, report rendering, scope/credential/job safety semantics, architecture, docs, version log entries, setup scripts, or tests.
---

# Synapse Developing

## Core Rule

Treat Synapse development as work on a local-first, operator-controlled MCP
control plane for authorized security assessments. Preserve the existing
architecture unless the operator explicitly asks for a larger change.

Keep edits small, compatible, and aligned with existing module boundaries. Do
not introduce a database, frontend app, autonomous agent loop, storage
migration, report product, plugin marketplace, or disconnected scanner wrapper
unless the operator asks for that direction.

## Current-State References

Before editing, read the relevant live files instead of relying on memory:

- `AGENTS.md` for repository and operating policy.
- `README.md` for current capabilities and concepts.
- `docs/Architecture.md` for boundaries and data flow.
- `docs/Implementation-Map.md` for module ownership and data layout.
- `docs/Operations.md` for workflows, setup, jobs, credentials, and reports.
- `MCPS/Synapse-MCP/README.md` for MCP component notes and exposed tools.
- `MCPS/Synapse-MCP/synapse_mcp/transport/stdio_server.py` for exact tool
  schemas, resources, prompts, and dispatch.
- `MCPS/Synapse-MCP/tests/` for regression patterns.

Use `rg` / `rg --files` for repository search. Inspect surrounding tests before
editing behavior.

## Development Workflow

1. Classify the request: code change, bug fix, review, docs, adapter work,
   reporting, tests, or architecture.
2. Read the relevant docs and implementation files first.
3. Locate the owning module and tests; avoid cross-cutting rewrites unless the
   request requires them.
4. Make the narrowest coherent change.
5. Preserve scope checks, confirmation gates, approval metadata, credential
   references, redaction, evidence logging, candidate semantics, background job
   behavior, and passive/active separation.
6. Add or update focused tests for changed behavior.
7. Update the local `docs/Version-Log.md` (gitignored per-developer scratch log,
   provisioned from `docs/Version-Log.template.md` on setup) when behavior,
   architecture, user-visible capabilities, reports, setup, or safety semantics
   change. At ship time, summarize the shared narrative into the committed
   root `CHANGELOG.md`.
8. Run focused tests, preferably through `bin/test`; run broader tests when the
   change touches shared models, transport, ingestion, adapters, or reports.

Do not modify runtime `DATA/` artifacts, credentials, generated reports,
browser state, or client artifacts unless the operator explicitly requests a
curated sample.

## Module Boundaries

Keep these ownership lines intact:

- `transport/stdio_server.py`: MCP JSON-RPC boundary, tool schemas, resources,
  prompts, dispatch, and transport deadlines.
- `core/scope.py`: global authorization scope and target checks.
- `core/workspace.py`: workspace files, ingestion, entity normalization,
  deduplication, findings, and compact planning context.
- `core/evidence.py`: sanitized event logging and host evidence context.
- `core/credentials.py`: scoped credential storage, auth profiles, browser auth,
  redacted retrieval, and credential resolution.
- `core/background_jobs.py`: durable jobs, status, cancellation, finalization,
  and job metadata.
- `core/http/`: bounded HTTP policy, backends, models, client behavior, and
  response comparison.
- `core/fingerprint.py`, `core/perimeter.py`, `core/js/`: passive derived
  models over stored workspace/evidence state.
- `core/documentation/`: report contexts, layer providers, renderers, exports,
  redaction policy, templates, and shared assets.
- `core/adapters/`: adapter metadata, registry, base interface, result models,
  and workspace-native entity bundles.
- `adapters/web/`: web app crawling, content discovery, passive web analyzers,
  active web probes, JS adapter glue, and access-control adapter.
- `adapters/infra/`: infrastructure and OSINT adapters such as nmap and Shodan.

Adapters should emit structured results, observations, findings, actions,
evidence references, and metadata. They should not render report sections
directly; reporting belongs under `core/documentation/`.

## MCP Tool Changes

When adding or changing an MCP tool:

- Update `TOOL_SCHEMAS` and dispatch together in `transport/stdio_server.py`.
- Keep schemas precise but compatible with existing callers.
- Record active approval fields consistently when the tool sends traffic or
  mutates state.
- Use background jobs for long-running or command-backed work unless the action
  is deliberately bounded and synchronous.
- Add tests that call the dispatch layer or the owning module directly.
- Update `MCPS/Synapse-MCP/README.md` and relevant docs when the public tool
  surface changes.

If a synchronous tool can exceed transport deadlines, redesign it as a
background job or add an explicit total wall-clock budget. Do not depend on a
timeout as normal control flow.

## Adapter Changes

For passive adapters, read existing workspace, dumps, fingerprints, or operator
data and optionally ingest observations through `workspace.ingest_data`. Make
scope status explicit without hiding passive out-of-scope input.

For active adapters:

- Enforce exact target scope before execution.
- Require `confirm=true` and include approval metadata.
- Prefer a no-traffic command/plan builder separate from the run method.
- Use credential IDs, never raw secrets.
- Redact secret-bearing fields before evidence or responses.
- Store raw output as evidence and normalize structured output into workspace
  entities.
- Default command-backed or long-running work to background jobs and finalizers.
- Treat scanner output as candidates until operator review.

Place new web functionality under `adapters/web/` and infrastructure or OSINT
functionality under `adapters/infra/`. Register metadata through
`core/adapters/registry.py` so `adapters.list` and `adapters.capabilities`
describe traffic impact, safety, limitations, and output expectations.

## Workspace And Findings

Keep workspace state and evidence as the source of truth. The ingestion model is
two-phase: parser/adapter output first becomes structurally sane entities, then
workspace-aware normalization adds timestamps, affected assets, evidence
validation, enum enforcement, stable keys, and deduplication.

Use stable content-derived keys for repeated observations/findings. Do not use
mutable fields such as `evidenceIds` as deduplication identity.

Maintain conservative semantics:

- `candidate`: requires validation or review.
- `finding`: operator-reviewed issue suitable for tracking.
- `gap`: missing coverage or unresolved uncertainty.
- `evidence`: traceable support for an action, observation, or finding.

Do not promote scanner labels or passive observations into confirmed findings
in code.

## Documentation And Reports

Build reports from workspace entities and documentation contexts. Reports are
derived views, not source data.

Preserve the current internal report model:

- `operator` view: detailed operational context and traceability.
- `high_level` view: concise internal summary, not a redaction boundary and not
  client-safe by default.

Keep candidates visually and textually distinct from confirmed findings. Include
coverage and gaps when useful. Avoid adding external report dependencies unless
the operator explicitly accepts that tradeoff.

## Testing

Use the project harness from the repository root:

```bash
bin/test
bin/test --core
bin/test --template
bin/test --core -k access_control
```

The harness configures `PYTHONPATH` for `MCPS/Synapse-MCP` and uses
`SYNAPSE_PYTHON`, the active virtualenv, `.venv/bin/python`, or `python3`.

Choose focused tests based on the changed surface:

- Transport/tool schemas: `test_tool_wrappers.py` and targeted dispatch tests.
- Scope, credentials, evidence, jobs, paths, workspace state:
  `test_core_state.py`, `test_paths.py`, and focused module tests.
- Ingestion and entity normalization: `test_workspace_ingestion.py`.
- Dumps, sitemap, SQLi/XSS passive behavior: `test_dump_analysis.py`.
- Web discovery, active probes, and passive analyzers:
  `test_web_discovery_adapters.py`, `test_reference_web_adapters.py`.
- Access control: `test_access_control_adapter.py`.
- JavaScript intelligence: `test_js_intelligence.py`.
- Perimeter and fingerprint output: `test_perimeter.py`.
- Documentation/report rendering: `test_documentation.py`.
- Adapter framework and custom template: `test_adapter_framework.py` and
  `bin/test --template`.

If tests cannot run because dependencies are missing, state that clearly and
explain what was validated instead.

## Final Checks

Before finishing a development task:

- Review `git diff` for unrelated churn.
- Ensure no secrets, runtime data, generated client artifacts, `__pycache__`,
  or local reports were added unintentionally.
- Confirm docs and version log updates match the blast radius.
- Summarize changed files, tests run, and any residual risk.
