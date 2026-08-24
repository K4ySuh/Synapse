# Synapse Documentation

This directory holds project-level documentation. Component-specific details stay
next to the component under `MCPS/`.

## Read First

- [Root README](../README.md): project overview, setup, and current runtime.
- [Architecture](Architecture.md): system boundaries and data flow.
- [Modernization](modernization/README.md): reviewed baseline, architecture decisions, and phase evidence.
- [Phase 4 handoff](modernization/phase-4-handoff.md): State Store v2 adoption, migration, backup/recovery, and acceptance.
- [Implementation Map](Implementation-Map.md): current modules, tool surface, and workflows.
- [Reporting Model](Reporting-Model.md): internal HTML report views, presentation toggle, and what reports must not do.
- [Operations](Operations.md): practical setup, workflows, cleanup, and tests.
- [Adapter Development](Adapter-Development.md): how to build safe workspace-native adapters.
- [Contributing](../CONTRIBUTING.md): development, test, documentation, and safety expectations.
- [Security Policy](../SECURITY.md): vulnerability reporting and security boundaries.
- [License](../LICENSE): project license.

## Component References

- Burp MCP notes under `MCPS/Burp-Mcp/README.md` when the optional
  PortSwigger proxy launcher is installed.
- [Synapse MCP](../MCPS/Synapse-MCP/README.md): tool surface and adapter policy.

## Current Flagship Areas

- Workspace ingestion and target context: normalized services, endpoints,
  parameters, observations, findings, actions, and raw evidence references.
- Generic background jobs: async-default `crawler`, `ffuf`, `nuclei`, and
  `nmap` execution with `jobs.*` polling and finalization.
- Workspace fingerprinting and perimeter reporting: structured technology
  components, canonical login portals, protected resources, and Markdown/HTML
  perimeter reports.
- JavaScript intelligence: JS asset discovery/fetching, static API extraction,
  inferred endpoint normalization, and sitemap-style app-map reports.
- Documentation builder: report, finding, evidence-pack, coverage, normalized
  layer, and all-layer HTML contexts with internal Operator / High-Level views.
- Access-control planner: object discovery, context records, BOLA/BOPLA/BFLA
  matrices, and approved cross-context replay.
- Web vulnerability adapters: passive analyzers for SQLi/XSS, SSRF, open
  redirect, command injection, SSTI, LFI/RFI, SSI, CSRF, CORS, XXE, GraphQL,
  insecure deserialization, security headers/cookies, JWT, and TLS posture, plus
  OpenAPI/Swagger/Postman spec import — with bounded, operator-approved active
  probes where applicable.

## Documentation Ownership

- Keep the root README short and current.
- Put durable design decisions in `Architecture.md`.
- Put operator procedures in `Operations.md`.
- Summarize shipped, user-facing changes in the committed root `CHANGELOG.md`.
- Record every agent-made code change in your local `Version-Log.md` — a
  gitignored, per-developer scratch log provisioned from
  `Version-Log.template.md` on setup, so each operator keeps their own private
  history.
- Keep generated data and engagement-specific evidence out of documentation.
