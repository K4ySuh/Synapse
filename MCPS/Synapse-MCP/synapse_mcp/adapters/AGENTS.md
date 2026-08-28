# Adapter Development Instructions

- Adapters emit structured results, observations, candidates, actions, evidence
  references, artifacts, availability, and metadata. They do not render report
  sections or become a second workspace/evidence store.
- Start with parsing, dump, workspace, or disabled-traffic analysis. Separate
  passive planning from active execution and declare canonical effects, risk,
  credential need, scope behavior, replay safety, and background capability.
- Active traffic, third-party APIs, browser flows, command-backed tools,
  credential changes, and destructive local effects must cross the Registry,
  exact scope, and legacy/server-held authority gates.
- Use credential IDs and auth profiles. Do not place raw secrets in commands,
  public results, evidence, logs, fixtures, or reports; redact execution
  diagnostics before returning them.
- Prefer bounded request/workspace-native inputs so method, headers, body,
  routing, and evidence context survive. Long-running tools use durable jobs;
  timeout recovery polls existing work instead of redispatching it.
- Treat scanner and external-intelligence output as candidates until validated
  and operator reviewed. Preserve confidence, provenance, gaps, contradictions,
  scope status, and cross-asset relations; never fetch an out-of-scope related
  asset merely because it was discovered.
- Keep report rendering in `core/documentation/` and self-contained at runtime.
  Operator and High-Level are internal views, not client-redaction boundaries.
- Tests must disable real target traffic by default and use fictional hosts,
  inert commands, stubbed providers, bounded output, and explicit gate checks.
