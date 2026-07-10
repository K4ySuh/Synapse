---
name: operate-synapse
description: Operate Synapse, the local-first MCP control plane for authorized human-in-the-loop offensive security assessments. Use when Codex needs to recover or manage Synapse scope, workspaces, evidence, credentials, dumps, jobs, passive analysis, JavaScript intelligence, access-control modeling, guarded active adapters, infrastructure/OSINT adapters, or internal Synapse reports. Also use when planning approved engagement actions through Synapse MCP rather than ad hoc shell commands.
---

# Operate Synapse

## Core Rule

Use Synapse MCP as the source of truth for assessment operations: scope,
workspace state, evidence, credentials by reference, dumps, fingerprints,
adapters, background jobs, and reports.

Keep the operator in control. Scope authorization and execution approval are
separate gates. Never send active traffic, mutate Burp state, store/delete
credentials, delete local data, run command-backed scanners, or run active
validation unless the operator has approved that exact action.

## Current-State References

When operating from the Synapse repository, treat `AGENTS.md` as authoritative
policy. If behavior, schemas, or current capabilities are uncertain, read the
live repo files instead of relying on memory:

- `README.md` for system overview and current capabilities.
- `docs/Operations.md` for normal workflows, approval gates, jobs, credentials,
  active adapters, and reporting.
- `docs/Architecture.md` for boundaries and data flow.
- `docs/Implementation-Map.md` for modules, resources, and current data layout.
- `MCPS/Synapse-MCP/README.md` for exposed tool names.
- `MCPS/Synapse-MCP/synapse_mcp/transport/stdio_server.py` for exact MCP input
  schemas.

Use `adapters.list`, `adapters.capabilities`, and
`documentation.list_layers` to discover current tool behavior from the running
MCP server. If Synapse MCP tools are not visible in the current Codex session,
use tool discovery for Synapse before falling back to repo docs.

## Mode Decision

If the user asks about Synapse code, tests, docs, adapters, architecture, or
implementation changes, work in repository development mode: inspect files,
edit narrowly, and run focused tests such as `bin/test`.

If the user provides an authorized target or asks to continue an engagement,
work in assessment operation mode through Synapse MCP. Ask only for missing
target/workspace/scope details that cannot be recovered from local state.

Use direct shell commands for repository development, local file inspection,
helper launchers, and tests. For assessment operations, prefer Synapse tools so
scope, approvals, evidence, credentials, jobs, and ingestion stay connected.
Use the optional Burp MCP only for live Burp Suite state such as proxy history,
Repeater, and UI/session interactions; keep offline dump analysis and normalized
workspace memory in Synapse.

## Session Recovery

Before planning new engagement work, recover state instead of repeating work:

1. Identify workspace and target from the user request or local Synapse state.
2. Check active work with `jobs.list(activeOnly=true)` and poll relevant jobs
   with `jobs.status(jobId=...)`.
3. Inspect available offline data with `dumps.list`.
4. Check scope for a concrete host or URL with `scope.check_target`.
5. Review compact context with `workspace.summary`,
   `workspace.prepare_target_context`, `evidence.tail`,
   `evidence.host_context`, and `fingerprint.read_host` where useful.
6. If no project exists and the operator supplied authorized assets, initialize
   with `project.start`; otherwise use `scope.set` only for explicit authorized
   hosts, patterns, or CIDRs.

When multiple assets are in scope, do not infer they are one application or one
engagement unless the operator says so.

## Active Approval Gate

Before any active action:

1. Check exact target scope.
2. Explain the tool/action, target, expected traffic or mutation, output
   handling, and risk tier.
3. Ask for explicit approval for that exact action.
4. After approval, pass `confirm=true` and approval metadata such as
   `approvalReason`, `approvalId`, and `riskTier` when supported.
5. Prefer background execution for long-running tools, then poll with
   `jobs.status`.

Do not turn a passive plan into active testing without a new approval. Do not
escalate from benign validation to destructive exploitation. Never use sqlmap
OS shell, file read/write, registry, privilege escalation, or post-exploitation
features.

## Passive-First Workflow

Default to this sequence:

1. Establish workspace and scope with `project.start` or `scope.set`.
2. Import or analyze passive data with `workspace.ingest_data`,
   `sitemap.from_dump`, `sqli.analyze_dump`, `xss.analyze_dump`, or other
   no-traffic analyzers.
3. Refresh target understanding with `fingerprint.analyze_workspace`,
   `perimeter.analyze_workspace`, and `perimeter.build_summary`.
4. Use JavaScript intelligence after endpoints exist:
   `js.discover_assets` is passive; `js.fetch_assets` sends traffic and needs
   approval; `js.analyze_static` and `js.normalize_endpoints` operate on local
   assets and usually run as jobs.
5. Run passive candidate analyzers before validation: SSRF, open redirect,
   command injection, SSTI, LFI/RFI, SSI, headers/cookies, CSRF, CORS, XXE,
   insecure deserialization, GraphQL, TLS posture, JWT, SQLi, and XSS modules.
6. Generate test plans and replay previews where available.
7. Run candidate-specific active validation only after exact approval.
8. Promote candidates to findings only after operator review, then render
   internal reports from workspace state.

Treat scanner output and analyzer output as candidates until reviewed. Keep
confirmed facts, assumptions, candidates, and gaps distinct in responses.

## Credentials And Auth

Use credential IDs and auth profile IDs, never raw secrets in commands, notes,
evidence, or final responses.

Before storing reusable credentials or auth profiles, ensure target scope is
set and ask for explicit approval. Use:

- `credentials.set` for scoped static HTTP credentials.
- `credentials.set_auth_profile` and `credentials.authenticate` for approved
  HTTP login refresh flows.
- `credentials.set_browser_auth_profile`,
  `credentials.browser_auth_check_setup`, and
  `credentials.browser_authenticate` for SSO, MFA, CAPTCHA, device approval, or
  JavaScript-heavy flows.
- `credentials.validate_session` only after approval because it sends traffic.

For complex auth, ask the operator to describe the flow before automation. Use
manual browser completion or Burp-derived context when automation would be
fragile.

## Active Tool Families

Use the lowest-noise bounded option that answers the question:

- Crawling: `crawler.crawl` defaults to background jobs and GET-oriented
  mapping; it records cross-host/out-of-scope relations without fetching those
  assets. `crawler.extended` submits POST forms and needs stronger approval.
- Discovery/scanning: `ffuf.run_profile`, `nuclei.run_profile`, and
  `nmap.run_profile` are approval-gated and job-oriented.
- OSINT: Shodan runtime-key and API-backed operations require the relevant
  operator approval and should be normalized before driving conclusions.
  Review per-asset ingestions and `asset_relation`/`dns_resolution` records;
  do not treat ordinary DNS resolution as an origin-IP leak.
- CVE intelligence: fingerprint versions first. Version-unknown components
  produce precision gaps and skip broad NVD lookup by default; use
  `includeVersionUnknown=true` only for an explicitly broad, corroboration-gated
  run. Successful reruns retire stale unreviewed source candidates without
  deleting history; source failures preserve prior candidates.
- Access control: use `access_control.identify_objects`,
  `access_control.record_context`, `access_control.build_test_matrix`, and
  `access_control.plan_tests` before any
  `access_control.execute_matrix_test`.
- Active web probes: CORS, GraphQL, command injection, SSTI, LFI/RFI, and SSI
  active tests must be specific, benign, scoped, and approved.

If a tool returns a `jobId`, report it and poll with `jobs.status`. If an MCP
call times out, check `jobs.list(activeOnly=true)` and poll likely jobs before
rerunning anything.

## Evidence, Findings, Reports

Log important operator-reviewed milestones, assumptions, approvals, commands,
and decisions with `evidence.log_event` when useful.

Ingest external outputs and operator notes through `workspace.ingest_data` so
raw evidence, normalized entities, scope status, and summaries stay linked.

Do not create confirmed findings directly from raw candidates. Deterministic
passive analyzers may create `operatorReviewed=false` findings, which still
need operator signoff. Use
`workspace.promote_observation_to_finding`, `workspace.create_finding`,
`workspace.update_finding`, `workspace.link_evidence_to_finding`, and
`workspace.mark_finding_reviewed` according to operator review.

Reports are internal operator artifacts unless the user explicitly requests a
separate deliverable. The current `high_level` view is concise internal
presentation, not a redaction boundary or client-safe export. Build reports
with `documentation.*`, `perimeter.render_report`, or `js.render_app_map` from
workspace state, not disconnected notes.
