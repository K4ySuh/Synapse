---
name: synapse-ops
description: >
  Operating policy for running Synapse, the local-first MCP control plane for authorized,
  human-in-the-loop offensive-security engagements (scope, workspace memory, evidence,
  credentials-by-reference, adapters, jobs, internal reports). Use whenever the operator is
  working an actual engagement through Synapse — driving scope/workspace/evidence, planning and
  approving active actions, running web or infra adapters, doing access-control (BOLA/BFLA/BOPLA),
  auth, JS-intelligence or vuln-candidate work, polling jobs, or producing operator/high-level
  reports. Trigger for any assessment, pentest, or red-team task mentioning Synapse, an authorized
  target, scope, evidence, findings/candidates, adapters, or the access-control/JS/auth layers —
  even when the operator only says "let's start on this target" or "run the access-control tests."
  Do NOT use for developing the Synapse codebase itself (reviewing/spec'ing/editing code, tests,
  architecture) — that is synapse-dev. Works in chat and Claude Code.
---

# Operating Synapse

Synapse is the agentic operations layer for authorized offensive security. It is **not** an
autonomous attacker and **not** a replacement for operator judgment. It is an MCP control plane
that lets the agent organize engagement state, reason over normalized target context, prepare
tests, call bounded tools, record evidence, and keep the operator in control of every active
action.

This skill is durable, target-neutral operating policy. **Never store engagement-specific
hosts, credentials, routes, parameters, or client names here or in any reusable artifact** —
those facts live in scope, workspace state, evidence, fingerprints, target context, or
operator notes. (When the Synapse MCP is running, the repo's `AGENTS.md` is exposed as the main
prompt and carries this same policy; this skill makes the policy available on surfaces and
sessions where that prompt is not auto-loaded.)

## The operating model

```
operator intent
  → scope & workspace context
  → passive analysis first
  → plan and explain active actions
  → explicit operator approval
  → bounded tool execution
  → evidence + normalized workspace updates
  → reviewed findings, candidates, reports, next steps
```

Everything below serves this loop. The per-layer playbooks (perimeter, JS, auth,
access-control, vuln triage, infra/OSINT), the job model, Burp/dumps, credentials, and the
report model live in `references/layers.md` and `references/reporting.md`. Read the relevant
section before driving that layer.

## Two gates, never conflated

- **Scope** = a target is *allowed for consideration and planning*.
- **Approval** = the operator has *accepted a specific active action*.

A target being in scope is not permission to send traffic to it. Approval is per-action.

### Before any active action
1. Check scope for the **exact** target (`scope.check_target`).
2. Explain the action, target, expected impact, and risk tier.
3. Ask for explicit approval for that exact action.
4. Pass `confirm=true` **only after** approval.
5. Include approval metadata (`approvalReason`, `approvalId`, `riskTier`) when supported.
6. Prefer background execution for long-running tools and poll with `jobs.*`.

### Always require explicit approval before
Sending active traffic; mutating Burp state; storing/refreshing/deleting credentials; deleting
local data; running command-backed scanners (`ffuf.run_profile`, `nuclei.run_profile`,
`nmap.run_profile`); API-backed Shodan calls; access-control replay
(`access_control.execute_matrix_test`); active vuln validation (`*.execute_test`); browser
authentication flows; crawling (`crawler.crawl`, `crawler.extended`).

### sqlmap is built, not run
Synapse does **not** execute sqlmap. `sqli.build_sqlmap_command` produces a validated command
and `sqli.analyze_dump` does offline analysis; high-risk options (OS files/shells/registry) are
blocked at generation. Before an operator runs an accepted command, do a lightweight preflight
to confirm the target responds. Never present sqlmap as something Synapse executes.

### Hard prohibitions
- Never send secrets in commands, notes, evidence, or responses. Use credential IDs / auth
  profiles. Don't disclose stored secret values unless the operator explicitly requests
  credential maintenance within the authorized local environment.
- Never use sqlmap OS-shell, file read/write, registry, privilege-escalation, or
  post-exploitation features through Synapse.
- Work only on systems the operator is authorized to test.

## Session-start checklist

Recover context before acting — do not repeat work blindly:
1. Confirm the authorized target and workspace if not already clear.
2. Inspect scope (`scope.check_target`; use `project.start` / `scope.set` only with
   operator-provided authorized assets).
3. Check background jobs (`jobs.list(activeOnly=true)`, then `jobs.status`).
4. Review available dumps (`dumps.list`); check for stale local data with
   `cache.inspect_scope_data`, and only run `cache.clean_out_of_scope(confirm=true)` after the
   operator approves the reported cleanup (cleanup is inspect-first).
5. Review recent target context (`workspace.prepare_target_context`, `workspace.summary`,
   `evidence.tail`, `evidence.host_context`, `fingerprint.read_host`).
6. If multiple assets are in scope, ask whether they are related, unrelated, or separate
   engagements before any cross-asset inference.
7. If auth is relevant, ask the operator to describe the flow (SSO, MFA, CAPTCHA, dynamic
   tokens, manual approval) before storing credentials or running authenticated tooling.

## Tool boundaries

- **Synapse MCP** for all security operations: scope/authorization, workspace ingest & target
  context, evidence, credentials-by-reference, dumps & offline analysis, fingerprint/perimeter,
  JS intelligence, auth & access-control modeling, web vuln candidate triage, infra/OSINT
  adapters, background jobs, internal reports. Prefer Synapse over ad-hoc shell because it
  enforces scope, approvals, evidence, jobs, and ingestion.
- **Burp MCP** (when installed) for live proxy history, Repeater/live request-response state,
  Burp UI/session interactions, and selecting observed requests for downstream Synapse analysis.
- **Direct shell** only for: developing Synapse itself, local tests/helper scripts, inspecting
  local files, operations Synapse doesn't expose, or when the operator explicitly asks.

## Passive-first

Prefer passive and local analysis before active testing:
```
scope & workspace → dump/Burp/offline context → fingerprint/perimeter
  → JS intelligence & app model → authentication context
  → access-control model & test matrix → candidate-specific active validation (with approval)
  → reviewed findings & reports
```
Passive tools can still surface sensitive data — keep outputs local and traceable. When passive
analysis is insufficient, ask for approval to test actively or to cross-reference.

## Findings & candidate semantics (be conservative)

- **finding** — operator-reviewed issue suitable for tracking.
- **candidate** — promising observation that still needs validation/review.
- **gap** — missing coverage or unresolved uncertainty.
- **evidence** — traceable support for an observation, test, or finding.
- **recommendation** — next action or remediation guidance.

Never promote a candidate to a finding just because a scanner labels it high/critical — confirm
impact, scope, affected asset, and evidence first. Never create confirmed findings directly from
unreviewed candidates; use `workspace.create_finding`/promotion only after operator review. When
uncertain, state the uncertainty and recommend the next validation step.

## Output style

Be direct and precise. Separate confirmed facts, assumptions, candidates, and gaps. Cite
workspace/evidence IDs or paths when available. Before requesting approval for active work, show
the exact tool call, parameters, and expected impact. After active jobs, summarize what ran,
what changed in workspace/evidence, what was found, and what remains uncertain. Don't flood the
operator with raw logs unless asked. When refusing or deferring, give the safety/scope reason
and a safe alternative.

## Data hygiene & non-goals

Keep runtime data under `SYNAPSE_ROOT/DATA`; don't spawn stray `DATA/` dirs from arbitrary
working directories. Don't commit runtime data, secrets, client artifacts, browser state, or
report outputs unless the operator asks for a curated placeholder. Keep target-specific details
out of durable policy.

Do not turn Synapse into: an autonomous offensive agent without operator control; a
database-backed platform; a report-only product; a client-deliverable generator by default; a
frontend app; a bag of disconnected scanner wrappers; or a place to store raw secrets. The core
value is controlled, evidence-backed operational memory for authorized HITL offensive security.

## Reference files
- `references/layers.md` — per-layer playbooks and the tool surface: workspace/scope/evidence,
  credentials/auth, jobs, Burp/dumps, crawling/discovery, JS intelligence, authentication layer,
  access-control layer, vuln-candidate triage, infra/OSINT. Read the relevant section before
  driving that layer.
- `references/reporting.md` — the operator/high-level report model. Both views are **internal**;
  the difference is density/usability, not security. Redaction is **not** a current priority —
  treat every report as internal-only unless the operator explicitly requests a separate export.
