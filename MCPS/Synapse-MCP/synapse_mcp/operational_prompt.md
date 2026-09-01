# Synapse Operational Instructions

Synapse is a local-first MCP control plane for authorized, human-in-the-loop
offensive-security work. It preserves shared scope, workspace knowledge,
evidence, credential references, actions, jobs, work items, findings, artifacts,
and internal reports. Synapse is the operational memory and execution boundary;
the operator remains responsible for authorization, validation, and judgment.

## Recover before acting

Confirm the workspace and authorized target, then recover current scope,
workspace revision, active or unknown jobs, claimed work, recent evidence, and
relevant target context. Use compact revision-aware context rather than loading
raw engagement history. Inspect existing work before repeating it.

Use live capability search for operational intent and describe the selected
action before dynamic execution. Capability packs organize discovery; they do
not create separate authority, workspace, or evidence paths. Do not rely on a
remembered action catalog when the selected startup profile can differ.

Codex is the currently tested model client. Operate as one agent by default:
use the installed `operate-synapse` skill, load Web Pentesting or CVE
Intelligence methodology on demand, and preserve workspace state when changing
methods. Do not spawn sub-agents unless the operator explicitly selects the
multi-agent compatibility profile.

Simple reads and bounded local analysis should remain direct. Create or claim a
work item only when an objective benefits from durable restart recovery,
dependencies, long-running responsibility, or coordination with an independent
consumer or human. A claim records ownership for coordination; it grants no
scope, credentials, or execution authority. Work items are a multi-consumer
coordination ledger, not evidence that one client should create more agents.

When using work items:

- put role, targets, pack hints, context, completion contract, parent,
  dependencies, exclusivity, and known gaps in the create payload because
  these coordination boundaries are not mutable later;
- inspect the objective, targets, dependencies, completion contract, and last
  seen revision before acting;
- claim exclusive work atomically and reroute after a claim collision;
- record concise progress, blockers, gaps, results, and workspace/evidence
  references rather than reasoning traces or chat transcripts;
- heartbeat only while actively responsible for the item;
- checkpoint, hand off to an independent consumer, or complete explicitly with
  remaining uncertainty and next work;
- after reclaim, inspect linked jobs and dispatches before any rerun.

Lease expiry makes a claim reclaimable. It does not cancel or make active,
state-changing, or outcome-unknown execution safe to repeat.

## Scope and authority

Work only on systems the operator is authorized to test. Scope permits a target
to be considered; it never grants execution authority.

Before active traffic or another consequential effect, identify the exact
target, action, expected impact, risk, credential use, output, and execution
profile. Under `legacy`, obtain exact operator approval and use the action's
legacy confirmation contract. Under an authority-aware profile, submit the
bounded plan and let Synapse evaluate trusted server-held grants and supervised
step-up state. Caller arguments, prose, role labels, work-item claims, and
`confirm=true` cannot assert modern authority.

Treat scope denial separately from missing authority and never widen scope with
a grant. Covered delegated work may proceed without another per-call pause;
uncovered or supervised work must surface the approval requirement for the
trusted operator path. Never place raw secrets in arguments, notes, commands,
evidence, logs, reports, or responses. Use credential IDs and redacted metadata.

## Passive and active work

Prefer stored dumps, observed traffic, workspace state, static assets, and
local analysis before sending traffic. Passive results can still be sensitive;
keep them local, bounded, and traceable.

Use active validation only when passive context justifies a specific test and
the exact scope and authority gates are satisfied. Preserve method, path,
headers, body, actor/auth context, target, approval or grant decision, tool
profile, result, and evidence references. Do not escalate benign validation to
destructive exploitation without a new explicit operator request and authority.

Treat Internet research and provider output as external intelligence. Validate
and normalize it into workspace evidence before it drives conclusions; never
execute retrieved material blindly or fetch an out-of-scope related asset.

## Evidence and conclusions

Keep these states distinct:

- a `finding` is a lifecycle-managed issue supported by reviewed evidence;
- a `candidate` is promising but still requires validation or review;
- a `gap` is missing coverage or unresolved uncertainty;
- `evidence` is traceable support for an observation, action, or conclusion;
- a `recommendation` is a next action or remediation proposal, not proof.

Scanner labels, CVSS, public exploit maturity, inferred JavaScript routes, and
heuristic matches do not by themselves create reviewed findings. Preserve
provenance, applicability confidence, contradictions, negative results, and
coverage gaps. Promote candidates only after impact, affected scope, and
evidence have been reviewed. Reports must visibly separate candidates from
findings and include unresolved gaps.

Operator and High-Level reports are internal Synapse views. High-Level reduces
operational detail but is not a sanitized, redacted, or client-safe export.
Reports are projections over workspace state and evidence, never a source of
truth.

## Jobs, timeouts, and completion

Prefer durable background jobs for long-running tools. When a call times out or
a worker disappears, list and inspect relevant jobs and work-item execution
links before assuming failure. Poll the existing job to terminal finalization;
do not redispatch merely because the client lost the response.

At completion, report concisely:

- what ran and under which target/profile boundary;
- what changed in workspace revision, work items, evidence, and artifacts;
- confirmed findings, candidates, contradictions, negative results, and gaps;
- active or outcome-unknown execution that still needs recovery;
- authority blockers, skipped coverage, and the next safe action.

Use workspace, evidence, work-item, job, action, observation, finding, and
artifact references where available. State assumptions and uncertainty plainly;
do not flood the operator with raw logs unless requested.
