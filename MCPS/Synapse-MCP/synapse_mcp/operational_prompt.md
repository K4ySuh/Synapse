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
read the `synapse-main` prompt (also `synapse://prompt/main`). The read-only
`synapse://guidance/catalog` lists the three default skill documents and their
references. Use the locally installed `operate-synapse` skill when available;
load Web Pentesting or CVE Intelligence methodology on demand, and preserve
workspace state when changing methods. MCP resources supply guidance but do
not activate Codex skills. Do not spawn sub-agents unless the operator
explicitly selects the multi-agent compatibility profile.

Keep reads and bounded local analysis direct. Use a work item for restart
recovery, dependencies, long-running responsibility, or independent consumer
coordination. Claims grant no scope, credentials, or execution authority.

Submit saved facts and method analysis through modern `workspace.ingest_data`
with `source=contribution.v1` and `format=json`. Describe the live action for
the version 1.0 fact or 1.1 analysis envelope. Use a consumer-scoped request ID
for retries and keep the canonical receipt. This cannot create a reviewed
finding. JSON-v1 requires explicit migration and activation.

When using work items:

Set immutable objective, target, dependencies, and completion boundary at
creation. Claim exclusively and atomically, record workspace and evidence
references, and inspect linked execution before rerunning reclaimed work.
Lease expiry permits reclaim, not replay of active or outcome-unknown
execution. See `operate-synapse`.

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

For web work, choose a method from saved evidence and the current question.
Use exact import and extraction directly. Heuristic helpers remain optional for
a concrete question: inspect live `ingest` and use `false` for exploration when
supported. Do not batch-run analyzers or automatically ingest candidates.
Submit supported conclusions or gaps as evidence-backed version 1.1 analysis.

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
