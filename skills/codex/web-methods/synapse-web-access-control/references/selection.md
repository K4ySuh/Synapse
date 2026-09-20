# Access-control procedure

## Select this method

Select `synapse-web-access-control` when the current question compares what an
actor may read, create, change, delete, invoke, or transition across an object,
function, property, tenant, role, ownership boundary, or workflow state.
Respect an explicit operator selection.

Use `synapse-web-auth-session` when the unresolved question is how identity or
session state is established, rotated, recovered, or ended. Return to the main
web method for broad surface mapping or for a vulnerability family outside this
boundary.

Read the main skill's shared comparison foundations once when needed. Hosted,
they are at
`synapse://guidance/skills/synapse-web-pentesting/references/auth-and-access-control.md`.
For native skills installed beside the default profile, open
`synapse-web-pentesting/references/auth-and-access-control.md` under the same
skill root. The catalog maps hosted URIs; relative Markdown paths do not resolve
through MCP by themselves.

## Required context

Recover the workspace revision and target, then gather only what the comparison
needs:

- two well-defined actor contexts or one actor and a documented policy
  boundary, including role, ownership, tenant or trust domain, authentication
  state, and approved credential or auth-profile references;
- a stable subject: canonical route and method plus object shape or ID source,
  function, property, tenant, or workflow transition;
- expected allow or deny behavior and its policy basis, with request
  preconditions and object ownership or state;
- canonical request, response, and state evidence IDs for a known-allowed
  baseline and the minimal changed comparison;
- observable success criteria, pre/post state, indirect effects, and telemetry
  limits.

If actor equivalence, ownership, expected policy, baseline behavior, subject
identity, state, or evidence is unreliable, record that exact coverage gap.

## Analyze the comparison

Change one relevant dimension at a time. Compare actor, object ownership,
tenant, function, property set, or workflow state while retaining method,
route, request shape, and preconditions where possible. Ask whether enforcement
occurs on the server for direct requests as well as the visible UI, whether
read and write controls differ, whether nested or bulk operations expose extra
properties, and whether an indirect or asynchronous effect crossed the same
boundary.

Prefer a minimal known object or harmless state transition. Establish the
allowed control before interpreting the denied case. Preserve redirects,
challenges, partial bodies, property differences, and resulting state. A
different status, length, timing, or identifier pattern is a signal to explain,
not automatic proof of unauthorized access.

## Test alternative explanations

Account for expired or refreshed sessions, object absence, validation or parser
differences, tenant routing, eventual consistency, caching, localization,
content negotiation, rate limiting, WAF behavior, feature flags, and a policy
that legitimately delegates the operation. Distinguish a UI restriction from
server enforcement, a masked response from actual object access, and request
acceptance from a completed state change. Confirm that actor and object
substitutions did not also change an unrelated precondition.

## Weigh evidence and unknowns

Supporting evidence ties the unauthorized actor and stable subject to a
repeatable protected result: returned object data, accepted function, exposed
property, cross-tenant effect, or verified state change, with the allowed
control and canonical exchange or state evidence. Contrary evidence includes a
consistent denial with no side effect, server-side ownership enforcement,
independent state showing no change, expected policy that permits access, or an
alternate cause that explains the signal.

State unresolved questions explicitly: missing owner control, uncertain role or
tenant, unobserved side effect, asynchronous completion, masked response,
property-level difference, alternate route or method, workflow precondition,
bulk behavior, or missing telemetry. A negative pair covers only that actor,
subject, operation, and state.

## Contribute canonically

Describe the live `workspace.ingest_data` action and its
`x-synapse-contribution` contract. Submit a `contribution.v1` version 1.1
analysis through the existing passive action route, using a stable subject and
candidate class or a coverage gap. Include the inferred or reported knowledge
state, confidence, reason, supporting and contrary evidence IDs, producer, and
a `methodRef` with ID `synapse-web-access-control` and the package digest from
the current guidance catalog. An inconclusive comparison or missing baseline
remains inconclusive or a coverage gap.

Use the returned canonical IDs, receipt, and committed revision. If the commit
outcome is uncertain, retry the same request ID only with the identical target
and payload. The contribution must not claim direct observation, execution
success, validation outcome, operator review, or finding status. Those remain
server-derived or explicit lifecycle decisions.

## Stop or hand back

Stop after the bounded comparison has an evidence-backed conclusion, an
inconclusive result, or a precise coverage gap and the result is committed.
Also stop on scope or authority denial, approval-required or unknown execution
outcome, unsafe state change, loss of either actor baseline, anti-automation
boundary, or inability to observe the expected effect safely.

Hand back to `$synapse-web-pentesting` with the subject, actor matrix,
conclusion, evidence, contrary evidence, unknowns, receipt, revision, and next
question. Hand to `$synapse-web-auth-session` when identity or session state is
not reliable enough for the comparison. Use `$synapse-cve-intelligence` only
for a supported component-applicability question.
