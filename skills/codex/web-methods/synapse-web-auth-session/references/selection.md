# Authentication and session procedure

## Select this method

Select `synapse-web-auth-session` when the current question concerns login,
logout, session creation or rotation, cookie or token handling, recovery, MFA,
SSO callbacks, CSRF binding, or a privilege transition caused by
authentication. Respect an explicit operator selection.

Use `synapse-web-access-control` when authenticated actors are established and
the question is whether one actor may reach an object, function, property,
tenant, or workflow state. Return to the main web method for broad surface
mapping or for a vulnerability family outside this boundary.

Read the main skill's shared comparison foundations once when needed. Hosted,
they are at
`synapse://guidance/skills/synapse-web-pentesting/references/auth-and-access-control.md`.
For native skills installed beside the default profile, open
`synapse-web-pentesting/references/auth-and-access-control.md` under the same
skill root. The catalog maps hosted URIs; relative Markdown paths do not resolve
through MCP by themselves.

Apply the common contribution and handoff contract at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`,
or `synapse-web-pentesting/references/method-contract.md` in the native default
skill tree.

## Required context

Recover the workspace revision and target, then gather only what the question
needs:

- actor and authentication states, role or tenant, and approved credential or
  auth-profile references;
- entry, callback, recovery, logout, refresh, and state-changing routes in
  scope, including manual MFA, SSO, CAPTCHA, or device-binding constraints;
- canonical request and response evidence IDs, redirects or intermediate
  challenges, and a known-allowed or known-denied baseline;
- session artifact metadata such as cookie attributes, token type and claims,
  storage or transport location, rotation points, and expiry timing without
  copying reusable secrets;
- the expected policy or secure behavior, preconditions, state before and
  after the exchange, and any telemetry limit.

If the decisive request, actor state, lifecycle step, baseline, or evidence is
missing, record that exact coverage gap before considering execution.

## Analyze the question

Model the lifecycle: unauthenticated state, authentication ceremony, session
issuance, rotation or privilege change, refresh, idle and absolute expiry,
logout or revocation, recovery, and concurrent sessions. Ask which server-side
state or cryptographic binding establishes the actor and whether that binding
changes at each trust transition.

For the selected transition, compare expected and actual behavior. Check that
session identifiers rotate when trust changes; logout, recovery, password
change, and administrative revocation have the expected reach; cookies and
tokens are bound to their intended origin, path, audience, issuer, time, and
client context; and state-changing requests enforce the documented CSRF or
origin binding. Treat decoded JWT claims, cookie flags, or a redirect as clues
whose security effect still needs context.

## Test alternative explanations

Account for stale client state, transparent refresh, clock skew, propagation
delay, concurrent sessions, cached or replayed responses, an upstream identity
provider, a WAF or rate limit, tenant-specific policy, and a login challenge
that was never completed. A status code or body change can reflect routing,
validation, content negotiation, localization, or anti-automation behavior.
Separate client-side token removal from server-side invalidation and separate
CSRF rejection from ordinary authorization or input validation.

## Weigh evidence and unknowns

Supporting evidence links the exact actor state and transition to a repeatable
server-side outcome: stable exchange evidence, pre/post state, session rotation
or continued acceptance, and an independent signal of identity or state
change. Contrary evidence includes consistent rotation or rejection, confirmed
revocation, expected policy that permits the behavior, a failed ceremony, and
an alternate cause that explains the same response.

State unresolved questions explicitly: untested logout scope, refresh-token
behavior, another device or tenant, expiry window, MFA/recovery path, cookie or
token binding, CSRF precondition, missing server telemetry, or an unavailable
safe baseline. Negative comparisons define covered behavior; they do not prove
untested paths safe.

## Stop or hand back

Follow the common contribution and stop contract using method ID
`synapse-web-auth-session` and the current catalog digest. Also stop on loss of
the baseline, an anti-automation boundary, or a required manual authentication
step.

Hand back to `$synapse-web-pentesting` with the subject, conclusion, evidence,
contrary evidence, unknowns, receipt, revision, and next question. Hand to
`$synapse-web-access-control` only when authenticated states are reliable and a
specific authorization comparison remains. Use `$synapse-cve-intelligence`
only for a supported component-applicability question.
