# Configuration procedure

## Select this method

Select `synapse-web-configuration` when the current question concerns security
headers, CORS, cookie attributes, TLS or certificate behavior, or a deployed
web setting whose effect depends on route, origin, client, or trust context.
Use authentication/session for lifecycle flaws, browser-input for a concrete
execution or redirect path, and access-control for actor/resource policy.

Apply the common contract at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`.
For native skills installed beside the default profile, open
`synapse-web-pentesting/references/method-contract.md` under the same skill root.

## Required context

Recover the exact origin, route and response class, actor/authentication state,
canonical exchanges or TLS evidence IDs, expected policy, client context,
deployment boundary, baseline, and protected data or operation. For headers,
record the effective response after redirects and intermediaries and the
browser context the policy governs. For CORS, identify requesting origin,
credentials mode, preflight and actual request, allowed methods/headers,
response sensitivity, and browser enforcement. For cookies, record purpose,
Domain, Path, Secure, HttpOnly, SameSite, prefixes, expiry, transport, and where
the cookie is sent or read. For TLS, record endpoint, hostname, termination
point, protocol/cipher/certificate evidence, client expectations, and whether a
weaker path is actually reachable.

A missing header, permissive-looking value, old protocol label, certificate
warning, or scanner severity without this context is a hardening signal or
coverage gap rather than a confirmed vulnerability.

## Analyze the family question

Relate each setting to a concrete security decision. For browser headers,
determine which resource and execution/framing/MIME/referrer/transport boundary
the effective policy covers and whether redirects, error responses, or alternate
origins change it. For CORS, model the browser's effective allow decision for
the exact attacker origin and credentials mode and ask whether readable
sensitive data or a meaningful operation crosses the boundary. A response
header that browsers reject or a request that succeeds without readable data
does not establish CORS impact.

For cookies, connect attributes and scope to the authentication or state value
and the actual cross-site, script, subdomain, or transport threat. For TLS,
separate supported from negotiated behavior, certificate identity from trust
chain, edge termination from upstream transport, and compatibility exposure
from a demonstrated downgrade or confidentiality/integrity effect.

Deterministic header, cookie, CORS, or TLS parsers can normalize evidence, but
their labels remain inputs to this contextual decision.

## Test alternative explanations

Account for per-route policy, redirects, cached responses, CDN or reverse-proxy
injection, browser rejection of an invalid CORS combination, public data,
credentialless requests, a cookie that is not security-sensitive, host-only
defaults, local TLS termination, SNI or virtual-host mismatch, incomplete chain
capture, deliberate legacy compatibility, and a scanner observing a different
endpoint or response class.

## Weigh evidence and unknowns

Supporting evidence connects the effective deployed setting to a reachable
security boundary and protected effect using canonical exchanges, browser-
equivalent policy evaluation, cookie use, or negotiated TLS behavior.
Contrary evidence includes consistent restrictive policy, browser rejection,
non-sensitive/public responses, correct cookie scope for the threat, enforced
HTTPS, modern negotiation, a valid identity/chain, intermediary correction, or
an alternate deployment layer that explains the signal.

State unknown alternate origins and routes, error responses, preflight cache,
credential modes, cookie consumers and subdomains, proxy/CDN behavior, TLS
termination and upstream links, client population, SNI, certificate chain, and
actual negotiation. Negative evidence covers only the observed route, origin,
client policy, endpoint, and time.

## Stop or hand back

Follow the common contribution and stop contract using method ID
`synapse-web-configuration` and the current catalog digest. Stop when the exact
configuration question is supported, refuted, classified as hardening only,
inconclusive, or blocked by a named gap. Hand back to
`$synapse-web-pentesting`, or select browser-input, authentication/session,
access-control, or CVE intelligence when that boundary becomes decisive.
