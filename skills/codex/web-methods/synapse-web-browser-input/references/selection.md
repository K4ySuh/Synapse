# Browser input procedure

## Select this method

Select `synapse-web-browser-input` when the question is whether supplied or
stored data reaches a browser markup, script, style, URL, or DOM execution
context, or controls a client or server redirect destination. Use the relevant
installed family instead when the decisive interpretation occurs in a server
query, command, template, fetch, file, XML, or structured-data boundary.

Apply the common contract at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`.
For native skills installed beside the default profile, open
`synapse-web-pentesting/references/method-contract.md` under the same skill root.

## Required context

Recover the stable route and input, actor and authentication state, input
location and origin, canonical request/response or saved script evidence IDs,
and expected rendering or navigation behavior. For browser interpretation,
identify the source, transformations, sink, surrounding HTML/attribute/script/
style/URL context, encoding steps, DOM lifecycle, framework behavior, CSP and
trusted-types evidence, and the browser or parser actually represented. For a
redirect, identify who supplies the destination, normalization and allowlist
rules, base/origin handling, the redirect mechanism, and the security decision
that consumes the final URL.

Missing sink context, transformation order, browser execution evidence,
redirect consumer, or a safe baseline is a specific coverage gap.

## Analyze the family question

Trace data from source through decoding, normalization, encoding, templating,
DOM mutation, or URL resolution to the final sink. Ask whether protection is
correct for that exact context and applied after the last interpretation step.
Distinguish reflected, stored, and DOM-mediated paths and keep the input that
was accepted separate from the content the browser ultimately parsed.

For redirects, resolve the effective destination using the application's
observed rules. Determine whether the behavior crosses an origin or trust
boundary, whether an allowlist is evaluated on the same normalized value, and
whether the redirect participates in login, token, recovery, or other trusted
flows. A controllable Location value without a harmful trust transition may be
a hardening issue or benign behavior rather than a vulnerability.

## Test alternative explanations

Account for escaped text rendered in a non-executable context, sanitization at
a later transformation, inert template output, browser or framework rewriting,
CSP or trusted-types enforcement, a test harness that differs from the saved
response, and content that requires an unavailable user gesture. Redirect
signals may instead reflect relative URL resolution, an internal route name,
an allowlisted host, an intermediate identity-provider hop, canonicalization,
or a client-only navigation that does not receive sensitive state.

## Weigh evidence and unknowns

Supporting evidence links the stable input to the final browser sink or
effective destination and preserves the intervening transformations, parsed
context, policy, and observable execution, navigation, or trust-boundary
effect. Contrary evidence includes context-correct encoding, verified
sanitization after the last decode, an inert sink, enforced browser policy, a
same-origin destination, a correctly normalized allowlist, or an alternate
cause for the observed response.

State unknown browser versions or policies, unobserved DOM branches, stored
rendering paths, encoding order, user-interaction requirements, destination
normalization, token/referrer propagation, and downstream redirect consumers.
Negative evidence covers only the saved context and transformation path.

## Stop or hand back

Follow the common contribution and stop contract using method ID
`synapse-web-browser-input` and the current catalog digest. Stop when the exact
source-to-sink or redirect question is supported, refuted, inconclusive, or
blocked by a named gap. Hand back to `$synapse-web-pentesting` when broader
surface or trust-boundary work remains, or select the server-input,
fetch/file/XML, structured-data, authentication/session, or access-control
method when that boundary becomes decisive.
