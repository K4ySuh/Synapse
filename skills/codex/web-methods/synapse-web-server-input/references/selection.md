# Server input procedure

## Select this method

Select `synapse-web-server-input` when the question is whether input changes the
structure or behavior of a server-side SQL or other query, operating-system
command, template expression, or SSI directive. Use another family when the
decisive boundary is browser parsing, a server-side fetch, file/path handling,
XML, GraphQL structure, or serialized object processing.

Apply the common contract at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`.
For native skills installed beside the default profile, open
`synapse-web-pentesting/references/method-contract.md` under the same skill root.

## Required context

Recover the stable route, method, parameter or body field, actor state,
canonical request/response evidence IDs, accepted data shape, baseline, and
expected server behavior. Identify the suspected interpreter, input location,
normalization and decoding stages, type conversion, query or command binding,
template engine or SSI processing context, error handling, and an observable
success criterion. Preserve timing conditions and repeated control samples when
timing is relevant.

A suggestive parameter name, generic error, scanner label, or one slow response
does not establish an interpreter boundary. Missing interpreter context,
baseline stability, or a safe observable effect is a coverage gap.

## Analyze the family question

Determine whether the input is treated as data or can change interpreter
structure. Compare values that isolate syntax, type, branch, timing, or output
effects while keeping authentication, route, state, and request shape stable.
For queries, distinguish parser behavior from application search/filter logic
and check whether binding occurs after all decoding. For commands, identify the
actual process boundary and argument construction. For templates and SSI,
separate literal rendering from server-side expression or directive evaluation
and identify the engine and evaluation stage when evidence supports it.

Prefer passive interpretation and deterministic parsing of saved evidence.
Any active comparison must have a bounded non-destructive effect and a control
that can distinguish the hypothesis without relying on bulk extraction,
filesystem changes, process persistence, or service disruption.

## Test alternative explanations

Account for ordinary validation and type errors, backend unavailability,
generic exception pages, application search semantics, caching, connection
pooling, rate limiting, WAF behavior, queueing, noisy latency, template
placeholders rendered literally, and a response difference caused by business
logic or content negotiation. A deterministic helper may identify syntax or
error markers without proving reachability, exploitability, or impact.

## Weigh evidence and unknowns

Supporting evidence connects the stable input to a repeatable interpreter-
specific structural, branch, time, or output effect with matched controls and
canonical exchanges. Contrary evidence includes parameter binding, literal
rendering, stable validation rejection, a non-interpreting code path, matched
timing controls, or a different component that explains the error or latency.

State unknown decoding stages, backend type or version, hidden query builders,
command wrappers, template engines, asynchronous effects, privilege context,
and untested alternate routes or content types. Negative evidence covers only
the represented interpreter, request shape, actor, and state.

## Stop or hand back

Follow the common contribution and stop contract using method ID
`synapse-web-server-input` and the current catalog digest. Stop when the exact
interpreter-boundary question is supported, refuted, inconclusive, or blocked
by a named gap. Hand back to `$synapse-web-pentesting` when broader mapping is
needed, or select the browser-input, fetch/file/XML, structured-data, or
business-logic method when evidence moves the decisive boundary.
