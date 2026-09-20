# Structured data procedure

## Select this method

Select `synapse-web-structured-data` when the current question concerns a
GraphQL schema, operation, variable, resolver, batching or complexity boundary,
or a typed serialization/deserialization format that may construct or select
objects. Use server-input for SQL/command/template interpretation and
fetch/file/XML for resource or XML parser boundaries.

Apply the common contract at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`.
For native skills installed beside the default profile, open
`synapse-web-pentesting/references/method-contract.md` under the same skill root.

## Required context

Recover the stable endpoint and operation, actor and tenant state, canonical
request/response or artifact evidence IDs, content type or transport, baseline,
expected schema or object behavior, and observable effect. For GraphQL, gather
the known schema source and version, operation type and name, fields, arguments,
variables, aliases/fragments, resolver ownership, field and object authorization,
error shape, batching, and complexity controls. For serialized data, identify
the format, framing, signatures or integrity checks, type metadata, parser and
runtime, allowed types, object construction hooks, transformations, provenance,
and the component that consumes the resulting object.

Introspection, a type name, parser error, or a recognizable format is context;
it does not by itself establish unauthorized access or unsafe object creation.
Missing schema/runtime identity, consumer, baseline, or safe success criterion
is a coverage gap.

## Analyze the family question

For GraphQL, trace authorization and validation from operation to each resolver
and returned field. Compare equivalent REST or documented policy where useful,
and distinguish schema visibility from reachable data or mutation effects.
Assess aliases, fragments, batching, nesting, subscriptions, and complexity only
against explicit bounded behavior and controls; more fields or slower responses
alone do not prove a security impact.

For serialized data, determine whether untrusted bytes or fields select a type,
instantiate an object, invoke a hook, or reach a protected operation. Check
whether integrity is verified before parsing, whether type selection is
allowlisted, and whether the actual consumer and runtime contain a reachable
effect. A known gadget or version match is an applicability hypothesis until
the deployment, data path, object construction, and effect are supported.

Prefer schema and artifact analysis. Active validation must remain within
bounded query depth, field count, batch size, object size, parser work, and a
benign observable effect.

## Test alternative explanations

Account for documented public schema visibility, resolver-level denial,
field masking, tenant filtering, validation before resolver execution, cached
errors, persisted-query policy, ordinary query cost, and client-generated
GraphQL errors. Serialization signals may instead be inert metadata, a safe
data-only parser, an allowlisted type registry, signature rejection, a client-
side decoder, an unreachable class, or an error before object construction.

## Weigh evidence and unknowns

Supporting evidence connects a stable operation or serialized value to the
specific resolver, protected field/mutation, type selection, object hook, or
downstream effect with matched controls and canonical evidence. Contrary
evidence includes consistent resolver authorization, field filtering, enforced
query limits, integrity verification before parsing, safe type allowlisting,
data-only decoding, an unreachable consumer, or another layer that explains
the response.

State unknown schema versions, hidden resolvers, field-level policy,
subscriptions, persisted queries, batch/depth limits, serializer format and
framing, integrity coverage, runtime classes, construction hooks, consumer
reachability, privileges, and downstream side effects. Negative evidence covers
only the represented operation, type path, actor, runtime, and state.

## Stop or hand back

Follow the common contribution and stop contract using method ID
`synapse-web-structured-data` and the current catalog digest. Stop when the
exact schema/resolver or object-construction question is supported, refuted,
inconclusive, or blocked by a named gap. Hand back to
`$synapse-web-pentesting` for broader work, or select access-control,
server-input, fetch/file/XML, business-logic, or CVE intelligence when that
boundary becomes decisive.
