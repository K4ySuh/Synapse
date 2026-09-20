# Fetch, file, and XML procedure

## Select this method

Select `synapse-web-fetch-file-xml` when the current question concerns a
server-side URL or resource fetch, upload/download or file transformation,
path construction, archive extraction, or XML parsing and external resolution.
Use server-input for query, command, or template interpretation and
structured-data for GraphQL or object serialization boundaries.

Apply the common contract at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`.
For native skills installed beside the default profile, open
`synapse-web-pentesting/references/method-contract.md` under the same skill root.

## Required context

Recover the stable route, actor state, input and location, request/response or
artifact evidence IDs, expected resource operation, baseline, and observable
effect. For fetches, identify URL ownership, parsing and normalization,
accepted schemes, redirect behavior, hostname and address checks, DNS timing,
proxy and egress controls, authentication forwarding, and how the response is
used. For files and archives, identify upload/read/write/delete/transform
semantics, filename and path sources, canonicalization, storage mapping,
content inspection, archive-member handling, permissions, and cleanup. For
XML, identify content type, parser and mode, schema, DTD/entity settings,
external resource resolution, transformations, and network/file access policy.

Missing backend-use evidence, canonical path, parser mode, safe baseline, or
observable success criterion is a coverage gap.

## Analyze the family question

Trace the supplied value through every decode, normalization, redirect,
canonicalization, extraction, or parse step to the resource operation. For a
fetch, ask whether policy is applied to the same effective scheme, host,
address, and destination used after redirects and DNS resolution, and whether
the response can influence protected state or disclose a meaningful signal.

For files, compare the logical object with the final canonical path and storage
operation. Check whether validation occurs after the last decode, whether
archive members and link-like entries remain inside the intended root, and
whether content type, extension, parser choice, permissions, and served origin
match the expected policy. For XML, determine whether untrusted declarations,
entities, includes, schemas, or transformations can cause external resolution,
local resource access, expansion, or a protected downstream effect.

Prefer saved evidence and deterministic parsing. Active validation must use an
operator-controlled benign resource or harmless file/state effect with strict
request, redirect, byte, parser, and cleanup bounds.

## Test alternative explanations

Account for a client-side fetch, CDN or preview service, proxy-generated error,
cache hit, allowlisted internal integration, DNS or connection failure, generic
timeout, and a response that is never exposed or consumed. File signals may be
ordinary filename sanitization, virtual object storage, content sniffing,
duplicate-name handling, or an error before persistence. XML signals may be
schema rejection, disabled DTD/entity processing, a safe parser, an unrelated
backend fetch, or literal text returned without entity expansion.

## Weigh evidence and unknowns

Supporting evidence connects the stable input to the effective backend
destination, canonical file operation, archive result, or XML resolver effect
with matched controls and canonical evidence. Contrary evidence includes
post-normalization allowlisting, redirect revalidation, blocked egress,
root-confined canonical paths, safe archive extraction, parser features shown
disabled, consistent rejection, cleanup, or another component that explains
the observed behavior.

State unknown redirect and DNS behavior, proxy boundaries, address families,
credential forwarding, response consumers, storage backend, path decoding,
archive formats, link handling, parser library and mode, transformation stages,
external resolver policy, permissions, and cleanup. Negative evidence covers
only the represented resource type, path, parser, actor, and state.

## Stop or hand back

Follow the common contribution and stop contract using method ID
`synapse-web-fetch-file-xml` and the current catalog digest. Stop when the exact
resource-boundary question is supported, refuted, inconclusive, or blocked by
a named gap. Hand back to `$synapse-web-pentesting` for broader surface work,
or select server-input, structured-data, configuration, authentication/session,
or access-control when that boundary becomes decisive.
