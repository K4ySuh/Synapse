# Phase 6 direct-client exercise

Task 6R7 used fictional saved data and a temporary SQLite-v2 workspace to
verify the supported Codex path directly. It did not contact an assessment
target, use credentials, or send active traffic. One Codex agent used the
default `modern-compact` surface and recovered only from canonical Synapse
workspace state between fresh client/server processes.

## Tested configuration

| Component | Tested value |
| --- | --- |
| Date | 2026-09-16 |
| Codex CLI | 0.154.0 |
| Model | `gpt-daybreak-blue-latest` |
| Reasoning | High |
| MCP SDK | `mcp==2.0.0` |
| Negotiated MCP protocol | `2025-06-18` |
| Synapse package | `0.6.0b0` |
| Surface and transport | `modern-compact` over stdio |
| Python | 3.14.7 |
| Workspace store | fresh per-workspace SQLite-v2 |
| Agent profile | one agent; default three-skill profile |

The model was selected by the operator for this exercise. It is not a Synapse
core dependency. The negotiated protocol revision is an official-SDK
compatibility path on the modern compact surface; it does not mean the frozen
legacy surface was used.

## Exercise result

The client completed this sequence:

1. Loaded `$operate-synapse`, discovered the hosted prompt and guidance
   catalog, then loaded `$synapse-web-pentesting` for the saved-data method.
2. Recovered a fictional OpenAPI import, two inferred routes, and its saved
   evidence. An observe-only contribution attempt was correctly denied.
3. Created and checkpointed one durable work item, then exited.
4. In a fresh client/server process, recovered the work item and evidence from
   workspace context. A narrow server-held grant covered only
   `workspace.ingest_data` for the fictional host.
5. Submitted and retried one `contribution.v1` request. Three successful
   dispatches with the same consumer request ID produced one durable receipt,
   one stable endpoint identity, and one evidence/artifact linkage. A fourth
   dispatch was correctly denied after the three-dispatch grant budget was
   exhausted.
6. In another fresh client/server process, recovered the contribution receipt,
   renewed the claim, rendered one internal Markdown report under a separate
   one-dispatch report grant, inspected its opaque artifact metadata, and
   completed the work item and claim.

The final canonical workspace revision was 77. The report projected one target
through all seven report layers and produced a 4,329-byte Markdown artifact.
No report call was retried.

Canonical SQLite inspection verified idempotency independently of the model's
summary: the repeated successful dispatches left exactly one receipt for the
consumer request ID and one endpoint identity. The existing `/health` route was
updated rather than duplicated.

## Bounded measurements

The three model sessions used 79 MCP calls in about 11 minutes 45 seconds and
reported 200,889 tokens in total. Fourteen calls were denied or retried: narrow
grant coverage, the exhausted dispatch budget, optimistic work-item versions,
and exclusive claim semantics accounted for them. All were recovered and no
product error remained. Codex did not expose per-MCP response byte sizes; the
report artifact size above is the only response-size measurement recorded.
No additional telemetry variants were sent.

Two setup attempts ended before a model session: the installed CLI rejected an
unsupported shorthand approval flag, and an initially incorrect MCP state path
failed the readiness handshake. Correcting the invocation and keeping modern
state under the runtime `DATA` root resolved both without a repository change.

## Current-suite verification

The same checkpoint ran the current supported gates:

- `bin/test --core -q`: 810 tests passed, including fresh SQLite-v2 bootstrap,
  migration/storage, generated inventory/output contracts, ingestion and
  retry receipts, independent-consumer contributions, context recovery,
  background recovery, and reports.
- `bin/test-modern -q`: 17 tests passed across compact/direct negotiation,
  stdio and Streamable HTTP, restart recovery, hosted resources, and frozen
  compatibility fixtures.
- Both Codex skill profiles validated: three default skills and eight explicit
  multi-agent compatibility skills.
- Offline wheel/sdist validation passed. Each archive installed outside the
  checkout and started the standard 174-action and core-only 42-action
  catalogs.

The first restricted-container runs could not bind loopback test servers and
could not reliably wake isolated process/thread workers. Re-running the
unchanged gates with the required local runtime permissions passed. The core
run also emitted a non-failing unclosed-SQLite resource warning and Python 3.14
fork deprecation warning. These are test-environment warnings, not a supported
client failure.

## Compatibility and limits

This is a direct pass for Codex CLI 0.154.0 with the provisioned Daybreak Blue
model, High reasoning, `mcp==2.0.0`, MCP protocol `2025-06-18`, and Synapse
`modern-compact` 0.6.0b0. The current modern suite separately preserves
`modern-direct`; the core fixtures and distribution checks preserve frozen
legacy and JSON-v1 compatibility.

The result does not claim support for untested clients or model builds. It does
not expand synchronous effect observation into provider, browser, background
worker, or child-process internals, and it does not turn internal High-Level
reports into a client-redaction boundary. Generalized taint/invalidation,
counterfactual evaluation, and migration of every saved-data adapter remain
future work.
