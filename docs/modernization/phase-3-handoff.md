# Phase 3 interoperability handoff

Date: 2026-08-24
Baseline: `c356b95412528e3a84c208b759225dd338d7bfd4`
Decision: complete; `modern-compact` stdio is the Codex default

Phase 3A through 3D are complete. The 2026-08-23 attempt is retained as
historical evidence: its original two-client requirement could not finish
because Claude Code was not authenticated and stable Codex did not expose the
`2026-07-28` protocol request-state carrier.

The operator removed Claude as a required or funded client on 2026-08-24. The
closure contract was therefore revised to the client actually used in
production: stable Codex, without experimental feature flags. Protocol-native
`input_required` remains supported when negotiated, but it is no longer the
only valid supervised-resume carrier. Older negotiated revisions use the
typed `approval_required` result, its opaque `operationHandle`, and
`tasks.control(operation=resume)` after trusted operator step-up.

## Adopted surfaces

| Surface | Tools | Exact payload bytes | Disposition |
| --- | ---: | ---: | --- |
| `modern-compact` | 11 | 21,648 | default Codex stdio surface |
| `legacy` | 174 | 99,337 | frozen rollback and bootstrap compatibility |
| `modern-direct` | 174 | 578,249 | explicit diagnostic/compatibility surface |

All three projections enter the same Registry/application path. Surface
selection does not change scope, identity, or execution authority. The legacy
launcher and contract fixtures remain intact; adoption does not imply a legacy
removal date.

## Codex closure gate

`bin/run-phase3d-codex` is the reproducible live gate. It uses a fictional
`benchmark` workspace and `app.acme-demo.test`, disables external target
traffic, creates private temporary identity/key files, and starts a new modern
MCP process for resume. It explicitly disables Codex's under-development
`mcp_2026_07_28` feature.

The accepted batch used Codex CLI `0.149.0`, `gpt-5.6-sol`, stable negotiated
behavior, `modern-compact`, and stdio. Three independent repetitions each
passed:

1. `engagement.inspect` exactly once under an observe grant;
2. `actions.run_active` exactly once, returning `approval_required`, an opaque
   handle, and `dispatch=not_started`;
3. one exact step-up through the trusted local operator service;
4. restart into a fresh MCP process;
5. `tasks.control(operation=resume)` exactly once;
6. trace continuity and exactly one successful Registry dispatch.

Across nine stages there were nine expected MCP tool calls, zero duplicates,
zero schema retries, three approval interruptions, three successful resumes,
and three successful dispatches. Response status remained null because the
CORS fixture used `httpBackend=disabled` and `disableTraffic=true`.

Reproduce it with:

```bash
bin/run-phase3d-codex --preflight
bin/run-phase3d-codex --run --repetitions 3
```

Raw JSONL and opaque handles remain under `DATA/phase3d-codex/`. Sanitized
machine evidence is committed as
[`codex-closure-results.json`](evidence/phase-3/codex-closure-results.json).

## Supporting gates and accepted residuals

- Exact payload fixtures remain deterministic: legacy 99,337 bytes, compact
  21,648 bytes, direct 578,249 bytes. Compact is 21.793% of legacy and below
  the 24,834-byte ceiling.
- Inspector `2.3.0` already discovered complete compact/direct schemas over
  stdio and loopback Streamable HTTP.
- The modern adapter suites cover both transports, every supported negotiated
  revision, restart, request-state rotation/tamper/expiry, cross-binding
  attacks, Host/Origin checks, and remote-startup fail-closed behavior.
- The alpha conformance subscription failures are accepted as non-blocking for
  this release because Synapse does not advertise subscription capabilities;
  runner-fixture tools and proxy-mediated header cases are not production
  Synapse contracts. HTTP remains supported but is not the selected local
  Codex default.
- Protocol-native `input_required` is additive. When stable Codex negotiates
  it, the server can use it; the application handle path remains necessary for
  compatible older revisions and for explicit task control.

## Operator configuration and rollback

`bin/print-mcp-config` now prints the modern compact Codex profile by default
and does not print Claude configuration. Use `--legacy` for the frozen rollback
profile; `--include-claude` is an optional compatibility output only.

Before using the modern profile, create the private `0600` identity binding and
request-state keyring described in `docs/Operations.md`, then create/select
the required Authority Grant with the trusted `synapse-authority` service.
Codex host approval permits an MCP invocation to reach Synapse; it does not
create scope or server-held execution authority.

Rollback requires only selecting:

```bash
bin/print-mcp-config --legacy
```

No workspace, evidence, scope, grant, or frozen legacy contract migration is
required.

PHASE_3_PASS
