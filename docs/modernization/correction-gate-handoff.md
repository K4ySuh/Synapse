# Modernization Correction Gate Handoff

## Verdict and identity

`READY_FOR_PHASE_2`

- Branch: `Beta`
- Initial HEAD: `79f13bbaa19202683aa5c6cd2ac98a29f1add07a`
- Implementation commits before this documentation handoff:
  `5a202aa`, `cf6bcb0`, `9583077`
- Final HEAD: the documentation commit containing this handoff; the operator
  response records its full hash
- Historical rollback point: `79f13bb`
- Modern-spike rollback: unset `SYNAPSE_ENABLE_MODERN_SPIKE` and use the stable
  `synapse-mcp` launcher

No push, merge, release, history rewrite, SQLite work, bulk 174-action
migration, or complete Phase 2 implementation occurred.

## Closed gates

1. Environment leakage checks parse fixture values and detect exact/descendant
   POSIX, Windows, and UNC paths without substring false positives.
2. Registry execution is direct by canonical action ID; shared input models are
   legal; ID/model mismatches and executor bypasses are tested.
3. All six actions have useful canonical input/output schemas. Success payloads
   are validated model instances; the exact legacy payload is a separate
   compatibility value. Invalid executor output fails deterministically.
4. `ActionEffects` expresses traffic, local write domains, local/remote change,
   destruction, credential/secret use, and replay safety. Input resolvers narrow
   maximum effects and fall back conservatively with a reason.
5. Availability runs before effects/policy/executor. Migrated adapter discovery
   derives operational fields from action descriptors through an
   application-layer provider; unmigrated adapters retain a named transitional
   bridge.
6. Credential upsert, delete, static/browser auth profiles, and refreshed
   credentials mutate through one full read-modify-write lock. Deterministic
   tests queue all workers at the lock and prove no lost updates or resurrection.
7. The opt-in official-SDK spike exposes exactly `workspace.summary`,
   `headers_cookies.analyze_workspace`, and `cors.execute_test`. It supports
   stdio and loopback Streamable HTTP, real input/output schemas, validated
   structured content plus text, annotations, error signaling, negotiation, and
   current-revision `input_required`. `confirm=true` is absent from discovery
   and never dispatches the active action.
8. A local ephemeral HTTP fixture runs twice from clean state. Each run discovers
   five routes/four navigation relations, sends seven requests, identifies one
   reportable CORS control and one safe control, emits six vulnerable-only
   header/cookie candidates, creates seven evidence records, and produces the
   same normalized result. It also fixed dropped crawler cookie flags.

## Architecture decisions

- ADR-0002 now requires explicit-ID routing, canonical output validation, and
  maximum/effective multidimensional effects.
- ADR-0003 grant dimensions consume effective effects and operator-configurable
  methods/rates/budgets/parallelism under `observe`, `supervised`, and
  `full_delegated` modes.
- ADR-0004 records normative MCP `2026-07-28`, stable official Python SDK 2.0.0,
  the isolated exact pin, feature flag, compatibility behavior, and rollback.
- ADR-0009 records this correction gate and supersedes input-type dispatch and
  singular-effect authority.
- `input-schema-keyword-inventory.md` records all keywords used by the 174
  schemas. Unsupported validation keywords are rejected, not ignored.
- `capability-gap-inventory.md` distinguishes current PoC/SSRF/XXE/sqlmap/raw
  limitations from future explicit capability and authority design while
  preserving current repository policy.

## Verification evidence

| Command | Result |
| --- | --- |
| `bin/test` | PASS: 475 core, 2 template, 7 workflow benchmarks |
| `bin/test --core -k contracts` | PASS: 53 tests |
| `bin/test --template` | PASS: 2 tests |
| `bin/test-modern` | PASS: 5 official-SDK tests |
| `bin/test --core -k local_pentest_vertical` | PASS: 1 two-run functional vertical |
| `python -m compileall` over package/core/modern tests | PASS |
| `git diff --check` | PASS |
| Official MCP Inspector `tools/list` over stdio | PASS, exit 0, exactly 3 tools |
| Official MCP Inspector active call from its older negotiated revision | expected compatibility fallback: `isError=true`, `approval_required`, no dispatch; Inspector exits 5 because the tool result is an error |

Final clean-environment seven-workflow wall times in milliseconds: `0.531`,
`3.290`, `2.392`, `3.248`, `55.975`, `58.774`, `6.774`. Baseline was `0.272`, `3.199`,
`1.498`, `1.867`, `53.077`, `55.883`, `4.147`; no workflow or call-count
regression occurred.

The official SDK 2.0.0 client negotiated `2026-07-28`. In-memory measurements:
10.472 ms connect, 0.533 ms tools/list, and 36.766 ms
`workspace.summary`. The three modern input/output schema pairs total 8,767
compact bytes; the six canonical Registry schema pairs total 15,055 bytes.

The frozen legacy surface remains 174 tools, 99,337 compact schema bytes,
protocol `2025-03-26`, zero legacy-published output schemas, and unchanged
fixtures. Core tests increased from 460 to 475; template tests remain 2 and
workflow benchmarks remain 7. Modern output schemas are published only by the
three-action spike; all six are available canonically from
`REGISTRY.contract_schema`.

## CI and residual risk

`.github/workflows/ci.yml` is `CI_READY_LOCAL`: Python 3.10–3.13 install the
documented stable package, run the complete suite plus contracts, and assert a
clean checkout. A separate Python 3.13 job installs `.[modern-spike]`, runs its
transport tests, and asserts cleanliness. `CI_REMOTE_PENDING`: these commits
were not pushed, so no remote check exists and none is claimed.

Deliberately deferred: migration of actions 7–174; durable grants, persistence,
revocation, resume flows, and dispatch ledger; default modern transport;
comparative vulnerable-app benchmarking; and the capability gaps in the
inventory. The Inspector currently negotiates an older revision than the SDK
2.0.0 client, so active calls receive the tested `isError` approval fallback;
the normative SDK client receives `input_required`.

The first revised Phase 2 task is: implement the typed, server-held
`AuthorityGrant` model and a pure decision evaluator for
`observe`/`supervised`/`full_delegated`, comparing canonical action ID plus
request-effective `ActionEffects`, scope digest, methods, credential/provider
references, and configurable budgets across the six-action slice. Prove all
allow/approval/scope-denial decisions without persistence or executor dispatch
before adding lifecycle storage.
