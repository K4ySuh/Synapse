# Phase 7 bounded client comparison

This checkpoint compares two interpretation routes over identical fictional,
saved Synapse state. It sends no target traffic, uses no credentials, and does
not authorize active execution. The retained-helper route explicitly selects
`headers_cookies.analyze_workspace` with its historical `ingest=true` behavior;
the selected-method
route uses `synapse-web-configuration` and does not invoke a heuristic helper.
Both routes use the same repaired checkout runtime, model, reasoning level,
compact surface, evidence, and scoring rubric.

## Budget fixed before execution

The comparison budget was fixed before the first model session at **120 MCP
calls or 350,000 non-cached reported model tokens, whichever is reached
first**. Codex reports cached input separately; the results record both gross
input and the budgeted non-cached input plus output so this definition remains
auditable. Each of
the four matched sessions may use at most 24 MCP calls and the restart session
may use at most 12, leaving 12 calls for one repeat only if a concrete ambiguous
or failing result requires it. A route stops with unfinished cases recorded
rather than exceeding either total. There is one run per case and route; no
per-case client or worker and no statistical repetition are planned.

The planned sessions are one matched pair for cases C1-C3, one matched pair for
cases C4-C6, and one fresh selected-method client/server process that recovers
C6. Raw client event logs and temporary workspaces stay under the gitignored
`DATA/` runtime tree and are not release artifacts.

The first budget ended before selected-method persistence and restart. Before
resuming, the continuation fixed a separate **36 MCP-call or 180,000
non-cached-input-plus-output-token** ceiling: at most 24 calls for recovery and
the four unfinished writes, and 12 for a fresh C6 restart. A denied read-only
preflight, one malformed pre-dispatch envelope, a four-call contract-exact
write session, and the restart used 26 calls and 134,430 budgeted tokens. No
original helper case or selected-method analysis was repeated.

## Fixed fictional cases and scoring oracle

| Case | Saved evidence and question | Expected supported conclusion | Expected unsupported conclusion / required restraint |
| --- | --- | --- | --- |
| C1 | HTTPS account response sets a security-sensitive `session_id` cookie without `HttpOnly`; saved evidence identifies its authentication purpose and otherwise records restrictive headers. | The missing `HttpOnly` attribute is supported for the represented response and permits script access if script execution occurs. | Do not claim session theft, XSS, account compromise, or a confirmed exploitable vulnerability. |
| C2 | HTTPS account response records a host-only `__Host-session` cookie with `Secure`, `HttpOnly`, `SameSite=Strict`, path `/`, plus restrictive browser headers. | The saved response is a benign counterexample for the stated cookie/header question. | Do not create a weakness merely from cookie or login-route presence; do not generalize to unobserved routes. |
| C3 | Public JSON health response omits CSP, framing, and referrer headers but has `nosniff`; saved evidence says it is non-HTML, unauthenticated, and contains no sensitive data. | Header absence is recorded, but the stated browser-policy vulnerability is unsupported for this response class; at most this is scoped hardening context. | Do not turn generic missing-header labels into clickjacking, XSS, data exposure, or impact candidates. |
| C4 | An inferred endpoint exists, but no canonical response/header exchange was saved. | A precise configuration-evidence coverage gap is supported. | Do not infer secure or insecure deployed headers and do not manufacture an evidence reference. |
| C5 | One target has 220 saved endpoints. 219 static responses have restrictive headers and no cookies; one account response sets a security-sensitive cookie without `Secure` while the other relevant attributes are present. | Recover the account response across the bounded inventory and conclude only that the represented cookie lacks `Secure`; preserve its evidence attribution. | Do not omit the account response, treat the 219 controls as vulnerable, or claim cleartext transmission was observed. |
| C6 | Saved admin HTML evidence records `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'`, an explicit hardening policy that forbids inline script, and no saved script-execution or injection path. | Weak CSP syntax is supported; exploitability and impact remain unestablished, so the durable result must preserve the limitation and method attribution. | Do not promote the syntax signal to confirmed XSS or validated impact. A fresh process must recover the conclusion, evidence, and method digest without conversation memory. |

Scoring counts each expected conclusion or restraint once per case. A supported
conclusion requires the saved facts the oracle names. An unsupported conclusion
is any stronger security or impact assertion not supported by those facts.
An unnecessary candidate is a durable or reported vulnerability hypothesis
outside the exact case question. An omission is a missed expected conclusion,
restraint, or required C5 inventory item. Evidence attribution is correct only
when the conclusion names the canonical evidence for that case and no unrelated
evidence. Operator corrections count prompt or manual interventions after a
session starts; fixture construction and the predeclared route instruction do
not count.

## Results

The live comparison and its separately budgeted continuation now satisfy
7R7.2. Both routes analyzed all six cases and the selected method traversed all
220 C5 endpoints. Both routes stated all six expected conclusions, made no
unsupported impact claim, and attributed every case to its correct canonical
evidence ID. The initial selected-method run ended before persistence; the
continuation committed the four useful C1/C4/C5/C6 analyses and a fresh
client/server process recovered C6 with its evidence, limitation, method ID,
and digest. The helper's five unnecessary findings remain an observed noise
difference, not a universal superiority claim.

| Measure | Retained helper | Selected method |
| --- | ---: | ---: |
| Expected case conclusions stated | 6/6 | 6/6 |
| Unsupported impact conclusions in client summaries | 0 | 0 |
| Correct case evidence attribution | 6/6 | 6/6 |
| Analysis omissions | 0 | 0 |
| Durable relevant findings/analyses in the initial run | 3 | 0 |
| Durable unnecessary findings/analyses | 5 | 0 |
| Required durable outputs omitted at the initial stop | 0 | 4 (C1, C4, C5, C6) |
| MCP calls | 26 scored + 10 failed setup calls | 47 |
| Non-success MCP calls | 2 scored + 3 failed setup calls | 6 |
| Operator corrections | 1 | 3 |
| Elapsed wall time | 323 seconds including setup failure | 661 seconds |
| Reported gross input/output tokens | 1,016,637 / 10,970 | 1,561,232 / 19,033 |
| Reported cached input tokens | 892,961 | 1,386,211 |
| Budgeted non-cached input plus output | 134,646 | 194,054 |
| Reported reasoning-output tokens | 5,355 | 11,105 |

The helper persisted eight confirmed findings: one relevant C1 cookie finding,
four generic C3 missing-header findings, one relevant C5 cookie finding, and
two C6 findings. The C3 records are unnecessary for the saved public JSON,
non-browser response. C6's weak-CSP record is relevant, while its separate
framing finding is outside the fixed question. C2 and C4 produced no helper
finding. The helper client nevertheless added the needed context and did not
claim exploitability or impact in its summaries.

The selected method correctly treated C2 as benign, C3 as inapplicable to the
stated browser-policy question, C4 as an evidence gap, C5 as a missing `Secure`
attribute without observed cleartext transport, and C6 as weak CSP syntax
without an injection path or execution evidence. It also recovered the C5
account response after bounded pagination. The initial run committed none of
its four useful outputs: C1 encountered a risk ceiling, forbidden legacy outer
metadata, and then an idempotency conflict; the C4-C6 grant expired during an
interrupted interval.

The continuation installed a six-hour low-risk grant limited to `jobs.list`
and `workspace.ingest_data`. One denied `jobs.list` preflight exposed an
under-scoped first grant. The corrected recovery session then spent 18 calls,
including unnecessary repeated guidance reads, before sending a version 1.1
body with legacy field names; strict validation rejected it before dispatch.
A four-call contract-exact session used fresh request and idempotency identities
and committed C1, C4, C5, and C6 at revisions 47, 54, 61, and 68. Their receipts
are `submission-6fc5d2efab16b4547bafa3a7`,
`submission-fc1c911f6690623588664c1f`,
`submission-71137afde93dfbf03bf41b5c`, and
`submission-d0ece89b00a3ab1f6a007a6b`. A fresh process used three read-only
calls to recover C6 and made no contribution.

The continuation used 853,690 input tokens, including 731,743 cached, 12,483
output tokens, 6,846 reasoning-output tokens, and 134,430 budgeted non-cached
input plus output. Across both declared budgets, the exercise used 109 MCP
calls and 463,130 budgeted tokens; budgets remain separate because the first
one had already stopped. The explicit helper remains a practical fallback for
this configuration family during broader Beta testing because the selected
route required corrections even though it ultimately persisted cleaner output.
No discovery-ranking change is justified.

## Exact client and byte record

| Component | Compared value |
| --- | --- |
| Codex | `codex-cli 0.154.0` |
| Model | `gpt-daybreak-blue-latest`; High reasoning; provider build ID was not exposed |
| MCP SDK | `mcp==2.0.0` |
| Negotiated protocol | `2025-06-18` on every recorded MCP result |
| Synapse | editable `synapse-mcp==0.6.0b0` at `c614ddb4feaa4abddb386d8853f0c6f24c465e24` |
| Python/store/surface | Python 3.14.7; SQLite-v2; `modern-compact` over stdio; one agent |
| Package metadata digest | `pyproject.toml` SHA-256 `a9ecd0e22df2fdc2ba6789402153f5025f48570f7d4d092a0c64defade5dfe8a` |
| Operating prompt digest | SHA-256 `8fbf77e20bff471a48bc915bede6092cdc0a289a3316283218b74d8d40132e88` |
| Default operating package | `operate-synapse` aggregate `ffd710013ddb1d2158ceff7815197aab40230adce16efa7613a8b778dee05816` |
| Main Web package | `synapse-web-pentesting` aggregate `9cf157590410554d615ed6e24875519fe4cb0511f2c75f1923f11739a07248e7` |
| Selected method package | `synapse-web-configuration` aggregate `d004c0aa03ed942e4666d4a6241a933661d29b01ff2d5ca44bdd3e255951fd49` |
| Selected method documents | `SKILL.md` `32ab21b63356df8a45c16b81884ba7f4b58802db8c09b1c5e619d2a106c6d990`; `references/selection.md` `5669c1b8e8881f697ca260f5449b147a9bc37a24054ab0c8b51d7e1cfec9eea7` |
| Common method contract | SHA-256 `07ac5323569030f428ce55d632cd01e54c087016590e8fbe3ddebd7f90aba79d` |

Codex reported 83 MCP calls across seven sessions, including the failed setup
and the narrowly justified C1 retries. Total elapsed event-file wall time was
984 seconds. Reported usage was 2,577,869 input tokens, 2,279,172 of them
cached, 30,003 output tokens, and 16,460 reasoning-output tokens. The budgeted
quantity was 328,700 non-cached input plus output tokens. The official-SDK
`2025-06-18` compact tool-list fixture is 24,797 bytes, so seven fresh sessions
made 173,579 schema bytes available at negotiation; Codex did not expose
per-session schema-transfer telemetry. Selected-method sessions read 94,092
resource-body bytes across 15 reads (33,271 unique bytes); the helper sessions
read no hosted guidance body. Saved case artifacts were 796, 794, 487, 346,
116,365, and 698 bytes for C1-C6 respectively.

The first helper session was the only shared setup repeat: its three writes
were denied before dispatch because the binding was observe-only. The operator
installed narrow no-traffic grants and reran the matched C1-C3 helper session.
The selected route's C1-only retries addressed the risk ceiling and strict
outer contribution contract; the final idempotency conflict was left
unfinished. No other case or route was repeated. These successive concrete C1
failures used 25 repeat/setup calls rather than the planned 12-call reserve;
every session cap and the fixed 120-call total still held. This allocation
deviation explains the initial stop and remains a recorded efficiency
limitation; the separately bounded continuation resolves the acceptance gap.

## Deterministic validation and restart boundary

Eight exact service regressions cover the required repaired boundaries. The
first command used three stale test class selectors: five tests passed and
three loader errors did not execute. The corrected three-selector rerun passed.
Together the executed checks passed F1 curated identity/restart, F4 normalized
same-target retry and changed-target conflict, F2 complete revision-bound
context pages, F3 knowledge state and attribution, both F5 bounded ordinary
relation-write paths, and two selected-method attribution/restart scenarios.
The restart tests use fresh Python processes and recover method ID, digest,
supporting/contrary evidence, uncertainty, and stable candidate identity.

The deterministic pass supplements rather than substitutes for the completed
live C6 restart. The exercised restart sequence was:

1. Record the returned receipt, revision 68, subject, evidence ID, and
   `synapse-web-configuration` digest.
2. Exit the client and server.
3. Start a fresh `modern-compact` client/server process and call
   `context.query` for `c6-restart.phase7.example`.
4. Verify the recovered candidate retains `ev-phase7-c6`, weak-CSP limitations,
   and the stored method ID/digest; do not recreate the contribution.

## Installation, rollback, and next Beta order

The default remains the three-skill directory returned by
`synapse-codex-assets --skills-dir`; copy its contents into the chosen Codex
skill root and start with `$operate-synapse`. Optional methods remain separate:
locate `synapse-codex-assets --skills-profile web-methods` and copy only the
selected folder, for example `synapse-web-configuration/`, beside the default
skills. Installation does not change capability packs, Registry actions,
authority, or workspace state.

To roll back this optional method, remove only its copied native skill folder
or stop selecting its hosted guidance. Keep the default skills and Synapse
runtime. Existing canonical data and historical method attribution remain
readable. For the tested configuration family, explicitly select
`headers_cookies.analyze_workspace` through live discovery when its normalized
labels are useful, review its output against route context, and avoid blanket
ingestion. No state migration, action removal, legacy-fixture rewrite, or
discovery-ranking rollback is required.

The next action is Beta testing in this order: fresh setup; supplied-data
import; context traversal; method selection and contribution; restart and
second consumer; report and bundle recovery; then separately authorized real
integration testing. Phase 7 is complete; do not open another modernization
phase to perform that testing.
