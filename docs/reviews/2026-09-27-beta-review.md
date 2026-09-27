# Synapse Beta readiness and skill review

Reviewed 27 September 2026 against `K4ySuh/Synapse` Beta
**`3eb1f8d1c1770a6af7f0313b0e665c6558ac1301`**, including the complete Phase 7
change range from `8134673`. Companion: [bounded stabilization task](beta-stabilization-task.md).

## Decision

**Start controlled Beta testing now. Do not yet rely on the candidate store and
compact context as a precise assessment record without the repairs below.**
There is no reason to begin another architecture phase or wait for a much
larger skill library. Phase 7's main direction is correct and its earlier
repairs are real. New offline probes nevertheless reproduce three correctness
gaps in candidate identity, attribution, and recovery, plus one context
efficiency problem. Passing the current suite does not cover those cases.

The immediate path is one stabilization task: repair these existing seams,
retain the refined skills, run a short end-to-end operator exercise, and freeze
the candidate for wider testing. Exploitation remains a separate objective.

## Verified results and limits

| Check | Result |
| --- | --- |
| Current core suite on reviewed Beta | **830/830**, 122.436 seconds |
| Current modern adapter suite, run after core | **17/17**, 44.608 seconds; includes SDK transport checks |
| Custom adapter template | **2/2** |
| Focused skill/default-profile/distribution suite after guidance edits | **31/31**, 3.617 seconds |
| Skill validators | 3 default, 8 optional web methods, 8 compatibility skills passed |
| Wheel/sdist installation | Both built and installed outside the checkout; standard 174 and core-only 42 actions; final prompt/assets checked |
| Repository inventory | 445 tracked files; all 234 tracked Python files parsed successfully; 66 core test modules |
| Duplicate-test scan | No exactly identical AST test bodies found; this does not rule out behavioral overlap |
| Existing relation diagnostic | 3 decoded rows per contribution at both 100 and 2,000 retained endpoints; median 14.12 / 16.39 ms locally |
| New offline precision probes | Reproduced the findings below in temporary SQLite-v2 workspaces; no target traffic |

Runtime: Python 3.12.14, linked SQLite 3.53.1, `mcp==2.0.0`, httpx 0.28.1,
pydantic 2.13.4. The initial post-edit focused run exposed a prompt-size limit
and a case-sensitive wording assertion, both corrected, plus a missing
`SYNAPSE_PYTHON` environment binding corrected in the rerun. Tests and frozen
fixtures were not weakened. The final main prompt is 6,881 bytes, within the
existing limit. The core run emitted the existing multiprocessing/fork warning.

This is a repository-wide inventory/static pass plus detailed inspection of
the Phase 7 runtime changes, skills, contribution/identity/context paths,
packaging, test organization, and selected execution/recovery boundaries. It is
**not a claim that every line of every retained adapter has been manually
verified**. Live browsers, scanners, Burp, third-party intelligence providers,
real target traffic, and a fresh Daybreak-connected MCP session were not run.
The prior client exercise is historical evidence, not a new result from this
review. The declared Python-version matrix was not reproduced locally.
An independent offline skill exercise was interrupted by the usage limit
before its proposal/schema-validation artifact was produced. It is not counted
as a passed behavioral evaluation; the bounded live exercise remains pending.

Reproducible probes and captured results:

- [Offline reproduction script](evidence/reproduce_beta_precision.py)
- [Candidate and context results](evidence/beta-20260927-precision.json)
- [Context budget measurements](evidence/beta-20260927-budgets.json)

From the repository root, using the selected project interpreter:

```sh
PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests \
  "$SYNAPSE_PYTHON" docs/reviews/evidence/reproduce_beta_precision.py
```

The script uses the workspace service directly to isolate data behavior; it is
not an authorization or live-client acceptance test. IDs generated during
reproduction differ between runs. Existing core tests also verify Phase 7's
previous identity-lifecycle, cross-target retry, provenance, and full-page
continuation repairs.

## Findings to repair

### B1 — P1: distinct surfaces collapse into one candidate

`core/adapters/results.py:434` builds `surface_candidate_id` from lowercased,
punctuation-replaced slugs and truncates the final result at 170 characters.
`core/workspace.py::_entity_key` then treats that ID as canonical identity.

Two version 1.1 candidate contributions for **`/a/b` and `/a-b`**, with the
same method, location, and parameter, return the same canonical row ID. Only
one observation survives. It retains the first URL but the second analysis's
reason. This is a reproduced data-integrity problem, not just a display-ID
collision. Case-distinct paths and long common prefixes also need regression
coverage because the same function lowercases/truncates them.

Repair identity from the complete canonical surface tuple, while retaining
existing IDs for unambiguously matched historical surfaces. Match the surface,
not a lossy alias. Do not silently rewrite old records, split evidence, or
regenerate frozen fixtures. If historical data already conflates surfaces,
preserve it and flag the ambiguity for review.

### B2 — P1: method analysis is not preserved per vulnerability class

`core/entity_merge.py:34–83` replaces analysis fields at the surface level,
while `candidateDetails` keeps the first detail for each class via `setdefault`.
The contribution normalizer stores method attribution only at the top level.

Reproduction: submit a high-confidence XSS hypothesis, then a low-confidence,
inconclusive SQLi hypothesis on the same surface. Both classes remain, but the
overall confidence, reason, conclusion, and method reference all become the
SQLi values. A later XSS update changes the overall reason/confidence while
the saved XSS detail still says high confidence with its original reason.

One surface containing several classes is a reasonable design. The defect is
mixing their analysis state. Store/update method-owned conclusions, evidence
roles, confidence, and attribution under the existing per-class detail;
preserve lifecycle-owned validation/review fields. Define the top-level
summary explicitly and avoid presenting the newest class's state as universal.
Keep historical submission evidence and receipts. Supporting/contrary roles
must not silently become contradictory through successive union merges.

### B3 — P1: compact recovery omits the actionable subject and disposition

`app/context.py::_attributes` omits `parameter`, `location`, `candidateId`,
`candidateDetails`, and `retired`. Its generic lifecycle still reads
`observed`; this does not communicate candidate validation.

The probe's `q`/query candidate loses both `q` and its location in compact
context. After refuting only XSS, the context still shows a remaining SQLi
class alongside the latest XSS reason/method and no per-class refutation
record. A resumed agent cannot faithfully reconstruct the decision from the
recommended context interface. An opaque row ID is not a substitute for the
missing subject or status.

Project a small, truthful candidate summary: exact surface coordinates,
canonical identity, per-class conclusion/validation/confidence/attribution,
retirement/reportability, and evidence roles. Keep history available through
existing detailed reads; do not place every historical payload in the prompt.
Test confirmed, inconclusive, and partially/fully refuted recovery as well as
proposed candidates.

### B4 — P2: continuation is complete only after a large page fits

Phase 7 fixed the permanent 200-row cutoff. However, `app/context.py::_pack`
returns a **replay cursor** when any part of the repository page does not fit
the response budget. The cursor advances only after the entire source page is
included. Increasing the budget is documented, so this is an efficiency and
usability limitation, not the previous silent-loss defect.

For 205 ordinary saved endpoints and an endpoint-filtered query:

| Requested budget | Endpoints returned | Following the cursor at the same budget |
| ---: | ---: | --- |
| 1,500 (default) | 0; `budget_too_small` | Same empty page |
| 6,000 | 10 | Same 10 records, same cursor |
| 20,000 | 45 | Same 45 records, same cursor |
| 100,000 | 200 | Advances to the final 5 |

The full 200-record response measured **81,807 UTF-8 bytes** under the current
`utf8_bytes_v1` counter. Despite the `maxTokens` name, these numbers are not
measured model tokens. Require continuation to advance through emitted records
at a practical fixed budget, with revision/filter binding and protected
warnings preserved. If even the protected minimum or one record cannot fit,
return an actionable insufficient-budget result. Do not solve this solely by
raising the default to a very large value.

The independent warning query is currently unbounded; preserve truthful
warning coverage when addressing the budget path rather than hiding warnings
to make a response fit. No new search service or MCP operation is needed.

## Architecture and adapter direction

The architecture remains appropriate: one external agent chooses experiments;
Synapse exposes a compact facade over the canonical Registry, execution and
authority services, SQLite workspace/evidence, context, jobs, and reports.
Multiple independent consumers share operational truth without Synapse
becoming their planner. No model/client SDK imports were found in the core,
application, state, or policy paths searched.

| Responsibility | Keep or change |
| --- | --- |
| Investigation choice, hypotheses, interpretation | Agent reasoning guided by selected skills |
| Parsing saved specifications/exports; normalization | Keep deterministic |
| Identity, evidence links, persistence, receipts, recovery | Keep deterministic and repair the findings above |
| HTTP/browser/tool execution and jobs | Keep concrete, bounded integration contracts |
| Heuristic vulnerability analyzers | Retain as explicit optional helpers during Beta; no blanket runs or candidate ingestion |
| Reviewed findings and reporting | Preserve the current canonical lifecycle |

The deterministic part should be **small and dependable**, not ephemeral.
Removing adapters wholesale would also remove useful parsers and execution
integrations. The compact connection already limits initial tool exposure to
eleven operations, so deleting retained action IDs is unnecessary for context
efficiency.

## Skills: keep the layers, improve practical use

The intended loading sequence is:

1. The package operating prompt and `operate-synapse`: recover state and use
   the live interfaces correctly.
2. `synapse-web-pentesting`: frame this engagement and select its next question.
3. One applicable method: auth/session, access control, browser input, server
   input, fetch/file/XML, structured data, configuration, or business logic.
4. CVE Intelligence only when a component-applicability question warrants it.

This is an adaptive methodology, not a mandatory sequence of sessions,
authorization, injection, JavaScript, and hidden-endpoint steps. Keep broad
surface/JavaScript mapping in the main method for now; add another specialist
only when repeated usage demonstrates a distinct workflow needing it. Do not
split each vulnerability subtype into another skill before Beta testing.

Codex's documented progressive loading supports this structure: metadata
selects a skill, then its body and needed references supply detail.
[Official skill documentation](https://learn.chatgpt.com/docs/build-skills).
Hosted MCP text is useful context but does not install a native Codex skill or
override the client's instruction hierarchy. Root `AGENTS.md` remains
repository-development guidance, not the engagement's runtime main prompt.

The review branch directly improves existing skill files:

- Load/reuse the server operating prompt and shared guidance once.
- Make identification, bounded discriminating checks, and a separate
  exploitation objective explicit.
- Clarify adaptive selection and evidence-based JavaScript/route discovery.
- Record benign/negative results as observations instead of forcing candidates.
- Select `rawDataSchemas["1.1"]`, distinguish outer arguments from the inner
  envelope, and explain local-write authority and retry/idempotency handling.
- Use the actual package digest, and clarify cursor/budget recovery.
- Improve XSS/SQLi trigger descriptions without adding payload catalogs.

The prior Phase 7 comparison supports a noise-reduction hypothesis, not a
speed or universal-model-superiority claim. It reported five unnecessary
helper findings; the selected method avoided those, but needed 47 initial
calls plus a 26-call continuation and operator corrections. Those corrections
are why contribution guidance was tightened. Current domain guidance is
sufficient to begin testing; only one family was exercised by that historical
live comparison.

## Code and test quality

The code has useful boundaries, typed contracts, real transaction/restart
tests, explicit compatibility fixtures, and reproducible distribution checks.
Its main weakness is the gap between those individual contracts and the exact
state a resumed operator model receives. The reproduced failures concentrate
there, rather than justifying a rewrite.

Maintenance hotspots are `workspace.py` (4,321 lines), `state/runtime.py`
(2,994), and the retained `stdio_server.py` (3,870). Extract a helper only when
one of the bounded repairs needs it; do not split these modules just to improve
line counts before Beta. Broad exception handlers merit individual reasoning:
several protect cleanup or explicitly return an unknown outcome, so blanket
replacement would be counterproductive.

**Do not combine test files merely to reduce their number.** The scan found no
exact duplicate test bodies. Useful, small cleanup is:

- Remove the CI `Re-run contract suite` step after confirming `bin/test`
  already discovers those same tests; it currently repeats them per matrix job.
- Keep packaging/content checks owned by `test_distribution.py`; keep operating
  topology/method guidance checks in `test_single_agent_default.py`.
- Keep `test_codex_skills.py` compatibility scenarios: they also exercise
  multi-consumer claims, dependencies, and recovery. Optional model workers
  are not the same thing as optional correctness of shared work records.
- Reduce brittle prose/heading assertions opportunistically when touching the
  relevant tests. Do not confuse checking that a heading exists with verifying
  agent behavior. Retain byte-exact legacy fixtures and migration/recovery tests.
- Add targeted regressions for the reproduced defects to existing modules,
  using parameterized/subTest cases where appropriate. No new framework,
  coverage-percentage target, or test-count target.

Testing order after the correctness repairs: clean setup and supplied-data
import; practical-budget context traversal; method contribution and negative
result; restart and a second consumer; report/bundle recovery; then the
operator's selected real integration. Freeze feature scope through that pass.
