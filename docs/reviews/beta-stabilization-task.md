# Codex task: stabilize Synapse Beta for operator testing

Prepared 27 September 2026. Review base:
`3eb1f8d1c1770a6af7f0313b0e665c6558ac1301` on `Beta`.
Read [the review and reproductions](2026-09-27-beta-review.md) first.
This is **one bounded stabilization task**, not Phase 8. Phase 7 stays complete.

## Objective and limits

Make stored candidate identity, per-class analysis, and compact recovery
precise; make context continuation usable at a practical budget; verify the
existing layered skills in one short operator exercise. Freeze feature work.

Keep one external Codex agent, using the operator's selected Daybreak model
for the actual web assessment. Preserve multiple independent consumers,
canonical workspace/evidence, the Registry, modern-compact's eleven
operations, direct/legacy compatibility, and explicit JSON-v1 migration.
Identification is the default web objective. Exploitation is a separate prompt
or manual operator workflow. Do not add a planner, model SDK, skill executor,
parallel memory, graph service, new migration by default, or a new adapter
replacement framework. Do not reopen deferred secret-persistence work.

## Checkpoints and effort

Effort means implementation complexity, not a promise of elapsed time. Use
the user's available **Codex Sol / High** for code repairs. XHigh is optional
only for a specific unresolved compatibility or cursor invariant; return to
High afterward. These are engineering recommendations, not model benchmarks.

| Checkpoint | Deliverable | Effort / model | Initial state |
| --- | --- | --- | --- |
| B0 | Reviewed skill/prompt clarification | Small / Sol Medium; domain review can use Daybreak High | Implemented on review branch; retain after merge |
| B1 | Collision-safe surface identity | Medium / Sol High | Pending |
| B2 | Correct per-class method updates | Medium / Sol High | Pending |
| B3 | Truthful compact candidate recovery | Medium / Sol High | Pending; depends on B2 |
| B4 | Advancing budget-bounded continuation | Medium / Sol High | Pending |
| B5 | Small test/CI cleanup and final automated checks | Small / Sol Medium | Pending; cleanup is non-blocking |
| B6 | One saved-data operator/restart exercise | Small / Daybreak High in Codex | Pending; depends on B1–B4 |
| B7 | Selected integration smoke and Beta freeze | Small / operator + Daybreak High | Pending |

Work serially. Do not assign a worker per checkpoint. Do not turn every line
item below into another task document or historical acceptance gate.

## Resume contract

At session start, read root/relevant nested `AGENTS.md`, this task, and the
latest record below. Check the worktree, preserve unrelated changes, and compare
current Beta with the review base. Continue the next incomplete checkpoint.

After a coherent slice, inspect the diff, run its focused checks, update this
same record, update the required local Version-Log/shared changelog, and commit.
Record the code commit in the following ledger update; do not invent a commit's
own future SHA. If usage ends mid-slice, record dirty paths and the exact next
command. A passing unrelated suite does not complete a checkpoint.

```yaml
checkpoint: B0
status: implemented_pending_merge
review_base: 3eb1f8d1c1770a6af7f0313b0e665c6558ac1301
implementation_branch: codex/beta-qa-skills-20260927
implementation_commit: null # resolve from this branch's commit history
checks:
  - 830 core and 17 modern tests passed on review base
  - 31 focused skill/default/distribution tests passed after guidance edits
  - default, web-method, and compatibility validators passed
next_checkpoint: B1
next_action: reproduce distinct-route candidate collision, then repair surface identity
dirty_worktree: inspect current status; preserve unrelated changes
```

## B0 — Retain and review the already-written skills

The review branch changes the existing operating/web guidance, common method
and saved-data references, XSS/SQLi descriptions, main prompt, and web default
prompt. Review and retain those changes rather than creating another skill
system. Check hosted/local content parity and package attribution after updating
installed assets. Do not rewrite historical `methodRef` digests.

The structure is operating entry → web methodology → selected family. Shared
references are read once per unchanged client context. Model-selected
experiments remain flexible; schemas, receipts, evidence, execution, and
identity remain deterministic. No additional method package is required now.

## B1 — Repair surface identity without corrupting existing records

1. Reproduce the `/a/b` versus `/a-b` collision through version 1.1 ingestion.
2. Derive new surface identity from the full canonical method/URL/location/
   parameter tuple using a collision-resistant digest. Preserve path case and
   meaningful separators; retain the existing intentional query-value
   normalization. A readable prefix may accompany the digest.
3. Resolve historical candidates by exact canonical coordinates before reusing
   their existing IDs. An old slug match alone must never merge two surfaces.
   Keep references and explicit validation decisions on unambiguous old rows.
   Flag historical ambiguous/conflated rows instead of silently splitting,
   deleting, or reassigning evidence.
4. Verify creation, repeat ingestion, curation by coordinates/ID, validation,
   and restart use the same resolved identity. Preserve JSON-v1 behavior and
   explain any deliberate externally visible ID changes. No blanket migration
   or fixture regeneration.
5. Add one parameterized regression in the existing ingestion/contribution
   tests: separator collisions, path case, long prefixes, and an unchanged
   same-surface retry. Include the historical exact-match case.

Acceptance: distinct canonical surfaces remain distinct; the same surface stays
stable; old references are not silently broken. The captured review case must
produce two records with the correct respective URLs and reasons.

## B2 — Preserve each class's analysis and evidence roles

1. Keep one surface candidate and existing `candidateDetails`; do not add a
   parallel analysis database. Put method-owned reason, confidence, conclusion,
   knowledge state, supporting/contrary evidence, and attribution on the
   relevant class detail using a bounded typed convention.
2. On a later method submission, update that class's current analysis without
   overwriting its lifecycle-owned validation/review/disposition fields or the
   other classes. Retain historical contributions and receipts as evidence.
3. Define top-level summaries for mixed classes explicitly. Never present the
   last class's confidence or method as the owner of all conclusions.
4. Define evidence-role updates within a class. A prior supporting ID that is
   later reconsidered must not become both current support and current contrary
   evidence through a blind union. Preserve history with its original role.
5. Extend the existing method recovery test: XSS → SQLi on the same surface →
   changed XSS conclusion → partial refutation → restart. Assert both classes'
   independent evidence/method state, unchanged validation decisions, stable
   identity, and idempotent receipts.

Acceptance: the review's mixed-class and stale-detail cases no longer occur.
The v1.0 envelope stays compatible; prefer internal/additive normalization of
the existing 1.1 fields over a new public submission version.

## B3 — Recover the precise surface and disposition through compact context

1. Extend the current context projection with the candidate's exact parameter,
   location, canonical candidate identity, and a concise per-class summary.
2. Preserve analysis conclusion separately from actual validation status,
   reportability, retirement, and operator review. Include enough reason,
   evidence-role, and method attribution to avoid conflating classes.
3. Ensure unresolved, partially refuted, fully refuted, and confirmed-but-not-
   reviewed candidates remain distinguishable. Reports and compact context
   must agree about their dispositions. Avoid treating generic row lifecycle
   `observed` as either successful validation or a promoted finding.
4. Keep projection bounded; link existing detail/evidence reads for history.
   Extend the existing context/recovery regression rather than adding a new
   test module. Run the relevant report test if its shared projection changes.

Acceptance: a fresh consumer can identify which parameter was tested, what is
still open, what was refuted, and which method/evidence supports each class
without conversation memory or reconstructing IDs from display labels.

## B4 — Make ordinary cursor continuation advance at a fixed budget

1. Reproduce the 205-endpoint case at 6,000 and 20,000 budget units. Currently
   the same cursor repeats the first 10/45 records until an entire 200-record
   repository page fits.
2. Advance through records actually emitted, using a stable ordering and a
   cursor bound to the existing normalized query and revision. Account for
   sources that project into multiple response sections; do not skip records
   when compiler priority order differs from repository order.
3. Preserve independent contradiction coverage and active/unknown execution
   recovery. If protected content must be bounded, expose incomplete coverage
   and usable continuation. Never silently truncate it to meet a byte budget.
4. Return accurate insufficient-budget guidance when the protected minimum or
   one record cannot fit. Keep `sinceRevision` separate from page position;
   concurrent mutation must still require explicit refresh.
5. Extend the existing paging test with a realistic fixed budget, a contradiction,
   and mixed candidate/fact sections. Traverse to completion with progress,
   no lost identities, and no duplicated ordinary records. Retain query-mismatch
   and revision-change controls. Distinguish bytes from actual model tokens.

Acceptance: normal same-budget continuation advances without requiring the
entire 200-row page in one response. No new MCP tool, open cross-call database
transaction, graph service, or context server.

## B5 — Limit test cleanup and verify the release candidate once

1. Inventory overlapping assertions by behavior before removing anything.
   Remove the redundant CI contract rerun if unchanged discovery confirms
   `bin/test` already runs it. This is optional cleanup, not a release blocker.
2. Keep asset/link/packaging checks in their existing owner and methodology
   checks in `test_single_agent_default.py`. Consolidate small repeated cases
   with `subTest` only when their fixtures and failure meaning truly match.
3. Keep compatibility, cross-process/restart, migration, receipt, and execution
   recovery coverage. Do not delete `test_codex_skills.py` merely because its
   compatibility scenario uses specialist labels. Do not merge large unrelated
   modules or rebuild the test framework.
4. Run focused tests at each repair. After B1–B4, run one full core suite, then
   one modern suite serially, plus template/skill checks. Rebuild/install wheel
   and sdist if shipped assets/contracts changed. Check generated contracts;
   update only explained modern changes and preserve frozen legacy fixtures.
5. Record exact commands/results, dirty files, remaining limitations, and actual
   interpreter/SQLite/MCP versions. Do not repeat all historical phase gates.

Acceptance: no known reproduced correctness failure remains; required current
checks pass. No test-count or coverage-percentage target is introduced.

## B6 — One practical saved-data exercise using Codex + Daybreak

Use the actual available Daybreak model at High; record the resolved model,
client version, MCP profile, and artifact/code commit. Prepare one fictional
workspace, a declared call/usage budget, and a grant covering only the required
local actions. Make the grant and exact contribution schema available before
starting so setup friction is measured separately from method reasoning.

In one session, import supplied data, load operating + web + one selected
method, assess a supported case and benign/ambiguous controls, save justified
records, and recover across a practical-budget page boundary. Then restart and
use a distinct consumer to read the same subject, evidence, method, disposition,
and receipt. Produce an internal report and verify bundle export/import using
existing mechanisms. Reuse fixtures; do not repeat the full Phase 7 comparison.

Record supported/unsupported conclusions, missed records, successful/failed
calls, repeated guidance reads, tokens as reported by the client, operator
corrections, and restart behavior. Do not create a new telemetry framework.
If the model needs envelope correction, fix the one guidance/discovery issue
and repeat only the failed step. If unavailable, mark this checkpoint blocked;
service tests or an offline skill read are not a substitute for the live run.

Acceptance: correct supported/negative/gap classification; successful durable
write and restart without narration-only completion; no exploit expansion;
no unexplained contract-correction loop. Do not claim model superiority from
this small exercise.

## B7 — Test the chosen integration and freeze Beta

Let the operator select the first real integration and authorized test target.
Smoke-test only that path: establish a baseline, perform a bounded identifying
check, retain evidence and state, stop/recover appropriately, and inspect the
report. A local intentionally vulnerable application is a useful initial target.
Do not activate every browser/scanner/provider to satisfy this checkpoint.

Mark the exact artifact as the Beta testing candidate, document unsupported or
untested integrations, and stop feature work. Later failures should produce
small bug reports and targeted repairs, not another modernization plan.

## Copyable launch instruction

> Stabilize Synapse Beta using docs/reviews/beta-stabilization-task.md and the
> associated 2026-09-27 review. Preserve the reviewed skill changes. Start at
> the next incomplete checkpoint, reproduce its specific defect, implement the
> smallest compatible repair, and run its focused verification. Update this
> same checkpoint record with the commit, actual results, dirty paths, and
> exact next action. Use one agent by default. Keep the Registry, canonical
> data model, and compatibility boundaries. Do not add features, rewrite the
> adapter framework, or expand the test suite beyond regressions needed for
> these failures. Stop after Beta is ready for the bounded operator exercise.
