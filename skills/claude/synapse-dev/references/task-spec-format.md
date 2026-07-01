# Task Spec Format

Two templates: a **Codex-style** spec (a self-contained task block) and a **Claude Code**
agentic-session brief (a protocol the agent runs). Both enforce the same principle — the
implementer makes no architectural decisions. Pick by where the work runs; the content
overlaps heavily.

---

## A. Codex-style task spec

Use when handing a discrete task to Codex (or any implementer that executes one task block).
Keep each task self-contained. Group only tightly-related fixes into one task.

```
TASK — <short imperative title>

FILES
  <exact path(s)>            # e.g. MCPS/Synapse-MCP/synapse_mcp/adapters/web/access_control.py
  <test path(s)>

PROBLEM / WRONG BEHAVIOR
  <what the code does now, and how to observe it — the reproduction, not a vibe>

WHY IT MATTERS
  <operational consequence: false positive, credential leak, duplicate entity, misleading
   report — in red-team terms, not abstract terms>

EXPECTED BEHAVIOR
  <the precise correct behavior. Resolve every design choice here. If a value/threshold/key
   strategy is involved, state it exactly. Leave nothing for the implementer to decide.>

REGRESSION TESTS
  <named test(s) with concrete inputs and expected outputs. If a fix changes behavior an
   existing passing test encodes, say which test and how to update it to the new contract.>

NON-GOALS
  <explicit guardrails: no new engine/DB/framework, no scope expansion, don't touch X>
```

Always sequence a batch of tasks by blast radius (confidentiality > correctness > misleading
internal output > polish), and state the order with a one-line rationale.

---

## B. Claude Code agentic-session brief

Use when Claude Code works directly in the repo. Frame the whole session as a protocol, then
list tasks; Claude Code reads files and runs tests itself, so describe *how to operate*, not
just *what to change*.

Include up front:
- **Role + mission:** decisions are pre-made in this brief; do not re-architect; stop and ask
  if a task needs an unspecified architectural call.
- **Working agreement:** inspect before editing (verify line numbers — the repo may have
  shifted); one commit per task referencing the task number; `bin/test` green is the gate
  after every task; stay inside each task's Non-Goals; report blockers instead of improvising.
- **Global design rule + guardrails** (from `architecture.md` §4).
- **Execution order** with rationale.

Then each task as: **Investigate → Implement → Tests → Non-goals → Done when**, where
Investigate points at the likely files/symbols to confirm, Implement states the exact change,
and "Done when" is the acceptance condition (always includes `bin/test` green).

End with a session-wide **Definition of done** and a standing **stop-and-report** instruction.

---

## C. Worked example (Codex-style)

```
TASK — Exclude 3xx redirects from access-control success classification

FILES
  MCPS/Synapse-MCP/synapse_mcp/adapters/web/access_control.py
  MCPS/Synapse-MCP/tests/test_access_control_adapter.py

PROBLEM / WRONG BEHAVIOR
  is_success_response() returns True for any status in 200–399. In execute_matrix_test(),
  an endpoint that redirects an unauthorized context to /login with a 302 is therefore scored
  as "access granted."

WHY IT MATTERS
  Produces a false-positive broken-access-control result on any app using redirect-based auth —
  the most common pattern. A false BOLA/BFLA finding in a deliverable is worse than a miss:
  it burns operator credibility and client trust.

EXPECTED BEHAVIOR
  is_success_response() returns True only for 200–299. 3xx, 4xx, 5xx are not access grants.
  No other call site relies on the old 200–399 range (verify before changing).

REGRESSION TESTS
  Add test_access_control_redirect_is_not_access_grant: mock server returns 302 → /login for
  the denied context; assert the replay result does NOT signal possible broken access control
  and the observed access is "deny".

NON-GOALS
  Do not change redirect-following behavior (redirects still must not be auto-followed).
  Do not touch the body-similarity thresholds. No new helper abstractions.
```

This is the standard to match: the implementer reads it and writes one obvious change plus one
obvious test, with zero design questions left open.
