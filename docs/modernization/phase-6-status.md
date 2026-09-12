# Phase 6 status

Phase 6 is in progress. Tasks 6A–6D are implemented, including trusted
synchronous effect observations. No Phase 6 closure or client-support claim is
made here.

- The default is one Codex agent using `modern-compact`. Provider-specific
  skills stay outside the Synapse application.
- Work items, authority grants, dispatches, and execution runs remain in
  canonical SQLite-v2 workspace state. JSON-v1 compatibility and explicit
  migration remain unchanged.
- The Action Registry is the single policy, execution, outcome, and evidence
  route. A dispatch is bound to its signed execution plan and durable run.
- 6D observes owned HTTP, planned local output, and synchronous child-process
  seams. It records bounded, redacted observations; a child process's internal
  traffic is not claimed as observed. Missing or uncertain effects require
  reconciliation and are not automatically replayed.

The applicable developer checks are focused service tests for the changed
boundary. Completed-phase acceptance and benchmark runners were retired; they
are not prerequisites for 6D. Current operator instructions are in
[Operations](../Operations.md). Durable decisions are in
[ADR-0013](adr/ADR-0013-observed-effect-execution-lifecycle.md).
