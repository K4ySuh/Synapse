"""Task 4C activated runtime, multi-process, crash, and artifact acceptance."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import multiprocessing
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest

from helpers import isolated_state
from synapse_mcp.app.actions import ActionRequest, ExecutionContext, REGISTRY, RiskClass
from synapse_mcp.app.facade.contracts import FacadeCallContext
from synapse_mcp.app.facade.resources import ResourceAccessError, ResourceReferenceService
from synapse_mcp.core import background_jobs, workspace
from synapse_mcp.policy import (
    Allow,
    AuthorityGrant,
    AuthorityMode,
    AuthorityRepositoryError,
    BudgetLimits,
    StateChangePolicy,
    WorkspaceAuthorityRepository,
)
from synapse_mcp.state import ActivatedWorkspaceRepository, StateBusyError, StateMigrationService
from synapse_mcp.state.connections import ConnectionFactory, verify_database_integrity
from synapse_mcp.state.migrations import apply_migrations


RACE_ROUNDS = 100


def _plan(workspace_id: str):
    descriptor = REGISTRY.get("workspace.summary")
    request = ActionRequest(
        descriptor.input_model.model_validate({"workspaceId": workspace_id}),
        ExecutionContext(workspace_id, "phase4c-race", 45.0, None),
    )
    return REGISTRY.resolve_execution_plan("workspace.summary", request)


def _grant(plan) -> AuthorityGrant:
    now = datetime.now(timezone.utc)
    return AuthorityGrant(
        grant_id="grant-phase4c",
        workspace_id=plan.intent.workspace_id,
        revision=1,
        mode=AuthorityMode.FULL_DELEGATED,
        scope_digest=plan.intent.target_envelope.scope_digest,
        target_envelope=plan.intent.target_envelope,
        allowed_action_patterns=(plan.action_id,),
        allowed_methods=plan.intent.methods,
        allowed_effects=plan.effects,
        risk_ceiling=RiskClass.HIGH,
        credential_refs=plan.intent.credential_refs,
        provider_routes=plan.intent.providers,
        third_party_providers=(),
        local_outputs=plan.intent.local_outputs,
        budgets=BudgetLimits(None, None, None, None),
        state_change_policy=StateChangePolicy.ALLOW,
        created_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=2),
        approved_by="operator:phase4c",
    )


def _entity_race_worker(workspace_root: str, barrier, worker: int, rounds: int, queue) -> None:
    try:
        root = Path(workspace_root)
        repository = ActivatedWorkspaceRepository(root.name, root)
        target_payload = {
            "workspaceId": root.name,
            "target": "race.example",
            "kind": "host",
            "createdAt": "2026-08-24T00:00:00Z",
            "updatedAt": "2026-08-24T00:00:00Z",
        }
        for round_number in range(rounds):
            barrier.wait()
            evidence_id = f"evidence-{round_number:03d}-{worker}"
            artifact = repository.artifacts.ingest_bytes(
                f"{round_number}:{worker}".encode(),
                media_type="text/plain",
                origin="phase4c.entity-race",
            )
            repository.ingest_collections(
                target="race.example",
                target_payload=target_payload,
                evidence_payload={
                    "evidenceId": evidence_id,
                    "source": "phase4c",
                    "dataType": "race",
                    "createdAt": "2026-08-24T00:00:00Z",
                },
                artifact=artifact,
                collections={
                    "endpoints": (
                        {
                            "type": "endpoint",
                            "key": "GET:https://race.example/shared",
                            "method": "GET",
                            "url": "https://race.example/shared",
                            "worker": worker,
                        },
                        {
                            "type": "endpoint",
                            "key": f"GET:https://race.example/distinct/{round_number}/{worker}",
                            "method": "GET",
                            "url": f"https://race.example/distinct/{round_number}/{worker}",
                        },
                    )
                },
                audit_payload={"summary": "Committed one same-entity race participant."},
            )
        queue.put({"worker": worker, "ok": True})
    except BaseException as exc:
        queue.put({"worker": worker, "ok": False, "error": f"{type(exc).__name__}: {exc}"})


def _dispatch_race_worker(workspaces_root: str, plan, barrier, worker: int, rounds: int, queue) -> None:
    workspace.WORKSPACES_DIR = Path(workspaces_root)
    outcomes = []
    try:
        for round_number in range(rounds):
            barrier.wait()
            try:
                result = WorkspaceAuthorityRepository("dispatch-race").authorize(
                    plan,
                    risk_class=RiskClass.NONE,
                    profile="full_delegated",
                    authority_session_id="phase4c-session",
                    selected_grant_id="grant-phase4c",
                    idempotency_key=f"round-{round_number:03d}",
                )
                outcomes.append((round_number, "allow", result.receipt.dispatch_id))
            except AuthorityRepositoryError as exc:
                outcomes.append((round_number, exc.reason_code, ""))
        queue.put({"worker": worker, "outcomes": outcomes})
    except BaseException as exc:
        queue.put({"worker": worker, "error": f"{type(exc).__name__}: {exc}"})


def _revocation_race_worker(workspaces_root: str, plan, barrier, operation: str, queue) -> None:
    workspace.WORKSPACES_DIR = Path(workspaces_root)
    repository = WorkspaceAuthorityRepository("revocation-race")
    barrier.wait()
    try:
        if operation == "revoke":
            grant = repository.revoke_grant("grant-phase4c", expected_grant_revision=1)
            queue.put({"operation": operation, "revision": grant.revision})
        else:
            result = repository.authorize(
                plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="phase4c-session",
                selected_grant_id="grant-phase4c",
                idempotency_key="revoke-race",
            )
            queue.put(
                {
                    "operation": operation,
                    "decision": result.decision.kind,
                    "dispatchId": result.receipt.dispatch_id if result.receipt else "",
                }
            )
    except BaseException as exc:
        queue.put({"operation": operation, "error": f"{type(exc).__name__}: {exc}"})


def _terminal_task_record(workspace_id: str, job_id: str, *, finalizer_name: str = "") -> dict:
    plan = background_jobs._legacy_job_execution_plan(
        action_id="phase4c.finalize",
        workspace_id=workspace_id,
        target="",
        correlation_id=job_id,
        output_path="",
        finalizer_name=finalizer_name,
        finalizer_data={},
    )
    record = {
        "jobId": job_id,
        "tool": "phase4c.finalize",
        "workspaceId": workspace_id,
        "target": "",
        "status": "completed",
        "pid": None,
        "createdAt": "2026-08-24T00:00:00Z",
        "startedAt": "2026-08-24T00:00:01Z",
        "completedAt": "2026-08-24T00:00:02Z",
        "timeoutSeconds": 30,
        "eventType": "phase4c.finalize",
        "summary": "Finalize one terminal v2 task.",
        "command": [],
        "shellCommand": "",
        "eventData": {"workspaceId": workspace_id},
        "approval": {},
        "outputPath": "",
        "stdoutPath": "",
        "stderrPath": "",
        "returnCodePath": "",
        "continuationPaths": {"stdoutPath": "", "stderrPath": "", "returnCodePath": ""},
        "returnCode": 0,
        "timedOut": False,
        "finalized": False,
        "finalizerName": finalizer_name,
        "finalizerData": {},
        "executionPlan": {},
        "finalizerEffects": plan.effects.to_dict(),
        "correlationId": job_id,
        "run": None,
        "result": None,
        "error": "",
        "revision": 0,
    }
    plan = plan.bind_continuation(
        job_id=job_id,
        handler=finalizer_name,
        material=background_jobs._continuation_material(record),
    )
    record["executionPlan"] = plan.to_dict()
    return record


def _finalization_race_worker(workspaces_root: str, barrier, worker: int, rounds: int, queue) -> None:
    workspace.WORKSPACES_DIR = Path(workspaces_root)
    errors = []
    for round_number in range(rounds):
        barrier.wait()
        try:
            background_jobs.status(f"task-race-{round_number:03d}", include_result=True)
        except BaseException as exc:
            errors.append(f"{round_number}:{type(exc).__name__}:{exc}")
    queue.put({"worker": worker, "errors": errors})


def _install_orphan_worker(workspace_root: str) -> None:
    root = Path(workspace_root)
    repository = ActivatedWorkspaceRepository(root.name, root)
    repository.artifacts.ingest_bytes(b"installed-before-metadata", origin="phase4c.crash")
    os._exit(73)


def _ingest_crash_worker(workspace_root: str, stage: str, exit_code: int) -> None:
    root = Path(workspace_root)
    repository = ActivatedWorkspaceRepository(root.name, root)
    artifact = repository.artifacts.ingest_bytes(
        f"crash:{stage}".encode(),
        origin="phase4c.transaction-crash",
    )

    def crash(boundary: str) -> None:
        if boundary == stage:
            os._exit(exit_code)

    repository.ingest_collections(
        target="crash.example",
        target_payload={"workspaceId": root.name, "target": "crash.example", "kind": "host"},
        evidence_payload={
            "evidenceId": f"evidence-crash-{stage}",
            "source": "phase4c-crash",
            "dataType": "crash",
        },
        artifact=artifact,
        collections={"observations": ({"type": "observation", "key": f"crash-{stage}"},)},
        audit_payload={"summary": f"Crash at {stage}."},
        fault_injector=crash,
    )


def _crash_finalizer(_record, _run, _data):
    os._exit(91)


def _crash_finalization_worker(workspaces_root: str, job_id: str) -> None:
    workspace.WORKSPACES_DIR = Path(workspaces_root)
    background_jobs.register_finalizer("phase4c.crash", _crash_finalizer)
    background_jobs.status(job_id, include_result=True)


def _authorize_then_exit(workspaces_root: str, plan) -> None:
    workspace.WORKSPACES_DIR = Path(workspaces_root)
    WorkspaceAuthorityRepository("crash-truth").authorize(
        plan,
        risk_class=RiskClass.NONE,
        profile="full_delegated",
        authority_session_id="phase4c-session",
        selected_grant_id="grant-phase4c",
        idempotency_key="post-commit-crash",
    )
    os._exit(0)


def _dispatch_before_commit_crash_worker(workspace_root: str) -> None:
    root = Path(workspace_root)
    repository = ActivatedWorkspaceRepository(root.name, root)
    with repository.transaction() as connection:
        revision = repository._workspace_revision(connection) + 1
        action_id = repository._ensure_action(
            connection,
            "workspace.summary",
            revision,
            {"state": "authorized", "planFingerprint": "pre-commit-crash"},
        )
        connection.execute(
            "INSERT INTO action_dispatches(dispatch_id, workspace_id, action_id, authority_grant_id, state, idempotency_key, payload_json, created_revision, updated_revision, created_at, updated_at) "
            "VALUES('dispatch-pre-commit-crash', ?, ?, 'grant-phase4c', 'authorized', 'sha256:pre-commit-crash', '{}', ?, ?, '2026-08-24T00:00:00Z', '2026-08-24T00:00:00Z')",
            (root.name, action_id, revision, revision),
        )
        os._exit(92)


def _task_transition_then_exit(workspaces_root: str, record: dict) -> None:
    workspace.WORKSPACES_DIR = Path(workspaces_root)
    transitioned = dict(record)
    transitioned["pid"] = os.getpid()
    background_jobs._write_record(transitioned)
    os._exit(0)


class Phase4CRuntimeAdoptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = isolated_state(self.root)
        self.state.__enter__()

    def tearDown(self) -> None:
        self.state.__exit__(None, None, None)
        self.temporary.cleanup()

    def activate(self, workspace_id: str, *, hosts: list[str] | None = None) -> ActivatedWorkspaceRepository:
        workspace.create_workspace(workspace_id, hosts=hosts or [], store_version="json-v1")
        migration = StateMigrationService(self.root)
        migration.migrate(workspace_id, apply=True)
        migration.activate(workspace_id)
        return ActivatedWorkspaceRepository(workspace_id, self.root / "workspaces" / workspace_id)

    def context(self):
        return multiprocessing.get_context("fork")

    def test_100_multiprocess_same_entity_rounds_preserve_every_evidence_relation(self) -> None:
        repository = self.activate("entity-race", hosts=["race.example"])
        context = self.context()
        barrier = context.Barrier(2)
        queue = context.Queue()
        processes = [
            context.Process(
                target=_entity_race_worker,
                args=(str(repository.workspace_root), barrier, worker, RACE_ROUNDS, queue),
            )
            for worker in (1, 2)
        ]
        for process in processes:
            process.start()
        results = [queue.get(timeout=60) for _process in processes]
        for process in processes:
            process.join(60)
            self.assertEqual(process.exitcode, 0)
        self.assertTrue(all(item.get("ok") for item in results), results)

        with repository.connection_factory.connect() as connection:
            entity_count = connection.execute(
                "SELECT COUNT(*) FROM entities WHERE workspace_id='entity-race' AND natural_key LIKE '%:GET:https://race.example/shared'"
            ).fetchone()[0]
            total_endpoints = connection.execute(
                "SELECT COUNT(*) FROM entities WHERE workspace_id='entity-race' AND entity_type='endpoint'"
            ).fetchone()[0]
            evidence_count = connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE workspace_id='entity-race' AND summary='phase4c'"
            ).fetchone()[0]
            relation_count = connection.execute(
                "SELECT COUNT(*) FROM entity_evidence WHERE workspace_id='entity-race'"
            ).fetchone()[0]
            audit_count = connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE workspace_id='entity-race'"
            ).fetchone()[0]
            verify_database_integrity(connection)
        self.assertEqual(entity_count, 1)
        self.assertEqual(total_endpoints, 1 + RACE_ROUNDS * 2)
        self.assertEqual(evidence_count, RACE_ROUNDS * 2)
        self.assertEqual(relation_count, RACE_ROUNDS * 4)
        self.assertEqual(repository.revision(), 1 + RACE_ROUNDS * 2)
        self.assertEqual(audit_count, repository.revision())

    def test_100_multiprocess_dispatch_rounds_cross_each_idempotency_boundary_once(self) -> None:
        self.activate("dispatch-race")
        plan = _plan("dispatch-race")
        WorkspaceAuthorityRepository("dispatch-race").create_grant(_grant(plan))
        context = self.context()
        barrier = context.Barrier(2)
        queue = context.Queue()
        processes = [
            context.Process(
                target=_dispatch_race_worker,
                args=(str(self.root / "workspaces"), plan, barrier, worker, RACE_ROUNDS, queue),
            )
            for worker in (1, 2)
        ]
        for process in processes:
            process.start()
        results = [queue.get(timeout=90) for _process in processes]
        for process in processes:
            process.join(90)
            self.assertEqual(process.exitcode, 0)
        self.assertFalse(any(item.get("error") for item in results), results)
        by_round: dict[int, list[str]] = {index: [] for index in range(RACE_ROUNDS)}
        for result in results:
            for round_number, outcome, _dispatch_id in result["outcomes"]:
                by_round[round_number].append(outcome)
        for round_number, outcomes in by_round.items():
            self.assertEqual(outcomes.count("allow"), 1, (round_number, outcomes))
            self.assertEqual(outcomes.count("dispatch_reconciliation_required"), 1, (round_number, outcomes))
        repository = WorkspaceAuthorityRepository("dispatch-race")
        self.assertEqual(len(repository.list_dispatches()), RACE_ROUNDS)
        self.assertEqual(repository.budget_usage("grant-phase4c").dispatches_used, RACE_ROUNDS)

    def test_100_multiprocess_terminal_status_rounds_finalize_once(self) -> None:
        repository = self.activate("task-race")
        for round_number in range(RACE_ROUNDS):
            background_jobs._write_record(_terminal_task_record("task-race", f"task-race-{round_number:03d}"))
        context = self.context()
        barrier = context.Barrier(2)
        queue = context.Queue()
        processes = [
            context.Process(
                target=_finalization_race_worker,
                args=(str(self.root / "workspaces"), barrier, worker, RACE_ROUNDS, queue),
            )
            for worker in (1, 2)
        ]
        for process in processes:
            process.start()
        results = [queue.get(timeout=90) for _process in processes]
        for process in processes:
            process.join(90)
            self.assertEqual(process.exitcode, 0)
        self.assertTrue(all(not item["errors"] for item in results), results)
        tasks = repository.list_tasks()
        self.assertEqual(len(tasks), RACE_ROUNDS)
        self.assertTrue(all(item.get("finalized") for item in tasks))
        with repository.connection_factory.connect() as connection:
            reserved = connection.execute(
                "SELECT COUNT(*) FROM task_events WHERE workspace_id='task-race' AND event_type='task.finalization_reserved'"
            ).fetchone()[0]
            applied = connection.execute(
                "SELECT COUNT(*) FROM task_events WHERE workspace_id='task-race' AND event_type='task.finalization_result'"
            ).fetchone()[0]
            duplicates = connection.execute(
                "SELECT COUNT(*) FROM (SELECT task_id, task_revision, COUNT(*) n FROM task_events GROUP BY task_id, task_revision HAVING n > 1)"
            ).fetchone()[0]
            verify_database_integrity(connection)
        self.assertEqual(reserved, RACE_ROUNDS)
        self.assertEqual(applied, RACE_ROUNDS)
        self.assertEqual(duplicates, 0)

    def test_revocation_and_dispatch_race_has_one_serializable_policy_order(self) -> None:
        repository = self.activate("revocation-race")
        plan = _plan("revocation-race")
        WorkspaceAuthorityRepository("revocation-race").create_grant(_grant(plan))
        context = self.context()
        barrier = context.Barrier(2)
        queue = context.Queue()
        processes = [
            context.Process(
                target=_revocation_race_worker,
                args=(str(self.root / "workspaces"), plan, barrier, operation, queue),
            )
            for operation in ("revoke", "dispatch")
        ]
        for process in processes:
            process.start()
        results = [queue.get(timeout=30) for _process in processes]
        for process in processes:
            process.join(30)
            self.assertEqual(process.exitcode, 0)
        self.assertFalse(any(item.get("error") for item in results), results)
        dispatch_result = next(item for item in results if item["operation"] == "dispatch")
        self.assertIn(dispatch_result["decision"], {"allow", "approval_required"})
        if dispatch_result["decision"] == "allow":
            dispatch = WorkspaceAuthorityRepository("revocation-race").inspect_dispatch(dispatch_result["dispatchId"])
            self.assertEqual(dispatch["grantRevision"], 1)
        else:
            self.assertFalse(dispatch_result["dispatchId"])
        with repository.connection_factory.connect() as connection:
            verify_database_integrity(connection)
            uncovered = connection.execute(
                "SELECT COUNT(*) FROM action_dispatches d JOIN authority_grants g ON g.workspace_id=d.workspace_id AND g.grant_id=d.authority_grant_id WHERE d.workspace_id='revocation-race' AND d.created_revision > g.updated_revision"
            ).fetchone()[0]
        self.assertEqual(uncovered, 0)

    def test_crash_boundaries_leave_orphan_bytes_and_reconcile_reserved_finalizer(self) -> None:
        repository = self.activate("crash-truth")
        context = self.context()
        artifact_process = context.Process(target=_install_orphan_worker, args=(str(repository.workspace_root),))
        artifact_process.start()
        artifact_process.join(30)
        self.assertEqual(artifact_process.exitcode, 73)
        with repository.connection_factory.connect() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0], 0)
        orphan_blobs = list(repository.artifacts.blob_root.glob("*/*"))
        self.assertEqual(len(orphan_blobs), 1)

        baseline_revision = repository.revision()
        with repository.connection_factory.connect() as connection:
            baseline_evidence_count = connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE workspace_id='crash-truth'"
            ).fetchone()[0]
        for offset, stage in enumerate(("after_change_log", "after_audit", "after_revision"), start=1):
            process = context.Process(
                target=_ingest_crash_worker,
                args=(str(repository.workspace_root), stage, 73 + offset),
            )
            process.start()
            process.join(30)
            self.assertEqual(process.exitcode, 73 + offset)
            self.assertEqual(repository.revision(), baseline_revision)
            self.assertFalse(repository.evidence_exists(f"evidence-crash-{stage}"))
        with repository.connection_factory.connect() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM evidence WHERE workspace_id='crash-truth'").fetchone()[0],
                baseline_evidence_count,
            )
            verify_database_integrity(connection)

        plan = _plan("crash-truth")
        WorkspaceAuthorityRepository("crash-truth").create_grant(_grant(plan))
        pre_commit_dispatch = context.Process(
            target=_dispatch_before_commit_crash_worker,
            args=(str(repository.workspace_root),),
        )
        pre_commit_dispatch.start()
        pre_commit_dispatch.join(30)
        self.assertEqual(pre_commit_dispatch.exitcode, 92)
        with repository.connection_factory.connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_dispatches WHERE dispatch_id='dispatch-pre-commit-crash'"
                ).fetchone()[0],
                0,
            )

        dispatch_process = context.Process(
            target=_authorize_then_exit,
            args=(str(self.root / "workspaces"), plan),
        )
        dispatch_process.start()
        dispatch_process.join(30)
        self.assertEqual(dispatch_process.exitcode, 0)
        with self.assertRaises(AuthorityRepositoryError) as replay:
            WorkspaceAuthorityRepository("crash-truth").authorize(
                plan,
                risk_class=RiskClass.NONE,
                profile="full_delegated",
                authority_session_id="phase4c-session",
                selected_grant_id="grant-phase4c",
                idempotency_key="post-commit-crash",
            )
        self.assertEqual(replay.exception.reason_code, "dispatch_reconciliation_required")
        self.assertEqual(len(WorkspaceAuthorityRepository("crash-truth").list_dispatches()), 1)

        job_id = "task-crash-finalizer"
        background_jobs._write_record(_terminal_task_record("crash-truth", job_id, finalizer_name="phase4c.crash"))
        finalizer_process = context.Process(
            target=_crash_finalization_worker,
            args=(str(self.root / "workspaces"), job_id),
        )
        finalizer_process.start()
        finalizer_process.join(30)
        self.assertEqual(finalizer_process.exitcode, 91)
        reconciled = background_jobs.status(job_id, include_result=True)
        self.assertTrue(reconciled["finalized"])
        self.assertTrue(reconciled["reconciliationRequired"])
        self.assertEqual(reconciled["reconciliationReason"], "finalization_interrupted")
        with repository.connection_factory.connect() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM task_events WHERE task_id=? AND event_type='task.finalization_reserved'",
                    (job_id,),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM task_events WHERE task_id=? AND event_type='task.finalization_result'",
                    (job_id,),
                ).fetchone()[0],
                1,
            )
            verify_database_integrity(connection)

        running = _terminal_task_record("crash-truth", "task-running-after-death")
        running.update(
            {
                "status": "running",
                "completedAt": "",
                "returnCode": None,
            }
        )
        task_process = context.Process(
            target=_task_transition_then_exit,
            args=(str(self.root / "workspaces"), running),
        )
        task_process.start()
        task_process.join(30)
        self.assertEqual(task_process.exitcode, 0)
        committed_transition = repository.read_task("task-running-after-death")
        self.assertIsNotNone(committed_transition)
        self.assertEqual(committed_transition["status"], "running")
        unknown = background_jobs.status("task-running-after-death", include_result=True)
        self.assertTrue(unknown["finalized"])
        self.assertTrue(unknown["reconciliationRequired"])
        self.assertEqual(unknown["reconciliationReason"], "process_truth_unknown_after_restart")

    def test_resource_restart_checkpoint_and_concurrent_backup_are_durable_and_bounded(self) -> None:
        repository = self.activate("operations")
        source = repository.workspace_root / "state-v2" / "generated" / "result.txt"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("durable resource", encoding="utf-8")
        context = FacadeCallContext(
            workspace_id="operations",
            principal_id="principal-phase4c",
            authority_session_id="session-phase4c",
            execution_profile="full_delegated",
        )
        service = ResourceReferenceService(allowed_roots=(self.root,))
        reference = service.issue(source, workspace_id="operations", context=context, artifact_type="result")
        restarted = ResourceReferenceService(allowed_roots=(self.root,))
        self.assertEqual(restarted.resolve(reference.reference, context=context).content, "durable resource")
        with self.assertRaises(ResourceAccessError) as denied:
            restarted.resolve(
                reference.reference,
                context=replace(context, principal_id="another-principal"),
            )
        self.assertEqual(denied.exception.reason_code, "resource_principal_mismatch")
        database_bytes = repository.database_path.read_bytes()
        self.assertNotIn(reference.reference.encode(), database_bytes)
        self.assertNotIn(str(source).encode(), database_bytes)
        self.assertNotIn(b"principal-phase4c", database_bytes)
        self.assertNotIn(b"session-phase4c", database_bytes)

        writer_done = threading.Event()

        def writer() -> None:
            for index in range(20):
                repository.replace_collection(
                    "checkpoint.example",
                    "observations",
                    ({"type": "observation", "key": f"writer-{index}", "value": index},),
                )
            writer_done.set()

        repository.upsert_target(
            "checkpoint.example",
            {
                "workspaceId": "operations",
                "target": "checkpoint.example",
                "kind": "host",
                "createdAt": "2026-08-24T00:00:00Z",
                "updatedAt": "2026-08-24T00:00:00Z",
            },
        )
        thread = threading.Thread(target=writer)
        thread.start()
        backup_path = self.root / "backups" / "operations.sqlite3"
        repository.backup_to(backup_path)
        thread.join(30)
        self.assertTrue(writer_done.is_set())
        backup_factory = ConnectionFactory(backup_path)
        with backup_factory.connect() as backup:
            apply_migrations(backup)
            verify_database_integrity(backup)
            backup_revision = backup.execute(
                "SELECT revision FROM workspace_revisions WHERE workspace_id='operations'"
            ).fetchone()[0]
        self.assertLessEqual(backup_revision, repository.revision())
        with repository.connection_factory.connect() as reader:
            reader.execute("BEGIN")
            reader.execute("SELECT revision FROM workspace_revisions").fetchone()
            repository.replace_collection(
                "checkpoint.example",
                "observations",
                ({"type": "observation", "key": "held-reader-writer"},),
            )
            status = repository.checkpoint_status()
            self.assertEqual(status["state"], "blocked")
            self.assertLess(status["checkpointedFrames"], status["frames"])
            reader.rollback()
        completed_checkpoint = repository.checkpoint_status(manual=True)
        self.assertEqual(completed_checkpoint["state"], "completed")
        self.assertLessEqual(
            completed_checkpoint["checkpointedFrames"],
            completed_checkpoint["frames"],
        )

        short_wait = ActivatedWorkspaceRepository(
            "operations",
            repository.workspace_root,
            connection_factory=ConnectionFactory(repository.database_path, busy_timeout_ms=5),
        )
        with repository.connection_factory.connect() as held:
            held.begin_immediate()
            try:
                with self.assertRaises(StateBusyError) as busy:
                    short_wait.replace_collection(
                        "checkpoint.example",
                        "observations",
                        ({"type": "observation", "key": "busy"},),
                    )
            finally:
                held.rollback()
        self.assertTrue(busy.exception.retryable)
        self.assertEqual(busy.exception.reason_code, "state_busy_retryable")


if __name__ == "__main__":
    unittest.main()
