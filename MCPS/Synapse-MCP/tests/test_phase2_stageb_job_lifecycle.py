from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from helpers import isolated_state
from synapse_mcp.core import background_jobs, evidence, workspace


def _start_job(*, finalizer_name: str = "", command: str = "exit 0") -> dict:
    return background_jobs.start_command(
        ["sh", "-c", command],
        timeout_seconds=30,
        event_type="unit.phase2.job",
        summary="phase 2 lifecycle fixture",
        tool="unit.phase2.job",
        workspace_id="ws",
        target="example.test",
        finalizer_name=finalizer_name,
    )


class TransactionalJobLifecycleTests(unittest.TestCase):
    def test_status_does_not_steal_timeout_from_a_live_watchdog(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            workspace.create_workspace("ws", hosts=["example.test"])
            with patch.object(background_jobs, "_start_watchdog"):
                started = _start_job(command="sleep 30")
            job_id = started["jobId"]
            release = threading.Event()
            fake_watchdog = threading.Thread(target=lambda: release.wait(timeout=5))
            fake_watchdog.start()
            background_jobs._WATCHDOGS[job_id] = fake_watchdog
            try:
                record = background_jobs._read_record(job_id)
                record["startedAt"] = "2000-01-01T00:00:00Z"
                background_jobs._write_record(record)
                observed = background_jobs.status(job_id)
                self.assertEqual(observed["status"], "running")
                self.assertEqual(observed["error"], "")
            finally:
                release.set()
                fake_watchdog.join(timeout=3)
                background_jobs._WATCHDOGS.pop(job_id, None)
                record = background_jobs._read_record(job_id)
                record["startedAt"] = background_jobs._utc_now()
                background_jobs._write_record(record)
                background_jobs.cancel(job_id)

    def test_observer_cannot_recreate_returncode_after_watchdog_finalization(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            workspace.create_workspace("ws", hosts=["example.test"])
            original_status = background_jobs.status
            original_observation = background_jobs._process_observation
            release_watchdog = threading.Event()
            watchdog_done = threading.Event()
            observer_ready = threading.Event()
            release_observer = threading.Event()
            pause_observer = threading.Event()

            def controlled_status(*args, **kwargs):
                if threading.current_thread().name.startswith("synapse-job-watchdog-"):
                    self.assertTrue(release_watchdog.wait(timeout=5))
                    try:
                        return original_status(*args, **kwargs)
                    finally:
                        watchdog_done.set()
                return original_status(*args, **kwargs)

            def controlled_observation(record):
                observed = original_observation(record)
                if (
                    pause_observer.is_set()
                    and not threading.current_thread().name.startswith("synapse-job-watchdog-")
                    and observed["returnCode"] is not None
                ):
                    observer_ready.set()
                    self.assertTrue(release_observer.wait(timeout=5))
                return observed

            with patch.object(background_jobs, "status", side_effect=controlled_status), patch.object(
                background_jobs,
                "_process_observation",
                side_effect=controlled_observation,
            ):
                started = _start_job(command="sleep 1")
                job_id = started["jobId"]
                job_dir = background_jobs._find_record_path(job_id).parent
                background_jobs._PROCESSES[job_id].wait(timeout=3)
                pause_observer.set()
                result: list[dict] = []
                observer = threading.Thread(target=lambda: result.append(original_status(job_id)))
                observer.start()
                self.assertTrue(observer_ready.wait(timeout=3))
                release_watchdog.set()
                self.assertTrue(watchdog_done.wait(timeout=5))
                finalized = background_jobs.snapshot_record(job_id)
                self.assertTrue(finalized["finalized"])
                self.assertFalse((job_dir / "returncode.txt").exists())
                release_observer.set()
                observer.join(timeout=5)

            self.assertEqual(len(result), 1)
            self.assertTrue(result[0]["finalized"])
            self.assertFalse((job_dir / "stdout.txt").exists())
            self.assertFalse((job_dir / "stderr.txt").exists())
            self.assertFalse((job_dir / "returncode.txt").exists())

    def test_two_status_callers_share_one_reserved_finalization_and_cleanup(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            workspace.create_workspace("ws", hosts=["example.test"])
            entered = threading.Event()
            release = threading.Event()
            calls = 0

            def finalizer(_record, _run, _data):
                nonlocal calls
                calls += 1
                entered.set()
                self.assertTrue(release.wait(timeout=3))
                return {"summary": {"calls": calls}}

            name = "unit.phase2.status-race"
            background_jobs.register_finalizer(name, finalizer)
            try:
                with patch.object(background_jobs, "_start_watchdog"):
                    started = _start_job(finalizer_name=name, command="sleep 1")
                background_jobs._PROCESSES[started["jobId"]].wait(timeout=3)
                results: list[dict] = []
                failures: list[BaseException] = []

                def inspect() -> None:
                    try:
                        results.append(background_jobs.status(started["jobId"], include_result=True))
                    except BaseException as exc:
                        failures.append(exc)

                first = threading.Thread(target=inspect)
                second = threading.Thread(target=inspect)
                first.start()
                self.assertTrue(entered.wait(timeout=3))
                second.start()
                release.set()
                first.join(timeout=3)
                second.join(timeout=3)

                self.assertEqual(failures, [])
                self.assertEqual(calls, 1)
                self.assertEqual(len(results), 2)
                self.assertTrue(all(item["finalized"] for item in results))
                record = background_jobs._read_record(started["jobId"])
                self.assertEqual(record["finalization"]["state"], "applied")
                self.assertEqual(record["finalization"]["attempts"], 1)
                self.assertEqual(sorted(record["sidecarCleanup"]["removed"]), ["returncode.txt", "stderr.txt", "stdout.txt"])
            finally:
                background_jobs._FINALIZERS.pop(name, None)

    def test_cancel_reservation_prevents_status_from_finalizing_a_stale_snapshot(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            workspace.create_workspace("ws", hosts=["example.test"])
            finalizer_calls = 0
            terminate_entered = threading.Event()
            terminate_release = threading.Event()
            original_terminate = background_jobs._terminate_process_group

            def finalizer(_record, _run, _data):
                nonlocal finalizer_calls
                finalizer_calls += 1
                return {"summary": {"calls": finalizer_calls}}

            def controlled_terminate(pid: int) -> None:
                terminate_entered.set()
                self.assertTrue(terminate_release.wait(timeout=3))
                original_terminate(pid)

            name = "unit.phase2.cancel-status"
            background_jobs.register_finalizer(name, finalizer)
            try:
                started = _start_job(finalizer_name=name, command="sleep 30")
                cancel_result: list[dict] = []
                with patch.object(background_jobs, "_terminate_process_group", side_effect=controlled_terminate):
                    cancel_thread = threading.Thread(
                        target=lambda: cancel_result.append(background_jobs.cancel(started["jobId"]))
                    )
                    cancel_thread.start()
                    self.assertTrue(terminate_entered.wait(timeout=3))
                    observed = background_jobs.status(started["jobId"])
                    self.assertEqual(observed["status"], "running")
                    self.assertFalse(observed["finalized"])
                    terminate_release.set()
                    cancel_thread.join(timeout=5)

                terminal = background_jobs.status(started["jobId"])
                self.assertEqual(terminal["status"], "canceled")
                self.assertTrue(terminal["finalized"])
                self.assertEqual(finalizer_calls, 1)
                self.assertEqual(len(cancel_result), 1)
            finally:
                background_jobs._FINALIZERS.pop(name, None)

    def test_cancel_and_watchdog_reservations_linearize_to_one_terminal_transition(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            workspace.create_workspace("ws", hosts=["example.test"])
            calls = 0
            reservation_barrier = threading.Barrier(2)
            original_reserve = background_jobs._reserve_control

            def finalizer(_record, _run, _data):
                nonlocal calls
                calls += 1
                return {"summary": {"calls": calls}}

            def synchronized_reserve(job_id: str, kind: str):
                if kind in {"operator_cancel", "watchdog_timeout"}:
                    reservation_barrier.wait(timeout=3)
                return original_reserve(job_id, kind)

            name = "unit.phase2.cancel-watchdog"
            background_jobs.register_finalizer(name, finalizer)
            try:
                started = _start_job(finalizer_name=name, command="sleep 30")
                proc = background_jobs._PROCESSES[started["jobId"]]
                failures: list[BaseException] = []

                def run(callable_) -> None:
                    try:
                        callable_()
                    except BaseException as exc:
                        failures.append(exc)

                with patch.object(background_jobs, "_reserve_control", side_effect=synchronized_reserve):
                    cancel_thread = threading.Thread(target=lambda: run(lambda: background_jobs.cancel(started["jobId"])))
                    watchdog_thread = threading.Thread(
                        target=lambda: run(lambda: background_jobs._watch_process(started["jobId"], proc, 0))
                    )
                    cancel_thread.start()
                    watchdog_thread.start()
                    cancel_thread.join(timeout=6)
                    watchdog_thread.join(timeout=6)

                terminal = background_jobs.status(started["jobId"])
                self.assertEqual(failures, [])
                self.assertIn(terminal["status"], {"canceled", "timed_out"})
                self.assertTrue(terminal["finalized"])
                self.assertEqual(calls, 1)
                self.assertIsNone(background_jobs._read_record(started["jobId"])["controlReservation"])
            finally:
                background_jobs._FINALIZERS.pop(name, None)

    def test_list_refresh_and_direct_status_apply_one_finalizer(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            workspace.create_workspace("ws", hosts=["example.test"])
            calls = 0
            start_barrier = threading.Barrier(2)

            def finalizer(_record, _run, _data):
                nonlocal calls
                calls += 1
                return {"summary": {"calls": calls}}

            name = "unit.phase2.list-status"
            background_jobs.register_finalizer(name, finalizer)
            try:
                with patch.object(background_jobs, "_start_watchdog"):
                    started = _start_job(finalizer_name=name, command="sleep 1")
                background_jobs._PROCESSES[started["jobId"]].wait(timeout=3)
                failures: list[BaseException] = []

                def invoke(callable_) -> None:
                    try:
                        start_barrier.wait(timeout=3)
                        callable_()
                    except BaseException as exc:
                        failures.append(exc)

                threads = [
                    threading.Thread(target=lambda: invoke(lambda: background_jobs.status(started["jobId"]))),
                    threading.Thread(target=lambda: invoke(lambda: background_jobs.list_jobs(workspace_id="ws"))),
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=4)

                self.assertEqual(failures, [])
                self.assertEqual(calls, 1)
                self.assertTrue(background_jobs.status(started["jobId"])["finalized"])
            finally:
                background_jobs._FINALIZERS.pop(name, None)

    def test_stale_writer_cannot_overwrite_a_terminal_revision(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            workspace.create_workspace("ws", hosts=["example.test"])
            with patch.object(background_jobs, "_start_watchdog"):
                started = _start_job(command="sleep 1")
            stale = background_jobs.snapshot_record(started["jobId"])
            background_jobs._PROCESSES[started["jobId"]].wait(timeout=3)
            terminal = background_jobs.status(started["jobId"])
            stale["status"] = "canceled"
            with self.assertRaises(background_jobs.JobRevisionConflict):
                background_jobs._write_record(stale)
            current = background_jobs.status(started["jobId"])
            self.assertEqual(current["status"], terminal["status"])
            self.assertTrue(current["finalized"])

    def test_finalizer_failure_is_a_single_attempt_with_cleanup_and_reconciliation(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            workspace.create_workspace("ws", hosts=["example.test"])
            calls = 0

            def finalizer(_record, _run, _data):
                nonlocal calls
                calls += 1
                raise RuntimeError("deterministic finalizer failure")

            name = "unit.phase2.finalizer-failure"
            background_jobs.register_finalizer(name, finalizer)
            try:
                with patch.object(background_jobs, "_start_watchdog"):
                    started = _start_job(finalizer_name=name, command="sleep 1")
                background_jobs._PROCESSES[started["jobId"]].wait(timeout=3)
                first = background_jobs.status(started["jobId"])
                second = background_jobs.status(started["jobId"])
                background_jobs.list_jobs(workspace_id="ws")
                record = background_jobs._read_record(started["jobId"])

                self.assertEqual(first["status"], "failed")
                self.assertTrue(first["reconciliationRequired"])
                self.assertEqual(first["reconciliationReason"], "finalizer_application_failed")
                self.assertEqual(second["status"], "failed")
                self.assertEqual(calls, 1)
                self.assertEqual(record["finalization"]["attempts"], 1)
                self.assertEqual(record["finalization"]["state"], "failed")
                self.assertEqual(sorted(record["sidecarCleanup"]["removed"]), ["returncode.txt", "stderr.txt", "stdout.txt"])
                completion_events = [
                    item
                    for item in evidence.tail_events(20)
                    if item.get("data", {}).get("jobId") == started["jobId"]
                    and item.get("data", {}).get("finalizationToken")
                ]
                self.assertEqual(len(completion_events), 1)
            finally:
                background_jobs._FINALIZERS.pop(name, None)

    def test_interrupted_finalization_reservation_is_not_replayed(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            workspace.create_workspace("ws", hosts=["example.test"])
            calls = 0

            def finalizer(_record, _run, _data):
                nonlocal calls
                calls += 1
                return {"summary": {"calls": calls}}

            name = "unit.phase2.interrupted-finalizer"
            background_jobs.register_finalizer(name, finalizer)
            try:
                with patch.object(background_jobs, "_start_watchdog"):
                    started = _start_job(finalizer_name=name, command="sleep 1")
                background_jobs._PROCESSES[started["jobId"]].wait(timeout=3)
                record = background_jobs._read_record(started["jobId"])
                record["status"] = "completed"
                record["returnCode"] = 0
                record["completedAt"] = background_jobs._utc_now()
                record["finalization"] = {
                    "state": "applying",
                    "attempts": 1,
                    "token": "crashed-process-reservation",
                    "error": "",
                }
                background_jobs._write_record(record)

                reconciled = background_jobs.status(started["jobId"])
                repeated = background_jobs.status(started["jobId"])
                self.assertEqual(reconciled["status"], "failed")
                self.assertTrue(reconciled["reconciliationRequired"])
                self.assertEqual(reconciled["reconciliationReason"], "finalization_interrupted")
                self.assertEqual(repeated["status"], "failed")
                self.assertEqual(calls, 0)
            finally:
                background_jobs._FINALIZERS.pop(name, None)

    def test_legacy_job_without_sealed_plan_requires_adoption_instead_of_replay(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            workspace.create_workspace("ws", hosts=["example.test"])
            with patch.object(background_jobs, "_start_watchdog"):
                started = _start_job(command="sleep 1")
            background_jobs._PROCESSES[started["jobId"]].wait(timeout=3)
            record = background_jobs._read_record(started["jobId"])
            record.pop("executionPlan", None)
            background_jobs._write_record(record)

            rejected = background_jobs.status(started["jobId"])
            self.assertEqual(rejected["status"], "failed")
            self.assertTrue(rejected["reconciliationRequired"])
            self.assertEqual(rejected["reconciliationReason"], "legacy_job_adoption_required")

    def test_process_wait_is_never_called_while_workspace_lock_is_held(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            workspace.create_workspace("ws", hosts=["example.test"])
            with patch.object(background_jobs, "_start_watchdog"):
                started = _start_job(command="sleep 30")
            proc = background_jobs._PROCESSES[started["jobId"]]
            original_lock = workspace.workspace_lock
            original_wait = proc.wait
            state = threading.local()
            observed_waits = 0

            @contextmanager
            def tracked_lock(workspace_id: str, timeout_seconds: float | None = None):
                with original_lock(workspace_id, timeout_seconds):
                    state.depth = getattr(state, "depth", 0) + 1
                    try:
                        yield
                    finally:
                        state.depth -= 1

            def checked_wait(*args, **kwargs):
                nonlocal observed_waits
                observed_waits += 1
                self.assertEqual(getattr(state, "depth", 0), 0)
                return original_wait(*args, **kwargs)

            with patch.object(background_jobs.workspace, "workspace_lock", side_effect=tracked_lock), patch.object(
                proc,
                "wait",
                side_effect=checked_wait,
            ):
                canceled = background_jobs.cancel(started["jobId"])

            self.assertEqual(canceled["status"], "canceled")
            self.assertGreaterEqual(observed_waits, 1)

    def test_restart_cancel_never_signals_an_unauthenticated_persisted_pid(self) -> None:
        with TemporaryDirectory() as tmp, isolated_state(Path(tmp)):
            workspace.create_workspace("ws", hosts=["example.test"])
            finalizer_calls = 0

            def finalizer(_record, _run, _data):
                nonlocal finalizer_calls
                finalizer_calls += 1
                return None

            name = "unit.phase2.restart-cancel"
            background_jobs.register_finalizer(name, finalizer)
            try:
                with patch.object(background_jobs, "_start_watchdog"):
                    started = _start_job(finalizer_name=name, command="sleep 30")
                proc = background_jobs._PROCESSES.pop(started["jobId"])
                try:
                    with patch.object(
                        background_jobs,
                        "_terminate_process_group",
                        side_effect=AssertionError("persisted PID must not be signaled"),
                    ):
                        result = background_jobs.cancel(started["jobId"])
                    self.assertIsNone(proc.poll())
                finally:
                    background_jobs.terminate_process_group(proc.pid)
                    proc.wait(timeout=5)

                self.assertEqual(result["status"], "failed")
                self.assertTrue(result["finalized"])
                self.assertTrue(result["reconciliationRequired"])
                self.assertEqual(result["finalization"]["reasonCode"], "cancel_process_handle_unavailable")
                self.assertEqual(finalizer_calls, 0)
            finally:
                background_jobs._FINALIZERS.pop(name, None)


if __name__ == "__main__":
    unittest.main()
