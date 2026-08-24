"""Observed-effect regressions for the fixed Phase 3R no-network corpus."""

from __future__ import annotations

from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import httpx

from helpers import isolated_state
from synapse_mcp.app.actions import (
    ActionEffects,
    Idempotency,
    LocalWriteDomain,
    REGISTRY,
    TrafficDestination,
)
from synapse_mcp.core import background_jobs, credentials, evidence, scope, workspace
from synapse_mcp.transport import stdio_server


def _snapshot(root: Path) -> dict[Path, str]:
    values: dict[Path, str] = {}
    for path in root.rglob("*"):
        if path.is_file():
            values[path.resolve()] = sha256(path.read_bytes()).hexdigest()
    return values


class EffectObserver:
    """Instrument write/process/network/credential/job boundaries for one call."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.primitive_writes: list[Path] = []
        self.traffic: set[TrafficDestination] = set()
        self.subprocess_launches = 0
        self.credential_reads = 0
        self.job_controls = 0

    def observe(self, action_id: str, arguments: dict) -> ActionEffects:
        before = _snapshot(self.root)
        original_write_text = Path.write_text
        original_write_bytes = Path.write_bytes
        original_mkdir = Path.mkdir
        original_unlink = Path.unlink
        original_replace = os.replace

        def write_text(path: Path, *args, **kwargs):
            self.primitive_writes.append(path.expanduser().resolve(strict=False))
            return original_write_text(path, *args, **kwargs)

        def write_bytes(path: Path, *args, **kwargs):
            self.primitive_writes.append(path.expanduser().resolve(strict=False))
            return original_write_bytes(path, *args, **kwargs)

        def mkdir(path: Path, *args, **kwargs):
            self.primitive_writes.append(path.expanduser().resolve(strict=False))
            return original_mkdir(path, *args, **kwargs)

        def unlink(path: Path, *args, **kwargs):
            self.primitive_writes.append(path.expanduser().resolve(strict=False))
            return original_unlink(path, *args, **kwargs)

        def replace(source, destination, *args, **kwargs):
            self.primitive_writes.append(Path(destination).expanduser().resolve(strict=False))
            return original_replace(source, destination, *args, **kwargs)

        def network(*_args, **_kwargs):
            self.traffic.add(TrafficDestination.THIRD_PARTY)
            raise AssertionError(f"{action_id} attempted network traffic in the no-network corpus")

        def launch(*_args, **_kwargs):
            self.subprocess_launches += 1
            raise AssertionError(f"{action_id} attempted a subprocess in the no-network corpus")

        def credential(*_args, **_kwargs):
            self.credential_reads += 1
            raise AssertionError(f"{action_id} attempted credential access in the no-network corpus")

        def job_control(*_args, **_kwargs):
            self.job_controls += 1
            raise AssertionError(f"{action_id} attempted job control in the no-network corpus")

        with ExitStack() as stack:
            stack.enter_context(patch.object(Path, "write_text", new=write_text))
            stack.enter_context(patch.object(Path, "write_bytes", new=write_bytes))
            stack.enter_context(patch.object(Path, "mkdir", new=mkdir))
            stack.enter_context(patch.object(Path, "unlink", new=unlink))
            stack.enter_context(patch("os.replace", new=replace))
            stack.enter_context(patch.object(socket.socket, "connect", new=network))
            stack.enter_context(patch.object(httpx.Client, "send", new=network))
            stack.enter_context(patch.object(httpx.AsyncClient, "send", new=network))
            stack.enter_context(patch.object(subprocess, "Popen", new=launch))
            stack.enter_context(patch.object(credentials, "credential_for_target", new=credential))
            stack.enter_context(patch.object(background_jobs, "start_command", new=job_control))
            stack.enter_context(patch.object(background_jobs, "cancel", new=job_control))
            result = stdio_server.call_tool(action_id, arguments)
            self._assert_json_object(action_id, result)

        after = _snapshot(self.root)
        changed = {path for path, digest in after.items() if before.get(path) != digest}
        removed = set(before).difference(after)
        domains = {self._domain(path) for path in changed | removed}
        domains.discard(None)
        return ActionEffects(
            traffic=frozenset(self.traffic),
            local_writes=frozenset(domains),
            local_change=bool(changed or removed),
            local_destruction=bool(removed),
            credential_use=bool(self.credential_reads),
            secret_use=bool(self.credential_reads),
            replay_safety=Idempotency.IDEMPOTENT_WRITE if changed or removed else Idempotency.PURE_READ,
            resolution_notes=(
                f"filesystem_primitives={len(self.primitive_writes)}",
                f"subprocess_launches={self.subprocess_launches}",
                f"job_controls={self.job_controls}",
            ),
        )

    @staticmethod
    def _assert_json_object(action_id: str, result: str) -> None:
        parsed = json.loads(result)
        if not isinstance(parsed, dict):
            raise AssertionError(f"{action_id} did not return a JSON object")

    @staticmethod
    def _within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root.resolve())
        except ValueError:
            return False
        return True

    def _domain(self, path: Path) -> LocalWriteDomain | None:
        if self._within(path, credentials.CREDENTIALS_FILE.parent) and path == credentials.CREDENTIALS_FILE.resolve():
            return LocalWriteDomain.CREDENTIALS
        if self._within(path, evidence.EVIDENCE_DIR):
            return LocalWriteDomain.EVIDENCE
        if self._within(path, workspace.REPORTS_DIR):
            return LocalWriteDomain.REPORTS_ARTIFACTS
        if self._within(path, workspace.WORKSPACES_DIR):
            return LocalWriteDomain.WORKSPACE
        if path == scope.SCOPE_FILE.resolve():
            return LocalWriteDomain.RUNTIME_CONFIG
        return LocalWriteDomain.REPORTS_ARTIFACTS


class Phase3REffectObservationTests(unittest.TestCase):
    def test_fixed_no_network_corpus_stays_within_declared_maximum_effects(self) -> None:
        with TemporaryDirectory(prefix="synapse-phase3r-effects-") as temporary:
            root = Path(temporary)
            with isolated_state(root):
                workspace.create_workspace("effects", hosts=["app.example.test"])
                scope.save_scope(["app.example.test"])
                dump = root / "fixture-dump"
                request_dir = dump / "requests"
                response_dir = dump / "responses"
                request_dir.mkdir(parents=True)
                response_dir.mkdir()
                request = request_dir / "1.http"
                response = response_dir / "1.http"
                request.write_text(
                    "GET /app HTTP/1.1\r\nHost: app.example.test\r\n\r\n",
                    encoding="utf-8",
                )
                response.write_text(
                    "HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\nContent-Type: text/html\r\n\r\n<title>Fixture</title>",
                    encoding="utf-8",
                )
                (dump / "history.jsonl").write_text(
                    json.dumps(
                        {
                            "id": 1,
                            "host": "app.example.test",
                            "requestFile": str(request),
                            "responseFile": str(response),
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                corpus = (
                    ("workspace.summary", {"workspaceId": "effects"}),
                    (
                        "workspace.ingest_data",
                        {
                            "workspaceId": "effects",
                            "target": "app.example.test",
                            "source": "operator_note",
                            "dataType": "note",
                            "format": "json",
                            "rawData": "{}",
                            "metadata": {"profile": "nginx", "principal": "target-user"},
                        },
                    ),
                    (
                        "sitemap.from_dump",
                        {"dumpPath": str(dump), "workspaceId": "effects", "onlyInScope": False},
                    ),
                    (
                        "fingerprint.from_dump",
                        {"dumpPath": str(dump), "organization": "fixture-org"},
                    ),
                    ("cve.plan_tests", {"cveId": "CVE-2099-0001", "component": "fixture"}),
                    ("shodan.company_queries", {"company": "Fixture Company"}),
                    (
                        "documentation.render_workspace_report",
                        {"workspaceId": "effects", "outputPath": "phase3r-effects.html"},
                    ),
                )
                for action_id, arguments in corpus:
                    with self.subTest(action=action_id):
                        observer = EffectObserver(root)
                        observed = observer.observe(action_id, arguments)
                        declared = REGISTRY.get(action_id).effects
                        self.assertTrue(
                            declared.permits(observed),
                            f"{action_id} observed undeclared effects: observed={observed}, declared={declared}",
                        )
                        self.assertEqual(observer.traffic, set())
                        self.assertEqual(observer.subprocess_launches, 0)
                        self.assertEqual(observer.credential_reads, 0)
                        self.assertEqual(observer.job_controls, 0)

    def test_independently_reproduced_effect_corrections_are_explicit(self) -> None:
        sitemap = REGISTRY.get("sitemap.from_dump").effects
        self.assertFalse(sitemap.traffic)
        self.assertTrue(sitemap.local_change)
        self.assertEqual(
            sitemap.local_writes,
            frozenset(
                {
                    LocalWriteDomain.WORKSPACE,
                    LocalWriteDomain.EVIDENCE,
                    LocalWriteDomain.REPORTS_ARTIFACTS,
                }
            ),
        )
        self.assertIsNot(sitemap.replay_safety, Idempotency.PURE_READ)

        fingerprint = REGISTRY.get("fingerprint.from_dump").effects
        self.assertIn(LocalWriteDomain.EVIDENCE, fingerprint.local_writes)
        self.assertIn(LocalWriteDomain.REPORTS_ARTIFACTS, fingerprint.local_writes)

        for action_id in ("cve.plan_tests", "shodan.company_queries"):
            effects = REGISTRY.get(action_id).effects
            self.assertFalse(effects.traffic)
            self.assertFalse(effects.local_change)
            self.assertEqual(effects.replay_safety, Idempotency.PURE_READ)


if __name__ == "__main__":
    unittest.main()
