# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Deterministic JSON-v1 inventory, migration, verification, and cutover."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import base64
import fcntl
from hashlib import sha256
import json
import mimetypes
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Callable, Iterator, Mapping, Sequence

from .artifacts import ContentAddressedArtifactRepository, normalize_workspace_id
from .connections import immediate_transaction, verify_database_integrity
from .errors import ArtifactStoreError, StateConflictError, StateIntegrityError, StateSelectionError, StateStoreError
from .migrations import apply_migrations, schema_hash
from .selector import selected_store_version, selector_path
from .sqlite_store import SQLiteWorkspaceRepository


FORMAT_VERSION = 1
MIGRATION_STAGES = (
    "snapshot",
    "initialize",
    "engagement",
    "knowledge",
    "evidence_artifacts",
    "execution_authority",
    "verify",
)
_JSON_LIMIT = 64 * 1024 * 1024
_FIXED_TIME = "1970-01-01T00:00:00Z"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:@/-]+$")
_SENSITIVE_KEYS = {
    "authorization",
    "authorizationsessionid",
    "bearer",
    "cookie",
    "credentialbody",
    "credentialsecret",
    "encryptionkey",
    "idempotencykey",
    "opaquehandle",
    "password",
    "privatekey",
    "rawhandle",
    "requeststateid",
    "requeststatekey",
    "secret",
    "secretvalue",
    "sessioncookie",
    "stepupid",
    "token",
}
_SENSITIVE_BODY_PATTERNS = (
    re.compile(rb"(?i)\bAuthorization\s*:\s*[^\r\n]+"),
    re.compile(rb"(?i)\b(?:Set-)?Cookie\s*:\s*[^\r\n]+"),
    re.compile(rb"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{6,}"),
    re.compile(rb"(?i)\b(?:password|passwd|secret|access_token|refresh_token)\s*[=:]\s*[^\s&;,]+"),
)
_TABLE_STAGES = {
    "engagement": (
        "workspaces",
        "workspace_revisions",
        "change_log",
        "scope_snapshots",
        "targets",
    ),
    "knowledge": ("entities", "entity_relations", "findings", "review_events", "evidence"),
    "evidence_artifacts": ("artifacts", "evidence_artifacts"),
    "execution_authority": (
        "actions",
        "authority_grants",
        "authority_grant_revisions",
        "step_ups",
        "request_states",
        "budget_windows",
        "action_dispatches",
        "tasks",
        "task_events",
        "reconciliations",
        "audit_events",
        "id_mappings",
    ),
}
_PRIMARY_KEYS = {
    "workspaces": ("workspace_id",),
    "workspace_revisions": ("workspace_id",),
    "change_log": ("workspace_id", "revision", "sequence"),
    "scope_snapshots": ("scope_snapshot_id",),
    "targets": ("target_id",),
    "entities": ("entity_id",),
    "entity_relations": ("relation_id",),
    "findings": ("finding_id",),
    "review_events": ("review_event_id",),
    "evidence": ("evidence_id",),
    "artifacts": ("artifact_id",),
    "evidence_artifacts": ("workspace_id", "evidence_id", "artifact_id"),
    "actions": ("action_id",),
    "action_dispatches": ("dispatch_id",),
    "tasks": ("task_id",),
    "task_events": ("task_event_id",),
    "authority_grants": ("grant_id",),
    "authority_grant_revisions": ("workspace_id", "grant_id", "grant_revision"),
    "step_ups": ("step_up_id",),
    "request_states": ("request_state_id",),
    "budget_windows": ("budget_window_id",),
    "reconciliations": ("reconciliation_id",),
    "audit_events": ("event_id",),
    "migration_runs": ("migration_run_id",),
    "migration_orphans": ("migration_orphan_id",),
    "id_mappings": ("migration_run_id", "source_kind", "source_id"),
}


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def _json_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _file_digest(path: Path) -> tuple[str, int]:
    digest = sha256()
    size = 0
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise StateIntegrityError(
            "migration_source_unreadable",
            "A migration source could not be opened safely.",
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise StateIntegrityError("migration_source_not_regular", "Migration sources must be regular files.")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
            after = os.fstat(handle.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise StateIntegrityError("migration_source_changed", "A migration source changed while it was hashed.")
        return digest.hexdigest(), size
    except StateStoreError:
        raise
    except OSError as exc:
        raise StateIntegrityError(
            "migration_source_unreadable",
            "A migration source could not be read safely.",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _atomic_write(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    try:
        with temporary.open("xb") as handle:
            os.chmod(temporary, mode)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_json(path: Path) -> Any:
    try:
        if path.stat(follow_symlinks=False).st_size > _JSON_LIMIT:
            raise StateIntegrityError("migration_json_limit", "A migration JSON source exceeds the metadata limit.")
        return json.loads(path.read_text(encoding="utf-8"))
    except StateStoreError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StateIntegrityError("migration_json_invalid", f"Migration JSON is invalid: {path.name}") from exc


def _timestamp(value: Any, fallback: str = _FIXED_TIME) -> str:
    text = str(value or "").strip()
    return text if text else fallback


def _stable_id(prefix: str, *values: Any) -> str:
    digest = sha256("\x1f".join(str(value) for value in values).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:24]}"


def _safe_identifier(value: Any, fallback_prefix: str, *identity: Any) -> str:
    text = str(value or "").strip()
    if text and len(text.encode("utf-8")) <= 512 and _IDENTIFIER.fullmatch(text):
        return text
    return _stable_id(fallback_prefix, *identity, text)


def _sanitize(value: Any) -> Any:
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized in _SENSITIVE_KEYS or normalized.endswith(
                ("password", "secret", "token", "cookie", "encryptionkey", "privatekey")
            ):
                continue
            sanitized[str(key)] = _sanitize(item)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        redacted = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer <redacted>", value)
        redacted = re.sub(r"(?i)(?:^|\n)Cookie\s*:[^\r\n]*", "Cookie: <redacted>", redacted)
        redacted = re.sub(r"(?i)(?:^|\n)Authorization\s*:[^\r\n]*", "Authorization: <redacted>", redacted)
        return redacted
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def _body_contains_secret(path: Path) -> bool:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    pending = b""
    try:
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            while chunk := handle.read(1024 * 1024):
                candidate = pending + chunk
                if any(pattern.search(candidate) for pattern in _SENSITIVE_BODY_PATTERNS):
                    return True
                pending = candidate[-4096:]
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _payload_workspace_ids(value: Any) -> set[str]:
    if not isinstance(value, Mapping):
        return set()
    found = set()
    for key in ("workspaceId", "workspace_id"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            found.add(normalize_workspace_id(candidate))
    data = value.get("data")
    if isinstance(data, Mapping):
        found.update(_payload_workspace_ids(data))
    return found


def _source_kind(relative: str) -> str:
    path = Path(relative)
    parts = path.parts
    lowered = {part.lower() for part in parts}
    if lowered & {"credentials", "keyring", "browser-state", "sessions"}:
        return "excluded_secret"
    if relative == "workspace.json":
        return "workspace"
    if relative == "scope.json":
        return "scope"
    if len(parts) >= 3 and parts[0] == "targets" and path.name == "target.json":
        return "target"
    if len(parts) >= 4 and parts[0] == "targets" and parts[2] == "entities" and path.suffix == ".json":
        return "entity_collection"
    if len(parts) >= 4 and parts[0] == "targets" and parts[2] == "evidence" and path.name.startswith("ev_") and path.suffix == ".json":
        return "evidence_metadata"
    if len(parts) >= 3 and parts[0] == "jobs" and path.name == "job.json":
        return "job"
    if relative == "authority/state.json":
        return "authority"
    if path.suffix == ".jsonl":
        return "jsonl"
    if path.suffix == ".json":
        return "json_artifact"
    return "artifact"


@dataclass(frozen=True, slots=True)
class InventoryResult:
    workspace_id: str
    workspace_root: Path
    records: tuple[dict[str, Any], ...]
    orphans: tuple[dict[str, Any], ...]
    source_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": FORMAT_VERSION,
            "workspaceId": self.workspace_id,
            "sourceDigest": self.source_digest,
            "records": list(self.records),
            "orphans": list(self.orphans),
        }


class JsonV1Inventory:
    """Read-only authoritative-source inventory for one JSON-v1 workspace."""

    def __init__(self, data_root: Path) -> None:
        self.data_root = Path(data_root).resolve(strict=False)
        self.workspaces_root = self.data_root / "workspaces"

    def collect(self, workspace_id: str) -> InventoryResult:
        wid = normalize_workspace_id(workspace_id)
        root = self.workspaces_root / wid
        if not root.is_dir() or root.is_symlink():
            raise StateStoreError("migration_workspace_missing", f"JSON-v1 workspace does not exist: {wid}")
        records: list[dict[str, Any]] = []
        orphans: list[dict[str, Any]] = []
        def on_walk_error(error: OSError) -> None:
            reference = str(error.filename or root)
            try:
                reference = Path(reference).relative_to(root).as_posix()
            except ValueError:
                pass
            orphans.append(self._orphan("path", reference, "migration_source_unreadable", True))

        for current, directories, files in os.walk(
            root,
            topdown=True,
            onerror=on_walk_error,
            followlinks=False,
        ):
            directories[:] = sorted(item for item in directories if item != "state-v2")
            for directory in tuple(directories):
                candidate = Path(current) / directory
                if candidate.is_symlink():
                    relative = candidate.relative_to(root).as_posix()
                    orphans.append(self._orphan("path", relative, "symlink_forbidden", True))
                    directories.remove(directory)
            for filename in sorted(files):
                path = Path(current) / filename
                relative = path.relative_to(root).as_posix()
                if relative == ".lock":
                    continue
                try:
                    mode = path.lstat().st_mode
                    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                        orphans.append(self._orphan("path", relative, "non_regular_source", True))
                        continue
                    digest, size = _file_digest(path)
                    kind = _source_kind(relative)
                    identities: set[str] = set()
                    if kind not in {"artifact", "excluded_secret"} and path.suffix in {".json", ".jsonl"}:
                        if path.suffix == ".json":
                            try:
                                identities = _payload_workspace_ids(_read_json(path))
                            except StateStoreError as exc:
                                orphans.append(self._orphan(kind, relative, exc.reason_code, True))
                        else:
                            identities = self._jsonl_identities(path, relative, orphans)
                    if identities and identities != {wid}:
                        orphans.append(
                            self._orphan(kind, relative, "cross_workspace_contamination", True, {"workspaceIds": sorted(identities)})
                        )
                    records.append(
                        {
                            "digest": digest,
                            "kind": kind,
                            "path": relative,
                            "size": size,
                            "workspaceIds": sorted(identities),
                        }
                    )
                except StateStoreError as exc:
                    orphans.append(self._orphan("path", relative, exc.reason_code, True))
        external = self.data_root / "evidence" / "events.jsonl"
        if external.is_file() and not external.is_symlink():
            try:
                selected_lines, missing = self._external_evidence(external, wid)
            except (OSError, UnicodeError):
                selected_lines, missing = [], 0
                orphans.append(
                    self._orphan(
                        "evidence_log",
                        "@external/evidence/events.jsonl",
                        "migration_source_unreadable",
                        True,
                    )
                )
            if selected_lines:
                body = b"".join(selected_lines)
                records.append(
                    {
                        "digest": sha256(body).hexdigest(),
                        "kind": "evidence_log",
                        "path": "@external/evidence/events.jsonl",
                        "size": len(body),
                        "workspaceIds": [wid],
                    }
                )
            if missing:
                orphans.append(self._orphan("evidence_log", "@external/evidence/events.jsonl", "workspace_identity_missing", False, {"records": missing}))
        records.sort(key=lambda item: (item["kind"], item["path"]))
        orphans.sort(key=lambda item: (item["sourceKind"], item["sourceRef"], item["reasonCode"]))
        digest_value = canonical_digest(
            {
                "workspaceId": wid,
                "records": records,
                "blockingOrphans": [item for item in orphans if item["blocking"]],
            }
        )
        return InventoryResult(wid, root, tuple(records), tuple(orphans), digest_value)

    @staticmethod
    def _orphan(kind: str, reference: str, reason: str, blocking: bool, detail: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return {
            "blocking": blocking,
            "detail": dict(detail or {}),
            "reasonCode": reason,
            "sourceKind": kind,
            "sourceRef": reference,
        }

    @staticmethod
    def _jsonl_identities(path: Path, relative: str, orphans: list[dict[str, Any]]) -> set[str]:
        identities: set[str] = set()
        try:
            if path.stat(follow_symlinks=False).st_size > _JSON_LIMIT:
                orphans.append(JsonV1Inventory._orphan("jsonl", relative, "migration_json_limit", True))
                return identities
            with path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        identities.update(_payload_workspace_ids(json.loads(line)))
                    except json.JSONDecodeError:
                        orphans.append(JsonV1Inventory._orphan("jsonl", f"{relative}:{line_number}", "migration_json_invalid", True))
        except (OSError, UnicodeError):
            orphans.append(JsonV1Inventory._orphan("jsonl", relative, "migration_source_unreadable", True))
        return identities

    @staticmethod
    def _external_evidence(path: Path, workspace_id: str) -> tuple[list[bytes], int]:
        selected: list[bytes] = []
        missing = 0
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                identities = _payload_workspace_ids(payload)
                if identities == {workspace_id}:
                    selected.append(canonical_json_bytes(payload) + b"\n")
                elif not identities:
                    missing += 1
        selected.sort()
        return selected, missing


class WorkspaceFileLock:
    def __init__(self, workspace_root: Path, timeout_seconds: float = 5.0) -> None:
        self.workspace_root = Path(workspace_root)
        self.timeout_seconds = timeout_seconds

    @contextmanager
    def hold(self) -> Iterator[None]:
        self.workspace_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        deadline = time.monotonic() + self.timeout_seconds
        with (self.workspace_root / ".lock").open("a+", encoding="utf-8") as handle:
            while True:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise StateConflictError("workspace_lock_timeout", "Timed out waiting for the workspace lock.") from exc
                    time.sleep(0.05)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class StateMigrationService:
    """Versioned, restartable JSON-v1 to SQLite-v2 migration service."""

    def __init__(self, data_root: Path) -> None:
        self.data_root = Path(data_root).resolve(strict=False)
        self.workspaces_root = self.data_root / "workspaces"
        self.inventory_service = JsonV1Inventory(self.data_root)

    def inventory(self, workspace_id: str) -> dict[str, Any]:
        return self.inventory_service.collect(workspace_id).to_dict()

    def migrate(
        self,
        workspace_id: str,
        *,
        apply: bool,
        fault_injector: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        inventory = self.inventory_service.collect(workspace_id)
        if not apply:
            return {
                "dryRun": True,
                "inventory": inventory.to_dict(),
                "plannedStages": list(MIGRATION_STAGES),
                "wouldActivate": False,
            }
        if selected_store_version(inventory.workspace_root) == "sqlite-v2":
            raise StateConflictError("migration_already_active", "The SQLite-v2 store is already authoritative.")
        with WorkspaceFileLock(inventory.workspace_root).hold():
            locked_inventory = self.inventory_service.collect(workspace_id)
            if locked_inventory.source_digest != inventory.source_digest:
                raise StateConflictError("migration_source_changed", "JSON-v1 changed before the migration lock was acquired.")
            snapshot = self._ensure_snapshot(locked_inventory)
            run = self._ensure_run(locked_inventory, snapshot)
            self._inject_after_stage(run, "snapshot", fault_injector)
            plan = self._build_plan(locked_inventory, snapshot, run)
            repository = SQLiteWorkspaceRepository(locked_inventory.workspace_id, locked_inventory.workspace_root)
            for stage in MIGRATION_STAGES[1:]:
                if run["stages"].get(stage) == "completed":
                    continue
                if stage == "initialize":
                    self._initialize_stage(repository, run, plan)
                elif stage == "evidence_artifacts":
                    self._install_artifacts(repository, plan, run)
                    self._insert_stage(repository, run, plan, stage)
                elif stage == "verify":
                    report = self._verify_locked(repository, plan, run)
                    if not report["success"]:
                        self._write_run(run)
                        raise StateIntegrityError("migration_verification_failed", "State migration verification failed.")
                else:
                    self._insert_stage(repository, run, plan, stage)
                run["stages"][stage] = "completed"
                self._write_run(run)
                self._inject_after_stage(run, stage, fault_injector)
            return self.status(workspace_id)

    def verify(self, workspace_id: str) -> dict[str, Any]:
        inventory = self.inventory_service.collect(workspace_id)
        with WorkspaceFileLock(inventory.workspace_root).hold():
            run = self._load_run(inventory.workspace_root)
            snapshot = self._load_snapshot(inventory.workspace_root)
            plan = self._build_plan(inventory, snapshot, run)
            repository = SQLiteWorkspaceRepository(inventory.workspace_id, inventory.workspace_root)
            report = self._verify_locked(repository, plan, run)
            self._write_run(run)
            return report

    def activate(self, workspace_id: str) -> dict[str, Any]:
        inventory = self.inventory_service.collect(workspace_id)
        with WorkspaceFileLock(inventory.workspace_root).hold():
            run = self._load_run(inventory.workspace_root)
            if run.get("sourceDigest") != inventory.source_digest:
                raise StateConflictError("migration_source_changed", "JSON-v1 changed after migration; re-migration is required.")
            verification = run.get("verification")
            if not isinstance(verification, Mapping) or not verification.get("success"):
                raise StateSelectionError("migration_not_verified", "Activation requires successful migration verification.")
            if any(item.get("blocking") for item in run.get("orphans", [])):
                raise StateSelectionError("migration_blocking_orphans", "Activation is blocked by unresolved migration orphans.")
            repository = SQLiteWorkspaceRepository(inventory.workspace_id, inventory.workspace_root)
            revision = repository.revision()
            selector = {
                "activatedRevision": revision,
                "authoritativeStore": "sqlite-v2",
                "migrationRunId": run["runId"],
                "sourceManifestDigest": run["sourceDigest"],
                "version": 1,
            }
            run["activationRevision"] = revision
            run["activationPending"] = True
            self._write_run(run)
            _atomic_write(selector_path(inventory.workspace_root), canonical_json_bytes(selector) + b"\n")
            run["activated"] = True
            run["activationPending"] = False
            self._write_run(run)
            return self.status(workspace_id)

    def rollback(self, workspace_id: str) -> dict[str, Any]:
        wid = normalize_workspace_id(workspace_id)
        root = self.workspaces_root / wid
        with WorkspaceFileLock(root).hold():
            run = self._load_run(root)
            if selected_store_version(root) != "sqlite-v2":
                return self.status(wid)
            repository = SQLiteWorkspaceRepository(wid, root)
            current = repository.revision()
            activated = int(run.get("activationRevision") or 0)
            if current != activated:
                raise StateConflictError(
                    "rollback_v2_data_loss_risk",
                    "SQLite-v2 has advanced beyond activation; export and perform a forward migration instead.",
                )
            encoded = run.get("previousSelector")
            path = selector_path(root)
            if encoded is None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            else:
                _atomic_write(path, base64.b64decode(str(encoded)))
            run["activated"] = False
            run["rolledBack"] = True
            self._write_run(run)
            return self.status(wid)

    def status(self, workspace_id: str) -> dict[str, Any]:
        wid = normalize_workspace_id(workspace_id)
        root = self.workspaces_root / wid
        if not root.is_dir():
            raise StateStoreError("migration_workspace_missing", f"Workspace does not exist: {wid}")
        run_path = root / "state-v2" / "migration" / "run.json"
        run = _read_json(run_path) if run_path.is_file() else None
        revision = None
        database = root / "state-v2" / "state.sqlite3"
        if database.is_file():
            try:
                revision = SQLiteWorkspaceRepository(wid, root).revision()
            except StateStoreError:
                revision = None
        activation_revision = int(run.get("activationRevision") or 0) if isinstance(run, Mapping) else 0
        selected = selected_store_version(root)
        return {
            "activationRevision": activation_revision or None,
            "migrationRun": run,
            "revision": revision,
            "rollbackAllowed": selected == "sqlite-v2" and revision == activation_revision,
            "selectedStore": selected,
            "workspaceId": wid,
        }

    def _ensure_snapshot(self, inventory: InventoryResult) -> dict[str, Any]:
        snapshot_root = inventory.workspace_root / "state-v2" / "migration" / "pre-cutover"
        manifest_path = snapshot_root / "manifest.json"
        if manifest_path.is_file():
            manifest = _read_json(manifest_path)
            if manifest.get("sourceDigest") != inventory.source_digest:
                raise StateConflictError("migration_snapshot_conflict", "A pre-cutover snapshot exists for different source bytes.")
            self._verify_snapshot(snapshot_root, manifest)
            return manifest
        entries: list[dict[str, Any]] = []
        for record in inventory.records:
            relative = str(record["path"])
            entry = dict(record)
            if record["kind"] == "evidence_log":
                source = self.data_root / "evidence" / "events.jsonl"
                lines, _missing = self.inventory_service._external_evidence(source, inventory.workspace_id)
                destination = snapshot_root / "files" / "external" / "evidence.events.jsonl"
                _atomic_write(destination, b"".join(lines), mode=0o400)
                entry["snapshotPath"] = "external/evidence.events.jsonl"
            elif record["kind"] in {"artifact", "excluded_secret"}:
                entry["retainedPath"] = relative
            else:
                source = inventory.workspace_root / relative
                destination = snapshot_root / "files" / relative
                self._copy_exact(source, destination)
                os.chmod(destination, 0o400)
                entry["snapshotPath"] = relative
            entries.append(entry)
        selector = selector_path(inventory.workspace_root)
        previous_selector = base64.b64encode(selector.read_bytes()).decode("ascii") if selector.is_file() else None
        manifest = {
            "entries": entries,
            "formatVersion": FORMAT_VERSION,
            "previousSelector": previous_selector,
            "sourceDigest": inventory.source_digest,
            "workspaceId": inventory.workspace_id,
        }
        manifest["manifestDigest"] = canonical_digest(manifest)
        _atomic_write(manifest_path, canonical_json_bytes(manifest) + b"\n", mode=0o400)
        self._verify_snapshot(snapshot_root, manifest)
        return manifest

    @staticmethod
    def _copy_exact(source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = destination.parent / f".{destination.name}.{os.getpid()}.tmp"
        source_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            with os.fdopen(source_descriptor, "rb") as reader:
                source_descriptor = -1
                with temporary.open("xb") as writer:
                    os.chmod(temporary, 0o600)
                    while chunk := reader.read(1024 * 1024):
                        writer.write(chunk)
                    writer.flush()
                    os.fsync(writer.fileno())
            os.replace(temporary, destination)
            descriptor = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            if source_descriptor >= 0:
                os.close(source_descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _verify_snapshot(root: Path, manifest: Mapping[str, Any]) -> None:
        unsigned = dict(manifest)
        claimed = str(unsigned.pop("manifestDigest", ""))
        if canonical_digest(unsigned) != claimed:
            raise StateIntegrityError("migration_snapshot_manifest_mismatch", "Pre-cutover snapshot manifest was modified.")
        for entry in manifest.get("entries", []):
            snapshot_path = entry.get("snapshotPath")
            if not snapshot_path:
                continue
            path = root / "files" / str(snapshot_path)
            digest, size = _file_digest(path)
            if digest != entry["digest"] or size != int(entry["size"]):
                raise StateIntegrityError("migration_snapshot_content_mismatch", "Pre-cutover snapshot content was modified.")

    def _ensure_run(self, inventory: InventoryResult, snapshot: Mapping[str, Any]) -> dict[str, Any]:
        path = inventory.workspace_root / "state-v2" / "migration" / "run.json"
        if path.is_file():
            run = _read_json(path)
            if run.get("sourceDigest") != inventory.source_digest:
                raise StateConflictError("migration_run_conflict", "A migration run exists for different JSON-v1 bytes.")
            return run
        run = {
            "activated": False,
            "formatVersion": FORMAT_VERSION,
            "orphans": list(inventory.orphans),
            "previousSelector": snapshot.get("previousSelector"),
            "runId": _stable_id("migration", inventory.workspace_id, inventory.source_digest),
            "sourceDigest": inventory.source_digest,
            "stages": {stage: ("completed" if stage == "snapshot" else "pending") for stage in MIGRATION_STAGES},
            "workspaceId": inventory.workspace_id,
        }
        self._write_run(run, inventory.workspace_root)
        return run

    def _load_run(self, workspace_root: Path) -> dict[str, Any]:
        path = workspace_root / "state-v2" / "migration" / "run.json"
        if not path.is_file():
            raise StateStoreError("migration_run_missing", "No applied migration run exists for this workspace.")
        value = _read_json(path)
        if not isinstance(value, dict) or value.get("formatVersion") != FORMAT_VERSION:
            raise StateIntegrityError("migration_run_invalid", "Migration run manifest is invalid.")
        return value

    def _load_snapshot(self, workspace_root: Path) -> dict[str, Any]:
        path = workspace_root / "state-v2" / "migration" / "pre-cutover" / "manifest.json"
        if not path.is_file():
            raise StateStoreError("migration_snapshot_missing", "No pre-cutover snapshot exists.")
        value = _read_json(path)
        self._verify_snapshot(path.parent, value)
        return value

    def _write_run(self, run: Mapping[str, Any], workspace_root: Path | None = None) -> None:
        root = workspace_root or self.workspaces_root / str(run["workspaceId"])
        _atomic_write(root / "state-v2" / "migration" / "run.json", canonical_json_bytes(run) + b"\n")

    @staticmethod
    def _inject_after_stage(run: Mapping[str, Any], stage: str, injector: Callable[[str], None] | None) -> None:
        if injector is not None and run.get("stages", {}).get(stage) == "completed":
            injector(stage)

    def _snapshot_json(self, inventory: InventoryResult, snapshot: Mapping[str, Any], relative: str) -> Any:
        entry = next((item for item in snapshot["entries"] if item["path"] == relative), None)
        if entry is None or not entry.get("snapshotPath"):
            raise StateIntegrityError("migration_snapshot_source_missing", f"Snapshot source is missing: {relative}")
        return _read_json(inventory.workspace_root / "state-v2" / "migration" / "pre-cutover" / "files" / entry["snapshotPath"])

    def _build_plan(self, inventory: InventoryResult, snapshot: Mapping[str, Any], run: dict[str, Any]) -> dict[str, Any]:
        wid = inventory.workspace_id
        rows: dict[str, list[dict[str, Any]]] = {table: [] for tables in _TABLE_STAGES.values() for table in tables}
        mappings: list[dict[str, Any]] = []
        workspace_value = self._snapshot_json(inventory, snapshot, "workspace.json")
        if not isinstance(workspace_value, Mapping):
            raise StateIntegrityError("migration_workspace_invalid", "workspace.json must contain an object.")
        created = _timestamp(workspace_value.get("createdAt"))
        updated = _timestamp(workspace_value.get("updatedAt"), created)
        rows["workspaces"].append(
            {
                "workspace_id": wid,
                "organization": str(workspace_value.get("organization") or ""),
                "notes": str(_sanitize(workspace_value.get("notes") or "")),
                "created_at": created,
                "updated_at": updated,
            }
        )
        rows["workspace_revisions"].append({"workspace_id": wid, "revision": 1, "updated_at": updated})
        rows["change_log"].append(
            {
                "workspace_id": wid,
                "revision": 1,
                "sequence": 0,
                "entity_type": "migration",
                "entity_id": str(run["runId"]),
                "change_kind": "create",
                "payload_json": _json_text({"sourceDigest": inventory.source_digest}),
                "created_at": updated,
            }
        )
        scope_entry = next((item for item in snapshot["entries"] if item["kind"] == "scope"), None)
        if scope_entry:
            scope_value = self._snapshot_json(inventory, snapshot, str(scope_entry["path"]))
            scope_payload = _sanitize(scope_value)
            scope_digest = canonical_digest(scope_payload)
            rows["scope_snapshots"].append(
                {
                    "scope_snapshot_id": f"scope-{scope_digest[:24]}",
                    "workspace_id": wid,
                    "digest": scope_digest,
                    "payload_json": _json_text(scope_payload),
                    "created_revision": 1,
                    "created_at": _timestamp(scope_value.get("updatedAt") if isinstance(scope_value, Mapping) else None, updated),
                }
            )
        target_ids: dict[str, str] = {}
        for entry in sorted((item for item in snapshot["entries"] if item["kind"] == "target"), key=lambda item: item["path"]):
            value = self._snapshot_json(inventory, snapshot, str(entry["path"]))
            if not isinstance(value, Mapping):
                self._add_orphan(run, "target", str(entry["path"]), "target_record_invalid", True)
                continue
            natural = str(value.get("target") or Path(str(entry["path"])).parts[1])
            raw_target_id = str(value.get("targetId") or "")
            target_id = _safe_identifier(raw_target_id, "target", wid, natural)
            target_ids[Path(str(entry["path"])).parts[1]] = target_id
            if raw_target_id != target_id:
                mappings.append(self._mapping(run, "target", raw_target_id or natural, "target", target_id))
            elif not raw_target_id:
                mappings.append(self._mapping(run, "target", natural, "target", target_id))
            rows["targets"].append(
                {
                    "target_id": target_id,
                    "workspace_id": wid,
                    "natural_key": natural,
                    "kind": str(value.get("kind") or "host"),
                    "payload_json": _json_text(_sanitize(value)),
                    "created_revision": 1,
                    "updated_revision": 1,
                    "created_at": _timestamp(value.get("createdAt"), created),
                    "updated_at": _timestamp(value.get("updatedAt"), updated),
                }
            )
        entity_ids: set[str] = set()
        entity_refs: dict[str, str] = {}
        pending_relations: list[tuple[str, Mapping[str, Any], str]] = []
        finding_ids: set[str] = set()
        evidence_ids: set[str] = set()
        evidence_raw: dict[str, str] = {}
        action_values: list[tuple[Mapping[str, Any], str]] = []
        collection_types = {
            "services.json": "service",
            "endpoints.json": "endpoint",
            "parameters.json": "parameter",
            "observations.json": "observation",
            "pretext-candidates.json": "pretext_candidate",
            "detection-gaps.json": "detection_gap",
        }
        for entry in sorted((item for item in snapshot["entries"] if item["kind"] == "entity_collection"), key=lambda item: item["path"]):
            values = self._snapshot_json(inventory, snapshot, str(entry["path"]))
            if not isinstance(values, list):
                self._add_orphan(run, "entity_collection", str(entry["path"]), "entity_collection_invalid", True)
                continue
            parts = Path(str(entry["path"])).parts
            target_id = target_ids.get(parts[1])
            filename = Path(str(entry["path"])).name
            if filename == "findings.json":
                for index, item in enumerate(values):
                    if not isinstance(item, Mapping):
                        continue
                    natural = str(item.get("key") or item.get("id") or canonical_digest(_sanitize(item)))
                    raw_finding_id = str(item.get("id") or "")
                    finding_id = _safe_identifier(raw_finding_id, "finding", wid, natural)
                    if finding_id in finding_ids:
                        self._add_orphan(run, "finding", f"{entry['path']}:{index}", "duplicate_identity", True)
                        continue
                    finding_ids.add(finding_id)
                    if raw_finding_id and raw_finding_id != finding_id:
                        mappings.append(self._mapping(run, "finding", raw_finding_id, "finding", finding_id))
                    item_created = _timestamp(item.get("createdAt"), created)
                    item_updated = _timestamp(item.get("updatedAt"), item_created)
                    rows["findings"].append(
                        {
                            "finding_id": finding_id,
                            "workspace_id": wid,
                            "target_id": target_id,
                            "natural_key": natural,
                            "status": str(item.get("status") or "candidate"),
                            "severity": str(item.get("severity") or "info"),
                            "operator_reviewed": int(bool(item.get("operatorReviewed"))),
                            "payload_json": _json_text(_sanitize(item)),
                            "created_revision": 1,
                            "updated_revision": 1,
                            "created_at": item_created,
                            "updated_at": item_updated,
                        }
                    )
                    if item.get("operatorReviewed"):
                        review_id = _stable_id("review", wid, finding_id, item_updated)
                        rows["review_events"].append(
                            {
                                "review_event_id": review_id,
                                "workspace_id": wid,
                                "finding_id": finding_id,
                                "decision": str(item.get("status") or "reviewed"),
                                "reviewer_ref": str(item.get("reviewedBy") or "legacy-operator"),
                                "payload_json": _json_text({"source": "json-v1"}),
                                "created_revision": 1,
                                "created_at": item_updated,
                            }
                        )
                continue
            if filename == "actions.json":
                action_values.extend((item, str(entry["path"])) for item in values if isinstance(item, Mapping))
                continue
            entity_type = collection_types.get(filename, Path(filename).stem)
            for index, item in enumerate(values):
                if not isinstance(item, Mapping):
                    continue
                natural = str(item.get("key") or item.get("id") or canonical_digest(_sanitize(item)))
                raw_entity_id = str(item.get("entityId") or item.get("id") or "")
                entity_id = _safe_identifier(raw_entity_id, "entity", wid, entity_type, natural)
                if entity_id in entity_ids:
                    self._add_orphan(run, entity_type, f"{entry['path']}:{index}", "duplicate_identity", True)
                    continue
                entity_ids.add(entity_id)
                if raw_entity_id and raw_entity_id != entity_id:
                    mappings.append(self._mapping(run, "entity", raw_entity_id, "entity", entity_id))
                for reference in (item.get("entityId"), item.get("id"), item.get("key"), natural):
                    if reference:
                        entity_refs[str(reference)] = entity_id
                relation_values = item.get("relations")
                if isinstance(relation_values, list):
                    pending_relations.extend(
                        (entity_id, relation, f"{entry['path']}:{index}")
                        for relation in relation_values
                        if isinstance(relation, Mapping)
                    )
                item_created = _timestamp(item.get("createdAt"), created)
                rows["entities"].append(
                    {
                        "entity_id": entity_id,
                        "workspace_id": wid,
                        "target_id": target_id,
                        "entity_type": str(item.get("type") or entity_type),
                        "natural_key": natural,
                        "lifecycle": str(item.get("status") or "observed"),
                        "payload_json": _json_text(_sanitize(item)),
                        "created_revision": 1,
                        "updated_revision": 1,
                        "created_at": item_created,
                        "updated_at": _timestamp(item.get("updatedAt"), item_created),
                    }
                )
        for source_entity_id, relation, source_ref in pending_relations:
            requested_target = str(relation.get("targetEntityId") or relation.get("targetId") or "")
            target_entity_id = entity_refs.get(requested_target)
            relation_type = str(relation.get("type") or relation.get("relationType") or "")
            if target_entity_id is None or not relation_type:
                self._add_orphan(run, "entity_relation", source_ref, "relation_endpoint_missing", True)
                continue
            relation_id = _safe_identifier(
                relation.get("relationId"),
                "relation",
                wid,
                source_entity_id,
                target_entity_id,
                relation_type,
            )
            rows["entity_relations"].append(
                {
                    "relation_id": relation_id,
                    "workspace_id": wid,
                    "source_entity_id": source_entity_id,
                    "target_entity_id": target_entity_id,
                    "relation_type": relation_type,
                    "payload_json": _json_text(_sanitize(relation)),
                    "created_revision": 1,
                    "created_at": created,
                }
            )
        for entry in sorted((item for item in snapshot["entries"] if item["kind"] == "evidence_metadata"), key=lambda item: item["path"]):
            value = self._snapshot_json(inventory, snapshot, str(entry["path"]))
            if not isinstance(value, Mapping):
                continue
            raw_evidence_id = str(value.get("evidenceId") or "")
            evidence_id = _safe_identifier(raw_evidence_id, "evidence", wid, entry["path"])
            if evidence_id in evidence_ids:
                self._add_orphan(run, "evidence", str(entry["path"]), "duplicate_identity", True)
                continue
            evidence_ids.add(evidence_id)
            if raw_evidence_id and raw_evidence_id != evidence_id:
                mappings.append(self._mapping(run, "evidence", raw_evidence_id, "evidence", evidence_id))
            parts = Path(str(entry["path"])).parts
            raw_value = str(value.get("rawPath") or "")
            evidence_raw[evidence_id] = self._normalize_raw_reference(inventory.workspace_root, str(entry["path"]), raw_value)
            safe = dict(_sanitize(value))
            safe.pop("rawPath", None)
            rows["evidence"].append(
                {
                    "evidence_id": evidence_id,
                    "workspace_id": wid,
                    "target_id": target_ids.get(parts[1]),
                    "summary": f"{value.get('source', 'legacy')} {value.get('dataType', 'evidence')}",
                    "payload_json": _json_text(safe),
                    "created_revision": 1,
                    "created_at": _timestamp(value.get("createdAt"), created),
                }
            )
        evidence_log = next((item for item in snapshot["entries"] if item["kind"] == "evidence_log"), None)
        if evidence_log:
            path = inventory.workspace_root / "state-v2" / "migration" / "pre-cutover" / "files" / evidence_log["snapshotPath"]
            with path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    event = json.loads(line)
                    event_id = _safe_identifier(event.get("eventId"), "evidence-event", wid, line_number, canonical_digest(event))
                    if event_id in evidence_ids:
                        event_id = _stable_id("evidence-event", wid, event_id, line_number)
                    evidence_ids.add(event_id)
                    rows["evidence"].append(
                        {
                            "evidence_id": event_id,
                            "workspace_id": wid,
                            "target_id": None,
                            "summary": str(
                                _sanitize(
                                    event.get("summary")
                                    or event.get("type")
                                    or "Legacy evidence event"
                                )
                            ),
                            "payload_json": _json_text(_sanitize(event)),
                            "created_revision": 1,
                            "created_at": _timestamp(event.get("createdAt"), created),
                        }
                    )
        artifact_sources: dict[str, str] = {}
        for entry in sorted(snapshot["entries"], key=lambda item: item["path"]):
            if entry["kind"] not in {"artifact", "json_artifact"}:
                continue
            digest = str(entry["digest"])
            artifact_id = f"sha256:{digest}"
            source_path = str(entry.get("snapshotPath") or entry.get("retainedPath"))
            artifact_sources.setdefault(artifact_id, source_path)
            if any(row["artifact_id"] == artifact_id for row in rows["artifacts"]):
                continue
            rows["artifacts"].append(
                {
                    "artifact_id": artifact_id,
                    "workspace_id": wid,
                    "digest": digest,
                    "size": int(entry["size"]),
                    "media_type": mimetypes.guess_type(str(entry["path"]))[0] or "application/octet-stream",
                    "origin": f"json-v1:{entry['path']}",
                    "creator_action_id": None,
                    "creator_dispatch_id": None,
                    "created_revision": 1,
                    "created_at": updated,
                }
            )
        path_to_artifact = {
            str(entry["path"]): f"sha256:{entry['digest']}"
            for entry in snapshot["entries"]
            if entry["kind"] in {"artifact", "json_artifact"}
        }
        for evidence_id, relative in sorted(evidence_raw.items()):
            artifact_id = path_to_artifact.get(relative)
            if artifact_id:
                rows["evidence_artifacts"].append(
                    {"workspace_id": wid, "evidence_id": evidence_id, "artifact_id": artifact_id, "created_revision": 1}
                )
        rejected_artifacts = set(run.get("rejectedArtifactIds", []))
        if rejected_artifacts:
            rows["artifacts"] = [
                row for row in rows["artifacts"] if row["artifact_id"] not in rejected_artifacts
            ]
            rows["evidence_artifacts"] = [
                row
                for row in rows["evidence_artifacts"]
                if row["artifact_id"] not in rejected_artifacts
            ]
        authority_entry = next((item for item in snapshot["entries"] if item["kind"] == "authority"), None)
        authority = self._snapshot_json(inventory, snapshot, str(authority_entry["path"])) if authority_entry else {}
        self._authority_rows(wid, authority, rows, mappings, action_values, run, created, updated)
        self._job_rows(inventory, snapshot, rows, action_values, mappings, run, created, updated)
        self._action_rows(wid, rows, action_values, mappings, run, created, updated)
        rows["audit_events"].append(
            {
                "event_id": _stable_id("audit", wid, run["runId"]),
                "workspace_id": wid,
                "revision": 1,
                "event_type": "migration.json_v1_import",
                "summary": "Imported deterministic JSON-v1 baseline.",
                "actor_ref": "operator:migration",
                "payload_json": _json_text({"sourceDigest": inventory.source_digest}),
                "created_at": updated,
            }
        )
        rows["id_mappings"].extend(mappings)
        for table in rows:
            rows[table].sort(key=lambda row: tuple(row.get(key) for key in _PRIMARY_KEYS[table]))
        return {
            "artifactSources": artifact_sources,
            "authorityRepositoryRevision": (
                int(authority.get("revision") or 0)
                if isinstance(authority, Mapping)
                else 0
            ),
            "rows": rows,
            "scopeDigest": (
                rows["scope_snapshots"][0]["digest"]
                if rows["scope_snapshots"]
                else ""
            ),
        }

    @staticmethod
    def _normalize_raw_reference(workspace_root: Path, metadata_relative: str, raw_value: str) -> str:
        if raw_value:
            candidate = Path(raw_value)
            if candidate.is_absolute():
                try:
                    return candidate.resolve(strict=False).relative_to(workspace_root.resolve(strict=False)).as_posix()
                except ValueError:
                    return ""
            normalized = Path(raw_value)
            if ".." not in normalized.parts:
                return normalized.as_posix()
        metadata = Path(metadata_relative)
        stem = metadata.stem
        parent = metadata.parent
        matches = sorted(path.as_posix() for path in parent.glob(f"{stem}_raw.*"))
        return matches[0] if matches else ""

    @staticmethod
    def _mapping(run: Mapping[str, Any], source_kind: str, source_id: str, target_kind: str, target_id: str, *, opaque: bool = False) -> dict[str, Any]:
        safe_source = f"sha256:{sha256(source_id.encode('utf-8')).hexdigest()}" if opaque else source_id
        return {
            "migration_run_id": run["runId"],
            "source_kind": source_kind,
            "source_id": safe_source,
            "target_kind": target_kind,
            "target_id": target_id,
        }

    @staticmethod
    def _add_orphan(run: dict[str, Any], kind: str, reference: str, reason: str, blocking: bool, detail: Mapping[str, Any] | None = None) -> None:
        item = JsonV1Inventory._orphan(kind, reference, reason, blocking, detail)
        if item not in run["orphans"]:
            run["orphans"].append(item)
            run["orphans"].sort(key=lambda value: (value["sourceKind"], value["sourceRef"], value["reasonCode"]))

    def _authority_rows(
        self,
        wid: str,
        value: Any,
        rows: dict[str, list[dict[str, Any]]],
        mappings: list[dict[str, Any]],
        actions: list[tuple[Mapping[str, Any], str]],
        run: dict[str, Any],
        created: str,
        updated: str,
    ) -> None:
        if not isinstance(value, Mapping):
            return
        grants = value.get("grants") if isinstance(value.get("grants"), Mapping) else {}
        for grant_id, entry in sorted(grants.items()):
            if not isinstance(entry, Mapping) or not isinstance(entry.get("revisions"), Mapping):
                self._add_orphan(run, "authority_grant", str(grant_id), "grant_record_invalid", True)
                continue
            current = int(entry.get("currentRevision") or 0)
            revisions = entry["revisions"]
            current_value = revisions.get(str(current))
            if current < 1 or not isinstance(current_value, Mapping):
                self._add_orphan(run, "authority_grant", str(grant_id), "grant_revision_missing", True)
                continue
            safe_grant_id = _safe_identifier(grant_id, "grant", wid, grant_id)
            if safe_grant_id != str(grant_id):
                mappings.append(self._mapping(run, "authority_grant", str(grant_id), "authority_grant", safe_grant_id))
            grant_created = _timestamp(current_value.get("createdAt"), created)
            revoked = bool(current_value.get("revokedAt"))
            rows["authority_grants"].append(
                {
                    "grant_id": safe_grant_id,
                    "workspace_id": wid,
                    "current_revision": current,
                    "state": "revoked" if revoked else "active",
                    "expires_at": _timestamp(current_value.get("expiresAt"), _FIXED_TIME),
                    "created_revision": 1,
                    "updated_revision": 1,
                    "created_at": grant_created,
                    "updated_at": _timestamp(current_value.get("revokedAt"), grant_created),
                }
            )
            for revision_key, revision_value in sorted(revisions.items(), key=lambda item: int(item[0])):
                if not isinstance(revision_value, Mapping):
                    continue
                rows["authority_grant_revisions"].append(
                    {
                        "workspace_id": wid,
                        "grant_id": safe_grant_id,
                        "grant_revision": int(revision_key),
                        "policy_json": _json_text(_sanitize(revision_value)),
                        "created_revision": 1,
                        "created_at": _timestamp(revision_value.get("createdAt"), grant_created),
                    }
                )
        action_ids: set[str] = set()

        def ensure_action(raw: Any, name: str = "legacy.authority_action") -> str | None:
            text = str(raw or "").strip()
            if not text:
                return None
            action_id = _safe_identifier(text, "action", wid, text)
            if action_id not in action_ids:
                if action_id != text:
                    mappings.append(self._mapping(run, "action", text, "action", action_id))
                actions.append(({"actionId": action_id, "tool": name, "status": "imported"}, "authority/state.json"))
                action_ids.add(action_id)
            return action_id

        request_mapping: dict[str, str] = {}
        request_states = value.get("requestStates") if isinstance(value.get("requestStates"), Mapping) else {}
        for raw_id, item in sorted(request_states.items()):
            if not isinstance(item, Mapping):
                continue
            target_id = _stable_id("request-state", wid, sha256(str(raw_id).encode("utf-8")).hexdigest())
            request_mapping[str(raw_id)] = target_id
            mappings.append(self._mapping(run, "request_state", str(raw_id), "request_state", target_id, opaque=True))
            grant_id = str(item.get("grantId") or "") or None
            if grant_id and not any(row["grant_id"] == grant_id for row in rows["authority_grants"]):
                grant_id = None
            action_id = ensure_action(item.get("actionId"))
            item_created = _timestamp(item.get("createdAt"), created)
            rows["request_states"].append(
                {
                    "request_state_id": target_id,
                    "workspace_id": wid,
                    "action_id": action_id,
                    "grant_id": grant_id,
                    "opaque_state_ref": f"sha256:{sha256(str(raw_id).encode('utf-8')).hexdigest()}",
                    "state": str(item.get("status") or "pending"),
                    "expires_at": _timestamp(item.get("expiresAt"), _FIXED_TIME),
                    "created_revision": 1,
                    "updated_revision": 1,
                    "created_at": item_created,
                    "updated_at": _timestamp(item.get("lastEvaluatedAt") or item.get("consumedAt"), item_created),
                }
            )
        step_up_mapping: dict[str, str] = {}
        step_ups = value.get("stepUps") if isinstance(value.get("stepUps"), Mapping) else {}
        for raw_id, item in sorted(step_ups.items()):
            if not isinstance(item, Mapping):
                continue
            grant_id = str(item.get("grantId") or "")
            grant_revision = int(item.get("grantRevision") or 0)
            if not any(row["grant_id"] == grant_id and row["grant_revision"] == grant_revision for row in rows["authority_grant_revisions"]):
                self._add_orphan(run, "step_up", f"sha256:{sha256(str(raw_id).encode()).hexdigest()}", "grant_revision_missing", True)
                continue
            target_id = _stable_id("step-up", wid, sha256(str(raw_id).encode("utf-8")).hexdigest())
            step_up_mapping[str(raw_id)] = target_id
            mappings.append(self._mapping(run, "step_up", str(raw_id), "step_up", target_id, opaque=True))
            rows["step_ups"].append(
                {
                    "step_up_id": target_id,
                    "workspace_id": wid,
                    "grant_id": grant_id,
                    "grant_revision": grant_revision,
                    "authorization_fingerprint": str(item.get("authorizationFingerprint") or ""),
                    "approved_by_ref": str(item.get("approvedBy") or "legacy-operator"),
                    "expires_at": _timestamp(item.get("expiresAt"), _FIXED_TIME),
                    "consumed_at": item.get("consumedAt") or None,
                    "created_revision": 1,
                    "created_at": _timestamp(item.get("createdAt"), created),
                }
            )
        budgets = value.get("budgetWindows") if isinstance(value.get("budgetWindows"), Mapping) else {}
        for grant_id, item in sorted(budgets.items()):
            if not isinstance(item, Mapping) or not any(row["grant_id"] == grant_id for row in rows["authority_grants"]):
                continue
            window_start = _timestamp(item.get("windowStartedAt"), created)
            for dimension, field, reserved in (
                ("dispatch_total", "dispatchesUsed", False),
                ("dispatch_window", "dispatchWindowUsed", False),
                ("active_dispatch", "activeDispatches", True),
            ):
                amount = max(int(item.get(field) or 0), 0)
                rows["budget_windows"].append(
                    {
                        "budget_window_id": _stable_id("budget", wid, grant_id, dimension, window_start),
                        "workspace_id": wid,
                        "grant_id": grant_id,
                        "dimension": dimension,
                        "window_start": window_start,
                        "window_end": _timestamp(item.get("windowEndsAt"), "9999-12-31T23:59:59Z"),
                        "reserved": amount if reserved else 0,
                        "consumed": 0 if reserved else amount,
                        "created_revision": 1,
                        "updated_revision": 1,
                    }
                )
        dispatches = value.get("dispatches") if isinstance(value.get("dispatches"), Mapping) else {}
        valid_dispatches: set[str] = set()
        for dispatch_id, item in sorted(dispatches.items()):
            if not isinstance(item, Mapping):
                continue
            action_id = ensure_action(item.get("actionId"))
            if action_id is None:
                self._add_orphan(run, "dispatch", str(dispatch_id), "action_identity_missing", True)
                continue
            grant_id = str(item.get("grantId") or "") or None
            if grant_id and not any(row["grant_id"] == grant_id for row in rows["authority_grants"]):
                self._add_orphan(run, "dispatch", str(dispatch_id), "grant_identity_missing", True)
                grant_id = None
            safe_dispatch = _safe_identifier(dispatch_id, "dispatch", wid, dispatch_id)
            if safe_dispatch != str(dispatch_id):
                mappings.append(self._mapping(run, "dispatch", str(dispatch_id), "dispatch", safe_dispatch))
            valid_dispatches.add(safe_dispatch)
            item_created = _timestamp(item.get("createdAt"), created)
            idempotency = str(item.get("idempotencyKey") or "")
            rows["action_dispatches"].append(
                {
                    "dispatch_id": safe_dispatch,
                    "workspace_id": wid,
                    "action_id": action_id,
                    "authority_grant_id": grant_id,
                    "state": str(item.get("state") or "unknown"),
                    "idempotency_key": f"sha256:{sha256(idempotency.encode()).hexdigest()}" if idempotency else "",
                    "payload_json": _json_text(_sanitize(item)),
                    "created_revision": 1,
                    "updated_revision": 1,
                    "created_at": item_created,
                    "updated_at": _timestamp(item.get("updatedAt"), item_created),
                }
            )
        reconciliations = value.get("reconciliations") if isinstance(value.get("reconciliations"), Mapping) else {}
        for reconciliation_id, item in sorted(reconciliations.items()):
            if not isinstance(item, Mapping):
                continue
            dispatch_id = _safe_identifier(item.get("dispatchId"), "dispatch", wid, item.get("dispatchId"))
            if dispatch_id not in valid_dispatches:
                self._add_orphan(run, "reconciliation", str(reconciliation_id), "dispatch_identity_missing", True)
                continue
            rows["reconciliations"].append(
                {
                    "reconciliation_id": _safe_identifier(reconciliation_id, "reconciliation", wid, reconciliation_id),
                    "workspace_id": wid,
                    "dispatch_id": dispatch_id,
                    "state": str(item.get("state") or "recorded"),
                    "payload_json": _json_text(_sanitize(item)),
                    "created_revision": 1,
                    "created_at": _timestamp(item.get("createdAt"), created),
                }
            )
        decisions = value.get("decisions") if isinstance(value.get("decisions"), list) else []
        for index, item in enumerate(decisions):
            if not isinstance(item, Mapping):
                continue
            event_id = _safe_identifier(item.get("auditId"), "audit", wid, "authority", index, canonical_digest(item))
            rows["audit_events"].append(
                {
                    "event_id": event_id,
                    "workspace_id": wid,
                    "revision": 1,
                    "event_type": f"authority.{item.get('kind') or 'decision'}",
                    "summary": str(
                        _sanitize(
                            item.get("reason") or "Legacy authority decision"
                        )
                    ),
                    "actor_ref": "authority-engine-v1",
                    "payload_json": _json_text(_sanitize(item)),
                    "created_at": _timestamp(item.get("at"), created),
                }
            )

    def _job_rows(
        self,
        inventory: InventoryResult,
        snapshot: Mapping[str, Any],
        rows: dict[str, list[dict[str, Any]]],
        actions: list[tuple[Mapping[str, Any], str]],
        mappings: list[dict[str, Any]],
        run: dict[str, Any],
        created: str,
        updated: str,
    ) -> None:
        wid = inventory.workspace_id
        for entry in sorted((item for item in snapshot["entries"] if item["kind"] == "job"), key=lambda item: item["path"]):
            item = self._snapshot_json(inventory, snapshot, str(entry["path"]))
            if not isinstance(item, Mapping):
                continue
            raw_task_id = str(item.get("jobId") or "")
            task_id = _safe_identifier(raw_task_id, "task", wid, entry["path"])
            if raw_task_id and raw_task_id != task_id:
                mappings.append(self._mapping(run, "task", raw_task_id, "task", task_id))
            plan = item.get("executionPlan") if isinstance(item.get("executionPlan"), Mapping) else {}
            action_id = _safe_identifier(plan.get("actionId") or item.get("actionId"), "action", wid, item.get("tool"), task_id)
            actions.append(({"actionId": action_id, "tool": item.get("tool") or "legacy.job", "status": "imported"}, str(entry["path"])))
            item_created = _timestamp(item.get("createdAt"), created)
            revision = max(int(item.get("revision") or 1), 1)
            safe_payload = {
                key: _sanitize(item.get(key))
                for key in (
                    "jobId",
                    "tool",
                    "target",
                    "status",
                    "revision",
                    "startedAt",
                    "completedAt",
                    "error",
                    "finalized",
                    "finalization",
                    "executionPlan",
                    "finalizerEffects",
                    "correlationId",
                    "reconciliationRequired",
                )
                if key in item
            }
            rows["tasks"].append(
                {
                    "task_id": task_id,
                    "workspace_id": wid,
                    "action_id": action_id,
                    "state": str(item.get("status") or "unknown"),
                    "revision": revision,
                    "payload_json": _json_text(safe_payload),
                    "created_revision": 1,
                    "updated_revision": 1,
                    "created_at": item_created,
                    "updated_at": _timestamp(item.get("updatedAt") or item.get("completedAt"), updated),
                }
            )
            rows["task_events"].append(
                {
                    "task_event_id": _stable_id("task-event", wid, task_id, revision),
                    "workspace_id": wid,
                    "task_id": task_id,
                    "event_type": "migration.snapshot",
                    "task_revision": revision,
                    "payload_json": _json_text({"state": str(item.get("status") or "unknown")}),
                    "created_revision": 1,
                    "created_at": _timestamp(item.get("updatedAt") or item.get("completedAt"), updated),
                }
            )

    @staticmethod
    def _action_rows(
        wid: str,
        rows: dict[str, list[dict[str, Any]]],
        actions: Sequence[tuple[Mapping[str, Any], str]],
        mappings: list[dict[str, Any]],
        run: Mapping[str, Any],
        created: str,
        updated: str,
    ) -> None:
        seen: set[str] = set()
        for item, source in sorted(actions, key=lambda pair: (str(pair[0].get("actionId") or ""), pair[1])):
            raw_action_id = str(item.get("actionId") or item.get("id") or "")
            action_id = _safe_identifier(raw_action_id, "action", wid, source, canonical_digest(_sanitize(item)))
            if action_id in seen:
                continue
            seen.add(action_id)
            if raw_action_id != action_id:
                mappings.append(
                    StateMigrationService._mapping(
                        run,
                        "action",
                        raw_action_id or f"content:{canonical_digest(_sanitize(item))}",
                        "action",
                        action_id,
                    )
                )
            item_created = _timestamp(item.get("createdAt"), created)
            rows["actions"].append(
                {
                    "action_id": action_id,
                    "workspace_id": wid,
                    "action_name": str(item.get("tool") or item.get("name") or "legacy.action"),
                    "state": str(item.get("status") or item.get("state") or "recorded"),
                    "plan_fingerprint": str(item.get("planFingerprint") or ""),
                    "payload_json": _json_text(_sanitize(item)),
                    "created_revision": 1,
                    "updated_revision": 1,
                    "created_at": item_created,
                    "updated_at": _timestamp(item.get("updatedAt"), updated),
                }
            )

    def _initialize_stage(self, repository: SQLiteWorkspaceRepository, run: dict[str, Any], plan: Mapping[str, Any]) -> None:
        with repository.connection_factory.connect() as connection:
            apply_migrations(connection)
            with immediate_transaction(connection):
                connection.execute(
                    "INSERT OR IGNORE INTO migration_runs(migration_run_id, workspace_id, source_version, target_version, state, source_manifest_digest, counts_json, started_at) VALUES(?, ?, 'json-v1', 'sqlite-v2', 'initialize', ?, ?, ?)",
                    (
                        run["runId"],
                        run["workspaceId"],
                        run["sourceDigest"],
                        _json_text(
                            {
                                "authorityRepositoryRevision": plan[
                                    "authorityRepositoryRevision"
                                ],
                                "stages": {
                                    **dict(run["stages"]),
                                    "initialize": "completed",
                                }
                            }
                        ),
                        plan["rows"]["workspaces"][0]["updated_at"],
                    ),
                )
                self._persist_orphans(connection, run)

    def _insert_stage(self, repository: SQLiteWorkspaceRepository, run: dict[str, Any], plan: Mapping[str, Any], stage: str) -> None:
        with repository.connection_factory.connect() as connection:
            apply_migrations(connection)
            with immediate_transaction(connection):
                for table in _TABLE_STAGES[stage]:
                    self._insert_rows(connection, table, plan["rows"][table])
                self._persist_orphans(connection, run)
                counts = {table: len(plan["rows"][table]) for table in sorted(plan["rows"])}
                connection.execute(
                    "UPDATE migration_runs SET state=?, counts_json=? WHERE migration_run_id=?",
                    (
                        stage,
                        _json_text(
                            {
                                "authorityRepositoryRevision": plan[
                                    "authorityRepositoryRevision"
                                ],
                                "counts": counts,
                                "stages": {
                                    **dict(run["stages"]),
                                    stage: "completed",
                                },
                            }
                        ),
                        run["runId"],
                    ),
                )

    def _install_artifacts(self, repository: SQLiteWorkspaceRepository, plan: Mapping[str, Any], run: dict[str, Any]) -> None:
        snapshot_files = repository.workspace_root / "state-v2" / "migration" / "pre-cutover" / "files"
        rejected: set[str] = set(run.get("rejectedArtifactIds", []))
        for row in tuple(plan["rows"]["artifacts"]):
            artifact_id = row["artifact_id"]
            source_relative = plan["artifactSources"].get(artifact_id)
            if source_relative is None:
                self._add_orphan(run, "artifact", artifact_id, "artifact_source_missing", True)
                rejected.add(str(artifact_id))
                continue
            source = snapshot_files / source_relative
            if not source.is_file():
                source = repository.workspace_root / source_relative
            try:
                if _body_contains_secret(source):
                    raise StateIntegrityError(
                        "artifact_secret_material",
                        "Artifact body contains credential or session material and was not migrated.",
                    )
                record = repository.artifacts.ingest_path(source, media_type=row["media_type"], origin=row["origin"])
                if record.artifact_id != artifact_id or record.size != row["size"]:
                    raise StateIntegrityError("migration_artifact_hash_mismatch", "Migrated artifact differs from inventory.")
            except (ArtifactStoreError, StateIntegrityError) as exc:
                self._add_orphan(run, "artifact", str(source_relative), getattr(exc, "reason_code", "artifact_rejected"), True)
                rejected.add(str(artifact_id))
        run["rejectedArtifactIds"] = sorted(rejected)
        plan["rows"]["artifacts"][:] = [
            row for row in plan["rows"]["artifacts"] if row["artifact_id"] not in rejected
        ]
        plan["rows"]["evidence_artifacts"][:] = [
            row
            for row in plan["rows"]["evidence_artifacts"]
            if row["artifact_id"] not in rejected
        ]

    @staticmethod
    def _insert_rows(connection: Any, table: str, rows: Sequence[Mapping[str, Any]]) -> None:
        if table not in _PRIMARY_KEYS:
            raise StateIntegrityError("migration_table_unknown", f"Migration table is not approved: {table}")
        for row in rows:
            columns = tuple(row)
            if not columns or any(not re.fullmatch(r"[a-z_]+", column) for column in columns):
                raise StateIntegrityError("migration_column_invalid", "Migration row contains an invalid column.")
            placeholders = ",".join("?" for _ in columns)
            connection.execute(
                f"INSERT OR IGNORE INTO {table}({','.join(columns)}) VALUES({placeholders})",
                tuple(row[column] for column in columns),
            )

    @staticmethod
    def _persist_orphans(connection: Any, run: Mapping[str, Any]) -> None:
        for orphan in run.get("orphans", []):
            orphan_id = _stable_id(
                "orphan",
                run["runId"],
                orphan["sourceKind"],
                orphan["sourceRef"],
                orphan["reasonCode"],
            )
            connection.execute(
                "INSERT OR IGNORE INTO migration_orphans(migration_orphan_id, migration_run_id, source_kind, source_ref, reason_code, detail_json) VALUES(?, ?, ?, ?, ?, ?)",
                (
                    orphan_id,
                    run["runId"],
                    orphan["sourceKind"],
                    orphan["sourceRef"],
                    orphan["reasonCode"],
                    _json_text({"blocking": bool(orphan["blocking"]), **dict(orphan.get("detail") or {})}),
                ),
            )

    def _verify_locked(self, repository: SQLiteWorkspaceRepository, plan: Mapping[str, Any], run: dict[str, Any]) -> dict[str, Any]:
        failures: list[dict[str, Any]] = []
        counts: dict[str, dict[str, int]] = {}
        identifiers: dict[str, str] = {}
        content_hashes: dict[str, str] = {}
        with repository.connection_factory.connect() as connection:
            apply_migrations(connection)
            verify_database_integrity(connection)
            for table, expected_rows in sorted(plan["rows"].items()):
                actual = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                expected = len(expected_rows)
                counts[table] = {"actual": actual, "expected": expected}
                if actual != expected:
                    failures.append({"actual": actual, "expected": expected, "reasonCode": "count_mismatch", "table": table})
                key_columns = _PRIMARY_KEYS[table]
                actual_ids = [tuple(row) for row in connection.execute(f"SELECT {','.join(key_columns)} FROM {table} ORDER BY {','.join(key_columns)}")]
                expected_ids = sorted(tuple(row[key] for key in key_columns) for row in expected_rows)
                identifiers[table] = canonical_digest(actual_ids)
                if actual_ids != expected_ids:
                    failures.append({"reasonCode": "identity_mismatch", "table": table})
                if expected_rows:
                    columns = tuple(expected_rows[0])
                    actual_rows = [
                        {column: value for column, value in zip(columns, values)}
                        for values in connection.execute(
                            f"SELECT {','.join(columns)} FROM {table} "
                            f"ORDER BY {','.join(key_columns)}"
                        )
                    ]
                else:
                    actual_rows = []
                content_hashes[table] = canonical_digest(actual_rows)
                if actual_rows != list(expected_rows):
                    failures.append({"reasonCode": "content_mismatch", "table": table})
            expected_scope = str(plan.get("scopeDigest") or "")
            actual_scope_row = connection.execute(
                "SELECT digest FROM scope_snapshots WHERE workspace_id=? ORDER BY created_revision DESC LIMIT 1", (run["workspaceId"],)
            ).fetchone()
            actual_scope = str(actual_scope_row[0]) if actual_scope_row else ""
            if actual_scope != expected_scope:
                failures.append({"reasonCode": "scope_digest_mismatch"})
            revision_row = connection.execute(
                "SELECT revision FROM workspace_revisions WHERE workspace_id=?", (run["workspaceId"],)
            ).fetchone()
            revision = int(revision_row[0]) if revision_row else -1
            if revision != 1:
                failures.append({"actual": revision, "expected": 1, "reasonCode": "revision_mismatch"})
            migration_row = connection.execute(
                "SELECT counts_json FROM migration_runs WHERE migration_run_id=?",
                (run["runId"],),
            ).fetchone()
            persisted_migration = (
                json.loads(str(migration_row[0])) if migration_row else {}
            )
            authority_repository_revision = int(
                persisted_migration.get("authorityRepositoryRevision", -1)
            )
            if authority_repository_revision != int(
                plan["authorityRepositoryRevision"]
            ):
                failures.append(
                    {
                        "actual": authority_repository_revision,
                        "expected": plan["authorityRepositoryRevision"],
                        "reasonCode": "authority_revision_mismatch",
                    }
                )
            for artifact in plan["rows"]["artifacts"]:
                try:
                    repository.artifacts.resolve(artifact["artifact_id"], workspace_id=run["workspaceId"])
                except ArtifactStoreError:
                    failures.append({"artifactId": artifact["artifact_id"], "reasonCode": "artifact_content_mismatch"})
            blocking = [item for item in run.get("orphans", []) if item.get("blocking")]
            if blocking:
                failures.append({"count": len(blocking), "reasonCode": "blocking_orphans"})
            success = not failures
            report = {
                "authorityTotals": {
                    "budgets": len(plan["rows"]["budget_windows"]),
                    "dispatches": len(plan["rows"]["action_dispatches"]),
                    "grantRevisions": len(plan["rows"]["authority_grant_revisions"]),
                    "grants": len(plan["rows"]["authority_grants"]),
                    "requestStates": len(plan["rows"]["request_states"]),
                    "repositoryRevision": authority_repository_revision,
                },
                "counts": counts,
                "contentHashes": content_hashes,
                "failures": failures,
                "foreignKeys": "ok",
                "identifiers": identifiers,
                "integrity": "ok",
                "revision": revision,
                "schemaHash": schema_hash(),
                "scopeDigest": actual_scope,
                "sourceDigest": run["sourceDigest"],
                "success": success,
                "workspaceId": run["workspaceId"],
            }
            report["verificationDigest"] = canonical_digest(report)
            with immediate_transaction(connection):
                self._persist_orphans(connection, run)
                connection.execute(
                    "UPDATE migration_runs SET state=?, counts_json=?, completed_at=? WHERE migration_run_id=?",
                    (
                        "verified" if success else "verification_failed",
                        _json_text(
                            {
                                "authorityRepositoryRevision": plan[
                                    "authorityRepositoryRevision"
                                ],
                                "counts": {
                                    table: values["actual"]
                                    for table, values in counts.items()
                                },
                                "stages": {
                                    **dict(run["stages"]),
                                    "verify": "completed" if success else "failed",
                                },
                            }
                        ),
                        plan["rows"]["workspaces"][0]["updated_at"],
                        run["runId"],
                    ),
                )
        run["verification"] = report
        _atomic_write(
            repository.workspace_root / "state-v2" / "migration" / "verification.json",
            canonical_json_bytes(report) + b"\n",
        )
        return report


__all__ = [
    "FORMAT_VERSION",
    "MIGRATION_STAGES",
    "InventoryResult",
    "JsonV1Inventory",
    "StateMigrationService",
    "canonical_digest",
    "canonical_json_bytes",
]
