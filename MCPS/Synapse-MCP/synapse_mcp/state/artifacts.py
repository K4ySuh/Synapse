# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Workspace-local content-addressed artifact storage."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
from hashlib import sha256
import json
import mimetypes
import os
from pathlib import Path
import re
import stat
import time
from typing import Callable, Iterator
from uuid import uuid4

from .contracts import ArtifactRecord
from .errors import (
    ArtifactCollisionError,
    ArtifactLimitError,
    ArtifactStoreError,
)
from .readiness import check_filesystem_readiness, detect_filesystem_type


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_WORKSPACE_ID = re.compile(r"[^a-zA-Z0-9._-]+")


@dataclass(frozen=True, slots=True)
class ArtifactLimits:
    file_count: int = 10_000
    total_bytes: int = 2 * 1024 * 1024 * 1024
    per_file_bytes: int = 512 * 1024 * 1024
    relative_path_bytes: int = 4_096
    depth: int = 64

    def __post_init__(self) -> None:
        if any(
            value < 1
            for value in (
                self.file_count,
                self.total_bytes,
                self.per_file_bytes,
                self.relative_path_bytes,
                self.depth,
            )
        ):
            raise ValueError("Artifact limits must be positive integers")


@dataclass(frozen=True, slots=True)
class _SourceFile:
    path: Path
    relative: str
    size: int


def normalize_workspace_id(value: str) -> str:
    normalized = _WORKSPACE_ID.sub("-", str(value).strip().lower()).strip("-")
    if not normalized:
        raise ArtifactStoreError("artifact_workspace_invalid", "Artifact workspace identity is required.")
    return normalized


class ContentAddressedArtifactRepository:
    """Bounded SHA-256 blob storage scoped to exactly one workspace."""

    def __init__(
        self,
        workspace_id: str,
        workspace_root: Path,
        *,
        limits: ArtifactLimits | None = None,
        fault_injector: Callable[[str], None] | None = None,
        filesystem_type_resolver: Callable[[Path], str] = detect_filesystem_type,
    ) -> None:
        self._workspace_id = normalize_workspace_id(workspace_id)
        self.workspace_root = Path(workspace_root).resolve(strict=False)
        if self.workspace_root.name != self._workspace_id:
            raise ArtifactStoreError(
                "artifact_workspace_root_mismatch",
                "Artifact root does not belong to the bound workspace.",
            )
        self.root = self.workspace_root / "state-v2" / "artifacts"
        self.blob_root = self.root / "sha256"
        self.incoming_root = self.root / ".incoming"
        self.lock_root = self.root / ".locks"
        self.limits = limits or ArtifactLimits()
        self._fault_injector = fault_injector
        self._filesystem_type_resolver = filesystem_type_resolver

    @property
    def workspace_id(self) -> str:
        return self._workspace_id

    def ingest_path(
        self,
        path: Path,
        *,
        media_type: str = "application/octet-stream",
        origin: str = "local",
    ) -> ArtifactRecord:
        source = Path(path)
        try:
            source_lstat = source.lstat()
        except OSError as exc:
            raise ArtifactStoreError("artifact_source_unreadable", "Artifact source is unreadable.") from exc
        if stat.S_ISLNK(source_lstat.st_mode):
            raise ArtifactStoreError("artifact_symlink_forbidden", "Artifact sources cannot be symbolic links.")
        if stat.S_ISREG(source_lstat.st_mode):
            if source_lstat.st_size > self.limits.per_file_bytes:
                raise ArtifactLimitError("artifact_file_bytes_limit", "Artifact exceeds the per-file byte limit.")
            return self._ingest_file(source, media_type=media_type, origin=origin)
        if stat.S_ISDIR(source_lstat.st_mode):
            return self._ingest_directory(source, origin=origin)
        raise ArtifactStoreError("artifact_non_regular_file", "Artifact source must be a regular file or directory.")

    def ingest_bytes(
        self,
        content: bytes,
        *,
        media_type: str = "application/octet-stream",
        origin: str = "generated",
    ) -> ArtifactRecord:
        if len(content) > self.limits.per_file_bytes:
            raise ArtifactLimitError("artifact_file_bytes_limit", "Artifact exceeds the per-file byte limit.")
        self._ensure_roots()
        temp = self.incoming_root / f"{uuid4().hex}.part"
        installed = False
        try:
            with temp.open("xb") as handle:
                os.chmod(temp, 0o600)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            digest = sha256(content).hexdigest()
            target = self._install(temp, digest, len(content))
            installed = True
            self._inject("after_install")
            return ArtifactRecord(
                artifact_id=f"sha256:{digest}",
                digest=digest,
                size=len(content),
                media_type=media_type,
                origin=origin,
                path=target,
            )
        finally:
            if not installed or temp.exists():
                try:
                    temp.unlink()
                except FileNotFoundError:
                    pass

    def resolve(self, artifact_id: str, *, workspace_id: str) -> Path:
        self._verify_filesystem()
        if normalize_workspace_id(workspace_id) != self._workspace_id:
            raise ArtifactStoreError(
                "artifact_workspace_mismatch",
                "Artifact reference belongs to a different workspace.",
            )
        digest = artifact_id.removeprefix("sha256:")
        path = self.path_for_digest(digest)
        if not path.is_file() or path.is_symlink():
            raise ArtifactStoreError("artifact_blob_missing", "Artifact blob is missing.")
        if not self._matches(path, digest, path.stat(follow_symlinks=False).st_size):
            raise ArtifactCollisionError(
                "artifact_collision_mismatch",
                "Artifact blob content does not match its digest.",
            )
        return path

    def path_for_digest(self, digest: str) -> Path:
        if not _DIGEST.fullmatch(str(digest)):
            raise ArtifactStoreError("artifact_digest_invalid", "Artifact digest must be lowercase SHA-256.")
        return self.blob_root / digest[:2] / digest

    def blob_exists(self, record: ArtifactRecord) -> bool:
        self._verify_filesystem()
        if record.artifact_id != f"sha256:{record.digest}":
            return False
        try:
            path = self.path_for_digest(record.digest)
        except ArtifactStoreError:
            return False
        return path.is_file() and not path.is_symlink() and self._matches(path, record.digest, record.size)

    def _ingest_file(self, source: Path, *, media_type: str, origin: str) -> ArtifactRecord:
        self._ensure_roots()
        temp = self.incoming_root / f"{uuid4().hex}.part"
        digest = sha256()
        size = 0
        installed = False
        source_descriptor = -1
        try:
            source_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            before = os.fstat(source_descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ArtifactStoreError("artifact_non_regular_file", "Artifact source is not a regular file.")
            with os.fdopen(source_descriptor, "rb") as reader:
                source_descriptor = -1
                with temp.open("xb") as writer:
                    os.chmod(temp, 0o600)
                    while chunk := reader.read(1024 * 1024):
                        size += len(chunk)
                        if size > self.limits.per_file_bytes:
                            raise ArtifactLimitError(
                                "artifact_file_bytes_limit",
                                "Artifact grew beyond the per-file byte limit while streaming.",
                            )
                        digest.update(chunk)
                        writer.write(chunk)
                    writer.flush()
                    os.fsync(writer.fileno())
                after = os.fstat(reader.fileno())
            path_after = source.lstat()
            identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            if (
                identity_before != identity_after
                or (path_after.st_dev, path_after.st_ino) != identity_before[:2]
                or stat.S_ISLNK(path_after.st_mode)
                or size != before.st_size
            ):
                raise ArtifactStoreError("artifact_source_changed", "Artifact source changed during ingest.")
            hexdigest = digest.hexdigest()
            target = self._install(temp, hexdigest, size)
            installed = True
            self._inject("after_install")
            return ArtifactRecord(
                artifact_id=f"sha256:{hexdigest}",
                digest=hexdigest,
                size=size,
                media_type=media_type,
                origin=origin,
                path=target,
            )
        except ArtifactStoreError:
            raise
        except OSError as exc:
            raise ArtifactStoreError("artifact_ingest_failed", "Artifact could not be streamed into CAS.") from exc
        finally:
            if source_descriptor >= 0:
                os.close(source_descriptor)
            if not installed or temp.exists():
                try:
                    temp.unlink()
                except FileNotFoundError:
                    pass

    def _ingest_directory(self, source: Path, *, origin: str) -> ArtifactRecord:
        files = self._directory_files(source)
        entries = []
        for item in files:
            media_type = mimetypes.guess_type(item.relative)[0] or "application/octet-stream"
            record = self._ingest_file(item.path, media_type=media_type, origin=origin)
            entries.append(
                {
                    "digest": record.digest,
                    "mediaType": record.media_type,
                    "path": item.relative,
                    "size": record.size,
                }
            )
        manifest = json.dumps(
            {"entries": entries, "type": "synapse-directory-v1"},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return self.ingest_bytes(
            manifest,
            media_type="application/vnd.synapse.directory+json",
            origin=origin,
        )

    def _directory_files(self, source: Path) -> tuple[_SourceFile, ...]:
        files: list[_SourceFile] = []
        total_bytes = 0
        directories = [source]
        while directories:
            current = directories.pop()
            try:
                iterator = os.scandir(current)
            except OSError as exc:
                raise ArtifactStoreError("artifact_source_unreadable", "Artifact directory is unreadable.") from exc
            with iterator:
                for entry in iterator:
                    path = Path(entry.path)
                    relative_path = path.relative_to(source)
                    relative = relative_path.as_posix()
                    if relative.startswith("../") or relative.startswith("/") or ".." in relative_path.parts:
                        raise ArtifactStoreError("artifact_traversal_forbidden", "Artifact path traversal is forbidden.")
                    if len(relative.encode("utf-8", errors="surrogateescape")) > self.limits.relative_path_bytes:
                        raise ArtifactLimitError("artifact_path_bytes_limit", "Artifact relative path is too long.")
                    if len(relative_path.parts) > self.limits.depth:
                        raise ArtifactLimitError("artifact_depth_limit", "Artifact directory is too deep.")
                    if entry.is_symlink():
                        raise ArtifactStoreError("artifact_symlink_forbidden", "Artifact directories cannot contain symlinks.")
                    if entry.is_dir(follow_symlinks=False):
                        directories.append(path)
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        raise ArtifactStoreError(
                            "artifact_non_regular_file",
                            "Artifact directories may contain only regular files.",
                        )
                    size = entry.stat(follow_symlinks=False).st_size
                    if size > self.limits.per_file_bytes:
                        raise ArtifactLimitError("artifact_file_bytes_limit", "Artifact file is too large.")
                    if len(files) >= self.limits.file_count:
                        raise ArtifactLimitError("artifact_file_count_limit", "Artifact directory has too many files.")
                    total_bytes += size
                    if total_bytes > self.limits.total_bytes:
                        raise ArtifactLimitError("artifact_total_bytes_limit", "Artifact directory is too large.")
                    files.append(_SourceFile(path=path, relative=relative, size=size))
        return tuple(sorted(files, key=lambda item: item.relative.encode("utf-8")))

    def _ensure_roots(self) -> None:
        self._verify_filesystem()
        for path in (self.blob_root, self.incoming_root, self.lock_root):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _verify_filesystem(self) -> None:
        readiness = check_filesystem_readiness(
            self.workspace_root,
            resolver=self._filesystem_type_resolver,
        )
        if not readiness.ready:
            raise ArtifactStoreError(
                readiness.reason_code,
                f"Artifact store refuses filesystem type {readiness.filesystem_type}.",
            )

    def _install(self, temp: Path, digest: str, size: int) -> Path:
        target = self.path_for_digest(digest)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._fsync_directory(self.blob_root)
        with self._digest_lock(digest):
            if target.exists():
                if target.is_symlink() or not target.is_file() or not self._matches(target, digest, size):
                    raise ArtifactCollisionError(
                        "artifact_collision_mismatch",
                        "Existing CAS path does not match its digest and size.",
                    )
                return target
            try:
                os.rename(temp, target)
                os.chmod(target, 0o600)
                self._fsync_directory(target.parent)
            except OSError as exc:
                raise ArtifactStoreError("artifact_install_failed", "Artifact CAS install failed.") from exc
        return target

    @staticmethod
    def _matches(path: Path, digest: str, size: int) -> bool:
        try:
            if path.stat(follow_symlinks=False).st_size != size:
                return False
            actual = sha256()
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    actual.update(chunk)
            return actual.hexdigest() == digest
        except OSError:
            return False

    @contextmanager
    def _digest_lock(self, digest: str) -> Iterator[None]:
        lock_path = self.lock_root / f"{digest}.lock"
        deadline = time.monotonic() + 10.0
        with lock_path.open("a+b") as handle:
            while True:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise ArtifactStoreError(
                            "artifact_lock_timeout",
                            "Timed out waiting for artifact digest lock.",
                        ) from exc
                    time.sleep(0.02)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _inject(self, stage: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(stage)
