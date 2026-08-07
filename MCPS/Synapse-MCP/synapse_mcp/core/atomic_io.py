# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import threading
import time
from uuid import uuid4

from .errors import McpError


__all__ = ["atomic_write_text", "file_lock"]

DEFAULT_STORE_LOCK_TIMEOUT_SECONDS = 10.0
_LOCK_STATE = threading.local()


def atomic_write_text(
    path: Path,
    text: str,
    *,
    mode: int | None = None,
    fsync: bool = True,
) -> None:
    """Atomically replace a text file without exposing partial contents."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f"{path.name}.{os.getpid()}.{uuid4().hex}.tmp")
    replaced = False
    try:
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
        try:
            if mode is not None:
                os.fchmod(fd, mode)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write(text)
                handle.flush()
                if fsync:
                    os.fsync(handle.fileno())
        finally:
            if fd >= 0:
                os.close(fd)

        os.replace(temp_path, path)
        replaced = True
        if fsync:
            try:
                directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
    finally:
        if not replaced:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


@contextmanager
def file_lock(path: Path, *, timeout_seconds: float | None = None):
    """Hold an exclusive, thread-reentrant advisory lock for one store file."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f"{path.name}.lock")
    lock_key = str(lock_path.resolve())
    held = getattr(_LOCK_STATE, "held_file_locks", set())
    if lock_key in held:
        yield
        return

    timeout = DEFAULT_STORE_LOCK_TIMEOUT_SECONDS if timeout_seconds is None else float(timeout_seconds)
    deadline = time.monotonic() + max(timeout, 0.0)
    with lock_path.open("a+", encoding="utf-8") as handle:
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                held.add(lock_key)
                _LOCK_STATE.held_file_locks = held
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise McpError(
                        -32000,
                        f"Timed out waiting for store lock for {path} after {timeout:.1f}s.",
                    ) from exc
                time.sleep(0.05)
        try:
            yield
        finally:
            held.discard(lock_key)
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
