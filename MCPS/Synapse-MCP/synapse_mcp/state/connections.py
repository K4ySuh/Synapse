# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""State Store v2 connection factory and explicit transaction helpers."""

from __future__ import annotations

from contextlib import contextmanager
import importlib
import os
from pathlib import Path
import sqlite3
from typing import Any, Callable, Iterator, Sequence

from .errors import StateIntegrityError, StateReadinessError
from .readiness import (
    MINIMUM_SQLITE_VERSION,
    RuntimeReadiness,
    check_filesystem_readiness,
    detect_filesystem_type,
    probe_state_store_runtime,
)


DEFAULT_BUSY_TIMEOUT_MS = 5_000
MAX_BUSY_TIMEOUT_MS = 30_000


class StateConnection:
    """Small common surface over sqlite3 and APSW connections."""

    def __init__(self, raw: Any, binding: str) -> None:
        self.raw = raw
        self.binding = binding

    def execute(self, statement: str, parameters: Sequence[Any] = ()) -> Any:
        return self.raw.execute(statement, tuple(parameters))

    def executemany(self, statement: str, parameters: Sequence[Sequence[Any]]) -> Any:
        return self.raw.executemany(statement, parameters)

    def close(self) -> None:
        self.raw.close()

    def begin_immediate(self) -> None:
        self.execute("BEGIN IMMEDIATE")

    def commit(self) -> None:
        self.execute("COMMIT")

    def rollback(self) -> None:
        self.execute("ROLLBACK")


class ConnectionFactory:
    """Open one verified, short-lived connection per operation."""

    def __init__(
        self,
        database_path: Path,
        *,
        readiness: RuntimeReadiness | None = None,
        filesystem_type_resolver: Callable[[Path], str] = detect_filesystem_type,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    ) -> None:
        self.database_path = Path(database_path)
        self.readiness = readiness or probe_state_store_runtime()
        self.filesystem_type_resolver = filesystem_type_resolver
        timeout = int(busy_timeout_ms)
        if timeout < 1 or timeout > MAX_BUSY_TIMEOUT_MS:
            raise StateReadinessError(
                "busy_timeout_invalid",
                f"State Store busy timeout must be between 1 and {MAX_BUSY_TIMEOUT_MS} ms.",
            )
        self.busy_timeout_ms = timeout

    def verify_readiness(self) -> None:
        if not self.readiness.ready:
            raise StateReadinessError(
                self.readiness.reason_code,
                "No SQLite runtime satisfies the State Store v2 safety floor.",
            )
        filesystem = check_filesystem_readiness(
            self.database_path.parent,
            resolver=self.filesystem_type_resolver,
        )
        if not filesystem.ready:
            raise StateReadinessError(
                filesystem.reason_code,
                f"State Store v2 refuses filesystem type {filesystem.filesystem_type}.",
            )

    def open(self) -> StateConnection:
        self.verify_readiness()
        self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            if self.readiness.selected_binding == "sqlite3":
                raw = sqlite3.connect(
                    self.database_path,
                    timeout=self.busy_timeout_ms / 1_000,
                    isolation_level=None,
                )
            elif self.readiness.selected_binding == "apsw":
                apsw = importlib.import_module("apsw")
                raw = apsw.Connection(str(self.database_path))
                setter = getattr(raw, "set_busy_timeout", None) or getattr(raw, "setbusytimeout")
                setter(self.busy_timeout_ms)
            else:
                raise StateReadinessError(
                    "sqlite_binding_unavailable",
                    "The selected State Store SQLite binding is unavailable.",
                )
        except StateReadinessError:
            raise
        except Exception as exc:
            raise StateReadinessError(
                "sqlite_connection_failed",
                "State Store v2 could not open its workspace database.",
            ) from exc
        connection = StateConnection(raw, self.readiness.selected_binding)
        try:
            self._initialize(connection)
            try:
                os.chmod(self.database_path, 0o600)
            except OSError:
                pass
            return connection
        except Exception:
            connection.close()
            raise

    @contextmanager
    def connect(self) -> Iterator[StateConnection]:
        connection = self.open()
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self, connection: StateConnection) -> None:
        try:
            actual_version = str(connection.execute("SELECT sqlite_version()").fetchone()[0])
            journal = str(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0])
            synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
            timeout = int(connection.execute("PRAGMA busy_timeout").fetchone()[0])
        except Exception as exc:
            raise StateReadinessError(
                "sqlite_pragma_initialization_failed",
                "State Store v2 could not establish required SQLite pragmas.",
            ) from exc
        try:
            actual_version_tuple = tuple(int(part) for part in actual_version.split("."))
        except ValueError as exc:
            raise StateReadinessError(
                "sqlite_runtime_version_invalid",
                "Selected SQLite runtime returned an invalid version.",
            ) from exc
        if actual_version_tuple < MINIMUM_SQLITE_VERSION:
            raise StateReadinessError(
                "sqlite_runtime_too_old",
                f"Connected SQLite {actual_version} is below the State Store v2 safety floor.",
            )
        if journal != "wal" or foreign_keys != 1 or synchronous != 2 or timeout != self.busy_timeout_ms:
            raise StateReadinessError(
                "sqlite_pragma_verification_failed",
                "State Store v2 SQLite safety pragmas were not retained.",
            )


@contextmanager
def immediate_transaction(connection: StateConnection) -> Iterator[StateConnection]:
    connection.begin_immediate()
    try:
        yield connection
    except BaseException:
        try:
            connection.rollback()
        except Exception:
            pass
        raise
    else:
        connection.commit()


def verify_database_integrity(connection: StateConnection) -> None:
    foreign_key_rows = list(connection.execute("PRAGMA foreign_key_check"))
    integrity_rows = list(connection.execute("PRAGMA integrity_check"))
    if foreign_key_rows:
        raise StateIntegrityError(
            "foreign_key_check_failed",
            "State Store v2 contains invalid foreign-key references.",
        )
    if integrity_rows != [("ok",)]:
        raise StateIntegrityError(
            "integrity_check_failed",
            "State Store v2 failed SQLite integrity_check.",
        )
