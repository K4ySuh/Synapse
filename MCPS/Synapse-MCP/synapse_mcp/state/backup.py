# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""SQLite online backup support; live database files are never copied raw."""

from __future__ import annotations

from pathlib import Path

from .connections import ConnectionFactory, verify_database_integrity
from .errors import StateStoreError
from .migrations import apply_migrations


def online_backup(source: ConnectionFactory, destination_path: Path) -> Path:
    destination = Path(destination_path).resolve(strict=False)
    if destination == source.database_path.resolve(strict=False):
        raise StateStoreError("backup_destination_invalid", "Backup destination must differ from the live database.")
    destination_factory = ConnectionFactory(
        destination,
        readiness=source.readiness,
        filesystem_type_resolver=source.filesystem_type_resolver,
        busy_timeout_ms=source.busy_timeout_ms,
    )
    try:
        with source.connect() as live, destination_factory.connect() as backup:
            if live.binding != backup.binding:
                raise StateStoreError("backup_binding_mismatch", "Online backup requires the selected source binding.")
            if live.binding == "sqlite3":
                live.raw.backup(backup.raw)
            elif live.binding == "apsw":
                operation = backup.raw.backup("main", live.raw, "main")
                try:
                    while not operation.done:
                        operation.step(128)
                finally:
                    operation.finish()
            else:
                raise StateStoreError("backup_binding_unavailable", "No online backup implementation is available.")
        with destination_factory.connect() as verified:
            apply_migrations(verified)
            verify_database_integrity(verified)
    except StateStoreError:
        raise
    except Exception as exc:
        raise StateStoreError("online_backup_failed", "SQLite online backup failed.") from exc
    return destination
