# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Versioned State Store v2 schema migrations."""

from __future__ import annotations

from hashlib import sha256
from importlib.resources import files
import sqlite3
from typing import Iterator

from ..connections import StateConnection, immediate_transaction
from ..errors import StateIntegrityError


MIGRATION_NAMES = (
    "0001_initial.sql",
    "0002_runtime_adoption.sql",
    "0003_operational_work_items.sql",
    "0004_work_execution_attempts.sql",
    "0005_work_dependency_policies.sql",
    "0006_execution_lifecycle.sql",
)


def migration_text(name: str = MIGRATION_NAMES[0]) -> str:
    if name not in MIGRATION_NAMES:
        raise StateIntegrityError("migration_unknown", "State Store migration is not registered.")
    return files(__package__).joinpath(name).read_text(encoding="utf-8")


def migration_hash(name: str) -> str:
    return sha256(migration_text(name).encode("utf-8")).hexdigest()


def schema_hash() -> str:
    manifest = "\n".join(f"{name}:{migration_hash(name)}" for name in MIGRATION_NAMES)
    return sha256(manifest.encode("utf-8")).hexdigest()


def _statements(script: str) -> Iterator[str]:
    pending = ""
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statement = pending.strip()
            pending = ""
            if statement:
                yield statement
    if pending.strip():
        raise StateIntegrityError("migration_incomplete", "State Store migration contains incomplete SQL.")


def apply_migrations(connection: StateConnection) -> str:
    expected_hash = schema_hash()
    existing = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if existing:
        installed_rows = list(connection.execute(
            "SELECT version, name, schema_hash FROM schema_migrations ORDER BY version"
        ))
        installed = {int(row[0]): (str(row[1]), str(row[2])) for row in installed_rows}
        complete = True
        for version, name in enumerate(MIGRATION_NAMES, start=1):
            prior = installed.get(version)
            if prior is None:
                complete = False
                continue
            if prior != (name, migration_hash(name)):
                raise StateIntegrityError(
                    "schema_hash_mismatch",
                    "State Store schema does not match the reviewed migration hash.",
                )
        if complete:
            metadata = connection.execute(
                "SELECT value FROM store_metadata WHERE key='schema_hash'"
            ).fetchone()
            if metadata is None or str(metadata[0]) != expected_hash:
                raise StateIntegrityError(
                    "schema_hash_mismatch",
                    "State Store schema metadata does not match the reviewed migration set.",
                )
            return expected_hash
    with immediate_transaction(connection):
        existing = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
        ).fetchone()
        installed: dict[int, tuple[str, str]] = {}
        if existing:
            installed = {
                int(row[0]): (str(row[1]), str(row[2]))
                for row in connection.execute(
                    "SELECT version, name, schema_hash FROM schema_migrations ORDER BY version"
                )
            }
        for version, name in enumerate(MIGRATION_NAMES, start=1):
            migration_digest = migration_hash(name)
            prior = installed.get(version)
            if prior is not None:
                if prior != (name, migration_digest):
                    raise StateIntegrityError(
                        "schema_hash_mismatch",
                        "State Store schema does not match the reviewed migration hash.",
                    )
                continue
            for statement in _statements(migration_text(name)):
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations(version, name, schema_hash) VALUES(?, ?, ?)",
                (version, name, migration_digest),
            )
        connection.execute(
            "INSERT INTO store_metadata(key, value) VALUES('schema_hash', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (expected_hash,),
        )
        connection.execute(
            "INSERT INTO store_metadata(key, value) VALUES('store_version', 'sqlite-v2') "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        )
    return expected_hash
