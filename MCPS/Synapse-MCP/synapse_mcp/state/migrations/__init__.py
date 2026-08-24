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


MIGRATION_NAME = "0001_initial.sql"


def migration_text() -> str:
    return files(__package__).joinpath(MIGRATION_NAME).read_text(encoding="utf-8")


def schema_hash() -> str:
    return sha256(migration_text().encode("utf-8")).hexdigest()


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
        row = connection.execute(
            "SELECT schema_hash FROM schema_migrations WHERE version=1"
        ).fetchone()
        if row is None or str(row[0]) != expected_hash:
            raise StateIntegrityError(
                "schema_hash_mismatch",
                "State Store schema does not match the reviewed migration hash.",
            )
        return expected_hash

    with immediate_transaction(connection):
        for statement in _statements(migration_text()):
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations(version, name, schema_hash) VALUES(1, ?, ?)",
            (MIGRATION_NAME, expected_hash),
        )
        connection.execute(
            "INSERT INTO store_metadata(key, value) VALUES('schema_hash', ?)",
            (expected_hash,),
        )
        connection.execute(
            "INSERT INTO store_metadata(key, value) VALUES('store_version', 'sqlite-v2')"
        )
    return expected_hash
