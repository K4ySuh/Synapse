# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""State Store v2 SQLite runtime selection and readiness reporting."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import importlib
import json
import platform
import sqlite3
from typing import Any


MINIMUM_SQLITE_VERSION = (3, 51, 3)
MINIMUM_SQLITE_VERSION_TEXT = ".".join(str(part) for part in MINIMUM_SQLITE_VERSION)


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = value.split(".")
    try:
        parsed = tuple(int(part) for part in parts)
    except ValueError:
        return ()
    return parsed if len(parsed) >= 3 else ()


def _supported(value: str) -> bool:
    parsed = _version_tuple(value)
    return bool(parsed) and parsed >= MINIMUM_SQLITE_VERSION


@dataclass(frozen=True, slots=True)
class RuntimeReadiness:
    python_version: str
    stdlib_sqlite_version: str
    apsw_binding_version: str
    apsw_sqlite_version: str
    selected_binding: str
    selected_sqlite_version: str
    minimum_sqlite_version: str
    ready: bool
    reason_code: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def select_sqlite_runtime(
    *,
    stdlib_sqlite_version: str,
    apsw_sqlite_version: str = "",
    apsw_binding_version: str = "",
    python_version: str | None = None,
) -> RuntimeReadiness:
    """Choose stdlib SQLite when safe, otherwise the reviewed APSW fallback."""

    selected_binding = ""
    selected_version = ""
    if _supported(stdlib_sqlite_version):
        selected_binding = "sqlite3"
        selected_version = stdlib_sqlite_version
    elif _supported(apsw_sqlite_version):
        selected_binding = "apsw"
        selected_version = apsw_sqlite_version
    ready = bool(selected_binding)
    return RuntimeReadiness(
        python_version=python_version or platform.python_version(),
        stdlib_sqlite_version=stdlib_sqlite_version,
        apsw_binding_version=apsw_binding_version,
        apsw_sqlite_version=apsw_sqlite_version,
        selected_binding=selected_binding,
        selected_sqlite_version=selected_version,
        minimum_sqlite_version=MINIMUM_SQLITE_VERSION_TEXT,
        ready=ready,
        reason_code="ready" if ready else "sqlite_runtime_too_old",
    )


def _apsw_versions() -> tuple[str, str]:
    try:
        apsw = importlib.import_module("apsw")
    except ImportError:
        return "", ""
    binding_version = str(apsw.apsw_version())
    sqlite_version = str(apsw.sqlite_lib_version())
    return binding_version, sqlite_version


def probe_state_store_runtime() -> RuntimeReadiness:
    apsw_binding_version, apsw_sqlite_version = _apsw_versions()
    return select_sqlite_runtime(
        stdlib_sqlite_version=str(sqlite3.sqlite_version),
        apsw_sqlite_version=apsw_sqlite_version,
        apsw_binding_version=apsw_binding_version,
    )


def _render_human(readiness: RuntimeReadiness) -> str:
    fallback = (
        f"{readiness.apsw_sqlite_version} (APSW {readiness.apsw_binding_version})"
        if readiness.apsw_sqlite_version
        else "unavailable"
    )
    selected = (
        f"{readiness.selected_binding} / SQLite {readiness.selected_sqlite_version}"
        if readiness.ready
        else "none"
    )
    status = "STATE STORE V2 READY" if readiness.ready else "STATE STORE V2 NOT READY"
    return "\n".join(
        (
            f"Python: {readiness.python_version}",
            f"sqlite3.sqlite_version: {readiness.stdlib_sqlite_version}",
            f"APSW SQLite runtime: {fallback}",
            f"Required SQLite: >= {readiness.minimum_sqlite_version}",
            f"Selected State Store v2 binding: {selected}",
            status,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable readiness")
    args = parser.parse_args()
    readiness = probe_state_store_runtime()
    if args.json:
        print(json.dumps(readiness.to_dict(), indent=2, sort_keys=True))
    else:
        print(_render_human(readiness))
    return 0 if readiness.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
