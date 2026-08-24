# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Operator CLI for State Store v1-to-v2 migration and bundles."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Sequence

from .bundles import StateBundleService
from .errors import StateStoreError
from .migration import StateMigrationService


def _default_data_root() -> Path:
    configured = os.environ.get("SYNAPSE_DATA_DIR")
    if configured:
        return Path(configured)
    return Path(os.environ.get("SYNAPSE_ROOT") or Path.cwd()) / "DATA"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="synapse-state", description="Synapse State Store migration operator service")
    parser.add_argument("--data-root", type=Path, default=_default_data_root())
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inventory", "verify", "activate", "rollback", "status"):
        command = commands.add_parser(name)
        command.add_argument("workspace")
    migrate = commands.add_parser("migrate")
    migrate.add_argument("workspace")
    selection = migrate.add_mutually_exclusive_group(required=True)
    selection.add_argument("--dry-run", action="store_true")
    selection.add_argument("--apply", action="store_true")
    export = commands.add_parser("export")
    export.add_argument("workspace")
    export.add_argument("--output", type=Path)
    import_command = commands.add_parser("import")
    import_command.add_argument("bundle", type=Path)
    import_command.add_argument("--workspace")
    return parser


def run(arguments: Sequence[str] | None = None) -> dict:
    values = _parser().parse_args(arguments)
    migration = StateMigrationService(values.data_root)
    bundles = StateBundleService(values.data_root)
    if values.command == "inventory":
        return migration.inventory(values.workspace)
    if values.command == "migrate":
        return migration.migrate(values.workspace, apply=bool(values.apply))
    if values.command == "verify":
        return migration.verify(values.workspace)
    if values.command == "activate":
        return migration.activate(values.workspace)
    if values.command == "rollback":
        return migration.rollback(values.workspace)
    if values.command == "status":
        return migration.status(values.workspace)
    if values.command == "export":
        output = values.output
        if output is None:
            status = migration.status(values.workspace)
            output = values.data_root / "exports" / f"{status['workspaceId']}-r{status['revision']}"
        return bundles.export(values.workspace, output)
    if values.command == "import":
        return bundles.import_bundle(values.bundle, workspace_id=values.workspace)
    raise AssertionError(values.command)


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        result = run(arguments)
    except StateStoreError as exc:
        print(json.dumps({"error": {"message": str(exc), "reasonCode": exc.reason_code}}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
