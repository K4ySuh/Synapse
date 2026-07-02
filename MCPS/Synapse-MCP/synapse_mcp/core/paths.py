# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _configured_path(name: str, default: Path, *, relative_to: Path) -> Path:
    value = os.environ.get(name)
    path = Path(value).expanduser() if value else default
    if not path.is_absolute():
        path = relative_to / path
    return path.resolve()


def _require_within(path: Path, parent: Path, *, name: str, parent_name: str) -> None:
    try:
        path.relative_to(parent)
    except ValueError as exc:
        raise RuntimeError(f"{name} must resolve under {parent_name} ({parent}); got {path}") from exc


SYNAPSE_ROOT = _configured_path("SYNAPSE_ROOT", ROOT.parents[1], relative_to=ROOT.parents[1])
DATA_DIR = _configured_path("SYNAPSE_DATA_DIR", SYNAPSE_ROOT / "DATA", relative_to=SYNAPSE_ROOT)
DUMP_DIR = _configured_path("SYNAPSE_DUMP_DIR", DATA_DIR / "workspaces", relative_to=DATA_DIR)
# Generated reports and per-workspace review-decision archives live at the top level,
# not inside DATA/workspaces, so they are easy to find and share and are never
# duplicated in workspace state. Gitignored like other engagement output.
REPORTS_DIR = _configured_path("SYNAPSE_REPORTS_DIR", SYNAPSE_ROOT / "reports", relative_to=SYNAPSE_ROOT)
PROMPT_PATH = _configured_path("SYNAPSE_PROMPT_PATH", SYNAPSE_ROOT / "AGENTS.md", relative_to=SYNAPSE_ROOT)

_require_within(DATA_DIR, SYNAPSE_ROOT, name="SYNAPSE_DATA_DIR", parent_name="SYNAPSE_ROOT")
_require_within(DUMP_DIR, DATA_DIR, name="SYNAPSE_DUMP_DIR", parent_name="SYNAPSE_DATA_DIR")


def synapse_python() -> str:
    configured = os.environ.get("SYNAPSE_PYTHON", "").strip()
    if configured:
        path = Path(configured).expanduser()
        if path.is_absolute() or len(path.parts) > 1:
            if not path.is_absolute():
                path = SYNAPSE_ROOT / path
            # Normalize without following symlinks: a venv's bin/python is a
            # symlink to the base interpreter, and resolving it would drop venv
            # isolation so background workers lose venv-only deps (Playwright,
            # Selenium). os.path.abspath normalizes "." / ".." without that.
            return os.path.abspath(path)
        return configured

    virtual_env = os.environ.get("VIRTUAL_ENV", "").strip()
    if virtual_env:
        venv_python = Path(virtual_env).expanduser() / "bin" / "python"
        if venv_python.exists():
            return str(venv_python.resolve())

    venv_python = SYNAPSE_ROOT / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)

    return sys.executable
