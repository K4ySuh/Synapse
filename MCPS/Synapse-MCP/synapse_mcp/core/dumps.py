# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import workspace
from .errors import McpError
from .paths import DUMP_DIR


def resolve_dump_history_path(dump_path_text: str) -> tuple[Path, Path]:
    path = Path(dump_path_text).expanduser().resolve()
    if path.is_dir():
        return path, path / "history.jsonl"
    if path.name == "manifest.json":
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise McpError(-32602, f"Could not read dump manifest: {exc}") from exc
        return path.parent, Path(manifest.get("historyJsonl", path.parent / "history.jsonl")).resolve()
    return path.parent, path


def load_dump_entries(dump_path_text: str) -> tuple[Path, list[dict[str, Any]]]:
    dump_dir, history_path = resolve_dump_history_path(dump_path_text)
    if not history_path.exists():
        raise McpError(-32602, f"Dump history file not found: {history_path}")
    entries = []
    for line_number, line in enumerate(history_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise McpError(-32602, f"Invalid JSONL at {history_path}:{line_number}: {exc}") from exc
        for key in ("requestFile", "responseFile"):
            if entry.get(key):
                file_path = Path(entry[key]).expanduser()
                entry[key] = str(file_path.resolve() if file_path.is_absolute() else (dump_dir / file_path).resolve())
        entries.append(entry)
    return dump_dir, entries


def _dump_roots() -> list[Path]:
    roots = [DUMP_DIR]
    if workspace.WORKSPACES_DIR not in roots:
        roots.append(workspace.WORKSPACES_DIR)
    return [root for root in roots if root.exists()]


def iter_dump_directories() -> list[Path]:
    seen: set[Path] = set()
    matches: list[Path] = []
    for root in _dump_roots():
        candidates = [root] if (root / "history.jsonl").exists() else []
        candidates.extend(path.parent for path in root.rglob("history.jsonl") if path.is_file())
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            matches.append(resolved)
    return sorted(matches)


def _workspace_context(path: Path) -> dict[str, str]:
    try:
        relative = path.resolve().relative_to(workspace.WORKSPACES_DIR.resolve())
    except ValueError:
        return {}
    parts = relative.parts
    context: dict[str, str] = {}
    if parts:
        context["workspaceId"] = parts[0]
    if len(parts) >= 3 and parts[1] == "targets":
        context["target"] = parts[2]
    return context


def list_dumps() -> list[dict[str, Any]]:
    out = []
    for path in iter_dump_directories():
        history = path / "history.jsonl"
        manifest = path / "manifest.json"
        count = 0
        if history.exists():
            count = sum(1 for line in history.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
        out.append(
            {
                "path": str(path),
                "historyJsonl": str(history) if history.exists() else None,
                "manifest": str(manifest) if manifest.exists() else None,
                "entryCount": count,
                **_workspace_context(path),
            }
        )
    return out
