# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Checked-in machine-readable inventory for the frozen action surface."""

from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
from typing import Any


INVENTORY_PATH = Path(__file__).with_name("action_inventory.json")


@lru_cache(maxsize=1)
def action_inventory_document() -> dict[str, Any]:
    document = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("legacyActionCount") != 174:
        raise RuntimeError("canonical action inventory must declare exactly 174 actions")
    actions = document.get("actions")
    if not isinstance(actions, list) or len(actions) != 174:
        raise RuntimeError("canonical action inventory must contain exactly 174 actions")
    return document


def action_inventory() -> tuple[dict[str, Any], ...]:
    """Return inventory entries in frozen legacy order."""

    return tuple(action_inventory_document()["actions"])


def inventory_entry(action_id: str) -> dict[str, Any]:
    """Return one inventory entry by canonical action id."""

    for entry in action_inventory():
        if entry.get("actionId") == action_id:
            return entry
    raise LookupError(f"Unknown inventory action id: {action_id}")
