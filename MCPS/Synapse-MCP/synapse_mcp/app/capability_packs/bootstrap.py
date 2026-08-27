# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""One-shot trusted startup selection read before Action Registry assembly."""

from __future__ import annotations

import re


_PACK_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_startup_selection: tuple[str, ...] | None = None
_assembly_started = False


def select_startup_capability_packs(pack_ids: tuple[str, ...]) -> None:
    """Seal one explicit launcher selection before application imports."""

    global _startup_selection
    if _assembly_started:
        raise RuntimeError("capability-pack selection is already sealed")
    selected = tuple(pack_ids)
    if not selected:
        raise ValueError("capability-pack selection must be non-empty and unique")
    invalid = [
        value
        for value in selected
        if not isinstance(value, str) or not _PACK_ID_PATTERN.fullmatch(value)
    ]
    if invalid:
        raise ValueError(f"invalid capability-pack selection: {invalid}")
    if len(selected) != len(set(selected)):
        raise ValueError("capability-pack selection must be non-empty and unique")
    if _startup_selection is not None and _startup_selection != selected:
        raise RuntimeError("capability-pack selection was already configured")
    _startup_selection = selected


def consume_startup_capability_packs() -> tuple[str, ...] | None:
    """Return the selected packs and prevent later startup mutation."""

    global _assembly_started
    _assembly_started = True
    return _startup_selection
