# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Compatibility entry points for the passive saved-spec integration."""

from __future__ import annotations

from functools import wraps
import json
from typing import Any

from ...core import saved_spec_import


def capabilities(_: dict[str, Any] | None = None) -> str:
    """Return the retained adapter discovery projection."""

    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("spec_import"), indent=2)


@wraps(saved_spec_import.import_spec)
def import_spec(args: dict[str, Any]) -> str:
    """Forward the retained legacy alias to the deterministic core seam."""

    return saved_spec_import.import_spec(args)
