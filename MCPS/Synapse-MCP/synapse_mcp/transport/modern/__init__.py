# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Official-SDK modern MCP adapter; application code remains protocol-free."""

from __future__ import annotations

from typing import Any


__all__ = ["ModernAdapterConfig", "ModernConfigurationError"]


def __getattr__(name: str) -> Any:
    if name not in __all__:
        raise AttributeError(name)
    from .config import ModernAdapterConfig, ModernConfigurationError

    values = {
        "ModernAdapterConfig": ModernAdapterConfig,
        "ModernConfigurationError": ModernConfigurationError,
    }
    globals().update(values)
    return values[name]
