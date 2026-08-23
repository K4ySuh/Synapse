# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Official-SDK modern MCP adapter; application code remains protocol-free."""

from .config import ModernAdapterConfig, ModernConfigurationError

__all__ = ["ModernAdapterConfig", "ModernConfigurationError"]
