# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Deprecated command alias for the production modern MCP adapter."""

from __future__ import annotations

import warnings


def main() -> None:
    warnings.warn(
        "synapse-mcp-modern-spike is deprecated; use synapse-mcp-modern with explicit production configuration",
        DeprecationWarning,
        stacklevel=2,
    )
    from synapse_mcp.transport.modern.__main__ import main as modern_main

    modern_main()


if __name__ == "__main__":
    main()
