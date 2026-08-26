# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Production official-SDK Synapse MCP launcher."""

from __future__ import annotations

import argparse
from pathlib import Path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--surface", choices=("modern-compact", "modern-direct"), required=True)
    parser.add_argument(
        "--capability-pack",
        action="append",
        default=[],
        help="Select one capability pack; repeat for multiple packs. Default: all built-ins.",
    )
    parser.add_argument("--transport", choices=("stdio", "streamable-http"), required=True)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--audience", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--enable-remote", action="store_true")
    parser.add_argument("--identity-bindings", type=Path, required=True)
    parser.add_argument("--stdio-principal", default="")
    parser.add_argument("--http-token-map", type=Path)
    parser.add_argument("--request-state-keyring", type=Path)
    parser.add_argument("--allow-ephemeral-request-state", action="store_true")
    parser.add_argument("--request-state-ttl", type=float, default=600.0)
    parser.add_argument("--allowed-host", action="append", default=[])
    parser.add_argument("--allowed-origin", action="append", default=[])
    parser.add_argument("--tls-termination", choices=("local", "direct", "trusted-proxy"), default="local")
    parser.add_argument("--trusted-proxy", action="append", default=[])
    parser.add_argument("--tls-certfile", type=Path)
    parser.add_argument("--tls-keyfile", type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--observability", choices=("disabled", "otel"), default="otel")
    return parser


def main() -> None:
    args = _parser().parse_args()
    selected_packs = tuple(args.capability_pack)
    if selected_packs:
        from synapse_mcp.app.capability_packs.bootstrap import select_startup_capability_packs

        select_startup_capability_packs(selected_packs)

    from synapse_mcp.app.facade.projections import SurfaceMode

    from .config import ModernAdapterConfig
    from .server import build_runtime, run_runtime

    values = {
        "surface": SurfaceMode(args.surface),
        # The launcher selection has already assembled the process-global
        # catalog. Leaving this override empty avoids re-discovering providers
        # when a selected pack pulled in dependencies such as core.
        "capability_packs": (),
        "transport": args.transport,
        "server_name": args.server_name,
        "audience": args.audience,
        "host": args.host,
        "port": args.port,
        "remote_enabled": args.enable_remote,
        "identity_bindings_path": args.identity_bindings,
        "stdio_principal": args.stdio_principal,
        "http_token_map_path": args.http_token_map,
        "request_state_keyring_path": args.request_state_keyring,
        "allow_ephemeral_request_state": args.allow_ephemeral_request_state,
        "request_state_ttl_seconds": args.request_state_ttl,
        "allowed_hosts": tuple(args.allowed_host),
        "allowed_origins": tuple(args.allowed_origin),
        "tls_termination": args.tls_termination,
        "trusted_proxies": tuple(args.trusted_proxy),
        "tls_certfile": args.tls_certfile,
        "tls_keyfile": args.tls_keyfile,
        "observability": args.observability,
    }
    if args.state_dir is not None:
        values["state_dir"] = args.state_dir
    run_runtime(build_runtime(ModernAdapterConfig(**values)))


if __name__ == "__main__":
    main()
