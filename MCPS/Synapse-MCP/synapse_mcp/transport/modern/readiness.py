# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Non-mutating modern adapter readiness checks used by local setup tooling."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
import os
from pathlib import Path

from synapse_mcp.app.facade.projections import SurfaceMode

from .config import ModernAdapterConfig, ModernConfigurationError, load_rotation_keyring, require_private_file
from .identity import AuthorityBindingResolver


@dataclass(frozen=True, slots=True)
class ModernReadiness:
    ready: bool
    checks: tuple[str, ...]
    failures: tuple[str, ...]


def check_modern_readiness(
    *,
    identity_bindings: Path,
    request_state_keyring: Path,
    state_dir: Path,
    principal: str,
    workspace_id: str = "",
) -> ModernReadiness:
    checks: list[str] = []
    failures: list[str] = []
    try:
        sdk_version = version("mcp")
    except PackageNotFoundError:
        failures.append("official Python SDK mcp==2.0.0 is not installed")
    else:
        if sdk_version != "2.0.0":
            failures.append(f"official Python SDK must be mcp==2.0.0, found {sdk_version}")
        else:
            checks.append("official Python SDK mcp==2.0.0")

    resolver: AuthorityBindingResolver | None = None
    if not identity_bindings.expanduser().is_file():
        failures.append(f"private identity binding file is missing: {identity_bindings.expanduser()}")
    else:
        try:
            require_private_file(identity_bindings, label="identity binding file")
            resolver = AuthorityBindingResolver(identity_bindings)
            checks.append("private identity binding file")
        except (OSError, ModernConfigurationError, ValueError) as exc:
            failures.append(str(exc))
    if not request_state_keyring.expanduser().is_file():
        failures.append(f"private request-state keyring is missing: {request_state_keyring.expanduser()}")
    else:
        try:
            load_rotation_keyring(request_state_keyring)
            checks.append("private request-state keyring")
        except (OSError, ModernConfigurationError, ValueError) as exc:
            failures.append(str(exc))

    resolved_state = state_dir.expanduser().resolve(strict=False)
    if not resolved_state.is_dir():
        failures.append(f"modern state directory does not exist: {resolved_state}")
    elif not os.access(resolved_state, os.W_OK | os.X_OK):
        failures.append(f"modern state directory is not writable: {resolved_state}")
    else:
        checks.append("writable modern state directory")

    if not principal.strip():
        failures.append("stdio principal is empty")
    elif resolver is not None:
        try:
            binding = resolver.resolve(principal, workspace_id)
        except (PermissionError, ModernConfigurationError, ValueError) as exc:
            failures.append(f"authority binding is not resolvable: {exc}")
        else:
            if not binding.workspace_id and not workspace_id:
                failures.append("authority binding has no default workspace")
            else:
                checks.append("resolvable principal/workspace authority binding")
    if resolver is not None and request_state_keyring.expanduser().is_file() and resolved_state.is_dir():
        try:
            ModernAdapterConfig(
                surface=SurfaceMode.MODERN_COMPACT,
                transport="stdio",
                server_name="synapse-readiness",
                audience="synapse-readiness",
                identity_bindings_path=identity_bindings,
                stdio_principal=principal,
                request_state_keyring_path=request_state_keyring,
                state_dir=resolved_state,
                observability="disabled",
            )
        except (OSError, ModernConfigurationError, ValueError) as exc:
            failures.append(f"modern startup configuration is invalid: {exc}")
        else:
            checks.append("fail-closed modern startup configuration")
    return ModernReadiness(not failures, tuple(checks), tuple(failures))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-bindings", type=Path, required=True)
    parser.add_argument("--request-state-keyring", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--workspace", default="")
    args = parser.parse_args()
    result = check_modern_readiness(
        identity_bindings=args.identity_bindings,
        request_state_keyring=args.request_state_keyring,
        state_dir=args.state_dir,
        principal=args.principal,
        workspace_id=args.workspace,
    )
    for check in result.checks:
        print(f"OK   modern: {check}")
    for failure in result.failures:
        print(f"MISS modern: {failure}")
    return 0 if result.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
