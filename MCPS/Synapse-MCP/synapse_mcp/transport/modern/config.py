# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed startup configuration for the production modern adapter."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
from typing import Literal

from synapse_mcp.app.facade.projections import SurfaceMode
from synapse_mcp.core import paths


TransportMode = Literal["stdio", "streamable-http"]
TlsTermination = Literal["local", "direct", "trusted-proxy"]
ObservabilityMode = Literal["disabled", "otel"]


class ModernConfigurationError(ValueError):
    """Unsafe or contradictory modern adapter configuration."""


def is_loopback_host(host: str) -> bool:
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def require_private_file(path: Path, *, label: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file():
        raise ModernConfigurationError(f"{label} must identify a regular file")
    if os.name == "posix" and resolved.stat().st_mode & 0o077:
        raise ModernConfigurationError(f"{label} must not be accessible by group or other users")
    return resolved


def load_rotation_keyring(path: Path) -> tuple[bytes, ...]:
    resolved = require_private_file(path, label="request-state keyring")
    try:
        document = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModernConfigurationError("request-state keyring is unreadable") from exc
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ModernConfigurationError("request-state keyring must use schema version 1")
    raw_keys = document.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
        raise ModernConfigurationError("request-state keyring must contain an ordered non-empty keys list")
    keys: list[bytes] = []
    for index, value in enumerate(raw_keys):
        if not isinstance(value, str):
            raise ModernConfigurationError(f"request-state key {index} must be encoded as hex: or base64:")
        try:
            if value.startswith("hex:"):
                decoded = bytes.fromhex(value[4:])
            elif value.startswith("base64:"):
                import base64

                decoded = base64.b64decode(value[7:], validate=True)
            else:
                raise ValueError("unknown encoding")
        except ValueError as exc:
            raise ModernConfigurationError(f"request-state key {index} has invalid encoding") from exc
        if len(decoded) < 32:
            raise ModernConfigurationError(f"request-state key {index} must contain at least 32 bytes")
        keys.append(decoded)
    if len(set(keys)) != len(keys):
        raise ModernConfigurationError("request-state rotation keys must be unique")
    return tuple(keys)


@dataclass(frozen=True, slots=True)
class ModernAdapterConfig:
    surface: SurfaceMode
    transport: TransportMode
    server_name: str
    audience: str
    host: str = "127.0.0.1"
    port: int = 8765
    remote_enabled: bool = False
    identity_bindings_path: Path | None = None
    stdio_principal: str = ""
    http_token_map_path: Path | None = None
    request_state_keyring_path: Path | None = None
    allow_ephemeral_request_state: bool = False
    request_state_ttl_seconds: float = 600.0
    allowed_hosts: tuple[str, ...] = ()
    allowed_origins: tuple[str, ...] = ()
    tls_termination: TlsTermination = "local"
    trusted_proxies: tuple[str, ...] = ()
    tls_certfile: Path | None = None
    tls_keyfile: Path | None = None
    state_dir: Path = paths.DATA_DIR / "modern-adapter"
    observability: ObservabilityMode = "otel"

    def __post_init__(self) -> None:
        try:
            surface = SurfaceMode(self.surface)
        except ValueError as exc:
            raise ModernConfigurationError(f"unknown modern surface: {self.surface}") from exc
        if surface is SurfaceMode.LEGACY:
            raise ModernConfigurationError("the production modern adapter cannot select the frozen legacy surface")
        object.__setattr__(self, "surface", surface)
        if self.transport not in {"stdio", "streamable-http"}:
            raise ModernConfigurationError(f"unknown modern transport: {self.transport}")
        if not self.server_name.strip() or not self.audience.strip():
            raise ModernConfigurationError("stable server name and request-state audience are required")
        if not (1 <= self.port <= 65535):
            raise ModernConfigurationError("port must be between 1 and 65535")
        if not (self.request_state_ttl_seconds > 0):
            raise ModernConfigurationError("request-state TTL must be positive")
        if self.observability not in {"disabled", "otel"}:
            raise ModernConfigurationError(f"unknown observability mode: {self.observability}")
        state_dir = self.state_dir.expanduser().resolve()
        try:
            state_dir.relative_to(paths.DATA_DIR.resolve())
        except ValueError as exc:
            raise ModernConfigurationError("modern adapter state must remain under SYNAPSE_DATA_DIR") from exc
        object.__setattr__(self, "state_dir", state_dir)
        if self.identity_bindings_path is None:
            raise ModernConfigurationError("a server-held principal/authority binding file is required")
        require_private_file(self.identity_bindings_path, label="identity binding file")
        if self.request_state_keyring_path is None:
            if not self.allow_ephemeral_request_state:
                raise ModernConfigurationError(
                    "request-state keyring is required unless explicit local ephemeral mode is enabled"
                )
            if self.remote_enabled or not is_loopback_host(self.host):
                raise ModernConfigurationError("ephemeral request-state keys are restricted to local single-process mode")
        else:
            load_rotation_keyring(self.request_state_keyring_path)
        if self.transport == "stdio":
            if not self.stdio_principal.strip():
                raise ModernConfigurationError("stdio requires an operator-configured local principal")
            if self.http_token_map_path is not None or self.remote_enabled:
                raise ModernConfigurationError("stdio cannot accept HTTP identity or remote-enablement settings")
            if self.tls_termination != "local" or self.trusted_proxies or self.allowed_hosts or self.allowed_origins:
                raise ModernConfigurationError("stdio cannot accept HTTP host, origin, proxy, or TLS settings")
            return
        if self.http_token_map_path is None:
            raise ModernConfigurationError("Streamable HTTP requires an authenticated token-to-principal resolver")
        require_private_file(self.http_token_map_path, label="HTTP token map")
        loopback = is_loopback_host(self.host)
        if not loopback:
            if not self.remote_enabled:
                raise ModernConfigurationError("non-loopback HTTP binding requires explicit remote enablement")
            if self.request_state_keyring_path is None:
                raise ModernConfigurationError("remote HTTP requires a persistent request-state keyring")
            if not self.allowed_hosts or not self.allowed_origins:
                raise ModernConfigurationError("remote HTTP requires explicit allowed hosts and origins")
            if any(not value.strip() or value.strip() == "*" for value in self.allowed_hosts):
                raise ModernConfigurationError("remote HTTP allowed hosts must be explicit non-wildcard values")
            if any(
                not value.strip()
                or value.strip() == "*"
                or not value.strip().lower().startswith("https://")
                for value in self.allowed_origins
            ):
                raise ModernConfigurationError("remote HTTP allowed origins must be explicit HTTPS origins")
            if self.tls_termination == "local":
                raise ModernConfigurationError("remote HTTP requires direct TLS or declared trusted-proxy termination")
        elif self.remote_enabled:
            raise ModernConfigurationError("remote enablement is contradictory with a loopback bind")
        if self.tls_termination == "direct":
            if self.tls_certfile is None or self.tls_keyfile is None:
                raise ModernConfigurationError("direct TLS requires certificate and private-key files")
            self.tls_certfile.expanduser().resolve(strict=True)
            require_private_file(self.tls_keyfile, label="TLS private key")
            if self.trusted_proxies:
                raise ModernConfigurationError("direct TLS cannot also trust forwarded proxy headers")
        elif self.tls_termination == "trusted-proxy":
            if not self.trusted_proxies:
                raise ModernConfigurationError("trusted-proxy TLS termination requires explicit proxy networks")
            for network in self.trusted_proxies:
                try:
                    ipaddress.ip_network(network, strict=False)
                except ValueError as exc:
                    raise ModernConfigurationError(f"invalid trusted proxy network: {network}") from exc
            if self.tls_certfile is not None or self.tls_keyfile is not None:
                raise ModernConfigurationError("trusted-proxy termination cannot also configure direct TLS files")
        elif self.tls_termination != "local":
            raise ModernConfigurationError(f"unknown TLS termination policy: {self.tls_termination}")
        if loopback and self.tls_termination != "local":
            raise ModernConfigurationError("loopback development HTTP uses the local TLS policy")
