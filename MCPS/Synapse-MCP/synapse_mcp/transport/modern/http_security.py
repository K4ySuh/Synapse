# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Narrow ASGI authentication and forwarded-header trust boundary."""

from __future__ import annotations

import ipaddress
from typing import Any, Awaitable, Callable

from .config import ModernAdapterConfig
from .identity import CURRENT_HTTP_PRINCIPAL, TokenPrincipalResolver


class AuthenticatedHTTPMiddleware:
    def __init__(self, app: Any, *, config: ModernAdapterConfig, tokens: TokenPrincipalResolver) -> None:
        self.app = app
        self.config = config
        self.tokens = tokens
        self._trusted = tuple(ipaddress.ip_network(value, strict=False) for value in config.trusted_proxies)

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Awaitable[Any]], send: Callable[..., Awaitable[Any]]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers: dict[str, list[str]] = {}
        for raw_name, raw_value in scope.get("headers", []):
            name = raw_name.decode("latin-1").lower()
            headers.setdefault(name, []).append(raw_value.decode("latin-1"))
        forwarded = headers.get("forwarded", [])
        x_forwarded_names = {name for name in headers if name.startswith("x-forwarded-")}
        x_forwarded = [value for name in x_forwarded_names for value in headers[name]]
        if forwarded and x_forwarded:
            await self._reject(send, 400, b"Ambiguous forwarded headers")
            return
        if x_forwarded_names.difference({"x-forwarded-proto"}):
            await self._reject(send, 400, b"Unsupported forwarded headers")
            return
        if forwarded or x_forwarded:
            if self.config.tls_termination != "trusted-proxy" or not self._peer_is_trusted(scope):
                await self._reject(send, 400, b"Untrusted forwarded headers")
                return
            if not self._forwarded_https(headers):
                await self._reject(send, 400, b"Trusted proxy must assert one HTTPS scheme")
                return
        authorization = headers.get("authorization", [])
        if len(authorization) != 1:
            await self._reject(send, 401, b"Bearer authentication required", authenticate=True)
            return
        try:
            principal = self.tokens.authenticate(authorization[0])
        except PermissionError:
            await self._reject(send, 401, b"Bearer authentication required", authenticate=True)
            return
        token = CURRENT_HTTP_PRINCIPAL.set(principal)
        try:
            async def no_store_send(message: dict[str, Any]) -> None:
                if message.get("type") == "http.response.start":
                    headers = list(message.get("headers") or [])
                    if not any(name.lower() == b"cache-control" for name, _value in headers):
                        headers.append((b"cache-control", b"private, no-store"))
                    message = {**message, "headers": headers}
                await send(message)

            await self.app(scope, receive, no_store_send)
        finally:
            CURRENT_HTTP_PRINCIPAL.reset(token)

    def _peer_is_trusted(self, scope: dict[str, Any]) -> bool:
        client = scope.get("client")
        if not isinstance(client, (tuple, list)) or not client:
            return False
        try:
            address = ipaddress.ip_address(str(client[0]))
        except ValueError:
            return False
        return any(address in network for network in self._trusted)

    @staticmethod
    def _forwarded_https(headers: dict[str, list[str]]) -> bool:
        if headers.get("forwarded"):
            if len(headers["forwarded"]) != 1 or "," in headers["forwarded"][0]:
                return False
            parameters: dict[str, str] = {}
            for part in headers["forwarded"][0].split(";"):
                if "=" not in part:
                    return False
                key, value = part.split("=", 1)
                normalized = key.strip().lower()
                if not normalized or normalized in parameters:
                    return False
                parameters[normalized] = value.strip().strip('"').lower()
            return parameters.get("proto") == "https"
        values = headers.get("x-forwarded-proto", [])
        return len(values) == 1 and values[0].strip().lower() == "https"

    @staticmethod
    async def _reject(send: Callable[..., Awaitable[Any]], status: int, body: bytes, *, authenticate: bool = False) -> None:
        headers = [(b"content-type", b"text/plain; charset=utf-8"), (b"cache-control", b"no-store")]
        if authenticate:
            headers.append((b"www-authenticate", b"Bearer"))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})
