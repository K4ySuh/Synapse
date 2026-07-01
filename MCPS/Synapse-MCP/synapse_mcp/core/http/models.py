# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


HttpBackendName = Literal["direct", "proxy", "disabled"]


@dataclass
class HttpRequest:
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | str | None = None

    def __post_init__(self) -> None:
        self.method = str(self.method or "GET").upper()
        self.url = str(self.url)
        self.headers = {str(name): str(value) for name, value in self.headers.items()}

    @property
    def body_bytes(self) -> bytes | None:
        if self.body is None:
            return None
        if isinstance(self.body, bytes):
            return self.body
        return str(self.body).encode("utf-8")


@dataclass
class HttpResponse:
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""
    url: str = ""
    cookies: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "headers": self.headers,
            "body": self.body,
            "error": self.error,
        }


@dataclass
class HttpClientPolicy:
    backend: HttpBackendName = "direct"
    timeout_seconds: float = 10
    max_body_bytes: int = 12_000
    follow_redirects: bool = True
    proxy_url: str | None = None
    verify_tls: bool = True
    http2: bool = False

    def __post_init__(self) -> None:
        if self.backend not in {"direct", "proxy", "disabled"}:
            raise ValueError(f"Unsupported HTTP backend: {self.backend}")
        self.timeout_seconds = max(float(self.timeout_seconds), 0.1)
        self.max_body_bytes = max(int(self.max_body_bytes), 0)

    @classmethod
    def from_args(cls, args: dict[str, Any] | None, *, timeout_seconds: float | None = None) -> "HttpClientPolicy":
        args = args or {}
        backend = str(args.get("httpBackend") or args.get("backend") or "direct").lower()
        if args.get("disableTraffic") is True:
            backend = "disabled"
        return cls(
            backend=backend,  # type: ignore[arg-type]
            timeout_seconds=timeout_seconds if timeout_seconds is not None else float(args.get("requestTimeout", 10)),
            max_body_bytes=int(args.get("maxBodyBytes", 12_000)),
            follow_redirects=bool(args.get("followRedirects", True)),
            proxy_url=args.get("proxyUrl") or args.get("proxy"),
            verify_tls=bool(args.get("verifyTls", True)),
            http2=bool(args.get("http2", False)),
        )
