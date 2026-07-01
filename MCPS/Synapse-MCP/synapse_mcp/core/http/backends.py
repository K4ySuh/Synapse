# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Protocol

import httpx

from .models import HttpClientPolicy, HttpRequest, HttpResponse


class HttpBackend(Protocol):
    def send(self, request: HttpRequest, policy: HttpClientPolicy) -> HttpResponse:
        ...


class DirectHttpBackend:
    def send(self, request: HttpRequest, policy: HttpClientPolicy) -> HttpResponse:
        return _send_with_httpx(request, policy, proxy_url=None)


class ProxyHttpBackend:
    def send(self, request: HttpRequest, policy: HttpClientPolicy) -> HttpResponse:
        if not policy.proxy_url:
            return HttpResponse(status=None, error="Proxy HTTP backend requires proxy_url.")
        return _send_with_httpx(request, policy, proxy_url=policy.proxy_url)


class DisabledHttpBackend:
    def send(self, request: HttpRequest, policy: HttpClientPolicy) -> HttpResponse:
        return HttpResponse(status=None, error="HTTP traffic disabled by client policy.")


def backend_for(policy: HttpClientPolicy) -> HttpBackend:
    if policy.backend == "disabled":
        return DisabledHttpBackend()
    if policy.backend == "proxy":
        return ProxyHttpBackend()
    return DirectHttpBackend()


class HttpSession:
    def __init__(self, policy: HttpClientPolicy):
        self.policy = policy
        self.proxy_url = policy.proxy_url if policy.backend == "proxy" else None
        self.client: httpx.Client | None = None

    def __enter__(self) -> "HttpSession":
        if self.policy.backend in {"direct", "proxy"} and (self.policy.backend != "proxy" or self.policy.proxy_url):
            self.client = _build_client(self.policy, self.proxy_url)
        return self

    def __exit__(self, *_: object) -> None:
        if self.client is not None:
            self.client.close()

    def send(self, request: HttpRequest, *, timeout_seconds: float | None = None) -> HttpResponse:
        if self.policy.backend == "disabled":
            return HttpResponse(status=None, error="HTTP traffic disabled by client policy.")
        if self.policy.backend == "proxy" and not self.policy.proxy_url:
            return HttpResponse(status=None, error="Proxy HTTP backend requires proxy_url.")
        if self.client is None:
            policy = self.policy if timeout_seconds is None else HttpClientPolicy(
                backend=self.policy.backend,
                timeout_seconds=timeout_seconds,
                max_body_bytes=self.policy.max_body_bytes,
                follow_redirects=self.policy.follow_redirects,
                proxy_url=self.policy.proxy_url,
                verify_tls=self.policy.verify_tls,
                http2=self.policy.http2,
            )
            return _send_with_httpx(request, policy, proxy_url=self.proxy_url)
        return _send_with_client(self.client, request, self.policy, timeout_seconds=timeout_seconds)


def session_for(policy: HttpClientPolicy) -> HttpSession:
    return HttpSession(policy)


def _build_client(policy: HttpClientPolicy, proxy_url: str | None) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(policy.timeout_seconds),
        follow_redirects=policy.follow_redirects,
        proxy=proxy_url,
        verify=policy.verify_tls,
        http2=policy.http2,
        trust_env=False,
    )


def _send_with_httpx(request: HttpRequest, policy: HttpClientPolicy, *, proxy_url: str | None) -> HttpResponse:
    try:
        with _build_client(policy, proxy_url) as client:
            return _send_with_client(client, request, policy)
    except httpx.HTTPError as exc:
        return HttpResponse(status=None, headers={}, body="", error=str(exc))


def _send_with_client(client: httpx.Client, request: HttpRequest, policy: HttpClientPolicy, *, timeout_seconds: float | None = None) -> HttpResponse:
    try:
        stream_kwargs: dict[str, object] = {
            "headers": request.headers,
            "content": request.body_bytes,
        }
        if timeout_seconds is not None:
            stream_kwargs["timeout"] = httpx.Timeout(max(float(timeout_seconds), 0.1))
        with client.stream(
            request.method,
            request.url,
            **stream_kwargs,
        ) as response:
            body = _read_limited_text(response, policy.max_body_bytes)
            return HttpResponse(
                status=response.status_code,
                headers={str(name): str(value) for name, value in response.headers.items()},
                body=body,
                error="",
                url=str(response.url),
                cookies=[
                    {
                        "name": str(cookie.name),
                        "value": str(cookie.value),
                        "domain": str(cookie.domain or ""),
                        "domainSpecified": str(bool(cookie.domain_specified)).lower(),
                        "path": str(cookie.path or ""),
                    }
                    for cookie in client.cookies.jar
                ],
            )
    except httpx.HTTPError as exc:
        return HttpResponse(status=None, headers={}, body="", error=str(exc))


def _read_limited_text(response: httpx.Response, max_body_bytes: int) -> str:
    if max_body_bytes <= 0:
        return ""
    chunks: list[bytes] = []
    bytes_read = 0
    for chunk in response.iter_bytes():
        remaining = max_body_bytes - bytes_read
        if remaining <= 0:
            break
        piece = chunk[:remaining]
        chunks.append(piece)
        bytes_read += len(piece)
        if len(chunk) > remaining:
            break
    encoding = response.encoding or "utf-8"
    return b"".join(chunks).decode(encoding, errors="replace")
