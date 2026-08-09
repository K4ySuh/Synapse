# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Protocol
from urllib.parse import urljoin

import httpx

from ..execution import CanonicalTarget, ExecutionPlanError
from ..url_hygiene import redact_url_query_values
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
                max_redirects=self.policy.max_redirects,
                execution_plan=self.policy.execution_plan,
                proxy_credential_ref=self.policy.proxy_credential_ref,
                proxy_headers=self.policy.proxy_headers,
            )
            return _send_with_httpx(request, policy, proxy_url=self.proxy_url)
        return _send_with_client(self.client, request, self.policy, timeout_seconds=timeout_seconds)


def session_for(policy: HttpClientPolicy) -> HttpSession:
    return HttpSession(policy)


def _build_client(policy: HttpClientPolicy, proxy_url: str | None) -> httpx.Client:
    proxy: str | httpx.Proxy | None = proxy_url
    if proxy_url and policy.proxy_headers:
        proxy = httpx.Proxy(proxy_url, headers=policy.proxy_headers)
    return httpx.Client(
        timeout=httpx.Timeout(policy.timeout_seconds),
        # Redirects are advanced manually so every next hop can be checked
        # against the same execution target envelope policy reviewed.
        follow_redirects=False,
        proxy=proxy,
        verify=policy.verify_tls,
        http2=policy.http2,
        trust_env=False,
    )


def _send_with_httpx(request: HttpRequest, policy: HttpClientPolicy, *, proxy_url: str | None) -> HttpResponse:
    try:
        if policy.execution_plan is not None:
            policy.execution_plan.assert_http_policy(policy.backend, policy.proxy_url, policy.proxy_credential_ref)
        with _build_client(policy, proxy_url) as client:
            return _send_with_client(client, request, policy)
    except (httpx.HTTPError, ExecutionPlanError) as exc:
        return HttpResponse(status=None, headers={}, body="", error=str(exc))


def _send_with_client(client: httpx.Client, request: HttpRequest, policy: HttpClientPolicy, *, timeout_seconds: float | None = None) -> HttpResponse:
    try:
        if policy.execution_plan is not None:
            policy.execution_plan.assert_http_policy(policy.backend, policy.proxy_url, policy.proxy_credential_ref)
        current_url = request.url
        current_method = request.method
        current_headers = dict(request.headers)
        current_body = request.body_bytes
        redirect_chain: list[dict[str, object]] = []
        seen: set[str] = set()
        redirect_hop: int | None = None
        while True:
            if policy.execution_plan is not None:
                policy.execution_plan.assert_http_request(current_url, current_method, redirect_hop=redirect_hop)
            stream_kwargs: dict[str, object] = {"headers": current_headers, "content": current_body}
            if timeout_seconds is not None:
                stream_kwargs["timeout"] = httpx.Timeout(max(float(timeout_seconds), 0.1))
            with client.stream(current_method, current_url, **stream_kwargs) as response:
                headers = {str(name): str(value) for name, value in response.headers.items()}
                location = headers.get("location", "")
                if policy.follow_redirects and response.status_code in {301, 302, 303, 307, 308} and location:
                    next_url = urljoin(str(response.url), location)
                    next_hop = len(redirect_chain) + 1
                    if next_hop > policy.max_redirects:
                        raise ExecutionPlanError("redirect_limit_exceeded", "HTTP redirect hop limit was exceeded.")
                    if next_url in seen:
                        raise ExecutionPlanError("redirect_loop", "HTTP redirect loop detected before the next connection.")
                    if policy.execution_plan is not None:
                        policy.execution_plan.assert_http_request(next_url, current_method, redirect_hop=next_hop)
                    redirect_chain.append(
                        {
                            "hop": next_hop,
                            "status": response.status_code,
                            "from": redact_url_query_values(str(response.url)),
                            "to": redact_url_query_values(next_url),
                        }
                    )
                    seen.add(current_url)
                    previous = CanonicalTarget.from_url(current_url)
                    following = CanonicalTarget.from_url(next_url)
                    if previous.origin != following.origin:
                        current_headers = {
                            name: value
                            for name, value in current_headers.items()
                            if name.lower() not in {"authorization", "cookie", "proxy-authorization"}
                        }
                    if response.status_code == 303 or (response.status_code in {301, 302} and current_method == "POST"):
                        current_method = "GET"
                        current_body = None
                        current_headers = {
                            name: value
                            for name, value in current_headers.items()
                            if name.lower() not in {"content-length", "content-type", "transfer-encoding"}
                        }
                    current_url = next_url
                    redirect_hop = next_hop
                    continue
                body = _read_limited_text(response, policy.max_body_bytes)
                return HttpResponse(
                    status=response.status_code,
                    headers=headers,
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
                    redirect_chain=redirect_chain,
                )
    except (httpx.HTTPError, ExecutionPlanError) as exc:
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
