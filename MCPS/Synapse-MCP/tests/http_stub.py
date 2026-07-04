"""In-process HTTP stubbing for adapter/behavior tests.

Adapter tests that only need "a server that answers X" previously spun up a real
``http.server.HTTPServer`` on a loopback port and a background thread. That is slow
and occasionally flakes on port/thread timing. These helpers route Synapse's httpx
traffic to an in-process handler via ``httpx.MockTransport`` instead: the entire real
client code path (streaming, body-size limiting, cookie jar, redirect following,
error handling) still runs — only the socket layer is replaced. The actual transport
is still exercised against real servers by ``test_core_http_client.py``.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Iterator
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx

from synapse_mcp.core.http import backends

Handler = Callable[[httpx.Request], httpx.Response]


@contextmanager
def stub_httpx(handler: Handler) -> Iterator[None]:
    """Route all Synapse httpx traffic to ``handler`` for the duration of the block.

    ``handler`` takes an ``httpx.Request`` and returns an ``httpx.Response``; it is
    invoked once per request, including for each hop when redirects are followed.
    """
    real_client = httpx.Client

    def factory(*args: object, **kwargs: object) -> httpx.Client:
        # A MockTransport supersedes the socket-level knobs; drop them so httpx does
        # not reject transport + proxy/verify combinations.
        for key in ("proxy", "verify", "http2", "trust_env"):
            kwargs.pop(key, None)
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    with patch.object(backends.httpx, "Client", factory):
        yield


def route(routes: dict[str, Callable[[httpx.Request, dict[str, list[str]]], httpx.Response]], default_body: str = "ok") -> Handler:
    """Build a handler that dispatches on URL path.

    ``routes`` maps a path to a callable ``(request, query) -> httpx.Response`` where
    ``query`` is the parsed query string. Unmatched paths return a 200 ``default_body``.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        parsed = urlsplit(str(request.url))
        query = parse_qs(parsed.query)
        responder = routes.get(parsed.path)
        if responder is None:
            return httpx.Response(200, text=default_body)
        return responder(request, query)

    return handler


def text_response(status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, text=body, headers=headers or {"content-type": "text/html"})
