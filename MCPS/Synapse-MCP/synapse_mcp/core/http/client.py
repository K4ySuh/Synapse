# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from .backends import backend_for, session_for
from .models import HttpClientPolicy, HttpRequest, HttpResponse


def send(request: HttpRequest, *, policy: HttpClientPolicy | None = None) -> HttpResponse:
    policy = policy or HttpClientPolicy()
    return backend_for(policy).send(request, policy)


def session(policy: HttpClientPolicy | None = None):
    return session_for(policy or HttpClientPolicy())
