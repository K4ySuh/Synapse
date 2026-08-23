# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Authenticated principal resolution and server-held authority bindings."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import secrets
from typing import Any, Mapping

from .config import ModernConfigurationError, require_private_file


CURRENT_HTTP_PRINCIPAL: ContextVar[str | None] = ContextVar("synapse_modern_http_principal", default=None)
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class AuthorityBinding:
    principal_id: str
    workspace_id: str
    execution_profile: str
    authority_session_id: str
    selected_grant_id: str = ""


class AuthorityBindingResolver:
    """Reloadable exact principal/workspace bindings owned by the server."""

    def __init__(self, path: Path | None = None, *, document: Mapping[str, Any] | None = None) -> None:
        if (path is None) == (document is None):
            raise ValueError("AuthorityBindingResolver requires exactly one of path or document")
        self._path = require_private_file(path, label="identity binding file") if path is not None else None
        self._document = dict(document) if document is not None else None
        self._load()

    def resolve(self, principal_id: str, workspace_id: str = "") -> AuthorityBinding:
        document = self._load()
        principals = document["principals"]
        raw_principal = principals.get(principal_id)
        if not isinstance(raw_principal, dict):
            raise PermissionError("authenticated principal has no Synapse authority binding")
        workspaces = raw_principal.get("workspaces", {})
        raw_binding = None
        selected_workspace = workspace_id
        if workspace_id and isinstance(workspaces, dict):
            raw_binding = workspaces.get(workspace_id)
            if raw_binding is None:
                raw_binding = workspaces.get("*")
        elif not workspace_id:
            raw_binding = raw_principal.get("default")
            selected_workspace = str(raw_principal.get("defaultWorkspace") or "")
        if not isinstance(raw_binding, dict):
            raise PermissionError("principal is not bound to the requested Synapse workspace")
        profile = str(raw_binding.get("executionProfile") or "")
        session = str(raw_binding.get("authoritySessionId") or "")
        if profile not in {"observe", "supervised", "full_delegated"} or not session:
            raise ModernConfigurationError("identity binding contains an invalid authority profile or session")
        return AuthorityBinding(
            principal_id=principal_id,
            workspace_id=selected_workspace,
            execution_profile=profile,
            authority_session_id=session,
            selected_grant_id=str(raw_binding.get("selectedGrantId") or ""),
        )

    def _load(self) -> dict[str, Any]:
        if self._path is not None:
            try:
                value = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ModernConfigurationError("identity binding file is unreadable") from exc
        else:
            value = self._document
        if not isinstance(value, dict) or value.get("version") != 1 or not isinstance(value.get("principals"), dict):
            raise ModernConfigurationError("identity binding file must use schema version 1")
        return value


class TokenPrincipalResolver:
    """Resolve high-entropy bearer tokens by digest without storing token values."""

    def __init__(self, path: Path | None = None, *, token_digests: Mapping[str, str] | None = None) -> None:
        if (path is None) == (token_digests is None):
            raise ValueError("TokenPrincipalResolver requires exactly one of path or token_digests")
        self._path = require_private_file(path, label="HTTP token map") if path is not None else None
        self._digests = dict(token_digests) if token_digests is not None else None
        self._load()

    def authenticate(self, authorization: str) -> str:
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or len(token) < 32 or any(character.isspace() for character in token):
            raise PermissionError("invalid bearer authentication")
        candidate = sha256(token.encode("utf-8")).hexdigest()
        principal = ""
        for digest, value in self._load().items():
            if secrets.compare_digest(candidate, digest):
                principal = value
        if not principal:
            raise PermissionError("invalid bearer authentication")
        return principal

    def _load(self) -> dict[str, str]:
        if self._path is not None:
            try:
                document = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ModernConfigurationError("HTTP token map is unreadable") from exc
            if not isinstance(document, dict) or document.get("version") != 1:
                raise ModernConfigurationError("HTTP token map must use schema version 1")
            raw = document.get("tokenDigests")
        else:
            raw = self._digests
        if not isinstance(raw, dict) or not raw:
            raise ModernConfigurationError("HTTP token map must contain tokenDigests")
        result: dict[str, str] = {}
        for digest, principal in raw.items():
            normalized = str(digest).lower()
            if not _HEX_DIGEST.fullmatch(normalized) or not isinstance(principal, str) or not principal.strip():
                raise ModernConfigurationError("HTTP token map contains an invalid digest or principal")
            result[normalized] = principal
        return result
