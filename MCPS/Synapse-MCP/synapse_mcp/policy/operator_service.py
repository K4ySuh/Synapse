# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Trusted local operator service for Phase 2 authority management."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import getpass
import os
from typing import Any

from synapse_mcp.core import evidence

from .authority import AuthorityGrant, StepUpAuthorization
from .repository import AuthorityRepositoryError, WorkspaceAuthorityRepository


@dataclass(frozen=True, slots=True)
class OperatorPrincipal:
    principal_id: str
    source: str
    authenticated: bool

    def __post_init__(self) -> None:
        if not self.principal_id or not self.authenticated:
            raise PermissionError("A trusted authenticated operator principal is required.")
        if self.source not in {"local_os", "test_fixture"}:
            raise PermissionError("Operator principal source is not trusted by the local adapter.")

    @classmethod
    def current_local(cls) -> "OperatorPrincipal":
        return cls(
            principal_id=f"local:{getpass.getuser()}:uid-{os.geteuid()}",
            source="local_os",
            authenticated=True,
        )


class AuthorityOperatorService:
    """Non-Registry service that requires a principal from a trusted adapter."""

    def __init__(self, workspace_id: str, principal: OperatorPrincipal):
        if not isinstance(principal, OperatorPrincipal):
            raise PermissionError("Operator service requires an OperatorPrincipal.")
        self.principal = principal
        self.repository = WorkspaceAuthorityRepository(workspace_id)

    def create_grant(self, grant: AuthorityGrant, *, expected_repository_revision: int | None = None) -> AuthorityGrant:
        result = self.repository.create_grant(
            replace(grant, approved_by=self.principal.principal_id),
            expected_repository_revision=expected_repository_revision,
        )
        self._audit("authority.grant_created", grant_id=result.grant_id, grant_revision=result.revision)
        return result

    def inspect_grant(self, grant_id: str, revision: int | None = None) -> AuthorityGrant:
        return self.repository.inspect_grant(grant_id, revision)

    def list_grants(self) -> tuple[AuthorityGrant, ...]:
        return self.repository.list_grants()

    def revise_grant(self, replacement: AuthorityGrant, *, expected_grant_revision: int) -> AuthorityGrant:
        result = self.repository.revise_grant(
            replace(replacement, approved_by=self.principal.principal_id),
            expected_grant_revision=expected_grant_revision,
        )
        self._audit("authority.grant_revised", grant_id=result.grant_id, grant_revision=result.revision)
        return result

    def revoke_grant(self, grant_id: str, *, expected_grant_revision: int) -> AuthorityGrant:
        result = self.repository.revoke_grant(
            grant_id,
            expected_grant_revision=expected_grant_revision,
        )
        self._audit("authority.grant_revoked", grant_id=result.grant_id, grant_revision=result.revision)
        return result

    def issue_step_up(
        self,
        *,
        grant_id: str,
        grant_revision: int,
        authorization_fingerprint: str,
        idempotency_key: str,
        expires_in_seconds: int = 300,
    ) -> str:
        if expires_in_seconds < 1:
            raise ValueError("Step-up expiry must be positive.")
        authorization = StepUpAuthorization(
            grant_id,
            grant_revision,
            authorization_fingerprint,
            idempotency_key,
            self.principal.principal_id,
            datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds),
        )
        step_up_id = self.repository.issue_step_up(authorization)
        self._audit(
            "authority.step_up_issued",
            grant_id=grant_id,
            grant_revision=grant_revision,
            authorization_fingerprint=authorization_fingerprint,
        )
        return step_up_id

    def issue_request_step_up(self, request_state_id: str, *, expires_in_seconds: int = 300) -> str:
        """Approve the exact server-held request without caller-supplied identity."""

        if expires_in_seconds < 1:
            raise ValueError("Step-up expiry must be positive.")
        state = self.repository.inspect_request_state(request_state_id)
        step_up_id = self.repository.issue_request_step_up(
            request_state_id,
            approved_by=self.principal.principal_id,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds),
        )
        self._audit(
            "authority.request_step_up_issued",
            grant_id=str(state.get("grantId") or ""),
            grant_revision=int(state.get("grantRevision") or 0),
            authorization_fingerprint=str(state.get("authorizationFingerprint") or ""),
        )
        return step_up_id

    def inspect_required_authority(self, request_state_id: str) -> dict[str, Any]:
        return self.repository.inspect_request_state(request_state_id)

    def list_required_authority(self) -> tuple[dict[str, Any], ...]:
        return self.repository.list_request_states()

    def resume_request_state(self, request_state_id: str) -> dict[str, Any]:
        """Return the exact trusted binding a local adapter may place in context."""

        state = self.repository.inspect_request_state(request_state_id)
        self._audit(
            "authority.request_resumed",
            grant_id=str(state.get("grantId") or ""),
            grant_revision=int(state.get("grantRevision") or 0),
            authorization_fingerprint=str(state.get("authorizationFingerprint") or ""),
            plan_fingerprint=str(state.get("planFingerprint") or ""),
        )
        return state

    def reconcile_or_cancel_dispatch(self, dispatch_id: str, resolution: str) -> dict[str, Any]:
        dispatch = self.repository.inspect_dispatch(dispatch_id)
        if dispatch["state"] == "authorized" and resolution == "cancelled":
            result = self.repository.transition_dispatch(dispatch_id, "cancelled")
        elif dispatch["state"] == "unknown":
            result = self.repository.reconcile_unknown(
                dispatch_id,
                resolution,
                operator_id=self.principal.principal_id,
            )
        else:
            raise AuthorityRepositoryError(
                "dispatch_reconciliation_invalid",
                "Only authorized dispatches may be cancelled and only unknown dispatches may be reconciled.",
            )
        self._audit("authority.dispatch_reconciled", dispatch_id=dispatch_id)
        return result

    def adopt_legacy_job(self, job_id: str, grant_id: str, *, authority_session_id: str) -> dict[str, Any]:
        result = self.repository.adopt_legacy_job(
            job_id,
            grant_id,
            operator_id=self.principal.principal_id,
            authority_session_id=authority_session_id,
        )
        self._audit(
            "authority.legacy_job_adopted",
            grant_id=grant_id,
            grant_revision=int(result["grantRevision"]),
            dispatch_id=str(result["dispatchId"]),
        )
        return result

    def inspect_usage(self, grant_id: str) -> dict[str, Any]:
        return {
            "workspaceId": self.repository.workspace_id,
            "grantId": grant_id,
            "budgetSemantics": "dispatch",
            "usage": self.repository.budget_usage(grant_id).to_dict(),
            "dispatches": [
                item for item in self.repository.list_dispatches() if item.get("grantId") == grant_id
            ],
        }

    def _audit(
        self,
        event_type: str,
        *,
        grant_id: str = "",
        grant_revision: int = 0,
        authorization_fingerprint: str = "",
        plan_fingerprint: str = "",
        dispatch_id: str = "",
    ) -> None:
        try:
            evidence.log_event(
                event_type,
                f"Operator {self.principal.principal_id} performed {event_type}.",
                {
                    "workspaceId": self.repository.workspace_id,
                    "operatorPrincipal": self.principal.principal_id,
                    "operatorSource": self.principal.source,
                    "grantId": grant_id,
                    "grantRevision": grant_revision,
                    "authorizationFingerprint": authorization_fingerprint,
                    "planFingerprint": plan_fingerprint,
                    "dispatchId": dispatch_id,
                },
            )
        except Exception:
            # Repository management/decision records are canonical. A failed
            # evidence mirror must not turn a committed operator mutation into
            # an apparent failure that could be retried blindly.
            return
