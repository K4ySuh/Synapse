# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Typed, transport-independent State Store failures."""

from __future__ import annotations


class StateStoreError(RuntimeError):
    """Base failure with a stable machine-readable reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class StateReadinessError(StateStoreError):
    pass


class StateConflictError(StateStoreError):
    pass


class StateBusyError(StateConflictError):
    """Bounded lock wait expired before any durable truth was attempted."""

    retryable = True


class StateCommitUnknownError(StateStoreError):
    """Commit returned an ambiguous outcome and must never be blindly retried."""

    retryable = False


class StateIntegrityError(StateStoreError):
    pass


class StateSelectionError(StateStoreError):
    pass


class ArtifactStoreError(StateStoreError):
    pass


class ArtifactLimitError(ArtifactStoreError):
    pass


class ArtifactCollisionError(ArtifactStoreError):
    pass
