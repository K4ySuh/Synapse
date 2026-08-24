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
