# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Fail-fast capability-pack startup errors."""


class CapabilityPackError(RuntimeError):
    """Base error for invalid or unavailable startup pack assembly."""


class CapabilityPackDiscoveryError(CapabilityPackError):
    """An installed entry point could not provide a valid manifest."""


class CapabilityPackValidationError(CapabilityPackError):
    """A manifest, dependency, contribution, or ownership contract is invalid."""


class CapabilityPackCompatibilityError(CapabilityPackValidationError):
    """A pack does not support the running Synapse application version."""
