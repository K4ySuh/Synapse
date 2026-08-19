# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Protocol-free bridge to the retained frozen implementation adapter."""

from __future__ import annotations

import json
from typing import Any, Callable

from synapse_mcp.core.errors import McpError
from synapse_mcp.core.execution import ExecutionPlanError

from .descriptor import ActionRequest
from .outcomes import (
    ExecutionFailure,
    Success,
    ValidationFailure,
    legacy_payload_signals_error,
    outcome_from_mcp_error,
)


RetainedImplementation = Callable[[str, dict[str, Any]], str]
_retained_implementation: RetainedImplementation | None = None


def bind_retained_legacy_implementation(implementation: RetainedImplementation) -> None:
    """Bind the independently retained adapter after transport initialization."""

    global _retained_implementation
    _retained_implementation = implementation


def retained_legacy_implementation_bound() -> bool:
    return _retained_implementation is not None


class RetainedLegacyExecutor:
    """Execute one migrated descriptor through its frozen implementation branch."""

    def __init__(
        self,
        legacy_name: str,
        serializer: str,
        input_model: type,
        output_model: type,
        *,
        confirm_declared: bool,
    ) -> None:
        self.legacy_name = legacy_name
        self.serializer = serializer
        self.input_model = input_model
        self.output_model = output_model
        self.confirm_declared = confirm_declared

    def __call__(self, request: ActionRequest):
        implementation = _retained_implementation
        if implementation is None:
            return ExecutionFailure(
                message=f"{self.legacy_name}: retained implementation adapter is not bound",
                legacy_code=-32000,
                reason_code="implementation_not_bound",
            )
        args = request.input.model_dump(by_alias=True, exclude_unset=True)
        plan = request.context.execution_plan
        try:
            if plan is None:
                raise ExecutionPlanError(
                    "execution_plan_missing",
                    f"{self.legacy_name}: canonical execution plan is missing",
                )
            plan.assert_runtime_input(args)
            legacy_args = dict(args)
            if (
                self.confirm_declared
                and request.context.execution_profile != "legacy"
                and request.context.authorization_receipt is not None
            ):
                legacy_args["confirm"] = True
            serialized = implementation(self.legacy_name, legacy_args)
        except ExecutionPlanError as exc:
            return ValidationFailure(str(exc), legacy_code=-32602, reason_code=exc.reason_code)
        except McpError as exc:
            return outcome_from_mcp_error(
                exc,
                confirm_declared=self.confirm_declared,
                confirm_value=args.get("confirm"),
            )
        try:
            payload = json.loads(serialized)
        except (TypeError, json.JSONDecodeError):
            return ExecutionFailure(
                message=f"{self.legacy_name}: retained implementation returned invalid JSON",
                legacy_code=-32000,
                reason_code="invalid_legacy_json",
            )
        legacy_payload: object = serialized if self.serializer == "executor" else payload
        return Success(
            payload=payload,
            payload_signals_error=legacy_payload_signals_error(payload),
            legacy_payload=legacy_payload,
        )
