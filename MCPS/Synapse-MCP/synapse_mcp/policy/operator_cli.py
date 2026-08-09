# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Minimal local operator CLI for durable Authority Grants."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .authority import AuthorityGrant
from .operator_service import AuthorityOperatorService, OperatorPrincipal


def _grant_file(path: str) -> AuthorityGrant:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Grant file must contain one JSON object.")
    return AuthorityGrant.from_dict(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Workspace-local authority store")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list-grants")
    inspect = commands.add_parser("inspect-grant")
    inspect.add_argument("grant_id")
    inspect.add_argument("--revision", type=int)
    create = commands.add_parser("create-grant")
    create.add_argument("grant_file")
    revise = commands.add_parser("revise-grant")
    revise.add_argument("grant_file")
    revise.add_argument("--expected-revision", required=True, type=int)
    revoke = commands.add_parser("revoke-grant")
    revoke.add_argument("grant_id")
    revoke.add_argument("--expected-revision", required=True, type=int)
    step_up = commands.add_parser("issue-step-up")
    step_up.add_argument("grant_id")
    step_up.add_argument("grant_revision", type=int)
    step_up.add_argument("plan_fingerprint")
    step_up.add_argument("idempotency_key")
    step_up.add_argument("--expires-in", type=int, default=300)
    required = commands.add_parser("inspect-request")
    required.add_argument("request_state_id")
    resume = commands.add_parser("resume-request")
    resume.add_argument("request_state_id")
    reconcile = commands.add_parser("reconcile-dispatch")
    reconcile.add_argument("dispatch_id")
    reconcile.add_argument("resolution", choices=("succeeded", "failed", "cancelled"))
    adopt = commands.add_parser("adopt-legacy-job")
    adopt.add_argument("job_id")
    adopt.add_argument("grant_id")
    adopt.add_argument("--session", required=True)
    usage = commands.add_parser("usage")
    usage.add_argument("grant_id")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    service = AuthorityOperatorService(args.workspace, OperatorPrincipal.current_local())
    result: Any
    if args.command == "list-grants":
        result = [item.to_dict() for item in service.list_grants()]
    elif args.command == "inspect-grant":
        result = service.inspect_grant(args.grant_id, args.revision).to_dict()
    elif args.command == "create-grant":
        result = service.create_grant(_grant_file(args.grant_file)).to_dict()
    elif args.command == "revise-grant":
        result = service.revise_grant(
            _grant_file(args.grant_file),
            expected_grant_revision=args.expected_revision,
        ).to_dict()
    elif args.command == "revoke-grant":
        result = service.revoke_grant(
            args.grant_id,
            expected_grant_revision=args.expected_revision,
        ).to_dict()
    elif args.command == "issue-step-up":
        result = {
            "stepUpId": service.issue_step_up(
                grant_id=args.grant_id,
                grant_revision=args.grant_revision,
                plan_fingerprint=args.plan_fingerprint,
                idempotency_key=args.idempotency_key,
                expires_in_seconds=args.expires_in,
            )
        }
    elif args.command == "inspect-request":
        result = service.inspect_required_authority(args.request_state_id)
    elif args.command == "resume-request":
        result = service.resume_request_state(args.request_state_id)
    elif args.command == "reconcile-dispatch":
        result = service.reconcile_or_cancel_dispatch(args.dispatch_id, args.resolution)
    elif args.command == "adopt-legacy-job":
        result = service.adopt_legacy_job(
            args.job_id,
            args.grant_id,
            authority_session_id=args.session,
        )
    else:
        result = service.inspect_usage(args.grant_id)
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
