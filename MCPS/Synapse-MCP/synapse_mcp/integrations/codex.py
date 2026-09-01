# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Locate and validate the Codex configuration and skill distribution assets."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sysconfig


CONFIG_PROFILES = ("standard", "core-only", "modern-direct", "legacy", "multi-agent-compat")
SKILL_PROFILES = ("default", "multi-agent-compat", "development")
OPERATING_SKILLS = (
    "operate-synapse",
    "synapse-web-pentesting",
    "synapse-cve-intelligence",
)
MULTI_AGENT_COMPAT_SKILLS = (
    "operate-synapse",
    "synapse-coordinate-engagement",
    "synapse-engagement-bootstrap",
    "synapse-perimeter-triage",
    "synapse-web-assessment",
    "synapse-access-control",
    "synapse-cve-validation",
    "synapse-reporting",
)
DEVELOPMENT_SKILLS = ("synapse-developing",)
PROFILE_SKILLS = {
    "default": OPERATING_SKILLS,
    "multi-agent-compat": MULTI_AGENT_COMPAT_SKILLS,
    "development": DEVELOPMENT_SKILLS,
}


class CodexAssetError(RuntimeError):
    """The installed or repository Codex asset package is incomplete."""


def _repository_root() -> Path | None:
    candidate = Path(__file__).resolve().parents[4]
    if (candidate / "skills" / "codex").is_dir() and (candidate / "config" / "codex").is_dir():
        return candidate
    return None


def _installed_asset_roots() -> tuple[Path, ...]:
    target_relative = Path(__file__).resolve().parents[2] / "share" / "synapse-mcp" / "codex"
    prefix_relative = Path(sysconfig.get_path("data")).resolve() / "share" / "synapse-mcp" / "codex"
    return tuple(dict.fromkeys((target_relative, prefix_relative)))


def codex_skills_dir(profile: str = "default") -> Path:
    if profile not in PROFILE_SKILLS:
        raise CodexAssetError(f"Unknown Codex skill profile: {profile}")
    repository = _repository_root()
    candidates = []
    if repository is not None:
        candidates.append(repository / "skills" / "codex" / profile)
    candidates.extend(root / "skills" / profile for root in _installed_asset_roots())
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise CodexAssetError(f"Codex skill assets are unavailable; checked: {candidates}")


def codex_config_dir() -> Path:
    repository = _repository_root()
    candidates = []
    if repository is not None:
        candidates.append(repository / "config" / "codex")
    candidates.extend(root / "config" for root in _installed_asset_roots())
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise CodexAssetError(f"Codex config assets are unavailable; checked: {candidates}")


def validate_assets() -> list[str]:
    failures: list[str] = []
    try:
        skill_roots = {profile: codex_skills_dir(profile) for profile in SKILL_PROFILES}
    except CodexAssetError as exc:
        failures.append(str(exc))
        skill_roots = {}
    try:
        configs = codex_config_dir()
    except CodexAssetError as exc:
        failures.append(str(exc))
        configs = None

    for profile, skills in skill_roots.items():
        for name in PROFILE_SKILLS[profile]:
            skill = skills / name / "SKILL.md"
            interface = skills / name / "agents" / "openai.yaml"
            if not skill.is_file():
                failures.append(f"missing {profile} skill: {skill}")
                continue
            if not interface.is_file():
                failures.append(f"missing {profile} interface metadata: {interface}")
            text = skill.read_text(encoding="utf-8")
            for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
                if target.startswith(("http://", "https://", "#")):
                    continue
                linked = (skill.parent / target.split("#", 1)[0]).resolve()
                if not linked.is_file():
                    failures.append(f"{skill}: missing reference {target}")

    if configs is not None:
        for profile in CONFIG_PROFILES:
            path = configs / f"{profile}.toml"
            if not path.is_file():
                failures.append(f"missing Codex config profile: {path}")
    return sorted(set(failures))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--skills-dir",
        action="store_true",
        help="Print the default three-skill operating profile directory.",
    )
    group.add_argument(
        "--skills-profile",
        choices=SKILL_PROFILES,
        help="Print one explicitly selected shipped Codex skill profile directory.",
    )
    group.add_argument("--config", choices=CONFIG_PROFILES, help="Print one shipped Codex MCP config example.")
    group.add_argument("--verify", action="store_true", help="Validate shipped skills, references, and configs.")
    args = parser.parse_args()
    try:
        if args.skills_dir:
            print(codex_skills_dir())
        elif args.skills_profile:
            print(codex_skills_dir(args.skills_profile))
        elif args.config:
            print((codex_config_dir() / f"{args.config}.toml").read_text(encoding="utf-8"), end="")
        else:
            failures = validate_assets()
            if failures:
                for failure in failures:
                    print(f"FAIL {failure}")
                return 1
            print(
                "Codex distribution assets are current: "
                f"{len(OPERATING_SKILLS)} default operating skills, "
                f"{len(MULTI_AGENT_COMPAT_SKILLS)} compatibility skills, "
                f"{len(CONFIG_PROFILES)} configs"
            )
    except (CodexAssetError, OSError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
