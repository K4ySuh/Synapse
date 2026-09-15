# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Read the packaged operating prompt and selected, static client guidance."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sysconfig

from synapse_mcp import __version__


MAIN_PROMPT_URI = "synapse://prompt/main"
GUIDANCE_CATALOG_URI = "synapse://guidance/catalog"
GUIDANCE_BASE_URI = "synapse://guidance/skills"
MAX_GUIDANCE_BYTES = 64 * 1024

# These are the only hosted files. Paths are also the relative paths in the
# installed default Codex skill profile; no client-specific loader is needed.
GUIDANCE_FILES = (
    ("operate-synapse", "SKILL.md", "Default single-agent operating workflow"),
    ("operate-synapse", "references/operational-invariants.md", "Scope, authority, and evidence invariants"),
    ("operate-synapse", "references/single-agent-workflow.md", "Recovery and convergence workflow"),
    ("synapse-web-pentesting", "SKILL.md", "Web assessment methodology"),
    ("synapse-web-pentesting", "references/auth-and-access-control.md", "Authentication and access-control methodology"),
    ("synapse-web-pentesting", "references/saved-data-integrations.md", "Saved-data import and contribution methodology"),
    ("synapse-cve-intelligence", "SKILL.md", "Vulnerability intelligence methodology"),
    ("synapse-cve-intelligence", "references/source-and-poc-analysis.md", "Source and public-PoC analysis"),
)


@dataclass(frozen=True)
class GuidanceDocument:
    uri: str
    skill: str
    path: str
    description: str
    version: str
    sha256: str
    size: int


def read_main_prompt(path: Path | None = None) -> str:
    """Return the shared prompt, honoring the documented local override."""
    from synapse_mcp.core.paths import PROMPT_PATH

    return (path or PROMPT_PATH).read_text(encoding="utf-8")


def default_skills_dir() -> Path:
    """Locate the same default assets used by the local Codex installer."""
    repository = Path(__file__).resolve().parents[3]
    candidates = (
        repository / "skills" / "codex" / "default",
        Path(__file__).resolve().parents[1] / "share" / "synapse-mcp" / "codex" / "skills" / "default",
        Path(sysconfig.get_path("data")).resolve() / "share" / "synapse-mcp" / "codex" / "skills" / "default",
    )
    for candidate in candidates:
        if (candidate / "operate-synapse" / "SKILL.md").is_file():
            return candidate
    raise FileNotFoundError("Default Synapse guidance assets are unavailable")


def guidance_uri(skill: str, path: str) -> str:
    return f"{GUIDANCE_BASE_URI}/{skill}/{path}"


def _bounded_content(path: Path) -> bytes:
    if path.stat().st_size > MAX_GUIDANCE_BYTES:
        raise ValueError(f"Guidance document exceeds {MAX_GUIDANCE_BYTES} bytes: {path.name}")
    data = path.read_bytes()
    if len(data) > MAX_GUIDANCE_BYTES:
        raise ValueError(f"Guidance document exceeds {MAX_GUIDANCE_BYTES} bytes: {path.name}")
    return data


def guidance_documents() -> tuple[GuidanceDocument, ...]:
    root = default_skills_dir()
    return tuple(
        GuidanceDocument(
            uri=guidance_uri(skill, path),
            skill=skill,
            path=path,
            description=description,
            version=__version__,
            sha256=sha256(data).hexdigest(),
            size=len(data),
        )
        for skill, path, description in GUIDANCE_FILES
        for data in (_bounded_content(root / skill / path),)
    )


def read_guidance(uri: str) -> str:
    allowed = {guidance_uri(skill, path): (skill, path) for skill, path, _ in GUIDANCE_FILES}
    if uri not in allowed:
        raise ValueError(f"Unknown Synapse guidance resource: {uri}")
    skill, path = allowed[uri]
    return _bounded_content(default_skills_dir() / skill / path).decode("utf-8")


def guidance_catalog() -> str:
    return json.dumps(
        {
            "version": __version__,
            "documents": [
                {
                    "uri": item.uri,
                    "skill": item.skill,
                    "path": item.path,
                    "description": item.description,
                    "version": item.version,
                    "sha256": item.sha256,
                    "size": item.size,
                }
                for item in guidance_documents()
            ],
        },
        separators=(",", ":"),
    )
