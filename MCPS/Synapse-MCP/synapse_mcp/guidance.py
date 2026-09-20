# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Read the packaged operating prompt and a fixed set of client guidance."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sysconfig


MAIN_PROMPT_URI = "synapse://prompt/main"
GUIDANCE_CATALOG_URI = "synapse://guidance/catalog"
GUIDANCE_BASE_URI = "synapse://guidance/skills"
MAX_GUIDANCE_BYTES = 64 * 1024


@dataclass(frozen=True)
class GuidancePackage:
    id: str
    kind: str
    description: str
    profile: str
    source_path: str
    parent: str | None = None


# Package identity and selection belong here. Only SKILL.md and Markdown files
# immediately under references/ can be served; no request path reaches disk.
GUIDANCE_PACKAGES = (
    GuidancePackage("operate-synapse", "entry", "Default single-agent operating workflow", "default", "operate-synapse"),
    GuidancePackage("synapse-web-pentesting", "entry", "Web assessment methodology", "default", "synapse-web-pentesting"),
    GuidancePackage("synapse-cve-intelligence", "entry", "Vulnerability intelligence methodology", "default", "synapse-cve-intelligence"),
    GuidancePackage("synapse-web-auth-session", "method", "Select from saved auth/session evidence; optional JWT and CSRF interpretation helpers", "web-methods", "synapse-web-auth-session", "synapse-web-pentesting"),
    GuidancePackage("synapse-web-access-control", "method", "Select for actor/object authorization comparisons; optional object and matrix helpers", "web-methods", "synapse-web-access-control", "synapse-web-pentesting"),
    GuidancePackage("synapse-web-browser-input", "method", "Select for browser input and redirect questions; optional XSS, redirect, and JS signal helpers", "web-methods", "synapse-web-browser-input", "synapse-web-pentesting"),
    GuidancePackage("synapse-web-server-input", "method", "Select for SQL, command, template, or SSI questions; optional candidate and plan helpers", "web-methods", "synapse-web-server-input", "synapse-web-pentesting"),
    GuidancePackage("synapse-web-fetch-file-xml", "method", "Select for fetch, file/path, or XML questions; optional SSRF, LFI, and XXE helpers", "web-methods", "synapse-web-fetch-file-xml", "synapse-web-pentesting"),
    GuidancePackage("synapse-web-structured-data", "method", "Select for GraphQL or serialized-data questions; optional schema and marker helpers", "web-methods", "synapse-web-structured-data", "synapse-web-pentesting"),
    GuidancePackage("synapse-web-configuration", "method", "Select for deployment, header, CORS, cookie, or TLS evidence; optional posture helpers", "web-methods", "synapse-web-configuration", "synapse-web-pentesting"),
    GuidancePackage("synapse-web-business-logic", "method", "Select for workflow and state invariants from saved evidence; no dedicated heuristic helper", "web-methods", "synapse-web-business-logic", "synapse-web-pentesting"),
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
    profile: str


@dataclass(frozen=True)
class GuidanceSnapshot:
    packages: tuple[dict[str, object], ...]
    documents: tuple[GuidanceDocument, ...]
    bodies: dict[str, bytes]
    version: str

    def read(self, uri: str) -> str:
        try:
            return self.bodies[uri].decode("utf-8")
        except KeyError as exc:
            raise ValueError(f"Unknown Synapse guidance resource: {uri}") from exc

    def catalog(self) -> str:
        return json.dumps(
            {
                "version": self.version,
                "packages": self.packages,
                "documents": [document.__dict__ for document in self.documents],
            },
            separators=(",", ":"),
        )


def read_main_prompt(path: Path | None = None) -> str:
    """Return the shared prompt, honoring the documented local override."""
    from synapse_mcp.core.paths import PROMPT_PATH

    return (path or PROMPT_PATH).read_text(encoding="utf-8")


def skills_dir(profile: str) -> Path:
    """Locate one packaged skill profile without accepting arbitrary paths."""
    if profile not in {package.profile for package in GUIDANCE_PACKAGES}:
        raise ValueError(f"Unknown Synapse guidance profile: {profile}")
    repository = Path(__file__).resolve().parents[3]
    candidates = (
        repository / "skills" / "codex" / profile,
        Path(__file__).resolve().parents[1] / "share" / "synapse-mcp" / "codex" / "skills" / profile,
        Path(sysconfig.get_path("data")).resolve() / "share" / "synapse-mcp" / "codex" / "skills" / profile,
    )
    sentinel = next(package.source_path for package in GUIDANCE_PACKAGES if package.profile == profile)
    for candidate in candidates:
        if (candidate / sentinel / "SKILL.md").is_file():
            return candidate
    raise FileNotFoundError(f"Synapse {profile} guidance assets are unavailable")


def default_skills_dir() -> Path:
    return skills_dir("default")


def guidance_uri(skill: str, path: str) -> str:
    return f"{GUIDANCE_BASE_URI}/{skill}/{path}"


def _bounded_content(path: Path) -> bytes:
    if path.stat().st_size > MAX_GUIDANCE_BYTES:
        raise ValueError(f"Guidance document exceeds {MAX_GUIDANCE_BYTES} bytes: {path.name}")
    data = path.read_bytes()
    if len(data) > MAX_GUIDANCE_BYTES:
        raise ValueError(f"Guidance document exceeds {MAX_GUIDANCE_BYTES} bytes: {path.name}")
    data.decode("utf-8")
    return data


def build_guidance_snapshot() -> GuidanceSnapshot:
    """Freeze allowlisted paths, metadata, and bytes for one server build."""
    documents: list[GuidanceDocument] = []
    packages: list[dict[str, object]] = []
    bodies: dict[str, bytes] = {}
    for package in GUIDANCE_PACKAGES:
        directory = skills_dir(package.profile) / package.source_path
        reference_dir = directory / "references"
        paths = (Path("SKILL.md"),) + tuple(
            Path("references") / path.name for path in sorted(reference_dir.glob("*.md"))
        )
        package_hash = sha256()
        package_size = 0
        uris = []
        for relative in paths:
            source = directory / relative
            if source.is_symlink() or not source.resolve().is_relative_to(directory.resolve()):
                raise ValueError(f"Guidance document escapes its package: {relative}")
            data = _bounded_content(source)
            digest = sha256(data).hexdigest()
            path = relative.as_posix()
            uri = guidance_uri(package.id, path)
            package_hash.update(path.encode("utf-8") + bytes([0]) + data)
            package_size += len(data)
            uris.append(uri)
            bodies[uri] = data
            documents.append(GuidanceDocument(
                uri, package.id, path, package.description, digest[:12], digest,
                len(data), package.profile,
            ))
        packages.append({
            "id": package.id,
            "kind": package.kind,
            "description": package.description,
            "profile": package.profile,
            "sourcePath": package.source_path,
            "parent": package.parent,
            "version": package_hash.hexdigest()[:12],
            "sha256": package_hash.hexdigest(),
            "size": package_size,
            "documents": uris,
        })
    catalog_hash = sha256(json.dumps(packages, sort_keys=True).encode("utf-8")).hexdigest()
    return GuidanceSnapshot(tuple(packages), tuple(documents), bodies, catalog_hash[:12])


def guidance_documents() -> tuple[GuidanceDocument, ...]:
    return build_guidance_snapshot().documents


def read_guidance(uri: str) -> str:
    return build_guidance_snapshot().read(uri)


def guidance_catalog() -> str:
    return build_guidance_snapshot().catalog()
