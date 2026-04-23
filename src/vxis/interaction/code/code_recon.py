"""CodeRecon — manifest / Dockerfile / OpenAPI / .env.example detection.

Implements the Recon ABC for the CODE TargetKind. Scans `target.entry`
(a local directory or cloned git repo) for known project manifest files
and extracts structured metadata into ReconReport.components.

Component types emitted:
    {"type": "manifest",        "value": "<relative path>",
     "tech": "<tech+framework>"}
    {"type": "openapi",         "value": "<relative path>",
     "endpoints": "<comma-sep endpoint list>"}
    {"type": "secret_template", "value": "<relative path>",
     "keys": "<comma-sep key list>"}
    {"type": "dockerfile",      "value": "<relative path>",
     "base_image": "<FROM image>"}
    {"type": "compose",         "value": "<relative path>",
     "services": "<comma-sep service names>"}

IMPORTANT: CodeRecon MUST NOT call report_finding at any point.
           Hypothesis generation happens in code_to_hypothesis.py.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from vxis.interaction.surface import Recon, ReconReport, Target, TargetKind


# ---------------------------------------------------------------------------
# Manifest filename → tech label mapping
# The label is used by code_to_hypothesis to pick appropriate vuln hypotheses.
# ---------------------------------------------------------------------------
_MANIFEST_TECH: dict[str, str] = {
    "pyproject.toml":    "python",
    "setup.py":          "python",
    "setup.cfg":         "python",
    "requirements.txt":  "python",
    "Pipfile":           "python+pipenv",
    "package.json":      "nodejs",
    "package-lock.json": "nodejs",
    "yarn.lock":         "nodejs+yarn",
    "pnpm-lock.yaml":    "nodejs+pnpm",
    "pom.xml":           "java+maven",
    "build.gradle":      "java+gradle",
    "build.gradle.kts":  "kotlin+gradle",
    "project.clj":       "clojure+lein",
    "deps.edn":          "clojure+tools-deps",
    "Cargo.toml":        "rust",
    "go.mod":            "go",
    "Gemfile":           "ruby",
    "Gemfile.lock":      "ruby+bundler",
    "composer.json":     "php+composer",
    "mix.exs":           "elixir",
}

_OPENAPI_NAMES = {
    "openapi.yaml", "openapi.yml", "openapi.json",
    "swagger.yaml", "swagger.yml", "swagger.json",
}

_DOCKER_COMPOSE_NAMES = {
    "docker-compose.yml", "docker-compose.yaml",
    "docker-compose.prod.yml", "docker-compose.dev.yml",
}


class CodeRecon(Recon):
    """File-system manifest detector for the CODE surface.

    Walks `target.entry` up to a reasonable depth and classifies every
    file it recognises into the ReconReport.components list. Non-manifest
    files are silently skipped — this keeps the output focused on
    hypothesis-relevant signals.
    """

    def __init__(self, target: Target) -> None:
        self._target = target

    async def fingerprint(self, target: Target) -> ReconReport:
        """Walk the repo root and classify manifest / config files.

        Returns a ReconReport with surface_kind=CODE. The fingerprint
        dict carries top-level metadata (root path, Python version hint,
        etc.). The components list is consumed by code_to_hypothesis.py.
        """
        root = Path(target.entry).expanduser().resolve()
        if not root.is_dir():
            return ReconReport(
                surface_kind=TargetKind.CODE,
                fingerprint={"root": str(root), "error": "not a directory"},
                components=[],
            )

        components: list[dict[str, str]] = []
        fingerprint: dict[str, str] = {"root": str(root)}

        # Walk up to depth 4 to avoid infinite recursion on huge repos
        for path in _walk_limited(root, max_depth=4):
            name = path.name
            rel = str(path.relative_to(root))

            if name in _MANIFEST_TECH:
                tech = _manifest_tech_detail(path, _MANIFEST_TECH[name])
                components.append({
                    "type": "manifest",
                    "value": rel,
                    "tech": tech,
                })
                fingerprint.setdefault("tech", tech)

            elif name in _OPENAPI_NAMES:
                endpoints = _extract_openapi_endpoints(path)
                components.append({
                    "type": "openapi",
                    "value": rel,
                    "endpoints": ", ".join(endpoints[:50]),  # cap to avoid huge strings
                })

            elif name == "Dockerfile":
                base = _extract_dockerfile_base(path)
                components.append({
                    "type": "dockerfile",
                    "value": rel,
                    "base_image": base,
                })

            elif name in _DOCKER_COMPOSE_NAMES:
                services = _extract_compose_services(path)
                components.append({
                    "type": "compose",
                    "value": rel,
                    "services": ", ".join(services),
                })

            elif name == ".env.example" or name == ".env.sample":
                keys = _extract_env_keys(path)
                components.append({
                    "type": "secret_template",
                    "value": rel,
                    "keys": ", ".join(keys[:100]),
                })

        return ReconReport(
            surface_kind=TargetKind.CODE,
            fingerprint=fingerprint,
            components=components,
        )


# ---------------------------------------------------------------------------
# Internal helpers — pure functions, no I/O side effects beyond reading files
# ---------------------------------------------------------------------------

def _walk_limited(root: Path, max_depth: int) -> list[Path]:
    """Yield file paths up to `max_depth` levels below `root`."""
    results: list[Path] = []
    _recurse(root, root, 0, max_depth, results)
    return results


def _recurse(
    root: Path,
    current: Path,
    depth: int,
    max_depth: int,
    acc: list[Path],
) -> None:
    if depth > max_depth:
        return
    try:
        for entry in sorted(current.iterdir()):
            if entry.name.startswith(".") and entry.name not in {
                ".env.example", ".env.sample"
            }:
                continue
            if entry.is_file():
                acc.append(entry)
            elif entry.is_dir() and not _is_skip_dir(entry.name):
                _recurse(root, entry, depth + 1, max_depth, acc)
    except PermissionError:
        pass


def _is_skip_dir(name: str) -> bool:
    _SKIP = {
        ".git", ".hg", ".svn", "node_modules", "__pycache__",
        ".venv", "venv", ".mypy_cache", ".pytest_cache",
        "dist", "build", "target", ".idea", ".vscode",
    }
    return name in _SKIP


def _manifest_tech_detail(path: Path, base_tech: str) -> str:
    """Attempt to refine the tech label with framework hints."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return base_tech

    framework_hints: dict[str, str] = {
        "fastapi":    "python+fastapi",
        "django":     "python+django",
        "flask":      "python+flask",
        "express":    "nodejs+express",
        "next":       "nodejs+nextjs",
        "nestjs":     "nodejs+nestjs",
        "spring":     "java+spring",
        "litellm":    "python+litellm",
        "python-jose": "python+python-jose",
        "pyjwt":      "python+pyjwt",
        "korma":      "clojure+korma",
        "sqlalchemy": "python+sqlalchemy",
    }
    for keyword, label in framework_hints.items():
        if keyword in content:
            return label
    return base_tech


def _extract_openapi_endpoints(path: Path) -> list[str]:
    """Parse paths from an OpenAPI/Swagger file."""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    # JSON schema
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(raw)
            return list(data.get("paths", {}).keys())
        except json.JSONDecodeError:
            return []

    # YAML — parse manually to avoid pyyaml dependency
    endpoints: list[str] = []
    for line in raw.splitlines():
        # Match top-level path keys: lines starting with "/" (possibly quoted)
        m = re.match(r"^\s{0,2}['\"]?(/[\w/{}\-._~%!$&'()*+,;=:@]+)['\"]?\s*:", line)
        if m:
            endpoints.append(m.group(1))
    return endpoints


def _extract_dockerfile_base(path: Path) -> str:
    """Return the first FROM image in a Dockerfile."""
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip().upper()
            if stripped.startswith("FROM "):
                return line.strip()[5:].split()[0]
    except OSError:
        pass
    return "unknown"


def _extract_compose_services(path: Path) -> list[str]:
    """Extract service names from a docker-compose file (regex, no yaml dep)."""
    services: list[str] = []
    try:
        in_services = False
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if re.match(r"^services\s*:", line):
                in_services = True
                continue
            if in_services:
                # Service name: two-space indented key, not a deeper indent
                m = re.match(r"^  ([a-zA-Z0-9_-]+)\s*:", line)
                if m:
                    services.append(m.group(1))
                elif line and not line.startswith(" "):
                    in_services = False
    except OSError:
        pass
    return services


def _extract_env_keys(path: Path) -> list[str]:
    """Extract variable names from a .env.example / .env.sample file."""
    keys: list[str] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = re.match(r"^([A-Z0-9_]+)\s*=", stripped)
            if m:
                keys.append(m.group(1))
    except OSError:
        pass
    return keys
