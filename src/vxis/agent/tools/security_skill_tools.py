"""Read-only bridge to the local Anthropic Cybersecurity Skills library.

These tools expose the library as methodology/reference material for the Brain.
They deliberately do not execute anything from the skills; execution must stay
inside VXIS tools so scope, egress, evidence, and verifier gates remain active.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from vxis.agent.tool_registry import ToolResult

_ENV_ROOT = "VXIS_SECURITY_SKILLS_DIR"
_MAX_SEARCH_LIMIT = 20
_DEFAULT_SEARCH_LIMIT = 8
_DEFAULT_LOAD_CHARS = 14_000
_MAX_LOAD_CHARS = 40_000


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _candidate_roots() -> list[Path]:
    configured = os.getenv(_ENV_ROOT, "").strip()
    roots: list[Path] = []
    if configured:
        roots.append(Path(configured).expanduser())
    roots.append(_repo_root().parent / "Anthropic-Cybersecurity-Skills")
    return roots


def _skills_dir() -> Path | None:
    for root in _candidate_roots():
        expanded = root.expanduser()
        candidates = [expanded]
        if expanded.name != "skills":
            candidates.insert(0, expanded / "skills")
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if resolved.is_dir() and any(resolved.glob("*/SKILL.md")):
                return resolved
    return None


def _parse_frontmatter(raw: str) -> tuple[dict[str, Any], str]:
    if not raw.startswith("---"):
        return {}, raw
    parts = raw.split("---", 2)
    if len(parts) < 3:
        return {}, raw
    try:
        data = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return data, parts[2].strip()


def _normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def _skill_entries(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for skill_md in sorted(root.glob("*/SKILL.md")):
        try:
            raw = skill_md.read_text(encoding="utf-8")
        except OSError:
            continue
        fm, body = _parse_frontmatter(raw)
        name = str(fm.get("name") or skill_md.parent.name).strip()
        description = str(fm.get("description") or "").strip()
        subdomain = str(fm.get("subdomain") or "").strip()
        tags = _normalize_list(fm.get("tags"))
        entries.append(
            {
                "name": name,
                "slug": skill_md.parent.name,
                "description": description,
                "subdomain": subdomain,
                "tags": tags,
                "path": skill_md,
                "skill_dir": skill_md.parent,
                "frontmatter": fm,
                "body": body,
                "raw": raw,
            }
        )
    return entries


def _terms(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 2]


def _score(entry: dict[str, Any], query_terms: list[str]) -> int:
    name = str(entry["name"]).lower()
    slug = str(entry["slug"]).lower()
    description = str(entry["description"]).lower()
    subdomain = str(entry["subdomain"]).lower()
    tags = " ".join(entry["tags"]).lower()
    body_head = str(entry["body"])[:4000].lower()

    score = 0
    for term in query_terms:
        if term in name or term in slug:
            score += 8
        if term in tags:
            score += 5
        if term in subdomain:
            score += 4
        if term in description:
            score += 3
        if term in body_head:
            score += 1
    return score


def _bounded_int(value: Any, default: int, max_value: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(parsed, max_value))


def _find_entry(root: Path, name: str) -> dict[str, Any] | None:
    wanted = str(name or "").strip().lower()
    if not wanted:
        return None
    for entry in _skill_entries(root):
        names = {
            str(entry["name"]).lower(),
            str(entry["slug"]).lower(),
            str(entry["name"]).lower().replace("_", "-"),
            str(entry["slug"]).lower().replace("_", "-"),
        }
        if wanted in names:
            return entry
    return None


def _linked_files(skill_dir: Path) -> list[str]:
    linked: list[str] = []
    for child_name in ("references", "scripts", "assets", "templates"):
        base = skill_dir / child_name
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and not path.is_symlink():
                linked.append(path.relative_to(skill_dir).as_posix())
    return linked


class SearchSecuritySkillsTool:
    name = "search_security_skills"
    description = (
        "Search the local Anthropic-Cybersecurity-Skills SKILL.md library for "
        "pentest methodology, checks, and verification guidance. Read-only and "
        "offline: this does not touch the target. Use for security planning, "
        "hypothesis expansion, and choosing VXIS tools. Load a match with "
        "load_security_skill before relying on it."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Security topic or hypothesis, e.g. SSRF, JWT alg none, CSP, Kubernetes RBAC.",
            },
            "limit": {
                "type": "integer",
                "description": f"Maximum matches to return, 1-{_MAX_SEARCH_LIMIT}.",
                "default": _DEFAULT_SEARCH_LIMIT,
            },
        },
        "required": ["query"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        root = _skills_dir()
        if root is None:
            return ToolResult(
                ok=False,
                summary=(
                    "security skills library not found. Set "
                    f"{_ENV_ROOT} to the repo root or skills/ directory."
                ),
                error="library_not_found",
            )

        query = str(kwargs.get("query", "")).strip()
        if not query:
            return ToolResult(ok=False, summary="search_security_skills: query is required", error="missing_query")

        limit = _bounded_int(kwargs.get("limit"), _DEFAULT_SEARCH_LIMIT, _MAX_SEARCH_LIMIT)
        query_terms = _terms(query)
        scored: list[tuple[int, dict[str, Any]]] = []
        for entry in _skill_entries(root):
            score = _score(entry, query_terms)
            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda item: (-item[0], str(item[1]["name"])))
        matches = []
        for score, entry in scored[:limit]:
            matches.append(
                {
                    "name": entry["name"],
                    "slug": entry["slug"],
                    "description": entry["description"],
                    "subdomain": entry["subdomain"],
                    "tags": entry["tags"][:12],
                    "score": score,
                }
            )

        return ToolResult(
            ok=True,
            data={
                "query": query,
                "library": str(root),
                "count": len(matches),
                "matches": matches,
                "usage": "Call load_security_skill(name=<name>) for the full workflow, then execute only through VXIS tools within authorized scope.",
            },
            summary=(
                f"security skills search: {len(matches)} match(es) for {query!r}"
                if matches
                else f"security skills search: no matches for {query!r}"
            ),
        )


class LoadSecuritySkillTool:
    name = "load_security_skill"
    description = (
        "Load one local Anthropic-Cybersecurity-Skills SKILL.md by name/slug. "
        "Read-only reference material only: do not execute commands directly "
        "from the skill. Translate the workflow into VXIS scoped tools "
        "(http_request, browser_*, shell_exec/python_exec, report_finding, "
        "verify_finding)."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Exact skill name or directory slug returned by search_security_skills.",
            },
            "max_chars": {
                "type": "integer",
                "description": f"Maximum SKILL.md characters to return, 1-{_MAX_LOAD_CHARS}.",
                "default": _DEFAULT_LOAD_CHARS,
            },
        },
        "required": ["name"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        root = _skills_dir()
        if root is None:
            return ToolResult(
                ok=False,
                summary=(
                    "security skills library not found. Set "
                    f"{_ENV_ROOT} to the repo root or skills/ directory."
                ),
                error="library_not_found",
            )

        name = str(kwargs.get("name", "")).strip()
        if not name:
            return ToolResult(ok=False, summary="load_security_skill: name is required", error="missing_name")

        entry = _find_entry(root, name)
        if entry is None:
            return ToolResult(
                ok=False,
                summary=f"load_security_skill: {name!r} not found. Search first with search_security_skills.",
                error="not_found",
            )

        max_chars = _bounded_int(kwargs.get("max_chars"), _DEFAULT_LOAD_CHARS, _MAX_LOAD_CHARS)
        raw = str(entry["raw"])
        truncated = len(raw) > max_chars
        content = raw[:max_chars]
        if truncated:
            content = content.rstrip() + "\n\n[TRUNCATED: raise max_chars or inspect the file directly if more detail is required.]"

        return ToolResult(
            ok=True,
            data={
                "name": entry["name"],
                "slug": entry["slug"],
                "subdomain": entry["subdomain"],
                "tags": entry["tags"],
                "skill_dir": str(entry["skill_dir"]),
                "linked_files": _linked_files(entry["skill_dir"]),
                "content": content,
                "truncated": truncated,
                "safety": (
                    "Reference only. Keep all target interaction inside VXIS scoped tools "
                    "and report/verify findings with evidence."
                ),
            },
            summary=f"loaded security skill '{entry['name']}' ({len(content)} chars returned)",
        )
