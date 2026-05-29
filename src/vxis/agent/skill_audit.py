from __future__ import annotations

import ast
import inspect
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SkillAuditIssue:
    code: str
    path: str
    line: int
    message: str

    def compact(self) -> dict[str, Any]:
        return asdict(self)


_RAW_HTTP_IMPORTS = {"httpx", "requests"}
_RAW_URLLIB_REQUEST_NAMES = {"urlopen", "Request", "build_opener", "ProxyHandler"}
_SUBPROCESS_CALLS = {"run", "Popen", "call", "check_call", "check_output"}
_SOCKET_CALLS = {
    "socket",
    "create_connection",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "getnameinfo",
}


def audit_skill_file(path: str | Path) -> list[SkillAuditIssue]:
    source_path = Path(path)
    rel = _relative_path(source_path)
    try:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
    except SyntaxError as exc:
        return [
            SkillAuditIssue(
                code="syntax_error",
                path=rel,
                line=int(exc.lineno or 0),
                message=str(exc),
            )
        ]

    allow_local_subprocess = _is_desktop_skill(source_path)
    issues: list[SkillAuditIssue] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in _RAW_HTTP_IMPORTS:
                    issues.append(_issue(rel, node.lineno, "raw_http_import", alias.name))
                elif root == "socket":
                    issues.append(_issue(rel, node.lineno, "raw_socket_import", alias.name))
                elif root == "subprocess" and not allow_local_subprocess:
                    issues.append(_issue(rel, node.lineno, "raw_subprocess_import", alias.name))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            root = module.split(".", 1)[0]
            names = {alias.name for alias in node.names}
            if root in _RAW_HTTP_IMPORTS:
                issues.append(_issue(rel, node.lineno, "raw_http_import", module))
            elif module == "urllib.request" and names & _RAW_URLLIB_REQUEST_NAMES:
                issues.append(_issue(rel, node.lineno, "raw_urlopen_import", module))
            elif root == "socket":
                issues.append(_issue(rel, node.lineno, "raw_socket_import", module))
            elif root == "subprocess" and not allow_local_subprocess:
                issues.append(_issue(rel, node.lineno, "raw_subprocess_import", module))
        elif isinstance(node, ast.Call):
            dotted = _dotted_name(node.func)
            if dotted in {"asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell"}:
                issues.append(_issue(rel, node.lineno, "raw_subprocess_call", dotted))
            elif dotted.startswith("requests."):
                issues.append(_issue(rel, node.lineno, "raw_http_call", dotted))
            elif dotted.startswith("httpx."):
                issues.append(_issue(rel, node.lineno, "raw_http_call", dotted))
            elif dotted in {"urllib.request.urlopen", "urlopen"}:
                issues.append(_issue(rel, node.lineno, "raw_urlopen_call", dotted))
            elif dotted.startswith("socket.") and dotted.split(".")[-1] in _SOCKET_CALLS:
                issues.append(_issue(rel, node.lineno, "raw_socket_call", dotted))
            elif (
                dotted.startswith("subprocess.")
                and dotted.split(".")[-1] in _SUBPROCESS_CALLS
                and not allow_local_subprocess
            ):
                issues.append(_issue(rel, node.lineno, "raw_subprocess_call", dotted))
    return issues


def audit_registered_skill(skill_name: str, registry: dict[str, dict] | None = None) -> dict[str, Any]:
    skill = _registry(registry).get(skill_name)
    if not skill:
        return {
            "skill": skill_name,
            "mode": "unknown",
            "ghost_coverage": "unknown",
            "errors": [{"code": "unknown_skill", "path": "", "line": 0, "message": skill_name}],
        }
    source_path = _skill_source_path(skill)
    if source_path is None:
        return {
            "skill": skill_name,
            "mode": "unknown",
            "ghost_coverage": "unknown",
            "errors": [],
            "warnings": ["skill source path unavailable"],
        }
    issues = audit_skill_file(source_path)
    metadata = skill_egress_metadata_for_path(skill_name, source_path, issues)
    metadata["errors"] = [issue.compact() for issue in issues]
    return metadata


def audit_registered_skills(registry: dict[str, dict] | None = None) -> dict[str, Any]:
    reg = _registry(registry)
    skills = [audit_registered_skill(name, reg) for name in sorted(reg)]
    errors = [
        error
        for skill in skills
        for error in skill.get("errors", [])
    ]
    return {
        "ok": not errors,
        "skills": skills,
        "errors": errors,
    }


def skill_egress_metadata(skill_name: str, registry: dict[str, dict] | None = None) -> dict[str, Any]:
    audit = audit_registered_skill(skill_name, registry)
    return {
        key: value
        for key, value in audit.items()
        if key not in {"errors"} or value
    }


def skill_egress_metadata_for_path(
    skill_name: str,
    source_path: Path,
    issues: list[SkillAuditIssue] | None = None,
) -> dict[str, Any]:
    issue_count = len(issues or [])
    if issue_count:
        return {
            "skill": skill_name,
            "mode": "blocked_raw_egress",
            "target_facing": True,
            "ghost_coverage": "unknown",
            "risk": "direct",
            "audit_error_count": issue_count,
        }
    if _is_desktop_skill(source_path):
        return {
            "skill": skill_name,
            "mode": "offline_local_analysis",
            "target_facing": False,
            "ghost_coverage": "not_applicable",
            "risk": "none",
        }
    text = source_path.read_text(encoding="utf-8")
    if "SessionManager" in text or "TargetSession" in text:
        return {
            "skill": skill_name,
            "mode": "ghost_transport",
            "target_facing": True,
            "ghost_coverage": "covered",
            "risk": "low",
        }
    return {
        "skill": skill_name,
        "mode": "offline_or_unknown",
        "target_facing": False,
        "ghost_coverage": "not_applicable",
        "risk": "none",
    }


def _registry(registry: dict[str, dict] | None) -> dict[str, dict]:
    if registry is not None:
        return registry
    from vxis.agent.skills import SKILL_REGISTRY

    return SKILL_REGISTRY


def _skill_source_path(skill: dict[str, Any]) -> Path | None:
    fn = skill.get("fn")
    try:
        raw = inspect.getsourcefile(fn)
    except TypeError:
        raw = None
    return Path(raw).resolve() if raw else None


def _issue(path: str, line: int, code: str, detail: str) -> SkillAuditIssue:
    return SkillAuditIssue(
        code=code,
        path=path,
        line=line,
        message=f"{detail} bypasses VXIS SessionManager/tool egress controls",
    )


def _relative_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _is_desktop_skill(path: Path) -> bool:
    return "desktop" in path.parts and "skills" in path.parts


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""
