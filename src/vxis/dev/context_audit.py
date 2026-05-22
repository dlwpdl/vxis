"""Repository and prompt context-size audit helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from vxis.agent.context_budget import estimate_context_tokens, resolve_context_budget


DEFAULT_EXCLUDES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "node_modules",
    "reports",
    ".vxis",
}
DEFAULT_SUFFIXES = {".py", ".md", ".toml", ".yaml", ".yml", ".json"}


@dataclass(frozen=True)
class FileContextAudit:
    path: str
    lines: int
    bytes: int
    estimated_tokens: int
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ContextAuditReport:
    files: tuple[FileContextAudit, ...]
    total_files: int
    total_lines: int
    total_bytes: int
    total_estimated_tokens: int
    warning_count: int

    @property
    def offenders(self) -> tuple[FileContextAudit, ...]:
        return tuple(item for item in self.files if item.warnings)


def audit_repo_context(
    roots: Iterable[Path | str],
    *,
    max_file_tokens: int = 30_000,
    max_file_bytes: int = 120_000,
    max_file_lines: int = 2_500,
    suffixes: set[str] | None = None,
) -> ContextAuditReport:
    suffix_filter = suffixes or DEFAULT_SUFFIXES
    files: list[FileContextAudit] = []
    for root in roots:
        base = Path(root)
        if base.is_file():
            candidates = [base]
        else:
            candidates = [
                path
                for path in base.rglob("*")
                if path.is_file() and path.suffix in suffix_filter and not _is_excluded(path)
            ]
        for path in candidates:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            line_count = text.count("\n") + (1 if text else 0)
            byte_count = len(text.encode("utf-8", errors="ignore"))
            token_count = estimate_context_tokens(text)
            warnings: list[str] = []
            if token_count > max_file_tokens:
                warnings.append(f"tokens>{max_file_tokens}")
            if byte_count > max_file_bytes:
                warnings.append(f"bytes>{max_file_bytes}")
            if line_count > max_file_lines:
                warnings.append(f"lines>{max_file_lines}")
            files.append(
                FileContextAudit(
                    path=str(path),
                    lines=line_count,
                    bytes=byte_count,
                    estimated_tokens=token_count,
                    warnings=tuple(warnings),
                )
            )
    files.sort(key=lambda item: (bool(item.warnings), item.estimated_tokens), reverse=True)
    return ContextAuditReport(
        files=tuple(files),
        total_files=len(files),
        total_lines=sum(item.lines for item in files),
        total_bytes=sum(item.bytes for item in files),
        total_estimated_tokens=sum(item.estimated_tokens for item in files),
        warning_count=sum(len(item.warnings) for item in files),
    )


def role_budget_lines() -> list[str]:
    roles = (
        ("frontier director", "director", "openai", "gpt-5.4"),
        ("frontier worker", "worker", "openai", "gpt-5.4-mini"),
        ("local director", "director", "llamacpp", "local-30b"),
        ("local worker", "worker", "llamacpp", "local-30b"),
        ("verifier", "verifier", "openai", "gpt-4o-mini"),
        ("summarizer", "summarizer", "llamacpp", "local-30b"),
    )
    lines: list[str] = []
    for label, role, provider, model in roles:
        budget = resolve_context_budget(role, provider=provider, model=model)
        lines.append(
            f"{label}: prompt<={budget.max_prompt_tokens}t "
            f"history<={budget.history_tokens}t skill<={budget.max_skill_chars}c"
        )
    return lines


def format_context_audit(report: ContextAuditReport, *, limit: int = 20) -> str:
    lines = [
        "Context audit",
        (
            f"files={report.total_files} lines={report.total_lines} "
            f"bytes={report.total_bytes} est_tokens={report.total_estimated_tokens} "
            f"warnings={report.warning_count}"
        ),
        "",
        "Role budgets",
        *role_budget_lines(),
        "",
        "Top offenders",
    ]
    offenders = report.offenders[:limit]
    if not offenders:
        lines.append("none")
    for item in offenders:
        lines.append(
            f"{item.estimated_tokens:>8}t {item.lines:>6}l {item.bytes:>8}b "
            f"{','.join(item.warnings)} {item.path}"
        )
    return "\n".join(lines)


def _is_excluded(path: Path) -> bool:
    return any(part in DEFAULT_EXCLUDES for part in path.parts)


__all__ = [
    "ContextAuditReport",
    "FileContextAudit",
    "audit_repo_context",
    "format_context_audit",
    "role_budget_lines",
]
