"""CodeHands — file-system I/O for the Code surface.

Implements the Hands ABC for the CODE TargetKind. All operations are
read-only: no writes, no execution, no network calls.

Supported intents:
    "read"  — read a single file by path
    "grep"  — search a pattern (regex) across one or more file paths
    "glob"  — walk a directory and return paths matching a glob pattern

IMPORTANT: CodeHands MUST NOT call report_finding at any point.
           It is a pure data-collection primitive — the Code-to-Hypothesis
           adapter (code_to_hypothesis.py) converts its output into
           unverified Hypothesis objects for the P3 queue.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from vxis.interaction.surface import Hands, InteractionEnvelope, Target, TargetKind


class CodeHands(Hands):
    """Read-only file-system operations for the CODE surface.

    `target.entry` is treated as the root directory (or git repo root).
    All path arguments are resolved relative to that root; absolute
    paths outside the root are rejected to prevent path-traversal.
    """

    def __init__(self, target: Target) -> None:
        self._target = target
        self._root = Path(target.entry).expanduser().resolve()

    # ------------------------------------------------------------------
    # Hands ABC lifecycle — no-ops for a file-system surface
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """No persistent session to open for file-system access."""
        return None

    async def stop(self) -> None:
        """No persistent session to close."""
        return None

    # ------------------------------------------------------------------
    # Core dispatch
    # ------------------------------------------------------------------

    async def request(self, intent: str, **kw: object) -> InteractionEnvelope:
        """Dispatch a file-system intent.

        Args:
            intent: one of "read", "grep", "glob"
            **kw:
                read  → path: str
                grep  → pattern: str, paths: list[str] | None (default: entire root)
                         max_matches: int (default 200)
                glob  → pattern: str (glob), base: str | None (default: root)

        Returns:
            InteractionEnvelope with surface_kind=CODE.
            On success, artifacts["lines"] contains the result (JSON-serialisable str).
        """
        if intent == "read":
            return await self._read(str(kw.get("path", "")))
        if intent == "grep":
            return await self._grep(
                pattern=str(kw.get("pattern", "")),
                paths=kw.get("paths"),  # type: ignore[arg-type]
                max_matches=int(kw.get("max_matches", 200)),
            )
        if intent == "glob":
            return await self._glob(
                pattern=str(kw.get("pattern", "**/*")),
                base=kw.get("base"),  # type: ignore[arg-type]
            )
        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=False,
            summary=f"unknown intent: {intent!r}",
            error=f"CodeHands supports 'read', 'grep', 'glob'; got {intent!r}",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _safe_path(self, rel: str) -> Path | None:
        """Resolve *rel* under root; return None if traversal is attempted."""
        candidate = (self._root / rel).resolve()
        try:
            candidate.relative_to(self._root)
        except ValueError:
            return None
        return candidate

    async def _read(self, path: str) -> InteractionEnvelope:
        if not path:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary="path argument required for intent='read'",
                error="missing path",
            )
        resolved = self._safe_path(path)
        if resolved is None:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary="path traversal rejected",
                error=f"{path!r} resolves outside repo root",
            )
        if not resolved.is_file():
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary=f"file not found: {path}",
                error="file not found",
            )
        try:
            content = resolved.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary=f"read error: {exc}",
                error=str(exc),
            )
        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=True,
            summary=f"read {resolved.relative_to(self._root)} ({len(content)} chars)",
            artifacts={"path": str(resolved), "lines": content},
        )

    async def _grep(
        self,
        pattern: str,
        paths: list[str] | None,
        max_matches: int,
    ) -> InteractionEnvelope:
        if not pattern:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary="pattern argument required for intent='grep'",
                error="missing pattern",
            )
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary=f"invalid regex: {exc}",
                error=str(exc),
            )

        search_paths: list[Path]
        if paths:
            resolved_list: list[Path] = []
            for p in paths:
                r = self._safe_path(p)
                if r and r.is_file():
                    resolved_list.append(r)
            search_paths = resolved_list
        else:
            search_paths = [
                f for f in self._root.rglob("*") if f.is_file() and not _is_binary_path(f)
            ]

        matches: list[str] = []
        for file_path in search_paths:
            if len(matches) >= max_matches:
                break
            try:
                for lineno, line in enumerate(
                    file_path.read_text(encoding="utf-8", errors="replace").splitlines(),
                    start=1,
                ):
                    if regex.search(line):
                        rel = str(file_path.relative_to(self._root))
                        matches.append(f"{rel}:{lineno}: {line.rstrip()}")
                        if len(matches) >= max_matches:
                            break
            except OSError:
                continue

        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=True,
            summary=f"grep '{pattern}': {len(matches)} match(es)",
            artifacts={"lines": "\n".join(matches)},
        )

    async def _glob(
        self,
        pattern: str,
        base: object,
    ) -> InteractionEnvelope:
        if isinstance(base, str) and base:
            base_path = self._safe_path(base)
            if base_path is None:
                return InteractionEnvelope(
                    surface_kind=TargetKind.CODE,
                    success=False,
                    summary="base path traversal rejected",
                    error=f"{base!r} resolves outside repo root",
                )
        else:
            base_path = self._root

        found: list[str] = []
        for entry in base_path.rglob("*"):
            if fnmatch.fnmatch(entry.name, pattern.split("/")[-1]):
                found.append(str(entry.relative_to(self._root)))

        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=True,
            summary=f"glob '{pattern}': {len(found)} file(s)",
            artifacts={"lines": "\n".join(found)},
        )


def _is_binary_path(path: Path) -> bool:
    """Heuristic: skip known binary / compiled extensions."""
    _BINARY_SUFFIXES = {
        ".pyc",
        ".pyo",
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".o",
        ".a",
        ".class",
        ".jar",
        ".zip",
        ".tar",
        ".gz",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".pdf",
        ".ico",
    }
    return path.suffix.lower() in _BINARY_SUFFIXES
