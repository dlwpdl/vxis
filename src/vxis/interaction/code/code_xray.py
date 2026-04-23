"""CodeXRay — git history inspector for the Code surface.

Implements the XRay ABC for the CODE TargetKind. Delegates to the
`git` binary via subprocess (no third-party git libraries).

Supported windows:
    "log"   — recent N commit metadata (hash, author, date, subject)
               kw: n: int (default 20)
    "blame" — per-line attribution for a file
               kw: path: str (required), start: int, end: int (optional line range)
    "diff"  — unified diff between two commits
               kw: base: str (required), head: str (default "HEAD")

IMPORTANT: CodeXRay MUST NOT call report_finding at any point.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from vxis.interaction.surface import InteractionEnvelope, Target, TargetKind, XRay


class CodeXRay(XRay):
    """Git history inspector for the CODE surface.

    `target.entry` must be a path inside (or equal to) a git repository.
    All git commands run with `-C <repo_root>` so the cwd does not matter.
    """

    _GIT_TIMEOUT = 30  # seconds

    def __init__(self, target: Target) -> None:
        self._target = target
        self._root = Path(target.entry).expanduser().resolve()

    # ------------------------------------------------------------------
    # XRay ABC lifecycle — no-ops for subprocess-based inspection
    # ------------------------------------------------------------------

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    # ------------------------------------------------------------------
    # Core dispatch
    # ------------------------------------------------------------------

    async def capture(self, window: str, **kw: object) -> InteractionEnvelope:
        """Invoke a git sub-command and return the output.

        Args:
            window: one of "log", "blame", "diff"
            **kw:   see module docstring for per-window arguments

        Returns:
            InteractionEnvelope with surface_kind=CODE.
            artifacts["lines"] contains raw git output.
        """
        if window == "log":
            return self._git_log(n=int(kw.get("n", 20)))
        if window == "blame":
            return self._git_blame(
                path=str(kw.get("path", "")),
                start=kw.get("start"),
                end=kw.get("end"),
            )
        if window == "diff":
            return self._git_diff(
                base=str(kw.get("base", "")),
                head=str(kw.get("head", "HEAD")),
            )
        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=False,
            summary=f"unknown window: {window!r}",
            error=f"CodeXRay supports 'log', 'blame', 'diff'; got {window!r}",
        )

    # ------------------------------------------------------------------
    # Git helpers
    # ------------------------------------------------------------------

    def _run(self, args: list[str]) -> tuple[bool, str]:
        """Run `git -C <root> <args>` and return (success, output)."""
        cmd = ["git", "-C", str(self._root)] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._GIT_TIMEOUT,
            )
        except FileNotFoundError:
            return False, "git binary not found on PATH"
        except subprocess.TimeoutExpired:
            return False, f"git command timed out after {self._GIT_TIMEOUT}s"

        if result.returncode != 0:
            return False, result.stderr.strip() or f"git exited {result.returncode}"
        return True, result.stdout

    def _git_log(self, n: int) -> InteractionEnvelope:
        ok, output = self._run(
            ["log", f"-{n}", "--pretty=format:%H|%an|%ad|%s", "--date=short"]
        )
        if not ok:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary=f"git log failed: {output}",
                error=output,
            )
        lines = output.strip().splitlines()
        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=True,
            summary=f"git log: {len(lines)} commit(s)",
            artifacts={"lines": output},
        )

    def _git_blame(
        self,
        path: str,
        start: object,
        end: object,
    ) -> InteractionEnvelope:
        if not path:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary="path argument required for window='blame'",
                error="missing path",
            )
        args = ["blame", "--line-porcelain"]
        if start is not None and end is not None:
            args += [f"-L{int(start)},{int(end)}"]
        args.append(path)
        ok, output = self._run(args)
        if not ok:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary=f"git blame failed: {output}",
                error=output,
            )
        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=True,
            summary=f"git blame: {path}",
            artifacts={"path": path, "lines": output},
        )

    def _git_diff(self, base: str, head: str) -> InteractionEnvelope:
        if not base:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary="base argument required for window='diff'",
                error="missing base",
            )
        ok, output = self._run(["diff", base, head])
        if not ok:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary=f"git diff failed: {output}",
                error=output,
            )
        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=True,
            summary=f"git diff {base}..{head}: {len(output.splitlines())} line(s)",
            artifacts={"base": base, "head": head, "lines": output},
        )
