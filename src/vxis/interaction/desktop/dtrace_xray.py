"""MacOSXRay — phase-I.

dtrace-backed syscall capture for macOS desktop targets. dtrace is gated by
SIP since Big Sur (10.15+) — most consumer macs have SIP enabled, so dtrace
calls return EPERM unless the user has booted into recovery and run
`csrutil disable`. The `is_available()` check filters this so callers can
fall back gracefully (e.g. ETW-only on Windows, frida-only on macOS).

Today's surface: `capture("syscall", duration_s=N)` runs a one-off dtrace
script for N seconds and parses each line into a `SyscallEvent`. Brain
gets back an `InteractionEnvelope` with the events serialised under
`artifacts["events_jsonl"]` and the count under `artifacts["count"]`.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass

from vxis.interaction.surface import (
    InteractionEnvelope,
    Target,
    TargetKind,
    XRay,
)

logger = logging.getLogger(__name__)


@dataclass
class SyscallEvent:
    syscall: str
    pid: int
    path: str = ""


class MacOSXRay(XRay):
    def __init__(self, target: Target, pid: int | None = None) -> None:
        self._target = target
        # system-wide capture leaks unrelated process events into the scan report
        self._pid = pid
        self._captured: list[SyscallEvent] = []
        self._running = False

    @staticmethod
    def is_available() -> bool:
        """True only when dtrace is reachable and the caller has root.

        Production callers should branch on this and fall back to a
        Frida-only XRay when False (the dtrace SIP gate hits most users).
        """
        if sys.platform != "darwin":
            return False
        if shutil.which("dtrace") is None:
            return False
        try:
            return os.geteuid() == 0
        except AttributeError:  # non-POSIX, defensive
            return False

    async def __aenter__(self) -> "MacOSXRay":
        await self.start()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.stop()

    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False

    async def capture(self, window: str, **kw: object) -> InteractionEnvelope:
        if not self.is_available():
            return InteractionEnvelope(
                surface_kind=TargetKind.DESKTOP,
                success=False,
                summary="dtrace unavailable (SIP / non-root / non-darwin)",
                error="dtrace not available",
            )

        duration = float(kw.get("duration_s", 5.0) or 5.0)
        events = await self._dtrace_open_syscalls(duration)
        self._captured.extend(events)

        # Persist as JSONL so downstream FlowAnalyzer / consumers can ingest.
        tmpdir = tempfile.mkdtemp(prefix="vxis_macos_xray_")
        out = os.path.join(tmpdir, "events.jsonl")
        with open(out, "w") as fh:
            for e in events:
                fh.write(
                    json.dumps(
                        {"syscall": e.syscall, "pid": e.pid, "path": e.path}
                    )
                    + "\n"
                )

        return InteractionEnvelope(
            surface_kind=TargetKind.DESKTOP,
            success=True,
            summary=f"capture window={window}: {len(events)} syscall events",
            artifacts={"events_jsonl": out, "count": str(len(events))},
        )

    async def events(self, timeout: float = 0.0) -> list[SyscallEvent]:
        """Drain the running capture buffer (used by the dtrace test)."""
        if timeout > 0 and not self._captured:
            # If a capture wasn't run yet, do a default one
            duration = max(timeout, 1.0)
            self._captured = await self._dtrace_open_syscalls(duration)
        return list(self._captured)

    async def _dtrace_open_syscalls(self, duration_s: float) -> list[SyscallEvent]:
        """Run dtrace for `duration_s` seconds capturing open*() syscalls.

        Script prints:    pid<TAB>path
        Anything else is ignored (banners, errors).
        """
        if self._pid is not None:
            predicate = f"/pid == {self._pid}/"
        else:
            logger.warning("dtrace running system-wide — set pid to scope")
            predicate = ""
        script = (
            f"syscall::open*:entry {predicate} "
            '{ printf("%d\\t%s\\n", pid, copyinstr(arg0)); }'
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                "dtrace",
                "-q",
                "-n",
                script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.warning("dtrace binary not found")
            return []

        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=duration_s + 1.0
            )
        except asyncio.TimeoutError:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            await proc.wait()
            stdout = b""

        events: list[SyscallEvent] = []
        for line in stdout.decode(errors="replace").splitlines():
            parts = line.split("\t", 1)
            if len(parts) != 2:
                continue
            try:
                pid = int(parts[0].strip())
            except ValueError:
                continue
            events.append(
                SyscallEvent(syscall="open", pid=pid, path=parts[1].strip())
            )
        return events


__all__ = ["MacOSXRay", "SyscallEvent"]
