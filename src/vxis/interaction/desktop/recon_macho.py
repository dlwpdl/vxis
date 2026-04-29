"""MacOSRecon — phase-I.

Static fingerprint for Mach-O binaries via macOS native CLI:

  - `otool -L <bin>`  → linked dylibs
  - `lipo -info <bin>` → architecture(s)
  - `codesign --display --entitlements :- <bin>` → entitlements XML
  - `codesign --verify --deep --strict <bin>` → signed/unsigned

We use CLI rather than `lief` so no third-party dep install is needed
(SCFW pre-approval would block); lief can replace the otool path later
without breaking the public ReconReport contract.

Each component is a `{"type": ..., "value": ...}` dict matching the shape
WindowsRecon (phase-D) and WebRecon (phase-B) emit so the downstream Brain
prompt template works unchanged across surfaces.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re

from vxis.interaction.surface import Recon, ReconReport, Target, TargetKind

logger = logging.getLogger(__name__)


_OTOOL_DYLIB_RE = re.compile(r"^\s+(\S+\.dylib)\b")


class MacOSRecon(Recon):
    async def fingerprint(self, target: Target) -> ReconReport:
        binary = target.entry
        components: list[dict[str, str]] = []
        fingerprint: dict[str, str] = {"path": binary, "os": "macos"}

        if not os.path.exists(binary):
            components.append(
                {"type": "error", "value": f"binary not found: {binary}"}
            )
            return ReconReport(
                surface_kind=TargetKind.DESKTOP,
                fingerprint=fingerprint,
                components=components,
            )

        # 1) dylibs via otool -L
        dylibs = await self._otool_dylibs(binary)
        for d in dylibs:
            components.append({"type": "dylib", "value": d})
        fingerprint["dylib_count"] = str(len(dylibs))

        # 2) architectures via lipo -info
        arches = await self._lipo_arches(binary)
        if arches:
            fingerprint["arch"] = ",".join(arches)
            for a in arches:
                components.append({"type": "arch", "value": a})

        # 3) entitlements via codesign
        ents = await self._codesign_entitlements(binary)
        if ents:
            fingerprint["entitlements"] = ents
            # surface every <key>com.apple.*</key> as a component for Brain
            for m in re.finditer(r"<key>([^<]+)</key>", ents):
                components.append({"type": "entitlement", "value": m.group(1)})

        # 4) signature presence
        signed = await self._codesign_verify(binary)
        components.append(
            {"type": "signature", "value": "valid" if signed else "unsigned"}
        )
        fingerprint["signed"] = str(signed)

        return ReconReport(
            surface_kind=TargetKind.DESKTOP,
            fingerprint=fingerprint,
            components=components,
        )

    @staticmethod
    async def _run(*cmd: str, timeout: float = 10.0) -> tuple[int, str, str]:
        """Run an external CLI tool and return (rc, stdout, stderr) text."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return (
                proc.returncode or 0,
                stdout.decode(errors="replace"),
                stderr.decode(errors="replace"),
            )
        except (FileNotFoundError, asyncio.TimeoutError) as exc:
            logger.warning("MacOSRecon._run %s failed: %s", cmd[0], exc)
            return (-1, "", str(exc))

    async def _otool_dylibs(self, binary: str) -> list[str]:
        rc, stdout, _ = await self._run("otool", "-L", binary)
        if rc != 0:
            return []
        results: list[str] = []
        for line in stdout.splitlines():
            m = _OTOOL_DYLIB_RE.match(line)
            if m:
                results.append(m.group(1))
        return results

    async def _lipo_arches(self, binary: str) -> list[str]:
        rc, stdout, _ = await self._run("lipo", "-info", binary)
        if rc != 0:
            return []
        # "Non-fat file: /bin/ls is architecture: arm64"
        # "Architectures in the fat file: foo are: x86_64 arm64"
        m = re.search(r"(?:architecture|are): (.+)$", stdout.strip())
        if not m:
            return []
        return m.group(1).strip().split()

    async def _codesign_entitlements(self, binary: str) -> str:
        # `codesign --display --entitlements - <bin>` prints to stdout in modern
        # codesign; older versions need the `:-` syntax. Try both.
        rc, stdout, _ = await self._run(
            "codesign", "--display", "--entitlements", "-", binary
        )
        if rc == 0 and stdout.strip():
            return stdout
        # fallback to legacy `:-`
        rc, stdout, _ = await self._run(
            "codesign", "--display", "--entitlements", ":-", binary
        )
        return stdout if rc == 0 else ""

    async def _codesign_verify(self, binary: str) -> bool:
        rc, _, _ = await self._run(
            "codesign", "--verify", "--deep", "--strict", binary
        )
        return rc == 0


__all__ = ["MacOSRecon"]
