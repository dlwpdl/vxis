"""MacOSHands — phase-I.

Launches macOS .app / Mach-O binary as a subprocess and exposes a small
`request(intent, **kw)` dispatch table. Today's intents:

  - "launch"       → spawn the binary, return PID
  - "terminate"    → kill the running process
  - "verify_sig"   → run `codesign --verify --deep --strict` and report

Frida bridge is intentionally NOT wired here — frida-mobile/frida-core would
need SCFW pre-approval and a separate `frida_bridge.py`. We keep the surface
contract and let later phases plug Frida in via additional intents.

`verify_signature()` returns a small `SignatureStatus` so Brain can chain
"unsigned macOS binary" → "downgrade trust" findings without parsing
codesign stderr itself.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from vxis.interaction.surface import Hands, InteractionEnvelope, Target, TargetKind

logger = logging.getLogger(__name__)


@dataclass
class SignatureStatus:
    """Outcome of `codesign --verify` against a Mach-O binary."""

    is_signed: bool
    is_valid: bool
    detail: str = ""


class MacOSHands(Hands):
    def __init__(self, target: Target) -> None:
        self._target = target
        self._proc: Optional[asyncio.subprocess.Process] = None

    async def start(self) -> None:
        # No-op until an explicit `launch` intent — Brain owns when the
        # process actually spawns so it can pre-attach an XRay first.
        return None

    async def stop(self) -> None:
        if self._proc is not None and self._proc.returncode is None:
            try:
                self._proc.terminate()
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    self._proc.kill()
                    await self._proc.wait()
            except ProcessLookupError:
                pass
        self._proc = None

    async def request(self, intent: str, **kw: object) -> InteractionEnvelope:
        intent_norm = intent.lower()
        try:
            if intent_norm == "launch":
                return await self._launch(**kw)
            if intent_norm == "terminate":
                await self.stop()
                return InteractionEnvelope(
                    surface_kind=TargetKind.DESKTOP,
                    success=True,
                    summary="terminated",
                )
            if intent_norm in {"verify_sig", "verify_signature"}:
                sig = await self.verify_signature()
                return InteractionEnvelope(
                    surface_kind=TargetKind.DESKTOP,
                    success=sig.is_valid,
                    summary=(
                        f"signed={sig.is_signed} valid={sig.is_valid} {sig.detail}"
                    ),
                    artifacts={
                        "is_signed": str(sig.is_signed),
                        "is_valid": str(sig.is_valid),
                    },
                )
            return InteractionEnvelope(
                surface_kind=TargetKind.DESKTOP,
                success=False,
                summary=f"unknown intent: {intent}",
                error=f"MacOSHands intent '{intent}' not implemented",
            )
        except Exception as exc:
            logger.warning("MacOSHands.request(%s) failed: %s", intent, exc)
            return InteractionEnvelope(
                surface_kind=TargetKind.DESKTOP,
                success=False,
                summary=f"intent={intent}",
                error=str(exc),
            )

    async def _launch(self, **kw: object) -> InteractionEnvelope:
        args_raw = kw.get("args", [])
        if not isinstance(args_raw, (list, tuple)):
            args_raw = []
        args = [str(a) for a in args_raw]
        self._proc = await asyncio.create_subprocess_exec(
            self._target.entry,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return InteractionEnvelope(
            surface_kind=TargetKind.DESKTOP,
            success=True,
            summary=f"launched pid={self._proc.pid}",
            artifacts={"pid": str(self._proc.pid)},
        )

    async def verify_signature(self) -> SignatureStatus:
        """Run `codesign --verify --deep --strict <entry>`.

        Return code 0 → valid signature. Non-zero → either unsigned or
        signature broken; we read the first stderr line to disambiguate.
        """
        proc = await asyncio.create_subprocess_exec(
            "codesign",
            "--verify",
            "--deep",
            "--strict",
            self._target.entry,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        detail = stderr.decode(errors="replace").strip().splitlines()
        first_line = detail[0] if detail else ""
        is_valid = proc.returncode == 0
        # codesign prints "code object is not signed at all" for unsigned bins.
        is_signed = is_valid or "not signed" not in first_line.lower()
        return SignatureStatus(
            is_signed=is_signed, is_valid=is_valid, detail=first_line
        )


__all__ = ["MacOSHands", "SignatureStatus"]
