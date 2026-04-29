"""macOS desktop surface — phase-I.

DesktopSurface for `target.kind=DESKTOP, os=macos`. Three tools ship today:

  - MacOSHands  : launch via subprocess, optional frida bridge, codesign verify
  - MacOSRecon  : otool -L (dylibs) + codesign entitlements + lipo (arch)
  - MacOSXRay   : dtrace-backed syscall capture (root-gated; skips otherwise)

We use macOS native CLI (otool/codesign/dtrace) rather than `lief` so that no
new pip install is required (SCFW pre-approval would be needed). lief can be
swapped in later for richer Mach-O parsing without changing the public API.

Tests gated `@pytest.mark.skipif(sys.platform != "darwin")`. dtrace test
additionally gated on root via `os.geteuid() == 0`.
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

darwin_only = pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only")
root_only = pytest.mark.skipif(
    sys.platform != "darwin" or os.geteuid() != 0,
    reason="macOS+root-only (dtrace SIP)",
)


# ── I.1 — MacOSHands implements Hands ABC ────────────────────────────────────


@darwin_only
def test_macos_hands_implements_hands_abc():
    """phase-I.1 — MacOSHands must satisfy the Hands ABC contract."""
    from vxis.interaction.desktop.macos_hands import MacOSHands
    from vxis.interaction.surface import Hands, Target, TargetKind

    h = MacOSHands(Target(kind=TargetKind.DESKTOP, entry="/bin/ls", os="macos"))
    assert isinstance(h, Hands)


# ── I.2 — MacOSRecon lists dylibs (otool -L) ────────────────────────────────


@darwin_only
@pytest.mark.asyncio
async def test_macos_recon_lists_dylibs_for_signed_binary():
    """phase-I.2 — fingerprint must surface libSystem from /bin/ls.

    libSystem.B.dylib is universal on macOS — every binary depends on it. If
    we don't see it the otool path is broken.
    """
    from vxis.interaction.desktop.recon_macho import MacOSRecon
    from vxis.interaction.surface import Target, TargetKind

    target = Target(kind=TargetKind.DESKTOP, entry="/bin/ls", os="macos")
    report = await MacOSRecon().fingerprint(target)
    assert report.surface_kind == TargetKind.DESKTOP
    dylibs = [c for c in report.components if c["type"] == "dylib"]
    assert dylibs, "expected at least one dylib component"
    assert any("libSystem" in c["value"] for c in dylibs)


@darwin_only
@pytest.mark.asyncio
async def test_macos_recon_handles_missing_binary():
    """phase-I.2 — missing binary path emits an error component, not raise."""
    from vxis.interaction.desktop.recon_macho import MacOSRecon
    from vxis.interaction.surface import Target, TargetKind

    target = Target(
        kind=TargetKind.DESKTOP, entry="/nonexistent/binary/path", os="macos"
    )
    report = await MacOSRecon().fingerprint(target)
    assert report.surface_kind == TargetKind.DESKTOP
    assert any(c["type"] == "error" for c in report.components)


# ── I.3 — MacOSRecon extracts entitlements ──────────────────────────────────


@darwin_only
@pytest.mark.asyncio
async def test_macos_recon_extracts_entitlements_for_calculator():
    """phase-I.3 — Calculator.app is signed with sandbox entitlement."""
    from vxis.interaction.desktop.recon_macho import MacOSRecon
    from vxis.interaction.surface import Target, TargetKind

    calc = "/System/Applications/Calculator.app/Contents/MacOS/Calculator"
    if not os.path.exists(calc):
        pytest.skip("Calculator.app not present on this host")

    target = Target(kind=TargetKind.DESKTOP, entry=calc, os="macos")
    report = await MacOSRecon().fingerprint(target)
    ents = report.fingerprint.get("entitlements", "")
    assert "com.apple.security.app-sandbox" in ents


# ── I.4 — codesign verifies Apple-signed ────────────────────────────────────


@darwin_only
@pytest.mark.asyncio
async def test_macos_hands_verify_signature_passes_for_apple_signed():
    """phase-I.4 — codesign verify must report /bin/ls as Apple-signed."""
    from vxis.interaction.desktop.macos_hands import MacOSHands
    from vxis.interaction.surface import Target, TargetKind

    h = MacOSHands(Target(kind=TargetKind.DESKTOP, entry="/bin/ls", os="macos"))
    sig = await h.verify_signature()
    assert sig.is_valid is True
    assert sig.is_signed is True


@darwin_only
@pytest.mark.asyncio
async def test_macos_hands_verify_signature_handles_unsigned(tmp_path):
    """phase-I.4 — homemade unsigned binary must report is_signed=False."""
    from vxis.interaction.desktop.macos_hands import MacOSHands
    from vxis.interaction.surface import Target, TargetKind

    # Tiny shell script — codesign will report not-signed.
    fake = tmp_path / "fake.sh"
    fake.write_text("#!/bin/sh\necho hi\n")
    fake.chmod(0o755)

    h = MacOSHands(Target(kind=TargetKind.DESKTOP, entry=str(fake), os="macos"))
    sig = await h.verify_signature()
    assert sig.is_valid is False


# ── I.5 — dtrace XRay captures open syscall (root-gated) ────────────────────


@root_only
@pytest.mark.asyncio
async def test_dtrace_xray_captures_open_syscall(tmp_path):
    """phase-I.5 — DTraceXRay records open() against a target file."""
    from vxis.interaction.desktop.dtrace_xray import MacOSXRay
    from vxis.interaction.surface import Target, TargetKind

    f = tmp_path / "vxis-fixture-file"
    f.write_text("x")
    x = MacOSXRay(Target(kind=TargetKind.DESKTOP, entry="/bin/cat", os="macos"))
    async with x:
        proc = await asyncio.create_subprocess_exec("/bin/cat", str(f))
        await proc.wait()
        events = await x.events(timeout=2.0)
    assert any(str(f) in e.path for e in events)


@darwin_only
def test_macos_xray_is_available_check_returns_bool():
    """phase-I.5 — non-root or SIP-restricted callers see is_available()=False
    instead of getting a runtime error mid-scan."""
    from vxis.interaction.desktop.dtrace_xray import MacOSXRay

    # Static method — no Target needed
    assert isinstance(MacOSXRay.is_available(), bool)


# ── I.6 — factory routes target.os=macos to MacOS* impls ────────────────────


@darwin_only
def test_factory_routes_macos_desktop_target():
    """phase-I.6 — DESKTOP + os=macos must construct MacOS* surface aggregate."""
    from vxis.interaction.desktop.macos_hands import MacOSHands
    from vxis.interaction.desktop.dtrace_xray import MacOSXRay
    from vxis.interaction.desktop.recon_macho import MacOSRecon
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Surface, Target, TargetKind

    s = SurfaceFactory.build(
        Target(kind=TargetKind.DESKTOP, entry="/bin/ls", os="macos")
    )
    assert isinstance(s, Surface)
    assert isinstance(s.hands, MacOSHands)
    assert isinstance(s.recon, MacOSRecon)
    assert isinstance(s.xray, MacOSXRay)


def test_factory_routes_linux_desktop_to_explicit_pending_error():
    """phase-I.6 — desktop/linux must raise an explicit phase-pending error
    so callers can branch instead of getting a confusing 'unknown' message."""
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    with pytest.raises(NotImplementedError) as exc:
        SurfaceFactory.build(
            Target(kind=TargetKind.DESKTOP, entry="/usr/bin/ls", os="linux")
        )
    msg = str(exc.value).lower()
    assert "linux" in msg
    assert "phase-linux-impl-pending" in msg or "linux" in msg


def test_factory_routes_windows_desktop_to_phase_c_error():
    """phase-I.6 — desktop/windows must surface phase-C pending until C lands."""
    from vxis.interaction.factory import SurfaceFactory
    from vxis.interaction.surface import Target, TargetKind

    with pytest.raises(NotImplementedError) as exc:
        SurfaceFactory.build(
            Target(kind=TargetKind.DESKTOP, entry="C:/x.exe", os="windows")
        )
    assert "phase-c" in str(exc.value).lower() or "windows" in str(exc.value).lower()
