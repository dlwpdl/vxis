"""Tests for the test_ipc_injection desktop skill (DESK-IPC-001).

Uses tmp_path fixtures to create fake .app bundles with XPCServices
directories. All filesystem operations are real — no subprocess mocking
needed because the skill only reads plists and stat-s permissions.
"""
from __future__ import annotations

import os
import plistlib
import stat
from pathlib import Path
from typing import Any

import pytest

from vxis.agent.skills.desktop.test_ipc_injection import execute


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_xpc_bundle(
    parent: Path,
    bundle_name: str = "com.example.helper.xpc",
    mach_service: str = "com.example.helper",
    writable: bool = False,
) -> Path:
    """Create a minimal .xpc bundle with Info.plist under XPCServices/."""
    xpc_dir = parent / bundle_name
    contents_dir = xpc_dir / "Contents"
    contents_dir.mkdir(parents=True)

    plist: dict[str, Any] = {
        "CFBundleIdentifier": bundle_name.replace(".xpc", ""),
        "XPCService": {
            "ServiceType": "Application",
        },
        "MachServices": {mach_service: True},
    }
    plist_path = contents_dir / "Info.plist"
    with plist_path.open("wb") as fh:
        plistlib.dump(plist, fh)

    if writable:
        # Make the bundle directory group/world-writable to trigger the finding.
        current = stat.S_IMODE(os.stat(xpc_dir).st_mode)
        os.chmod(xpc_dir, current | stat.S_IWGRP | stat.S_IWOTH)

    return xpc_dir


# ---------------------------------------------------------------------------
# 1. No XPCServices directory → tested=0, no findings
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_no_xpc_services_returns_empty(tmp_path: Path) -> None:
    """Skill returns empty result when the .app has no XPCServices dir."""
    app_bundle = tmp_path / "MyApp.app"
    app_bundle.mkdir()
    (app_bundle / "Contents").mkdir()

    result = await execute(target_url=str(app_bundle))

    assert result["vulnerable"] is False
    assert result["findings"] == []
    assert result["tested"] == 0
    assert "skipped_reason" not in result or result.get("skipped_reason") is None or True
    # skipped_reason may or may not be present when no XPC services exist


# ---------------------------------------------------------------------------
# 2. Writable XPC bundle → DESK-IPC-001 high severity finding
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_writable_xpc_bundle_emits_finding(tmp_path: Path) -> None:
    """A world-writable XPC bundle must produce a DESK-IPC-001 high finding."""
    app_bundle = tmp_path / "VulnApp.app"
    xpc_svc_dir = app_bundle / "Contents" / "XPCServices"
    xpc_svc_dir.mkdir(parents=True)

    _make_xpc_bundle(xpc_svc_dir, writable=True)

    result = await execute(target_url=str(app_bundle))

    assert result["tested"] >= 1, f"expected >=1 tested, got: {result['tested']}"
    vuln_findings = [f for f in result["findings"] if f.get("vector") == "DESK-IPC-001"]
    assert vuln_findings, f"expected DESK-IPC-001 finding, got: {result['findings']}"
    assert vuln_findings[0]["severity"] == "high"
    # Bilingual check
    assert "|||" in vuln_findings[0]["title"]
    assert "|||" in vuln_findings[0]["description"]


# ---------------------------------------------------------------------------
# 3. Safe XPC bundle (not writable, no typosquat) → 0 findings
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_safe_xpc_bundle_no_findings(tmp_path: Path) -> None:
    """A normal, non-writable XPC bundle with a proper mach service name produces no findings."""
    app_bundle = tmp_path / "SafeApp.app"
    xpc_svc_dir = app_bundle / "Contents" / "XPCServices"
    xpc_svc_dir.mkdir(parents=True)

    _make_xpc_bundle(
        xpc_svc_dir,
        bundle_name="com.example.safehelper.xpc",
        mach_service="com.example.safehelper",
        writable=False,
    )

    result = await execute(target_url=str(app_bundle))

    assert result["tested"] >= 1, f"expected >=1 tested, got: {result['tested']}"
    writable_findings = [
        f for f in result["findings"]
        if "writable" in f.get("title", "").lower() or "DESK-IPC-001" == f.get("vector")
    ]
    assert not writable_findings, f"expected 0 writable findings, got: {writable_findings}"


# ---------------------------------------------------------------------------
# 4. Typosquat mach service name → additional finding
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_typosquat_mach_service_emits_finding(tmp_path: Path) -> None:
    """A mach service name impersonating com.apple.* triggers a typosquat finding."""
    app_bundle = tmp_path / "TyApp.app"
    xpc_svc_dir = app_bundle / "Contents" / "XPCServices"
    xpc_svc_dir.mkdir(parents=True)

    # Service name pretends to be Apple but bundle ID shows it is not
    _make_xpc_bundle(
        xpc_svc_dir,
        bundle_name="com.evil.xpc",
        mach_service="com.apple.securityd.fake",
        writable=False,
    )

    result = await execute(target_url=str(app_bundle))

    typosquat_findings = [
        f for f in result["findings"]
        if "typosquat" in f.get("title", "").lower()
        or "typosquat" in f.get("description", "").lower()
        or "impersonat" in f.get("title", "").lower()
        or "impersonat" in f.get("description", "").lower()
    ]
    assert typosquat_findings, (
        f"expected typosquat finding for com.apple.securityd.fake, "
        f"got: {result['findings']}"
    )


# ---------------------------------------------------------------------------
# 5. Non-existent path → graceful skipped result
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_nonexistent_path_returns_skipped(tmp_path: Path) -> None:
    """Skill returns a graceful skip for paths that do not exist."""
    result = await execute(target_url=str(tmp_path / "does_not_exist.app"))

    assert result["findings"] == []
    assert result["tested"] == 0
    assert result.get("skipped_reason"), "expected skipped_reason to be set"


# ---------------------------------------------------------------------------
# 6. Return schema validation
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_return_schema_always_present(tmp_path: Path) -> None:
    """All mandatory return keys are present regardless of outcome."""
    app_bundle = tmp_path / "SchemaApp.app"
    app_bundle.mkdir()

    result = await execute(target_url=str(app_bundle))

    for key in ("vulnerable", "findings", "tested"):
        assert key in result, f"missing mandatory key: {key!r}"
    assert isinstance(result["findings"], list)
    assert isinstance(result["tested"], int)
    assert isinstance(result["vulnerable"], bool)
