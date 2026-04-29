"""Tests for the test_deeplink_abuse desktop skill (DESK-DLK-001/002/003).

Uses tmp_path to create synthetic .app bundles with valid binary plist
Info.plist files. No subprocess calls — skill is pure static analysis.
"""
from __future__ import annotations

import os
import plistlib
from typing import Any

import pytest

from vxis.agent.skills.desktop.test_deeplink_abuse import execute


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app(tmp_path, plist_data: dict[str, Any]) -> str:
    """Create a minimal .app bundle with the given Info.plist dict.

    Returns the path to the .app root.
    """
    app = tmp_path / "TestApp.app"
    contents = app / "Contents"
    contents.mkdir(parents=True)
    info_plist = contents / "Info.plist"
    with open(info_plist, "wb") as fh:
        plistlib.dump(plist_data, fh)
    return str(app)


def _url_type(schemes: list[str], role: str | None = None) -> dict[str, Any]:
    """Build a CFBundleURLTypes entry dict."""
    entry: dict[str, Any] = {"CFBundleURLSchemes": schemes}
    if role is not None:
        entry["CFBundleTypeRole"] = role
    return entry


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_generic_scheme_emits_dlk_001(tmp_path):
    """'app' scheme is in _GENERIC_SCHEMES → DESK-DLK-001 medium finding."""
    app_root = _make_app(tmp_path, {
        "CFBundleURLTypes": [_url_type(["app"], role="Viewer")],
    })
    result = await execute(app_root)

    assert result["scanned"] == 1
    assert "error" not in result
    dlk001 = [f for f in result["findings"] if f["vector"] == "DESK-DLK-001"]
    assert len(dlk001) == 1
    assert dlk001[0]["severity"] == "medium"
    assert dlk001[0]["scheme"] == "app"


@pytest.mark.asyncio
async def test_short_scheme_emits_dlk_001(tmp_path):
    """A 2-character scheme like 'xx' matches ^[a-z]{1,3}$ → DESK-DLK-001."""
    app_root = _make_app(tmp_path, {
        "CFBundleURLTypes": [_url_type(["xx"], role="Viewer")],
    })
    result = await execute(app_root)

    dlk001 = [f for f in result["findings"] if f["vector"] == "DESK-DLK-001"]
    assert len(dlk001) == 1
    assert dlk001[0]["scheme"] == "xx"


@pytest.mark.asyncio
async def test_specific_scheme_no_dlk_001(tmp_path):
    """A unique, long scheme like 'mycompany-uniqueapp' must NOT emit DLK-001."""
    app_root = _make_app(tmp_path, {
        "CFBundleURLTypes": [_url_type(["mycompany-uniqueapp"], role="Viewer")],
    })
    result = await execute(app_root)

    dlk001 = [f for f in result["findings"] if f["vector"] == "DESK-DLK-001"]
    assert len(dlk001) == 0


@pytest.mark.asyncio
async def test_missing_role_emits_dlk_002(tmp_path):
    """url_type with schemes but no CFBundleTypeRole → DESK-DLK-002 high."""
    app_root = _make_app(tmp_path, {
        "CFBundleURLTypes": [_url_type(["myspecialapp"])],  # no role kwarg
    })
    result = await execute(app_root)

    dlk002 = [f for f in result["findings"] if f["vector"] == "DESK-DLK-002"]
    assert len(dlk002) == 1
    assert dlk002[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_role_present_no_dlk_002(tmp_path):
    """url_type with CFBundleTypeRole=Viewer must NOT emit DLK-002."""
    app_root = _make_app(tmp_path, {
        "CFBundleURLTypes": [_url_type(["myspecialapp"], role="Viewer")],
    })
    result = await execute(app_root)

    dlk002 = [f for f in result["findings"] if f["vector"] == "DESK-DLK-002"]
    assert len(dlk002) == 0


@pytest.mark.asyncio
async def test_six_schemes_emit_dlk_003(tmp_path):
    """Total scheme count > 5 across all url_types → exactly one DESK-DLK-003."""
    # 3 entries × 2 schemes each = 6 total → triggers DLK-003
    app_root = _make_app(tmp_path, {
        "CFBundleURLTypes": [
            _url_type(["myapp-alpha", "myapp-beta"], role="Viewer"),
            _url_type(["myapp-gamma", "myapp-delta"], role="Viewer"),
            _url_type(["myapp-epsilon", "myapp-zeta"], role="Viewer"),
        ],
    })
    result = await execute(app_root)

    dlk003 = [f for f in result["findings"] if f["vector"] == "DESK-DLK-003"]
    assert len(dlk003) == 1, "DLK-003 should fire exactly once regardless of entry count"
    assert dlk003[0]["severity"] == "medium"
    assert dlk003[0]["total_scheme_count"] == 6


@pytest.mark.asyncio
async def test_no_url_types_no_findings(tmp_path):
    """Info.plist present but no CFBundleURLTypes key → 0 findings (clean app)."""
    app_root = _make_app(tmp_path, {
        "CFBundleName": "CleanApp",
        "CFBundleIdentifier": "com.example.cleanapp",
    })
    result = await execute(app_root)

    assert result["scanned"] == 1
    assert result["findings"] == []
    assert result["schemes"] == []
    assert "error" not in result


@pytest.mark.asyncio
async def test_missing_info_plist_returns_error(tmp_path):
    """No Contents/Info.plist → error key, not a finding, scanned=0."""
    app = tmp_path / "NoInfo.app"
    (app / "Contents").mkdir(parents=True)
    # Do NOT create Info.plist
    result = await execute(str(app))

    assert result["scanned"] == 0
    assert result["findings"] == []
    assert "error" in result
    assert "Info.plist not found" in result["error"]


@pytest.mark.asyncio
async def test_handles_corrupt_plist_gracefully(tmp_path):
    """A file that is not a valid plist → graceful error, no exception raised."""
    app = tmp_path / "CorruptApp.app"
    (app / "Contents").mkdir(parents=True)
    with open(app / "Contents" / "Info.plist", "wb") as fh:
        fh.write(b"THIS IS NOT A VALID PLIST !!!")

    result = await execute(str(app))

    assert result["scanned"] == 0
    assert "error" in result
    assert "plist parse error" in result["error"]
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_finding_has_bilingual_description(tmp_path):
    """Every finding's title and description must contain the '|||' bilingual separator."""
    app_root = _make_app(tmp_path, {
        "CFBundleURLTypes": [
            _url_type(["auth"]),                    # DLK-001 + DLK-002
            _url_type(["myapp-s2"], role="Viewer"),
            _url_type(["myapp-s3"], role="Viewer"),
            _url_type(["myapp-s4"], role="Viewer"),
            _url_type(["myapp-s5"], role="Viewer"),
            _url_type(["myapp-s6"], role="Viewer"), # 6 total → DLK-003
        ],
    })
    result = await execute(app_root)

    assert len(result["findings"]) > 0, "Expected at least one finding"
    for finding in result["findings"]:
        assert "|||" in finding["title"], (
            f"Finding {finding['vector']} title missing bilingual separator"
        )
        assert "|||" in finding["description"], (
            f"Finding {finding['vector']} description missing bilingual separator"
        )
