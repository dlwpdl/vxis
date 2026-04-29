"""Tests for the test_electron_misconfig desktop skill (DESK-ELC-001/002/003).

Fixtures use tmp_path to simulate Electron .app bundles without touching real
apps.  All tests are async — Electron framework marker detection and JS walk
run in-process (no I/O to real Electron binaries).
"""
from __future__ import annotations

import os
import pytest

from vxis.agent.skills.desktop.test_electron_misconfig import execute


# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------

def _make_electron_app(tmp_path, main_js_content: str = "") -> tuple[str, str]:
    """Create a minimal Electron .app structure under tmp_path.

    Returns (app_root, main_js_path).
    """
    app = tmp_path / "MyApp.app"
    # Electron marker
    framework_dir = app / "Contents" / "Frameworks" / "Electron Framework.framework"
    framework_dir.mkdir(parents=True)
    # Main process JS
    js_dir = app / "Contents" / "Resources" / "app"
    js_dir.mkdir(parents=True)
    main_js = js_dir / "main.js"
    main_js.write_text(main_js_content)
    return str(app), str(main_js)


# ---------------------------------------------------------------------------
# 1. nodeIntegration: true  →  DESK-ELC-001 (critical)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_detects_node_integration_true(tmp_path):
    app_root, _ = _make_electron_app(
        tmp_path,
        "new BrowserWindow({ nodeIntegration: true, width: 800 });",
    )
    result = await execute(target_url=app_root)

    assert result["is_electron"] is True
    findings = result["findings"]
    match = next((f for f in findings if f["flag"] == "nodeIntegration"), None)
    assert match is not None, f"expected nodeIntegration finding, got: {findings}"
    assert match["severity"] == "critical"
    assert match["vector"] == "DESK-ELC-001"


# ---------------------------------------------------------------------------
# 2. contextIsolation: false  →  DESK-ELC-002 (high)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_detects_context_isolation_false(tmp_path):
    app_root, _ = _make_electron_app(
        tmp_path,
        "new BrowserWindow({ contextIsolation: false });",
    )
    result = await execute(target_url=app_root)

    assert result["is_electron"] is True
    findings = result["findings"]
    match = next((f for f in findings if f["flag"] == "contextIsolation"), None)
    assert match is not None, f"expected contextIsolation finding, got: {findings}"
    assert match["severity"] == "high"
    assert match["vector"] == "DESK-ELC-002"


# ---------------------------------------------------------------------------
# 3. webSecurity: false  →  DESK-ELC-003 (high)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_detects_web_security_false(tmp_path):
    app_root, _ = _make_electron_app(
        tmp_path,
        "new BrowserWindow({ webSecurity: false });",
    )
    result = await execute(target_url=app_root)

    assert result["is_electron"] is True
    findings = result["findings"]
    match = next((f for f in findings if f["flag"] == "webSecurity"), None)
    assert match is not None, f"expected webSecurity finding, got: {findings}"
    assert match["severity"] == "high"
    assert match["vector"] == "DESK-ELC-003"


# ---------------------------------------------------------------------------
# 4. All three flags in one file  →  3 findings
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_detects_all_three_in_one_file(tmp_path):
    app_root, _ = _make_electron_app(
        tmp_path,
        (
            "new BrowserWindow({\n"
            "  nodeIntegration: true,\n"
            "  contextIsolation: false,\n"
            "  webSecurity: false,\n"
            "});\n"
        ),
    )
    result = await execute(target_url=app_root)

    assert result["is_electron"] is True
    flags_found = {f["flag"] for f in result["findings"]}
    assert flags_found == {"nodeIntegration", "contextIsolation", "webSecurity"}, (
        f"expected all three flags, got: {flags_found}"
    )
    assert len(result["findings"]) == 3


# ---------------------------------------------------------------------------
# 5. Secure config  →  0 findings
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_secure_config_no_findings(tmp_path):
    app_root, _ = _make_electron_app(
        tmp_path,
        (
            "new BrowserWindow({\n"
            "  nodeIntegration: false,\n"
            "  contextIsolation: true,\n"
            "  webSecurity: true,\n"
            "});\n"
        ),
    )
    result = await execute(target_url=app_root)

    assert result["is_electron"] is True
    assert result["findings"] == [], f"expected no findings, got: {result['findings']}"


# ---------------------------------------------------------------------------
# 6. Misconfig in node_modules/ is skipped (pruned by _SKIP_DIRS)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_skips_node_modules(tmp_path):
    app_root, _ = _make_electron_app(tmp_path, "// clean main.js")

    # Plant a misconfig inside node_modules — must NOT be reported.
    nm = (
        tmp_path / "MyApp.app" / "Contents" / "Resources" / "app" / "node_modules" / "foo"
    )
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("new BrowserWindow({ nodeIntegration: true });")

    result = await execute(target_url=app_root)

    assert result["is_electron"] is True
    assert result["findings"] == [], (
        f"node_modules misconfig should be pruned, got: {result['findings']}"
    )


# ---------------------------------------------------------------------------
# 7. Non-Electron app  →  is_electron=False, no findings
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_non_electron_app_returns_empty(tmp_path):
    app = tmp_path / "NotElectron.app"
    js_dir = app / "Contents" / "Resources" / "app"
    js_dir.mkdir(parents=True)
    (js_dir / "main.js").write_text("new BrowserWindow({ nodeIntegration: true });")
    # NOTE: no Electron Framework.framework/ dir

    result = await execute(target_url=str(app))

    assert result["is_electron"] is False
    assert result["findings"] == []
    assert result["scanned"] == 0


# ---------------------------------------------------------------------------
# 8. Binary/Mach-O path climbs to .app root
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_walks_app_bundle_from_macho_path(tmp_path):
    app_root, _ = _make_electron_app(
        tmp_path,
        "new BrowserWindow({ nodeIntegration: true });",
    )
    # Simulate a Mach-O binary path inside the bundle.
    macos_dir = tmp_path / "MyApp.app" / "Contents" / "MacOS"
    macos_dir.mkdir(parents=True)
    binary = macos_dir / "MyApp"
    binary.write_bytes(b"\xca\xfe\xba\xbe")  # Mach-O magic bytes

    result = await execute(target_url=str(binary))

    # _walk_root should climb to MyApp.app; Electron marker should be found.
    assert result["is_electron"] is True
    flags = {f["flag"] for f in result["findings"]}
    assert "nodeIntegration" in flags


# ---------------------------------------------------------------------------
# 9. Electron marker exists but Resources/app/ dir is missing  →  graceful empty
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_handles_missing_resources_dir(tmp_path):
    app = tmp_path / "Sparse.app"
    # Only the Electron marker — no Resources/app/ directory.
    framework_dir = app / "Contents" / "Frameworks" / "Electron Framework.framework"
    framework_dir.mkdir(parents=True)

    result = await execute(target_url=str(app))

    assert result["is_electron"] is True
    assert result["findings"] == []
    assert result["scanned"] == 0


# ---------------------------------------------------------------------------
# 10. Bilingual format: all findings have ||| in title and description
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_finding_descriptions_bilingual(tmp_path):
    app_root, _ = _make_electron_app(
        tmp_path,
        (
            "new BrowserWindow({\n"
            "  nodeIntegration: true,\n"
            "  contextIsolation: false,\n"
            "  webSecurity: false,\n"
            "});\n"
        ),
    )
    result = await execute(target_url=app_root)

    assert result["findings"], "expected at least one finding for bilingual check"
    for finding in result["findings"]:
        assert "|||" in finding["title"], (
            f"title missing |||: {finding['title']!r}"
        )
        assert "|||" in finding["description"], (
            f"description missing |||: {finding['description']!r}"
        )
