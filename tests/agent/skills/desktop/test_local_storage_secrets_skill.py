"""Integration tests for the test_local_storage_secrets desktop skill.

Tests cover:
- Detection of planted AWS/GitHub/JWT secrets
- Clean directory returns no findings
- Binary file skipping
- node_modules pruning via _SKIP_DIRS
- .app bundle root climbing via _walk_root
- max_files cap on scanned count
- Missing path error handling
- Bilingual description (|||) requirement
"""
from __future__ import annotations

import os
import pytest

from vxis.agent.skills.desktop.test_local_storage_secrets import execute


# ---------------------------------------------------------------------------
# 1. AWS Access Key detection
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_finds_planted_aws_key(tmp_path):
    """Plant an AWS access key — expect one critical finding with correct metadata."""
    secret_file = tmp_path / "credentials.txt"
    secret_file.write_text("AKIAIOSFODNN7EXAMPLE some config entry\n")

    result = await execute(target_url=str(tmp_path))

    assert result["scanned"] >= 1
    findings = result["findings"]
    assert len(findings) >= 1

    match = next((f for f in findings if f["pattern"] == "aws_access_key"), None)
    assert match is not None, f"expected aws_access_key finding, got: {findings}"
    assert match["severity"] == "critical"
    assert match["vector"] == "DESK-LSS-001"


# ---------------------------------------------------------------------------
# 2. GitHub token detection
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_finds_planted_github_token(tmp_path):
    """Plant a ghp_ token (36 chars after prefix) — expect github_token pattern."""
    token = "ghp_" + "A" * 36
    (tmp_path / "env.json").write_text(f'{{"token": "{token}"}}')

    result = await execute(target_url=str(tmp_path))

    findings = result["findings"]
    match = next((f for f in findings if f["pattern"] == "github_token"), None)
    assert match is not None, f"github_token finding missing; all findings: {findings}"


# ---------------------------------------------------------------------------
# 3. JWT detection
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_finds_jwt(tmp_path):
    """Plant a well-formed three-segment JWT — expect jwt pattern match."""
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.signaturehere1234567"
    (tmp_path / "config.js").write_text(f'const TOKEN = "{jwt}";')

    result = await execute(target_url=str(tmp_path))

    findings = result["findings"]
    match = next((f for f in findings if f["pattern"] == "jwt"), None)
    assert match is not None, f"jwt finding missing; all findings: {findings}"


# ---------------------------------------------------------------------------
# 4. Clean directory — no findings
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_no_findings_on_clean_dir(tmp_path):
    """Innocuous text files must produce zero findings but increment scanned."""
    (tmp_path / "readme.txt").write_text("Hello world. No secrets here.\n")
    (tmp_path / "settings.cfg").write_text("[server]\nhost=localhost\nport=8080\n")

    result = await execute(target_url=str(tmp_path))

    assert result["findings"] == []
    assert result["scanned"] > 0


# ---------------------------------------------------------------------------
# 5. Binary file skipping
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_skips_binary_files(tmp_path):
    """A file containing NUL bytes must be counted in skipped_binary, not findings."""
    # Use a .txt extension so _SKIP_EXT does not trigger — the binary heuristic
    # (_looks_binary) fires instead.
    binary_file = tmp_path / "libsecret.txt"
    binary_file.write_bytes(b"\x00\x01\x02AKIAIOSFODNN7EXAMPLE\x00\x00")

    result = await execute(target_url=str(tmp_path))

    assert result["skipped_binary"] >= 1
    # The secret inside the binary must not leak into findings
    for f in result["findings"]:
        assert "AKIA" not in f.get("snippet", "")


# ---------------------------------------------------------------------------
# 6. _SKIP_DIRS: node_modules is pruned
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_respects_skip_dirs(tmp_path):
    """Secrets inside node_modules/ must be ignored (os.walk prunes it)."""
    node_modules = tmp_path / "node_modules" / "evil-package"
    node_modules.mkdir(parents=True)
    (node_modules / "index.js").write_text('const key = "AKIAIOSFODNN7EXAMPLE";')

    # Also add a clean file in root so scanned > 0 proves the walk ran
    (tmp_path / "clean.txt").write_text("nothing suspicious\n")

    result = await execute(target_url=str(tmp_path))

    # Must not find the secret buried in node_modules
    assert all(
        "node_modules" not in f.get("path", "") for f in result["findings"]
    ), f"node_modules secret leaked into findings: {result['findings']}"


# ---------------------------------------------------------------------------
# 7. .app bundle root climbing
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_walks_app_bundle_from_macho_path(tmp_path):
    """Passing the Mach-O binary path should cause _walk_root to climb to .app
    and then discover secrets in Contents/Resources/."""
    # Build: <tmp>/MyApp.app/Contents/MacOS/MyApp  (the "binary")
    #        <tmp>/MyApp.app/Contents/Resources/secrets.json  (the secret)
    app_bundle = tmp_path / "MyApp.app"
    macos_dir = app_bundle / "Contents" / "MacOS"
    resources_dir = app_bundle / "Contents" / "Resources"
    macos_dir.mkdir(parents=True)
    resources_dir.mkdir(parents=True)

    binary_path = macos_dir / "MyApp"
    binary_path.write_text("MH_MAGIC stub")  # text so skip-ext doesn't drop it

    secret_file = resources_dir / "secrets.json"
    secret_file.write_text('{"aws_key": "AKIAIOSFODNN7EXAMPLE"}')

    result = await execute(target_url=str(binary_path))

    assert any(
        f["pattern"] == "aws_access_key" for f in result["findings"]
    ), f"Expected aws_access_key in findings after bundle climb; got: {result['findings']}"


# ---------------------------------------------------------------------------
# 8. max_files cap
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_max_files_caps_walk(tmp_path):
    """With max_files=10, no more than 10 files should be scanned."""
    for i in range(50):
        (tmp_path / f"secret_{i:02d}.txt").write_text(f"AKIAIOSFODNN7EXAMPLE_{i}\n")

    result = await execute(target_url=str(tmp_path), max_files=10)

    assert result["scanned"] <= 10
    assert len(result["findings"]) <= 10


# ---------------------------------------------------------------------------
# 9. Missing path — error key or scanned == 0
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_returns_error_for_missing_path():
    """A nonexistent path must either return an 'error' key or scanned == 0."""
    result = await execute(target_url="/nonexistent/path/vxis_test_12345")

    # The skill returns {"error": ..., "scanned": 0, ...} when path not found
    has_error = "error" in result
    scanned_zero = result.get("scanned", -1) == 0
    assert has_error or scanned_zero, (
        f"Expected 'error' key or scanned==0 for missing path; got: {result}"
    )


# ---------------------------------------------------------------------------
# 10. Bilingual description
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_finding_has_bilingual_description(tmp_path):
    """Every finding's description must contain the '|||' bilingual separator."""
    (tmp_path / "keys.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")

    result = await execute(target_url=str(tmp_path))

    assert len(result["findings"]) >= 1, "Expected at least one finding"
    for finding in result["findings"]:
        assert "|||" in finding.get("description", ""), (
            f"description missing '|||' separator: {finding.get('description', '')!r}"
        )
