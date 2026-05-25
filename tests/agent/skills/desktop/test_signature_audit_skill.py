"""Tests for the test_signature_audit desktop skill (DESK-SIG-002/003/004).

All subprocess.run calls are mocked so that tests run without invoking
the real codesign binary.  All tests are async.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vxis.agent.skills.desktop.test_signature_audit import execute


# ---------------------------------------------------------------------------
# Mock factory helpers
# ---------------------------------------------------------------------------


def _mock_proc(returncode: int = 0, stderr: str = "", stdout: str = "") -> MagicMock:
    """Build a fake CompletedProcess return value."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.stderr = stderr
    proc.stdout = stdout
    return proc


_VALID_AUTHORITY_STDERR = (
    "Executable=/Applications/MyApp.app/Contents/MacOS/MyApp\n"
    "Identifier=com.example.myapp\n"
    "Format=app bundle with Mach-O universal (arm64e x86_64)\n"
    "CodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=40+7 location=embedded\n"
    "Authority=Developer ID Application: Example Corp (ABCD1234)\n"
    "Authority=Developer ID Certification Authority\n"
    "Authority=Apple Root CA\n"
    "TeamIdentifier=ABCD1234\n"
    "Timestamp=Apr 23 12:00:00 2026\n"
    "Info.plist entries=26\n"
    "Sealed Resources version=2 rules=13 files=42\n"
    "Internal requirements count=1 size=184\n"
)

_ADHOC_STDERR = (
    "Executable=/tmp/test/MyApp.app/Contents/MacOS/MyApp\n"
    "Identifier=com.example.myapp\n"
    "Format=app bundle with Mach-O thin (arm64)\n"
    "CodeDirectory v=20500 size=512 flags=0x2(adhoc) hashes=16+7 location=embedded\n"
    "Authority=-\n"
    "Timestamp=none\n"
)

_NO_RUNTIME_STDERR = (
    "Executable=/tmp/test/MyApp.app/Contents/MacOS/MyApp\n"
    "Identifier=com.example.myapp\n"
    "Format=app bundle with Mach-O thin (arm64)\n"
    "CodeDirectory v=20500 size=1024 flags=0x0(none) hashes=30+7 location=embedded\n"
    "Authority=Developer ID Application: Example Corp (ABCD1234)\n"
    "Authority=Developer ID Certification Authority\n"
    "Authority=Apple Root CA\n"
)


# ---------------------------------------------------------------------------
# 1. Unsigned binary (returncode=1 + "not signed at all") → DESK-SIG-002
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_unsigned_binary_emits_sig_002(tmp_path):
    target = tmp_path / "MyApp.app"
    target.mkdir()

    proc = _mock_proc(
        returncode=1,
        stderr="/tmp/MyApp.app: code object is not signed at all\n",
    )
    with patch("vxis.agent.skills.desktop.test_signature_audit.subprocess.run", return_value=proc):
        result = await execute(target_url=str(target))

    assert result["signed"] is False
    vectors = [f["vector"] for f in result["findings"]]
    assert "DESK-SIG-002" in vectors, f"expected DESK-SIG-002, got: {vectors}"
    sig_002 = next(f for f in result["findings"] if f["vector"] == "DESK-SIG-002")
    assert sig_002["severity"] == "high"


# ---------------------------------------------------------------------------
# 2. Ad-hoc signed (Authority=-) → DESK-SIG-003
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_adhoc_signed_emits_sig_003(tmp_path):
    target = tmp_path / "MyApp.app"
    target.mkdir()

    proc = _mock_proc(returncode=0, stderr=_ADHOC_STDERR)
    with patch("vxis.agent.skills.desktop.test_signature_audit.subprocess.run", return_value=proc):
        result = await execute(target_url=str(target))

    assert result["signed"] is True
    vectors = [f["vector"] for f in result["findings"]]
    assert "DESK-SIG-003" in vectors, f"expected DESK-SIG-003, got: {vectors}"
    sig_003 = next(f for f in result["findings"] if f["vector"] == "DESK-SIG-003")
    assert sig_003["severity"] == "medium"


# ---------------------------------------------------------------------------
# 3. No Hardened Runtime (flags lacks 0x10000) → DESK-SIG-004
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_no_hardened_runtime_emits_sig_004(tmp_path):
    target = tmp_path / "MyApp.app"
    target.mkdir()

    proc = _mock_proc(returncode=0, stderr=_NO_RUNTIME_STDERR)
    with patch("vxis.agent.skills.desktop.test_signature_audit.subprocess.run", return_value=proc):
        result = await execute(target_url=str(target))

    assert result["signed"] is True
    assert result["hardened_runtime"] is False
    vectors = [f["vector"] for f in result["findings"]]
    assert "DESK-SIG-004" in vectors, f"expected DESK-SIG-004, got: {vectors}"
    sig_004 = next(f for f in result["findings"] if f["vector"] == "DESK-SIG-004")
    assert sig_004["severity"] == "medium"


# ---------------------------------------------------------------------------
# 4. Developer ID signed + runtime flag → 0 findings
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_developer_id_signed_no_findings(tmp_path):
    target = tmp_path / "MyApp.app"
    target.mkdir()

    proc = _mock_proc(returncode=0, stderr=_VALID_AUTHORITY_STDERR)
    with patch("vxis.agent.skills.desktop.test_signature_audit.subprocess.run", return_value=proc):
        result = await execute(target_url=str(target))

    assert result["signed"] is True
    assert result["findings"] == [], f"expected 0 findings for valid sig, got: {result['findings']}"


# ---------------------------------------------------------------------------
# 5. Apple-signed passes (multiple Authority lines including Apple Root CA)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_apple_signed_passes(tmp_path):
    target = tmp_path / "Safari.app"
    target.mkdir()

    stderr = (
        "Executable=/Applications/Safari.app/Contents/MacOS/Safari\n"
        "Identifier=com.apple.Safari\n"
        "Format=app bundle with Mach-O universal (arm64e x86_64)\n"
        "CodeDirectory v=20500 size=9876 flags=0x10000(runtime) hashes=300+7 location=embedded\n"
        "Authority=Apple Mac OS Application Signing\n"
        "Authority=Apple Worldwide Developer Relations Certification Authority\n"
        "Authority=Apple Root CA\n"
        "TeamIdentifier=APPLE\n"
    )
    proc = _mock_proc(returncode=0, stderr=stderr)
    with patch("vxis.agent.skills.desktop.test_signature_audit.subprocess.run", return_value=proc):
        result = await execute(target_url=str(target))

    assert result["signed"] is True
    assert result["findings"] == [], (
        f"Apple-signed app should have 0 findings, got: {result['findings']}"
    )


# ---------------------------------------------------------------------------
# 6. signed=True reflected correctly for valid signature
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_returns_signed_true_for_valid(tmp_path):
    target = tmp_path / "MyApp.app"
    target.mkdir()

    proc = _mock_proc(returncode=0, stderr=_VALID_AUTHORITY_STDERR)
    with patch("vxis.agent.skills.desktop.test_signature_audit.subprocess.run", return_value=proc):
        result = await execute(target_url=str(target))

    assert result["signed"] is True, "signed field must be True when codesign exits 0"
    assert "error" not in result


# ---------------------------------------------------------------------------
# 7. authority field populated from stderr
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_returns_authority_field(tmp_path):
    target = tmp_path / "MyApp.app"
    target.mkdir()

    proc = _mock_proc(returncode=0, stderr=_VALID_AUTHORITY_STDERR)
    with patch("vxis.agent.skills.desktop.test_signature_audit.subprocess.run", return_value=proc):
        result = await execute(target_url=str(target))

    assert result["authority"] is not None
    assert "Developer ID Application" in result["authority"]


# ---------------------------------------------------------------------------
# 8. hardened_runtime field reflects flags parse
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_returns_hardened_runtime_field(tmp_path):
    target = tmp_path / "MyApp.app"
    target.mkdir()

    proc_with_runtime = _mock_proc(returncode=0, stderr=_VALID_AUTHORITY_STDERR)
    with patch(
        "vxis.agent.skills.desktop.test_signature_audit.subprocess.run",
        return_value=proc_with_runtime,
    ):
        result = await execute(target_url=str(target))
    assert result["hardened_runtime"] is True

    proc_without_runtime = _mock_proc(returncode=0, stderr=_NO_RUNTIME_STDERR)
    with patch(
        "vxis.agent.skills.desktop.test_signature_audit.subprocess.run",
        return_value=proc_without_runtime,
    ):
        result2 = await execute(target_url=str(target))
    assert result2["hardened_runtime"] is False


# ---------------------------------------------------------------------------
# 9. Missing codesign binary → graceful error dict
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_handles_missing_codesign_binary(tmp_path):
    target = tmp_path / "MyApp.app"
    target.mkdir()

    with patch(
        "vxis.agent.skills.desktop.test_signature_audit.subprocess.run",
        side_effect=FileNotFoundError("codesign not found"),
    ):
        result = await execute(target_url=str(target))

    assert result["signed"] is False
    assert result["findings"] == []
    assert "error" in result
    assert "codesign" in result["error"].lower()
    assert result["scanned"] == 0


# ---------------------------------------------------------------------------
# 10. Each finding has bilingual description (contains |||)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_finding_has_bilingual_description(tmp_path):
    target = tmp_path / "MyApp.app"
    target.mkdir()

    # unsigned — emits SIG-002
    proc = _mock_proc(returncode=1, stderr="code object is not signed at all\n")
    with patch("vxis.agent.skills.desktop.test_signature_audit.subprocess.run", return_value=proc):
        result = await execute(target_url=str(target))

    assert result["findings"], "need at least one finding to test bilingual format"
    for finding in result["findings"]:
        assert "|||" in finding["title"], f"title missing |||: {finding['title']!r}"
        assert "|||" in finding["description"], (
            f"description missing |||: {finding['description']!r}"
        )
