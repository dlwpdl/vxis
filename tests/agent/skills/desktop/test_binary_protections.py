"""Tests for the test_binary_protections desktop skill (DESK-PIE-001/002/003).

Uses subprocess mocking for otool/nm/codesign calls and a real system
binary (/bin/ls) for the positive case. The weak-binary negative case
is skipped when the clang build is unavailable.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vxis.agent.skills.desktop.test_binary_protections import execute

# Skip the entire module on non-darwin because the skill itself returns
# a skip result and we cannot build Mach-O test binaries on Linux/Windows.
pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="Mach-O binary protection tests require macOS",
)


# ---------------------------------------------------------------------------
# Mock factory helpers
# ---------------------------------------------------------------------------

def _mock_proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


# Canonical otool -hv output for a PIE binary (MH_PIE flag present)
_OTOOL_PIE_OUTPUT = """\
/bin/ls (architecture arm64e):
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
 0xFEEDFACF 16777228          2  0x80       MH_EXECUTE   25       3424  MH_NOUNDEFS|MH_DYLDLINK|MH_TWOLEVEL|MH_PIE
"""

# otool output for a binary WITHOUT PIE
_OTOOL_NOPIE_OUTPUT = """\
/tmp/weak.bin:
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
 0xFEEDFACF   16777223          3  0x00       MH_EXECUTE   10       1024  MH_NOUNDEFS|MH_DYLDLINK
"""

# nm output containing __stack_chk_guard (canary present)
_NM_CANARY_OUTPUT = """\
                 U ___stack_chk_guard
                 U ___stack_chk_fail
0000000100001234 T _main
"""

# nm output WITHOUT canary
_NM_NO_CANARY_OUTPUT = """\
0000000100001234 T _main
"""

# otool -l output containing __RESTRICT,__restrict segment
_OTOOL_RESTRICT_OUTPUT = """\
Section
  sectname __restrict
   segname __RESTRICT
      addr 0x0000000100008000
      size 0x0000000000000000
"""

# otool -l output without __RESTRICT
_OTOOL_NO_RESTRICT_OUTPUT = """\
Section
  sectname __text
   segname __TEXT
      addr 0x0000000100001000
      size 0x0000000000001234
"""


# ---------------------------------------------------------------------------
# 1. /bin/ls — positive case, real binary (mocked tools to avoid CI flakiness)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_system_binary_with_pie_no_findings(tmp_path: Path) -> None:
    """A fully protected binary (PIE + canary + restrict) should emit 0 findings."""

    def _fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
        if "otool" in cmd[0] and "-hv" in cmd:
            return _mock_proc(stdout=_OTOOL_PIE_OUTPUT)
        if "nm" in cmd[0]:
            return _mock_proc(stdout=_NM_CANARY_OUTPUT)
        if "otool" in cmd[0] and "-l" in cmd:
            return _mock_proc(stdout=_OTOOL_RESTRICT_OUTPUT)
        if "codesign" in cmd[0]:
            return _mock_proc(
                returncode=0,
                stderr="Authority=Apple Mac OS Application Signing\n",
                stdout="",
            )
        return _mock_proc()

    with patch("vxis.agent.skills.desktop.test_binary_protections.subprocess.run", side_effect=_fake_run):
        result = await execute(target_url="/bin/ls")

    assert result["tested"] == 1
    assert result["findings"] == [], f"expected 0 findings for fully-protected binary, got: {result['findings']}"
    assert result["pie"] is True
    assert result["stack_canary"] is True
    assert result["restrict_segment"] is True


# ---------------------------------------------------------------------------
# 2. No PIE → DESK-PIE-001 finding (high severity)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_no_pie_emits_desk_pie_001(tmp_path: Path) -> None:
    """A binary without MH_PIE must produce a DESK-PIE-001 high finding."""

    def _fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
        if "otool" in cmd[0] and "-hv" in cmd:
            return _mock_proc(stdout=_OTOOL_NOPIE_OUTPUT)
        if "nm" in cmd[0]:
            return _mock_proc(stdout=_NM_CANARY_OUTPUT)
        if "otool" in cmd[0] and "-l" in cmd:
            return _mock_proc(stdout=_OTOOL_RESTRICT_OUTPUT)
        if "codesign" in cmd[0]:
            return _mock_proc(returncode=0, stderr="Authority=Developer ID Application: Foo\n")
        return _mock_proc()

    with patch("vxis.agent.skills.desktop.test_binary_protections.subprocess.run", side_effect=_fake_run):
        result = await execute(target_url="/tmp/nopie.bin")

    assert result["pie"] is False
    pie_findings = [f for f in result["findings"] if f["vector"] == "DESK-PIE-001"]
    assert pie_findings, f"expected DESK-PIE-001 finding, got: {result['findings']}"
    assert pie_findings[0]["severity"] == "high"
    assert "|||" in pie_findings[0]["title"]
    assert "|||" in pie_findings[0]["description"]


# ---------------------------------------------------------------------------
# 3. No stack canary → DESK-PIE-002 finding (high severity)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_no_canary_emits_desk_pie_002(tmp_path: Path) -> None:
    """A binary without __stack_chk_guard must produce a DESK-PIE-002 finding."""

    def _fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
        if "otool" in cmd[0] and "-hv" in cmd:
            return _mock_proc(stdout=_OTOOL_PIE_OUTPUT)
        if "nm" in cmd[0]:
            return _mock_proc(stdout=_NM_NO_CANARY_OUTPUT)
        if "otool" in cmd[0] and "-l" in cmd:
            return _mock_proc(stdout=_OTOOL_RESTRICT_OUTPUT)
        if "codesign" in cmd[0]:
            return _mock_proc(returncode=0, stderr="Authority=Developer ID Application: Foo\n")
        return _mock_proc()

    with patch("vxis.agent.skills.desktop.test_binary_protections.subprocess.run", side_effect=_fake_run):
        result = await execute(target_url="/tmp/nocanary.bin")

    assert result["stack_canary"] is False
    canary_findings = [f for f in result["findings"] if f["vector"] == "DESK-PIE-002"]
    assert canary_findings, f"expected DESK-PIE-002 finding, got: {result['findings']}"
    assert canary_findings[0]["severity"] == "high"
    assert "|||" in canary_findings[0]["title"]


# ---------------------------------------------------------------------------
# 4. No __RESTRICT segment → DESK-PIE-003 finding (medium severity)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_no_restrict_emits_desk_pie_003(tmp_path: Path) -> None:
    """A binary without __RESTRICT,__restrict segment must produce DESK-PIE-003."""

    def _fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
        if "otool" in cmd[0] and "-hv" in cmd:
            return _mock_proc(stdout=_OTOOL_PIE_OUTPUT)
        if "nm" in cmd[0]:
            return _mock_proc(stdout=_NM_CANARY_OUTPUT)
        if "otool" in cmd[0] and "-l" in cmd:
            return _mock_proc(stdout=_OTOOL_NO_RESTRICT_OUTPUT)
        if "codesign" in cmd[0]:
            return _mock_proc(returncode=0, stderr="Authority=Developer ID Application: Foo\n")
        return _mock_proc()

    with patch("vxis.agent.skills.desktop.test_binary_protections.subprocess.run", side_effect=_fake_run):
        result = await execute(target_url="/tmp/norestrict.bin")

    assert result["restrict_segment"] is False
    restrict_findings = [f for f in result["findings"] if f["vector"] == "DESK-PIE-003"]
    assert restrict_findings, f"expected DESK-PIE-003 finding, got: {result['findings']}"
    assert restrict_findings[0]["severity"] == "medium"
    assert "|||" in restrict_findings[0]["title"]


# ---------------------------------------------------------------------------
# 5. otool not found → graceful skip
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_otool_not_found_returns_skip(tmp_path: Path) -> None:
    """When otool binary is missing, skill must return tested=0 with skipped_reason."""
    with patch(
        "vxis.agent.skills.desktop.test_binary_protections.subprocess.run",
        side_effect=FileNotFoundError("otool not found"),
    ):
        result = await execute(target_url="/bin/ls")

    assert result["tested"] == 0
    assert result["findings"] == []
    assert result.get("skipped_reason"), "expected skipped_reason when otool is missing"


# ---------------------------------------------------------------------------
# 6. Return schema always present
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_return_schema_always_present(tmp_path: Path) -> None:
    """Mandatory keys must be present regardless of outcome."""

    def _fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
        return _mock_proc(stdout=_OTOOL_PIE_OUTPUT)

    with patch("vxis.agent.skills.desktop.test_binary_protections.subprocess.run", side_effect=_fake_run):
        result = await execute(target_url="/tmp/schema_check.bin")

    for key in ("tested", "findings", "pie", "stack_canary", "restrict_segment"):
        assert key in result, f"missing mandatory key: {key!r}"
    assert isinstance(result["findings"], list)
    assert isinstance(result["tested"], int)
    assert isinstance(result["pie"], bool)
    assert isinstance(result["stack_canary"], bool)
    assert isinstance(result["restrict_segment"], bool)


# ---------------------------------------------------------------------------
# 7. All three protections missing → 3 findings
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_all_protections_missing_three_findings(tmp_path: Path) -> None:
    """Binary lacking PIE + canary + restrict should emit all three findings."""

    def _fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
        if "otool" in cmd[0] and "-hv" in cmd:
            return _mock_proc(stdout=_OTOOL_NOPIE_OUTPUT)
        if "nm" in cmd[0]:
            return _mock_proc(stdout=_NM_NO_CANARY_OUTPUT)
        if "otool" in cmd[0] and "-l" in cmd:
            return _mock_proc(stdout=_OTOOL_NO_RESTRICT_OUTPUT)
        if "codesign" in cmd[0]:
            return _mock_proc(returncode=0, stderr="Authority=Developer ID Application: Foo\n")
        return _mock_proc()

    with patch("vxis.agent.skills.desktop.test_binary_protections.subprocess.run", side_effect=_fake_run):
        result = await execute(target_url="/tmp/weak.bin")

    vectors = [f["vector"] for f in result["findings"]]
    assert "DESK-PIE-001" in vectors, f"missing DESK-PIE-001 in {vectors}"
    assert "DESK-PIE-002" in vectors, f"missing DESK-PIE-002 in {vectors}"
    assert "DESK-PIE-003" in vectors, f"missing DESK-PIE-003 in {vectors}"
    assert len(result["findings"]) == 3
