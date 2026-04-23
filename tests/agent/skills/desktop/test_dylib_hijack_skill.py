"""Tests for the test_dylib_hijack desktop skill (DESK-DYL-001/002/003).

All tests mock subprocess.run so they do not depend on a real `otool` binary.

otool output format reference
------------------------------
`otool -L <binary>` stdout — one dylib per line, tab-indented, followed by
  parenthesised version info:

    /path/to/binary:
    \t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1336.0.0)
    \t@rpath/Sparkle.framework/Versions/B/Sparkle (compatibility version 2.0.0, current version 2.7.0)

`otool -l <binary>` stdout — load commands dump.  LC_RPATH sections look like:

    Load command 7
          cmd LC_RPATH
      cmdsize 56
         path /usr/local/lib (offset 12)

    Load command 8
          cmd LC_RPATH
      cmdsize 48
         path @executable_path/../Frameworks (offset 12)

LC_LOAD_WEAK_DYLIB sections look the same as LC_LOAD_DYLIB but with the
command name `LC_LOAD_WEAK_DYLIB`.

The helper `_fake_otool_L` and `_fake_otool_l` below reproduce these formats.
"""
from __future__ import annotations

import os
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

from vxis.agent.skills.desktop.test_dylib_hijack import execute


# ---------------------------------------------------------------------------
# Format helpers — reproduce the exact otool output the skill parses
# ---------------------------------------------------------------------------

def _fake_otool_L(dylibs: list[str]) -> str:
    """Return a `otool -L` stdout string containing the given dylib paths.

    Each entry is tab-indented and followed by a version parenthetical,
    exactly as real otool(1) produces.

    Example:
        _fake_otool_L(["@rpath/Foo.dylib", "/usr/lib/libz.dylib"])
        →
        "/path/to/binary:\\n"
        "\\t@rpath/Foo.dylib (compatibility version 1.0.0, current version 1.0.0)\\n"
        "\\t/usr/lib/libz.dylib (compatibility version 1.0.0, current version 1.0.0)\\n"
    """
    lines = ["/fake/binary:\n"]
    for d in dylibs:
        lines.append(f"\t{d} (compatibility version 1.0.0, current version 1.0.0)\n")
    return "".join(lines)


def _fake_otool_l(rpaths: list[str], weak_dylibs: list[str] | None = None) -> str:
    """Return a `otool -l` stdout string with the given RPATH entries and
    optional LC_LOAD_WEAK_DYLIB commands.

    rpaths:      list of RPATH path strings.
    weak_dylibs: list of dylib paths to emit as LC_LOAD_WEAK_DYLIB commands.

    The format mirrors real otool(1) output closely enough for the skill's
    regex parsers (_RE_RPATH_PATH and _RE_WEAK_CMD) to match.
    """
    sections: list[str] = []
    for i, rp in enumerate(rpaths):
        sections.append(
            f"Load command {i}\n"
            f"      cmd LC_RPATH\n"
            f"  cmdsize 56\n"
            f"     path {rp} (offset 12)\n"
        )
    if weak_dylibs:
        for j, wd in enumerate(weak_dylibs, start=len(rpaths)):
            sections.append(
                f"Load command {j}\n"
                f"      cmd LC_LOAD_WEAK_DYLIB\n"
                f"  cmdsize 80\n"
                f"     name {wd} (offset 24)\n"
            )
    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Mock factory
# ---------------------------------------------------------------------------

def _make_proc(stdout: str = "", returncode: int = 0) -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = ""
    return m


# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------

def _make_binary(tmp_path: Any) -> str:
    """Create a dummy file that stands in for a Mach-O binary.

    The skill doesn't validate that it's actually a Mach-O — it just feeds the
    path to otool, which we mock.
    """
    binary = tmp_path / "FakeApp"
    binary.write_bytes(b"\xcf\xfa\xed\xfe")  # MH_MAGIC_64 magic bytes
    return str(binary)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestWritableRpath:
    """DESK-DYL-001: @rpath dylib whose resolved dir is writable."""

    @pytest.mark.asyncio
    async def test_writable_rpath_emits_dyl_001(self, tmp_path: Any) -> None:
        """A binary with @rpath/foo.dylib + writable RPATH → DESK-DYL-001 finding."""
        binary = _make_binary(tmp_path)
        rpath = str(tmp_path)  # tmp_path is always writable by the test runner

        otool_L_out = _fake_otool_L(["@rpath/foo.dylib"])
        otool_l_out = _fake_otool_l(rpaths=[rpath])

        def _side_effect(cmd: list[str], **kw: Any) -> MagicMock:
            if "-L" in cmd:
                return _make_proc(otool_L_out)
            return _make_proc(otool_l_out)

        with patch("subprocess.run", side_effect=_side_effect):
            result = await execute(str(tmp_path))

        assert result["macho_inspected"] > 0
        dyl001 = [f for f in result["findings"] if f["vector"] == "DESK-DYL-001"]
        assert len(dyl001) >= 1, "Expected at least one DESK-DYL-001 finding"

    @pytest.mark.asyncio
    async def test_system_only_rpath_no_findings(self, tmp_path: Any) -> None:
        """RPATH pointing to /usr/lib (not writable) → 0 findings."""
        binary = _make_binary(tmp_path)
        rpath = "/usr/lib"  # not writable by regular users

        otool_L_out = _fake_otool_L(["@rpath/foo.dylib"])
        otool_l_out = _fake_otool_l(rpaths=[rpath])

        def _side_effect(cmd: list[str], **kw: Any) -> MagicMock:
            if "-L" in cmd:
                return _make_proc(otool_L_out)
            return _make_proc(otool_l_out)

        with patch("subprocess.run", side_effect=_side_effect):
            result = await execute(str(tmp_path))

        assert result["findings"] == []


class TestMissingWeakDylib:
    """DESK-DYL-002: LC_LOAD_WEAK_DYLIB path doesn't exist on disk."""

    @pytest.mark.asyncio
    async def test_missing_weak_dylib_emits_dyl_002(self, tmp_path: Any) -> None:
        """Weak-linked @rpath/missing.dylib with no resolved candidate on disk → DESK-DYL-002."""
        binary = _make_binary(tmp_path)
        rpath = str(tmp_path)  # writable but dylib won't exist there

        # The dylib path is @rpath/missing.dylib — resolved: tmp_path/missing.dylib
        # We do NOT create that file, so os.path.exists returns False.
        otool_L_out = _fake_otool_L(["@rpath/missing.dylib"])
        otool_l_out = _fake_otool_l(
            rpaths=[rpath],
            weak_dylibs=["@rpath/missing.dylib"],
        )

        def _side_effect(cmd: list[str], **kw: Any) -> MagicMock:
            if "-L" in cmd:
                return _make_proc(otool_L_out)
            return _make_proc(otool_l_out)

        with patch("subprocess.run", side_effect=_side_effect):
            result = await execute(str(tmp_path))

        dyl002 = [f for f in result["findings"] if f["vector"] == "DESK-DYL-002"]
        assert len(dyl002) >= 1, "Expected at least one DESK-DYL-002 finding"


class TestMultipleRpaths:
    """DESK-DYL-003: multiple RPATHs with ≥1 writable → search-order hijack."""

    @pytest.mark.asyncio
    async def test_multiple_rpaths_with_writable_emits_dyl_003(self, tmp_path: Any) -> None:
        """2 RPATHs (one writable) + @rpath dylib → DESK-DYL-003 + DESK-DYL-001."""
        binary = _make_binary(tmp_path)
        writable_rpath = str(tmp_path)
        system_rpath = "/usr/lib"

        # @rpath/bar.dylib resolves to tmp_path/bar.dylib (dir writable, file absent)
        otool_L_out = _fake_otool_L(["@rpath/bar.dylib"])
        otool_l_out = _fake_otool_l(rpaths=[system_rpath, writable_rpath])

        def _side_effect(cmd: list[str], **kw: Any) -> MagicMock:
            if "-L" in cmd:
                return _make_proc(otool_L_out)
            return _make_proc(otool_l_out)

        with patch("subprocess.run", side_effect=_side_effect):
            result = await execute(str(tmp_path))

        vectors = {f["vector"] for f in result["findings"]}
        assert "DESK-DYL-003" in vectors, "Expected DESK-DYL-003 (multi-RPATH writable)"
        assert "DESK-DYL-001" in vectors, "Expected DESK-DYL-001 (writable resolved dir)"


class TestNoRpath:
    """No RPATH entries at all → no DYL findings."""

    @pytest.mark.asyncio
    async def test_no_rpath_no_findings(self, tmp_path: Any) -> None:
        """Binary with only absolute dylib paths and no RPATH → 0 findings."""
        binary = _make_binary(tmp_path)

        otool_L_out = _fake_otool_L(["/usr/lib/libSystem.B.dylib"])
        otool_l_out = _fake_otool_l(rpaths=[])  # no RPATH entries

        def _side_effect(cmd: list[str], **kw: Any) -> MagicMock:
            if "-L" in cmd:
                return _make_proc(otool_L_out)
            return _make_proc(otool_l_out)

        with patch("subprocess.run", side_effect=_side_effect):
            result = await execute(str(tmp_path))

        assert result["findings"] == []


class TestReturnShape:
    """Return dict has expected keys and populated counts."""

    @pytest.mark.asyncio
    async def test_macho_inspected_count_populated(self, tmp_path: Any) -> None:
        """execute() returns macho_inspected > 0 when otool succeeds."""
        _make_binary(tmp_path)

        otool_L_out = _fake_otool_L(["/usr/lib/libSystem.B.dylib"])
        otool_l_out = _fake_otool_l(rpaths=[])

        def _side_effect(cmd: list[str], **kw: Any) -> MagicMock:
            if "-L" in cmd:
                return _make_proc(otool_L_out)
            return _make_proc(otool_l_out)

        with patch("subprocess.run", side_effect=_side_effect):
            result = await execute(str(tmp_path))

        assert result["macho_inspected"] > 0
        assert "scanned" in result
        assert "rpaths" in result
        assert "root" in result
        assert "findings" in result


class TestErrorHandling:
    """Graceful error handling for broken environments."""

    @pytest.mark.asyncio
    async def test_handles_missing_otool_binary(self, tmp_path: Any) -> None:
        """FileNotFoundError from otool → error key in result, no exception."""
        _make_binary(tmp_path)

        with patch("subprocess.run", side_effect=FileNotFoundError("otool not found")):
            result = await execute(str(tmp_path))

        assert "error" in result
        assert "otool" in result["error"].lower()
        assert result["findings"] == []

    @pytest.mark.asyncio
    async def test_handles_otool_returning_nonzero(self, tmp_path: Any) -> None:
        """otool -L returncode != 0 → skip that binary, continue, return valid dict."""
        binary = _make_binary(tmp_path)

        # First binary: otool -L fails (non-zero).  otool -l is never called.
        def _side_effect(cmd: list[str], **kw: Any) -> MagicMock:
            if "-L" in cmd:
                return _make_proc(stdout="", returncode=1)
            return _make_proc(_fake_otool_l([]))

        with patch("subprocess.run", side_effect=_side_effect):
            result = await execute(str(tmp_path))

        # Should return cleanly — macho_inspected = 0 since we skipped the binary.
        assert result["macho_inspected"] == 0
        assert result["findings"] == []
        assert "error" not in result


class TestBilingualFindings:
    """Finding format validation."""

    @pytest.mark.asyncio
    async def test_finding_has_bilingual_description(self, tmp_path: Any) -> None:
        """All findings must contain '|||' in both title and description."""
        binary = _make_binary(tmp_path)
        rpath = str(tmp_path)

        otool_L_out = _fake_otool_L(["@rpath/foo.dylib"])
        otool_l_out = _fake_otool_l(rpaths=[rpath])

        def _side_effect(cmd: list[str], **kw: Any) -> MagicMock:
            if "-L" in cmd:
                return _make_proc(otool_L_out)
            return _make_proc(otool_l_out)

        with patch("subprocess.run", side_effect=_side_effect):
            result = await execute(str(tmp_path))

        assert result["findings"], "Need at least one finding for this test"
        for finding in result["findings"]:
            assert "|||" in finding["title"], f"title missing ||| separator: {finding['title']}"
            assert "|||" in finding["description"], "description missing ||| separator"


class TestFindingCap:
    """Output is capped at 20 findings regardless of input size."""

    @pytest.mark.asyncio
    async def test_caps_output_at_20_findings(self, tmp_path: Any) -> None:
        """Flood with many @rpath dylibs across many RPATHs — result capped at 20."""
        # Create 50 @rpath dylib references.
        dylibs = [f"@rpath/lib{i:03d}.dylib" for i in range(50)]
        # One writable RPATH → each dylib can produce DESK-DYL-001.
        rpath = str(tmp_path)

        otool_L_out = _fake_otool_L(dylibs)
        otool_l_out = _fake_otool_l(rpaths=[rpath])

        def _side_effect(cmd: list[str], **kw: Any) -> MagicMock:
            if "-L" in cmd:
                return _make_proc(otool_L_out)
            return _make_proc(otool_l_out)

        with patch("subprocess.run", side_effect=_side_effect):
            result = await execute(str(tmp_path))

        assert len(result["findings"]) <= 20, (
            f"findings count {len(result['findings'])} exceeds the 20-finding cap"
        )
