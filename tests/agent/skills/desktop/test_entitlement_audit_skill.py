"""Tests for the test_entitlement_audit desktop skill (DESK-ENT-001/002/003).

All tests mock subprocess.run so they do not depend on a real `codesign`
binary.  Plist XML fixtures are minimal but valid.
"""
from __future__ import annotations

import textwrap
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from vxis.agent.skills.desktop.test_entitlement_audit import execute


# ---------------------------------------------------------------------------
# Plist XML helpers
# ---------------------------------------------------------------------------

_PLIST_HEADER = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
        "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
""")
_PLIST_FOOTER = "</dict>\n</plist>\n"


def _plist_xml(*key_value_pairs: tuple[str, str]) -> bytes:
    """Build a minimal plist XML bytes object.

    Each pair is (key, plist_value_tag) e.g.
    ("com.apple.security.cs.allow-jit", "<true/>")
    """
    body = ""
    for key, tag in key_value_pairs:
        body += f"    <key>{key}</key>{tag}\n"
    return (_PLIST_HEADER + body + _PLIST_FOOTER).encode()


def _mock_codesign_ok(xml_bytes: bytes) -> MagicMock:
    """Return a mock subprocess.CompletedProcess with plist output on stdout."""
    m = MagicMock()
    m.returncode = 0
    m.stdout = xml_bytes
    m.stderr = b""
    return m


def _mock_codesign_fail(returncode: int = 1) -> MagicMock:
    """Return a mock subprocess.CompletedProcess indicating failure."""
    m = MagicMock()
    m.returncode = returncode
    m.stdout = b""
    m.stderr = b""
    return m


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_disabled_library_validation_emits_ent_001(tmp_path: Any) -> None:
    """disable-library-validation=true → 1 high finding, vector DESK-ENT-001."""
    xml = _plist_xml(
        ("com.apple.security.cs.disable-library-validation", "<true/>"),
        ("com.apple.security.app-sandbox", "<true/>"),
    )
    with patch("subprocess.run", return_value=_mock_codesign_ok(xml)):
        result = await execute(str(tmp_path))

    assert result["scanned"] == 1
    findings = result["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["vector"] == "DESK-ENT-001"
    assert f["severity"] == "high"
    assert "error" not in result


@pytest.mark.asyncio
async def test_dyld_env_allowed_emits_ent_002(tmp_path: Any) -> None:
    """allow-dyld-environment-variables=true → DESK-ENT-002."""
    xml = _plist_xml(
        ("com.apple.security.cs.allow-dyld-environment-variables", "<true/>"),
        ("com.apple.security.app-sandbox", "<true/>"),
    )
    with patch("subprocess.run", return_value=_mock_codesign_ok(xml)):
        result = await execute(str(tmp_path))

    vectors = [f["vector"] for f in result["findings"]]
    assert "DESK-ENT-002" in vectors
    assert result["scanned"] == 1


@pytest.mark.asyncio
async def test_jit_allowed_emits_ent_003(tmp_path: Any) -> None:
    """allow-jit=true → DESK-ENT-003 (medium severity)."""
    xml = _plist_xml(
        ("com.apple.security.cs.allow-jit", "<true/>"),
        ("com.apple.security.app-sandbox", "<true/>"),
    )
    with patch("subprocess.run", return_value=_mock_codesign_ok(xml)):
        result = await execute(str(tmp_path))

    findings = result["findings"]
    assert len(findings) == 1
    assert findings[0]["vector"] == "DESK-ENT-003"
    assert findings[0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_unsigned_executable_mem_emits_ent_003(tmp_path: Any) -> None:
    """allow-unsigned-executable-memory=true → DESK-ENT-003 (dedup: no duplicate)."""
    xml = _plist_xml(
        ("com.apple.security.cs.allow-unsigned-executable-memory", "<true/>"),
        ("com.apple.security.app-sandbox", "<true/>"),
    )
    with patch("subprocess.run", return_value=_mock_codesign_ok(xml)):
        result = await execute(str(tmp_path))

    vectors = [f["vector"] for f in result["findings"]]
    assert vectors.count("DESK-ENT-003") == 1   # deduplicated even if both keys set


@pytest.mark.asyncio
async def test_safe_entitlements_no_findings(tmp_path: Any) -> None:
    """Only app-sandbox=true → 0 findings (no dangerous keys)."""
    xml = _plist_xml(
        ("com.apple.security.app-sandbox", "<true/>"),
    )
    with patch("subprocess.run", return_value=_mock_codesign_ok(xml)):
        result = await execute(str(tmp_path))

    assert result["scanned"] == 1
    assert result["findings"] == []
    assert "error" not in result


@pytest.mark.asyncio
async def test_no_entitlements_returns_empty(tmp_path: Any) -> None:
    """codesign returncode != 0 → empty result with error key, NOT a finding."""
    with patch("subprocess.run", return_value=_mock_codesign_fail()):
        result = await execute(str(tmp_path))

    assert result["scanned"] == 0
    assert result["findings"] == []
    assert "error" in result
    assert result["entitlements"] == {}


@pytest.mark.asyncio
async def test_entitlements_field_populated(tmp_path: Any) -> None:
    """Return dict must have `entitlements` key with the parsed dangerous booleans."""
    xml = _plist_xml(
        ("com.apple.security.cs.disable-library-validation", "<true/>"),
        ("com.apple.security.cs.allow-jit", "<false/>"),
        ("com.apple.security.app-sandbox", "<true/>"),
    )
    with patch("subprocess.run", return_value=_mock_codesign_ok(xml)):
        result = await execute(str(tmp_path))

    ents = result["entitlements"]
    assert isinstance(ents, dict)
    # disable-library-validation=true should be captured
    assert ents.get("com.apple.security.cs.disable-library-validation") is True
    # allow-jit=false should be captured (so Brain can reason about its absence)
    assert ents.get("com.apple.security.cs.allow-jit") is False


@pytest.mark.asyncio
async def test_handles_missing_codesign_binary(tmp_path: Any) -> None:
    """FileNotFoundError (codesign not on PATH) → graceful error dict, no exception."""
    with patch("subprocess.run", side_effect=FileNotFoundError("codesign not found")):
        result = await execute(str(tmp_path))

    assert result["scanned"] == 0
    assert result["findings"] == []
    assert "error" in result
    assert "codesign" in result["error"].lower()


@pytest.mark.asyncio
async def test_handles_malformed_plist(tmp_path: Any) -> None:
    """Invalid plist XML → graceful error dict (no exception, no crash)."""
    bad_xml = b"<?xml version='1.0'?><plist><dict><key>bad</dict></plist>"
    with patch("subprocess.run", return_value=_mock_codesign_ok(bad_xml)):
        result = await execute(str(tmp_path))

    assert result["scanned"] == 0
    assert result["findings"] == []
    assert "error" in result


@pytest.mark.asyncio
async def test_finding_has_bilingual_description(tmp_path: Any) -> None:
    """Finding title and description must contain the '|||' bilingual separator."""
    xml = _plist_xml(
        ("com.apple.security.cs.disable-library-validation", "<true/>"),
        ("com.apple.security.app-sandbox", "<true/>"),
    )
    with patch("subprocess.run", return_value=_mock_codesign_ok(xml)):
        result = await execute(str(tmp_path))

    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert "|||" in f["title"], "title must contain bilingual separator '|||'"
    assert "|||" in f["description"], "description must contain bilingual separator '|||'"
    # Sanity: both EN and KO portions are non-trivial
    en_part, ko_part = f["description"].split("|||", 1)
    assert len(en_part.strip()) > 50
    assert len(ko_part.strip()) > 50
