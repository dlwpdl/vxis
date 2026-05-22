from __future__ import annotations

import pytest

from vxis.cli.main import _load_scan_instructions


def test_load_scan_instructions_combines_inline_and_file(tmp_path) -> None:
    path = tmp_path / "instructions.md"
    path.write_text("Exclude /admin\nUse test user credentials.", encoding="utf-8")

    loaded = _load_scan_instructions("Focus IDOR", path)

    assert loaded == "Focus IDOR\n\nExclude /admin\nUse test user credentials."


def test_load_scan_instructions_ignores_empty_inputs() -> None:
    assert _load_scan_instructions("  ", None) == ""


def test_load_scan_instructions_rejects_missing_file(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        _load_scan_instructions(None, tmp_path / "missing.md")
