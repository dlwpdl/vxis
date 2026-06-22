from __future__ import annotations

import importlib.util

import pytest
import typer

from vxis.cli.main import _require_optional_dependency


def test_require_optional_dependency_allows_present_module(monkeypatch) -> None:
    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: object())

    assert _require_optional_dependency("docx", "export", "vxis export --format docx") is None


def test_require_optional_dependency_exits_for_missing_module(monkeypatch) -> None:
    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: None)

    with pytest.raises(typer.Exit) as exc_info:
        _require_optional_dependency("docx", "export", "vxis export --format docx")

    assert exc_info.value.exit_code == 2
