"""Tests for CodeEyes — Python AST focus extraction."""
from __future__ import annotations

import textwrap

import pytest

from vxis.interaction.surface import Target, TargetKind


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "app.py").write_text(
        textwrap.dedent("""\
            import os
            from pathlib import Path
            from typing import Optional

            class BaseHandler:
                pass

            class AuthHandler(BaseHandler):
                def __init__(self, secret: str):
                    self.secret = secret

                async def verify(self, token: str) -> Optional[bool]:
                    return None

            def helper(x: int) -> int:
                return x + 1

            result = helper(42)
            report_finding("this should be caught by guard")
        """),
        encoding="utf-8",
    )
    (tmp_path / "non_python.js").write_text("const x = 1;\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def target(repo):
    return Target(kind=TargetKind.CODE, entry=str(repo))


@pytest.fixture
def eyes(target):
    from vxis.interaction.code.code_eyes import CodeEyes
    return CodeEyes(target)


# ---------------------------------------------------------------------------
# imports
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_imports_extracted(eyes):
    env = await eyes.observe("imports", path="app.py")
    assert env.success is True
    lines = env.artifacts["lines"]
    assert "import os" in lines
    assert "from pathlib import Path" in lines
    assert "from typing import Optional" in lines


# ---------------------------------------------------------------------------
# functions
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_functions_extracted(eyes):
    env = await eyes.observe("functions", path="app.py")
    assert env.success is True
    lines = env.artifacts["lines"]
    assert "helper" in lines
    assert "verify" in lines
    assert "__init__" in lines
    # async def should be labelled
    assert "async def" in lines


# ---------------------------------------------------------------------------
# classes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_classes_extracted(eyes):
    env = await eyes.observe("classes", path="app.py")
    assert env.success is True
    lines = env.artifacts["lines"]
    assert "BaseHandler" in lines
    assert "AuthHandler" in lines
    assert "BaseHandler" in lines  # base class reference


# ---------------------------------------------------------------------------
# calls
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_calls_to_report_finding(eyes):
    """Guard: even in tests we can detect report_finding call-sites via AST."""
    env = await eyes.observe("calls", path="app.py", name="report_finding")
    assert env.success is True
    # The fixture file has one report_finding call
    assert "report_finding" in env.artifacts["lines"]


@pytest.mark.asyncio
async def test_calls_missing_name_returns_failure(eyes):
    env = await eyes.observe("calls", path="app.py")
    assert env.success is False
    assert "name" in (env.error or "")


# ---------------------------------------------------------------------------
# non-Python file
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_non_python_file_returns_unsupported(eyes):
    env = await eyes.observe("imports", path="non_python.js")
    assert env.success is False
    assert "lang_unsupported" in env.summary


# ---------------------------------------------------------------------------
# missing file / traversal
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_missing_file_returns_failure(eyes):
    env = await eyes.observe("imports", path="does_not_exist.py")
    assert env.success is False


@pytest.mark.asyncio
async def test_traversal_rejected(eyes):
    env = await eyes.observe("imports", path="../../../etc/passwd")
    assert env.success is False


# ---------------------------------------------------------------------------
# unknown focus
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unknown_focus_returns_failure(eyes):
    env = await eyes.observe("execute", path="app.py")
    assert env.success is False
