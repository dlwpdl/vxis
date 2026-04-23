"""Tests for CodeHands — read / grep / glob intents."""
from __future__ import annotations

import pytest
import textwrap

from vxis.interaction.surface import Target, TargetKind


@pytest.fixture
def repo(tmp_path):
    """Create a minimal fake repo directory with a few source files."""
    (tmp_path / "main.py").write_text(
        textwrap.dedent("""\
            import os
            import sys

            SECRET_KEY = "hunter2"

            def greet(name):
                print(f"Hello {name}")
        """),
        encoding="utf-8",
    )
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "helper.py").write_text("def helper(): pass\n", encoding="utf-8")
    (sub / "data.txt").write_text("some text\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def target(repo):
    return Target(kind=TargetKind.CODE, entry=str(repo))


@pytest.fixture
def hands(target):
    from vxis.interaction.code.code_hands import CodeHands
    return CodeHands(target)


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_read_existing_file(hands):
    env = await hands.request("read", path="main.py")
    assert env.success is True
    assert "SECRET_KEY" in env.artifacts["lines"]
    assert env.surface_kind == TargetKind.CODE


@pytest.mark.asyncio
async def test_read_nested_file(hands):
    env = await hands.request("read", path="sub/helper.py")
    assert env.success is True
    assert "helper" in env.artifacts["lines"]


@pytest.mark.asyncio
async def test_read_missing_file_returns_failure(hands):
    env = await hands.request("read", path="nonexistent.py")
    assert env.success is False
    assert "not found" in env.summary.lower() or "not found" in (env.error or "").lower()


@pytest.mark.asyncio
async def test_read_path_traversal_rejected(hands):
    env = await hands.request("read", path="../../../etc/passwd")
    assert env.success is False
    assert "traversal" in env.summary.lower() or "traversal" in (env.error or "").lower()


@pytest.mark.asyncio
async def test_read_missing_path_arg(hands):
    env = await hands.request("read")
    assert env.success is False


# ---------------------------------------------------------------------------
# grep
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_grep_finds_pattern(hands):
    env = await hands.request("grep", pattern="SECRET_KEY")
    assert env.success is True
    assert "SECRET_KEY" in env.artifacts["lines"]
    assert "main.py" in env.artifacts["lines"]


@pytest.mark.asyncio
async def test_grep_no_matches(hands):
    env = await hands.request("grep", pattern="XYZZY_NOT_PRESENT_12345")
    assert env.success is True
    assert env.artifacts["lines"] == ""


@pytest.mark.asyncio
async def test_grep_invalid_regex(hands):
    env = await hands.request("grep", pattern="[invalid regex")
    assert env.success is False
    assert env.error is not None


@pytest.mark.asyncio
async def test_grep_with_explicit_paths(hands, repo):
    env = await hands.request("grep", pattern="helper", paths=["sub/helper.py"])
    assert env.success is True
    assert "helper" in env.artifacts["lines"]


# ---------------------------------------------------------------------------
# glob
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_glob_finds_py_files(hands):
    env = await hands.request("glob", pattern="*.py")
    assert env.success is True
    found = env.artifacts["lines"].splitlines()
    py_files = [f for f in found if f.endswith(".py")]
    assert len(py_files) >= 2  # main.py + sub/helper.py


@pytest.mark.asyncio
async def test_glob_empty_result(hands):
    env = await hands.request("glob", pattern="*.rb")
    assert env.success is True
    assert env.artifacts["lines"] == ""


# ---------------------------------------------------------------------------
# unknown intent
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unknown_intent_returns_failure(hands):
    env = await hands.request("execute_code")
    assert env.success is False
    assert "execute_code" in (env.error or "") or "execute_code" in env.summary
