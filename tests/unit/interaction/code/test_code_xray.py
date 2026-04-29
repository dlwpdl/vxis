"""Tests for CodeXRay — git history log / blame / diff."""
from __future__ import annotations

import subprocess

import pytest

from vxis.interaction.surface import Target, TargetKind


@pytest.fixture
def git_repo(tmp_path):
    """Create a minimal git repo with two commits."""

    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-C", str(tmp_path)] + list(args),
            check=True,
            capture_output=True,
        )

    git("init")
    git("config", "user.email", "test@vxis.local")
    git("config", "user.name", "VXIS Test")

    secret_file = tmp_path / "config.py"
    secret_file.write_text('DB_PASS = "password123"\n', encoding="utf-8")
    git("add", "config.py")
    git("commit", "-m", "initial commit")

    # Second commit — remove the hardcoded secret (but git history keeps it)
    secret_file.write_text('DB_PASS = os.getenv("DB_PASS")\n', encoding="utf-8")
    git("add", "config.py")
    git("commit", "-m", "remove hardcoded password")

    return tmp_path


@pytest.fixture
def target(git_repo):
    return Target(kind=TargetKind.CODE, entry=str(git_repo))


@pytest.fixture
def xray(target):
    from vxis.interaction.code.code_xray import CodeXRay
    return CodeXRay(target)


# ---------------------------------------------------------------------------
# log
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_log_returns_commits(xray):
    env = await xray.capture("log", n=5)
    assert env.success is True
    lines = env.artifacts["lines"].splitlines()
    assert len(lines) >= 2  # two commits
    # Each line: hash|author|date|subject
    assert "initial commit" in env.artifacts["lines"]
    assert "remove hardcoded" in env.artifacts["lines"]


@pytest.mark.asyncio
async def test_log_surface_kind(xray):
    env = await xray.capture("log")
    assert env.surface_kind == TargetKind.CODE


# ---------------------------------------------------------------------------
# blame
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_blame_file(xray):
    env = await xray.capture("blame", path="config.py")
    assert env.success is True
    # blame output contains commit hashes and author lines
    assert "config.py" in env.artifacts.get("path", "")
    assert len(env.artifacts["lines"]) > 0


@pytest.mark.asyncio
async def test_blame_missing_path_returns_failure(xray):
    env = await xray.capture("blame")
    assert env.success is False
    assert "path" in (env.error or "")


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_diff_head_minus_one(xray):
    env = await xray.capture("diff", base="HEAD~1", head="HEAD")
    assert env.success is True
    # The diff should mention the password change
    assert "password123" in env.artifacts["lines"] or "DB_PASS" in env.artifacts["lines"]


@pytest.mark.asyncio
async def test_diff_missing_base_returns_failure(xray):
    env = await xray.capture("diff")
    assert env.success is False
    assert "base" in (env.error or "")


# ---------------------------------------------------------------------------
# unknown window
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unknown_window_returns_failure(xray):
    env = await xray.capture("stash")
    assert env.success is False
    assert "stash" in env.summary or "stash" in (env.error or "")
