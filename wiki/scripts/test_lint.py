"""
wiki/scripts/test_lint.py — pytest suite for lint.py

Runs lint.py as a subprocess against isolated tmp wikis.
Each test builds a minimal wiki structure in tmp_path and verifies exit code + output.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

LINT_SCRIPT = Path(__file__).parent / "lint.py"

# Minimal valid frontmatter + body (concept, ~10 body words after TL;DR)
VALID_FRONTMATTER = """\
---
name: Test Concept
type: concept
status: active
when_to_read: when testing lint tooling
updated: 2026-04-16
sources: []
related: []
---
"""

VALID_BODY = """\
# Test Concept

## 핵심 사실
| 항목 | 값 |
|---|---|
| 목적 | lint 테스트 |

## TL;DR
lint 툴링 동작 확인용 더미 페이지.

## What
This is a test concept page used for lint validation.
"""


def _make_wiki(tmp: Path) -> tuple[Path, Path]:
    """
    Create minimal wiki structure under tmp:
      tmp/wiki/index.md
      tmp/wiki/log.md
      tmp/wiki/CLAUDE.md  (empty stub)
    Returns (wiki_root, concepts_dir).
    """
    wiki = tmp / "wiki"
    wiki.mkdir()
    (wiki / "index.md").write_text("# Index\n", encoding="utf-8")
    (wiki / "log.md").write_text("# Log\n", encoding="utf-8")
    (wiki / "CLAUDE.md").write_text("# CLAUDE\n", encoding="utf-8")
    concepts = wiki / "concepts"
    concepts.mkdir()
    return wiki, concepts


def _run_lint(tmp: Path) -> subprocess.CompletedProcess[str]:
    """Run lint.py from tmp as cwd (repo root simulation)."""
    return subprocess.run(
        [sys.executable, str(LINT_SCRIPT)],
        cwd=str(tmp),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _register_in_index(wiki: Path, page_rel_from_wiki: str) -> None:
    """Append page path to index.md so orphan check passes."""
    index = wiki / "index.md"
    content = index.read_text(encoding="utf-8")
    index.write_text(content + f"\n- [{page_rel_from_wiki}]({page_rel_from_wiki})\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestOrphan:
    """Page exists in wiki but is NOT registered in index.md → [ERR] + non-zero exit."""

    def test_orphan_page_errors(self, tmp_path: Path) -> None:
        wiki, concepts = _make_wiki(tmp_path)
        # Write page but do NOT register in index.md
        page = concepts / "orphan_page.md"
        page.write_text(VALID_FRONTMATTER + VALID_BODY, encoding="utf-8")

        result = _run_lint(tmp_path)
        output = result.stdout + result.stderr

        assert result.returncode != 0, f"Expected non-zero exit, got 0.\nOutput:\n{output}"
        assert "[ERR]" in output, f"Expected [ERR] in output:\n{output}"
        assert "orphan" in output.lower(), f"Expected 'orphan' in output:\n{output}"


class TestBrokenLink:
    """Page links to a nonexistent file → [ERR] + non-zero exit."""

    def test_broken_relative_link_errors(self, tmp_path: Path) -> None:
        wiki, concepts = _make_wiki(tmp_path)

        body_with_broken_link = VALID_BODY + "\n[nonexistent](../entities/does_not_exist.md)\n"
        page = concepts / "broken_link_page.md"
        page.write_text(VALID_FRONTMATTER + body_with_broken_link, encoding="utf-8")
        _register_in_index(wiki, "concepts/broken_link_page.md")

        result = _run_lint(tmp_path)
        output = result.stdout + result.stderr

        assert result.returncode != 0, f"Expected non-zero exit, got 0.\nOutput:\n{output}"
        assert "[ERR]" in output, f"Expected [ERR] in output:\n{output}"
        assert "broken link" in output.lower() or "does_not_exist" in output, (
            f"Expected broken link message:\n{output}"
        )


class TestMissingHeading:
    """Page missing ## 핵심 사실 → [ERR] + non-zero exit."""

    def test_missing_keysil_heading_errors(self, tmp_path: Path) -> None:
        wiki, concepts = _make_wiki(tmp_path)

        # Body without ## 핵심 사실
        body_no_heading = """\
# Test Concept

## TL;DR
TL;DR only — 핵심 사실 표 없음.

## What
Missing the required heading.
"""
        page = concepts / "no_keysil.md"
        page.write_text(VALID_FRONTMATTER + body_no_heading, encoding="utf-8")
        _register_in_index(wiki, "concepts/no_keysil.md")

        result = _run_lint(tmp_path)
        output = result.stdout + result.stderr

        assert result.returncode != 0, f"Expected non-zero exit, got 0.\nOutput:\n{output}"
        assert "[ERR]" in output, f"Expected [ERR] in output:\n{output}"
        assert "핵심 사실" in output, f"Expected '핵심 사실' mention in output:\n{output}"


class TestWordOverBudget:
    """
    Concept page with >300 words body after TL;DR → zero exit (warning only) + [WARN].
    """

    def test_word_over_budget_warns_not_errors(self, tmp_path: Path) -> None:
        wiki, concepts = _make_wiki(tmp_path)

        # Generate ~400 words after TL;DR (concept budget = 300)
        filler_words = " ".join([f"word{i}" for i in range(400)])
        over_budget_body = f"""\
# Over Budget Concept

## 핵심 사실
| 항목 | 값 |
|---|---|
| 목적 | word budget test |

## TL;DR
This page intentionally exceeds the 300-word concept budget.

## What
{filler_words}
"""
        page = concepts / "over_budget.md"
        page.write_text(VALID_FRONTMATTER + over_budget_body, encoding="utf-8")
        _register_in_index(wiki, "concepts/over_budget.md")

        result = _run_lint(tmp_path)
        output = result.stdout + result.stderr

        assert result.returncode == 0, f"Expected zero exit (warning only), got {result.returncode}.\nOutput:\n{output}"
        assert "[WARN]" in output, f"Expected [WARN] in output:\n{output}"
        assert "[ERR]" not in output, f"Unexpected [ERR] in output:\n{output}"


class TestValidPage:
    """A fully valid page → zero exit, no errors."""

    def test_valid_page_passes(self, tmp_path: Path) -> None:
        wiki, concepts = _make_wiki(tmp_path)

        page = concepts / "valid_concept.md"
        page.write_text(VALID_FRONTMATTER + VALID_BODY, encoding="utf-8")
        _register_in_index(wiki, "concepts/valid_concept.md")

        result = _run_lint(tmp_path)
        output = result.stdout + result.stderr

        assert result.returncode == 0, f"Expected zero exit, got {result.returncode}.\nOutput:\n{output}"
        assert "[ERR]" not in output, f"Unexpected [ERR] in output:\n{output}"
