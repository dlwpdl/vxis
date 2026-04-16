#!/usr/bin/env python3
"""
wiki/scripts/lint.py — VXIS Wiki Linter. Run from repo root.
Errors (non-zero): missing frontmatter fields, missing headings, broken links, orphan pages.
Warnings (zero):   word-budget exceeded, stale updated, stale code_anchors.
"""
from __future__ import annotations

import re
import subprocess
import sys
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

WIKI_ROOT = Path("wiki")
EXCLUDED_FILES = {"CLAUDE.md", "index.md", "log.md"}
EXCLUDED_DIRS = {"scripts"}
REQUIRED_FIELDS = {"name", "type", "status", "when_to_read", "updated", "sources", "related"}
WORD_BUDGETS: dict[str, int] = {
    "concept": 300, "skill": 400, "module": 500,
    "pipeline": 250, "decision": 250, "incident": 350,
}
TODAY = date.today()
STALE_THRESHOLD = timedelta(days=90)


def _parse_frontmatter(text: str) -> tuple[dict[str, Any] | None, str]:
    """Regex-based YAML frontmatter parser (stdlib only). Handles flat keys + list values."""
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?", text, re.DOTALL)
    if not m:
        return None, text
    body = text[m.end():]
    result: dict[str, Any] = {}
    lines = m.group(1).splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.strip().startswith("#"):
            i += 1
            continue
        km = re.match(r"^(\w+):\s*(.*)", line)
        if not km:
            i += 1
            continue
        key, val = km.group(1), km.group(2).strip()
        if val.startswith("["):
            bracket = val
            while "]" not in bracket and i + 1 < len(lines):
                i += 1
                bracket += " " + lines[i].strip()
            inner = re.sub(r"[\[\]]", "", bracket)
            result[key] = [x.strip().strip('"').strip("'") for x in inner.split(",") if x.strip()]
        elif val == "":
            items: list[str] = []
            while i + 1 < len(lines) and re.match(r"^\s+-\s+", lines[i + 1]):
                i += 1
                items.append(re.sub(r"^\s+-\s+", "", lines[i]).strip().strip('"').strip("'"))
            result[key] = items if items else None
        else:
            result[key] = val.strip('"').strip("'")
        i += 1
    return result, body


def _collect_pages() -> list[Path]:
    pages: list[Path] = []
    for p in WIKI_ROOT.rglob("*.md"):
        if p.name in EXCLUDED_FILES:
            continue
        if any(part in EXCLUDED_DIRS for part in p.parts):
            continue
        pages.append(p)
    return sorted(pages)


def _load_index() -> str:
    idx = WIKI_ROOT / "index.md"
    return idx.read_text(encoding="utf-8") if idx.exists() else ""


def _relative_links(body: str) -> list[str]:
    paths: list[str] = []
    for link in re.findall(r"\[(?:[^\]]*)\]\(([^)]+)\)", body):
        p = link.split("#")[0].strip()
        if p and not re.match(r"^https?://|^mailto:", p):
            paths.append(p)
    return paths


def _count_body_words(body: str) -> int:
    m = re.search(r"^##\s+TL;DR", body, re.MULTILINE)
    if not m:
        return 0
    after = body[m.end():]
    lines = [ln for ln in after.splitlines() if not ln.strip().startswith("|")]
    text = re.sub(r"[#*`>_~\[\]()]", " ", " ".join(lines))
    return len([w for w in text.split() if w.strip()])


def _parse_date(s: str) -> date | None:
    try:
        return datetime.strptime(s.strip(), "%Y-%m-%d").date()
    except (ValueError, AttributeError):
        return None


def _git_mtime(file_path: str) -> date | None:
    try:
        r = subprocess.run(
            ["git", "log", "-1", "--format=%cI", file_path],
            capture_output=True, text=True, timeout=10,
        )
        raw = r.stdout.strip()
        return datetime.fromisoformat(raw).date() if raw else None
    except Exception:
        return None


def lint(wiki_root: Path = WIKI_ROOT) -> int:
    """Run all lint checks. Returns 0 (ok) or 1 (errors found)."""
    global WIKI_ROOT
    WIKI_ROOT = wiki_root

    pages = _collect_pages()
    index_text = _load_index()
    errors: list[str] = []
    warnings: list[str] = []

    for page in pages:
        rel = page.relative_to(WIKI_ROOT.parent)
        rel_from_wiki = str(page.relative_to(WIKI_ROOT)).replace("\\", "/")
        text = page.read_text(encoding="utf-8")

        fm, body = _parse_frontmatter(text)
        if fm is None:
            errors.append(f"[ERR] {rel}: frontmatter missing")
            continue

        for field in REQUIRED_FIELDS:
            if field not in fm or fm[field] is None or fm[field] == "":
                errors.append(f"[ERR] {rel}: required frontmatter field missing: {field}")

        if not re.search(r"^##\s+핵심 사실", body, re.MULTILINE):
            errors.append(f"[ERR] {rel}: '## 핵심 사실' heading missing")
        if not re.search(r"^##\s+TL;DR", body, re.MULTILINE):
            errors.append(f"[ERR] {rel}: '## TL;DR' heading missing")

        for link_path in _relative_links(body):
            if not (page.parent / link_path).resolve().exists():
                errors.append(f"[ERR] {rel}: broken link → {link_path}")

        if rel_from_wiki not in index_text:
            errors.append(f"[ERR] {rel}: orphan — not registered in wiki/index.md")

        page_type = fm.get("type", "")
        budget = WORD_BUDGETS.get(str(page_type))
        if budget is not None:
            wc = _count_body_words(body)
            if wc > budget:
                warnings.append(f"[WARN] {rel}: body {wc} words > budget {budget} (type={page_type})")

        updated_date = _parse_date(str(fm.get("updated", "")))
        if updated_date and (TODAY - updated_date) > STALE_THRESHOLD:
            warnings.append(f"[WARN] {rel}: 'updated' ({updated_date}) older than 90 days")

        anchors = fm.get("code_anchors")
        if anchors and isinstance(anchors, list) and updated_date:
            for anchor in anchors:
                file_part = anchor.split(":")[0].strip()
                mtime = _git_mtime(file_part)
                if mtime and mtime > updated_date:
                    warnings.append(
                        f"[WARN] {rel}: code_anchor '{file_part}' modified {mtime} "
                        f"after page updated {updated_date}"
                    )

    for line in errors + warnings:
        print(line)

    total, ec, wc2 = len(pages), len(errors), len(warnings)
    if ec == 0 and wc2 == 0:
        print(f"OK — {total} page(s), 0 errors, 0 warnings")
    else:
        print(f"\nSummary: {total} page(s) / {ec} error(s) / {wc2} warning(s)")

    return 1 if errors else 0


def main() -> None:
    sys.exit(lint())


if __name__ == "__main__":
    main()
