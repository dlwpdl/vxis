#!/usr/bin/env python3
"""
wiki/scripts/log_ingest.py — VXIS Wiki Log Ingest Helper
Run from repo root: python wiki/scripts/log_ingest.py --type ingest --subject "..." [--body "..."]

Allowed types: init | ingest | refactor | decay | lint-fix | decision
Appends to wiki/log.md. Idempotent: skips if last entry has same date+type+subject.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOG_PATH = Path("wiki/log.md")
ALLOWED_TYPES = {"init", "ingest", "refactor", "decay", "lint-fix", "decision"}
TODAY = date.today().isoformat()


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def _read_log() -> str:
    if not LOG_PATH.exists():
        return ""
    return LOG_PATH.read_text(encoding="utf-8")


def _last_entry_matches(log_text: str, entry_type: str, subject: str) -> bool:
    """
    Return True if the most recent ## [...] header has the same date+type+subject.
    Prevents double-append on rerun.
    """
    import re
    headers = re.findall(
        r"^##\s+\[(\d{4}-\d{2}-\d{2})\]\s+(\S+)\s+\|\s+(.+)$",
        log_text,
        re.MULTILINE,
    )
    if not headers:
        return False
    last_date, last_type, last_subject = headers[-1]
    return (
        last_date == TODAY
        and last_type == entry_type
        and last_subject.strip() == subject.strip()
    )


def _build_entry(entry_type: str, subject: str, body: str | None) -> str:
    lines = [f"\n## [{TODAY}] {entry_type} | {subject}"]
    if body:
        for line in body.strip().splitlines():
            lines.append(f"- {line.strip()}")
    return "\n".join(lines) + "\n"


def append_log(entry_type: str, subject: str, body: str | None = None) -> int:
    """
    Append a log entry to wiki/log.md.
    Returns 0 on success, 1 on error.
    """
    if entry_type not in ALLOWED_TYPES:
        print(
            f"[ERR] Unknown type '{entry_type}'. "
            f"Allowed: {', '.join(sorted(ALLOWED_TYPES))}",
            file=sys.stderr,
        )
        return 1

    log_text = _read_log()

    if _last_entry_matches(log_text, entry_type, subject):
        print(
            f"[WARN] Skipping duplicate: last entry already has "
            f"[{TODAY}] {entry_type} | {subject}"
        )
        return 0

    entry = _build_entry(entry_type, subject, body)

    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(entry)

    print(f"[OK] Appended to {LOG_PATH}: [{TODAY}] {entry_type} | {subject}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Append a log entry to wiki/log.md",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            f"Allowed types: {', '.join(sorted(ALLOWED_TYPES))}\n\n"
            "Examples:\n"
            "  python wiki/scripts/log_ingest.py --type ingest --subject \"WebGoat 2026-04 scan report\"\n"
            "  python wiki/scripts/log_ingest.py --type decision --subject \"Chose cursor pagination\" --body \"Offset too slow at 1M rows\"\n"
        ),
    )
    parser.add_argument("--type", required=True, dest="entry_type", help="Log entry type")
    parser.add_argument("--subject", required=True, help="One-line subject")
    parser.add_argument("--body", default=None, help="Optional 1-3 line body text")

    args = parser.parse_args()
    sys.exit(append_log(args.entry_type, args.subject, args.body))


if __name__ == "__main__":
    main()
