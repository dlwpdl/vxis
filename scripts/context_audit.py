#!/usr/bin/env python3
"""Audit repository files against LLM-friendly context-size budgets."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

logging.getLogger("vxis.ghost.transport").setLevel(logging.ERROR)

from vxis.dev.context_audit import audit_repo_context, format_context_audit  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", default=["src/vxis", "tests", "scripts"])
    parser.add_argument("--max-file-tokens", type=int, default=30_000)
    parser.add_argument("--max-file-bytes", type=int, default=120_000)
    parser.add_argument("--max-file-lines", type=int, default=2_500)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--fail-on-warning", action="store_true")
    args = parser.parse_args(argv)

    roots = [ROOT / path for path in args.paths]
    report = audit_repo_context(
        roots,
        max_file_tokens=args.max_file_tokens,
        max_file_bytes=args.max_file_bytes,
        max_file_lines=args.max_file_lines,
    )
    print(format_context_audit(report, limit=args.limit))
    if args.fail_on_warning and report.warning_count:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
