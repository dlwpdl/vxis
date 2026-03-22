#!/usr/bin/env python3
"""
VXIS Upstream Watch — Main orchestrator.

Monitors target open-source repos, analyzes changes with Claude API,
checks overlap against VXIS codebase, and generates adoption proposals.

Usage:
    # Daily run (typically via GitHub Actions cron)
    python -m tools.upstream_watch --mode daily

    # Weekly digest (aggregates daily results)
    python -m tools.upstream_watch --mode weekly

    # Dry run (fetch + analyze but don't notify)
    python -m tools.upstream_watch --mode daily --dry-run

    # Check specific repo only
    python -m tools.upstream_watch --mode daily --repo usestrix/strix

    # Manage targets (see cli.py for full commands)
    python -m tools.upstream_watch.cli target list
    python -m tools.upstream_watch.cli target add owner/repo --reason "..."
    python -m tools.upstream_watch.cli review
    python -m tools.upstream_watch.cli decide <id> approved "reason"

Environment variables:
    ANTHROPIC_API_KEY    — Required for AI analysis
    GITHUB_TOKEN         — Recommended for higher API rate limits
    VXIS_SLACK_WEBHOOK   — Optional, for Slack notifications
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from .adoption import create_proposals, save_proposals, save_proposals_json
from .analyzer import analyze_all
from .config import TARGETS, NotifyConfig
from .fetcher import fetch_all
from .notifier import (
    create_github_issue_body,
    generate_daily_digest,
    save_digest,
    send_slack,
)
from .overlap import check_all_overlaps, format_overlap_report
from .registry import get_active_targets, load_targets


def _resolve_targets(repo_filter: str | None = None):
    """Get targets from registry (dynamic TOML) or fallback to hardcoded defaults."""
    registry_targets = load_targets()
    if registry_targets:
        targets = get_active_targets()
        source = "registry"
    else:
        targets = TARGETS
        source = "defaults"

    if repo_filter:
        if source == "registry":
            targets = [t for t in targets if t.full_name == repo_filter]
        else:
            targets = [
                t for t in targets if f"{t.owner}/{t.repo}" == repo_filter
            ]

    return targets, source


def run_daily(
    dry_run: bool = False,
    repo_filter: str | None = None,
    min_relevance: float = 0.6,
) -> int:
    """Execute daily upstream watch cycle."""
    targets, source = _resolve_targets(repo_filter)
    if not targets:
        print(f"[ERROR] No targets found (source: {source}, filter: {repo_filter})")
        return 1

    # Phase 1: Fetch changes
    print(f"[FETCH] Checking {len(targets)} repositories (source: {source})...")

    # Convert registry WatchTargets to fetcher-compatible format
    from .config import WatchTarget as ConfigTarget
    fetch_targets = []
    for t in targets:
        if isinstance(t, ConfigTarget):
            fetch_targets.append(t)
        else:
            # Registry WatchTarget → Config WatchTarget adapter
            fetch_targets.append(ConfigTarget(
                owner=t.owner,
                repo=t.repo,
                reason=t.reason,
                watch_releases=t.watch_releases,
                watch_commits=t.watch_commits,
                branches=tuple(t.branches),
                include_paths=tuple(t.include_paths),
                exclude_paths=tuple(t.exclude_paths),
                relevance_tags=tuple(t.relevance_tags),
            ))

    changes_list = fetch_all(fetch_targets)

    repos_with_changes = sum(1 for c in changes_list if c.has_changes)
    total_commits = sum(len(c.commits) for c in changes_list)
    total_releases = sum(len(c.releases) for c in changes_list)
    print(
        f"[FETCH] Done — {repos_with_changes} repos with changes, "
        f"{total_commits} commits, {total_releases} releases"
    )

    if repos_with_changes == 0:
        print("[SKIP] No changes detected. Nothing to analyze.")
        return 0

    # Phase 2: AI analysis
    print("[ANALYZE] Running Claude analysis on changes...")
    results = analyze_all(changes_list)

    relevant = [r for r in results if r.relevance_score >= min_relevance]
    total_actions = sum(len(r.actionable_items) for r in relevant)
    print(
        f"[ANALYZE] Done — {len(relevant)} relevant repos, "
        f"{total_actions} actionable items"
    )

    # Phase 3: Overlap detection against VXIS codebase
    all_items = [item for r in relevant for item in r.actionable_items]
    if all_items:
        print(f"[OVERLAP] Checking {len(all_items)} items against VXIS codebase...")
        overlaps = check_all_overlaps(all_items)

        new_count = sum(1 for o in overlaps if o.verdict == "new")
        enhance_count = sum(1 for o in overlaps if o.verdict == "enhancement")
        dup_count = sum(1 for o in overlaps if o.verdict == "already_exists")
        print(
            f"[OVERLAP] {new_count} new, {enhance_count} enhancements, "
            f"{dup_count} already exist"
        )

        # Print overlap details
        for o in overlaps:
            icon = {"new": "+", "enhancement": "~", "already_exists": "X", "partial_overlap": "?"}
            print(f"    [{icon.get(o.verdict, '?')}] {o.item.title} — {o.verdict} ({o.overlap_score:.0%})")
    else:
        overlaps = []

    # Phase 4: Generate proposals
    if all_items and overlaps:
        print("[PROPOSE] Generating adoption proposals...")
        proposal_set = create_proposals(results, overlaps)
        if proposal_set.proposals:
            md_path = save_proposals(proposal_set)
            json_path = save_proposals_json(proposal_set)
            print(f"[PROPOSE] {len(proposal_set.proposals)} proposals saved:")
            print(f"    Review:  {md_path}")
            print(f"    Data:    {json_path}")
            print(f"    Decide:  python -m tools.upstream_watch.cli decide <id> approved|rejected")

    # Phase 5: Output summary
    for r in sorted(results, key=lambda x: x.relevance_score, reverse=True):
        if r.relevance_score > 0:
            print(f"\n  {r.repo}: score={r.relevance_score:.2f}")
            print(f"    {r.summary}")
            for item in r.actionable_items:
                print(f"    [{item.priority.upper()}] {item.title} ({item.category})")

    # Phase 6: Save digest (includes overlap report)
    now = datetime.now(timezone.utc)
    digest = generate_daily_digest(results)
    if overlaps:
        digest += "\n\n" + format_overlap_report(overlaps)
    filename = f"daily-{now.strftime('%Y-%m-%d')}.md"
    path = save_digest(digest, filename)
    print(f"\n[DIGEST] Saved to {path}")

    # Phase 7: Notify (unless dry run)
    if not dry_run:
        config = NotifyConfig(min_relevance_score=min_relevance)
        if send_slack(results, config):
            print("[NOTIFY] Slack notification sent")
        else:
            print("[NOTIFY] Slack not configured or send failed")

        issue_body = create_github_issue_body(results)
        if issue_body:
            issue_path = save_digest(
                issue_body,
                f"issue-{now.strftime('%Y-%m-%d')}.md",
            )
            print(f"[ISSUE] High-priority issue template saved to {issue_path}")
    else:
        print("[DRY-RUN] Skipping notifications")

    return 0


def run_weekly() -> int:
    """Aggregate daily digests into a weekly report."""
    from pathlib import Path

    digest_dir = Path("tools/upstream_watch/digests")
    if not digest_dir.exists():
        print("[ERROR] No digest directory found")
        return 1

    daily_files = sorted(digest_dir.glob("daily-*.md"), reverse=True)[:7]
    if not daily_files:
        print("[ERROR] No daily digests found")
        return 1

    dailies = [f.read_text() for f in daily_files]
    print(f"[WEEKLY] Aggregating {len(dailies)} daily digests...")

    from .notifier import generate_weekly_digest

    weekly = generate_weekly_digest(dailies)
    now = datetime.now(timezone.utc)
    filename = f"weekly-{now.strftime('%Y-%m-%d')}.md"
    path = save_digest(weekly, filename)
    print(f"[WEEKLY] Saved to {path}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VXIS Upstream Watch — AI-powered open-source intelligence"
    )
    parser.add_argument(
        "--mode",
        choices=["daily", "weekly"],
        default="daily",
        help="Run mode (default: daily)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and analyze but don't send notifications",
    )
    parser.add_argument(
        "--repo",
        type=str,
        default=None,
        help="Filter to specific repo (e.g., usestrix/strix)",
    )
    parser.add_argument(
        "--min-relevance",
        type=float,
        default=0.6,
        help="Minimum relevance score for notifications (0.0-1.0)",
    )

    args = parser.parse_args()

    if args.mode == "daily":
        return run_daily(
            dry_run=args.dry_run,
            repo_filter=args.repo,
            min_relevance=args.min_relevance,
        )
    elif args.mode == "weekly":
        return run_weekly()

    return 0


if __name__ == "__main__":
    sys.exit(main())
