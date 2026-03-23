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
    UPSTREAM_LLM_PROVIDER  — "together" | "anthropic" | "google" | "openai" | ... (default: together)
    UPSTREAM_LLM_MODEL     — Model override (e.g. "qwen-72b", "deepseek-r1")
    TOGETHER_API_KEY       — Together.ai key (access Kimi-K2.5, GLM-5, Llama, Qwen, DeepSeek, etc.)
    ANTHROPIC_API_KEY      — Claude direct API
    GOOGLE_API_KEY         — Gemini direct API
    OPENAI_API_KEY         — OpenAI direct API
    GITHUB_TOKEN           — Recommended for higher API rate limits
    VXIS_SLACK_WEBHOOK     — Optional, for Slack notifications
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from .adoption import create_proposals, save_proposals, save_proposals_json
from .analyzer import analyze_all
from .config import TARGETS, NotifyConfig
from .discovery import format_discovery_report, search_new_tools
from .fetcher import fetch_all
from .notifier import (
    create_github_issue_body,
    generate_daily_digest,
    save_digest,
    send_slack,
    send_telegram,
)
from .overlap import check_all_overlaps, format_overlap_report
from .registry import get_active_targets, load_targets
from .telegram_bot import poll_decisions, send_decision_summary, send_proposals_with_buttons
from .trending import TrendTracker, fetch_repo_metrics, format_trending_report
from .trends import ProposalDeduplicator, TrendDetector


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
    # Phase 0: Check for Telegram decisions from previous run
    print("[TELEGRAM] 이전 제안에 대한 결정 확인 중...")
    tg_decisions = poll_decisions()
    if tg_decisions:
        print(f"[TELEGRAM] {len(tg_decisions)}개 결정 수집 완료:")
        for d in tg_decisions:
            action_kr = {"approved": "승인", "rejected": "거절", "deferred": "보류"}.get(d.action, d.action)
            print(f"    {action_kr}: {d.proposal_id}")
            if d.reason:
                print(f"       💬 {d.reason}")
        send_decision_summary(tg_decisions)
    else:
        print("[TELEGRAM] 대기 중인 결정 없음")

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

    # Phase 2: Activity spike detection + metrics recording
    print("[TREND] Collecting repo metrics and checking for activity spikes...")
    tracker = TrendTracker()
    for t in fetch_targets:
        try:
            metrics = fetch_repo_metrics(t.owner, t.repo)
            tracker.record_metrics(metrics)
            spikes = tracker.detect_spikes(f"{t.owner}/{t.repo}")
            if spikes:
                print(
                    f"    [SPIKE] {t.owner}/{t.repo}: "
                    + ", ".join(s.upper() for s in spikes)
                )
        except Exception as exc:
            print(f"    [TREND] Could not fetch metrics for {t.owner}/{t.repo}: {exc}")

    # Phase 3: AI analysis
    print("[ANALYZE] Running Claude analysis on changes...")
    results = analyze_all(changes_list)

    relevant = [r for r in results if r.relevance_score >= min_relevance]
    total_actions = sum(len(r.actionable_items) for r in relevant)
    print(
        f"[ANALYZE] Done — {len(relevant)} relevant repos, "
        f"{total_actions} actionable items"
    )

    # Phase 3a: Cross-repo trend detection
    if relevant:
        detector = TrendDetector()
        cross_trends = detector.detect_cross_repo_trends(relevant)
        if cross_trends:
            print(f"[TRENDS] {len(cross_trends)} cross-repo trends detected:")
            for trend in cross_trends:
                print(f"    {trend}")

    # Phase 4: Overlap detection against VXIS codebase
    all_items = [item for r in relevant for item in r.actionable_items]
    # Phase 4a: Filter out already-decided proposals before overlap check
    if all_items:
        from .adoption import DECISIONS_FILE
        deduplicator = ProposalDeduplicator(DECISIONS_FILE)
        original_count = len(all_items)
        all_items = deduplicator.filter_decided(all_items)
        filtered_count = original_count - len(all_items)
        if filtered_count:
            print(
                f"[DEDUP] Filtered {filtered_count} already-decided item(s); "
                f"{len(all_items)} remaining"
            )

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

    # Phase 5: Generate proposals + send to Telegram with buttons
    if all_items and overlaps:
        print("[PROPOSE] Generating adoption proposals...")
        proposal_set = create_proposals(results, overlaps)
        if proposal_set.proposals:
            md_path = save_proposals(proposal_set)
            json_path = save_proposals_json(proposal_set)
            print(f"[PROPOSE] {len(proposal_set.proposals)} proposals saved:")
            print(f"    Review:  {md_path}")
            print(f"    Data:    {json_path}")

            if not dry_run:
                sent = send_proposals_with_buttons(proposal_set)
                if sent:
                    print(f"[TELEGRAM] {sent}개 제안을 인라인 버튼과 함께 전송")
                else:
                    print("[TELEGRAM] Telegram 미설정 또는 전송 실패")

    # Phase 6: Output summary
    for r in sorted(results, key=lambda x: x.relevance_score, reverse=True):
        if r.relevance_score > 0:
            print(f"\n  {r.repo}: score={r.relevance_score:.2f}")
            print(f"    {r.summary}")
            for item in r.actionable_items:
                print(f"    [{item.priority.upper()}] {item.title} ({item.category})")

    # Phase 7: Save digest (includes overlap, trending, and discovery reports)
    now = datetime.now(timezone.utc)
    digest = generate_daily_digest(results)
    if overlaps:
        digest += "\n\n" + format_overlap_report(overlaps)

    # Append trending report
    trending_report = format_trending_report(tracker)
    digest += "\n\n" + trending_report

    # Append cross-repo trend summary (if any)
    if relevant:
        detector = TrendDetector()
        cross_trends = detector.detect_cross_repo_trends(relevant)
        if cross_trends:
            digest += "\n\n## Cross-Repo Trends\n\n" + "\n".join(cross_trends) + "\n"

    filename = f"daily-{now.strftime('%Y-%m-%d')}.md"
    path = save_digest(digest, filename)
    print(f"\n[DIGEST] Saved to {path}")

    # Phase 8: Notify (unless dry run)
    if not dry_run:
        config = NotifyConfig(min_relevance_score=min_relevance)
        if send_telegram(results, config):
            print("[NOTIFY] Telegram report sent")
        else:
            print("[NOTIFY] Telegram not configured or send failed")

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

    # Append discovery report to weekly digest
    print("[WEEKLY] Running new tool discovery search...")
    try:
        discovered = search_new_tools()
        discovery_report = format_discovery_report(discovered)
        if discovered:
            print(f"[WEEKLY] Discovered {len(discovered)} new tool(s)")
        else:
            print("[WEEKLY] No new tools discovered")
        weekly += "\n\n" + discovery_report
    except Exception as exc:
        print(f"[WEEKLY] Discovery search failed: {exc}")

    # Append weekly trending report
    try:
        tracker = TrendTracker()
        weekly += "\n\n" + format_trending_report(tracker)
    except Exception as exc:
        print(f"[WEEKLY] Trending report failed: {exc}")

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
