"""
Upstream Watch — Notification & digest system.

Sends Slack webhooks for high-relevance items and generates
weekly markdown digest reports.
"""

from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .analyzer import ActionItem, AnalysisResult
from .config import DIGEST_DIR, NotifyConfig


def _priority_emoji(priority: str) -> str:
    return {"high": "[!!!]", "medium": "[!!]", "low": "[!]"}.get(priority, "[ ]")


def _score_bar(score: float) -> str:
    filled = int(score * 10)
    return f"[{'#' * filled}{'.' * (10 - filled)}] {score:.1f}"


# ── Slack Notification ───────────────────────────────────────────


def send_slack(
    results: list[AnalysisResult],
    config: NotifyConfig,
) -> bool:
    """Send relevant findings to Slack webhook."""
    webhook_url = config.slack_webhook_url or os.environ.get("VXIS_SLACK_WEBHOOK", "")
    if not webhook_url:
        return False

    relevant = [r for r in results if r.relevance_score >= config.min_relevance_score]
    if not relevant:
        return True  # Nothing to send, but not an error

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"VXIS Upstream Watch — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            },
        }
    ]

    for result in relevant:
        # Repo summary
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{result.repo}* — Relevance: {_score_bar(result.relevance_score)}\n"
                    f"{result.summary}"
                ),
            },
        })

        # Action items
        for item in result.actionable_items[:5]:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{_priority_emoji(item.priority)} *{item.title}* "
                        f"(`{item.category}` / {item.priority})\n"
                        f"{item.description[:300]}\n"
                        f"Affects: {', '.join(item.vxis_files[:3]) or 'TBD'}"
                    ),
                },
            })

        blocks.append({"type": "divider"})

    payload = json.dumps({"blocks": blocks}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception:
        return False


# ── Markdown Digest ──────────────────────────────────────────────


def generate_daily_digest(results: list[AnalysisResult]) -> str:
    """Generate a markdown daily digest of all analyzed repos."""
    now = datetime.now(timezone.utc)
    lines = [
        f"# VXIS Upstream Watch — Daily Digest",
        f"**Date:** {now.strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]

    # Summary table
    lines.extend([
        "## Summary",
        "",
        "| Repository | Relevance | Action Items |",
        "|------------|-----------|--------------|",
    ])
    for r in sorted(results, key=lambda x: x.relevance_score, reverse=True):
        count = len(r.actionable_items)
        lines.append(
            f"| {r.repo} | {_score_bar(r.relevance_score)} | {count} items |"
        )
    lines.append("")

    # Detailed results (only relevant ones)
    relevant = [r for r in results if r.relevance_score > 0.0]
    if relevant:
        lines.append("## Relevant Changes")
        lines.append("")

        for r in sorted(relevant, key=lambda x: x.relevance_score, reverse=True):
            lines.extend([
                f"### {r.repo} (score: {r.relevance_score:.2f})",
                "",
                r.summary,
                "",
            ])

            if r.actionable_items:
                for item in r.actionable_items:
                    lines.extend([
                        f"#### {_priority_emoji(item.priority)} {item.title}",
                        f"- **Category:** {item.category}",
                        f"- **Priority:** {item.priority}",
                        f"- **Description:** {item.description}",
                        f"- **Source:** {item.source_ref}",
                    ])
                    if item.vxis_files:
                        lines.append(
                            f"- **VXIS files:** {', '.join(item.vxis_files)}"
                        )
                    lines.append("")

    # No changes section
    no_changes = [r for r in results if r.relevance_score == 0.0]
    if no_changes:
        lines.extend([
            "## No Relevant Changes",
            "",
        ])
        for r in no_changes:
            lines.append(f"- **{r.repo}**: {r.summary}")
        lines.append("")

    return "\n".join(lines)


def generate_weekly_digest(daily_digests: list[str]) -> str:
    """Aggregate daily digests into a weekly summary."""
    now = datetime.now(timezone.utc)
    lines = [
        f"# VXIS Upstream Watch — Weekly Digest",
        f"**Week of:** {now.strftime('%Y-%m-%d')}",
        "",
        "---",
        "",
    ]
    for digest in daily_digests:
        lines.append(digest)
        lines.append("\n---\n")

    return "\n".join(lines)


def save_digest(content: str, filename: str) -> Path:
    """Save digest to file."""
    path = Path(DIGEST_DIR)
    path.mkdir(parents=True, exist_ok=True)
    filepath = path / filename
    filepath.write_text(content)
    return filepath


def create_github_issue_body(results: list[AnalysisResult]) -> str:
    """Format results as a GitHub issue body for tracking."""
    high_priority = []
    for r in results:
        for item in r.actionable_items:
            if item.priority == "high":
                high_priority.append((r.repo, item))

    if not high_priority:
        return ""

    lines = [
        "## Upstream Watch: High-Priority Items",
        "",
        "The following high-priority changes were detected in upstream repos.",
        "",
    ]

    for repo, item in high_priority:
        lines.extend([
            f"### [{item.title}]({item.source_ref})",
            f"- **Repo:** {repo}",
            f"- **Category:** {item.category}",
            f"- **Description:** {item.description}",
        ])
        if item.vxis_files:
            lines.append(f"- **Affected VXIS files:** {', '.join(item.vxis_files)}")
        lines.extend([
            "",
            "- [ ] Reviewed",
            "- [ ] Implemented / Not applicable",
            "",
        ])

    return "\n".join(lines)
