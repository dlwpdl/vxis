"""
Upstream Watch — Notification & digest system.

Sends reports via Telegram bot, Slack webhooks, and generates
markdown digest reports.

Telegram setup:
    1. Create bot via @BotFather → get token
    2. Get chat ID: send /start to bot, then visit
       https://api.telegram.org/bot<TOKEN>/getUpdates
    3. Set env vars: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
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


# ── Telegram Notification ────────────────────────────────────────


def _relevance_gauge(score: float) -> str:
    """Visual relevance gauge with emoji."""
    pct = int(score * 100)
    if pct >= 80:
        return f"\ud83d\udd34 {pct}%"
    if pct >= 60:
        return f"\ud83d\udfe0 {pct}%"
    if pct >= 40:
        return f"\ud83d\udfe1 {pct}%"
    return f"\u26aa {pct}%"


def _priority_icon(priority: str) -> str:
    """Priority indicator for Telegram."""
    return {
        "high": "\ud83d\udea8",
        "medium": "\u26a0\ufe0f",
        "low": "\ud83d\udca1",
    }.get(priority.lower(), "\u2022")


def _category_kr(category: str) -> str:
    """Translate category to Korean."""
    return {
        "architecture": "\uc544\ud0a4\ud14d\ucc98",
        "plugin": "\ud50c\ub7ec\uadf8\uc778",
        "report": "\ub9ac\ud3ec\ud2b8",
        "pipeline": "\ud30c\uc774\ud504\ub77c\uc778",
        "tool-integration": "\ud234 \ud1b5\ud569",
        "performance": "\uc131\ub2a5",
        "security": "\ubcf4\uc548",
    }.get(category, category)


def _priority_kr(priority: str) -> str:
    """Translate priority to Korean."""
    return {"high": "\ub192\uc74c", "medium": "\uc911\uac04", "low": "\ub0ae\uc74c"}.get(priority.lower(), priority)


def send_telegram(
    results: list[AnalysisResult],
    config: NotifyConfig,
) -> bool:
    """Send upstream watch report to Telegram in Korean with clean formatting.

    Env vars: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return False

    relevant = [r for r in results if r.relevance_score >= config.min_relevance_score]
    no_change = [r for r in results if r.relevance_score < config.min_relevance_score]

    now = datetime.now(timezone.utc)
    kst_hour = (now.hour + 9) % 24
    time_str = f"{now.strftime('%Y-%m-%d')} {kst_hour:02d}:{now.strftime('%M')} KST"

    lines: list[str] = []

    # ── Header ──
    lines.append("\ud83d\udd0d <b>VXIS Upstream Watch \ub9ac\ud3ec\ud2b8</b>")
    lines.append(f"\ud83d\udcc5 {time_str}")
    lines.append(f"\ud83d\udcca \uac10\uc2dc \ub300\uc0c1 {len(results)}\uac1c \ub808\ud3ec | \ubcc0\uacbd \uac10\uc9c0 {len(relevant)}\uac1c")
    lines.append("")

    if not relevant:
        lines.append("\u2705 \ubcc0\uacbd \uc0ac\ud56d \uc5c6\uc74c \u2014 \ubaa8\ub4e0 \ub808\ud3ec \uc548\uc815\uc801")
        if no_change:
            names = ", ".join(r.repo.split("/")[-1] for r in no_change[:8])
            lines.append(f"\n<i>\ud655\uc778\ub41c \ub808\ud3ec: {_tg_escape(names)}</i>")
    else:
        # ── Each relevant repo ──
        for idx, r in enumerate(
            sorted(relevant, key=lambda x: x.relevance_score, reverse=True)
        ):
            gauge = _relevance_gauge(r.relevance_score)
            repo_short = r.repo.split("/")[-1]
            repo_url = f"https://github.com/{r.repo}"

            lines.append(f"\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500")
            lines.append(
                f"{gauge}  <b><a href=\"{repo_url}\">{_tg_escape(r.repo)}</a></b>"
            )
            lines.append(f"\ud83d\udcdd {_tg_escape(r.summary)}")
            lines.append("")

            # Action items
            for item in r.actionable_items[:4]:
                icon = _priority_icon(item.priority)
                cat = _category_kr(item.category)
                prio = _priority_kr(item.priority)

                lines.append(
                    f"  {icon} <b>{_tg_escape(item.title)}</b>"
                )
                lines.append(
                    f"     \ud83c\udff7 {cat} | \uc6b0\uc120\uc21c\uc704: {prio}"
                )

                desc = item.description[:150]
                if len(item.description) > 150:
                    desc += "..."
                lines.append(f"     {_tg_escape(desc)}")

                if item.vxis_files:
                    files = ", ".join(item.vxis_files[:3])
                    lines.append(f"     \ud83d\udcc2 <code>{_tg_escape(files)}</code>")
                lines.append("")

        # ── Summary footer ──
        total_actions = sum(len(r.actionable_items) for r in relevant)
        high_count = sum(
            1 for r in relevant
            for item in r.actionable_items
            if item.priority == "high"
        )
        lines.append("\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500")
        lines.append(f"\ud83d\udcca <b>\uc694\uc57d</b>")
        lines.append(f"  \u2022 \uc561\uc158 \uc544\uc774\ud15c: {total_actions}\uac1c")
        if high_count:
            lines.append(f"  \u2022 \ud83d\udea8 \ub192\uc740 \uc6b0\uc120\uc21c\uc704: {high_count}\uac1c")
        lines.append(f"  \u2022 \ubcc0\uacbd \uc5c6\ub294 \ub808\ud3ec: {len(no_change)}\uac1c")

        # No-change repos at bottom
        if no_change:
            names = ", ".join(r.repo.split("/")[-1] for r in no_change[:10])
            lines.append(f"\n<i>\ubcc0\uacbd \uc5c6\uc74c: {_tg_escape(names)}</i>")

    full_text = "\n".join(lines)

    chunks = _split_telegram_message(full_text, 4000)
    success = True
    for chunk in chunks:
        if not _send_telegram_message(token, chat_id, chunk):
            success = False

    return success


def send_telegram_text(text: str) -> bool:
    """Send arbitrary text to Telegram. For digest/trending reports."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return False

    chunks = _split_telegram_message(text, 4000)
    for chunk in chunks:
        if not _send_telegram_message(token, chat_id, chunk):
            return False
    return True


def _tg_escape(text: str) -> str:
    """Escape special chars for Telegram HTML parse mode."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _send_telegram_message(token: str, chat_id: str, text: str) -> bool:
    """Send a single message via Telegram Bot API."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=15)
        return True
    except Exception:
        return False


def _split_telegram_message(text: str, max_len: int = 4000) -> list[str]:
    """Split long text into chunks that fit Telegram's 4096 char limit."""
    if len(text) <= max_len:
        return [text]

    chunks = []
    while text:
        if len(text) <= max_len:
            chunks.append(text)
            break
        # Try to split at last newline before limit
        split_at = text.rfind("\n", 0, max_len)
        if split_at == -1:
            split_at = max_len
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    return chunks


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
