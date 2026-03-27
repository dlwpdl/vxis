"""Domain Intelligence — Telegram 알림.

보안 트렌드 리포트를 Telegram으로 전송한다.
모드: daily, weekly, monthly, quarterly, yearly

Env vars: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from datetime import datetime, timezone

from .synthesizer import WeeklyReport

logger = logging.getLogger(__name__)

_PERIOD_EMOJI = {
    "daily": "\U0001f4c6",    # 📆
    "weekly": "\U0001f4c5",   # 📅
    "monthly": "\U0001f5d3",  # 🗓
    "quarterly": "\U0001f4ca",  # 📊
    "yearly": "\U0001f3c6",   # 🏆
}

_PERIOD_KR = {
    "daily": "일일",
    "weekly": "주간",
    "monthly": "월간",
    "quarterly": "분기",
    "yearly": "연간",
}


def send_telegram_report(report: WeeklyReport, period: str = "weekly") -> bool:
    """WeeklyReport를 Telegram HTML 메시지로 전송."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return False

    text = _format_telegram_message(report, period)
    chunks = _split_message(text, 4000)

    for chunk in chunks:
        if not _send(token, chat_id, chunk):
            return False
    return True


def send_telegram_rollup(
    period: str,
    period_kr: str,
    date_str: str,
    digest_count: int,
    summary: str,
) -> bool:
    """롤업 리포트를 Telegram으로 전송 (월간/분기/연간)."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return False

    emoji = _PERIOD_EMOJI.get(period, "\U0001f4ca")
    now = datetime.now(timezone.utc)
    kst_hour = (now.hour + 9) % 24
    time_str = f"{date_str} {kst_hour:02d}:{now.strftime('%M')} KST"

    lines: list[str] = [
        f"{emoji} <b>VXIS Domain Intelligence \u2014 {_esc(period_kr)} \ub864\uc5c5</b>",
        f"\U0001f4c5 {time_str}",
        "",
    ]

    if digest_count == 0:
        lines.append("\u2705 \ud574\ub2f9 \uae30\uac04 \uc218\uc9d1\ub41c \ub9ac\ud3ec\ud2b8\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.")
        lines.append("\ub2e4\uc74c \uc8fc\uae30\uc5d0 \ub370\uc774\ud130\uac00 \uc30d\uc774\uba74 \uc885\ud569 \ubd84\uc11d\uc744 \uc81c\uacf5\ud569\ub2c8\ub2e4.")
    else:
        lines.append(f"\U0001f4d1 \ud3ec\ud568 \ub9ac\ud3ec\ud2b8: <b>{digest_count}\uac1c</b>")
        lines.append("")
        lines.append("<b>\uc8fc\uc694 \ud2b8\ub80c\ub4dc:</b>")
        lines.append(_esc(summary))

    text = "\n".join(lines)
    return _send(token, chat_id, text)


# ── 메시지 포맷 ──────────────────────────────────────────────────


def _format_telegram_message(report: WeeklyReport, period: str = "weekly") -> str:
    now = datetime.now(timezone.utc)
    kst_hour = (now.hour + 9) % 24
    time_str = f"{now.strftime('%Y-%m-%d')} {kst_hour:02d}:{now.strftime('%M')} KST"

    emoji = _PERIOD_EMOJI.get(period, "\U0001f30d")
    period_kr = _PERIOD_KR.get(period, period)

    lines: list[str] = []

    # ── Header ──
    lines.append(f"{emoji} <b>VXIS Domain Intelligence \u2014 {period_kr} \ub9ac\ud3ec\ud2b8</b>")
    lines.append(f"\U0001f4c5 {time_str}")
    lines.append(
        f"\U0001f4ca \uc2dc\uadf8\ub110 {report.total_signals}\uac1c | "
        f"\ud2b8\ub80c\ub4dc {len(report.trends)}\uac1c | "
        f"CISA KEV {len(report.cisa_kev_alerts)}\uac1c"
    )
    lines.append("")

    # ── 소스별 시그널 ──
    if report.raw_signal_summary:
        lines.append("<b>\uc18c\uc2a4\ubcc4 \uc2dc\uadf8\ub110:</b>")
        for src, cnt in sorted(report.raw_signal_summary.items()):
            lines.append(f"  \u2022 {_esc(src)}: {cnt}\uac1c")
        lines.append("")

    # ── CISA KEV ──
    if report.cisa_kev_alerts:
        lines.append(f"\U0001f6a8 <b>CISA KEV \uc54c\ub9bc ({len(report.cisa_kev_alerts)}\uac1c)</b>")
        for alert in report.cisa_kev_alerts[:5]:
            meta = alert.get("metadata", {})
            cve_id = meta.get("cve_id", "")
            vendor = meta.get("vendor", "")
            product = meta.get("product", "")
            lines.append(f"  \u2022 <b>{_esc(cve_id)}</b> \u2014 {_esc(vendor)} {_esc(product)}")
        if len(report.cisa_kev_alerts) > 5:
            lines.append(f"  ... \uc678 {len(report.cisa_kev_alerts) - 5}\uac1c")
        lines.append("")

    # ── 트렌드 ──
    if report.trends:
        lines.append("\u2500" * 25)
        for i, t in enumerate(report.trends, 1):
            icon = {
                "critical": "\U0001f6a8",
                "high": "\U0001f536",
                "medium": "\U0001f4a1",
                "low": "\U0001f4cc",
            }.get(t.priority, "\u2022")
            priority_kr = {
                "critical": "\uce58\uba85\uc801",
                "high": "\ub192\uc74c",
                "medium": "\uc911\uac04",
                "low": "\ub0ae\uc74c",
            }.get(t.priority, t.priority)

            lines.append(f"{icon} <b>Trend {i}: {_esc(t.title)}</b>")
            lines.append(f"   \uc6b0\uc120\uc21c\uc704: {priority_kr}")
            lines.append(f"   {_esc(t.description)}")
            lines.append("")

            if t.vxis_impact:
                lines.append(f"   \U0001f3af <b>VXIS \uc601\ud5a5:</b> {_esc(t.vxis_impact)}")

            if t.recommendation:
                lines.append(f"   \u2705 <b>\ucd94\ucc9c:</b> {_esc(t.recommendation)}")

            if t.evidence:
                lines.append(f"   \U0001f4ce \uadfc\uac70: {_esc(', '.join(t.evidence[:3]))}")

            lines.append("")

        # ── 요약 ──
        lines.append("\u2500" * 25)
        lines.append("\U0001f4ca <b>\uc694\uc57d</b>")
        lines.append(f"  \u2022 \ud2b8\ub80c\ub4dc: {len(report.trends)}\uac1c")

        by_priority: dict[str, int] = {}
        for t in report.trends:
            by_priority[t.priority] = by_priority.get(t.priority, 0) + 1
        for p in ("critical", "high", "medium", "low"):
            if p in by_priority:
                lines.append(f"  \u2022 {p}: {by_priority[p]}\uac1c")

    else:
        lines.append(f"\u2705 {period_kr} \ud2b9\ubcc4\ud55c \ud2b8\ub80c\ub4dc \uc5c6\uc74c")

    return "\n".join(lines)


# ── 헬퍼 ─────────────────────────────────────────────────────────


def _esc(text: str) -> str:
    """Telegram HTML 이스케이프."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _send(token: str, chat_id: str, text: str) -> bool:
    """Telegram Bot API로 메시지 전송."""
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
    except Exception as e:
        logger.error("[Telegram] 전송 실패: %s", e)
        return False


def _split_message(text: str, max_len: int = 4000) -> list[str]:
    """텔레그램 4096자 제한에 맞게 분할."""
    if len(text) <= max_len:
        return [text]

    chunks: list[str] = []
    while text:
        if len(text) <= max_len:
            chunks.append(text)
            break
        split_at = text.rfind("\n", 0, max_len)
        if split_at == -1:
            split_at = max_len
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    return chunks
