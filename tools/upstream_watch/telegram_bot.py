"""
Upstream Watch — Telegram 인터랙티브 봇.

Proposal을 인라인 버튼(승인/거절/보류)과 함께 전송하고,
버튼 클릭 + 답장 코멘트를 수집하여 decisions.json에 기록.

Architecture:
    1. send_proposals_with_buttons() — 각 proposal을 개별 메시지로 전송 (인라인 키보드 포함)
    2. poll_decisions() — getUpdates로 버튼 콜백 + 답장 수집 → 결정 기록

Env vars:
    TELEGRAM_BOT_TOKEN  — Bot token from @BotFather
    TELEGRAM_CHAT_ID    — Target chat ID
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path

from .adoption import (
    DecisionStatus,
    Proposal,
    ProposalSet,
    record_decision,
)

logger = logging.getLogger(__name__)

_STATE_FILE = Path("tools/upstream_watch/.telegram_state.json")


def _tg_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _tg_api(token: str, method: str, payload: dict | None = None, timeout: int = 15) -> dict:
    """Call Telegram Bot API and return parsed JSON response."""
    url = f"https://api.telegram.org/bot{token}/{method}"

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
    else:
        req = urllib.request.Request(url, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:300]
        logger.warning("Telegram API %s error %d: %s", method, e.code, body)
        return {"ok": False, "error": body}
    except Exception as e:
        logger.warning("Telegram API %s failed: %s", method, e)
        return {"ok": False, "error": str(e)}


def _load_state() -> dict:
    if _STATE_FILE.exists():
        return json.loads(_STATE_FILE.read_text())
    return {"last_update_id": 0, "pending_proposals": {}}


def _save_state(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))


def _category_kr(cat: str) -> str:
    return {
        "architecture": "아키텍처", "plugin": "플러그인", "report": "리포트",
        "pipeline": "파이프라인", "tool-integration": "툴 통합",
        "performance": "성능", "security": "보안",
    }.get(cat, cat)


def _priority_kr(p: str) -> str:
    return {"high": "높음", "medium": "중간", "low": "낮음"}.get(p.lower(), p)


def _priority_icon(p: str) -> str:
    return {"high": "\ud83d\udea8", "medium": "\u26a0\ufe0f", "low": "\ud83d\udca1"}.get(p.lower(), "\u2022")


def _overlap_kr(verdict: str) -> str:
    return {
        "new": "\ud83c\udd95 신규 기능",
        "enhancement": "\ud83d\udd27 기존 기능 강화",
        "already_exists": "\u274c 이미 존재",
        "partial_overlap": "\ud83d\udfe1 부분 겹침",
    }.get(verdict, verdict)


# ── Send proposals with inline buttons ──────────────────────────


def send_proposals_with_buttons(proposal_set: ProposalSet) -> int:
    """Send each proposal as a Telegram message with approve/reject/defer buttons.

    Returns the number of successfully sent proposals.
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return 0

    state = _load_state()
    sent_count = 0

    for proposal in proposal_set.proposals:
        # Format proposal message
        icon = _priority_icon(proposal.priority)
        cat = _category_kr(proposal.category)
        prio = _priority_kr(proposal.priority)
        overlap = _overlap_kr(proposal.overlap_verdict)

        text_lines = [
            f"{icon} <b>새 제안: {_tg_escape(proposal.title)}</b>",
            "",
            f"\ud83c\udff7 분류: {cat} | 우선순위: {prio}",
            f"\ud83d\udd17 출처: <code>{_tg_escape(proposal.source_repo)}</code>",
            f"\ud83d\udd00 중복 분석: {overlap} ({int(proposal.overlap_score * 100)}%)",
            "",
            f"\ud83d\udcdd <b>설명</b>",
            _tg_escape(proposal.description[:500]),
            "",
        ]

        if proposal.vxis_files:
            files = ", ".join(proposal.vxis_files[:4])
            text_lines.append(f"\ud83d\udcc2 영향 파일: <code>{_tg_escape(files)}</code>")

        if proposal.overlap_details:
            text_lines.append(f"\n\ud83d\udcca {_tg_escape(proposal.overlap_details[:200])}")

        text_lines.extend([
            "",
            f"<code>ID: {proposal.id}</code>",
            "",
            "\u2b07\ufe0f <b>결정을 선택하세요:</b>",
            "<i>\uc774 \uba54\uc2dc\uc9c0\uc5d0 \ub2f5\uc7a5\uc73c\ub85c \ucd94\uac00 \uc758\uacac\uc744 \ub0a8\uae38 \uc218 \uc788\uc2b5\ub2c8\ub2e4</i>",
        ])

        text = "\n".join(text_lines)

        # Inline keyboard: approve / reject / defer
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "\u2705 \uc2b9\uc778", "callback_data": f"approve:{proposal.id}"},
                    {"text": "\u274c \uac70\uc808", "callback_data": f"reject:{proposal.id}"},
                    {"text": "\u23f3 \ubcf4\ub958", "callback_data": f"defer:{proposal.id}"},
                ]
            ]
        }

        result = _tg_api(token, "sendMessage", {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            "reply_markup": keyboard,
        })

        if result.get("ok"):
            msg_id = result["result"]["message_id"]
            state["pending_proposals"][proposal.id] = {
                "message_id": msg_id,
                "title": proposal.title,
                "sent_at": proposal.proposed_at,
            }
            sent_count += 1
        else:
            logger.warning("Failed to send proposal %s: %s", proposal.id, result)

    _save_state(state)
    return sent_count


# ── Poll for button clicks and replies ──────────────────────────


@dataclass
class TelegramDecision:
    """A decision collected from Telegram interaction."""
    proposal_id: str
    action: str  # approved, rejected, deferred
    reason: str  # from reply message, or empty
    user: str  # telegram username


def poll_decisions() -> list[TelegramDecision]:
    """Check Telegram for button callbacks and reply comments.

    Flow:
    1. Call getUpdates with offset = last_update_id + 1
    2. For callback_query: extract action + proposal_id, answer the callback
    3. For reply messages to proposal messages: extract comment text
    4. Record decisions and return list

    Should be called periodically (e.g., each CI run).
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not token:
        return []

    state = _load_state()
    offset = state.get("last_update_id", 0) + 1
    pending = state.get("pending_proposals", {})

    # Reverse lookup: message_id → proposal_id
    msg_to_proposal = {
        info["message_id"]: pid
        for pid, info in pending.items()
    }

    result = _tg_api(token, "getUpdates", {
        "offset": offset,
        "timeout": 5,
        "allowed_updates": ["callback_query", "message"],
    })

    if not result.get("ok"):
        return []

    updates = result.get("result", [])
    if not updates:
        return []

    decisions: list[TelegramDecision] = []
    # Temporary store: proposal_id → {action, reasons}
    collected: dict[str, dict] = {}

    for update in updates:
        update_id = update["update_id"]
        state["last_update_id"] = max(state.get("last_update_id", 0), update_id)

        # Handle button callback
        if "callback_query" in update:
            cb = update["callback_query"]
            data = cb.get("data", "")
            user = cb.get("from", {}).get("username", cb.get("from", {}).get("first_name", "unknown"))

            if ":" in data:
                action, proposal_id = data.split(":", 1)
                action_map = {"approve": "approved", "reject": "rejected", "defer": "deferred"}
                status = action_map.get(action)

                if status and proposal_id in pending:
                    collected.setdefault(proposal_id, {"action": status, "reasons": [], "user": user})
                    collected[proposal_id]["action"] = status
                    collected[proposal_id]["user"] = user

                    # Answer callback (removes loading spinner)
                    status_kr = {"approved": "\u2705 \uc2b9\uc778\ub428", "rejected": "\u274c \uac70\uc808\ub428", "deferred": "\u23f3 \ubcf4\ub958\ub428"}
                    _tg_api(token, "answerCallbackQuery", {
                        "callback_query_id": cb["id"],
                        "text": f"{status_kr.get(status, status)} — 답장으로 추가 의견을 남길 수 있습니다",
                    })

                    # Update message to show decision
                    msg = cb.get("message", {})
                    chat_id = msg.get("chat", {}).get("id")
                    msg_id = msg.get("message_id")
                    title = pending[proposal_id].get("title", proposal_id)

                    if chat_id and msg_id:
                        _tg_api(token, "editMessageReplyMarkup", {
                            "chat_id": chat_id,
                            "message_id": msg_id,
                            "reply_markup": {"inline_keyboard": [
                                [{"text": f"{status_kr.get(status, status)}", "callback_data": "done"}]
                            ]},
                        })

        # Handle reply messages (comments on proposals)
        elif "message" in update:
            msg = update["message"]
            reply_to = msg.get("reply_to_message", {})
            reply_msg_id = reply_to.get("message_id")
            text = msg.get("text", "").strip()
            user = msg.get("from", {}).get("username", msg.get("from", {}).get("first_name", "unknown"))

            if reply_msg_id and reply_msg_id in msg_to_proposal and text:
                proposal_id = msg_to_proposal[reply_msg_id]
                collected.setdefault(proposal_id, {"action": "", "reasons": [], "user": user})
                collected[proposal_id]["reasons"].append(text)
                collected[proposal_id]["user"] = user

    # Process collected decisions
    for proposal_id, info in collected.items():
        action = info["action"]
        reasons = info["reasons"]
        user = info["user"]
        reason_text = " | ".join(reasons) if reasons else ""

        if action:
            # Record in decisions.json
            try:
                status = DecisionStatus(action)
                full_reason = f"[Telegram @{user}] {reason_text}" if reason_text else f"[Telegram @{user}]"
                record_decision(proposal_id, status, full_reason)

                decisions.append(TelegramDecision(
                    proposal_id=proposal_id,
                    action=action,
                    reason=reason_text,
                    user=user,
                ))

                # Remove from pending
                pending.pop(proposal_id, None)

            except (ValueError, KeyError) as e:
                logger.warning("Failed to record decision for %s: %s", proposal_id, e)

        elif reasons:
            # Comment without button press — store as note
            logger.info(
                "Comment on %s from @%s: %s (no button pressed yet)",
                proposal_id, user, reason_text,
            )

    _save_state(state)
    return decisions


def send_decision_summary(decisions: list[TelegramDecision]) -> bool:
    """Send a summary of processed decisions back to Telegram."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id or not decisions:
        return False

    status_icon = {"approved": "\u2705", "rejected": "\u274c", "deferred": "\u23f3"}

    lines = ["\ud83d\udcdd <b>결정 처리 완료</b>", ""]
    for d in decisions:
        icon = status_icon.get(d.action, "\u2022")
        action_kr = {"approved": "승인", "rejected": "거절", "deferred": "보류"}.get(d.action, d.action)
        lines.append(f"{icon} <b>{_tg_escape(d.proposal_id)}</b> → {action_kr}")
        if d.reason:
            lines.append(f"   \ud83d\udcac {_tg_escape(d.reason)}")

    text = "\n".join(lines)
    result = _tg_api(token, "sendMessage", {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    })
    return result.get("ok", False)
