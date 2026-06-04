"""Human ask BrainTool.

The tool is non-blocking by default. It only waits for an operator answer when
constructed with ``attended=True`` and called with ``blocking=True``.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from vxis.agent.ask.queue import AskQueue, AskQuestion, AskStatus, question_to_tool_data
from vxis.agent.tool_registry import ToolResult


class AskHumanTool:
    name = "ask_human"
    description = (
        "Ask an operator to resolve an ambiguous scan decision. Unattended scans "
        "immediately continue with default_when_skipped."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "question": {"type": "string"},
            "context_summary": {"type": "string"},
            "options": {"type": ["array", "null"], "items": {"type": "string"}},
            "default_when_skipped": {"type": "string"},
            "blocking": {"type": "boolean", "default": False},
            "scan_id": {"type": "string", "default": "default"},
            "iter": {"type": "integer", "default": 0},
            "timeout_seconds": {"type": "integer", "default": 0, "minimum": 0},
        },
        "required": ["question", "context_summary", "default_when_skipped"],
    }

    def __init__(
        self,
        *,
        queue: AskQueue | None = None,
        attended: bool = False,
        default_timeout_seconds: int = 60,
        poll_interval_seconds: float = 0.25,
    ) -> None:
        self.queue = queue or AskQueue()
        self.attended = attended
        self.default_timeout_seconds = max(0, int(default_timeout_seconds))
        self.poll_interval_seconds = max(0.01, float(poll_interval_seconds))

    async def run(self, **kwargs: Any) -> ToolResult:
        try:
            blocking = _as_bool(kwargs.get("blocking", False))
            scan_id = str(kwargs.get("scan_id") or "default")
            iter_value = _coerce_nonnegative_int(kwargs.get("iter"), default=0)
            timeout_seconds = _coerce_nonnegative_int(kwargs.get("timeout_seconds"), default=0)
            if blocking and self.attended and timeout_seconds == 0:
                timeout_seconds = self.default_timeout_seconds

            q = AskQuestion(
                scan_id=scan_id,
                iter=iter_value,
                context_summary=str(kwargs.get("context_summary") or "").strip(),
                question=str(kwargs.get("question") or "").strip(),
                options=_normalize_options(kwargs.get("options")),
                timeout_seconds=timeout_seconds if blocking and self.attended else 0,
                default_when_skipped=str(kwargs.get("default_when_skipped") or "").strip(),
            )
        except ValueError as exc:
            return ToolResult(ok=False, error="invalid_ask", summary=str(exc))

        q = self.queue.enqueue(q)
        if q.status != AskStatus.PENDING:
            return ToolResult(
                ok=True,
                data={
                    "question": question_to_tool_data(q),
                    "answer": q.answer,
                    "status": q.status.value,
                    "assumed_safe_default": True,
                    "cap_hit": q.cap_hit,
                },
                summary=f"ask_human used default answer: {q.answer}",
            )

        if not (blocking and self.attended):
            answer = self.queue.skip_with_default(q.question_id)
            stored = self.queue.get(q.question_id) or q
            return ToolResult(
                ok=True,
                data={
                    "question": question_to_tool_data(stored),
                    "answer": answer,
                    "status": AskStatus.SKIPPED.value,
                    "assumed_safe_default": True,
                    "blocking_denied": bool(blocking and not self.attended),
                },
                summary=f"ask_human skipped unattended question with default answer: {answer}",
            )

        if timeout_seconds <= 0:
            answer = self.queue.skip_with_default(q.question_id)
            stored = self.queue.get(q.question_id) or q
            return ToolResult(
                ok=True,
                data={
                    "question": question_to_tool_data(stored),
                    "answer": answer,
                    "status": AskStatus.SKIPPED.value,
                    "assumed_safe_default": True,
                },
                summary=f"ask_human skipped zero-timeout question with default answer: {answer}",
            )

        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            stored = self.queue.get(q.question_id)
            if stored is not None and stored.status == AskStatus.ANSWERED:
                return ToolResult(
                    ok=True,
                    data={
                        "question": question_to_tool_data(stored),
                        "answer": stored.answer,
                        "status": stored.status.value,
                        "assumed_safe_default": False,
                    },
                    summary=f"ask_human received operator answer: {stored.answer}",
                )
            await asyncio.sleep(
                min(self.poll_interval_seconds, max(0.0, deadline - time.monotonic()))
            )

        answer = self.queue.timeout(q.question_id)
        stored = self.queue.get(q.question_id) or q
        return ToolResult(
            ok=True,
            data={
                "question": question_to_tool_data(stored),
                "answer": answer,
                "status": AskStatus.TIMEOUT.value,
                "assumed_safe_default": True,
            },
            summary=f"ask_human timed out and used default answer: {answer}",
        )


def _normalize_options(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list | tuple):
        raise ValueError("options must be an array when provided")
    options = [str(item).strip() for item in value if str(item).strip()]
    return options or None


def _coerce_nonnegative_int(value: Any, *, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, parsed)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)
