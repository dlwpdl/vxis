"""Human-in-the-loop ask queue.

The queue is safe for unattended scans: callers can enqueue questions, then
explicitly skip or timeout them to continue with deterministic defaults. The
queue itself does not block or wait.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, Field, model_validator


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AskStatus(StrEnum):
    PENDING = "pending"
    ANSWERED = "answered"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


class AskQuestion(BaseModel):
    question_id: str = Field(default_factory=lambda: f"ask_{uuid.uuid4().hex[:12]}")
    scan_id: str
    iter: int = Field(default=0, ge=0)
    context_summary: str
    question: str
    options: list[str] | None = None
    timeout_seconds: int = Field(default=0, ge=0)
    default_when_skipped: str
    status: AskStatus = AskStatus.PENDING
    answer: str | None = None
    answered_at: datetime | None = None
    answered_by: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    timed_out_at: datetime | None = None
    cap_hit: bool = False

    @model_validator(mode="after")
    def _validate_options(self) -> "AskQuestion":
        if self.options is not None:
            normalized = [str(option) for option in self.options]
            self.options = normalized
            if self.default_when_skipped not in normalized:
                raise ValueError("default_when_skipped must be one of options")
            if self.answer is not None and self.answer not in normalized:
                raise ValueError("answer must be one of options")
        if self.status in {AskStatus.ANSWERED, AskStatus.SKIPPED, AskStatus.TIMEOUT}:
            if self.answer is None:
                raise ValueError("terminal ask status requires answer")
            if self.answered_at is None:
                self.answered_at = _utcnow()
        return self


class AskQueue:
    """In-memory queue with optional SQLite persistence."""

    def __init__(
        self,
        sqlite_path: str | Path | None = None,
        *,
        max_questions_per_scan: int = 10,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.sqlite_path = Path(sqlite_path) if sqlite_path is not None else None
        self.max_questions_per_scan = max(1, int(max_questions_per_scan))
        self._now = now or _utcnow
        self._questions: dict[str, AskQuestion] = {}
        if self.sqlite_path is not None:
            self._init_db()
            self._load_db()

    def enqueue(self, q: AskQuestion) -> AskQuestion:
        if q.question_id in self._questions:
            raise ValueError(f"ask question already exists: {q.question_id}")
        if self._scan_question_count(q.scan_id) >= self.max_questions_per_scan:
            q.status = AskStatus.SKIPPED
            q.answer = q.default_when_skipped
            q.answered_at = self._now()
            q.answered_by = "system:cap"
            q.cap_hit = True
        self._questions[q.question_id] = q
        self._persist(q)
        return q

    def pending(self, scan_id: str) -> list[AskQuestion]:
        self.expire_timeouts(scan_id=scan_id)
        return [
            q
            for q in self._questions.values()
            if q.scan_id == scan_id and q.status == AskStatus.PENDING
        ]

    def answer(self, question_id: str, answer: str, by: str) -> AskQuestion:
        q = self._require_pending(question_id)
        if q.options is not None and answer not in q.options:
            raise ValueError("answer must be one of question options")
        q.status = AskStatus.ANSWERED
        q.answer = answer
        q.answered_at = self._now()
        q.answered_by = str(by)
        self._persist(q)
        return q

    def skip_with_default(self, question_id: str) -> str:
        q = self._require_pending(question_id)
        q.status = AskStatus.SKIPPED
        q.answer = q.default_when_skipped
        q.answered_at = self._now()
        q.answered_by = "system:default"
        self._persist(q)
        return q.answer

    def timeout(self, question_id: str) -> str:
        q = self._require_pending(question_id)
        q.status = AskStatus.TIMEOUT
        q.answer = q.default_when_skipped
        now = self._now()
        q.answered_at = now
        q.timed_out_at = now
        q.answered_by = "system:timeout"
        self._persist(q)
        return q.answer

    def expire_timeouts(
        self,
        *,
        scan_id: str | None = None,
        now: datetime | None = None,
    ) -> list[AskQuestion]:
        current = now or self._now()
        expired: list[AskQuestion] = []
        for q in list(self._questions.values()):
            if scan_id is not None and q.scan_id != scan_id:
                continue
            if q.status != AskStatus.PENDING or q.timeout_seconds <= 0:
                continue
            if q.created_at + timedelta(seconds=q.timeout_seconds) <= current:
                self.timeout(q.question_id)
                expired.append(self._questions[q.question_id])
        return expired

    def get(self, question_id: str) -> AskQuestion | None:
        return self._questions.get(question_id)

    def all(self, scan_id: str | None = None) -> list[AskQuestion]:
        self.expire_timeouts(scan_id=scan_id)
        if scan_id is None:
            return list(self._questions.values())
        return [q for q in self._questions.values() if q.scan_id == scan_id]

    def _scan_question_count(self, scan_id: str) -> int:
        return sum(1 for q in self._questions.values() if q.scan_id == scan_id)

    def _require_pending(self, question_id: str) -> AskQuestion:
        q = self._questions.get(question_id)
        if q is None:
            raise KeyError(f"ask question not found: {question_id}")
        if q.status != AskStatus.PENDING:
            raise ValueError(f"ask question is not pending: {question_id}")
        return q

    def _init_db(self) -> None:
        assert self.sqlite_path is not None
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.sqlite_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ask_questions (
                    question_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ask_questions_scan_status "
                "ON ask_questions(scan_id, status)"
            )

    def _load_db(self) -> None:
        assert self.sqlite_path is not None
        with sqlite3.connect(self.sqlite_path) as conn:
            for (payload,) in conn.execute("SELECT payload FROM ask_questions"):
                q = AskQuestion.model_validate_json(payload)
                self._questions[q.question_id] = q

    def _persist(self, q: AskQuestion) -> None:
        if self.sqlite_path is None:
            return
        with sqlite3.connect(self.sqlite_path) as conn:
            conn.execute(
                """
                INSERT INTO ask_questions(question_id, scan_id, status, payload)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(question_id) DO UPDATE SET
                    scan_id=excluded.scan_id,
                    status=excluded.status,
                    payload=excluded.payload
                """,
                (
                    q.question_id,
                    q.scan_id,
                    q.status.value,
                    q.model_dump_json(),
                ),
            )


def question_to_tool_data(q: AskQuestion) -> dict[str, Any]:
    return q.model_dump(mode="json")
