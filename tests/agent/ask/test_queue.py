from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vxis.agent.ask.queue import AskQueue, AskQuestion, AskStatus


def test_queue_enqueue_answer_skip_and_timeout_transitions() -> None:
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    queue = AskQueue(now=lambda: now)
    q1 = queue.enqueue(
        AskQuestion(
            question_id="q1",
            scan_id="scan-1",
            iter=3,
            context_summary="Observed admin export",
            question="Is export intended?",
            options=["intended", "vulnerable"],
            default_when_skipped="intended",
        )
    )
    queue.enqueue(
        AskQuestion(
            question_id="q2",
            scan_id="scan-1",
            context_summary="Observed optional setting",
            question="Should this be enabled?",
            default_when_skipped="safe",
        )
    )
    q3 = queue.enqueue(
        AskQuestion(
            question_id="q3",
            scan_id="scan-1",
            context_summary="Needs operator answer",
            question="Wait?",
            timeout_seconds=10,
            default_when_skipped="safe",
            created_at=now - timedelta(seconds=11),
        )
    )

    assert q1.status == AskStatus.PENDING
    assert [q.question_id for q in queue.pending("scan-1")] == ["q1", "q2"]
    assert q3.status == AskStatus.TIMEOUT
    assert q3.answer == "safe"

    answered = queue.answer("q1", "vulnerable", by="operator@example.com")
    assert answered.status == AskStatus.ANSWERED
    assert answered.answer == "vulnerable"
    assert answered.answered_by == "operator@example.com"

    default = queue.skip_with_default("q2")
    assert default == "safe"
    assert queue.get("q2").status == AskStatus.SKIPPED  # type: ignore[union-attr]

    with pytest.raises(ValueError):
        queue.answer("q2", "unsafe", by="operator")


def test_queue_validates_default_and_answer_options() -> None:
    with pytest.raises(ValueError, match="default_when_skipped"):
        AskQuestion(
            scan_id="scan-1",
            context_summary="ctx",
            question="Pick",
            options=["yes", "no"],
            default_when_skipped="maybe",
        )

    queue = AskQueue()
    queue.enqueue(
        AskQuestion(
            question_id="q1",
            scan_id="scan-1",
            context_summary="ctx",
            question="Pick",
            options=["yes", "no"],
            default_when_skipped="no",
        )
    )
    with pytest.raises(ValueError, match="answer must be one"):
        queue.answer("q1", "maybe", by="operator")


def test_queue_persists_to_sqlite(tmp_path) -> None:
    db_path = tmp_path / "asks.sqlite"
    queue = AskQueue(sqlite_path=db_path)
    queue.enqueue(
        AskQuestion(
            question_id="q1",
            scan_id="scan-1",
            context_summary="ctx",
            question="Question?",
            default_when_skipped="safe",
        )
    )
    queue.answer("q1", "unsafe", by="operator")

    loaded = AskQueue(sqlite_path=db_path)
    q = loaded.get("q1")

    assert q is not None
    assert q.status == AskStatus.ANSWERED
    assert q.answer == "unsafe"
    assert q.answered_by == "operator"


def test_queue_cap_forces_skip_with_default() -> None:
    queue = AskQueue(max_questions_per_scan=1)
    queue.enqueue(
        AskQuestion(
            question_id="q1",
            scan_id="scan-1",
            context_summary="ctx",
            question="Question?",
            default_when_skipped="safe",
        )
    )

    capped = queue.enqueue(
        AskQuestion(
            question_id="q2",
            scan_id="scan-1",
            context_summary="ctx",
            question="Question?",
            default_when_skipped="safe",
        )
    )

    assert capped.status == AskStatus.SKIPPED
    assert capped.answer == "safe"
    assert capped.cap_hit is True
    assert [q.question_id for q in queue.pending("scan-1")] == ["q1"]
