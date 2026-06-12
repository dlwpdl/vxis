from __future__ import annotations

from vxis.agent.scan_loop_state import ScanLoopState


def test_attempt_outcomes_are_bounded() -> None:
    state = ScanLoopState(target="http://example.com")
    state.ensure_vector_candidate("c1", "web:sqli", "SQLi probe")

    for i in range(500):
        state.record_attempt_outcome(
            "c1", "http_request", {"i": i}, status="clean", summary=f"try {i}"
        )

    # Unbounded growth over a long scan bloats every snapshot/serialization.
    assert len(state.attempt_outcomes) <= 200
    # The most recent attempts must survive the cap.
    assert state.attempt_outcomes[-1].summary == "try 499"
    # The recent-attempt slice consumers rely on still works.
    assert state.attempt_outcomes_as_dicts()[-1]["summary"] == "try 499"


def test_review_history_is_bounded() -> None:
    state = ScanLoopState(target="http://example.com")

    for i in range(500):
        state.record_review_decision(
            stage="triage",
            verdict="accept",
            title=f"finding {i}",
            reason="ok",
        )

    assert len(state.review_history) <= 200
    assert state.review_history_as_dicts()[-1]["title"] == "finding 499"
