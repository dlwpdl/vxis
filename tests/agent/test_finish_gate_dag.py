from __future__ import annotations

from vxis.agent.scan_loop_decision_policy import dag_blocks_finish
from vxis.agent.scan_loop_state import ScanLoopState


def test_finish_blocked_by_untested_high_prior_dag_node() -> None:
    state = ScanLoopState(target="http://example.com")
    state.ensure_vector_candidate(
        "admin-auth",
        "WEB-AUTH-001",
        "Authentication bypass or weak login",
        priority=95,
    )

    assert state.hypothesis_dag.top_untested(k=1)[0].prior >= 0.5
    assert dag_blocks_finish(state) is True


def test_finish_not_blocked_after_high_prior_node_confirmed() -> None:
    state = ScanLoopState(target="http://example.com")
    state.ensure_vector_candidate("admin-auth", "WEB-AUTH-001", "Authentication bypass", priority=95)
    state.record_attempt_outcome(
        "admin-auth",
        "run_skill",
        {"skill": "attempt_auth"},
        status="found",
        summary="confirmed",
    )

    assert dag_blocks_finish(state) is False
