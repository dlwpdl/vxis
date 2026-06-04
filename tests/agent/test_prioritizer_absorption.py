from __future__ import annotations

from vxis.agent.scan_loop_state import ScanLoopState


def test_vector_candidate_seeds_dag_node() -> None:
    state = ScanLoopState(target="http://example.com")

    state.ensure_vector_candidate(
        "web:sqli",
        "WEB-SQLI-001",
        "SQL injection toward DB/admin data",
        priority=95,
        evidence="seeded from test",
    )

    assert state.hypothesis_dag is not None
    node = state.hypothesis_dag.nodes["web:sqli"]
    assert node.proposed_vector_class == "sqli"
    assert node.status == "untested"
    assert node.prior == 0.95


def test_candidate_outcome_updates_dag_node_status() -> None:
    state = ScanLoopState(target="http://example.com")
    state.ensure_vector_candidate("web:xss", "WEB-XSS-001", "XSS", priority=70)

    state.record_attempt_outcome(
        "web:xss",
        "run_skill",
        {"skill": "test_xss"},
        status="found",
        summary="confirmed reflected xss",
    )

    assert state.hypothesis_dag.nodes["web:xss"].status == "confirmed"
