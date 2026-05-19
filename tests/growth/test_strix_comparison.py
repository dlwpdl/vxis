from __future__ import annotations

from vxis.growth.strix_comparison import build_strix_comparison_scorecard


def test_build_strix_comparison_scorecard_produces_dimension_scores() -> None:
    scorecard = build_strix_comparison_scorecard(
        findings=[
            {
                "finding_type": "sql_injection",
                "severity": "critical",
                "title": "SQLI on q",
                "technical_analysis": "Control pair recorded.",
                "poc_description": "Replay payload and compare response.",
                "poc_script_code": "curl ...",
                "evidence": "GET /search?q=' ...",
            },
            {
                "finding_type": "idor",
                "severity": "high",
                "title": "IDOR on users API",
                "technical_analysis": "Per-object comparisons recorded.",
                "poc_description": "Replay object access across IDs.",
                "poc_script_code": "curl .../users/2",
                "evidence": "GET /users/2 ...",
            },
        ],
        loop_result={
            "completed": False,
            "verdict_counts": {"CONFIRMED": 2, "UNCONFIRMED": 0, "REFUTED": 0},
            "review_queue": [],
            "review_history": [{"stage": "verifier"}],
            "branches": [{"id": "b1", "status": "open"}],
        },
        attack_chains=[
            {"raw": {"crown_jewel": "authenticated data exfiltration"}},
        ],
        llm_usage={"llm_calls": 4, "brain_decisions": 4},
        control_plane={
            "focus_branch": {"id": "web:sqli"},
            "focus_campaign": {"family": "injection"},
            "campaign_groups": [{"family": "injection"}],
            "blocking_branches": [{"id": "web:sqli"}],
            "chain_candidates": [{"source_id": "VXIS-1", "target_id": "VXIS-2"}],
        },
    )
    assert scorecard["reference"] == "strix"
    assert scorecard["overall_vxis"] > 0
    assert set(scorecard["dimensions"]) == {
        "poc_rigor",
        "chaining_depth",
        "campaign_convergence",
        "autonomy",
        "operator_visibility",
    }
    assert scorecard["dimensions"]["operator_visibility"]["vxis"] > 0
