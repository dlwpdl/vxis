from __future__ import annotations

from vxis.agent.critique.loop import (
    SelfCritique,
    compute_chain_depths,
    evaluate_coverage_gaps,
    find_untested_high_prior_hypotheses,
)


def test_self_critique_blocks_finish_for_coverage_and_high_prior_gaps() -> None:
    dag = {
        "nodes": [
            {
                "node_id": "n1",
                "claim": "IDOR may expose invoices",
                "prior": 0.91,
                "status": "pending",
            },
            {"node_id": "n2", "claim": "Reflected XSS", "prior": 0.4, "status": "pending"},
            {"node_id": "n3", "claim": "SQLi on login", "prior": 0.8, "status": "refuted"},
        ]
    }
    matrix = {
        "surfaces": [
            {"surface_id": "s1", "status": "tested", "high_value": True},
            {"surface_id": "s2", "status": "untested", "high_value": True},
            {"surface_id": "s3", "status": "untested", "high_value": False},
        ]
    }

    report = SelfCritique(coverage_threshold=80, high_value_coverage_threshold=80).run(
        dag=dag,
        matrix=matrix,
        findings=[],
        pti=None,
    )

    assert report.finish_allowed is False
    assert report.coverage_pct == 33.33333333333333
    assert report.high_value_surface_coverage == 50.0
    assert report.untested_high_prior_hypotheses == ["IDOR may expose invoices"]
    assert any("Overall coverage below threshold" in gap for gap in report.gaps)
    assert any("High-prior hypotheses remain untested" in gap for gap in report.gaps)
    assert any(
        proposal.claim == "Complete testing for high-prior hypothesis: IDOR may expose invoices"
        for proposal in report.new_hypotheses_proposed
    )


def test_self_critique_allows_finish_when_no_deterministic_gaps_exist() -> None:
    dag = {
        "nodes": [
            {
                "node_id": "n1",
                "claim": "IDOR may expose invoices",
                "prior": 0.91,
                "status": "confirmed",
            },
            {"node_id": "n2", "claim": "Reflected XSS", "prior": 0.74, "status": "refuted"},
        ]
    }
    matrix = {"coverage_pct": 0.95, "high_value_surface_coverage": 1.0}
    findings = [{"title": "Confirmed IDOR", "severity": "high", "status": "confirmed"}]
    pti = {"defenses": [{"kind": "waf-signature", "bypasses_known": ["browser-review"]}]}

    report = SelfCritique().run(dag=dag, matrix=matrix, findings=findings, pti=pti)

    assert report.finish_allowed is True
    assert report.coverage_pct == 95.0
    assert report.high_value_surface_coverage == 100.0
    assert report.gaps == []
    assert report.new_hypotheses_proposed == []


def test_helper_functions_are_deterministic() -> None:
    dag = {
        "nodes": {
            "a": {"node_id": "a", "claim": "root", "prior": 0.9, "status": "confirmed"},
            "b": {
                "node_id": "b",
                "claim": "child remains pending",
                "prior": 0.8,
                "status": "testing",
                "parent_ids": ["a"],
            },
            "c": {
                "node_id": "c",
                "claim": "grandchild",
                "prior": 0.2,
                "status": "pending",
                "parent_ids": ["b"],
            },
        }
    }

    assert find_untested_high_prior_hypotheses(dag) == ["child remains pending"]
    assert compute_chain_depths(dag) == (3, 2.0)
    assert evaluate_coverage_gaps(
        coverage_pct=79.9,
        high_value_surface_coverage=100,
        coverage_threshold=80,
        high_value_coverage_threshold=80,
    ) == ["Overall coverage below threshold: 79.9% < 80.0%."]


def test_pti_defense_without_follow_up_path_creates_gap() -> None:
    report = SelfCritique().run(
        dag={"nodes": []},
        matrix={"coverage_pct": 100, "high_value_surface_coverage": 100},
        findings=[],
        pti={"defenses": [{"kind": "cloudflare", "bypasses_known": []}]},
    )

    assert report.finish_allowed is False
    assert report.gaps == ["Known defense has no recorded safe follow-up path: cloudflare."]
    assert report.new_hypotheses_proposed[0].decision_class == "verify"
