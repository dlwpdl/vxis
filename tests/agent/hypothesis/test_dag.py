from __future__ import annotations

import pytest

from vxis.agent.hypothesis.bayes import bayes_update
from vxis.agent.hypothesis.dag import HypothesisNode, HypothesisDAG, DecisionClass


# Canonical set — if this list ever changes, update all import sites.
_CANONICAL_DECISION_CLASSES = frozenset(
    {"recon", "triage", "strategy", "exploit", "verify", "critique"}
)


def test_decision_class_canonical_set_is_complete() -> None:
    """DecisionClass Literal in dag.py must contain all 6 canonical members.

    Divergent definitions cause validation errors when 'triage' or 'critique'
    hypotheses are created via critique/loop.py or pti/models.py and later
    round-tripped through HypothesisNode.model_validate.
    """
    # Verify all canonical values are accepted by HypothesisNode without error
    for dc in _CANONICAL_DECISION_CLASSES:
        node = HypothesisNode(
            node_id=f"test-{dc}",
            claim=f"test claim for {dc}",
            decision_class=dc,  # type: ignore[arg-type]
            prior=0.5,
        )
        assert node.decision_class == dc, (
            f"decision_class {dc!r} not accepted by HypothesisNode — "
            "dag.py DecisionClass is missing this member."
        )

    # All 3 DecisionClass Literals must agree on the same set
    from vxis.agent.critique.loop import DecisionClass as CritiqueDecisionClass
    from vxis.pti.models import DecisionClass as PTIDecisionClass

    dag_args = set(DecisionClass.__args__)  # type: ignore[attr-defined]
    critique_args = set(CritiqueDecisionClass.__args__)  # type: ignore[attr-defined]
    pti_args = set(PTIDecisionClass.__args__)  # type: ignore[attr-defined]

    assert dag_args == _CANONICAL_DECISION_CLASSES, (
        f"dag.py DecisionClass diverges: {dag_args!r} vs canonical {_CANONICAL_DECISION_CLASSES!r}"
    )
    assert critique_args == dag_args, (
        f"critique/loop.py DecisionClass diverges: {critique_args!r} vs dag.py {dag_args!r}"
    )
    assert pti_args == dag_args, (
        f"pti/models.py DecisionClass diverges: {pti_args!r} vs dag.py {dag_args!r}"
    )


def hypothesis(
    node_id: str,
    *,
    claim: str | None = None,
    prior: float = 0.5,
    status: str = "untested",
    vector: str = "sql_injection",
) -> HypothesisNode:
    return HypothesisNode(
        node_id=node_id,
        claim=claim or f"{node_id} claim",
        decision_class="exploit",
        prior=prior,
        status=status,
        proposed_vector_class=vector,
        created_iter=1,
        last_updated_iter=1,
    )


def test_add_links_roots_parent_and_child_ids() -> None:
    dag = HypothesisDAG()

    dag.add(hypothesis("root", prior=0.7))
    dag.add(hypothesis("child", prior=0.4), parent_ids=["root"])

    assert dag.roots == ["root"]
    assert dag.nodes["root"].child_ids == ["child"]
    assert dag.nodes["child"].parent_ids == ["root"]

    with pytest.raises(ValueError, match="already exists"):
        dag.add(hypothesis("child"))


def test_update_belief_records_evidence_sets_status_and_propagates_to_children() -> None:
    dag = HypothesisDAG()
    dag.add(hypothesis("root", prior=0.5))
    dag.add(hypothesis("child", prior=0.4), parent_ids=["root"])

    dag.update_belief(
        "root",
        evidence="500 response only for SQL quote payload",
        delta=1.2,
        status_change="confirmed",
        iteration=7,
    )

    root = dag.nodes["root"]
    child = dag.nodes["child"]
    assert root.status == "confirmed"
    assert root.prior >= 0.95
    assert root.evidence == ["500 response only for SQL quote payload"]
    assert root.last_updated_iter == 7
    assert child.prior > 0.4
    assert child.status == "untested"
    assert child.last_updated_iter == 7


def test_refutation_penalizes_descendants_without_marking_them_final() -> None:
    dag = HypothesisDAG()
    dag.add(hypothesis("root", prior=0.8))
    dag.add(hypothesis("child", prior=0.7), parent_ids=["root"])
    dag.add(hypothesis("grandchild", prior=0.7), parent_ids=["child"])

    dag.update_belief(
        "root",
        evidence="control and payload responses were identical",
        delta=-1.5,
        status_change="refuted",
        iteration=3,
    )

    assert dag.nodes["root"].status == "refuted"
    assert dag.nodes["root"].prior <= 0.05
    assert dag.nodes["child"].prior < 0.7
    assert dag.nodes["grandchild"].prior < 0.7
    assert dag.nodes["child"].status == "untested"
    assert dag.nodes["grandchild"].status == "untested"


def test_prune_dead_removes_low_prior_nodes_and_cleans_links() -> None:
    dag = HypothesisDAG()
    dag.add(hypothesis("root", prior=0.8))
    dag.add(hypothesis("dead", prior=0.03), parent_ids=["root"])
    dag.add(hypothesis("orphaned", prior=0.4), parent_ids=["dead"])
    dag.add(hypothesis("confirmed_low", prior=0.01, status="confirmed"))

    pruned = dag.prune_dead(threshold=0.05)

    assert pruned == 1
    assert "dead" not in dag.nodes
    assert "dead" not in dag.nodes["root"].child_ids
    assert dag.nodes["orphaned"].parent_ids == []
    assert set(dag.roots) == {"root", "orphaned", "confirmed_low"}
    assert "confirmed_low" in dag.nodes


def test_top_untested_orders_by_prior_and_skips_other_statuses() -> None:
    dag = HypothesisDAG()
    dag.add(hypothesis("medium", prior=0.5))
    dag.add(hypothesis("confirmed", prior=0.95, status="confirmed"))
    dag.add(hypothesis("testing", prior=0.9, status="testing"))
    dag.add(hypothesis("high", prior=0.8))
    dag.add(hypothesis("low", prior=0.2))

    assert [node.node_id for node in dag.top_untested(k=2)] == ["high", "medium"]


def test_to_summary_includes_counts_and_respects_budget() -> None:
    dag = HypothesisDAG()
    dag.add(hypothesis("root", prior=0.7, vector="idor"))
    dag.add(hypothesis("done", prior=0.95, status="confirmed", vector="xss"))

    summary = dag.to_summary(token_budget=24)

    assert "HypothesisNode DAG" in summary
    assert "untested=1" in summary
    assert len(summary) <= 99


def test_bayes_update_is_monotonic() -> None:
    prior = 0.5

    assert bayes_update(prior, 1.0) > prior
    assert bayes_update(prior, -1.0) < prior
    assert bayes_update(prior, 0.0) == pytest.approx(prior)
