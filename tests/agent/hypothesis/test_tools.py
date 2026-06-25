from __future__ import annotations

import pytest

from vxis.agent.hypothesis.dag import HypothesisNode, HypothesisDAG
from vxis.agent.scan_loop_state import ScanLoopState
from vxis.agent.tool_registry import BrainTool
from vxis.agent.tools.hypothesis_tools import (
    AddChildHypothesisTool,
    GenerateHypothesesTool,
    PrioritizeHypothesisTool,
    QueryDAGTool,
    UpdateHypothesisTool,
    build_hypothesis_tools,
)


def root_hypothesis(node_id: str = "root") -> HypothesisNode:
    return HypothesisNode(
        node_id=node_id,
        claim="Search endpoint may be SQL injectable",
        decision_class="exploit",
        prior=0.6,
        proposed_vector_class="sql_injection",
    )


@pytest.mark.asyncio
async def test_generate_and_prioritize_share_passed_dag() -> None:
    dag = HypothesisDAG()
    generate = GenerateHypothesesTool(dag=dag)
    prioritize = PrioritizeHypothesisTool(dag=dag)

    generated = await generate.run(seed_evidence="login form and API search route", n=3)
    selected = await prioritize.run(k=1)

    assert generated.ok is True
    assert generated.data["added"] == 3
    assert len(dag.nodes) == 3
    assert selected.ok is True
    assert selected.data["hypothesis"]["status"] == "untested"
    assert selected.data["hypothesis"]["prior"] >= 0.6


@pytest.mark.asyncio
async def test_generate_tool_uses_injected_generator() -> None:
    async def generator(seed_evidence: str, n: int) -> list[dict[str, object]]:
        return [
            {
                "claim": f"custom claim from {seed_evidence}",
                "decision_class": "strategy",
                "prior": 0.77,
                "vector_class": "custom",
            }
        ][:n]

    dag = HypothesisDAG()
    tool = GenerateHypothesesTool(dag=dag, generator=generator)

    result = await tool.run(seed_evidence="seed", n=5)

    assert result.ok is True
    assert result.data["hypotheses"][0]["claim"] == "custom claim from seed"
    assert result.data["hypotheses"][0]["proposed_vector_class"] == "custom"
    assert len(dag.nodes) == 1


@pytest.mark.asyncio
async def test_update_tool_changes_status_and_query_tool_reports_counts() -> None:
    dag = HypothesisDAG()
    dag.add(root_hypothesis())
    dag.add(
        HypothesisNode(
            node_id="child",
            claim="information_schema may be accessible",
            decision_class="exploit",
            prior=0.4,
            proposed_vector_class="sql_injection",
        ),
        parent_ids=["root"],
    )

    updated = await UpdateHypothesisTool(dag=dag).run(
        node_id="root",
        evidence="SQL error appears only for quote payload",
        status_change="confirmed",
        delta=1.0,
        iteration=9,
    )
    queried = await QueryDAGTool(dag=dag).run(filter={"status": "confirmed"})

    assert updated.ok is True
    assert updated.data["hypothesis"]["status"] == "confirmed"
    assert dag.nodes["child"].prior > 0.4
    assert queried.ok is True
    assert queried.data["counts"]["confirmed"] == 1
    assert queried.data["nodes"][0]["node_id"] == "root"


@pytest.mark.asyncio
async def test_add_child_tool_links_parent_and_prioritize_returns_child() -> None:
    dag = HypothesisDAG()
    dag.add(root_hypothesis())

    added = await AddChildHypothesisTool(dag=dag).run(
        parent_id="root",
        claim="users table may contain password hashes",
        prior=0.71,
        vector_class="post_exploitation",
        decision_class="exploit",
        node_id="child-1",
    )
    selected = await PrioritizeHypothesisTool(dag=dag).run(k=1)

    assert added.ok is True
    assert added.data["hypothesis"]["node_id"] == "child-1"
    assert dag.nodes["root"].child_ids == ["child-1"]
    assert dag.nodes["child-1"].parent_ids == ["root"]
    assert selected.data["hypothesis"]["node_id"] == "child-1"


@pytest.mark.asyncio
async def test_add_child_tool_can_declare_crown_jewel_branch() -> None:
    dag = HypothesisDAG()
    dag.add(root_hypothesis())
    state = ScanLoopState(target="http://localhost:3000", max_iters=3)
    state.hypothesis_dag = dag

    added = await AddChildHypothesisTool(dag=dag, state=state).run(
        parent_id="root",
        claim="admin API may expose all orders",
        prior=0.82,
        vector_class="idor",
        decision_class="exploit",
        node_id="crown-1",
        branch_id="branch:crown-1",
        crown_jewel="full order data exfiltration",
        objective="Prove cross-user order access.",
        next_step="Replay with two identities against /api/orders.",
    )

    assert added.ok is True
    branch = state.branches["branch:crown-1"]
    assert branch.crown_jewel == "full order data exfiltration"
    assert branch.role == "post_exploit_worker"
    assert added.data["branch"]["id"] == "branch:crown-1"


@pytest.mark.asyncio
async def test_tools_resolve_and_share_state_dict_dag() -> None:
    state: dict[str, object] = {}
    tools = build_hypothesis_tools(state=state)

    for tool in tools:
        assert isinstance(tool, BrainTool)

    generated = await tools[0].run(seed_evidence="admin API and JWT cookie", n=2)
    selected = await tools[1].run(k=2)

    assert generated.ok is True
    assert "hypothesis_dag" in state
    assert isinstance(state["hypothesis_dag"], HypothesisDAG)
    assert len(state["hypothesis_dag"].nodes) == 2
    assert len(selected.data["hypotheses"]) == 2


@pytest.mark.asyncio
async def test_tool_errors_are_structured_for_unknown_nodes() -> None:
    dag = HypothesisDAG()

    update_result = await UpdateHypothesisTool(dag=dag).run(
        node_id="missing",
        evidence="nothing",
        delta=-1,
    )
    add_result = await AddChildHypothesisTool(dag=dag).run(
        parent_id="missing",
        claim="child",
        prior=0.5,
    )

    assert update_result.ok is False
    assert update_result.error == "unknown_hypothesis"
    assert add_result.ok is False
    assert add_result.error == "unknown_parent"
