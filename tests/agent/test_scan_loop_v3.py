from __future__ import annotations

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.scan_loop_v3 import (
    v3_after_action,
    v3_dashboard_summary,
    v3_finalize_runtime,
    v3_maybe_finish_gate,
    v3_prepare_decision,
    v3_result_payload,
)
from vxis.agent.tool_registry import ToolRegistry
from vxis.agent.tools import build_default_registry
from vxis.agent.tool_registry import ToolResult


def test_v3_runtime_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("VXIS_V3", raising=False)

    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)

    assert loop.state.v3_enabled is False
    assert v3_dashboard_summary(loop.state) == ""
    assert v3_result_payload(loop.state) == {"enabled": False}


def test_v3_runtime_best_effort_when_components_missing(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VXIS_V3", "1")
    monkeypatch.setenv("VXIS_PTI_DIR", str(tmp_path / "pti"))

    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)

    assert loop.state.v3_enabled is True
    assert isinstance(loop.state.v3_components, list)
    assert isinstance(loop.state.v3_errors, list)
    payload = v3_result_payload(loop.state)
    assert payload["enabled"] is True
    assert "components" in payload


def test_v3_registry_tools_share_loop_state(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VXIS_V3", "1")
    monkeypatch.setenv("VXIS_PTI_DIR", str(tmp_path / "pti"))

    registry = build_default_registry()
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=3)

    tool = registry.get_tool("prioritize_hypothesis")
    assert tool is not None
    assert getattr(tool, "_state") is loop.state
    ask_tool = registry.get_tool("ask_human")
    critique_tool = registry.get_tool("self_critique")
    assert ask_tool is not None
    assert getattr(ask_tool, "queue") is loop.state.ask_queue
    assert critique_tool is not None
    assert getattr(critique_tool, "_state") is loop.state
    assert loop.state.pti is not None
    assert loop.state.hypothesis_dag is not None
    assert loop.state.coverage_matrix is not None
    assert loop.state.cost_router is not None


def test_v3_component_flags_can_disable_individual_components(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VXIS_V3", "1")
    monkeypatch.setenv("VXIS_V3_PTI", "0")
    monkeypatch.setenv("VXIS_V3_ASK", "0")
    monkeypatch.setenv("VXIS_PTI_DIR", str(tmp_path / "pti"))

    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)

    assert loop.state.v3_enabled is True
    assert loop.state.pti is None
    assert loop.state.ask_queue is None
    assert loop.state.hypothesis_dag is not None
    assert "pti" not in loop.state.v3_components
    assert "ask_queue" not in loop.state.v3_components


def test_v3_prepare_decision_seeds_dag_and_coverage(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VXIS_V3", "1")
    monkeypatch.setenv("VXIS_PTI_DIR", str(tmp_path / "pti"))

    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)

    decision_class = v3_prepare_decision(loop)

    assert decision_class in {"recon", "exploit", "strategy"}
    assert loop.state.hypothesis_dag is not None
    assert loop.state.hypothesis_dag.nodes
    assert loop.state.coverage_matrix is not None
    assert loop.state.coverage_matrix.cells


def test_v3_after_action_records_coverage_block_and_trajectory(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VXIS_V3", "1")
    monkeypatch.setenv("VXIS_PTI_DIR", str(tmp_path / "pti"))

    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.iteration = 1
    v3_prepare_decision(loop)

    result = ToolResult(
        ok=False,
        summary="HTTP 429 too many requests from Cloudflare",
        data={"status": 429, "headers": {"server": "cloudflare"}, "body": "too many requests"},
    )
    v3_after_action(
        loop,
        name="http_request",
        args={"url": "http://localhost:3000/rest/products/search?q=test", "method": "GET"},
        result=result,
        candidate_ids=["web:sqli"],
        branch_ids=[],
    )

    assert loop.state.block_history
    assert loop.state.trajectories_written == 1
    assert any(
        cell.status == "tested-blocked" for cell in loop.state.coverage_matrix.cells.values()
    )

    v3_finalize_runtime(loop)
    assert (tmp_path / "pti" / loop.state.pti.target_hash / "dossier.yaml").exists()


def test_v3_recon_action_does_not_park_hypothesis_in_testing(monkeypatch, tmp_path) -> None:
    """A recon/browser action with ok=True must NOT move a hypothesis to 'testing'.

    Only exploit/mutating actions should promote a hypothesis to 'testing'.
    A recon result may nudge belief but the hypothesis must stay 'untested'.
    """
    monkeypatch.setenv("VXIS_V3", "1")
    monkeypatch.setenv("VXIS_PTI_DIR", str(tmp_path / "pti"))

    from vxis.agent.hypothesis.dag import HypothesisDAG, HypothesisNode

    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.iteration = 1

    # Seed a DAG with one untested hypothesis targeting sqli
    dag = HypothesisDAG()
    node = HypothesisNode(
        node_id="hyp-0001",
        claim="Login endpoint is vulnerable to SQLi",
        decision_class="exploit",
        prior=0.6,
        proposed_vector_class="sqli",
    )
    dag.add(node)
    loop.state.hypothesis_dag = dag

    # A recon/browser action with ok=True — should NOT park hypothesis in 'testing'
    recon_result = ToolResult(ok=True, summary="page loaded successfully", data={})
    v3_after_action(
        loop,
        name="browser_navigate",
        args={"url": "http://localhost:3000/login"},
        result=recon_result,
        candidate_ids=["hyp-0001"],
        branch_ids=[],
    )

    recon_status = loop.state.hypothesis_dag.nodes["hyp-0001"].status
    assert recon_status == "untested", (
        f"Expected 'untested' after recon action, got {recon_status!r}. "
        "Recon must not park hypothesis in 'testing'."
    )

    # Now an exploit action with ok=True — SHOULD promote to 'testing'
    exploit_result = ToolResult(ok=True, summary="injection attempt sent", data={})
    v3_after_action(
        loop,
        name="run_skill",
        args={"skill": "test_injection", "url": "http://localhost:3000/login"},
        result=exploit_result,
        candidate_ids=["hyp-0001"],
        branch_ids=[],
    )

    exploit_status = loop.state.hypothesis_dag.nodes["hyp-0001"].status
    assert exploit_status == "testing", (
        f"Expected 'testing' after exploit action, got {exploit_status!r}. "
        "Exploit actions should promote hypothesis to 'testing'."
    )


def test_v3_finish_gate_blocks_unresolved_work(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VXIS_V3", "1")
    monkeypatch.setenv("VXIS_PTI_DIR", str(tmp_path / "pti"))
    monkeypatch.setenv("VXIS_V3_COVERAGE_REQUIRED", "99")

    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=50)
    loop.state.iteration = 50
    v3_prepare_decision(loop)

    gate = v3_maybe_finish_gate(loop)

    assert gate is not None
    assert gate["title"] == "v3_cognitive_gate"
    assert "coverage_gate" in gate["data"] or "self_critique" in gate["data"]
