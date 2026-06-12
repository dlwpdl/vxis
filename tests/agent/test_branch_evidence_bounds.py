from __future__ import annotations

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry


def test_parent_branch_evidence_is_capped() -> None:
    loop = ScanAgentLoop(target="http://example.com", registry=ToolRegistry(), max_iters=3)
    loop.state.ensure_branch("b1", "web:rce", "RCE foothold")

    # Each proven post-exploit worker appends ~hundreds of chars; over a long
    # scan this would grow unboundedly and bloat every snapshot/dashboard dump.
    for i in range(80):
        loop._mark_agent_graph_crown_parent_needs_report(
            parent_branch_id="b1",
            agent={"result": f"proof-{i} " + ("X" * 300)},
            summary=f"worker {i}",
        )

    branch = loop.state.branches["b1"]
    assert len(branch.evidence) <= 2000
    # The most recent proof must survive the cap.
    assert "proof-79" in branch.evidence
