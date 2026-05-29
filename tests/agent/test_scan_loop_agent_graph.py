import asyncio
import json
import pytest
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

from vxis.agent.context_budget import estimate_context_tokens
from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.agent.tools.agent_graph_tools import AgentGraphTool
from vxis.agent.tools.finding_tools import (
    LinkChainTool,
    ReportFindingTool,
    _get_chains,
    _get_findings,
    _reset_for_tests as _reset_findings,
)
from vxis.llm.hybrid_config import resolve_hybrid_model_config


class RunSkillTool:
    name = "run_skill"
    description = "execute prebuilt skill"
    input_schema = {"type": "object"}

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def run(self, **kwargs) -> ToolResult:
        self.calls.append(dict(kwargs))
        return ToolResult(ok=True, summary=f"ran skill {kwargs.get('skill', '?')}", data={})


class WorkerPlannerBrain:
    def __init__(
        self,
        *,
        response: str = "",
        responses: list[str | None] | None = None,
        delay: float = 0.0,
        unavailable: bool = False,
    ) -> None:
        self._hybrid_model_config = resolve_hybrid_model_config(
            env={"VXIS_WORKER_LLM": "llamacpp/local-35b"}
        )
        self.response = response
        self.responses = list(responses) if responses is not None else None
        self.delay = delay
        self.unavailable = unavailable
        self.calls: list[dict] = []
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    def _call_llm_direct(
        self,
        system_prompt: str,
        user_prompt: str,
        provider: str = "",
        model: str = "",
        image_path: str = "",
    ) -> str | None:
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if self.delay:
                time.sleep(self.delay)
            self.calls.append(
                {
                    "system": system_prompt,
                    "user": user_prompt,
                    "provider": provider,
                    "model": model,
                    "image_path": image_path,
                }
            )
            if self.unavailable:
                return None
            if self.responses is not None and self.responses:
                return self.responses.pop(0)
            if self.response:
                return self.response
            skill = "post_auth_enum" if "allowed_skills=post_auth_enum" in user_prompt else "test_injection"
            return json.dumps(
                {
                    "tool": "run_skill",
                    "args": {
                        "skill": skill,
                        "target_url": "http://localhost:3000",
                        "params": {},
                    },
                    "evidence_intent": "collect control/payload delta for EvidenceArtifact",
                }
            )
        finally:
            with self._lock:
                self.active -= 1


@pytest.fixture(autouse=True)
def _isolate_findings():
    _reset_findings()
    yield
    _reset_findings()


def test_agent_graph_is_planning_capability_allowed_for_recon_worker():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    args = {"action": "create", "task": "Map target surface", "role": "recon_worker"}
    assert loop._action_capability("agent_graph", args) == "plan"
    assert loop._role_allows_action("recon_worker", "agent_graph", args) is True


def test_agent_graph_action_has_ui_details():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    vector_id, method, endpoint, summary = loop._ui_action_details(
        "agent_graph",
        {"action": "create", "role": "recon_worker", "task": "Map unauthenticated surface"},
    )
    assert vector_id == "scan:agent-graph"
    assert method == "GRAPH"
    assert endpoint == "recon_worker"
    assert "Map unauthenticated surface" in summary


def test_scan_loop_normalizes_agent_graph_create_into_bounded_envelope():
    normalized = ScanAgentLoop._normalize_tool_args(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Validate SQL injection on /search",
            "skills": ["test_injection"],
        },
    )
    assert normalized["objective"] == "Validate SQL injection on /search"
    assert "raw proof artifact via test_injection" in normalized["expected_artifact"]
    assert "bounded proof step" in normalized["stop_condition"]
    assert "pivot planning" in normalized["escalation_trigger"]


def test_scan_dashboard_includes_agent_graph_snapshot():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.brain = SimpleNamespace(_provider="openai", _model="gpt-5.5")
    loop.state.add_message(
        "tool",
        {
            "name": "agent_graph",
            "args": {
                "action": "create",
                "role": "recon_worker",
                "task": "Map auth and API surface",
            },
            "result": {
                "ok": True,
                "summary": "agent_graph: created agent-0001 (recon_worker)",
                "data": {
                    "agent": {
                        "id": "agent-0001",
                        "role": "recon_worker",
                        "task": "Map auth and API surface",
                        "status": "running",
                        "parent_id": None,
                        "skills": ["enumerate_endpoints"],
                        "task_envelope": {
                            "objective": "Map auth and API surface",
                            "target_surface": "web",
                            "allowed_tools": [
                                "run_skill",
                                "http_request",
                                "browser_navigate",
                                "skills:enumerate_endpoints",
                            ],
                            "expected_artifact": "surface map with concrete endpoints or auth boundaries",
                            "stop_condition": "stop after mapping the relevant surface and naming the next proof step",
                            "escalation_trigger": "escalate after repeated blocked/clean runs or when a positive result needs a sharper next task",
                        },
                        "result": "",
                        "created_at": "2026-05-22T00:00:00+00:00",
                        "updated_at": "2026-05-22T00:00:00+00:00",
                        "message_count": 1,
                        "execution_count": 1,
                        "executions": [
                            {
                                "id": "exec-0001",
                                "tool": "run_skill",
                                "args": {"skill": "enumerate_endpoints"},
                                "ok": True,
                                "summary": "mapped /login and /api/products",
                                "data": {},
                                "error": None,
                                "created_at": "2026-05-22T00:00:01+00:00",
                            }
                        ],
                    },
                    "active_agents": 1,
                },
            },
        },
    )
    dashboard = loop._build_scan_dashboard()
    assert "Agent graph:" in dashboard
    assert "agent-0001" in dashboard
    assert "Map auth and API surface" in dashboard
    assert "last_run: run_skill ok: mapped /login and /api/products" in dashboard
    assert 'agent_graph(action="finish", agent_id="agent-0001", result="...")' in dashboard


def test_scan_dashboard_surfaces_director_worker_exchange():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.brain = SimpleNamespace(_provider="openai", _model="gpt-5.5")
    loop.state.add_message(
        "tool",
        {
            "name": "agent_graph",
            "args": {"action": "run", "agent_id": "agent-0001"},
            "result": {
                "ok": True,
                "summary": "agent_graph: ran agent-0001 -> run_skill: status delta observed",
                "data": {
                    "agent": {
                        "id": "agent-0001",
                        "role": "exploit_worker",
                        "task": "Validate SQL injection on /api/search",
                        "status": "waiting",
                        "parent_id": None,
                        "skills": ["test_injection"],
                        "skill_context": (
                            "### test_injection\n"
                            'action: run_skill(skill="test_injection", target_url=<target>, params={...})\n'
                            "validate: require baseline/control/payload delta"
                        ),
                        "task_envelope": {
                            "objective": "Validate SQL injection on /api/search",
                            "target_surface": "web",
                            "allowed_tools": [
                                "run_skill",
                                "http_request",
                                "browser_navigate",
                                "browser_analyze_dom",
                                "skills:test_injection",
                            ],
                            "expected_artifact": "raw proof artifact via test_injection: request/response transcript, control pair, or exploit delta",
                            "stop_condition": "stop after one bounded proof attempt yields concrete evidence or a blocker",
                            "escalation_trigger": "escalate after repeated blocked/clean runs or when a positive result needs a sharper next task",
                        },
                        "result_package": {
                            "attempted_tool": "run_skill",
                            "attempt_summary": "status delta observed on /api/search",
                            "raw_evidence_summary": "status delta observed on /api/search",
                            "control_result": "baseline 200 vs payload 500",
                            "observed_delta": "SQL error signature present",
                            "verdict_guess": "candidate_positive",
                            "evidence_artifact": {
                                "schema": "vxis.agent_graph.evidence_artifact.v1",
                                "claim": "SQL injection on /api/search",
                                "target": "http://localhost:3000/api/search",
                                "control": {
                                    "request": "GET /api/search?q=test",
                                    "response_status": 200,
                                },
                                "payload": {
                                    "request": "GET /api/search?q='",
                                    "response_status": 500,
                                },
                                "observed_delta": "baseline 200 vs payload 500 with SQL error",
                                "repro_steps": ["send control", "send payload", "compare"],
                                "missing_fields": [],
                                "valid": True,
                            },
                            "recommended_next_step": "Escalate to director for chain/pivot planning, then finish with concrete impact",
                        },
                        "result": "",
                        "created_at": "2026-05-22T00:00:00+00:00",
                        "updated_at": "2026-05-22T00:00:30+00:00",
                        "message_count": 2,
                        "execution_count": 1,
                        "executions": [
                            {
                                "id": "exec-0001",
                                "tool": "run_skill",
                                "args": {"skill": "test_injection"},
                                "ok": True,
                                "summary": "status delta observed on /api/search",
                                "data": {},
                                "error": None,
                                "created_at": "2026-05-22T00:00:30+00:00",
                            }
                        ],
                    },
                    "active_agents": 1,
                },
            },
        },
    )

    dashboard = loop._build_scan_dashboard()

    assert "Director-worker exchange:" in dashboard
    assert "agent-0001 waiting exploit_worker skills=test_injection" in dashboard
    assert "director_next=finish agent-0001 or open crown-chain pivot" in dashboard
    assert "contract: expect raw proof artifact" in dashboard
    assert "worker_verdict: candidate_positive" in dashboard
    assert "proof: valid" in dashboard
    assert "worker_card: action: run_skill" in dashboard


def test_agent_graph_positive_waiting_result_projects_director_followup_branch_state():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=30)
    result = ToolResult(
        ok=True,
        summary="agent_graph: ran agent-0001 -> run_skill: status delta observed",
        data={
            "agent": {
                "id": "agent-0001",
                "role": "exploit_worker",
                "task": "Validate SQL injection on /api/search",
                "status": "waiting",
                "skills": ["test_injection"],
                "task_envelope": {
                    "objective": "Validate SQL injection on /api/search",
                    "target_surface": "web",
                    "allowed_tools": [
                        "run_skill",
                        "http_request",
                        "browser_navigate",
                        "browser_analyze_dom",
                        "skills:test_injection",
                    ],
                    "expected_artifact": "raw proof artifact via test_injection: request/response transcript, control pair, or exploit delta",
                    "stop_condition": "stop after one bounded proof step yields concrete evidence or a blocker",
                    "escalation_trigger": "escalate after ambiguous evidence, blocked execution, or a positive result that needs pivot planning",
                },
                "result_package": {
                    "attempted_tool": "run_skill",
                    "attempt_summary": "status delta observed on /api/search",
                    "raw_evidence_summary": "status delta observed on /api/search",
                    "control_result": "baseline 200 vs payload 500",
                    "observed_delta": "SQL error signature present",
                    "verdict_guess": "candidate_positive",
                    "recommended_next_step": "Escalate to director for chain/pivot planning, then finish with concrete impact",
                },
                "result": "",
                "created_at": "2026-05-22T00:00:00+00:00",
                "updated_at": "2026-05-22T00:00:30+00:00",
                "message_count": 2,
                "execution_count": 1,
                "executions": [
                    {
                        "id": "exec-0001",
                        "tool": "run_skill",
                        "args": {"skill": "test_injection"},
                        "ok": True,
                        "summary": "status delta observed on /api/search",
                        "data": {},
                        "error": None,
                        "created_at": "2026-05-22T00:00:30+00:00",
                    }
                ],
            }
        },
    )

    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "run", "agent_id": "agent-0001"},
        result=result,
    )

    branch = loop.state.branches["agent:agent-0001"]
    assert "Director follow-up:" in branch.next_step
    assert branch.blocker == "positive delegated worker result requires director pivot/finish"


def test_positive_worker_result_missing_challenge_fields_spawns_gap_branch():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=30)
    result = ToolResult(
        ok=True,
        summary="agent_graph: ran agent-0002 -> run_skill: admin data observed",
        data={
            "agent": {
                "id": "agent-0002",
                "role": "post_exploit_worker",
                "parent_id": "agent-0001",
                "task": "Use prior token to access admin data",
                "status": "waiting",
                "result": "Confirmed session token allows admin data access.",
                "result_package": {
                    "verdict_guess": "candidate_positive",
                    "evidence_artifact": {
                        "schema": "vxis.agent_graph.evidence_artifact.v1",
                        "claim": "session token allows admin data access",
                        "target": "http://localhost:3000/admin",
                        "control": {"request": "GET /admin", "response_status": 403},
                        "payload": {"request": "GET /admin with token", "response_status": 200},
                        "observed_delta": "payload returned admin data",
                        "repro_steps": ["send control", "send token request", "compare"],
                        "valid": True,
                    },
                },
            }
        },
    )

    branch_id = loop._spawn_recursive_gap_branch_from_result(
        "agent_graph",
        {"action": "run", "agent_id": "agent-0002"},
        result,
    )

    assert branch_id is not None
    branch = loop.state.branches[branch_id]
    assert branch.vector_id == "CHALLENGE-WORKER"
    assert branch.owner == "gap"
    assert branch.escalation_status == "needs_recursive_dig"
    assert "repeat_count>=2" in branch.next_step
    assert "source-output reuse" in branch.next_step
    assert "crown-jewel evidence" in branch.next_step


@pytest.mark.asyncio
async def test_agent_graph_create_and_run_capture_contract_and_artifact():
    graph = AgentGraphTool()

    async def _executor(agent: dict[str, object], instruction: str) -> ToolResult:
        assert agent["task_envelope"]["objective"] == "Validate SQL injection on /search"
        return ToolResult(
            ok=True,
            summary="confirmed sql injection with status delta",
            data={
                "tool": "run_skill",
                "args": {"skill": "test_injection", "target_url": "http://localhost:3000"},
                "result": {
                    "ok": True,
                    "summary": "confirmed sql injection with status delta",
                    "evidence": "payload caused SQL error signature",
                    "control": "baseline stayed 200",
                },
            },
        )

    graph.set_executor(_executor)
    created = await graph.run(
        action="create",
        role="exploit_worker",
        task="Validate SQL injection on /search",
        skills=["test_injection"],
    )
    assert created.ok is True
    agent = created.data["agent"]
    assert agent["task_envelope"]["objective"] == "Validate SQL injection on /search"
    assert "expected_artifact" in agent["task_envelope"]
    assert "stop_condition" in agent["task_envelope"]
    assert "escalation_trigger" in agent["task_envelope"]

    ran = await graph.run(action="run", agent_id=agent["id"])
    assert ran.ok is True
    result_agent = ran.data["agent"]
    assert result_agent["result_package"]["attempted_tool"] == "run_skill"
    assert "payload caused SQL error signature" in str(
        result_agent["result_package"]["observed_delta"]
    )
    artifact = result_agent["result_package"]["evidence_artifact"]
    assert artifact["schema"] == "vxis.agent_graph.evidence_artifact.v1"
    assert artifact["valid"] is True
    assert artifact["source"] == "legacy_result_fields"
    assert artifact["missing_fields"] == []
    assert result_agent["result_package"]["verdict_guess"] == "candidate_positive"
    assert "recommended_next_step" in result_agent["result_package"]


@pytest.mark.asyncio
async def test_agent_graph_tool_restores_nodes_messages_and_counters(tmp_path):
    snapshot_path = tmp_path / "agent_graph.json"
    tool = AgentGraphTool()
    tool.set_persistence_path(snapshot_path)

    created = await tool.run(
        action="create",
        role="exploit_worker",
        task="Prove IDOR on /api/orders/2",
        message="Collect baseline and payload evidence.",
    )
    agent_id = created.data["agent"]["id"]
    sent = await tool.run(
        action="send",
        agent_id=agent_id,
        message="Narrow to the order ownership boundary.",
    )

    restored = AgentGraphTool()
    restored.set_persistence_path(snapshot_path)
    viewed = await restored.run(action="view", agent_id=agent_id)
    created_again = await restored.run(
        action="create",
        role="recon_worker",
        task="Map admin routes",
    )

    assert created.ok is True
    assert sent.ok is True
    assert snapshot_path.exists()
    assert viewed.ok is True
    assert viewed.data["agent"]["message_count"] == 2
    assert "Narrow to the order ownership" in viewed.data["agent"]["messages"][-1]["body"]
    assert created_again.data["agent"]["id"] == "agent-0002"


@pytest.mark.asyncio
async def test_agent_graph_structured_evidence_artifact_allows_positive_finish():
    graph = AgentGraphTool()

    async def _executor(agent: dict[str, object], instruction: str) -> ToolResult:
        return ToolResult(
            ok=True,
            summary="confirmed sql injection with response delta",
            data={
                "tool": "run_skill",
                "args": {"skill": "test_injection", "target_url": "http://localhost:3000"},
                "result": {
                    "ok": True,
                    "summary": "confirmed sql injection with response delta",
                    "proof_artifact": {
                        "claim": "SQL injection on /search",
                        "target": "http://localhost:3000/search?q=",
                        "control": {
                            "request": "GET /search?q=test",
                            "response_status": 200,
                            "response_excerpt": "normal search results",
                        },
                        "payload": {
                            "request": "GET /search?q='",
                            "response_status": 500,
                            "response_excerpt": "SQL syntax error",
                        },
                        "observed_delta": "control returns HTTP 200; payload returns HTTP 500 with SQL error",
                        "repro_steps": [
                            "send control request",
                            "send payload request",
                            "compare status and SQL error body",
                        ],
                    },
                },
            },
        )

    graph.set_executor(_executor)
    created = await graph.run(
        action="create",
        role="exploit_worker",
        task="Validate SQL injection on /search",
        skills=["test_injection"],
    )
    agent_id = created.data["agent"]["id"]
    ran = await graph.run(action="run", agent_id=agent_id)

    artifact = ran.data["agent"]["result_package"]["evidence_artifact"]
    assert artifact["valid"] is True
    assert artifact["source"] == "structured"
    assert ran.data["agent"]["result_package"]["proof_quality"] == "strong"
    assert ran.data["agent"]["result_package"]["verdict_guess"] == "candidate_positive"

    finished = await graph.run(
        action="finish",
        agent_id=agent_id,
        result="Confirmed SQL injection on /search with HTTP status and SQL error delta.",
    )

    assert finished.ok is True
    assert finished.data["agent"]["status"] == "finished"
    assert finished.data["agent"]["result_package"]["verdict_guess"] == "proven"
    assert finished.data["agent"]["result_package"]["evidence_artifact"]["valid"] is True


@pytest.mark.asyncio
async def test_agent_graph_create_accepts_explicit_director_envelope():
    graph = AgentGraphTool()
    created = await graph.run(
        action="create",
        role="exploit_worker",
        task="Validate SQL injection on /search",
        objective="Confirm SQL injection on /search using one bounded proof step",
        expected_artifact="raw request/response transcript with baseline vs payload delta",
        stop_condition="stop after one bounded proof attempt yields concrete evidence or blocker",
        escalation_trigger="escalate after ambiguous evidence or positive proof needing pivot planning",
        skills=["test_injection"],
    )
    agent = created.data["agent"]
    envelope = agent["task_envelope"]
    assert envelope["objective"].startswith("Confirm SQL injection")
    assert "baseline vs payload delta" in envelope["expected_artifact"]
    assert "one bounded proof attempt" in envelope["stop_condition"]
    assert "positive proof needing pivot planning" in envelope["escalation_trigger"]


@pytest.mark.asyncio
async def test_agent_graph_failed_runs_raise_director_escalation_state():
    graph = AgentGraphTool()

    async def _executor(agent: dict[str, object], instruction: str) -> ToolResult:
        return ToolResult(ok=False, summary="blocked by anti-automation", error="blocked")

    graph.set_executor(_executor)
    created = await graph.run(
        action="create",
        role="exploit_worker",
        task="Probe IDOR on /api/orders/{id}",
        skills=["test_idor"],
    )
    agent_id = created.data["agent"]["id"]
    first = await graph.run(action="run", agent_id=agent_id)
    second = await graph.run(action="run", agent_id=agent_id)
    assert first.ok is False
    assert second.ok is False
    escalated = second.data["agent"]["escalation"]
    assert escalated["status"] == "ambiguous"
    assert "repeated blocked or failed child turns" in escalated["reason"]


@pytest.mark.asyncio
async def test_agent_graph_positive_run_without_poc_requires_proof_before_finish():
    graph = AgentGraphTool()

    async def _executor(agent: dict[str, object], instruction: str) -> ToolResult:
        return ToolResult(
            ok=True,
            summary="confirmed sql injection on search",
            data={
                "tool": "run_skill",
                "args": {"skill": "test_injection"},
                "result": {
                    "ok": True,
                    "summary": "confirmed sql injection on search",
                },
            },
        )

    graph.set_executor(_executor)
    created = await graph.run(
        action="create",
        role="exploit_worker",
        task="Validate SQL injection on /search",
        skills=["test_injection"],
    )
    agent_id = created.data["agent"]["id"]
    ran = await graph.run(action="run", agent_id=agent_id)

    result_package = ran.data["agent"]["result_package"]
    assert result_package["verdict_guess"] == "needs_proof"
    assert result_package["proof_quality"] == "weak"
    assert ran.data["agent"]["escalation"]["status"] == "needs_proof"

    rejected = await graph.run(
        action="finish",
        agent_id=agent_id,
        result="Confirmed SQL injection on /search.",
    )

    assert rejected.ok is False
    assert rejected.error == "insufficient_proof_artifact"
    assert "PoC/control artifact" in rejected.summary


@pytest.mark.asyncio
async def test_agent_graph_positive_summary_with_proof_words_still_requires_artifact_fields():
    graph = AgentGraphTool()

    async def _executor(agent: dict[str, object], instruction: str) -> ToolResult:
        summary = "confirmed sql injection baseline 200 payload 500"
        return ToolResult(
            ok=True,
            summary=summary,
            data={
                "tool": "run_skill",
                "args": {"skill": "test_injection", "target_url": "http://localhost:3000"},
                "result": {"ok": True, "summary": summary},
            },
        )

    graph.set_executor(_executor)
    created = await graph.run(
        action="create",
        role="exploit_worker",
        task="Validate SQL injection on /search",
        skills=["test_injection"],
    )
    agent_id = created.data["agent"]["id"]
    ran = await graph.run(action="run", agent_id=agent_id)

    package = ran.data["agent"]["result_package"]
    assert package["verdict_guess"] == "needs_proof"
    assert package["proof_quality"] == "weak"
    assert package["evidence_artifact"]["valid"] is False
    assert "control" in package["evidence_artifact"]["missing_fields"]
    assert "payload" in package["evidence_artifact"]["missing_fields"]

    rejected = await graph.run(
        action="finish",
        agent_id=agent_id,
        result="Confirmed SQL injection on /search.",
    )

    assert rejected.ok is False
    assert rejected.error == "insufficient_proof_artifact"


def test_judge_replan_hint_uses_agent_graph_escalation_status():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=10)
    branch = loop.state.ensure_branch(
        "agent:agent-0001",
        "agent_graph:exploit_worker",
        "exploit_worker: Validate SQL injection",
        priority=95,
        role="exploit_worker",
        owner="agent_graph",
        objective="Validate SQL injection with control pair",
        next_step="Finish the worker or open a crown-chain task",
        escalation_status="positive_needs_pivot",
        escalation_reason="positive result needs chain/pivot decision from director",
    )
    branch.status = "active"
    hint = loop._judge_replan_hint()
    assert "positive result" in hint.lower()
    assert "crown-chain" in hint.lower() or "post-exploit" in hint.lower()


@pytest.mark.asyncio
async def test_agent_graph_envelope_restricts_child_tools():
    reg = ToolRegistry()

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):
            return ToolResult(ok=True, summary="ok")

    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=10)
    agent = {
        "id": "agent-0001",
        "role": "exploit_worker",
        "task": "Validate SQL injection on /search",
        "skills": ["test_injection"],
        "task_envelope": {"allowed_tools": ["http_request"]},
        "result_package": {},
    }
    blocked = await loop._run_agent_graph_child_turn(agent, "")
    assert blocked.ok is False
    assert blocked.error == "child_tool_not_allowed"


def test_agent_graph_result_creates_finish_blocking_branch():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=30)
    result = ToolResult(
        ok=True,
        summary="agent_graph: created agent-0001 (exploit_worker)",
        data={
            "agent": {
                "id": "agent-0001",
                "role": "exploit_worker",
                "task": "Validate SQL injection on /api/search and pursue DB impact",
                "status": "running",
                "parent_id": None,
                "skills": ["test_injection"],
                "result": "",
                "created_at": "2026-05-22T00:00:00+00:00",
                "updated_at": "2026-05-22T00:00:00+00:00",
                "message_count": 1,
            }
        },
    )

    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=result,
    )

    branch = loop.state.branches["agent:agent-0001"]
    assert branch.owner == "agent_graph"
    assert branch.status == "active"
    assert branch.priority >= 90
    assert "agent:agent-0001" in {b.id for b in loop._blocking_finish_branches()}
    assert loop._branch_ids_for_action(
        "agent_graph", {"action": "finish", "agent_id": "agent-0001"}
    ) == ["agent:agent-0001"]
    assert "agent:agent-0001" in loop._branch_ids_for_action(
        "shell_exec",
        {"command": "sqlmap -u http://localhost:3000/api/search?q=test --batch"},
    )


def test_agent_graph_finish_resolves_branch_blocker():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=30)
    create_result = ToolResult(
        ok=True,
        summary="agent_graph: created agent-0001 (recon_worker)",
        data={
            "agent": {
                "id": "agent-0001",
                "role": "recon_worker",
                "task": "Map unauthenticated API surface",
                "status": "running",
                "parent_id": None,
                "skills": ["enumerate_endpoints"],
                "result": "",
                "created_at": "2026-05-22T00:00:00+00:00",
                "updated_at": "2026-05-22T00:00:00+00:00",
                "message_count": 1,
            }
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "recon_worker"},
        result=create_result,
    )
    assert "agent:agent-0001" in {b.id for b in loop._blocking_finish_branches()}

    finish_result = ToolResult(
        ok=True,
        summary="agent_graph: agent-0001 finished",
        data={
            "agent": {
                "id": "agent-0001",
                "role": "recon_worker",
                "task": "Map unauthenticated API surface",
                "status": "finished",
                "parent_id": None,
                "skills": ["enumerate_endpoints"],
                "result": "Mapped /login, /api/products, and /api/search; no unauthenticated admin route found.",
                "created_at": "2026-05-22T00:00:00+00:00",
                "updated_at": "2026-05-22T00:01:00+00:00",
                "message_count": 2,
            }
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "finish", "agent_id": "agent-0001"},
        result=finish_result,
    )

    branch = loop.state.branches["agent:agent-0001"]
    assert branch.status == "exhausted"
    assert "agent:agent-0001" not in {b.id for b in loop._blocking_finish_branches()}


def test_agent_graph_positive_worker_result_spawns_crown_chain_branch():
    reg = ToolRegistry()
    reg.register(RunSkillTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)
    finish_result = ToolResult(
        ok=True,
        summary="agent_graph: agent-0001 finished",
        data={
            "agent": {
                "id": "agent-0001",
                "role": "exploit_worker",
                "task": "Validate SQL injection on /api/search",
                "status": "finished",
                "parent_id": None,
                "skills": ["test_injection"],
                "result": "Confirmed SQL injection on /api/search exposes session token material.",
                "created_at": "2026-05-22T00:00:00+00:00",
                "updated_at": "2026-05-22T00:01:00+00:00",
                "message_count": 2,
                "execution_count": 1,
                "executions": [
                    {
                        "id": "exec-0001",
                        "tool": "run_skill",
                        "args": {"skill": "test_injection"},
                        "ok": True,
                        "summary": "status delta and SQL error signature on /api/search",
                        "data": {},
                        "error": None,
                        "created_at": "2026-05-22T00:00:30+00:00",
                    }
                ],
            }
        },
    )

    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "finish", "agent_id": "agent-0001"},
        result=finish_result,
    )

    parent = loop.state.branches["agent:agent-0001"]
    followup = loop.state.branches["agent:agent-0001:crown-chain"]
    assert parent.status == "proven"
    assert followup.status == "active"
    assert followup.role == "post_exploit_worker"
    assert followup.parent_branch_id == parent.id
    assert followup.crown_jewel == "DB dump or admin credentials"
    assert followup in loop._blocking_finish_branches()
    assert any("chain follow-up agent-0001" in note for note in loop.state.shared_notes)

    forced = loop._forced_branch_action(followup)
    assert forced is not None
    assert forced[0] == "run_skill"
    assert forced[1]["skill"] == "post_auth_enum"


@pytest.mark.asyncio
async def test_agent_graph_crown_chain_creates_post_exploit_worker_child_agent():
    reg = ToolRegistry()
    graph = AgentGraphTool()
    reg.register(graph)
    reg.register(LinkChainTool())
    reg.register(ReportFindingTool())

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):
            return ToolResult(
                ok=True,
                summary="confirmed SQL injection with token impact",
                data={
                    "proof_artifact": {
                        "claim": "SQL injection on /api/search exposes token material",
                        "target": "http://localhost:3000/api/search",
                        "control": {
                            "request": "GET /api/search?q=test",
                            "response_status": 200,
                        },
                        "payload": {
                            "request": "GET /api/search?q='",
                            "response_status": 500,
                            "response_excerpt": "SQL error with session token column",
                        },
                        "observed_delta": "control HTTP 200 vs payload HTTP 500 with token-bearing SQL error",
                        "repro_steps": [
                            "send negative control",
                            "send payload",
                            "send payload again",
                            "compare token/error body",
                        ],
                        "repeat_count": 2,
                        "negative_control": {
                            "request": "GET /api/search?q=test",
                            "response_status": 200,
                            "response_excerpt": "no SQL error and no token material",
                        },
                        "source_output": "SQL error exposed session token column",
                        "source_output_used_in_pivot": True,
                        "crown_jewel_evidence": "SQL error exposed session token column/token material.",
                    }
                },
            )

    reg.register(_RunSkill())
    planner_brain = WorkerPlannerBrain()
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=30,
        brain=planner_brain,
    )
    foothold = await reg.dispatch(
        "report_finding",
        {
            "title": "Authentication bypass via SQL injection",
            "severity": "high",
            "finding_type": "sql_injection",
            "affected_component": "/api/search",
            "description": "Authentication bypass and session token exposure via SQL injection.",
            "impact": "The foothold exposes session material that can be reused post-auth.",
            "technical_analysis": "Negative control benign search showed no SQL error; SQL payload exposed token-bearing error output twice. repeat_count=2",
            "poc_description": "Send a benign search request, then send the SQL payload twice and compare the response delta.",
            "poc_script_code": (
                "GET /api/search?q=test HTTP/1.1\n\n"
                "HTTP/1.1 200 OK\n\n"
                "negative control: [] and no SQL error\n\n"
                "GET /api/search?q=' HTTP/1.1\n\n"
                "HTTP/1.1 500 Internal Server Error\n\n"
                "SQL error with session token column\n\n"
                "repeat_count=2\n"
                "GET /api/search?q=' HTTP/1.1\n\n"
                "HTTP/1.1 500 Internal Server Error\n\n"
                "SQL error with session token column"
            ),
            "remediation_steps": "Use parameterized queries and suppress token-bearing error output.",
        },
    )
    assert foothold.ok is True

    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Validate SQL injection on /api/search",
            "skills": ["test_injection"],
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=created,
    )
    parent_agent_id = created.data["agent"]["id"]

    ran = await reg.dispatch("agent_graph", {"action": "run", "agent_id": parent_agent_id})
    assert ran.ok is True
    assert ran.data["execution"]["data"]["planner"]["source"] == "worker_llm"
    assert ran.data["agent"]["result_package"]["evidence_artifact"]["valid"] is True
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "run", "agent_id": parent_agent_id},
        result=ran,
    )

    finished = await reg.dispatch(
        "agent_graph",
        {
            "action": "finish",
            "agent_id": parent_agent_id,
            "result": "Confirmed SQL injection on /api/search exposes session token material.",
        },
    )
    assert finished.ok is True
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "finish", "agent_id": parent_agent_id},
        result=finished,
    )

    followup = loop.state.branches["agent:agent-0001:crown-chain"]
    forced = loop._forced_branch_action(followup)
    assert forced is not None
    assert forced[0] == "agent_graph"
    assert forced[1]["action"] == "create"
    assert forced[1]["role"] == "post_exploit_worker"
    assert forced[1]["parent_id"] == parent_agent_id
    assert forced[1]["skills"] == ["post_auth_enum"]
    assert "valid EvidenceArtifact" in forced[1]["expected_artifact"]

    child_created = await reg.dispatch(forced[0], forced[1])
    assert child_created.ok is True
    loop._sync_agent_graph_result_to_branches(
        name=forced[0],
        args=forced[1],
        result=child_created,
    )

    child_agent_id = child_created.data["agent"]["id"]
    child_branch_id = f"agent:{child_agent_id}"
    child_branch = loop.state.branches[child_branch_id]
    assert child_branch.role == "post_exploit_worker"
    assert child_branch.parent_branch_id == followup.id
    assert child_branch_id in followup.child_ids
    assert "post_auth_enum" in child_branch.watch_terms
    assert loop._forced_branch_action(child_branch) == (
        "agent_graph",
        {"action": "run", "agent_id": child_agent_id},
    )

    child_ran = await reg.dispatch("agent_graph", {"action": "run", "agent_id": child_agent_id})
    assert child_ran.ok is True
    assert child_ran.data["execution"]["data"]["planner"]["source"] == "worker_llm"
    assert child_ran.data["agent"]["result_package"]["evidence_artifact"]["valid"] is True
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "run", "agent_id": child_agent_id},
        result=child_ran,
    )

    child_finished = await reg.dispatch(
        "agent_graph",
        {
            "action": "finish",
            "agent_id": child_agent_id,
            "result": "Confirmed session token allows admin data access to database rows.",
        },
    )
    assert child_finished.ok is True
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "finish", "agent_id": child_agent_id},
        result=child_finished,
    )

    assert followup.status == "active"
    assert followup.escalation_status == "needs_report"
    assert "report_finding" in followup.next_step
    assert "report_finding required" in followup.blocker
    report_forced = loop._forced_branch_action(followup)
    assert report_forced is not None
    assert report_forced[0] == "report_finding"
    report_args = report_forced[1]
    assert report_args["finding_type"] == "broken_access_control"
    assert report_args["severity"] == "critical"
    assert "post_exploit_worker report candidate" in report_args["technical_analysis"]
    assert "EvidenceArtifact" in report_args["poc_script_code"]
    assert "valid EvidenceArtifact" not in report_args["poc_script_code"]
    assert report_args["impact"]
    assert report_args["remediation_steps"]

    reported = await reg.dispatch(report_forced[0], report_args)
    assert reported.ok is True
    assert loop._status_from_tool_result(reported) == "found"
    await loop._maybe_auto_link_chain(reported.data["id"])
    loop.state.record_branch_attempt(
        followup.id,
        report_forced[0],
        report_args,
        status=loop._status_from_tool_result(reported),
        summary=reported.summary,
    )

    assert followup.status == "proven"
    assert followup.blocker == ""
    assert followup.escalation_status == ""
    findings = _get_findings()
    assert findings
    assert findings[-1]["finding_type"] == "broken_access_control"
    chains = _get_chains()
    assert chains
    assert chains[-1]["finding_ids"] == [foothold.data["id"], reported.data["id"]]
    assert planner_brain.calls


@pytest.mark.asyncio
async def test_agent_graph_worker_llm_disallowed_tool_repairs_to_allowed_skill():
    reg = ToolRegistry()
    graph = AgentGraphTool()
    reg.register(graph)

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        def __init__(self) -> None:
            self.calls: list[dict] = []

        async def run(self, **kwargs):
            self.calls.append(dict(kwargs))
            return ToolResult(
                ok=True,
                summary="confirmed SQL injection with control/payload delta",
                data={
                    "proof_artifact": {
                        "claim": "SQL injection on /api/search",
                        "target": "http://localhost:3000/api/search",
                        "control": {"request": "GET /api/search?q=test", "response_status": 200},
                        "payload": {"request": "GET /api/search?q='", "response_status": 500},
                        "observed_delta": "control 200 vs payload 500",
                        "repro_steps": ["send control", "send payload", "compare status"],
                    }
                },
            )

    runner = _RunSkill()
    reg.register(runner)
    brain = WorkerPlannerBrain(
        responses=[
            json.dumps(
                {
                    "tool": "shell_exec",
                    "args": {"cmd": "id"},
                    "evidence_intent": "hallucinated unsafe tool",
                }
            ),
            json.dumps(
                {
                    "tool": "run_skill",
                    "args": {
                        "skill": "test_injection",
                        "target_url": "http://localhost:3000",
                        "params": {},
                    },
                    "evidence_intent": "collect control/payload delta for EvidenceArtifact",
                }
            ),
        ]
    )
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=30,
        brain=brain,
    )
    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Validate SQL injection on /api/search",
            "skills": ["test_injection"],
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=created,
    )

    ran = await reg.dispatch(
        "agent_graph",
        {"action": "run", "agent_id": created.data["agent"]["id"]},
    )

    assert ran.ok is True
    assert runner.calls
    assert runner.calls[-1]["skill"] == "test_injection"
    planner = ran.data["execution"]["data"]["planner"]
    assert planner["source"] == "worker_llm"
    assert planner["repair_attempted"] is True
    assert planner["repair_succeeded"] is True
    assert planner["initial_failure_reason"] == "disallowed_tool"
    assert len(brain.calls) == 2
    assert "Repair VXIS worker planner output" in brain.calls[1]["system"]
    assert "failure_reason=disallowed_tool" in brain.calls[1]["user"]
    assert estimate_context_tokens(brain.calls[1]["system"] + "\n" + brain.calls[1]["user"]) < 700
    assert loop._agent_graph_worker_planner_metrics["successes"] == 1
    assert loop._agent_graph_worker_planner_metrics["repair_successes"] == 1
    loop.state.add_message(
        "tool",
        {
            "name": "agent_graph",
            "args": {"action": "run", "agent_id": created.data["agent"]["id"]},
            "result": {"ok": ran.ok, "summary": ran.summary, "data": ran.data},
        },
    )
    dashboard = loop._build_scan_dashboard()
    assert "Worker planner quality: success=1/1 repair=1/1 fallback=0 unavailable=0" in dashboard
    assert "planner: worker_llm repair=ok initial=disallowed_tool" in dashboard


@pytest.mark.asyncio
async def test_agent_graph_worker_llm_can_choose_bounded_nmap_scan():
    reg = ToolRegistry()
    graph = AgentGraphTool()
    reg.register(graph)

    class _NmapScan:
        name = "nmap_scan"
        description = "bounded nmap"
        input_schema = {"type": "object"}

        def __init__(self) -> None:
            self.calls: list[dict] = []

        async def run(self, **kwargs):
            self.calls.append(dict(kwargs))
            return ToolResult(
                ok=True,
                summary="nmap_scan: 1 open service on localhost",
                data={
                    "open_count": 1,
                    "open_ports": [{"port": "80", "service": "http"}],
                },
            )

    nmap_scan = _NmapScan()
    reg.register(nmap_scan)
    brain = WorkerPlannerBrain(
        response=json.dumps(
            {
                "tool": "nmap_scan",
                "args": {
                    "target": "http://localhost:3000",
                    "ports": "top-100",
                    "scripts": "default,http-title",
                },
                "evidence_intent": "map open services before exploit selection",
            }
        )
    )
    _loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=30,
        brain=brain,
    )
    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "recon_worker",
            "task": "Map exposed services with nmap before choosing deeper probes",
        },
    )

    ran = await reg.dispatch(
        "agent_graph",
        {"action": "run", "agent_id": created.data["agent"]["id"]},
    )

    assert "nmap_scan" in created.data["agent"]["task_envelope"]["allowed_tools"]
    assert ran.ok is True
    assert nmap_scan.calls == [
        {
            "target": "http://localhost:3000",
            "ports": "top-100",
            "scripts": "default,http-title",
        }
    ]
    assert ran.data["execution"]["tool"] == "nmap_scan"
    assert ran.data["agent"]["status"] == "waiting"
    assert "nmap_scan" in brain.calls[0]["system"]


@pytest.mark.asyncio
async def test_agent_graph_nmap_scan_result_spawns_service_pivot_branches():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=30)
    loop.state.ensure_branch(
        "agent:agent-0001",
        "agent_graph:recon_worker",
        "recon_worker: Map exposed services",
        priority=88,
        role="recon_worker",
        owner="agent_graph",
    )
    result = ToolResult(
        ok=True,
        summary="agent_graph: ran agent-0001 -> nmap_scan: 2 open services",
        data={
            "agent": {"id": "agent-0001"},
            "execution": {
                "tool": "nmap_scan",
                "args": {"target": "localhost", "ports": "top-1000"},
                "ok": True,
                "summary": "nmap_scan: 2 open service(s) on localhost",
                "data": {
                    "result": {
                        "ok": True,
                        "summary": "nmap_scan: 2 open service(s) on localhost",
                        "data": {
                            "target": "localhost",
                            "open_ports": [
                                {
                                    "host": "127.0.0.1",
                                    "port": "6379",
                                    "protocol": "tcp",
                                    "service": "redis",
                                    "product": "Redis key-value store",
                                    "reason": "syn-ack",
                                },
                                {
                                    "host": "127.0.0.1",
                                    "port": "80",
                                    "protocol": "tcp",
                                    "service": "http",
                                    "product": "nginx",
                                    "reason": "syn-ack",
                                },
                            ],
                        },
                        "error": None,
                    }
                },
            },
        },
    )

    promoted = await loop._credit_agent_graph_child_execution(
        result,
        skills_completed=set(),
        real_skills_completed=set(),
    )

    redis_branch = loop.state.branches["agent:agent-0001:svc:tcp-6379"]
    http_branch = loop.state.branches["agent:agent-0001:svc:tcp-80"]
    assert promoted is True
    assert redis_branch.status == "open"
    assert redis_branch.priority == 96
    assert redis_branch.role == "exploit_worker"
    assert "database service" in redis_branch.objective
    assert "nmap_scan" in redis_branch.next_step
    assert http_branch.role == "recon_worker"
    assert loop.state.scan_todos[redis_branch.id].status == "pending"
    assert any("nmap service pivot" in str(note) for note in loop.state.shared_notes)


def test_service_pivot_branch_forces_agent_graph_worker_create():
    reg = ToolRegistry()
    reg.register(AgentGraphTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)
    branch = loop.state.ensure_branch(
        "agent:agent-0001:svc:tcp-6379",
        "NET-SERVICE-PIVOT",
        "Probe redis Redis key-value store on 127.0.0.1:6379/tcp",
        priority=96,
        role="exploit_worker",
        owner="root",
        objective="Determine whether the database service exposes unauthenticated access.",
        next_step="Create an exploit_worker and use nmap_scan safe/vuln scripts.",
        crown_jewel="database data exposure or credential material",
        evidence="nmap_scan 127.0.0.1:6379/tcp redis Redis key-value store",
        watch_terms=["nmap_scan", "6379", "redis", "database"],
    )

    forced = loop._forced_branch_action(branch)

    assert forced is not None
    assert forced[0] == "agent_graph"
    assert forced[1]["action"] == "create"
    assert forced[1]["role"] == "exploit_worker"
    assert forced[1]["skills"] == ["test_infra"]
    assert "nmap_scan" in forced[1]["message"]


def test_control_plane_service_pivot_prefers_exploit_worker():
    reg = ToolRegistry()
    reg.register(AgentGraphTool())
    loop = ScanAgentLoop(target="https://cluster.local", registry=reg, max_iters=30)
    branch = loop.state.ensure_branch(
        "agent:agent-0001:svc:tcp-8080",
        "NET-SERVICE-PIVOT",
        "Probe http Jenkins on 10.0.0.5:8080/tcp",
        priority=94,
        role="exploit_worker",
        owner="root",
        objective="Validate exposed control-plane/admin service.",
        next_step="Create an exploit_worker and test only safe unauth/admin/API probes.",
        crown_jewel="control-plane takeover or admin data access",
        evidence="nmap_scan 10.0.0.5:8080/tcp http Jenkins",
        watch_terms=["nmap_scan", "8080", "http", "jenkins", "control-plane", "api"],
    )

    forced = loop._forced_branch_action(branch)

    assert forced is not None
    assert forced[1]["role"] == "exploit_worker"
    assert forced[1]["skills"] == ["test_api_security", "test_misconfig"]
    assert "target=10.0.0.5 ports=8080 scripts=default,safe,vuln" in forced[1]["message"]


def test_service_pivot_surfaces_in_dashboard_and_control_plane():
    events: list[tuple[str, dict]] = []
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=ToolRegistry(),
        max_iters=30,
        event_callback=lambda event_type, data: events.append((event_type, data)),
    )
    branch = loop.state.ensure_branch(
        "agent:agent-0001:svc:tcp-6379",
        "NET-SERVICE-PIVOT",
        "Probe redis Redis key-value store on 127.0.0.1:6379/tcp",
        priority=96,
        role="exploit_worker",
        owner="root",
        objective="Determine whether the database service exposes unauthenticated access.",
        next_step="Create an exploit_worker and use nmap_scan safe/vuln scripts.",
        crown_jewel="database data exposure or credential material",
        evidence="nmap_scan 127.0.0.1:6379/tcp redis Redis key-value store",
        watch_terms=["nmap_scan", "6379", "redis", "database"],
    )
    branch.status = "open"

    dashboard = loop._build_scan_dashboard()
    loop._emit_control_plane("service pivot ready")
    control_events = [data for event_type, data in events if event_type == "control_plane"]

    assert "Service pivots:" in dashboard
    assert "tcp-6379" in dashboard
    assert control_events[-1]["service_pivots"][0]["id"] == branch.id
    assert "redis" in control_events[-1]["service_pivots"][0]["evidence"]


@pytest.mark.asyncio
async def test_nmap_service_pivot_golden_chain_reaches_bounded_blocker():
    reg = ToolRegistry()
    graph = AgentGraphTool()
    reg.register(graph)

    class _NmapScan:
        name = "nmap_scan"
        description = "bounded nmap"
        input_schema = {"type": "object"}

        def __init__(self) -> None:
            self.calls: list[dict] = []

        async def run(self, **kwargs):
            self.calls.append(dict(kwargs))
            return ToolResult(
                ok=True,
                summary="nmap_scan: 1 open service on 127.0.0.1",
                data={
                    "target": str(kwargs.get("target") or "127.0.0.1"),
                    "open_count": 1,
                    "open_ports": [
                        {
                            "host": "127.0.0.1",
                            "port": "6379",
                            "protocol": "tcp",
                            "service": "redis",
                            "product": "Redis key-value store",
                            "reason": "syn-ack",
                        }
                    ],
                },
            )

    nmap_scan = _NmapScan()
    reg.register(nmap_scan)
    loop = ScanAgentLoop(target="127.0.0.1", registry=reg, max_iters=30)

    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "recon_worker",
            "task": "Map exposed services with nmap before choosing deeper probes",
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "recon_worker"},
        result=created,
    )
    first_run = await reg.dispatch(
        "agent_graph",
        {"action": "run", "agent_id": created.data["agent"]["id"]},
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "run", "agent_id": created.data["agent"]["id"]},
        result=first_run,
    )
    await loop._credit_agent_graph_child_execution(
        first_run,
        skills_completed=set(),
        real_skills_completed=set(),
    )

    service_branch = loop.state.branches["agent:agent-0001:svc:tcp-6379"]
    forced_create = loop._forced_branch_action(service_branch)
    assert forced_create is not None
    service_created = await reg.dispatch(*forced_create)
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args=forced_create[1],
        result=service_created,
    )
    service_agent_id = service_created.data["agent"]["id"]
    service_run = await reg.dispatch(
        "agent_graph",
        {"action": "run", "agent_id": service_agent_id},
    )
    service_finish = await reg.dispatch(
        "agent_graph",
        {
            "action": "finish",
            "agent_id": service_agent_id,
            "status": "blocked",
            "result": "Redis service was reachable, but no safe unauthenticated data proof was obtained.",
        },
    )

    assert first_run.ok is True
    assert service_created.ok is True
    assert service_run.ok is True
    assert service_finish.ok is True
    assert nmap_scan.calls[0]["ports"] == "top-1000"
    assert nmap_scan.calls[1]["target"] == "127.0.0.1"
    assert nmap_scan.calls[1]["ports"] == "6379"
    assert nmap_scan.calls[1]["scripts"] == "default,safe,vuln"
    assert service_finish.data["agent"]["status"] == "blocked"


@pytest.mark.asyncio
async def test_agent_graph_worker_llm_invalid_json_repairs_to_valid_action():
    reg = ToolRegistry()
    graph = AgentGraphTool()
    reg.register(graph)

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):
            return ToolResult(
                ok=True,
                summary="confirmed SQL injection with control/payload delta",
                data={
                    "proof_artifact": {
                        "claim": "SQL injection on /api/search",
                        "target": "http://localhost:3000/api/search",
                        "control": {"request": "GET /api/search?q=test", "response_status": 200},
                        "payload": {"request": "GET /api/search?q='", "response_status": 500},
                        "observed_delta": "control 200 vs payload 500",
                        "repro_steps": ["send control", "send payload", "compare status"],
                    }
                },
            )

    reg.register(_RunSkill())
    brain = WorkerPlannerBrain(
        responses=[
            "not json",
            json.dumps(
                {
                    "tool": "run_skill",
                    "args": {
                        "skill": "test_injection",
                        "target_url": "http://localhost:3000",
                        "params": {},
                    },
                    "evidence_intent": "collect control/payload delta for EvidenceArtifact",
                }
            ),
        ]
    )
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=30,
        brain=brain,
    )
    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Validate SQL injection on /api/search",
            "skills": ["test_injection"],
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=created,
    )

    ran = await reg.dispatch(
        "agent_graph",
        {"action": "run", "agent_id": created.data["agent"]["id"]},
    )

    planner = ran.data["execution"]["data"]["planner"]
    assert ran.ok is True
    assert planner["source"] == "worker_llm"
    assert planner["repair_attempted"] is True
    assert planner["repair_succeeded"] is True
    assert planner["initial_failure_reason"] == "invalid_json"
    assert len(brain.calls) == 2
    assert "failure_reason=invalid_json" in brain.calls[1]["user"]


@pytest.mark.asyncio
async def test_agent_graph_worker_llm_repair_fails_once_then_deterministic_fallback():
    reg = ToolRegistry()
    graph = AgentGraphTool()
    reg.register(graph)
    runner = RunSkillTool()
    reg.register(runner)
    brain = WorkerPlannerBrain(responses=["not json", "{bad"])
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=30,
        brain=brain,
    )
    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Validate SQL injection on /api/search",
            "skills": ["test_injection"],
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=created,
    )

    ran = await reg.dispatch(
        "agent_graph",
        {"action": "run", "agent_id": created.data["agent"]["id"]},
    )

    planner = ran.data["execution"]["data"]["planner"]
    assert ran.ok is True
    assert runner.calls
    assert planner["source"] == "deterministic_fallback"
    assert planner["fallback_reason"] == "invalid_json"
    assert planner["repair_attempted"] is True
    assert planner["repair_succeeded"] is False
    assert planner["initial_failure_reason"] == "invalid_json"
    assert planner["repair_failure_reason"] == "invalid_json"
    assert len(brain.calls) == 2
    metrics = loop._agent_graph_worker_planner_metrics
    assert metrics["fallbacks"] == 1
    assert metrics["repairs"] == 1
    assert metrics["repair_failures"] == 1


@pytest.mark.asyncio
async def test_agent_graph_worker_llm_unavailable_repeated_fallback_surfaces_health():
    reg = ToolRegistry()
    graph = AgentGraphTool()
    reg.register(graph)

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):
            return ToolResult(
                ok=True,
                summary="confirmed SQL injection with control/payload delta",
                data={
                    "proof_artifact": {
                        "claim": "SQL injection on /api/search",
                        "target": "http://localhost:3000/api/search",
                        "control": {"request": "GET /api/search?q=test", "response_status": 200},
                        "payload": {"request": "GET /api/search?q='", "response_status": 500},
                        "observed_delta": "control 200 vs payload 500",
                        "repro_steps": ["send control", "send payload", "compare status"],
                    }
                },
            )

    reg.register(_RunSkill())
    brain = WorkerPlannerBrain(unavailable=True)
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=30,
        brain=brain,
    )
    latest = None
    for idx in range(3):
        created = await reg.dispatch(
            "agent_graph",
            {
                "action": "create",
                "role": "exploit_worker",
                "task": f"Validate SQL injection on /api/search unavailable-{idx}",
                "skills": ["test_injection"],
            },
        )
        loop._sync_agent_graph_result_to_branches(
            name="agent_graph",
            args={"action": "create", "role": "exploit_worker"},
            result=created,
        )
        latest = await reg.dispatch(
            "agent_graph",
            {"action": "run", "agent_id": created.data["agent"]["id"]},
        )

    assert latest is not None
    planner = latest.data["execution"]["data"]["planner"]
    assert planner["source"] == "deterministic_fallback"
    assert planner["fallback_reason"] == "worker_llm_empty_response"
    assert planner["fallback_count"] == 3
    assert planner["health"] == "local_worker_unavailable"
    assert any("local worker unavailable" in note for note in loop.state.shared_notes)

    loop.state.add_message(
        "tool",
        {
            "name": "agent_graph",
            "args": {"action": "run", "agent_id": latest.data["agent"]["id"]},
            "result": {
                "ok": latest.ok,
                "summary": latest.summary,
                "data": latest.data,
            },
        },
    )
    dashboard = loop._build_scan_dashboard()
    assert "Worker planner quality: success=0/3 repair=0/0 fallback=3 unavailable=3" in dashboard
    assert "planner: deterministic_fallback reason=worker_llm_empty_response" in dashboard
    assert "health=local_worker_unavailable" in dashboard


def test_agent_graph_worker_planner_prompt_fits_local_budget_and_preserves_artifact_fields():
    reg = ToolRegistry()
    reg.register(AgentGraphTool())
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=30,
        brain=WorkerPlannerBrain(),
    )
    agent = {
        "id": "agent-large",
        "role": "exploit_worker",
        "task": "Validate SQL injection on /api/search " + ("noise " * 1200),
        "skills": ["test_injection"],
        "skill_context": "run_skill contract " + ("context " * 1600),
        "task_envelope": {
            "objective": "Validate SQL injection and return concrete proof " + ("objective " * 900),
            "expected_artifact": "EvidenceArtifact with control and payload comparison",
            "stop_condition": "stop after one bounded proof attempt",
            "escalation_trigger": "escalate if proof is ambiguous",
        },
        "result_package": {
            "evidence_artifact": {
                "schema": "vxis.agent_graph.evidence_artifact.v1",
                "claim": "SQL injection",
                "target": "http://localhost:3000/api/search",
                "control": {"request": "GET /api/search?q=test", "body": "A" * 5000},
                "payload": {"request": "GET /api/search?q='", "body": "B" * 5000},
                "observed_delta": "status delta",
                "repro_steps": ["send control", "send payload", "compare"],
                "valid": True,
            }
        },
        "messages": [
            {"sender": "root", "body": "old message " + ("M" * 4000)}
            for _ in range(8)
        ],
        "executions": [
            {"tool": "run_skill", "summary": "old execution " + ("E" * 5000)}
            for _ in range(8)
        ],
    }

    system_prompt, user_prompt, budget = loop._agent_graph_worker_planner_prompts(
        agent,
        "Use the sharpest bounded proof.",
        allowed_child_tools={"run_skill", "http_request"},
    )
    rendered = system_prompt + "\n" + user_prompt

    assert estimate_context_tokens(rendered) <= budget.max_prompt_tokens
    assert "WORKER-CONTEXT COMPACTION" in rendered
    for field in ("claim", "target", "control", "payload", "observed_delta", "repro_steps"):
        assert field in rendered
    assert "EvidenceArtifact" in rendered


@pytest.mark.asyncio
async def test_agent_graph_worker_llm_planner_respects_local_concurrency(monkeypatch):
    monkeypatch.setenv("VXIS_LOCAL_WORKER_CONCURRENCY", "1")
    reg = ToolRegistry()
    graph = AgentGraphTool()
    reg.register(graph)

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):
            return ToolResult(
                ok=True,
                summary="confirmed SQL injection with control/payload delta",
                data={
                    "proof_artifact": {
                        "claim": "SQL injection on /api/search",
                        "target": "http://localhost:3000/api/search",
                        "control": {"request": "GET /api/search?q=test", "response_status": 200},
                        "payload": {"request": "GET /api/search?q='", "response_status": 500},
                        "observed_delta": "control 200 vs payload 500",
                        "repro_steps": ["send control", "send payload", "compare status"],
                    }
                },
            )

    reg.register(_RunSkill())
    brain = WorkerPlannerBrain(delay=0.03)
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=30,
        brain=brain,
    )
    agent_ids: list[str] = []
    for suffix in ("one", "two"):
        created = await reg.dispatch(
            "agent_graph",
            {
                "action": "create",
                "role": "exploit_worker",
                "task": f"Validate SQL injection on /api/search {suffix}",
                "skills": ["test_injection"],
            },
        )
        loop._sync_agent_graph_result_to_branches(
            name="agent_graph",
            args={"action": "create", "role": "exploit_worker"},
            result=created,
        )
        agent_ids.append(created.data["agent"]["id"])

    results = await asyncio.gather(
        *[
            reg.dispatch("agent_graph", {"action": "run", "agent_id": agent_id})
            for agent_id in agent_ids
        ]
    )

    assert all(result.ok for result in results)
    assert len(brain.calls) == 2
    assert brain.max_active == 1


@pytest.mark.asyncio
async def test_agent_graph_positive_finish_without_child_execution_keeps_branch_active():
    reg = ToolRegistry()
    reg.register(AgentGraphTool())

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")

    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)

    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Validate SQL injection on /search",
            "skills": ["test_injection"],
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=created,
    )

    rejected = await reg.dispatch(
        "agent_graph",
        {
            "action": "finish",
            "agent_id": created.data["agent"]["id"],
            "result": "Confirmed vulnerable SQL injection on /search with status delta evidence.",
        },
    )
    assert rejected.ok is False
    assert rejected.error == "missing_execution_evidence"
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "finish", "agent_id": created.data["agent"]["id"]},
        result=rejected,
    )

    branch = loop.state.branches["agent:agent-0001"]
    assert branch.status == "active"
    assert "positive vulnerability result" in branch.last_summary
    assert loop._forced_branch_action(branch) == (
        "agent_graph",
        {"action": "run", "agent_id": "agent-0001"},
    )


@pytest.mark.asyncio
async def test_agent_graph_unsupported_positive_finish_reforces_child_run():
    reg = ToolRegistry()
    reg.register(AgentGraphTool())

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):
            return ToolResult(
                ok=True,
                summary="mapped /login and /api/products",
                data={"evidence": "route map only"},
            )

    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)

    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "recon_worker",
            "task": "Map API surface around /search",
            "skills": ["enumerate_endpoints"],
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=created,
    )
    agent_id = created.data["agent"]["id"]

    ran = await reg.dispatch("agent_graph", {"action": "run", "agent_id": agent_id})
    assert ran.ok is True
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "run", "agent_id": agent_id},
        result=ran,
    )
    branch = loop.state.branches["agent:agent-0001"]
    assert "Successful child execution is available" in branch.next_step
    assert loop._forced_branch_action(branch) is None

    rejected = await reg.dispatch(
        "agent_graph",
        {
            "action": "finish",
            "agent_id": agent_id,
            "result": "Confirmed vulnerable SQL injection on /search with status delta evidence.",
        },
    )
    assert rejected.ok is False
    assert rejected.error == "unsupported_execution_evidence"
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "finish", "agent_id": agent_id},
        result=rejected,
    )

    branch = loop.state.branches["agent:agent-0001"]
    assert "Run child evidence that matches the positive claim" in branch.next_step
    assert "not supported by the successful child execution history" in branch.blocker
    assert loop._forced_branch_action(branch) == (
        "agent_graph",
        {"action": "run", "agent_id": agent_id},
    )


@pytest.mark.asyncio
async def test_agent_graph_insufficient_proof_finish_reforces_child_run():
    reg = ToolRegistry()
    reg.register(AgentGraphTool())

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):
            return ToolResult(
                ok=True,
                summary="confirmed sql injection on search",
                data={"note": "positive summary without control pair"},
            )

    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)

    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Validate SQL injection on /search",
            "skills": ["test_injection"],
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=created,
    )
    agent_id = created.data["agent"]["id"]

    ran = await reg.dispatch("agent_graph", {"action": "run", "agent_id": agent_id})
    assert ran.ok is True
    assert ran.data["agent"]["result_package"]["verdict_guess"] == "needs_proof"
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "run", "agent_id": agent_id},
        result=ran,
    )
    branch = loop.state.branches["agent:agent-0001"]
    assert "valid EvidenceArtifact" in branch.next_step
    assert "Evidence gap:" in branch.blocker
    forced = loop._forced_branch_action(branch)
    assert forced is not None
    assert forced[0] == "agent_graph"
    assert forced[1]["action"] == "run"
    assert forced[1]["agent_id"] == agent_id
    assert "Evidence gap:" in forced[1]["instruction"]

    rejected = await reg.dispatch(
        "agent_graph",
        {
            "action": "finish",
            "agent_id": agent_id,
            "result": "Confirmed vulnerable SQL injection on /search.",
        },
    )
    assert rejected.ok is False
    assert rejected.error == "insufficient_proof_artifact"
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "finish", "agent_id": agent_id},
        result=rejected,
    )

    branch = loop.state.branches["agent:agent-0001"]
    assert "concrete PoC/control evidence" in branch.next_step
    assert "requires a concrete PoC/control artifact" in branch.blocker
    forced = loop._forced_branch_action(branch)
    assert forced is not None
    assert forced[0] == "agent_graph"
    assert forced[1]["action"] == "run"
    assert forced[1]["agent_id"] == agent_id


@pytest.mark.asyncio
async def test_agent_graph_evidence_gap_retry_then_valid_artifact_allows_crown_chain():
    reg = ToolRegistry()
    reg.register(AgentGraphTool())

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        def __init__(self) -> None:
            self.calls: list[dict] = []

        async def run(self, **kwargs):
            self.calls.append(dict(kwargs))
            if len(self.calls) == 1:
                return ToolResult(
                    ok=True,
                    summary="confirmed sql injection on search",
                    data={"note": "positive summary without control pair"},
                )
            return ToolResult(
                ok=True,
                summary="confirmed sql injection exposes session token material",
                data={
                    "proof_artifact": {
                        "claim": "SQL injection on /search exposes session token material",
                        "target": "http://localhost:3000/search",
                        "control": {
                            "request": "GET /search?q=test",
                            "response_status": 200,
                            "response_excerpt": "normal search results",
                        },
                        "payload": {
                            "request": "GET /search?q='",
                            "response_status": 500,
                            "response_excerpt": "SQL error includes session token column",
                        },
                        "observed_delta": (
                            "control HTTP 200 vs payload HTTP 500 with token-bearing SQL error"
                        ),
                        "repro_steps": [
                            "send negative control request",
                            "send payload request",
                            "send payload request again",
                            "compare status and token-bearing SQL error body",
                        ],
                        "repeat_count": 2,
                        "negative_control": {
                            "request": "GET /search?q=test",
                            "response_status": 200,
                            "response_excerpt": "normal search results; no SQL error and no token",
                        },
                        "source_output": "SQL error includes session token column",
                        "source_output_used_in_pivot": True,
                        "crown_jewel_evidence": "Session token column exposed through SQL error output.",
                    }
                },
            )

    runner = _RunSkill()
    reg.register(runner)
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)

    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Validate SQL injection on /search",
            "skills": ["test_injection"],
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=created,
    )
    agent_id = created.data["agent"]["id"]

    first = await reg.dispatch("agent_graph", {"action": "run", "agent_id": agent_id})
    gap = first.data["agent"]["result_package"]["evidence_gap"]
    assert gap["status"] == "needs_more_evidence"
    assert gap["repeat_count"] == 1
    assert "control" in gap["gap_fields"]
    assert "payload" in gap["gap_fields"]
    assert "Evidence gap:" in gap["next_instruction"]
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "run", "agent_id": agent_id},
        result=first,
    )
    forced = loop._forced_branch_action(loop.state.branches["agent:agent-0001"])
    assert forced is not None
    assert forced[0] == "agent_graph"
    assert forced[1]["agent_id"] == agent_id
    assert "instruction" in forced[1]
    assert "Evidence gap:" in forced[1]["instruction"]

    second = await reg.dispatch(forced[0], forced[1])
    assert second.ok is True
    assert second.data["agent"]["result_package"]["evidence_artifact"]["valid"] is True
    loop._sync_agent_graph_result_to_branches(
        name=forced[0],
        args=forced[1],
        result=second,
    )
    branch = loop.state.branches["agent:agent-0001"]
    assert "Valid EvidenceArtifact is available" in branch.next_step

    finished = await reg.dispatch(
        "agent_graph",
        {
            "action": "finish",
            "agent_id": agent_id,
            "result": "Confirmed SQL injection on /search exposes session token material.",
        },
    )
    assert finished.ok is True
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "finish", "agent_id": agent_id},
        result=finished,
    )

    assert loop.state.branches["agent:agent-0001"].status == "proven"
    assert "agent:agent-0001:crown-chain" in loop.state.branches
    assert runner.calls and len(runner.calls) == 2


@pytest.mark.asyncio
async def test_agent_graph_repeated_evidence_gap_stops_automatic_retry():
    reg = ToolRegistry()
    reg.register(AgentGraphTool())

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):
            return ToolResult(
                ok=True,
                summary="confirmed sql injection on search",
                data={"note": "positive summary without control pair"},
            )

    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)
    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Validate SQL injection on /search",
            "skills": ["test_injection"],
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=created,
    )
    agent_id = created.data["agent"]["id"]

    first = await reg.dispatch("agent_graph", {"action": "run", "agent_id": agent_id})
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "run", "agent_id": agent_id},
        result=first,
    )
    forced = loop._forced_branch_action(loop.state.branches["agent:agent-0001"])
    assert forced is not None

    second = await reg.dispatch(forced[0], forced[1])
    assert second.data["agent"]["escalation"]["status"] == "blocked_with_reason"
    assert second.data["agent"]["result_package"]["evidence_gap"]["repeat_count"] == 2
    loop._sync_agent_graph_result_to_branches(
        name=forced[0],
        args=forced[1],
        result=second,
    )

    branch = loop.state.branches["agent:agent-0001"]
    assert "same EvidenceArtifact gap repeated" in branch.blocker
    assert "create a narrower worker" in branch.next_step
    assert loop._forced_branch_action(branch) is None


def test_agent_graph_branch_declared_skill_forces_run_skill_action():
    reg = ToolRegistry()

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")

    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)
    result = ToolResult(
        ok=True,
        summary="agent_graph: created agent-0001 (exploit_worker)",
        data={
            "agent": {
                "id": "agent-0001",
                "role": "exploit_worker",
                "task": "Validate injection against the product search route",
                "status": "running",
                "parent_id": None,
                "skills": ["test_injection"],
                "result": "",
                "created_at": "2026-05-22T00:00:00+00:00",
                "updated_at": "2026-05-22T00:00:00+00:00",
                "message_count": 1,
            }
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=result,
    )

    forced = loop._forced_branch_action(loop.state.branches["agent:agent-0001"])
    assert forced is not None
    tool_name, args = forced
    assert tool_name == "run_skill"
    assert args["skill"] == "test_injection"
    assert args["target_url"] == "http://localhost:3000"
    assert args["params"]["url"].startswith("http://localhost:3000/")


def test_agent_graph_branch_prefers_protocol_run_when_tool_registered():
    reg = ToolRegistry()
    reg.register(AgentGraphTool())

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")

    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)
    result = ToolResult(
        ok=True,
        summary="agent_graph: created agent-0001 (exploit_worker)",
        data={
            "agent": {
                "id": "agent-0001",
                "role": "exploit_worker",
                "task": "Validate SQL injection against search",
                "status": "running",
                "parent_id": None,
                "skills": ["test_injection"],
                "result": "",
                "created_at": "2026-05-22T00:00:00+00:00",
                "updated_at": "2026-05-22T00:00:00+00:00",
                "message_count": 1,
            }
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=result,
    )

    forced = loop._forced_branch_action(loop.state.branches["agent:agent-0001"])
    assert forced == ("agent_graph", {"action": "run", "agent_id": "agent-0001"})
    loop.state.branches["agent:agent-0001"].priority = 99
    dashboard = loop._build_scan_dashboard()
    assert 'Forced next action: agent_graph(action="run", agent_id="agent-0001")' in dashboard


def test_agent_graph_branch_stops_forcing_run_after_limit_blocker():
    reg = ToolRegistry()
    reg.register(AgentGraphTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)
    branch = loop.state.ensure_branch(
        "agent:agent-0001",
        "agent_graph:exploit_worker",
        "exploit_worker: Validate SQL injection",
        priority=92,
        role="exploit_worker",
        owner="agent_graph",
        objective="Validate SQL injection",
        next_step="Use skill/tool path: test_injection; then finish this delegated agent with a concrete result.",
        watch_terms=["agent-0001", "test_injection"],
    )
    branch.blocker = "agent_graph run: agent-0001 reached the child-run limit (3)"
    assert loop._forced_branch_action(branch) is None


@pytest.mark.asyncio
async def test_agent_graph_branch_stops_forcing_run_after_no_child_action():
    reg = ToolRegistry()
    reg.register(AgentGraphTool())

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):  # pragma: no cover - should not be selected
            return ToolResult(ok=True, summary="ok")

    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)

    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "review_worker",
            "task": "Assess ambiguous delegated note without a concrete probe",
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "review_worker"},
        result=created,
    )

    ran = await reg.dispatch(
        "agent_graph",
        {"action": "run", "agent_id": created.data["agent"]["id"]},
    )
    assert ran.ok is False
    assert ran.error == "no_child_action"
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "run", "agent_id": created.data["agent"]["id"]},
        result=ran,
    )

    branch = loop.state.branches["agent:agent-0001"]
    assert "no executable step" in branch.blocker
    assert loop._forced_branch_action(branch) is None


def test_agent_graph_branch_requires_explicit_finish_after_tool_success():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=30)
    result = ToolResult(
        ok=True,
        summary="agent_graph: created agent-0001 (exploit_worker)",
        data={
            "agent": {
                "id": "agent-0001",
                "role": "exploit_worker",
                "task": "Validate IDOR and report concrete impact",
                "status": "running",
                "parent_id": None,
                "skills": ["test_idor"],
                "result": "",
                "created_at": "2026-05-22T00:00:00+00:00",
                "updated_at": "2026-05-22T00:00:00+00:00",
                "message_count": 1,
            }
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=result,
    )

    loop.state.record_branch_attempt(
        "agent:agent-0001",
        "run_skill",
        {"skill": "test_idor"},
        status="found",
        summary="confirmed IDOR on /api/orders/2",
    )

    branch = loop.state.branches["agent:agent-0001"]
    assert branch.status == "active"
    assert branch.last_tool == "run_skill"
    assert "agent:agent-0001" in {b.id for b in loop._blocking_finish_branches()}


@pytest.mark.asyncio
async def test_agent_graph_run_dispatches_declared_skill_via_scan_loop_executor():
    reg = ToolRegistry()
    graph = AgentGraphTool()
    reg.register(graph)

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        def __init__(self) -> None:
            self.calls: list[dict] = []

        async def run(self, **kwargs):
            self.calls.append(dict(kwargs))
            return ToolResult(
                ok=True,
                summary="confirmed injection signal on search route",
                data={
                    "proof_artifact": {
                        "claim": "SQL injection on /search",
                        "target": "http://localhost:3000/search",
                        "control": {
                            "request": "GET /search?q=test",
                            "response_status": 200,
                            "response_excerpt": "normal search results",
                        },
                        "payload": {
                            "request": "GET /search?q='",
                            "response_status": 500,
                            "response_excerpt": "SQL syntax error",
                        },
                        "observed_delta": "control HTTP 200 vs payload HTTP 500 with SQL error",
                        "repro_steps": [
                            "send control request",
                            "send payload request",
                            "compare status and body",
                        ],
                    }
                },
            )

    run_skill = _RunSkill()
    reg.register(run_skill)
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)

    created = await reg.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Validate SQL injection against search",
            "skills": ["test_injection"],
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create", "role": "exploit_worker"},
        result=created,
    )
    agent_id = created.data["agent"]["id"]

    ran = await reg.dispatch("agent_graph", {"action": "run", "agent_id": agent_id})
    assert ran.ok is True
    assert run_skill.calls
    assert run_skill.calls[0]["skill"] == "test_injection"
    assert ran.data["execution"]["tool"] == "run_skill"
    assert "artifact_schema=EvidenceArtifact" in ran.data["execution"]["data"]["instruction"]
    assert ran.data["agent"]["status"] == "waiting"
    assert ran.data["agent"]["execution_count"] == 1

    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "run", "agent_id": agent_id},
        result=ran,
    )
    branch = loop.state.branches["agent:agent-0001"]
    assert branch.status == "active"
    assert "confirmed injection signal" in branch.last_summary
    assert "Valid EvidenceArtifact is available" in branch.next_step
    assert loop._forced_branch_action(branch) is None
    assert "agent:agent-0001" in {b.id for b in loop._blocking_finish_branches()}


@pytest.mark.asyncio
async def test_agent_graph_child_run_skill_result_gets_vector_credit():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=30)
    result = ToolResult(
        ok=True,
        summary="agent_graph: ran agent-0001 -> run_skill: confirmed sql injection",
        data={
            "execution": {
                "id": "exec-0001",
                "tool": "run_skill",
                "args": {
                    "skill": "test_injection",
                    "target_url": "http://localhost:3000",
                    "params": {"url": "http://localhost:3000/search?q=test"},
                },
                "ok": True,
                "summary": "run_skill: confirmed sql injection",
                "data": {
                    "tool": "run_skill",
                    "args": {
                        "skill": "test_injection",
                        "target_url": "http://localhost:3000",
                        "params": {"url": "http://localhost:3000/search?q=test"},
                    },
                    "result": {
                        "ok": True,
                        "summary": "confirmed sql injection on search",
                        "data": {},
                        "error": None,
                    },
                },
                "error": None,
            }
        },
    )
    skills_completed: set[str] = set()
    real_skills_completed: set[str] = set()

    credited = await loop._credit_agent_graph_child_execution(
        result,
        skills_completed=skills_completed,
        real_skills_completed=real_skills_completed,
    )

    assert credited is True
    assert skills_completed == {"test_injection"}
    assert real_skills_completed == {"test_injection"}
    sqli_attempts = [
        item for item in loop.state.attempt_outcomes if item.candidate_id == "web:sqli"
    ]
    assert sqli_attempts
    assert sqli_attempts[-1].tool == "run_skill"
    assert sqli_attempts[-1].status == "found"


@pytest.mark.asyncio
async def test_scan_loop_runs_agent_graph_create_run_finish_end_to_end():
    reg = ToolRegistry()
    graph = AgentGraphTool()
    reg.register(graph)

    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}

        def __init__(self) -> None:
            self.calls: list[dict] = []

        async def run(self, **kwargs):
            self.calls.append(dict(kwargs))
            return ToolResult(
                ok=True,
                summary="confirmed injection signal on search route",
                data={
                    "proof_artifact": {
                        "claim": "SQL injection on /search",
                        "target": "http://localhost:3000/search",
                        "control": {
                            "request": "GET /search?q=test",
                            "response_status": 200,
                            "response_excerpt": "normal search results",
                        },
                        "payload": {
                            "request": "GET /search?q='",
                            "response_status": 500,
                            "response_excerpt": "SQL syntax error",
                        },
                        "observed_delta": "control HTTP 200 vs payload HTTP 500 with SQL error",
                        "repro_steps": [
                            "send control request",
                            "send payload request",
                            "compare status and body",
                        ],
                    }
                },
            )

    run_skill = _RunSkill()
    reg.register(run_skill)

    brain = SimpleNamespace(
        _provider="openai",
        _model="gpt-5.4",
        think_in_loop=AsyncMock(
            side_effect=[
                [
                    (
                        "agent_graph",
                        {
                            "action": "create",
                            "role": "post_exploit_worker",
                            "task": "Validate SQL injection and token impact on /search",
                            "skills": ["test_injection"],
                        },
                    )
                ],
                [("agent_graph", {"action": "run", "agent_id": "agent-0001"})],
                [
                    (
                        "agent_graph",
                        {
                            "action": "finish",
                            "agent_id": "agent-0001",
                            "result": "Confirmed vulnerable SQL injection signal on /search with status delta evidence.",
                        },
                    )
                ],
            ]
        ),
    )
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        brain=brain,
        max_iters=3,
    )

    result = await loop.run()

    assert brain.think_in_loop.await_count == 3
    assert run_skill.calls
    assert run_skill.calls[0]["skill"] == "test_injection"

    branch = loop.state.branches["agent:agent-0001"]
    assert branch.owner == "agent_graph"
    assert branch.status == "proven"
    assert "agent:agent-0001" not in {b.id for b in loop._blocking_finish_branches()}

    graph_messages = [
        message
        for message in loop.state.messages
        if isinstance(message.get("content"), dict)
        and message["content"].get("name") == "agent_graph"
    ]
    assert len(graph_messages) == 3
    run_message = graph_messages[1]["content"]["result"]
    assert run_message["data"]["execution"]["tool"] == "run_skill"
    assert run_message["data"]["execution"]["args"]["skill"] == "test_injection"

    assert "test_injection" in result["skills_completed"]
    sqli_attempts = [
        item
        for item in result["attempt_outcomes"]
        if item["candidate_id"] == "web:sqli" and item["tool"] == "run_skill"
    ]
    assert sqli_attempts
    assert sqli_attempts[-1]["status"] == "found"
