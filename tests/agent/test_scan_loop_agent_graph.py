import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.agent.tools.agent_graph_tools import AgentGraphTool
from vxis.agent.tools.finding_tools import _reset_for_tests as _reset_findings


class RunSkillTool:
    name = "run_skill"
    description = "execute prebuilt skill"
    input_schema = {"type": "object"}

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def run(self, **kwargs) -> ToolResult:
        self.calls.append(dict(kwargs))
        return ToolResult(ok=True, summary=f"ran skill {kwargs.get('skill', '?')}", data={})


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


def test_scan_dashboard_includes_agent_graph_snapshot():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.brain = SimpleNamespace(_provider="openai", _model="gpt-5.5")
    loop.state.add_message("tool", {
        "name": "agent_graph",
        "args": {"action": "create", "role": "recon_worker", "task": "Map auth and API surface"},
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
    })
    dashboard = loop._build_scan_dashboard()
    assert "Agent graph:" in dashboard
    assert "agent-0001" in dashboard
    assert "Map auth and API surface" in dashboard
    assert "last_run: run_skill ok: mapped /login and /api/products" in dashboard
    assert 'agent_graph(action="finish", agent_id="agent-0001", result="...")' in dashboard


def test_scan_dashboard_surfaces_director_worker_exchange():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.brain = SimpleNamespace(_provider="openai", _model="gpt-5.5")
    loop.state.add_message("tool", {
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
                        "action: run_skill(skill=\"test_injection\", target_url=<target>, params={...})\n"
                        "validate: require baseline/control/payload delta"
                    ),
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
    })

    dashboard = loop._build_scan_dashboard()

    assert "Director-worker exchange:" in dashboard
    assert "agent-0001 waiting exploit_worker skills=test_injection" in dashboard
    assert "director_next=finish or send sharper instruction to agent-0001" in dashboard
    assert "worker_card: action: run_skill" in dashboard


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
    assert loop._branch_ids_for_action("agent_graph", {"action": "finish", "agent_id": "agent-0001"}) == [
        "agent:agent-0001"
    ]
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
    assert loop._forced_branch_action(branch) == ("agent_graph", {"action": "run", "agent_id": "agent-0001"})


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
            "role": "exploit_worker",
            "task": "Validate SQL injection on /search",
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
    assert loop._forced_branch_action(branch) == ("agent_graph", {"action": "run", "agent_id": agent_id})


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
                data={"evidence": "status delta observed"},
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
    assert "Successful child execution is available" in branch.next_step
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
    sqli_attempts = [item for item in loop.state.attempt_outcomes if item.candidate_id == "web:sqli"]
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
                data={"evidence": "status delta observed"},
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
