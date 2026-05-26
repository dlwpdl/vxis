import pytest

from vxis.agent.tool_registry import BrainTool, ToolResult
from vxis.agent.tools import build_default_registry
from vxis.agent.tools.agent_graph_tools import AgentGraphTool


@pytest.mark.asyncio
async def test_agent_graph_conforms_to_brain_tool():
    tool = AgentGraphTool()
    assert isinstance(tool, BrainTool)
    assert tool.name == "agent_graph"
    assert tool.input_schema["required"] == ["action"]


@pytest.mark.asyncio
async def test_agent_graph_create_send_wait_finish_view_cycle():
    tool = AgentGraphTool()

    created = await tool.run(
        action="create",
        role="recon_worker",
        task="Map unauthenticated routes and identify login surface",
        skills=["enumerate_endpoints", "fingerprint_target"],
    )
    assert created.ok is True
    agent_id = created.data["agent"]["id"]
    assert agent_id == "agent-0001"
    assert created.data["agent"]["status"] == "running"
    assert created.data["agent"]["message_count"] == 1

    sent = await tool.run(
        action="send", agent_id=agent_id, message="Prioritize admin and API routes."
    )
    assert sent.ok is True
    assert sent.data["agent"]["message_count"] == 2

    waiting = await tool.run(action="wait", agent_id=agent_id, include_messages=True)
    assert waiting.ok is True
    assert waiting.data["agent"]["status"] == "running"
    assert waiting.data["note"] == "protocol_only_no_child_agent_execution"
    assert len(waiting.data["agent"]["messages"]) == 2

    finished = await tool.run(
        action="finish",
        agent_id=agent_id,
        result="Found /login and /api/products; no admin route exposed before auth.",
    )
    assert finished.ok is True
    assert finished.data["agent"]["status"] == "finished"
    assert finished.data["active_agents"] == 0

    viewed = await tool.run(action="view", include_messages=False)
    assert viewed.ok is True
    assert viewed.data["total_agents"] == 1
    assert viewed.data["agents"][0]["message_count"] == 3
    assert "messages" not in viewed.data["agents"][0]


@pytest.mark.asyncio
async def test_agent_graph_create_auto_injects_skill_context():
    tool = AgentGraphTool()

    created = await tool.run(
        action="create",
        role="exploit_worker",
        task="Validate SQL injection on /rest/products/search?q=test",
    )

    assert created.ok is True
    agent = created.data["agent"]
    assert "test_injection" in agent["skills"]
    assert "skill_context" in agent
    assert "validate:" in agent["skill_context"]
    assert 'run_skill(skill="test_injection"' in agent["skill_context"]


@pytest.mark.asyncio
async def test_agent_graph_target_kind_filters_recommended_worker_skills():
    tool = AgentGraphTool()
    tool.set_target_kind("desktop")

    created = await tool.run(
        action="create",
        role="exploit_worker",
        task="Audit macOS app entitlements and local storage secrets",
    )

    assert created.ok is True
    agent = created.data["agent"]
    assert "test_injection" not in agent["skills"]
    assert "desktop" in agent["skill_context"].lower()


@pytest.mark.asyncio
async def test_agent_graph_worker_snapshot_compacts_large_context():
    async def _executor(agent, instruction):
        return ToolResult(
            ok=True,
            summary="status delta observed " + ("A" * 5000),
            data={
                "tool": "run_skill",
                "args": {"skill": "test_injection", "payload": "B" * 5000},
                "raw": "C" * 8000,
            },
        )

    tool = AgentGraphTool(executor=_executor)
    created = await tool.run(
        action="create",
        role="exploit_worker",
        task="Validate SQL injection on /search " + ("D" * 5000),
        message="Use control and payload comparison " + ("E" * 5000),
    )
    agent_id = created.data["agent"]["id"]

    for _ in range(4):
        await tool.run(action="send", agent_id=agent_id, message="follow-up " + ("F" * 5000))
    ran = await tool.run(action="run", agent_id=agent_id)

    agent = ran.data["agent"]
    execution = ran.data["execution"]
    assert len(agent["task"]) < 900
    assert len(agent["skill_context"]) <= 720
    assert len(agent["messages"]) <= 3
    assert len(execution["summary"]) <= 1215
    assert len(str(execution["data"])) < 2500


@pytest.mark.asyncio
async def test_agent_graph_rejects_empty_create_and_empty_finish():
    tool = AgentGraphTool()

    missing_task = await tool.run(action="create", role="recon_worker")
    assert missing_task.ok is False
    assert missing_task.error == "missing_task"

    created = await tool.run(
        action="create", role="review_worker", task="Review current finding evidence"
    )
    agent_id = created.data["agent"]["id"]
    missing_result = await tool.run(action="finish", agent_id=agent_id)
    assert missing_result.ok is False
    assert missing_result.error == "missing_result"


@pytest.mark.asyncio
async def test_agent_graph_rejects_positive_finish_without_child_execution():
    tool = AgentGraphTool()
    created = await tool.run(
        action="create",
        role="exploit_worker",
        task="Validate SQL injection on /search",
        skills=["test_injection"],
    )
    agent_id = created.data["agent"]["id"]

    rejected = await tool.run(
        action="finish",
        agent_id=agent_id,
        result="Confirmed vulnerable SQL injection on /search with status delta evidence.",
    )

    assert rejected.ok is False
    assert rejected.error == "missing_execution_evidence"
    assert rejected.data["agent"]["status"] == "running"
    assert rejected.data["active_agents"] == 1


@pytest.mark.asyncio
async def test_agent_graph_rejects_positive_finish_after_only_failed_child_execution():
    async def _executor(agent, instruction):
        return ToolResult(
            ok=False,
            summary="run_skill: blocked before evidence",
            data={"tool": "run_skill", "args": {"skill": "test_injection"}},
            error="blocked",
        )

    tool = AgentGraphTool(executor=_executor)
    created = await tool.run(
        action="create",
        role="exploit_worker",
        task="Validate SQL injection on /search",
        skills=["test_injection"],
    )
    agent_id = created.data["agent"]["id"]

    ran = await tool.run(action="run", agent_id=agent_id)
    assert ran.ok is False
    assert ran.data["agent"]["execution_count"] == 1

    rejected = await tool.run(
        action="finish",
        agent_id=agent_id,
        result="Confirmed vulnerable SQL injection on /search with status delta evidence.",
    )

    assert rejected.ok is False
    assert rejected.error == "missing_execution_evidence"
    assert rejected.data["agent"]["status"] == "waiting"
    assert rejected.data["active_agents"] == 1


@pytest.mark.asyncio
async def test_agent_graph_rejects_positive_finish_with_unrelated_successful_execution():
    async def _executor(agent, instruction):
        return ToolResult(
            ok=True,
            summary="run_skill: mapped /login and /api/products",
            data={"tool": "run_skill", "args": {"skill": "enumerate_endpoints"}},
        )

    tool = AgentGraphTool(executor=_executor)
    created = await tool.run(
        action="create",
        role="exploit_worker",
        task="Validate SQL injection on /search",
        skills=["enumerate_endpoints"],
    )
    agent_id = created.data["agent"]["id"]
    ran = await tool.run(action="run", agent_id=agent_id)
    assert ran.ok is True

    rejected = await tool.run(
        action="finish",
        agent_id=agent_id,
        result="Confirmed vulnerable SQL injection on /search with status delta evidence.",
    )

    assert rejected.ok is False
    assert rejected.error == "unsupported_execution_evidence"
    assert rejected.data["agent"]["status"] == "waiting"


@pytest.mark.asyncio
async def test_agent_graph_accepts_positive_finish_with_related_structured_evidence_artifact():
    async def _executor(agent, instruction):
        return ToolResult(
            ok=True,
            summary="run_skill: status delta observed on /search",
            data={
                "tool": "run_skill",
                "args": {"skill": "test_injection", "target_url": "http://localhost:3000"},
                "result": {
                    "ok": True,
                    "summary": "confirmed sql injection on /search",
                    "proof_artifact": {
                        "claim": "SQL injection on /search",
                        "target": "http://localhost:3000/search",
                        "control": {
                            "request": "GET /search?q=test",
                            "response_status": 200,
                            "response_excerpt": "normal results",
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
                            "compare response status and body",
                        ],
                    },
                },
            },
        )

    tool = AgentGraphTool(executor=_executor)
    created = await tool.run(
        action="create",
        role="exploit_worker",
        task="Validate SQL injection on /search",
        skills=["test_injection"],
    )
    agent_id = created.data["agent"]["id"]
    ran = await tool.run(action="run", agent_id=agent_id)
    assert ran.ok is True

    finished = await tool.run(
        action="finish",
        agent_id=agent_id,
        result="Confirmed vulnerable SQL injection on /search with status delta evidence.",
    )

    assert finished.ok is True
    assert finished.data["agent"]["status"] == "finished"
    assert finished.data["agent"]["result_package"]["evidence_artifact"]["valid"] is True


@pytest.mark.asyncio
async def test_agent_graph_reuses_duplicate_active_agent():
    tool = AgentGraphTool()
    first = await tool.run(
        action="create",
        role="exploit_worker",
        task="Validate SQL injection on /search",
        skills=["test_injection"],
    )
    second = await tool.run(
        action="create",
        role="exploit_worker",
        task="  validate   SQL injection on /search  ",
        skills=["test_injection"],
    )

    assert second.ok is True
    assert second.data["duplicate"] is True
    assert second.data["agent"]["id"] == first.data["agent"]["id"]
    assert second.data["active_agents"] == 1

    viewed = await tool.run(action="view")
    assert viewed.data["total_agents"] == 1


@pytest.mark.asyncio
async def test_agent_graph_rejects_unknown_agent_operations():
    tool = AgentGraphTool()

    sent = await tool.run(action="send", agent_id="agent-9999", message="hello")
    assert sent.ok is False
    assert sent.error == "unknown_agent"

    viewed = await tool.run(action="view", agent_id="agent-9999")
    assert viewed.ok is False
    assert viewed.error == "unknown_agent"


@pytest.mark.asyncio
async def test_agent_graph_run_requires_executor():
    tool = AgentGraphTool()
    created = await tool.run(
        action="create", role="recon_worker", task="Map unauthenticated routes"
    )
    result = await tool.run(action="run", agent_id=created.data["agent"]["id"])
    assert result.ok is False
    assert result.error == "executor_unavailable"
    assert result.data["note"] == "executor_unavailable"


@pytest.mark.asyncio
async def test_agent_graph_run_records_bounded_executor_turn():
    async def _executor(agent, instruction):
        assert agent["id"] == "agent-0001"
        assert instruction == "try the declared route mapper"
        return ToolResult(
            ok=True,
            summary="run_skill: enumerate_endpoints complete",
            data={
                "tool": "run_skill",
                "args": {"skill": "enumerate_endpoints"},
                "result": {"ok": True, "summary": "mapped /login"},
            },
        )

    tool = AgentGraphTool(executor=_executor)
    created = await tool.run(
        action="create",
        role="recon_worker",
        task="Map unauthenticated routes",
        skills=["enumerate_endpoints"],
    )
    agent_id = created.data["agent"]["id"]

    result = await tool.run(
        action="run", agent_id=agent_id, instruction="try the declared route mapper"
    )
    assert result.ok is True
    assert result.data["execution"]["tool"] == "run_skill"
    assert result.data["agent"]["status"] == "waiting"
    assert result.data["agent"]["execution_count"] == 1
    assert result.data["agent"]["message_count"] == 2
    assert result.data["active_agents"] == 1


@pytest.mark.asyncio
async def test_agent_graph_run_limit_requires_explicit_finish_or_block():
    async def _executor(agent, instruction):
        return ToolResult(
            ok=True,
            summary="run_skill: one bounded turn",
            data={"tool": "run_skill", "args": {"skill": "enumerate_endpoints"}},
        )

    tool = AgentGraphTool(executor=_executor, max_child_runs=1)
    created = await tool.run(action="create", role="recon_worker", task="Map routes")
    agent_id = created.data["agent"]["id"]

    first = await tool.run(action="run", agent_id=agent_id)
    assert first.ok is True
    second = await tool.run(action="run", agent_id=agent_id)
    assert second.ok is False
    assert second.error == "run_limit_reached"
    assert second.data["execution_count"] == 1
    assert second.data["agent"]["execution_count"] == 1


def test_build_default_registry_contains_agent_graph_tool():
    reg = build_default_registry()
    assert "agent_graph" in reg.list_tools()
