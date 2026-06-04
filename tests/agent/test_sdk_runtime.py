import json

import pytest

from vxis.agent.sdk_runtime import (
    SDKAgentCoordinator,
    SDKEventJournal,
    SDKRunPaths,
    build_vxis_sdk_agent,
    make_vxis_model_settings,
    open_sdk_agent_session,
    sdk_tool_from_registry,
    sdk_tools_from_registry,
)
from vxis.agent.tool_registry import ToolRegistry, ToolResult


class EchoTool:
    name = "echo"
    description = "Echo a message for SDK bridge tests."
    input_schema = {
        "type": "object",
        "properties": {"message": {"type": "string"}},
        "required": ["message"],
    }

    async def run(self, **kwargs):
        return ToolResult(
            ok=True,
            summary=f"echoed {kwargs['message']}",
            data={"message": kwargs["message"]},
        )


@pytest.mark.asyncio
async def test_sdk_coordinator_writes_messages_to_agent_sessions(tmp_path):
    paths = SDKRunPaths.for_run_dir(tmp_path / "run-1")
    journal = SDKEventJournal(paths.events_path)
    coordinator = SDKAgentCoordinator(
        snapshot_path=paths.agents_snapshot_path,
        event_journal=journal,
    )
    root_session = open_sdk_agent_session("root", paths.agents_db_path)
    worker_session = open_sdk_agent_session("worker-1", paths.agents_db_path)

    await coordinator.register(
        "root",
        name="Director",
        role="director",
        task="Drive the scan to crown-jewel impact",
    )
    await coordinator.register(
        "worker-1",
        name="SQLi proof worker",
        role="exploit_worker",
        task="Validate SQL injection on /search",
        parent_id="root",
        metadata={"surface": "web"},
    )
    await coordinator.attach_session("root", root_session)
    await coordinator.attach_session("worker-1", worker_session)

    delivered = await coordinator.send(
        "root",
        "worker-1",
        "Collect baseline/control/payload evidence for /search?q=.",
        message_type="task",
        priority="high",
    )

    assert delivered is True
    assert await coordinator.wait_for_message("worker-1", timeout_seconds=0.01) is True
    pending_count, pending_items = await coordinator.consume_pending(
        "worker-1",
        include_items=True,
    )
    assert pending_count == 1
    assert "VXIS message from Director (root)" in pending_items[-1]["content"]
    assert "baseline/control/payload" in pending_items[-1]["content"]

    drilldown = await coordinator.agent_drilldown("worker-1", session_item_limit=3, event_limit=5)
    assert drilldown["agent"]["agent_id"] == "worker-1"
    assert drilldown["agent"]["pending_count"] == 0
    assert "baseline/control/payload" in drilldown["session_items"][-1]["content"]
    assert [event["event_type"] for event in drilldown["events"]][-1] == "message_sent"

    snapshot = json.loads(paths.agents_snapshot_path.read_text(encoding="utf-8"))
    assert snapshot["agents"]["worker-1"]["parent_id"] == "root"
    assert snapshot["agents"]["worker-1"]["status"] == "running"

    restored = SDKAgentCoordinator(snapshot_path=paths.agents_snapshot_path)
    assert await restored.restore_from_path() is True
    restored_snapshot = await restored.snapshot()
    assert restored_snapshot["statuses"]["worker-1"] == "running"
    assert restored_snapshot["parent_of"]["worker-1"] == "root"

    event_types = [event["event_type"] for event in journal.load_events()]
    assert event_types == [
        "agent_registered",
        "agent_registered",
        "session_attached",
        "session_attached",
        "message_sent",
    ]

    await coordinator.close_sessions()


@pytest.mark.asyncio
async def test_sdk_completion_report_returns_to_parent_session_and_blocks_finish_until_clear(
    tmp_path,
):
    paths = SDKRunPaths.for_run_dir(tmp_path / "run-2")
    journal = SDKEventJournal(paths.events_path)
    coordinator = SDKAgentCoordinator(
        snapshot_path=paths.agents_snapshot_path,
        event_journal=journal,
    )
    root_session = open_sdk_agent_session("root", paths.agents_db_path)
    worker_session = open_sdk_agent_session("worker-1", paths.agents_db_path)

    await coordinator.register(
        "root",
        name="Director",
        role="director",
        task="Drive the scan",
    )
    await coordinator.register(
        "worker-1",
        name="IDOR worker",
        role="exploit_worker",
        task="Prove IDOR on /api/orders/{id}",
        parent_id="root",
    )
    await coordinator.attach_session("root", root_session)
    await coordinator.attach_session("worker-1", worker_session)

    active_before = await coordinator.active_agents_except("root")
    assert [agent["agent_id"] for agent in active_before] == ["worker-1"]

    completed = await coordinator.complete_agent(
        "worker-1",
        result_summary="Confirmed cross-account order read with control 403 vs payload 200.",
        findings=[{"title": "Cross-account order read", "severity": "high"}],
        evidence_artifact={
            "valid": True,
            "claim": "IDOR on /api/orders/{id}",
            "target": "/api/orders/2",
            "control": {"response_status": 403},
            "payload": {"response_status": 200},
            "observed_delta": "403 denied own-control variant, 200 returned another account order",
            "repro_steps": ["login as low user", "request order 2", "compare response"],
        },
    )

    assert completed is True
    assert await coordinator.active_agents_except("root") == []

    pending_count, pending_items = await coordinator.consume_pending("root", include_items=True)
    assert pending_count == 1
    completion = pending_items[-1]["content"]
    assert "type=completion" in completion
    assert "agent_completion" in completion
    assert "Cross-account order read" in completion

    snapshot = json.loads(paths.agents_snapshot_path.read_text(encoding="utf-8"))
    assert snapshot["agents"]["worker-1"]["status"] == "completed"
    events = journal.load_events()
    assert events[-2]["event_type"] == "agent_completed"
    assert events[-1]["event_type"] == "message_sent"

    await coordinator.close_sessions()


def test_sdk_event_journal_continues_sequence_after_reopen(tmp_path):
    paths = SDKRunPaths.for_run_dir(tmp_path / "run-3")
    first = SDKEventJournal(paths.events_path)

    async def _write_initial_events():
        await first.append("one", agent_id="root")
        await first.append("two", agent_id="worker")

    import asyncio

    asyncio.run(_write_initial_events())

    reopened = SDKEventJournal(paths.events_path)

    async def _write_final_event():
        await reopened.append("three", agent_id="root")

    asyncio.run(_write_final_event())

    assert [event["sequence"] for event in reopened.load_events()] == [1, 2, 3]
    assert [event["event_type"] for event in reopened.load_events()] == ["one", "two", "three"]
    assert [event["event_type"] for event in reopened.load_events(agent_id="root")] == [
        "one",
        "three",
    ]


@pytest.mark.asyncio
async def test_sdk_sqlite_session_persists_agent_history_after_reopen(tmp_path):
    paths = SDKRunPaths.for_run_dir(tmp_path / "run-4")
    session = open_sdk_agent_session("worker-1", paths.agents_db_path)
    await session.add_items([{"role": "user", "content": "persist this worker turn"}])
    session.close()

    reopened = open_sdk_agent_session("worker-1", paths.agents_db_path)
    items = await reopened.get_items()

    assert items == [{"role": "user", "content": "persist this worker turn"}]
    reopened.close()


@pytest.mark.asyncio
async def test_sdk_tool_bridge_dispatches_existing_vxis_tools():
    registry = ToolRegistry()
    registry.register(EchoTool())
    sdk_tool = sdk_tool_from_registry(registry, "echo")

    raw_result = await sdk_tool.on_invoke_tool(None, '{"message":"hello"}')
    result = json.loads(raw_result)

    assert sdk_tool.name == "echo"
    assert result == {
        "ok": True,
        "summary": "echoed hello",
        "data": {"message": "hello"},
        "error": None,
    }


@pytest.mark.asyncio
async def test_sdk_tool_bridge_returns_tool_result_for_invalid_json():
    registry = ToolRegistry()
    registry.register(EchoTool())
    sdk_tool = sdk_tool_from_registry(registry, "echo")

    raw_result = await sdk_tool.on_invoke_tool(None, "{bad json")
    result = json.loads(raw_result)

    assert result["ok"] is False
    assert result["error"] == "invalid_json_args"


def test_sdk_agent_factory_enforces_single_required_tool_call():
    registry = ToolRegistry()
    registry.register(EchoTool())
    tools = sdk_tools_from_registry(registry)

    agent = build_vxis_sdk_agent(
        name="worker",
        instructions="Use one tool call.",
        tools=tools,
        model="gpt-test",
    )

    assert agent.name == "worker"
    assert agent.model == "gpt-test"
    assert agent.model_settings.tool_choice == "required"
    assert agent.model_settings.parallel_tool_calls is False
    assert agent.model_settings.include_usage is True
    assert agent.reset_tool_choice is False
    assert [tool.name for tool in agent.tools] == ["echo"]


def test_sdk_agent_factory_drops_required_tool_choice_for_reasoning_models():
    registry = ToolRegistry()
    registry.register(EchoTool())
    tools = sdk_tools_from_registry(registry)

    agent = build_vxis_sdk_agent(
        name="reasoning-worker",
        instructions="Use one tool call when useful.",
        tools=tools,
        model="openai/gpt-5.4",
    )

    assert agent.model_settings.tool_choice is None


def test_make_vxis_model_settings_keeps_required_for_non_reasoning_models():
    settings = make_vxis_model_settings(require_tool=True, model="gpt-test")

    assert settings.tool_choice == "required"
