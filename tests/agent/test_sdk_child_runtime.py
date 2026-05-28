import json
import asyncio
from types import SimpleNamespace

import pytest

from vxis.agent.context_budget import resolve_context_budget
from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.sdk_runtime import SDKChildAgentLoop, SDKRunPaths
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.agent.tools.agent_graph_tools import AgentGraphTool
from vxis.agent.tools.finding_tools import (
    LinkChainTool,
    ReportFindingTool,
    _get_chains,
    _get_findings,
    _reset_for_tests,
)


@pytest.fixture(autouse=True)
def _isolate_findings():
    _reset_for_tests()
    yield
    _reset_for_tests()


class RunSkillTool:
    name = "run_skill"
    description = "execute a bounded VXIS skill"
    input_schema = {"type": "object"}

    async def run(self, **kwargs):
        return ToolResult(ok=True, summary=f"ran {kwargs.get('skill', 'skill')}", data={})


def _valid_evidence_artifact() -> dict:
    return {
        "claim": "Confirmed IDOR on /api/orders/2",
        "target": "/api/orders/2",
        "control": {
            "request": "GET /api/orders/2 as user-a control",
            "response_status": 403,
            "response": "HTTP 403 denied for control account",
        },
        "payload": {
            "request": "GET /api/orders/2 as user-b payload",
            "response_status": 200,
            "response": "HTTP 200 returned another account order body",
        },
        "observed_delta": "control HTTP 403 denied while payload HTTP 200 returned order data",
        "repro_steps": [
            "Login as user-a and request /api/orders/2 for the control response",
            "Login as user-b and request the same order id",
            "Compare 403 control against 200 payload response",
        ],
    }


class FakeSDKRunner:
    def __init__(
        self,
        *,
        artifact: dict | None = None,
        status: str = "completed",
        raise_after_finish: bool = False,
        delay_seconds: float = 0.0,
    ) -> None:
        self.artifact = artifact if artifact is not None else _valid_evidence_artifact()
        self.status = status
        self.raise_after_finish = raise_after_finish
        self.delay_seconds = delay_seconds
        self.calls: list[dict] = []
        self.active = 0
        self.max_active = 0

    async def run(self, *, starting_agent, input, session=None, max_turns=0, **kwargs):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            self.calls.append(
                {
                    "agent": starting_agent,
                    "input": input,
                    "session": session,
                    "max_turns": max_turns,
                    "kwargs": kwargs,
                }
            )
            if self.delay_seconds:
                await asyncio.sleep(self.delay_seconds)
            finish_tool = next(tool for tool in starting_agent.tools if tool.name == "agent_finish")
            await finish_tool.on_invoke_tool(
                None,
                json.dumps(
                    {
                        "status": self.status,
                        "result_summary": "Confirmed IDOR with control 403 vs payload 200.",
                        "findings": [{"title": "IDOR", "severity": "high"}],
                        "evidence_artifact": self.artifact,
                    }
                ),
            )
            if self.raise_after_finish:
                raise RuntimeError("runner continued after agent_finish")
            return SimpleNamespace(final_output="done")
        finally:
            self.active -= 1


class CrashingBackgroundSDKRunner:
    async def run(self, **kwargs):
        raise RuntimeError("worker task crashed")


@pytest.mark.asyncio
async def test_sdk_child_loop_runs_sdk_agent_and_reports_completion_to_parent(tmp_path):
    registry = ToolRegistry()
    registry.register(RunSkillTool())
    paths = SDKRunPaths.for_run_dir(tmp_path / "sdk-run")
    runner = FakeSDKRunner()
    loop = SDKChildAgentLoop(
        registry=registry,
        run_paths=paths,
        runner=runner,
        target="http://localhost:3000",
        provider="llamacpp",
        model="local-30b",
    )
    agent = {
        "id": "agent-0001",
        "role": "exploit_worker",
        "task": "Prove IDOR on /api/orders/2",
        "skills": ["test_idor"],
        "task_envelope": {
            "allowed_tools": ["run_skill", "skills:test_idor"],
            "objective": "Prove IDOR on /api/orders/2",
            "expected_artifact": "control/payload HTTP transcript",
            "stop_condition": "finish after valid EvidenceArtifact",
        },
    }

    result = await loop.run_turn(agent, "collect a replayable control/payload pair")

    assert result.ok is True
    assert result.data["agent_finish"]["status"] == "completed"
    assert result.data["evidence_artifact"]["observed_delta"]
    assert result.data["planner"]["source"] == "sdk_agent_runtime"
    assert result.data["sdk_runtime"]["agent"]["agent_id"] == "agent-0001"
    assert "EvidenceArtifact_fields" in result.data["sdk_runtime"]["session_items"][-1]["content"]
    assert "message_sent" in [
        event["event_type"] for event in result.data["sdk_runtime"]["events"]
    ]
    assert runner.calls[0]["max_turns"] == 6
    assert "latest VXIS director task" in runner.calls[0]["input"]
    assert "EvidenceArtifact_fields" not in runner.calls[0]["input"]
    control_snapshot = loop.control_plane_snapshot()
    assert control_snapshot["enabled"] is True
    assert control_snapshot["agents"][0]["agent"]["agent_id"] == "agent-0001"

    pending_count, pending_items = await loop.coordinator.consume_pending("root", include_items=True)
    assert pending_count == 1
    assert "agent_completion" in pending_items[-1]["content"]
    assert await loop.coordinator.active_agents_except("root") == []
    assert paths.agents_db_path.exists()
    assert "agent_completed" in [event["event_type"] for event in loop.journal.load_events()]

    await loop.coordinator.close_sessions()


@pytest.mark.asyncio
async def test_sdk_child_loop_accepts_recorded_finish_if_runner_errors_after_finish(tmp_path):
    registry = ToolRegistry()
    registry.register(RunSkillTool())
    runner = FakeSDKRunner(raise_after_finish=True)
    loop = SDKChildAgentLoop(
        registry=registry,
        run_paths=SDKRunPaths.for_run_dir(tmp_path / "sdk-run"),
        runner=runner,
        target="http://localhost:3000",
    )
    agent = {
        "id": "agent-0001",
        "role": "exploit_worker",
        "task": "Prove IDOR on /api/orders/2",
        "task_envelope": {"allowed_tools": ["run_skill"]},
    }

    result = await loop.run_turn(agent)

    assert result.ok is True
    assert result.data["agent_finish"]["status"] == "completed"
    assert "runner_error_after_finish" in result.data["planner"]

    await loop.coordinator.close_sessions()


def test_sdk_child_prompt_harness_preserves_core_fields_and_caps_history(tmp_path):
    registry = ToolRegistry()
    registry.register(RunSkillTool())
    loop = SDKChildAgentLoop(
        registry=registry,
        run_paths=SDKRunPaths.for_run_dir(tmp_path / "sdk-run"),
        target="http://localhost:3000",
        provider="llamacpp",
        model="local-30b",
        context_window=8192,
    )
    large_blob = "verbose historical detail " * 1200
    agent = {
        "id": "agent-0001",
        "role": "exploit_worker",
        "task": large_blob,
        "skills": ["test_idor"],
        "skill_context": large_blob,
        "task_envelope": {
            "allowed_tools": ["run_skill", "http_request", "skills:test_idor"],
            "objective": "Prove IDOR without losing required proof fields",
            "expected_artifact": "EvidenceArtifact with control and payload",
            "stop_condition": "finish after proof or blocker",
            "escalation_trigger": "return blocker if no account boundary is reachable",
        },
        "messages": [{"body": large_blob, "sender": "root"} for _ in range(20)],
        "executions": [{"data": {"evidence_artifact": {"claim": large_blob}}} for _ in range(20)],
    }

    prompt = loop.build_prompt(
        agent,
        "preserve EvidenceArtifact fields",
        allowed_tool_names={"run_skill", "http_request"},
    )
    budget = resolve_context_budget(
        "worker",
        provider="llamacpp",
        model="local-30b",
        context_window=8192,
    )

    assert prompt.prompt_tokens <= budget.max_prompt_tokens
    assert prompt.history_tokens <= budget.history_tokens
    assert "EvidenceArtifact_fields=claim,target,control,payload,observed_delta,repro_steps" in (
        prompt.input_text
    )
    assert "allowed_tools=http_request,run_skill" in prompt.input_text
    assert prompt.compacted is True


@pytest.mark.asyncio
async def test_agent_graph_sdk_completion_finishes_node_with_valid_evidence():
    async def _executor(agent, instruction):
        artifact = _valid_evidence_artifact()
        return ToolResult(
            ok=True,
            summary="Confirmed IDOR with control 403 vs payload 200.",
            data={
                "tool": "sdk_agent",
                "args": {"instruction": instruction},
                "agent_finish": {
                    "status": "completed",
                    "result_summary": "Confirmed IDOR with control 403 vs payload 200.",
                    "evidence_artifact": artifact,
                },
                "evidence_artifact": artifact,
                "result": {
                    "ok": True,
                    "summary": "Confirmed IDOR with control 403 vs payload 200.",
                    "data": {"evidence_artifact": artifact},
                },
            },
        )

    graph = AgentGraphTool(executor=_executor)
    created = await graph.run(
        action="create",
        role="exploit_worker",
        task="Prove IDOR on /api/orders/2",
    )
    agent_id = created.data["agent"]["id"]
    ran = await graph.run(action="run", agent_id=agent_id, instruction="prove it")

    assert ran.ok is True
    assert ran.data["agent"]["status"] == "finished"
    assert ran.data["active_agents"] == 0
    assert ran.data["agent"]["result_package"]["final_status"] == "finished"
    assert ran.data["agent"]["result_package"]["evidence_artifact"]["valid"] is True


@pytest.mark.asyncio
async def test_agent_graph_rejects_positive_sdk_completion_without_valid_evidence():
    async def _executor(agent, instruction):
        return ToolResult(
            ok=True,
            summary="Confirmed SQL injection on /search.",
            data={
                "tool": "sdk_agent",
                "args": {"instruction": instruction},
                "agent_finish": {
                    "status": "completed",
                    "result_summary": "Confirmed SQL injection on /search.",
                    "evidence_artifact": {},
                },
                "result": {
                    "ok": True,
                    "summary": "Confirmed SQL injection on /search.",
                    "data": {},
                },
            },
        )

    graph = AgentGraphTool(executor=_executor)
    created = await graph.run(
        action="create",
        role="exploit_worker",
        task="Prove SQL injection on /search",
    )
    ran = await graph.run(action="run", agent_id=created.data["agent"]["id"])

    assert ran.ok is False
    assert ran.error == "insufficient_completion_evidence"
    assert ran.data["agent"]["status"] == "waiting"
    assert ran.data["agent"]["result_package"]["evidence_gap"]["status"] == "needs_more_evidence"


@pytest.mark.asyncio
async def test_scan_loop_feature_flag_wires_agent_graph_to_sdk_child_loop(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_USE_SDK_AGENT_RUNTIME", "1")
    monkeypatch.setenv("VXIS_SDK_RUN_DIR", str(tmp_path / "sdk-run"))
    events: list[tuple[str, dict]] = []
    registry = ToolRegistry()
    registry.register(AgentGraphTool())
    registry.register(RunSkillTool())
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=registry,
        max_iters=3,
        event_callback=lambda event_type, data: events.append((event_type, data)),
    )
    loop._sdk_agent_loop.runner = FakeSDKRunner()

    created = await registry.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Prove IDOR on /api/orders/2",
            "skills": ["test_idor"],
        },
    )
    ran = await registry.dispatch(
        "agent_graph",
        {"action": "run", "agent_id": created.data["agent"]["id"]},
    )

    assert ran.ok is True
    assert ran.data["agent"]["status"] == "finished"
    assert loop._sdk_agent_loop.paths.agents_db_path.exists()
    loop._emit_control_plane("sdk runtime ready")
    control_events = [data for event_type, data in events if event_type == "control_plane"]
    assert control_events[-1]["sdk_runtime"]["enabled"] is True
    assert control_events[-1]["sdk_runtime"]["agents"][0]["session_items"]


@pytest.mark.asyncio
async def test_sdk_child_completion_feeds_report_and_chain_golden_path(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_USE_SDK_AGENT_RUNTIME", "1")
    monkeypatch.setenv("VXIS_SDK_RUN_DIR", str(tmp_path / "sdk-run"))
    registry = ToolRegistry()
    registry.register(AgentGraphTool())
    registry.register(RunSkillTool())
    registry.register(ReportFindingTool())
    registry.register(LinkChainTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=3)
    loop._sdk_agent_loop.runner = FakeSDKRunner()

    created = await registry.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Prove IDOR on /api/orders/2",
            "skills": ["test_idor"],
        },
    )
    ran = await registry.dispatch(
        "agent_graph",
        {"action": "run", "agent_id": created.data["agent"]["id"]},
    )
    assert ran.data["agent"]["result_package"]["evidence_artifact"]["valid"] is True

    source = await registry.dispatch(
        "report_finding",
        {
            "title": "Order id enumeration hints reachable objects",
            "severity": "low",
            "finding_type": "info_disclosure",
            "affected_component": "/api/orders",
            "description": "Order id enumeration exposes candidate object ids.",
            "evidence": "GET /api/orders shows sequential ids.",
            "remediation": "Avoid exposing predictable object identifiers.",
        },
    )
    impact = await registry.dispatch(
        "report_finding",
        {
            "title": "Cross-account order read",
            "severity": "high",
            "finding_type": "idor",
            "affected_component": "/api/orders/2",
            "description": "A low-privilege user can read another user's order.",
            "impact": "Attacker can access customer order data across accounts.",
            "technical_analysis": "SDK child proved control HTTP 403 vs payload HTTP 200.",
            "poc_description": "Replay the two recorded requests and compare the status delta.",
            "poc_script_code": json.dumps(_valid_evidence_artifact(), sort_keys=True),
            "remediation_steps": "Enforce object ownership checks on every order read.",
            "endpoint": "/api/orders/2",
            "method": "GET",
            "cwe": "CWE-639",
        },
    )
    chained = await registry.dispatch(
        "link_chain",
        {
            "finding_ids": [source.data["id"], impact.data["id"]],
            "rationale": "Enumeration supplies object ids, then IDOR reads another account order.",
            "crown_jewel": "customer order data exposure",
        },
    )

    assert source.ok is True
    assert impact.ok is True
    assert chained.ok is True
    assert [finding["id"] for finding in _get_findings()] == ["VXIS-0001", "VXIS-0002"]
    assert _get_chains()[0]["finding_ids"] == ["VXIS-0001", "VXIS-0002"]


@pytest.mark.asyncio
async def test_sdk_runtime_syncs_agent_graph_create_send_before_worker_run(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_USE_SDK_AGENT_RUNTIME", "1")
    monkeypatch.setenv("VXIS_SDK_RUN_DIR", str(tmp_path / "sdk-run"))
    registry = ToolRegistry()
    registry.register(AgentGraphTool())
    registry.register(RunSkillTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=3)

    created = await registry.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Prove IDOR on /api/orders/2",
            "message": "Collect baseline and payload evidence before running.",
        },
    )
    await loop._sync_agent_graph_result_to_sdk_runtime(
        name="agent_graph",
        args={"action": "create"},
        result=created,
    )
    agent_id = created.data["agent"]["id"]

    first = await loop._sdk_agent_loop.coordinator.agent_drilldown(agent_id)
    assert first["agent"]["status"] == "running"
    assert first["agent"]["pending_count"] == 1
    assert "Collect baseline and payload" in first["session_items"][-1]["content"]

    sent = await registry.dispatch(
        "agent_graph",
        {
            "action": "send",
            "agent_id": agent_id,
            "message": "Narrow to the order ownership boundary.",
        },
    )
    await loop._sync_agent_graph_result_to_sdk_runtime(
        name="agent_graph",
        args={"action": "send", "agent_id": agent_id},
        result=sent,
    )

    second = await loop._sdk_agent_loop.coordinator.agent_drilldown(agent_id)
    assert second["agent"]["pending_count"] == 2
    assert "Narrow to the order ownership boundary" in second["session_items"][-1]["content"]
    assert [event["event_type"] for event in second["events"]].count("message_sent") >= 2

    await loop._sdk_agent_loop.coordinator.close_sessions()


@pytest.mark.asyncio
async def test_sdk_runtime_restores_agent_graph_and_sessions_across_loop_restart(
    monkeypatch, tmp_path
):
    run_dir = tmp_path / "sdk-run"
    monkeypatch.setenv("VXIS_USE_SDK_AGENT_RUNTIME", "1")
    monkeypatch.setenv("VXIS_SDK_RUN_DIR", str(run_dir))
    registry = ToolRegistry()
    registry.register(AgentGraphTool())
    registry.register(RunSkillTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=3)

    created = await registry.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Prove IDOR on /api/orders/2",
            "message": "Collect baseline and payload evidence.",
        },
    )
    agent_id = created.data["agent"]["id"]
    await loop._sync_agent_graph_result_to_sdk_runtime(
        name="agent_graph",
        args={"action": "create"},
        result=created,
    )
    await loop._sdk_agent_loop.coordinator.close_sessions()

    restored_registry = ToolRegistry()
    restored_registry.register(AgentGraphTool())
    restored_registry.register(RunSkillTool())
    restored_loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=restored_registry,
        max_iters=3,
    )
    restored_loop._sdk_agent_loop.runner = FakeSDKRunner()

    viewed = await restored_registry.dispatch(
        "agent_graph",
        {"action": "view", "agent_id": agent_id},
    )
    record = await restored_loop._sdk_agent_loop.coordinator.get_record(agent_id)
    control_snapshot = restored_loop._sdk_agent_loop.control_plane_snapshot()
    ran = await restored_registry.dispatch(
        "agent_graph",
        {"action": "run", "agent_id": agent_id},
    )

    assert viewed.ok is True
    assert viewed.data["agent"]["id"] == agent_id
    assert record is not None and record.status == "running"
    assert control_snapshot["restored"] is True
    assert control_snapshot["agents"][0]["agent"]["agent_id"] == agent_id
    assert ran.ok is True
    assert ran.data["agent"]["status"] == "finished"
    assert (run_dir / "runtime" / "agent_graph.json").exists()
    assert restored_loop._sdk_agent_loop.paths.agents_db_path.exists()

    await restored_loop._sdk_agent_loop.coordinator.close_sessions()


@pytest.mark.asyncio
async def test_sdk_runtime_sync_does_not_reopen_completed_worker(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_USE_SDK_AGENT_RUNTIME", "1")
    monkeypatch.setenv("VXIS_SDK_RUN_DIR", str(tmp_path / "sdk-run"))
    registry = ToolRegistry()
    registry.register(AgentGraphTool())
    registry.register(RunSkillTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=3)
    loop._sdk_agent_loop.runner = FakeSDKRunner()

    created = await registry.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Prove IDOR on /api/orders/2",
        },
    )
    ran = await registry.dispatch(
        "agent_graph",
        {"action": "run", "agent_id": created.data["agent"]["id"]},
    )
    agent_id = created.data["agent"]["id"]

    assert ran.data["agent"]["status"] == "finished"
    assert (await loop._sdk_agent_loop.coordinator.get_record(agent_id)).status == "completed"

    await loop._sync_agent_graph_result_to_sdk_runtime(
        name="agent_graph",
        args={"action": "run", "agent_id": agent_id},
        result=ran,
    )

    assert (await loop._sdk_agent_loop.coordinator.get_record(agent_id)).status == "completed"

    await loop._sdk_agent_loop.coordinator.close_sessions()


@pytest.mark.asyncio
async def test_sdk_background_worker_runs_pending_inbox_after_create_sync(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_USE_SDK_AGENT_RUNTIME", "1")
    monkeypatch.setenv("VXIS_SDK_BACKGROUND_WORKERS", "1")
    monkeypatch.setenv("VXIS_SDK_RUN_DIR", str(tmp_path / "sdk-run"))
    registry = ToolRegistry()
    registry.register(AgentGraphTool())
    registry.register(RunSkillTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=3)
    runner = FakeSDKRunner()
    loop._sdk_agent_loop.runner = runner

    created = await registry.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Prove IDOR on /api/orders/2",
            "message": "Collect baseline and payload evidence.",
        },
    )
    await loop._sync_agent_graph_result_to_sdk_runtime(
        name="agent_graph",
        args={"action": "create"},
        result=created,
    )
    agent_id = created.data["agent"]["id"]

    result = await loop._sdk_agent_loop.wait_for_background_worker(
        agent_id,
        timeout_seconds=1.0,
    )
    record = await loop._sdk_agent_loop.coordinator.get_record(agent_id)
    detail = await loop._sdk_agent_loop.coordinator.agent_drilldown(agent_id)
    event_types = [event["event_type"] for event in loop._sdk_agent_loop.journal.load_events()]

    assert result is not None and result.ok is True
    assert record.status == "completed"
    assert detail["agent"]["pending_count"] == 0
    assert "Collect baseline and payload evidence" in detail["session_items"][0]["content"]
    assert "latest VXIS director task" in runner.calls[0]["input"]
    assert "background_worker_started" in event_types
    assert "background_worker_completed" in event_types

    await loop._sdk_agent_loop.coordinator.close_sessions()


@pytest.mark.asyncio
async def test_sdk_background_workers_respect_local_concurrency(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_USE_SDK_AGENT_RUNTIME", "1")
    monkeypatch.setenv("VXIS_SDK_BACKGROUND_WORKERS", "1")
    monkeypatch.setenv("VXIS_SDK_BACKGROUND_WORKER_CONCURRENCY", "1")
    monkeypatch.setenv("VXIS_SDK_RUN_DIR", str(tmp_path / "sdk-run"))
    registry = ToolRegistry()
    registry.register(AgentGraphTool())
    registry.register(RunSkillTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=3)
    runner = FakeSDKRunner(delay_seconds=0.02)
    loop._sdk_agent_loop.runner = runner

    created_ids: list[str] = []
    for idx in range(2):
        created = await registry.dispatch(
            "agent_graph",
            {
                "action": "create",
                "role": "exploit_worker",
                "task": f"Prove IDOR on /api/orders/{idx + 2}",
                "message": f"Collect evidence for order {idx + 2}.",
            },
        )
        created_ids.append(created.data["agent"]["id"])
        await loop._sync_agent_graph_result_to_sdk_runtime(
            name="agent_graph",
            args={"action": "create"},
            result=created,
        )

    results = await loop._sdk_agent_loop.wait_for_background_workers(timeout_seconds=2.0)

    assert set(results) >= set(created_ids)
    assert all(results[agent_id].ok for agent_id in created_ids)
    assert runner.max_active == 1
    assert len(runner.calls) == 2

    await loop._sdk_agent_loop.coordinator.close_sessions()


@pytest.mark.asyncio
async def test_agent_graph_run_reuses_completed_background_worker_result(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_USE_SDK_AGENT_RUNTIME", "1")
    monkeypatch.setenv("VXIS_SDK_BACKGROUND_WORKERS", "1")
    monkeypatch.setenv("VXIS_SDK_RUN_DIR", str(tmp_path / "sdk-run"))
    registry = ToolRegistry()
    registry.register(AgentGraphTool())
    registry.register(RunSkillTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=3)
    runner = FakeSDKRunner()
    loop._sdk_agent_loop.runner = runner

    created = await registry.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Prove IDOR on /api/orders/2",
            "message": "Collect baseline and payload evidence.",
        },
    )
    await loop._sync_agent_graph_result_to_sdk_runtime(
        name="agent_graph",
        args={"action": "create"},
        result=created,
    )
    agent_id = created.data["agent"]["id"]

    background_result = await loop._sdk_agent_loop.wait_for_background_worker(
        agent_id,
        timeout_seconds=1.0,
    )
    ran = await registry.dispatch("agent_graph", {"action": "run", "agent_id": agent_id})
    absorbed = await loop._absorb_sdk_background_agent_results()

    assert background_result is not None and background_result.ok is True
    assert ran.ok is True
    assert ran.data["agent"]["status"] == "finished"
    assert absorbed == []
    assert len(runner.calls) == 1

    await loop._sdk_agent_loop.coordinator.close_sessions()


@pytest.mark.asyncio
async def test_scan_loop_absorbs_completed_sdk_background_worker_into_agent_graph(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("VXIS_USE_SDK_AGENT_RUNTIME", "1")
    monkeypatch.setenv("VXIS_SDK_BACKGROUND_WORKERS", "1")
    monkeypatch.setenv("VXIS_SDK_RUN_DIR", str(tmp_path / "sdk-run"))
    registry = ToolRegistry()
    registry.register(AgentGraphTool())
    registry.register(RunSkillTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=3)
    runner = FakeSDKRunner()
    loop._sdk_agent_loop.runner = runner

    created = await registry.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Prove IDOR on /api/orders/2",
            "message": "Collect baseline and payload evidence.",
        },
    )
    loop._sync_agent_graph_result_to_branches(
        name="agent_graph",
        args={"action": "create"},
        result=created,
    )
    await loop._sync_agent_graph_result_to_sdk_runtime(
        name="agent_graph",
        args={"action": "create"},
        result=created,
    )
    agent_id = created.data["agent"]["id"]

    background_result = await loop._sdk_agent_loop.wait_for_background_worker(
        agent_id,
        timeout_seconds=1.0,
    )
    absorbed = await loop._absorb_sdk_background_agent_results()
    second_absorb = await loop._absorb_sdk_background_agent_results()
    viewed = await registry.dispatch("agent_graph", {"action": "view", "agent_id": agent_id})

    assert background_result is not None and background_result.ok is True
    assert len(absorbed) == 1
    assert absorbed[0].ok is True
    assert second_absorb == []
    assert viewed.data["agent"]["status"] == "finished"
    assert viewed.data["agent"]["execution_count"] == 1
    assert len(runner.calls) == 1
    assert loop.state.branches[f"agent:{agent_id}"].status == "proven"
    tool_messages = [
        message
        for message in loop.state.messages
        if isinstance(message.get("content"), dict)
        and message["content"].get("name") == "agent_graph"
    ]
    assert tool_messages[-1]["content"]["args"]["instruction"].startswith(
        "absorb completed SDK background"
    )
    assert any(
        f"sdk background absorbed {agent_id}" in str(note)
        for note in loop.state.shared_notes
    )

    await loop._sdk_agent_loop.coordinator.close_sessions()


@pytest.mark.asyncio
async def test_sdk_background_worker_records_task_crash(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_USE_SDK_AGENT_RUNTIME", "1")
    monkeypatch.setenv("VXIS_SDK_BACKGROUND_WORKERS", "1")
    monkeypatch.setenv("VXIS_SDK_RUN_DIR", str(tmp_path / "sdk-run"))
    registry = ToolRegistry()
    registry.register(AgentGraphTool())
    registry.register(RunSkillTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=3)
    loop._sdk_agent_loop.runner = CrashingBackgroundSDKRunner()

    created = await registry.dispatch(
        "agent_graph",
        {
            "action": "create",
            "role": "exploit_worker",
            "task": "Prove IDOR on /api/orders/2",
            "message": "Collect baseline and payload evidence.",
        },
    )
    await loop._sync_agent_graph_result_to_sdk_runtime(
        name="agent_graph",
        args={"action": "create"},
        result=created,
    )
    agent_id = created.data["agent"]["id"]

    result = await loop._sdk_agent_loop.wait_for_background_worker(
        agent_id,
        timeout_seconds=1.0,
    )
    record = await loop._sdk_agent_loop.coordinator.get_record(agent_id)

    assert result is not None
    assert result.ok is False
    assert result.error == "sdk_background_worker_failed"
    assert record.status == "failed"

    await loop._sdk_agent_loop.coordinator.close_sessions()
