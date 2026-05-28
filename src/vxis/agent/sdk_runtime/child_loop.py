from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents import FunctionTool, Runner

from vxis.agent.context_budget import (
    compact_context_value,
    estimate_context_tokens,
    fit_lines_to_token_budget,
    resolve_context_budget,
    trim_text_chars,
)
from vxis.agent.sdk_runtime.coordinator import SDKAgentCoordinator
from vxis.agent.sdk_runtime.events import SDKEventJournal
from vxis.agent.sdk_runtime.sessions import SDKRunPaths, open_sdk_agent_session
from vxis.agent.sdk_runtime.tools import build_vxis_sdk_agent, sdk_tools_from_registry
from vxis.agent.tool_registry import ToolRegistry, ToolResult


_DEFAULT_CHILD_TOOLS = {
    "run_skill",
    "http_request",
    "browser_navigate",
    "browser_analyze_dom",
}
_FINISH_STATUSES = {"completed", "finished", "blocked", "failed", "crashed", "stopped"}
_EVIDENCE_FIELDS = "claim,target,control,payload,observed_delta,repro_steps"


@dataclass(frozen=True)
class SDKChildPrompt:
    instructions: str
    input_text: str
    prompt_tokens: int
    history_tokens: int
    compacted: bool


class SDKChildAgentLoop:
    """SDK-backed executor for one bounded AgentGraph child-agent turn."""

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        run_paths: SDKRunPaths | str | Path,
        coordinator: SDKAgentCoordinator | None = None,
        event_journal: SDKEventJournal | None = None,
        runner: Any = Runner,
        model: str | None = None,
        target: str = "",
        provider: str = "openai",
        context_window: int | None = None,
        max_turns: int = 6,
    ) -> None:
        self.registry = registry
        self.paths = (
            run_paths
            if isinstance(run_paths, SDKRunPaths)
            else SDKRunPaths.for_run_dir(Path(run_paths))
        )
        self.journal = event_journal or SDKEventJournal(self.paths.events_path)
        self.coordinator = coordinator or SDKAgentCoordinator(
            snapshot_path=self.paths.agents_snapshot_path,
            event_journal=self.journal,
        )
        self.runner = runner
        self.model = model
        self.target = str(target or "")
        self.provider = str(provider or "openai")
        self.context_window = context_window
        self.max_turns = max(1, int(max_turns))
        self._completions: dict[str, dict[str, Any]] = {}
        self._latest_drilldowns: dict[str, dict[str, Any]] = {}

    async def run_turn(self, agent: dict[str, Any], instruction: str = "") -> ToolResult:
        agent_id = str(agent.get("id") or agent.get("agent_id") or "").strip()
        if not agent_id:
            return ToolResult(
                ok=False,
                summary="sdk child agent: missing agent id",
                error="missing_agent_id",
            )
        allowed_tool_names = self._allowed_tool_names(agent)
        if not allowed_tool_names:
            return ToolResult(
                ok=False,
                data={"agent_id": agent_id, "allowed_tools": []},
                summary="sdk child agent: no registered child tools are available",
                error="no_child_tools",
            )

        await self._ensure_agent_records(agent)
        session = open_sdk_agent_session(agent_id, self.paths.agents_db_path)
        await self.coordinator.attach_session(agent_id, session)
        self._completions.pop(agent_id, None)

        prompt = self.build_prompt(
            agent,
            instruction,
            allowed_tool_names=allowed_tool_names,
        )
        await self._deliver_director_task(agent_id, prompt, instruction=instruction)
        tools = sdk_tools_from_registry(self.registry, tool_names=allowed_tool_names)
        tools.append(self._build_agent_finish_tool(agent_id))
        sdk_agent = build_vxis_sdk_agent(
            name=f"vxis-{agent_id}",
            instructions=prompt.instructions,
            tools=tools,
            model=self.model,
            require_tool=True,
        )

        try:
            await self.runner.run(
                starting_agent=sdk_agent,
                input=self._runner_input_text(agent_id),
                session=session,
                max_turns=self.max_turns,
            )
        except Exception as exc:
            completion = self._completions.get(agent_id)
            if completion:
                return await self._completion_tool_result(
                    agent_id,
                    instruction=instruction,
                    prompt=prompt,
                    allowed_tool_names=allowed_tool_names,
                    completion=completion,
                    runner_error=f"{type(exc).__name__}: {exc}",
                )
            await self.coordinator.set_status(agent_id, "failed")
            sdk_runtime = await self._runtime_drilldown(agent_id)
            return ToolResult(
                ok=False,
                data={
                    "agent_id": agent_id,
                    "tool": "sdk_agent",
                    "args": {"instruction": instruction},
                    "planner": self._planner_meta(prompt, allowed_tool_names),
                    "sdk_runtime": sdk_runtime,
                },
                summary=f"sdk child agent failed: {type(exc).__name__}: {exc}",
                error="sdk_child_run_failed",
            )

        completion = self._completions.get(agent_id)
        if not completion:
            await self.coordinator.set_status(agent_id, "waiting")
            sdk_runtime = await self._runtime_drilldown(agent_id)
            return ToolResult(
                ok=False,
                data={
                    "agent_id": agent_id,
                    "tool": "sdk_agent",
                    "args": {"instruction": instruction},
                    "planner": self._planner_meta(prompt, allowed_tool_names),
                    "sdk_runtime": sdk_runtime,
                },
                summary="sdk child agent did not call agent_finish",
                error="missing_agent_finish",
            )

        return await self._completion_tool_result(
            agent_id,
            instruction=instruction,
            prompt=prompt,
            allowed_tool_names=allowed_tool_names,
            completion=completion,
        )

    async def _completion_tool_result(
        self,
        agent_id: str,
        *,
        instruction: str,
        prompt: SDKChildPrompt,
        allowed_tool_names: set[str],
        completion: dict[str, Any],
        runner_error: str = "",
    ) -> ToolResult:
        evidence_artifact = (
            completion.get("evidence_artifact")
            if isinstance(completion.get("evidence_artifact"), dict)
            else {}
        )
        findings = completion.get("findings") if isinstance(completion.get("findings"), list) else []
        result_summary = str(completion.get("result_summary") or "").strip()
        planner_meta = self._planner_meta(prompt, allowed_tool_names)
        if runner_error:
            planner_meta["runner_error_after_finish"] = runner_error
        sdk_runtime = await self._runtime_drilldown(agent_id)
        return ToolResult(
            ok=completion.get("status") not in {"failed", "crashed"},
            data={
                "agent_id": agent_id,
                "tool": "sdk_agent",
                "args": {"instruction": instruction},
                "planner": planner_meta,
                "agent_finish": completion,
                "evidence_artifact": evidence_artifact,
                "sdk_runtime": sdk_runtime,
                "result": {
                    "ok": completion.get("status") not in {"failed", "crashed"},
                    "summary": result_summary,
                    "data": {
                        "findings": findings,
                        "evidence_artifact": evidence_artifact,
                    },
                    "error": None,
                },
            },
            summary=result_summary or f"sdk child agent {agent_id} completed",
        )

    def control_plane_snapshot(self, *, limit: int = 6) -> dict[str, Any]:
        agents = sorted(
            self._latest_drilldowns.values(),
            key=lambda item: str(
                (item.get("agent") if isinstance(item.get("agent"), dict) else {}).get(
                    "updated_at"
                )
            ),
            reverse=True,
        )
        return {
            "enabled": True,
            "run_dir": str(self.paths.run_dir),
            "agents": compact_context_value(agents[:limit], max_chars=900),
            "events": compact_context_value(self.journal.load_events(limit=limit * 2), max_chars=700),
        }

    async def _deliver_director_task(
        self,
        agent_id: str,
        prompt: SDKChildPrompt,
        *,
        instruction: str,
    ) -> None:
        delivered = await self.coordinator.send(
            "root",
            agent_id,
            prompt.input_text,
            message_type="task",
            priority="high",
            metadata={
                "instruction": trim_text_chars(instruction, 240),
                "prompt_tokens": prompt.prompt_tokens,
                "history_tokens": prompt.history_tokens,
                "compacted": prompt.compacted,
            },
        )
        if delivered:
            await self.coordinator.consume_pending(agent_id)

    @staticmethod
    def _runner_input_text(agent_id: str) -> str:
        return (
            f"Run the latest VXIS director task for {agent_id}. "
            "Use the available tools, preserve proof fields, then call agent_finish."
        )

    async def _runtime_drilldown(self, agent_id: str) -> dict[str, Any]:
        detail = await self.coordinator.agent_drilldown(
            agent_id,
            session_item_limit=5,
            event_limit=10,
        )
        if detail:
            detail["run_dir"] = str(self.paths.run_dir)
            self._latest_drilldowns[agent_id] = compact_context_value(detail, max_chars=1_200)
        return detail

    def build_prompt(
        self,
        agent: dict[str, Any],
        instruction: str = "",
        *,
        allowed_tool_names: set[str],
    ) -> SDKChildPrompt:
        budget = resolve_context_budget(
            "worker",
            provider=self.provider,
            model=self.model or "sdk-worker",
            context_window=self.context_window,
        )
        instructions = (
            "You are a VXIS bounded child security agent. Use available tools only. "
            "Work one delegated task deeply enough to return proof or a blocker. "
            "Do not create agents. Preserve EvidenceArtifact fields: "
            f"{_EVIDENCE_FIELDS}. End by calling agent_finish."
        )
        envelope = agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        result_package = (
            agent.get("result_package") if isinstance(agent.get("result_package"), dict) else {}
        )
        critical_lines = [
            f"target={self.target}",
            f"agent_id={str(agent.get('id') or agent.get('agent_id') or '')}",
            f"role={str(agent.get('role') or 'worker')}",
            f"allowed_tools={','.join(sorted(allowed_tool_names))}",
            f"allowed_skills={','.join(str(skill) for skill in list(agent.get('skills') or [])[:6])}",
            f"task={trim_text_chars(agent.get('task'), budget.max_message_chars)}",
            f"objective={trim_text_chars(envelope.get('objective'), budget.max_message_chars)}",
            f"expected_artifact={trim_text_chars(envelope.get('expected_artifact'), budget.max_message_chars)}",
            f"stop_condition={trim_text_chars(envelope.get('stop_condition'), budget.max_message_chars)}",
            f"escalation_trigger={trim_text_chars(envelope.get('escalation_trigger'), budget.max_message_chars)}",
            f"EvidenceArtifact_fields={_EVIDENCE_FIELDS}",
        ]
        if instruction:
            critical_lines.append(
                f"director_instruction={trim_text_chars(instruction, budget.max_message_chars)}"
            )

        history_lines = [
            "skill_context=" + trim_text_chars(agent.get("skill_context"), budget.max_skill_chars),
            "result_package="
            + json.dumps(
                compact_context_value(result_package, max_chars=budget.max_execution_chars),
                ensure_ascii=False,
                sort_keys=True,
            ),
        ]
        messages = agent.get("messages") if isinstance(agent.get("messages"), list) else []
        for message in messages[-budget.max_agent_messages :]:
            history_lines.append(
                "message="
                + json.dumps(
                    compact_context_value(message, max_chars=budget.max_message_chars),
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        executions = agent.get("executions") if isinstance(agent.get("executions"), list) else []
        for execution in executions[-budget.max_agent_executions :]:
            history_lines.append(
                "execution="
                + json.dumps(
                    compact_context_value(execution, max_chars=budget.max_execution_chars),
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )

        static_tokens = estimate_context_tokens(instructions) + sum(
            estimate_context_tokens(line) for line in critical_lines
        )
        history_budget = max(128, min(budget.history_tokens, budget.max_prompt_tokens - static_tokens - 96))
        fitted_history = fit_lines_to_token_budget(
            history_lines,
            history_budget,
            prefer_recent=True,
            marker="SDK-WORKER-CONTEXT COMPACTION",
        )
        input_text = "\n".join(critical_lines + fitted_history)
        prompt_tokens = estimate_context_tokens(instructions) + estimate_context_tokens(input_text)
        compacted = len(fitted_history) < len(history_lines) or prompt_tokens > budget.max_prompt_tokens
        if prompt_tokens > budget.max_prompt_tokens:
            input_text = trim_text_chars(
                input_text,
                max(900, int(budget.max_prompt_tokens * 2.2)),
            )
            prompt_tokens = estimate_context_tokens(instructions) + estimate_context_tokens(input_text)
            compacted = True
        return SDKChildPrompt(
            instructions=instructions,
            input_text=input_text,
            prompt_tokens=prompt_tokens,
            history_tokens=sum(estimate_context_tokens(line) for line in fitted_history),
            compacted=compacted,
        )

    async def _ensure_agent_records(self, agent: dict[str, Any]) -> None:
        agent_id = str(agent.get("id") or agent.get("agent_id") or "").strip()
        parent_id = str(agent.get("parent_id") or "root").strip() or "root"
        await self._ensure_record(
            "root",
            name="VXIS Director",
            role="director",
            task=f"Drive scan for {self.target}".strip(),
            parent_id=None,
        )
        if parent_id != "root":
            await self._ensure_record(
                parent_id,
                name=f"VXIS Parent {parent_id}",
                role="worker_parent",
                task="Parent delegated agent",
                parent_id="root",
            )
        await self._ensure_record(
            agent_id,
            name=f"VXIS {str(agent.get('role') or 'worker')}",
            role=str(agent.get("role") or "worker"),
            task=str(agent.get("task") or ""),
            parent_id=parent_id,
            metadata={"agent_graph_id": agent_id},
        )
        for session_agent_id in {"root", parent_id}:
            session = open_sdk_agent_session(session_agent_id, self.paths.agents_db_path)
            await self.coordinator.attach_session(session_agent_id, session)

    async def _ensure_record(
        self,
        agent_id: str,
        *,
        name: str,
        role: str,
        task: str,
        parent_id: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if await self.coordinator.get_record(agent_id) is None:
            await self.coordinator.register(
                agent_id,
                name=name,
                role=role,
                task=task,
                parent_id=parent_id,
                metadata=metadata,
                status="running",
            )
        else:
            await self.coordinator.set_status(agent_id, "running")

    def _allowed_tool_names(self, agent: dict[str, Any]) -> set[str]:
        allowed = set(_DEFAULT_CHILD_TOOLS)
        envelope = agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        envelope_allowed = {
            token
            for token in (str(item or "").strip() for item in list(envelope.get("allowed_tools") or []))
            if token and not token.startswith("skills:")
        }
        if envelope_allowed:
            allowed &= envelope_allowed
        return {name for name in allowed if self.registry.has_tool(name)}

    def _build_agent_finish_tool(self, agent_id: str) -> FunctionTool:
        async def _finish(_ctx: Any, raw_input: str) -> str:
            args = _parse_json_object(raw_input)
            if args is None:
                return _dump_tool_result(
                    ok=False,
                    summary="agent_finish requires a JSON object",
                    error="invalid_json_args",
                )
            status = _normalize_finish_status(args.get("status"))
            result_summary = trim_text_chars(args.get("result_summary") or args.get("summary"), 900)
            if not result_summary:
                return _dump_tool_result(
                    ok=False,
                    summary="agent_finish requires result_summary",
                    error="missing_result_summary",
                )
            findings = args.get("findings") if isinstance(args.get("findings"), list) else []
            evidence_artifact = (
                args.get("evidence_artifact") if isinstance(args.get("evidence_artifact"), dict) else {}
            )
            completion = {
                "agent_id": agent_id,
                "status": status,
                "result_summary": result_summary,
                "findings": list(findings),
                "evidence_artifact": dict(evidence_artifact),
            }
            completed = await self.coordinator.complete_agent(
                agent_id,
                result_summary=result_summary,
                status=status,
                findings=list(findings),
                evidence_artifact=dict(evidence_artifact),
            )
            if not completed:
                return _dump_tool_result(
                    ok=False,
                    summary=f"agent_finish failed: unknown SDK agent {agent_id}",
                    error="unknown_agent",
                )
            self._completions[agent_id] = completion
            return _dump_tool_result(
                ok=True,
                summary=result_summary,
                data={"agent_finish": completion},
            )

        return FunctionTool(
            name="agent_finish",
            description=(
                "Finish this bounded VXIS child agent with status, result_summary, "
                "optional findings, and EvidenceArtifact proof fields."
            ),
            params_json_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": sorted(_FINISH_STATUSES)},
                    "result_summary": {"type": "string"},
                    "findings": {"type": "array", "items": {"type": "object"}},
                    "evidence_artifact": {"type": "object"},
                },
                "required": ["status", "result_summary"],
                "additionalProperties": True,
            },
            on_invoke_tool=_finish,
            strict_json_schema=False,
        )

    @staticmethod
    def _planner_meta(prompt: SDKChildPrompt, allowed_tool_names: set[str]) -> dict[str, Any]:
        return {
            "source": "sdk_agent_runtime",
            "allowed_tools": sorted(allowed_tool_names),
            "prompt_tokens": prompt.prompt_tokens,
            "history_tokens": prompt.history_tokens,
            "compacted": prompt.compacted,
        }


def _normalize_finish_status(value: Any) -> str:
    status = str(value or "completed").strip().lower()
    if status == "finished":
        return "completed"
    if status in _FINISH_STATUSES:
        return status
    return "completed"


def _parse_json_object(raw_input: str) -> dict[str, Any] | None:
    if not raw_input:
        return {}
    try:
        parsed = json.loads(raw_input)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _dump_tool_result(
    *,
    ok: bool,
    summary: str,
    data: dict[str, Any] | None = None,
    error: str | None = None,
) -> str:
    return json.dumps(
        {
            "ok": bool(ok),
            "summary": str(summary or ""),
            "data": dict(data or {}),
            "error": error,
        },
        ensure_ascii=False,
        default=str,
    )
