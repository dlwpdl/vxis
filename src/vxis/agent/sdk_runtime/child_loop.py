from __future__ import annotations

import asyncio
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
from vxis.agent.sdk_runtime.coordinator import SDKAgentCoordinator, TERMINAL_AGENT_STATUSES
from vxis.agent.sdk_runtime.events import SDKEventJournal
from vxis.agent.sdk_runtime.sessions import SDKRunPaths, open_sdk_agent_session
from vxis.agent.sdk_runtime.tools import build_vxis_sdk_agent, sdk_tools_from_registry
from vxis.agent.tool_registry import ToolRegistry, ToolResult


_DEFAULT_CHILD_TOOLS = {
    "run_skill",
    "http_request",
    "nmap_scan",
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
        background_workers: bool = False,
        background_worker_concurrency: int = 1,
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
        self.background_workers = bool(background_workers)
        self.background_worker_concurrency = max(1, int(background_worker_concurrency or 1))
        self._completions: dict[str, dict[str, Any]] = {}
        self._latest_drilldowns: dict[str, dict[str, Any]] = {}
        self._synced_agent_graph_messages: dict[str, set[str]] = {}
        self._agent_snapshots: dict[str, dict[str, Any]] = {}
        self._background_tasks: dict[str, asyncio.Task[Any]] = {}
        self._background_results: dict[str, ToolResult] = {}
        self._background_absorbed_agent_ids: set[str] = set()
        self._background_semaphores: dict[int, asyncio.Semaphore] = {}
        self.restored_from_snapshot = self.coordinator.restore_from_path_sync()
        if self.restored_from_snapshot:
            for agent_id in self.coordinator.record_ids():
                session = open_sdk_agent_session(agent_id, self.paths.agents_db_path)
                self.coordinator.attach_session_sync(agent_id, session)

    async def run_turn(self, agent: dict[str, Any], instruction: str = "") -> ToolResult:
        agent_id = str(agent.get("id") or agent.get("agent_id") or "").strip()
        if not agent_id:
            return ToolResult(
                ok=False,
                summary="sdk child agent: missing agent id",
                error="missing_agent_id",
            )
        record = await self.coordinator.get_record(agent_id)
        if (
            record is not None
            and record.status in TERMINAL_AGENT_STATUSES
            and agent_id in self._background_results
        ):
            self._background_absorbed_agent_ids.add(agent_id)
            return self._background_results[agent_id]
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
        if not agents and self.restored_from_snapshot:
            restored_records = sorted(
                self.coordinator.records_snapshot(),
                key=lambda item: (
                    str(item.get("agent_id") or "") == "root",
                    str(item.get("updated_at") or ""),
                    str(item.get("agent_id") or ""),
                ),
            )
            agents = [
                {
                    "agent": record,
                    "session_items": [],
                    "events": self.journal.load_events(
                        agent_id=str(record.get("agent_id") or ""),
                        limit=4,
                    ),
                }
                for record in restored_records
            ]
        return {
            "enabled": True,
            "run_dir": str(self.paths.run_dir),
            "restored": self.restored_from_snapshot,
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

    async def sync_agent_graph_result(
        self,
        *,
        action: str,
        result_data: dict[str, Any],
    ) -> None:
        agents = self._agents_from_agent_graph_result(result_data)
        for agent in agents:
            agent_id = str(agent.get("id") or agent.get("agent_id") or "").strip()
            if not agent_id:
                continue
            await self._ensure_agent_records(agent)
            session = open_sdk_agent_session(agent_id, self.paths.agents_db_path)
            await self.coordinator.attach_session(agent_id, session)
            await self._sync_agent_graph_messages(agent_id, agent)
            if action == "finish" or str(agent.get("status") or "").lower() in {
                "finished",
                "blocked",
            }:
                await self._sync_agent_graph_completion(agent_id, agent)
            else:
                self._agent_snapshots[agent_id] = dict(agent)
                if self.background_workers and action in {"create", "send"}:
                    await self.wake_background_worker(agent_id)
            await self._runtime_drilldown(agent_id)

    async def wake_background_worker(self, agent_id: str) -> bool:
        record = await self.coordinator.get_record(agent_id)
        if record is None or record.status in TERMINAL_AGENT_STATUSES:
            return False
        existing = self._background_tasks.get(agent_id)
        if existing is not None and not existing.done():
            return False
        task = asyncio.create_task(self._background_worker_once(agent_id))
        self._background_tasks[agent_id] = task
        await self.coordinator.attach_task(agent_id, task)
        return True

    async def wait_for_background_worker(
        self,
        agent_id: str,
        *,
        timeout_seconds: float | None = None,
    ) -> ToolResult | None:
        task = self._background_tasks.get(agent_id)
        if task is None:
            return self._background_results.get(agent_id)
        try:
            if timeout_seconds is None:
                await task
            else:
                await asyncio.wait_for(task, timeout_seconds)
        except TimeoutError:
            return None
        return self._background_results.get(agent_id)

    async def wait_for_background_workers(
        self,
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, ToolResult]:
        tasks = [task for task in self._background_tasks.values() if not task.done()]
        if tasks:
            try:
                if timeout_seconds is None:
                    await asyncio.gather(*tasks)
                else:
                    await asyncio.wait_for(asyncio.gather(*tasks), timeout_seconds)
            except TimeoutError:
                pass
        return dict(self._background_results)

    def completed_background_result_agent_ids(self) -> list[str]:
        """Return completed SDK background results not yet mirrored to agent_graph."""
        agent_ids: list[str] = []
        for agent_id in self._background_results:
            if agent_id in self._background_absorbed_agent_ids:
                continue
            task = self._background_tasks.get(agent_id)
            if task is not None and not task.done():
                continue
            agent_ids.append(agent_id)
        return sorted(agent_ids)

    def mark_background_result_absorbed(self, agent_id: str) -> bool:
        if agent_id not in self._background_results:
            return False
        self._background_absorbed_agent_ids.add(agent_id)
        return True

    async def _background_worker_once(self, agent_id: str) -> None:
        await self.journal.append(
            "background_worker_started",
            agent_id=agent_id,
            payload={"concurrency": self.background_worker_concurrency},
        )
        try:
            async with self._background_semaphore():
                result = await self._run_agent_from_existing_session(agent_id)
        except Exception as exc:
            await self.coordinator.set_status(agent_id, "failed")
            result = ToolResult(
                ok=False,
                data={"agent_id": agent_id},
                summary=f"sdk background worker crashed: {type(exc).__name__}: {exc}",
                error="sdk_background_worker_crashed",
            )
        self._background_results[agent_id] = result
        await self.journal.append(
            "background_worker_completed",
            agent_id=agent_id,
            payload={
                "ok": result.ok,
                "summary": result.summary,
                "error": result.error,
            },
        )

    async def _run_agent_from_existing_session(self, agent_id: str) -> ToolResult:
        agent = dict(self._agent_snapshots.get(agent_id) or {})
        if not agent:
            record = await self.coordinator.get_record(agent_id)
            if record is None:
                return ToolResult(
                    ok=False,
                    data={"agent_id": agent_id},
                    summary="sdk background worker: unknown agent",
                    error="unknown_agent",
                )
            agent = {
                "id": record.agent_id,
                "role": record.role,
                "task": record.task,
                "parent_id": record.parent_id,
            }
        allowed_tool_names = self._allowed_tool_names(agent)
        if not allowed_tool_names:
            return ToolResult(
                ok=False,
                data={"agent_id": agent_id, "allowed_tools": []},
                summary="sdk background worker: no registered child tools are available",
                error="no_child_tools",
            )

        session = open_sdk_agent_session(agent_id, self.paths.agents_db_path)
        await self.coordinator.attach_session(agent_id, session)
        pending_count, _items = await self.coordinator.consume_pending(agent_id)
        prompt = self.build_prompt(
            agent,
            f"process {pending_count} pending SDK inbox item(s)",
            allowed_tool_names=allowed_tool_names,
        )
        tools = sdk_tools_from_registry(self.registry, tool_names=allowed_tool_names)
        tools.append(self._build_agent_finish_tool(agent_id))
        sdk_agent = build_vxis_sdk_agent(
            name=f"vxis-{agent_id}",
            instructions=prompt.instructions,
            tools=tools,
            model=self.model,
            require_tool=True,
        )
        self._completions.pop(agent_id, None)

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
                    instruction="background inbox run",
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
                    "args": {"instruction": "background inbox run"},
                    "planner": self._planner_meta(prompt, allowed_tool_names),
                    "sdk_runtime": sdk_runtime,
                },
                summary=f"sdk background worker failed: {type(exc).__name__}: {exc}",
                error="sdk_background_worker_failed",
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
                    "args": {"instruction": "background inbox run"},
                    "planner": self._planner_meta(prompt, allowed_tool_names),
                    "sdk_runtime": sdk_runtime,
                },
                summary="sdk background worker did not call agent_finish",
                error="missing_agent_finish",
            )

        return await self._completion_tool_result(
            agent_id,
            instruction="background inbox run",
            prompt=prompt,
            allowed_tool_names=allowed_tool_names,
            completion=completion,
        )

    def _background_semaphore(self) -> asyncio.Semaphore:
        loop_id = id(asyncio.get_running_loop())
        semaphore = self._background_semaphores.get(loop_id)
        if semaphore is None:
            semaphore = asyncio.Semaphore(self.background_worker_concurrency)
            self._background_semaphores[loop_id] = semaphore
        return semaphore

    @staticmethod
    def _agents_from_agent_graph_result(result_data: dict[str, Any]) -> list[dict[str, Any]]:
        agents: list[dict[str, Any]] = []
        single = result_data.get("agent")
        if isinstance(single, dict):
            agents.append(single)
        for key in ("agents", "active_agents"):
            collection = result_data.get(key)
            if isinstance(collection, list):
                agents.extend(item for item in collection if isinstance(item, dict))
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for agent in agents:
            agent_id = str(agent.get("id") or agent.get("agent_id") or "").strip()
            if not agent_id or agent_id in seen:
                continue
            seen.add(agent_id)
            deduped.append(agent)
        return deduped

    async def _sync_agent_graph_messages(
        self,
        agent_id: str,
        agent: dict[str, Any],
    ) -> None:
        messages = agent.get("messages") if isinstance(agent.get("messages"), list) else []
        synced = self._synced_agent_graph_messages.setdefault(agent_id, set())
        for message in messages:
            if not isinstance(message, dict):
                continue
            message_id = str(message.get("id") or "").strip()
            if message_id and message_id in synced:
                continue
            sender = str(message.get("sender") or "root").strip() or "root"
            recipient = str(message.get("recipient") or agent_id).strip() or agent_id
            content = str(message.get("body") or "").strip()
            if not content:
                continue
            if sender == recipient:
                continue
            delivered = await self.coordinator.send(
                sender,
                recipient,
                content,
                message_type="agent_graph",
                priority="normal",
                metadata={"agent_graph_message_id": message_id, "source": "agent_graph_sync"},
            )
            if delivered and message_id:
                synced.add(message_id)

    async def _sync_agent_graph_completion(
        self,
        agent_id: str,
        agent: dict[str, Any],
    ) -> None:
        record = await self.coordinator.get_record(agent_id)
        if record is not None and record.status in {"completed", "blocked", "failed", "crashed", "stopped"}:
            return
        result_summary = str(agent.get("result") or "").strip()
        if not result_summary:
            result_package = (
                agent.get("result_package") if isinstance(agent.get("result_package"), dict) else {}
            )
            result_summary = str(
                result_package.get("final_result")
                or result_package.get("raw_evidence_summary")
                or "agent_graph worker completed"
            ).strip()
        status = "blocked" if str(agent.get("status") or "").lower() == "blocked" else "completed"
        result_package = (
            agent.get("result_package") if isinstance(agent.get("result_package"), dict) else {}
        )
        evidence_artifact = (
            result_package.get("evidence_artifact")
            if isinstance(result_package.get("evidence_artifact"), dict)
            else {}
        )
        await self.coordinator.complete_agent(
            agent_id,
            result_summary=result_summary,
            status=status,
            evidence_artifact=evidence_artifact,
        )

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
        record = await self.coordinator.get_record(agent_id)
        if record is None:
            await self.coordinator.register(
                agent_id,
                name=name,
                role=role,
                task=task,
                parent_id=parent_id,
                metadata=metadata,
                status="running",
            )
        elif record.status not in TERMINAL_AGENT_STATUSES:
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
