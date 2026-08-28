from __future__ import annotations

import logging
import re
from typing import Any

from vxis.agent.agent_graph_runtime import (
    agent_graph_agents_from_messages,
    agent_graph_crown_chain_next,
    agent_graph_director_brief,
    agent_graph_director_next_step,
    agent_graph_evidence_gap,
)
from vxis.agent.scan_loop_agent_graph_nmap import ScanLoopAgentGraphNmapMixin
from vxis.agent.scan_loop_agent_graph_sync import ScanLoopAgentGraphSyncMixin
from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)


class ScanLoopAgentGraphMixin(ScanLoopAgentGraphSyncMixin, ScanLoopAgentGraphNmapMixin):
    def _agent_graph_agents_from_messages(self) -> list[dict[str, Any]]:
        agents_by_id: dict[str, dict[str, Any]] = {
            str(agent.get("id") or ""): dict(agent)
            for agent in agent_graph_agents_from_messages(self.state.messages)
            if str(agent.get("id") or "")
        }
        tool = self.registry.get_tool("agent_graph")
        snapshot_agents = getattr(tool, "snapshot_agents", None)
        if callable(snapshot_agents):
            try:
                for agent in snapshot_agents(limit=20, active_only=False, include_messages=True):
                    agent_id = str(agent.get("id") or "")
                    if agent_id:
                        agents_by_id[agent_id] = dict(agent)
            except Exception:
                logger.debug("agent_graph snapshot_agents failed", exc_info=True)

        def _sort_key(item: dict[str, Any]) -> tuple[int, str, str]:
            status = str(item.get("status") or "")
            active_rank = 0 if status in {"running", "waiting"} else 1
            return (active_rank, str(item.get("created_at") or ""), str(item.get("id") or ""))

        return sorted(agents_by_id.values(), key=_sort_key)

    def _agent_graph_director_brief(
        self,
        agents: list[dict[str, Any]],
        *,
        local_strict: bool,
    ) -> list[str]:
        return agent_graph_director_brief(agents, local_strict=local_strict)

    def _agent_graph_director_next_step(self, agent: dict[str, Any]) -> str:
        return agent_graph_director_next_step(agent)

    def _agent_graph_crown_chain_next(self, agent: dict[str, Any]) -> str:
        return agent_graph_crown_chain_next(agent)

    @staticmethod
    def _agent_graph_evidence_gap(agent: dict[str, Any]) -> dict[str, Any]:
        return agent_graph_evidence_gap(agent)

    async def _sync_agent_graph_result_to_sdk_runtime(
        self,
        *,
        name: str,
        args: dict[str, Any] | Any,
        result: ToolResult,
    ) -> None:
        if name != "agent_graph" or not isinstance(args, dict) or not isinstance(result.data, dict):
            return
        sdk_loop = getattr(self, "_sdk_agent_loop", None)
        sync = getattr(sdk_loop, "sync_agent_graph_result", None)
        if not callable(sync):
            return
        await sync(
            action=str(args.get("action") or ""),
            result_data=result.data,
        )

    async def _absorb_sdk_background_agent_results(
        self,
        *,
        skills_completed: set[str] | None = None,
        real_skills_completed: set[str] | None = None,
    ) -> list[ToolResult]:
        sdk_loop = getattr(self, "_sdk_agent_loop", None)
        completed_agent_ids = getattr(sdk_loop, "completed_background_result_agent_ids", None)
        mark_absorbed = getattr(sdk_loop, "mark_background_result_absorbed", None)
        if not callable(completed_agent_ids) or not callable(mark_absorbed):
            return []
        if not self.registry.has_tool("agent_graph"):
            return []

        absorbed_results: list[ToolResult] = []
        for agent_id in completed_agent_ids():
            clean_agent_id = str(agent_id or "").strip()
            if not clean_agent_id:
                continue
            args = {
                "action": "run",
                "agent_id": clean_agent_id,
                "instruction": "absorb completed SDK background worker result",
            }
            result = await self.registry.dispatch("agent_graph", args)
            self.state.add_message(
                "tool",
                {
                    "name": "agent_graph",
                    "args": args,
                    "result": {
                        "ok": result.ok,
                        "summary": result.summary,
                        "data": result.data,
                    },
                },
            )
            self._sync_agent_graph_result_to_branches(
                name="agent_graph",
                args=args,
                result=result,
            )
            await self._sync_agent_graph_result_to_sdk_runtime(
                name="agent_graph",
                args=args,
                result=result,
            )
            await self._credit_agent_graph_child_execution(
                result,
                skills_completed=skills_completed if skills_completed is not None else set(),
                real_skills_completed=real_skills_completed
                if real_skills_completed is not None
                else set(),
            )
            mark_absorbed(clean_agent_id)
            self.state.add_shared_note(
                f"sdk background absorbed {clean_agent_id}: {result.summary[:120]}"
            )
            absorbed_results.append(result)
        return absorbed_results

    async def _run_agent_graph_child_turn(
        self, agent: dict[str, Any], instruction: str
    ) -> ToolResult:
        agent_id = str(agent.get("id") or "").strip()
        branch = self.state.branches.get(self._agent_graph_branch_id(agent_id))
        allowed_child_tools = self._agent_graph_allowed_child_tools(agent)
        planner_meta: dict[str, Any] = {}
        action = (
            self._forced_branch_action(branch)
            if branch is not None and branch.owner != "agent_graph"
            else None
        )
        if action is not None:
            planner_meta = {"source": "forced_branch_action"}
        if action is None:
            planned = await self._agent_graph_worker_llm_action(
                agent,
                instruction,
                allowed_child_tools=allowed_child_tools,
            )
            if planned.get("ok"):
                action = (planned["tool"], planned["args"])
                planner_meta = self._agent_graph_worker_planner_success_meta(planned)
            else:
                planner_meta = self._agent_graph_worker_planner_fallback_meta(planned)
        if action is None:
            action = self._agent_graph_action_from_node(agent, instruction)
            if action is not None:
                planner_meta = planner_meta or {"source": "deterministic_fallback"}
        if action is None:
            return ToolResult(
                ok=False,
                data={"agent_id": agent_id, "instruction": instruction, "planner": planner_meta},
                summary="agent_graph child turn: no executable step found for delegated task",
                error="no_child_action",
            )

        tool_name, tool_args = action
        validation_error = self._agent_graph_child_action_validation_error(
            agent,
            tool_name,
            tool_args,
            allowed_child_tools=allowed_child_tools,
        )
        if validation_error is not None:
            return validation_error

        result = await self.registry.dispatch(tool_name, tool_args)
        return ToolResult(
            ok=result.ok,
            data={
                "agent_id": agent_id,
                "tool": tool_name,
                "args": tool_args,
                "planner": planner_meta,
                "instruction": self._agent_graph_worker_instruction(agent, instruction, tool_name),
                "result": {
                    "ok": result.ok,
                    "summary": result.summary,
                    "data": result.data,
                    "error": result.error,
                },
            },
            summary=f"{tool_name}: {result.summary}",
            error=result.error,
        )

    def _agent_graph_child_action_validation_error(
        self,
        agent: dict[str, Any],
        tool_name: str,
        tool_args: dict[str, Any],
        *,
        allowed_child_tools: set[str],
    ) -> ToolResult | None:
        agent_id = str(agent.get("id") or "").strip()
        role = str(agent.get("role") or "recon_worker").strip() or "recon_worker"
        if tool_name not in allowed_child_tools:
            return ToolResult(
                ok=False,
                data={
                    "agent_id": agent_id,
                    "tool": tool_name,
                    "args": tool_args,
                    "allowed_tools": sorted(allowed_child_tools),
                },
                summary=f"agent_graph child turn: tool {tool_name} is not allowed for bounded child execution",
                error="child_tool_not_allowed",
            )
        if not self._role_allows_action(role, tool_name, tool_args):
            return ToolResult(
                ok=False,
                data={"agent_id": agent_id, "role": role, "tool": tool_name, "args": tool_args},
                summary=(
                    f"agent_graph child turn: tool {tool_name} is not allowed for role {role}"
                ),
                error="child_role_not_allowed",
            )
        if not self.registry.has_tool(tool_name):
            return ToolResult(
                ok=False,
                data={"agent_id": agent_id, "tool": tool_name, "args": tool_args},
                summary=f"agent_graph child turn: tool {tool_name} is not registered",
                error="child_tool_unavailable",
            )
        return None

    def _agent_graph_allowed_child_tools(self, agent: dict[str, Any]) -> set[str]:
        allowed_child_tools = {
            "run_skill",
            "http_request",
            "nmap_scan",
            "browser_navigate",
            "browser_analyze_dom",
        }
        envelope_allowed = self._agent_graph_envelope_allowed_tools(agent)
        if envelope_allowed:
            allowed_child_tools = allowed_child_tools & envelope_allowed
        return allowed_child_tools

    def _agent_graph_nmap_args_from_blob(self, blob: str) -> dict[str, Any]:
        target = str(self.state.target)
        host_match = re.search(
            r"\b(?:on|at|target=)?\s*([A-Za-z0-9._-]+):(\d{1,5})/(tcp|udp)\b", blob
        )
        port = ""
        protocol = ""
        if host_match:
            target = host_match.group(1)
            port = host_match.group(2)
            protocol = host_match.group(3)
        if not port:
            port_match = re.search(r"\b(?:port|p)\s*[:=]?\s*(\d{1,5})\b", blob)
            if port_match:
                port = port_match.group(1)
        if not protocol and re.search(r"\budp\b", blob):
            protocol = "udp"

        scripts = "default,safe"
        if any(
            token in blob
            for token in (
                "vuln",
                "cve",
                "noauth",
                "no-auth",
                "redis",
                "mongodb",
                "postgres",
                "mysql",
                "smb",
                "rdp",
                "vnc",
                "ftp",
                "nfs",
            )
        ):
            scripts = "default,safe,vuln"
        args: dict[str, Any] = {
            "target": target,
            "ports": port or "top-1000",
            "scripts": scripts,
        }
        if protocol == "udp":
            args["udp"] = True
        if port:
            args["timeout"] = 180
        return args

    @staticmethod
    def _agent_graph_envelope_allowed_tools(agent: dict[str, Any]) -> set[str]:
        envelope = (
            agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        )
        raw_items = list(envelope.get("allowed_tools") or [])
        allowed: set[str] = set()
        for item in raw_items:
            token = str(item or "").strip()
            if not token or token.startswith("skills:"):
                continue
            allowed.add(token)
        return allowed

    @staticmethod
    def _agent_graph_worker_instruction(
        agent: dict[str, Any], instruction: str, tool_name: str
    ) -> str:
        envelope = (
            agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        )
        result_package = (
            agent.get("result_package") if isinstance(agent.get("result_package"), dict) else {}
        )
        evidence_gap = (
            result_package.get("evidence_gap")
            if isinstance(result_package.get("evidence_gap"), dict)
            else {}
        )
        parts = [
            f"objective={str(envelope.get('objective') or agent.get('task') or '').strip()}",
            f"tool={tool_name}",
        ]
        expected = str(envelope.get("expected_artifact") or "").strip()
        stop = str(envelope.get("stop_condition") or "").strip()
        escalate = str(envelope.get("escalation_trigger") or "").strip()
        prior = str(result_package.get("recommended_next_step") or "").strip()
        gap_instruction = str(evidence_gap.get("next_instruction") or "").strip()
        if expected:
            parts.append(f"expect={expected}")
        if stop:
            parts.append(f"stop={stop}")
        if escalate:
            parts.append(f"escalate={escalate}")
        if prior:
            parts.append(f"prior={prior}")
        if gap_instruction:
            parts.append(f"repair_gap={gap_instruction}")
        if instruction:
            parts.append(f"director_note={instruction.strip()}")
        parts.append(
            "artifact_schema=EvidenceArtifact{claim,target,control,payload,observed_delta,repro_steps}; positive finish requires valid artifact"
        )
        return " | ".join(part for part in parts if part)

    async def _credit_agent_graph_child_execution(
        self,
        result: ToolResult,
        *,
        skills_completed: set[str],
        real_skills_completed: set[str],
    ) -> bool:
        child = self._extract_agent_graph_child_execution(result)
        if child is None:
            return False
        child_tool, child_args, child_result = child
        for candidate_id in self._candidate_ids_for_action(child_tool, child_args):
            self.state.record_attempt_outcome(
                candidate_id,
                child_tool,
                child_args,
                status=self._status_from_tool_result(child_result),
                summary=child_result.summary,
            )
        for branch_id in self._branch_ids_for_action(child_tool, child_args):
            self.state.record_branch_attempt(
                branch_id,
                child_tool,
                child_args,
                status=self._status_from_tool_result(child_result),
                summary=child_result.summary,
            )

        if child_tool == "run_skill" and isinstance(child_args, dict):
            skill = str(child_args.get("skill") or "").strip()
            if skill and not child_result.ok:
                data = child_result.data if isinstance(child_result.data, dict) else {}
                if data.get("blocked"):
                    self.state.record_blocked_skill(skill)
            if skill and child_result.ok:
                real_skills_completed.add(skill)
                skills_completed.add(skill)
                if isinstance(child_result.data, dict) and child_result.data:
                    await self._promote_direct_run_skill_result(skill, child_result.data)
        if child_tool == "nmap_scan" and child_result.ok:
            self._promote_agent_graph_nmap_result(
                result,
                child_args=child_args,
                child_result=child_result,
            )
        return True

    @staticmethod
    def _extract_agent_graph_child_execution(
        result: ToolResult,
    ) -> tuple[str, dict[str, Any], ToolResult] | None:
        if not isinstance(result.data, dict):
            return None
        execution = result.data.get("execution")
        if not isinstance(execution, dict):
            return None
        data = execution.get("data") if isinstance(execution.get("data"), dict) else {}
        tool_name = str(execution.get("tool") or data.get("tool") or "").strip()
        if not tool_name:
            return None
        args_raw = (
            execution.get("args") if isinstance(execution.get("args"), dict) else data.get("args")
        )
        child_args = dict(args_raw) if isinstance(args_raw, dict) else {}
        raw_result = data.get("result") if isinstance(data.get("result"), dict) else {}
        child_result = ToolResult(
            ok=bool(raw_result.get("ok", execution.get("ok", result.ok))),
            data=dict(raw_result.get("data")) if isinstance(raw_result.get("data"), dict) else {},
            summary=str(raw_result.get("summary") or execution.get("summary") or result.summary),
            error=raw_result.get("error") or execution.get("error") or result.error,
        )
        return tool_name, child_args, child_result
