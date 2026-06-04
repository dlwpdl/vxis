from __future__ import annotations

import asyncio
import ast
import json
import os
import re
from typing import Any

from vxis.agent.agent_graph_runtime import (
    agent_graph_agents_from_messages,
    agent_graph_branch_id,
    agent_graph_branch_priority,
    agent_graph_crown_chain_next,
    agent_graph_crown_jewel_for_result,
    agent_graph_director_brief,
    agent_graph_director_next_step,
    agent_graph_evidence_artifact,
    agent_graph_evidence_artifact_brief,
    agent_graph_evidence_gap,
    agent_graph_has_valid_evidence_artifact,
    agent_graph_needs_evidence_artifact,
    agent_graph_result_needs_crown_chain,
    agent_graph_terminal_branch_status,
)
from vxis.agent.brain_prompts import _parse_llm_json
from vxis.agent.context_budget import (
    compact_context_value,
    estimate_context_tokens,
    fit_lines_to_token_budget,
    resolve_context_budget,
    trim_text_chars,
)
from vxis.agent.scan_loop_state import _TERMINAL_BRANCH_STATUSES, BranchState
from vxis.agent.tool_registry import ToolResult


_WORKER_PLANNER_REPAIRABLE_FAILURES = {
    "invalid_json",
    "invalid_json_shape",
    "missing_tool",
    "disallowed_tool",
    "tool_unavailable",
    "missing_skill",
    "invalid_skill",
    "disallowed_skill",
    "invalid_args",
    "role_disallowed",
}

_WORKER_PLANNER_UNAVAILABLE_REASONS = {
    "worker_llm_not_callable",
    "worker_llm_call_failed",
    "worker_llm_empty_response",
}


class ScanLoopAgentGraphMixin:
    def _agent_graph_agents_from_messages(self) -> list[dict[str, Any]]:
        agents_by_id: dict[str, dict[str, Any]] = {
            str(agent.get("id") or ""): dict(agent)
            for agent in agent_graph_agents_from_messages(self.state.messages)
            if str(agent.get("id") or "")
        }
        try:
            tool = self.registry.get_tool("agent_graph")
            snapshot_agents = getattr(tool, "snapshot_agents", None)
            if callable(snapshot_agents):
                for agent in snapshot_agents(limit=20, active_only=False, include_messages=True):
                    agent_id = str(agent.get("id") or "")
                    if agent_id:
                        agents_by_id[agent_id] = dict(agent)
        except Exception:
            pass

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

    def _ensure_agent_graph_crown_followup_branch(
        self,
        agent: dict[str, Any],
        *,
        parent_branch_id: str,
        directive: str,
    ) -> BranchState | None:
        agent_id = str(agent.get("id") or "").strip()
        result = str(agent.get("result") or "").strip()
        role = str(agent.get("role") or "").strip()
        if not agent_id or not parent_branch_id or role == "post_exploit_worker":
            return None
        if not result or not self._agent_graph_result_needs_crown_chain(result):
            return None

        kind = self._target_kind_name()
        vector_id = "DESK-CROWN-PIVOT" if kind == "desktop" else "WEB-CROWN-PIVOT"
        crown_jewel = self._agent_graph_crown_jewel_for_result(result)
        branch_id = f"{parent_branch_id}:crown-chain"
        task = str(agent.get("task") or "delegated worker result").strip()
        title = f"Crown-chain follow-up for {agent_id}"
        objective = (
            f"Turn delegated result into crown-jewel impact: {task}. Worker result: {result[:220]}"
        )
        next_step = (
            "Create a post_exploit_worker agent_graph child. Test session reuse, privilege "
            "boundaries, data access, and chain closure before allowing finish_scan."
        )
        artifact_brief = agent_graph_evidence_artifact_brief(agent, width=120)
        evidence = f"{agent_id}: {result[:220]}"
        if artifact_brief:
            evidence = f"{evidence} | {artifact_brief}"
        branch = self.state.ensure_branch(
            branch_id,
            vector_id,
            title,
            priority=96,
            role="post_exploit_worker",
            phase="session_reuse",
            owner="root",
            parent_branch_id=parent_branch_id,
            source_candidate_id=parent_branch_id,
            objective=objective,
            next_step=next_step,
            crown_jewel=crown_jewel,
            evidence=evidence,
            watch_terms=[
                agent_id,
                "post_exploit_worker",
                "post_auth_enum",
                "session",
                "token",
                "admin",
                "data",
                "link_chain",
            ],
        )
        if branch.status not in _TERMINAL_BRANCH_STATUSES:
            branch.status = "active"
        branch.last_tool = "agent_graph"
        branch.last_summary = directive[:240]
        branch.last_report = result[:160]
        branch.last_iter = self.state.iteration
        todo = self.state.ensure_scan_todo(
            branch.id,
            branch.title,
            priority=branch.priority,
            source_candidate_id=branch.source_candidate_id or branch.id,
        )
        todo.status = "in_progress" if branch.status == "active" else todo.status
        todo.detail = branch.last_report[:120]
        todo.last_iter = self.state.iteration
        return branch

    @staticmethod
    def _agent_graph_evidence_artifact_report_text(agent: dict[str, Any]) -> str:
        artifact = agent_graph_evidence_artifact(agent)
        if not artifact or not artifact.get("valid"):
            return ""

        def _section(value: Any) -> str:
            if isinstance(value, dict):
                return " | ".join(
                    str(value.get(key) or "").strip()
                    for key in (
                        "summary",
                        "request",
                        "response_status",
                        "status",
                        "response_excerpt",
                        "response",
                        "body",
                    )
                    if str(value.get(key) or "").strip()
                )
            if isinstance(value, list):
                return " | ".join(
                    str(item or "").strip() for item in value if str(item or "").strip()
                )
            return str(value or "").strip()

        parts = [
            f"EvidenceArtifact: {artifact.get('claim', '')}",
            f"target: {artifact.get('target', '')}",
            f"control: {_section(artifact.get('control'))}",
            f"negative_control: {_section(artifact.get('negative_control'))}",
            f"payload: {_section(artifact.get('payload'))}",
            f"delta: {artifact.get('observed_delta', '')}",
            f"repro: {_section(artifact.get('repro_steps'))}",
            f"repeat_count: {artifact.get('repeat_count', '')}",
            f"source_output: {artifact.get('source_output', '')}",
            f"source_output_used_in_pivot: {artifact.get('source_output_used_in_pivot', '')}",
            f"crown_jewel_evidence: {artifact.get('crown_jewel_evidence', '')}",
        ]
        return "\n".join(part for part in parts if part.split(":", 1)[-1].strip())[:1400]

    def _mark_agent_graph_crown_parent_needs_report(
        self,
        *,
        parent_branch_id: str,
        agent: dict[str, Any],
        summary: str,
    ) -> None:
        parent = self.state.branches.get(parent_branch_id)
        if parent is None or parent.status in _TERMINAL_BRANCH_STATUSES:
            return
        result_text = str(agent.get("result") or "").strip()
        artifact_text = self._agent_graph_evidence_artifact_report_text(agent)
        proof_text = " | ".join(part for part in (result_text[:240], artifact_text[:900]) if part)
        if proof_text and proof_text not in parent.evidence:
            parent.evidence = (parent.evidence + "; " + proof_text).strip("; ")
        parent.status = "active"
        parent.escalation_status = "needs_report"
        parent.escalation_reason = (
            "proven post-exploit EvidenceArtifact requires report_finding/link_chain"
        )
        parent.escalation_owner = "director"
        parent.blocker = "report_finding required for proven crown-jewel impact"
        parent.next_step = (
            "Call report_finding for the proven post-exploit crown impact, then link_chain "
            "to the foothold finding when a prior finding exists."
        )
        parent.last_tool = "agent_graph"
        parent.last_summary = summary[:240]
        parent.last_report = result_text[:160] or parent.last_report
        parent.last_iter = self.state.iteration
        todo = self.state.ensure_scan_todo(
            parent.id,
            parent.title,
            priority=parent.priority,
            source_candidate_id=parent.source_candidate_id or parent.id,
        )
        todo.status = "in_progress"
        todo.detail = "report_finding required for proven crown impact"
        todo.last_iter = self.state.iteration

    @staticmethod
    def _agent_graph_crown_jewel_for_result(result: str) -> str:
        return agent_graph_crown_jewel_for_result(result)

    @staticmethod
    def _agent_graph_result_needs_crown_chain(result: str) -> bool:
        return agent_graph_result_needs_crown_chain(result)

    @staticmethod
    def _agent_graph_branch_id(agent_id: str) -> str:
        return agent_graph_branch_id(agent_id)

    @staticmethod
    def _agent_graph_branch_priority(agent: dict[str, Any]) -> int:
        return agent_graph_branch_priority(agent)

    @staticmethod
    def _agent_graph_terminal_branch_status(agent: dict[str, Any]) -> str:
        return agent_graph_terminal_branch_status(agent)

    def _sync_agent_graph_result_to_branches(
        self,
        *,
        name: str,
        args: dict[str, Any] | Any,
        result: ToolResult,
    ) -> None:
        """Mirror agent_graph state into durable BranchState records.

        The tool keeps the protocol state; the loop needs a branch projection so
        focus discipline, dashboard goals, and finish gates can reason about
        delegated work.
        """
        if name != "agent_graph" or not isinstance(args, dict) or not isinstance(result.data, dict):
            return

        agents: list[dict[str, Any]] = []
        single = result.data.get("agent")
        if isinstance(single, dict):
            agents.append(single)
        for key in ("agents", "active_agents"):
            collection = result.data.get(key)
            if isinstance(collection, list):
                agents.extend(item for item in collection if isinstance(item, dict))

        seen: set[str] = set()
        for agent in agents:
            agent_id = str(agent.get("id") or "").strip()
            branch_id = self._agent_graph_branch_id(agent_id)
            if not branch_id or branch_id in seen:
                continue
            seen.add(branch_id)
            role = str(agent.get("role") or "recon_worker").strip() or "recon_worker"
            task = str(agent.get("task") or "").strip()
            result_text = str(agent.get("result") or "").strip()
            envelope = (
                agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
            )
            result_package = (
                agent.get("result_package") if isinstance(agent.get("result_package"), dict) else {}
            )
            escalation = (
                agent.get("escalation") if isinstance(agent.get("escalation"), dict) else {}
            )
            parent_agent_id = str(agent.get("parent_id") or "").strip()
            parent_branch_id = self._agent_graph_branch_id(parent_agent_id)
            if parent_branch_id and parent_branch_id not in self.state.branches:
                parent_branch_id = ""
            if role == "post_exploit_worker" and parent_branch_id:
                crown_parent_id = f"{parent_branch_id}:crown-chain"
                if crown_parent_id in self.state.branches:
                    parent_branch_id = crown_parent_id
            skills = (
                [
                    str(skill).strip()
                    for skill in list(agent.get("skills") or [])
                    if str(skill).strip()
                ]
                if isinstance(agent.get("skills"), list)
                else []
            )
            executions = agent.get("executions")
            successful_executions = (
                [item for item in executions if isinstance(item, dict) and item.get("ok")]
                if isinstance(executions, list)
                else []
            )
            latest_success = successful_executions[-1] if successful_executions else {}
            latest_success_summary = str(latest_success.get("summary") or "").strip()
            latest_success_tool = str(latest_success.get("tool") or "child").strip()
            task_terms = [
                token
                for token in re.findall(r"[a-z0-9_./:-]{4,}", task.lower())
                if token not in {"with", "then", "this", "that", "into", "from"}
            ]
            expected_artifact = str(envelope.get("expected_artifact") or "").strip()
            stop_condition = str(envelope.get("stop_condition") or "").strip()
            verdict_guess = str(result_package.get("verdict_guess") or "").strip()
            recommended_next = str(result_package.get("recommended_next_step") or "").strip()
            needs_artifact = agent_graph_needs_evidence_artifact(agent)
            has_valid_artifact = agent_graph_has_valid_evidence_artifact(agent)
            artifact_brief = agent_graph_evidence_artifact_brief(agent, width=140)
            evidence_gap = agent_graph_evidence_gap(agent)
            gap_instruction = str(evidence_gap.get("next_instruction") or "").strip()
            gap_fields = [
                str(item).strip()
                for item in list(evidence_gap.get("gap_fields") or [])
                if str(item).strip()
            ]
            next_step = (
                "Finish this delegated agent with agent_graph(action='finish', agent_id=..., result=...) "
                "after concrete evidence is gathered."
            )
            if skills:
                next_step = f"Use skill/tool path: {', '.join(skills[:4])}; then finish this delegated agent with a concrete result."
            if latest_success:
                evidence_hint = (
                    f"{latest_success_tool}: {latest_success_summary}"
                    if latest_success_summary
                    else latest_success_tool
                )
                if needs_artifact:
                    gap_text = f" Missing/weak: {', '.join(gap_fields[:6])}." if gap_fields else ""
                    instruction_text = (
                        gap_instruction
                        or "Return a valid EvidenceArtifact with claim,target,control,payload,observed_delta,repro_steps."
                    )
                    next_step = (
                        "Successful child execution is available but proof is incomplete. "
                        f"Run agent_graph(action='run', agent_id='{agent_id}', "
                        f"instruction='{instruction_text[:180]}') until the worker returns a valid "
                        f"EvidenceArtifact.{gap_text} Evidence: {evidence_hint[:100]}"
                    )
                elif has_valid_artifact:
                    next_step = (
                        "Valid EvidenceArtifact is available. Finish this delegated agent with "
                        f"agent_graph(action='finish', agent_id='{agent_id}', result='<concrete evidence and impact>') "
                        f"or open the required chain/pivot. Evidence: {evidence_hint[:100]}"
                    )
                else:
                    next_step = (
                        "Successful child execution is available. Finish this delegated agent with "
                        f"agent_graph(action='finish', agent_id='{agent_id}', result='<concrete evidence and impact>') "
                        f"unless the evidence is inconclusive. Evidence: {evidence_hint[:120]}"
                    )
            if verdict_guess == "candidate_positive" and recommended_next:
                next_step = f"{next_step} Director follow-up: {recommended_next[:120]}"
            if stop_condition:
                next_step = f"{next_step} Stop rule: {stop_condition[:120]}"
            branch = self.state.ensure_branch(
                branch_id,
                f"agent_graph:{role}",
                f"{role}: {task or agent_id}"[:120],
                priority=self._agent_graph_branch_priority(agent),
                role=role,
                phase="delegated_task",
                owner="agent_graph",
                parent_branch_id=parent_branch_id,
                objective=str(envelope.get("objective") or task),
                next_step=next_step,
                blocker=(
                    str(escalation.get("reason") or result_text)
                    if str(agent.get("status") or "").lower() == "blocked"
                    else ""
                ),
                escalation_status=str(escalation.get("status") or ""),
                escalation_reason=str(escalation.get("reason") or ""),
                escalation_owner=str(escalation.get("recommended_owner") or ""),
                crown_jewel="delegated proof result",
                evidence=(
                    result_text
                    or str(result_package.get("raw_evidence_summary") or "")
                    or latest_success_summary
                    or f"agent_graph {agent_id}"
                ),
                watch_terms=[agent_id, role, task, *task_terms, *skills],
            )
            branch.status = self._agent_graph_terminal_branch_status(agent)
            branch.last_tool = "agent_graph"
            branch.last_summary = result.summary[:240]
            branch.last_report = (
                result_text
                or str(result_package.get("raw_evidence_summary") or "")
                or result.summary
            )[:160]
            branch.last_iter = self.state.iteration
            if (
                branch.status == "active"
                and verdict_guess == "candidate_positive"
                and not branch.blocker
            ):
                branch.blocker = "positive delegated worker result requires director pivot/finish"
            if branch.status == "active" and needs_artifact:
                branch.blocker = str(
                    escalation.get("reason")
                    or gap_instruction
                    or "positive delegated worker result requires valid EvidenceArtifact"
                )[:180]
            if str(escalation.get("status") or "") == "blocked_with_reason":
                branch.blocker = str(escalation.get("reason") or branch.blocker)[:180]
                branch.next_step = (
                    "Evidence gap repeated without improvement. Finish this agent as blocked with the "
                    "gap reason, or create a narrower worker with fresh scope. "
                    f"Last gap: {(gap_instruction or branch.blocker)[:120]}"
                )
            if result.error in {
                "run_limit_reached",
                "executor_unavailable",
                "no_child_action",
                "child_tool_unavailable",
                "child_tool_not_allowed",
                "sdk_background_worker_failed",
                "sdk_background_worker_crashed",
                "sdk_child_run_failed",
                "missing_agent_finish",
                "no_child_tools",
            }:
                branch.blocker = result.summary[:180]
            if result.error in {"unsupported_execution_evidence", "insufficient_proof_artifact"}:
                branch.blocker = result.summary[:180]
                proof_note = (
                    "The previous successful execution did not include concrete PoC/control evidence."
                    if result.error == "insufficient_proof_artifact"
                    else "The previous successful execution did not support the claimed vulnerability family."
                )
                branch.next_step = (
                    "Run child evidence that matches the positive claim with concrete proof using "
                    f"agent_graph(action='run', agent_id='{agent_id}'), or finish this agent as blocked/clean. "
                    f"{proof_note}"
                )
            if branch.status == "blocked" and result_text:
                branch.blocker = str(escalation.get("reason") or result_text)[:180]
            elif branch.status in _TERMINAL_BRANCH_STATUSES:
                branch.blocker = ""
            if expected_artifact and branch.status == "active":
                branch.evidence = f"{branch.evidence[:180]} | expect: {expected_artifact[:90]}"
            if artifact_brief and branch.status == "active":
                branch.evidence = f"{branch.evidence[:180]} | {artifact_brief[:100]}"

            todo = self.state.ensure_scan_todo(
                branch.id,
                branch.title,
                priority=branch.priority,
                source_candidate_id=branch.source_candidate_id or branch.id,
            )
            todo.status = {
                "proven": "done",
                "exhausted": "done",
                "blocked": "blocked",
                "active": "in_progress",
            }.get(branch.status, "pending")
            todo.detail = branch.last_report[:120]
            todo.last_iter = self.state.iteration
            if verdict_guess == "candidate_positive" and branch.status == "active":
                todo.detail = f"candidate positive -> {str(result_package.get('recommended_next_step') or '')[:96]}"
            self.state.add_shared_note(f"agent_graph {agent_id}: {branch.status} {task[:80]}")
            if (
                role == "post_exploit_worker"
                and branch.status == "proven"
                and parent_branch_id
                and agent_graph_has_valid_evidence_artifact(agent)
            ):
                self._mark_agent_graph_crown_parent_needs_report(
                    parent_branch_id=parent_branch_id,
                    agent=agent,
                    summary=result.summary,
                )
            crown_next = self._agent_graph_crown_chain_next(agent)
            if crown_next:
                self.state.add_shared_note(f"chain directive {agent_id}: {crown_next}")
                followup = self._ensure_agent_graph_crown_followup_branch(
                    agent,
                    parent_branch_id=branch.id,
                    directive=crown_next,
                )
                if followup is not None:
                    self.state.add_shared_note(
                        f"chain follow-up {agent_id}: {followup.id} -> {followup.crown_jewel}"
                    )

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

    async def _agent_graph_worker_llm_action(
        self,
        agent: dict[str, Any],
        instruction: str,
        *,
        allowed_child_tools: set[str],
    ) -> dict[str, Any]:
        brain = getattr(self, "brain", None)
        endpoint = self._agent_graph_worker_endpoint()
        can_call_worker = callable(getattr(brain, "_call_llm_direct", None)) or callable(
            getattr(brain, "_call_openai_compatible", None)
        )
        if brain is None or endpoint is None:
            return self._agent_graph_worker_planner_failure("worker_planner_not_configured")
        if not can_call_worker:
            return self._agent_graph_worker_planner_failure("worker_llm_not_callable")

        system_prompt, user_prompt, budget = self._agent_graph_worker_planner_prompts(
            agent,
            instruction,
            allowed_child_tools=allowed_child_tools,
        )
        prompt_tokens = estimate_context_tokens(system_prompt) + estimate_context_tokens(user_prompt)
        if prompt_tokens > budget.max_prompt_tokens:
            user_prompt = trim_text_chars(
                user_prompt,
                max(900, int(budget.max_prompt_tokens * 2.2)),
            )
            prompt_tokens = estimate_context_tokens(system_prompt) + estimate_context_tokens(user_prompt)
        compacted = prompt_tokens > budget.max_prompt_tokens

        semaphore = self._agent_graph_worker_llm_semaphore()
        provider = str(getattr(endpoint, "provider", "") or "")
        model = str(getattr(endpoint, "model", "") or "")
        try:
            async with semaphore:
                loop = asyncio.get_running_loop()
                text = await loop.run_in_executor(
                    None,
                    lambda: self._agent_graph_call_worker_llm_direct(
                        brain,
                        system_prompt,
                        user_prompt,
                        provider=provider,
                        model=model,
                        base_url=str(getattr(endpoint, "base_url", "") or ""),
                    ),
                )
        except Exception as exc:
            return self._agent_graph_worker_planner_failure(
                "worker_llm_call_failed",
                detail=str(exc)[:180],
                provider=provider,
                model=model,
                prompt_tokens=prompt_tokens,
            )
        if not text:
            return self._agent_graph_worker_planner_failure(
                "worker_llm_empty_response",
                provider=provider,
                model=model,
                prompt_tokens=prompt_tokens,
            )

        planned = self._agent_graph_parse_worker_llm_action(
            str(text),
            agent=agent,
            instruction=instruction,
            allowed_child_tools=allowed_child_tools,
        )
        if self._agent_graph_worker_planner_should_repair(planned):
            planned = await self._agent_graph_repair_worker_llm_action(
                brain,
                agent,
                instruction,
                allowed_child_tools=allowed_child_tools,
                initial_failure=planned,
                previous_response=str(text),
                provider=provider,
                model=model,
                base_url=str(getattr(endpoint, "base_url", "") or ""),
            )
        planned.update({"provider": provider, "model": model, "prompt_tokens": prompt_tokens})
        if compacted:
            planned["prompt_compacted"] = True
        return planned

    async def _agent_graph_repair_worker_llm_action(
        self,
        brain: Any,
        agent: dict[str, Any],
        instruction: str,
        *,
        allowed_child_tools: set[str],
        initial_failure: dict[str, Any],
        previous_response: str,
        provider: str,
        model: str,
        base_url: str,
    ) -> dict[str, Any]:
        system_prompt, user_prompt, repair_tokens = self._agent_graph_worker_repair_prompts(
            agent,
            instruction,
            allowed_child_tools=allowed_child_tools,
            initial_failure=initial_failure,
            previous_response=previous_response,
        )
        initial_reason = str(initial_failure.get("failure_reason") or "unknown_worker_planner_failure")
        try:
            async with self._agent_graph_worker_llm_semaphore():
                loop = asyncio.get_running_loop()
                text = await loop.run_in_executor(
                    None,
                    lambda: self._agent_graph_call_worker_llm_direct(
                        brain,
                        system_prompt,
                        user_prompt,
                        provider=provider,
                        model=model,
                        base_url=base_url,
                    ),
                )
        except Exception as exc:
            repaired = self._agent_graph_worker_planner_failure(
                "worker_llm_call_failed",
                detail=str(exc)[:180],
                provider=provider,
                model=model,
                prompt_tokens=repair_tokens,
            )
            return self._agent_graph_worker_planner_repair_failure(
                initial_failure,
                repaired,
                repair_tokens=repair_tokens,
            )
        if not text:
            repaired = self._agent_graph_worker_planner_failure(
                "worker_llm_empty_response",
                provider=provider,
                model=model,
                prompt_tokens=repair_tokens,
            )
            return self._agent_graph_worker_planner_repair_failure(
                initial_failure,
                repaired,
                repair_tokens=repair_tokens,
            )

        repaired = self._agent_graph_parse_worker_llm_action(
            str(text),
            agent=agent,
            instruction=instruction,
            allowed_child_tools=allowed_child_tools,
        )
        repaired["repair_attempted"] = True
        repaired["repair_prompt_tokens"] = repair_tokens
        repaired["initial_failure_reason"] = initial_reason
        if repaired.get("ok"):
            repaired["repair_succeeded"] = True
            return repaired
        return self._agent_graph_worker_planner_repair_failure(
            initial_failure,
            repaired,
            repair_tokens=repair_tokens,
        )

    @staticmethod
    def _agent_graph_worker_planner_should_repair(planned: dict[str, Any] | None) -> bool:
        if not planned or planned.get("ok"):
            return False
        return str(planned.get("failure_reason") or "") in _WORKER_PLANNER_REPAIRABLE_FAILURES

    @staticmethod
    def _agent_graph_worker_planner_repair_failure(
        initial_failure: dict[str, Any],
        repaired_failure: dict[str, Any],
        *,
        repair_tokens: int,
    ) -> dict[str, Any]:
        initial_reason = str(
            initial_failure.get("failure_reason") or "unknown_worker_planner_failure"
        )
        repair_reason = str(
            repaired_failure.get("failure_reason") or "unknown_worker_planner_failure"
        )
        detail = str(repaired_failure.get("detail") or initial_failure.get("detail") or "")
        failure = dict(repaired_failure)
        failure.update(
            {
                "ok": False,
                "failure_reason": repair_reason,
                "detail": detail[:240],
                "repair_attempted": True,
                "repair_succeeded": False,
                "initial_failure_reason": initial_reason,
                "repair_failure_reason": repair_reason,
                "repair_prompt_tokens": int(repair_tokens or 0),
            }
        )
        return failure

    @staticmethod
    def _agent_graph_worker_planner_failure(
        reason: str,
        *,
        detail: str = "",
        provider: str = "",
        model: str = "",
        prompt_tokens: int = 0,
    ) -> dict[str, Any]:
        return {
            "ok": False,
            "failure_reason": str(reason or "unknown_worker_planner_failure"),
            "detail": str(detail or "")[:240],
            "provider": provider,
            "model": model,
            "prompt_tokens": int(prompt_tokens or 0),
        }

    def _agent_graph_worker_planner_success_meta(
        self,
        planned: dict[str, Any],
    ) -> dict[str, Any]:
        self._agent_graph_record_worker_planner_metric(planned, succeeded=True)
        meta = {
            "source": "worker_llm",
            "provider": planned.get("provider", ""),
            "model": planned.get("model", ""),
            "evidence_intent": planned.get("evidence_intent", ""),
            "prompt_tokens": planned.get("prompt_tokens", 0),
        }
        self._agent_graph_apply_worker_planner_repair_meta(meta, planned)
        return meta

    def _agent_graph_worker_planner_fallback_meta(
        self,
        planned: dict[str, Any] | None,
    ) -> dict[str, Any]:
        failure = planned or self._agent_graph_worker_planner_failure("worker_planner_not_configured")
        reason = str(failure.get("failure_reason") or "unknown_worker_planner_failure")
        if reason != "worker_planner_not_configured":
            self._agent_graph_record_worker_planner_metric(failure, succeeded=False)
        counts = getattr(self, "_agent_graph_worker_planner_fallback_counts", None)
        if not isinstance(counts, dict):
            counts = {}
            self._agent_graph_worker_planner_fallback_counts = counts
        counts[reason] = int(counts.get(reason, 0)) + 1
        meta = {
            "source": "deterministic_fallback",
            "fallback_reason": reason,
            "fallback_count": counts[reason],
            "provider": str(failure.get("provider") or ""),
            "model": str(failure.get("model") or ""),
            "prompt_tokens": int(failure.get("prompt_tokens") or 0),
        }
        detail = str(failure.get("detail") or "").strip()
        if detail:
            meta["detail"] = detail[:180]
        self._agent_graph_apply_worker_planner_repair_meta(meta, failure)
        if reason in _WORKER_PLANNER_UNAVAILABLE_REASONS and counts[reason] >= 3:
            meta["health"] = "local_worker_unavailable"
            note = f"agent_graph local worker unavailable: {reason} x{counts[reason]}"
            marker = f"agent_graph local worker unavailable: {reason}"
            if not any(str(existing).startswith(marker) for existing in self.state.shared_notes):
                self.state.add_shared_note(note)
        return meta

    def _agent_graph_record_worker_planner_metric(
        self,
        planned: dict[str, Any],
        *,
        succeeded: bool,
    ) -> None:
        metrics = getattr(self, "_agent_graph_worker_planner_metrics", None)
        if not isinstance(metrics, dict):
            metrics = {}
            self._agent_graph_worker_planner_metrics = metrics
        for key in (
            "attempts",
            "successes",
            "fallbacks",
            "repairs",
            "repair_successes",
            "repair_failures",
            "unavailable",
        ):
            metrics[key] = int(metrics.get(key) or 0)
        metrics["attempts"] += 1
        if succeeded:
            metrics["successes"] += 1
        else:
            metrics["fallbacks"] += 1
        if planned.get("repair_attempted"):
            metrics["repairs"] += 1
            if planned.get("repair_succeeded"):
                metrics["repair_successes"] += 1
            else:
                metrics["repair_failures"] += 1
        reason = str(planned.get("failure_reason") or planned.get("fallback_reason") or "")
        if reason in _WORKER_PLANNER_UNAVAILABLE_REASONS:
            metrics["unavailable"] += 1

    @staticmethod
    def _agent_graph_apply_worker_planner_repair_meta(
        meta: dict[str, Any],
        planned: dict[str, Any],
    ) -> None:
        if not planned.get("repair_attempted"):
            return
        meta["repair_attempted"] = True
        meta["repair_succeeded"] = bool(planned.get("repair_succeeded"))
        initial_reason = str(planned.get("initial_failure_reason") or "").strip()
        repair_reason = str(planned.get("repair_failure_reason") or "").strip()
        repair_tokens = int(planned.get("repair_prompt_tokens") or 0)
        if initial_reason:
            meta["initial_failure_reason"] = initial_reason
        if repair_reason:
            meta["repair_failure_reason"] = repair_reason
        if repair_tokens:
            meta["repair_prompt_tokens"] = repair_tokens

    @staticmethod
    def _agent_graph_call_worker_llm_direct(
        brain: Any,
        system_prompt: str,
        user_prompt: str,
        *,
        provider: str,
        model: str,
        base_url: str = "",
    ) -> str | None:
        if base_url and provider in {"llamacpp", "ollama"}:
            call_compatible = getattr(brain, "_call_openai_compatible", None)
            if callable(call_compatible):
                return call_compatible(
                    system_prompt,
                    user_prompt,
                    provider,
                    model,
                    base_url=base_url,
                )
        call_direct = getattr(brain, "_call_llm_direct", None)
        if not callable(call_direct):
            return None
        return call_direct(
            system_prompt,
            user_prompt,
            provider=provider,
            model=model,
        )

    def _agent_graph_worker_endpoint(self) -> Any | None:
        config = getattr(getattr(self, "brain", None), "_hybrid_model_config", None)
        if config is None:
            return None
        try:
            return config.for_role("worker")
        except Exception:
            return getattr(config, "worker", None)

    def _agent_graph_worker_context_budget(self) -> Any:
        endpoint = self._agent_graph_worker_endpoint()
        provider = str(getattr(endpoint, "provider", "") or "llamacpp")
        model = str(getattr(endpoint, "model", "") or "local")
        return resolve_context_budget("worker", provider=provider, model=model)

    def _agent_graph_worker_llm_semaphore(self) -> asyncio.Semaphore:
        raw_limit = os.environ.get("VXIS_LOCAL_WORKER_CONCURRENCY", "1").strip()
        try:
            limit = max(1, int(raw_limit))
        except ValueError:
            limit = 1
        current_limit = getattr(self, "_agent_graph_worker_llm_semaphore_limit", None)
        semaphore = getattr(self, "_agent_graph_worker_llm_semaphore_obj", None)
        if semaphore is None or current_limit != limit:
            semaphore = asyncio.Semaphore(limit)
            self._agent_graph_worker_llm_semaphore_obj = semaphore
            self._agent_graph_worker_llm_semaphore_limit = limit
        return semaphore

    def _agent_graph_worker_planner_prompts(
        self,
        agent: dict[str, Any],
        instruction: str,
        *,
        allowed_child_tools: set[str],
    ) -> tuple[str, str, Any]:
        budget = self._agent_graph_worker_context_budget()
        system_prompt = (
            "You are a bounded VXIS worker planner. Return JSON only. "
            'Schema: {"tool":"run_skill|http_request|nmap_scan|browser_navigate|browser_analyze_dom",'
            '"args":{},"evidence_intent":"short proof goal"}. '
            "Choose exactly one allowed tool. Do not report findings or finish scans. "
            "Positive evidence must preserve EvidenceArtifact fields: "
            "claim,target,control,payload,observed_delta,repro_steps."
        )
        envelope = agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        result_package = (
            agent.get("result_package") if isinstance(agent.get("result_package"), dict) else {}
        )
        critical_lines = [
            f"target={self.state.target}",
            f"agent_id={str(agent.get('id') or '')}",
            f"role={str(agent.get('role') or 'recon_worker')}",
            f"allowed_tools={','.join(sorted(allowed_child_tools))}",
            f"allowed_skills={','.join(str(skill) for skill in list(agent.get('skills') or [])[:6])}",
            "run_skill_args={\"skill\":\"one allowed skill\",\"target_url\":\"target\",\"params\":{}}",
            "http_request_args={\"method\":\"GET|POST|HEAD\",\"url\":\"target/path\"}",
            "browser_navigate_args={\"url\":\"target/path\"}",
            "browser_analyze_dom_args={}",
            f"task={trim_text_chars(agent.get('task'), budget.max_message_chars)}",
            f"objective={trim_text_chars(envelope.get('objective'), budget.max_message_chars)}",
            f"expected_artifact={trim_text_chars(envelope.get('expected_artifact'), budget.max_message_chars)}",
            f"stop_condition={trim_text_chars(envelope.get('stop_condition'), budget.max_message_chars)}",
            f"escalation_trigger={trim_text_chars(envelope.get('escalation_trigger'), budget.max_message_chars)}",
        ]
        if instruction:
            critical_lines.append(
                f"director_instruction={trim_text_chars(instruction, budget.max_message_chars)}"
            )

        history_lines = [
            "skill_context="
            + trim_text_chars(agent.get("skill_context"), budget.max_skill_chars),
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

        static_tokens = estimate_context_tokens(system_prompt) + sum(
            estimate_context_tokens(line) for line in critical_lines
        )
        history_budget = max(160, budget.max_prompt_tokens - static_tokens - 96)
        fitted_history = fit_lines_to_token_budget(
            history_lines,
            history_budget,
            prefer_recent=True,
            marker="WORKER-CONTEXT COMPACTION",
        )
        user_prompt = "\n".join(critical_lines + fitted_history)
        return system_prompt, user_prompt, budget

    def _agent_graph_worker_repair_prompts(
        self,
        agent: dict[str, Any],
        instruction: str,
        *,
        allowed_child_tools: set[str],
        initial_failure: dict[str, Any],
        previous_response: str,
    ) -> tuple[str, str, int]:
        budget = self._agent_graph_worker_context_budget()
        envelope = agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        system_prompt = (
            "Repair VXIS worker planner output. JSON only. "
            'Schema: {"tool":"allowed_tool","args":{},"evidence_intent":"short proof goal"}. '
            "No prose. One bounded action."
        )
        user_lines = [
            f"failure_reason={str(initial_failure.get('failure_reason') or '')}",
            f"failure_detail={trim_text_chars(initial_failure.get('detail'), 180)}",
            f"target={self.state.target}",
            f"role={str(agent.get('role') or 'recon_worker')}",
            f"allowed_tools={','.join(sorted(allowed_child_tools))}",
            f"allowed_skills={','.join(str(skill) for skill in list(agent.get('skills') or [])[:6])}",
            "run_skill_args={\"skill\":\"one allowed skill\",\"target_url\":\"target\",\"params\":{}}",
            "EvidenceArtifact_fields=claim,target,control,payload,observed_delta,repro_steps",
            f"task={trim_text_chars(agent.get('task'), 420)}",
            f"objective={trim_text_chars(envelope.get('objective'), 360)}",
            f"expected_artifact={trim_text_chars(envelope.get('expected_artifact'), 240)}",
        ]
        if instruction:
            user_lines.append(f"director_instruction={trim_text_chars(instruction, 280)}")
        user_lines.append(f"bad_output={trim_text_chars(previous_response, 500)}")
        user_lines.append("return_valid_json_now=true")
        user_prompt = "\n".join(user_lines)
        repair_tokens = estimate_context_tokens(system_prompt) + estimate_context_tokens(user_prompt)
        if repair_tokens > budget.max_prompt_tokens:
            user_lines[-2] = f"bad_output={trim_text_chars(previous_response, 240)}"
            user_prompt = "\n".join(user_lines)
            repair_tokens = estimate_context_tokens(system_prompt) + estimate_context_tokens(user_prompt)
        return system_prompt, user_prompt, repair_tokens

    def _agent_graph_parse_worker_llm_action(
        self,
        text: str,
        *,
        agent: dict[str, Any],
        instruction: str,
        allowed_child_tools: set[str],
    ) -> dict[str, Any]:
        try:
            parsed = _parse_llm_json(text)
        except Exception as exc:
            return self._agent_graph_worker_planner_failure(
                "invalid_json",
                detail=str(exc)[:180],
            )
        item: Any = parsed
        if isinstance(item, list):
            item = item[0] if item else {}
        if isinstance(item, dict) and isinstance(item.get("actions"), list):
            item = item["actions"][0] if item["actions"] else {}
        if not isinstance(item, dict):
            return self._agent_graph_worker_planner_failure("invalid_json_shape")
        tool_name = str(item.get("tool") or "").strip()
        raw_args = item.get("args") if isinstance(item.get("args"), dict) else {}
        if not tool_name:
            return self._agent_graph_worker_planner_failure("missing_tool")
        if tool_name not in allowed_child_tools:
            return self._agent_graph_worker_planner_failure(
                "disallowed_tool",
                detail=tool_name,
            )
        if not self.registry.has_tool(tool_name):
            return self._agent_graph_worker_planner_failure(
                "tool_unavailable",
                detail=tool_name,
            )
        normalized = self._agent_graph_normalize_worker_tool_args(
            tool_name,
            raw_args,
            agent=agent,
            instruction=instruction,
        )
        if not normalized.get("ok"):
            return self._agent_graph_worker_planner_failure(
                str(normalized.get("failure_reason") or "invalid_args"),
                detail=str(normalized.get("detail") or "")[:180],
            )
        tool_args = normalized["args"]
        role = str(agent.get("role") or "recon_worker").strip() or "recon_worker"
        if not self._role_allows_action(role, tool_name, tool_args):
            return self._agent_graph_worker_planner_failure(
                "role_disallowed",
                detail=f"{role}:{tool_name}",
            )
        return {
            "ok": True,
            "tool": tool_name,
            "args": tool_args,
            "evidence_intent": trim_text_chars(item.get("evidence_intent") or "", 220),
        }

    def _agent_graph_normalize_worker_tool_args(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        agent: dict[str, Any],
        instruction: str,
    ) -> dict[str, Any]:
        if tool_name == "run_skill":
            raw_skill = str(args.get("skill") or args.get("_skill_override") or "").strip()
            if not raw_skill:
                return {"ok": False, "failure_reason": "missing_skill"}
            skill = self._pivoted_skill_name(raw_skill)
            if not skill:
                return {"ok": False, "failure_reason": "invalid_skill", "detail": raw_skill}
            allowed_skills = {
                self._pivoted_skill_name(str(item))
                for item in list(agent.get("skills") or [])
                if self._pivoted_skill_name(str(item))
            }
            if allowed_skills and skill not in allowed_skills:
                return {"ok": False, "failure_reason": "disallowed_skill", "detail": skill}
            hint_blob = " ".join(
                str(value or "")
                for value in (
                    agent.get("role"),
                    agent.get("task"),
                    instruction,
                    args,
                )
            ).lower()
            params = args.get("params") if isinstance(args.get("params"), dict) else {}
            default_params = self._best_skill_params(skill, hint_blob=hint_blob)
            merged_params = {**default_params, **params}
            return {
                "ok": True,
                "args": {
                    "skill": skill,
                    "target_url": str(args.get("target_url") or self.state.target),
                    "params": compact_context_value(merged_params, max_chars=900),
                },
            }
        if tool_name == "http_request":
            method = str(args.get("method") or "GET").strip().upper()
            if method not in {"GET", "POST", "HEAD", "OPTIONS"}:
                return {"ok": False, "failure_reason": "invalid_args", "detail": method}
            out: dict[str, Any] = {
                "method": method,
                "url": str(args.get("url") or self.state.target),
            }
            if isinstance(args.get("headers"), dict):
                out["headers"] = compact_context_value(args["headers"], max_chars=600)
            if "body" in args:
                out["body"] = trim_text_chars(args.get("body"), 1200)
            return {"ok": True, "args": out}
        if tool_name == "nmap_scan":
            out = {"target": str(args.get("target") or self.state.target)}
            for key in ("ports", "scripts"):
                if key in args:
                    out[key] = trim_text_chars(args.get(key), 80)
            if "udp" in args:
                out["udp"] = bool(args.get("udp"))
            if "timing" in args:
                out["timing"] = args.get("timing")
            if "timeout" in args:
                out["timeout"] = args.get("timeout")
            return {"ok": True, "args": out}
        if tool_name == "browser_navigate":
            return {"ok": True, "args": {"url": str(args.get("url") or self.state.target)}}
        if tool_name == "browser_analyze_dom":
            return {
                "ok": True,
                "args": {
                    str(key): compact_context_value(value, max_chars=500)
                    for key, value in args.items()
                    if str(key) in {"selector", "include_text", "limit"}
                },
            }
        return {"ok": False, "failure_reason": "disallowed_tool", "detail": tool_name}

    def _agent_graph_action_from_node(
        self,
        agent: dict[str, Any],
        instruction: str,
    ) -> tuple[str, dict[str, Any]] | None:
        envelope = (
            agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        )
        blob = " ".join(
            str(value or "")
            for value in (
                agent.get("role"),
                agent.get("task"),
                agent.get("result"),
                " ".join(str(skill) for skill in list(agent.get("skills") or [])),
                str(envelope.get("objective") or ""),
                str(envelope.get("expected_artifact") or ""),
                str(envelope.get("stop_condition") or ""),
                instruction,
            )
        ).lower()
        envelope_allowed = self._agent_graph_envelope_allowed_tools(agent)
        if (
            self.registry.has_tool("nmap_scan")
            and (not envelope_allowed or "nmap_scan" in envelope_allowed)
            and any(
                token in blob
                for token in (
                    "nmap",
                    "open port",
                    "port ",
                    "service",
                    "tcp",
                    "udp",
                    "ssh",
                    "rdp",
                    "redis",
                    "mongodb",
                    "postgres",
                    "mysql",
                    "smb",
                )
            )
        ):
            return ("nmap_scan", self._agent_graph_nmap_args_from_blob(blob))
        if "run_skill" in self.registry.list_tools():
            for raw_skill in list(agent.get("skills") or []):
                skill = self._pivoted_skill_name(str(raw_skill))
                if skill:
                    return (
                        "run_skill",
                        {
                            "skill": skill,
                            "target_url": str(self.state.target),
                            "params": self._best_skill_params(skill, hint_blob=blob),
                        },
                    )
            inferred = (
                ("execute_chain", ("chain", "crown", "post-auth", "post exploit", "post_exploit")),
                ("test_idor", ("idor", "access_control", "broken access", "object")),
                ("test_injection", ("sqli", "sql", "injection", "nosql", "ssti")),
                ("test_xss", ("xss", "script")),
                ("test_ssrf", ("ssrf", "callback", "metadata")),
                ("attempt_auth", ("auth", "login", "credential", "session")),
                ("test_sensitive_files", ("secret", "config", "file", "disclosure", "git")),
                ("enumerate_endpoints", ("route", "endpoint", "surface", "map")),
            )
            for skill_name, tokens in inferred:
                if not any(token in blob for token in tokens):
                    continue
                skill = self._pivoted_skill_name(skill_name)
                if not skill:
                    continue
                return (
                    "run_skill",
                    {
                        "skill": skill,
                        "target_url": str(self.state.target),
                        "params": self._best_skill_params(skill, hint_blob=blob),
                    },
                )

        if "http_request" in self.registry.list_tools():
            return ("http_request", {"method": "GET", "url": str(self.state.target)})
        return None

    def _agent_graph_nmap_args_from_blob(self, blob: str) -> dict[str, Any]:
        target = str(self.state.target)
        host_match = re.search(r"\b(?:on|at|target=)?\s*([A-Za-z0-9._-]+):(\d{1,5})/(tcp|udp)\b", blob)
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
        if any(token in blob for token in ("vuln", "cve", "noauth", "no-auth", "redis", "mongodb", "postgres", "mysql", "smb", "rdp", "vnc", "ftp", "nfs")):
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

    def _promote_agent_graph_nmap_result(
        self,
        result: ToolResult,
        *,
        child_args: dict[str, Any],
        child_result: ToolResult,
    ) -> bool:
        if not isinstance(child_result.data, dict):
            return False
        open_ports = self._nmap_open_ports_from_child_result(child_result)
        if not open_ports:
            return False
        agent = result.data.get("agent") if isinstance(result.data, dict) else {}
        parent_agent_id = str(agent.get("id") or child_result.data.get("agent_id") or "").strip()
        parent_branch_id = self._agent_graph_branch_id(parent_agent_id)
        if parent_branch_id not in self.state.branches:
            parent_branch_id = "root"

        promoted = False
        ranked_services = sorted(
            [item for item in open_ports if isinstance(item, dict)],
            key=self._nmap_service_priority,
            reverse=True,
        )[:5]
        for service in ranked_services:
            port = str(service.get("port") or "").strip()
            protocol = str(service.get("protocol") or "tcp").strip().lower() or "tcp"
            if not port:
                continue
            profile = self._nmap_service_followup_profile(service)
            branch_id = f"{parent_branch_id}:svc:{protocol}-{port}"
            host = str(service.get("host") or child_result.data.get("target") or child_args.get("target") or self.state.target)
            service_label = self._nmap_service_label(service)
            evidence = (
                f"nmap_scan {host}:{port}/{protocol} {service_label}; "
                f"reason={str(service.get('reason') or '')}"
            ).strip()
            branch = self.state.ensure_branch(
                branch_id,
                "NET-SERVICE-PIVOT",
                f"Probe {service_label} on {host}:{port}/{protocol}"[:120],
                priority=profile["priority"],
                role=profile["role"],
                phase="service_pivot",
                owner="root",
                parent_branch_id=parent_branch_id if parent_branch_id != "root" else "",
                source_candidate_id=parent_branch_id if parent_branch_id != "root" else "network:services",
                objective=profile["objective"],
                next_step=profile["next_step"],
                crown_jewel=profile["crown_jewel"],
                evidence=evidence,
                watch_terms=profile["watch_terms"],
            )
            if branch.status not in _TERMINAL_BRANCH_STATUSES:
                branch.status = "open"
            branch.last_tool = "nmap_scan"
            branch.last_summary = child_result.summary[:240]
            branch.last_report = evidence[:160]
            branch.last_iter = self.state.iteration
            todo = self.state.ensure_scan_todo(
                branch.id,
                branch.title,
                priority=branch.priority,
                source_candidate_id=branch.source_candidate_id or branch.id,
            )
            todo.status = "pending" if branch.status == "open" else todo.status
            todo.detail = branch.next_step[:120]
            todo.last_iter = self.state.iteration
            self.state.add_shared_note(f"nmap service pivot {host}:{port}/{protocol}: {service_label}")
            promoted = True
        return promoted

    @staticmethod
    def _nmap_open_ports_from_child_result(child_result: ToolResult) -> list[dict[str, Any]]:
        if not isinstance(child_result.data, dict):
            return []
        raw_open_ports = child_result.data.get("open_ports")
        if isinstance(raw_open_ports, str):
            try:
                raw_open_ports = ast.literal_eval(raw_open_ports)
            except (SyntaxError, ValueError):
                raw_open_ports = []
        if not isinstance(raw_open_ports, list):
            return []
        return [dict(item) for item in raw_open_ports if isinstance(item, dict)]

    @staticmethod
    def _nmap_service_label(service: dict[str, Any]) -> str:
        parts = [
            str(service.get("service") or "unknown").strip(),
            str(service.get("product") or "").strip(),
            str(service.get("version") or "").strip(),
        ]
        return " ".join(part for part in parts if part).strip() or "unknown service"

    @staticmethod
    def _nmap_service_priority(service: dict[str, Any]) -> int:
        label = ScanLoopAgentGraphMixin._nmap_service_label(service).lower()
        port = str(service.get("port") or "")
        if any(token in label for token in ("redis", "mongodb", "postgres", "mysql", "mssql", "oracle", "elasticsearch")):
            return 96
        if any(token in label for token in ("rdp", "vnc", "telnet", "ftp", "smb", "microsoft-ds", "nfs")) or port in {"21", "23", "445", "3389", "5900"}:
            return 92
        if any(token in label for token in ("kubernetes", "docker", "etcd", "consul", "jenkins", "admin", "prometheus", "grafana")):
            return 91
        if "http" in label or port in {"80", "443", "8080", "8443", "8000", "9000"}:
            return 88
        if "ssh" in label or port == "22":
            return 84
        return 78

    @staticmethod
    def _nmap_service_followup_profile(service: dict[str, Any]) -> dict[str, Any]:
        label = ScanLoopAgentGraphMixin._nmap_service_label(service).lower()
        port = str(service.get("port") or "")
        base_watch = ["nmap_scan", port, str(service.get("service") or ""), str(service.get("product") or "")]
        if any(token in label for token in ("kubernetes", "docker", "etcd", "consul", "jenkins", "prometheus", "grafana", "admin")):
            return {
                "priority": 94,
                "role": "exploit_worker",
                "objective": "Validate whether the exposed control-plane/admin service permits unauthenticated access or privilege-changing actions.",
                "next_step": f"Create an exploit_worker. Re-run nmap_scan on exact port {port or '<port>'}, then test only safe unauth/admin/API probes with control evidence.",
                "crown_jewel": "control-plane takeover or admin data access",
                "service_family": "control_plane",
                "recommended_scripts": "default,safe,vuln",
                "watch_terms": [*base_watch, "admin", "control-plane", "unauth", "api", "privilege"],
            }
        if "http" in label or port in {"80", "443", "8080", "8443", "8000", "9000"}:
            return {
                "priority": 88,
                "role": "recon_worker",
                "objective": "Map the HTTP service, identify admin/API/auth surfaces, then hand off to exploit validation.",
                "next_step": f"Create a bounded agent_graph worker for this service. First re-run nmap_scan against exact port {port or '<port>'}, then use http_request/browser plus enumerate_endpoints/test_misconfig before reporting anything.",
                "crown_jewel": "admin route, API data, or service-side exploit path",
                "service_family": "http",
                "recommended_scripts": "default,http-title,http-headers",
                "watch_terms": [*base_watch, "http", "api", "admin", "enumerate_endpoints", "test_misconfig"],
            }
        if any(token in label for token in ("redis", "mongodb", "postgres", "mysql", "mssql", "oracle", "elasticsearch")):
            return {
                "priority": 96,
                "role": "exploit_worker",
                "objective": "Determine whether the database service exposes unauthenticated access, weak auth, or data exposure.",
                "next_step": f"Create an exploit_worker. Re-run nmap_scan with safe/vuln scripts for exact port {port or '<port>'}, then prove no-auth/weak-auth data access or mark blocked with exact service evidence.",
                "crown_jewel": "database data exposure or credential material",
                "service_family": "database",
                "recommended_scripts": "default,safe,vuln",
                "watch_terms": [*base_watch, "database", "noauth", "credential", "dump", "data"],
            }
        if "ssh" in label or port == "22":
            return {
                "priority": 84,
                "role": "recon_worker",
                "objective": "Fingerprint SSH exposure and decide whether credential, weak-algorithm, or lateral-movement validation is warranted.",
                "next_step": f"Create a recon_worker. Re-run nmap_scan on exact port {port or '22'} with ssh2-enum-algos, then escalate only if concrete weak config or credential path exists.",
                "crown_jewel": "credential reuse or lateral movement",
                "service_family": "ssh",
                "recommended_scripts": "default,ssh2-enum-algos",
                "watch_terms": [*base_watch, "ssh", "credential", "algorithm", "lateral"],
            }
        if any(token in label for token in ("rdp", "vnc", "telnet", "ftp", "smb", "microsoft-ds", "nfs")) or port in {"21", "23", "445", "3389", "5900"}:
            return {
                "priority": 92,
                "role": "exploit_worker",
                "objective": "Validate whether the remote/file service creates credential, file, or lateral-movement impact.",
                "next_step": f"Create an exploit_worker. Re-run nmap_scan on exact port {port or '<port>'} with safe scripts and service-specific controls; require transcript evidence before reporting.",
                "crown_jewel": "remote access, file disclosure, or lateral movement",
                "service_family": "remote_file",
                "recommended_scripts": "default,safe,vuln",
                "watch_terms": [*base_watch, "remote", "credential", "share", "lateral", "file"],
            }
        return {
            "priority": 78,
            "role": "recon_worker",
            "objective": "Fingerprint this exposed service and decide whether it warrants exploit validation.",
            "next_step": f"Create a bounded worker or re-run nmap_scan with safe scripts on exact port {port or '<port>'}; escalate only with concrete service evidence.",
            "crown_jewel": "service-specific exploit path",
            "service_family": "generic_service",
            "recommended_scripts": "default,safe",
            "watch_terms": [*base_watch, "service", "fingerprint"],
        }

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
