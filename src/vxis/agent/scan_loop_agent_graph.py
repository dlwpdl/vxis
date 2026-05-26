from __future__ import annotations

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
    agent_graph_has_valid_evidence_artifact,
    agent_graph_needs_evidence_artifact,
    agent_graph_result_needs_crown_chain,
    agent_graph_terminal_branch_status,
)
from vxis.agent.scan_loop_state import _TERMINAL_BRANCH_STATUSES, BranchState
from vxis.agent.tool_registry import ToolResult


class ScanLoopAgentGraphMixin:
    def _agent_graph_agents_from_messages(self) -> list[dict[str, Any]]:
        return agent_graph_agents_from_messages(self.state.messages)

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
            f"payload: {_section(artifact.get('payload'))}",
            f"delta: {artifact.get('observed_delta', '')}",
            f"repro: {_section(artifact.get('repro_steps'))}",
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
                    next_step = (
                        "Successful child execution is available but proof is incomplete. "
                        f"Run agent_graph(action='run', agent_id='{agent_id}') until the worker returns "
                        f"a valid EvidenceArtifact. Evidence: {evidence_hint[:100]}"
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
                    or "positive delegated worker result requires valid EvidenceArtifact"
                )[:180]
            if result.error in {
                "run_limit_reached",
                "executor_unavailable",
                "no_child_action",
                "child_tool_unavailable",
                "child_tool_not_allowed",
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

    async def _run_agent_graph_child_turn(
        self, agent: dict[str, Any], instruction: str
    ) -> ToolResult:
        agent_id = str(agent.get("id") or "").strip()
        branch = self.state.branches.get(self._agent_graph_branch_id(agent_id))
        action = (
            self._forced_branch_action(branch)
            if branch is not None and branch.owner != "agent_graph"
            else None
        )
        if action is None:
            action = self._agent_graph_action_from_node(agent, instruction)
        if action is None:
            return ToolResult(
                ok=False,
                data={"agent_id": agent_id, "instruction": instruction},
                summary="agent_graph child turn: no executable step found for delegated task",
                error="no_child_action",
            )

        tool_name, tool_args = action
        allowed_child_tools = {
            "run_skill",
            "http_request",
            "browser_navigate",
            "browser_analyze_dom",
        }
        envelope_allowed = self._agent_graph_envelope_allowed_tools(agent)
        if envelope_allowed:
            allowed_child_tools = allowed_child_tools & envelope_allowed
        if tool_name not in allowed_child_tools:
            return ToolResult(
                ok=False,
                data={"agent_id": agent_id, "tool": tool_name, "args": tool_args},
                summary=f"agent_graph child turn: tool {tool_name} is not allowed for bounded child execution",
                error="child_tool_not_allowed",
            )
        if not self.registry.has_tool(tool_name):
            return ToolResult(
                ok=False,
                data={"agent_id": agent_id, "tool": tool_name, "args": tool_args},
                summary=f"agent_graph child turn: tool {tool_name} is not registered",
                error="child_tool_unavailable",
            )

        result = await self.registry.dispatch(tool_name, tool_args)
        return ToolResult(
            ok=result.ok,
            data={
                "agent_id": agent_id,
                "tool": tool_name,
                "args": tool_args,
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

    def _agent_graph_action_from_node(
        self,
        agent: dict[str, Any],
        instruction: str,
    ) -> tuple[str, dict[str, Any]] | None:
        envelope = (
            agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        )
        if "run_skill" in self.registry.list_tools():
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
        parts = [
            f"objective={str(envelope.get('objective') or agent.get('task') or '').strip()}",
            f"tool={tool_name}",
        ]
        expected = str(envelope.get("expected_artifact") or "").strip()
        stop = str(envelope.get("stop_condition") or "").strip()
        escalate = str(envelope.get("escalation_trigger") or "").strip()
        prior = str(result_package.get("recommended_next_step") or "").strip()
        if expected:
            parts.append(f"expect={expected}")
        if stop:
            parts.append(f"stop={stop}")
        if escalate:
            parts.append(f"escalate={escalate}")
        if prior:
            parts.append(f"prior={prior}")
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
