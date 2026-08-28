from __future__ import annotations

import re
from typing import Any

from vxis.agent.agent_graph_runtime import (
    agent_graph_branch_id,
    agent_graph_branch_priority,
    agent_graph_crown_jewel_for_result,
    agent_graph_evidence_artifact,
    agent_graph_evidence_artifact_brief,
    agent_graph_evidence_gap,
    agent_graph_has_valid_evidence_artifact,
    agent_graph_needs_evidence_artifact,
    agent_graph_result_needs_crown_chain,
    agent_graph_terminal_branch_status,
)
from vxis.agent.scan_loop_state import _TERMINAL_BRANCH_STATUSES, BranchState
from vxis.agent.tool_registry import ToolResult


class ScanLoopAgentGraphSyncMixin:
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
            combined = (parent.evidence + "; " + proof_text).strip("; ")
            parent.evidence = combined[-2000:] if len(combined) > 2000 else combined
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
            parent_branch = self.state.branches.get(parent_branch_id) if parent_branch_id else None
            source_candidate_id = ""
            source_finding_id = ""
            if parent_branch is not None:
                source_candidate_id = str(
                    parent_branch.source_candidate_id or parent_branch.id or ""
                ).strip()
                source_finding_id = str(parent_branch.source_finding_id or "").strip()
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
                source_candidate_id=source_candidate_id,
                source_finding_id=source_finding_id,
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
