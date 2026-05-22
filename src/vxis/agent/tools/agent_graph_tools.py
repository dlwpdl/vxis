"""Lightweight agent graph coordination tool.

This is the first step toward Strix-style multi-agent scanning. It records
delegated tasks, messages, statuses, and final results inside one scan runtime.
It does not execute child agents yet; later phases can attach real workers to
the same protocol without changing the Brain-facing tool contract.
"""
from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from vxis.agent.context_budget import compact_context_value, resolve_context_budget, trim_text_chars
from vxis.agent.skill_context import recommend_skill_names, render_skill_context
from vxis.agent.tool_registry import ToolResult

AgentGraphExecutor = Callable[[dict[str, Any], str], ToolResult | Any]

_VALID_ACTIONS = ("create", "send", "run", "wait", "finish", "view")
_VALID_ROLES = (
    "recon_worker",
    "exploit_worker",
    "post_exploit_worker",
    "review_worker",
    "reporting_worker",
    "fix_worker",
)
_ACTIVE_STATUSES = {"running", "waiting"}
_FINAL_STATUSES = ("finished", "blocked")
_POSITIVE_SECURITY_RESULT_TOKENS = (
    "confirmed",
    "vulnerable",
    "exploited",
    "admin access",
    "admin takeover",
    "session token",
    "credential",
    "db dump",
    "data exfil",
    "rce",
    "sql injection",
    "xss",
    "idor",
    "ssrf",
    "auth bypass",
    "privilege escalation",
)
_RESULT_FAMILY_TOKENS = {
    "injection": ("sql injection", "sqli", "sql", "nosql", "ssti", "injection"),
    "xss": ("xss", "script", "cross-site scripting"),
    "idor": ("idor", "access control", "object reference", "broken access"),
    "ssrf": ("ssrf", "metadata", "callback"),
    "auth": ("auth bypass", "authentication", "login bypass", "session token", "session"),
    "credential": ("credential", "password", "secret", "token", "api key"),
    "admin": ("admin access", "admin takeover", "privilege", "role"),
    "rce": ("rce", "remote code execution", "command execution"),
    "data": ("db dump", "data exfil", "database", "table", "rows"),
    "disclosure": ("disclosure", "exposed", "config", "backup", "debug"),
}
_SKILL_RESULT_FAMILIES = {
    "test_injection": {"injection"},
    "test_xss": {"xss"},
    "test_idor": {"idor"},
    "test_ssrf": {"ssrf"},
    "attempt_auth": {"auth", "credential"},
    "test_auth_deep": {"auth", "admin", "privilege"},
    "post_auth_enum": {"auth", "admin", "data", "credential"},
    "test_sensitive_files": {"disclosure", "credential"},
    "test_api_security": {"auth", "idor", "data"},
    "test_business_logic": {"auth", "idor", "admin", "data"},
    "test_misconfig": {"disclosure", "credential", "admin"},
}


@dataclass
class AgentGraphMessage:
    id: str
    sender: str
    recipient: str
    body: str
    created_at: str


@dataclass
class AgentGraphExecution:
    id: str
    tool: str
    args: dict[str, Any]
    ok: bool
    summary: str
    data: dict[str, Any]
    error: str | None
    created_at: str


@dataclass
class AgentGraphNode:
    id: str
    role: str
    task: str
    status: str
    created_at: str
    updated_at: str
    parent_id: str | None = None
    skills: list[str] = field(default_factory=list)
    skill_context: str = ""
    result: str = ""
    messages: list[AgentGraphMessage] = field(default_factory=list)
    executions: list[AgentGraphExecution] = field(default_factory=list)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _task_key(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _clean_skills(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = [value]
    elif isinstance(value, list):
        raw_items = value
    else:
        raw_items = [str(value)]
    out: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        skill = str(item or "").strip()
        if not skill or skill in seen:
            continue
        seen.add(skill)
        out.append(skill)
    return out


def _looks_like_positive_security_result(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return any(token in text for token in _POSITIVE_SECURITY_RESULT_TOKENS)


def _families_in_text(value: Any) -> set[str]:
    text = str(value or "").strip().lower()
    if not text:
        return set()
    families: set[str] = set()
    for family, tokens in _RESULT_FAMILY_TOKENS.items():
        if any(token in text for token in tokens):
            families.add(family)
    return families


def _execution_blob(execution: AgentGraphExecution) -> str:
    return " ".join(
        str(value or "")
        for value in (
            execution.tool,
            execution.args,
            execution.summary,
            execution.data,
        )
    ).lower()


def _execution_skill(execution: AgentGraphExecution) -> str:
    skill = str(execution.args.get("skill") or "").strip().lower()
    if skill:
        return skill
    data_args = execution.data.get("args") if isinstance(execution.data.get("args"), dict) else {}
    return str(data_args.get("skill") or "").strip().lower()


def _execution_supports_result(execution: AgentGraphExecution, result: str) -> bool:
    if not execution.ok:
        return False
    result_families = _families_in_text(result)
    if not result_families:
        return True
    execution_families = _families_in_text(_execution_blob(execution))
    skill = _execution_skill(execution)
    execution_families.update(_SKILL_RESULT_FAMILIES.get(skill, set()))
    return bool(result_families & execution_families)


def _has_supporting_successful_execution(node: AgentGraphNode, result: str) -> bool:
    return any(_execution_supports_result(execution, result) for execution in node.executions)


class AgentGraphTool:
    name = "agent_graph"
    description = (
        "Coordinate scan sub-tasks as an explicit agent graph. Actions: create "
        "a worker task, send it a message, run one bounded child-agent turn, "
        "wait/view current status, or finish it with a concrete result."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": list(_VALID_ACTIONS),
                "description": "create, send, run, wait, finish, or view",
            },
            "role": {
                "type": "string",
                "enum": list(_VALID_ROLES),
                "description": "Worker role for create.",
            },
            "task": {
                "type": "string",
                "description": "Concrete task to delegate when action=create.",
            },
            "agent_id": {
                "type": "string",
                "description": "Target agent for send, run, wait, finish, or view.",
            },
            "message": {
                "type": "string",
                "description": "Message to append for create/send.",
            },
            "instruction": {
                "type": "string",
                "description": "Optional one-turn instruction for action=run.",
            },
            "status": {
                "type": "string",
                "enum": list(_FINAL_STATUSES),
                "description": "Final status for finish.",
            },
            "result": {
                "type": "string",
                "description": "Concrete result or blocker explanation for finish.",
            },
            "parent_id": {
                "type": "string",
                "description": "Optional parent agent id for nested delegation.",
            },
            "skills": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional skill names expected for the worker task.",
            },
            "include_messages": {
                "type": "boolean",
                "description": "Include full message history in view/wait responses.",
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "description": "Max agents returned by view/wait.",
            },
        },
        "required": ["action"],
    }

    def __init__(
        self,
        executor: AgentGraphExecutor | None = None,
        max_child_runs: int = 3,
    ) -> None:
        self._nodes: dict[str, AgentGraphNode] = {}
        self._agent_counter = 0
        self._message_counter = 0
        self._execution_counter = 0
        self._executor = executor
        self._max_child_runs = max(1, int(max_child_runs))
        self._target_kind = "web"
        self._worker_budget = resolve_context_budget("worker", provider="llamacpp", model="local")

    def set_executor(self, executor: AgentGraphExecutor | None) -> None:
        self._executor = executor

    def set_target_kind(self, target_kind: Any) -> None:
        self._target_kind = str(getattr(target_kind, "value", target_kind) or "web").strip().lower()

    async def run(self, **kwargs: Any) -> ToolResult:
        action = _clean_text(kwargs.get("action")).lower()
        if action not in _VALID_ACTIONS:
            return ToolResult(
                ok=False,
                summary=f"agent_graph: action must be one of {list(_VALID_ACTIONS)}",
                error="invalid_action",
            )
        if action == "create":
            return self._create(kwargs)
        if action == "send":
            return self._send(kwargs)
        if action == "run":
            return await self._run_agent(kwargs)
        if action == "wait":
            return self._wait(kwargs)
        if action == "finish":
            return self._finish(kwargs)
        return self._view(kwargs)

    def _create(self, kwargs: dict[str, Any]) -> ToolResult:
        task = _clean_text(kwargs.get("task"))
        if not task:
            return ToolResult(ok=False, summary="agent_graph create: task is required", error="missing_task")

        role = _clean_text(kwargs.get("role") or "recon_worker").lower()
        if role not in _VALID_ROLES:
            return ToolResult(
                ok=False,
                summary=f"agent_graph create: role must be one of {list(_VALID_ROLES)}",
                error="invalid_role",
            )

        parent_id = _clean_text(kwargs.get("parent_id")) or None
        if parent_id and parent_id not in self._nodes:
            return ToolResult(
                ok=False,
                summary=f"agent_graph create: unknown parent agent {parent_id}",
                error="unknown_parent",
            )

        message = _clean_text(kwargs.get("message")) or task
        declared_skills = _clean_skills(kwargs.get("skills"))
        skills = self._select_node_skills(role=role, task=task, message=message, declared=declared_skills)
        skill_context = self._render_node_skill_context(role=role, task=task, message=message, skills=skills)
        duplicate = self._find_active_duplicate(role=role, task=task, parent_id=parent_id)
        if duplicate is not None:
            if message and not self._has_recent_message(duplicate, message):
                self._append_message(duplicate, sender="root", recipient=duplicate.id, body=message)
            duplicate.skills = self._merge_skill_names(duplicate.skills, skills)
            duplicate.skill_context = skill_context or duplicate.skill_context
            duplicate.status = "running"
            duplicate.updated_at = _now_iso()
            return ToolResult(
                ok=True,
                data={
                    "agent": self._node_to_dict(duplicate),
                    "active_agents": self._active_count(),
                    "duplicate": True,
                },
                summary=f"agent_graph: reused active {duplicate.id} ({role})",
            )

        now = _now_iso()
        agent_id = self._next_agent_id()
        node = AgentGraphNode(
            id=agent_id,
            role=role,
            task=task,
            status="running",
            created_at=now,
            updated_at=now,
            parent_id=parent_id,
            skills=skills,
            skill_context=skill_context,
        )
        self._append_message(node, sender="root", recipient=agent_id, body=message)
        self._nodes[agent_id] = node

        return ToolResult(
            ok=True,
            data={"agent": self._node_to_dict(node), "active_agents": self._active_count()},
            summary=f"agent_graph: created {agent_id} ({role})",
        )

    def _send(self, kwargs: dict[str, Any]) -> ToolResult:
        agent_id = _clean_text(kwargs.get("agent_id"))
        node = self._nodes.get(agent_id)
        if node is None:
            return ToolResult(ok=False, summary="agent_graph send: unknown agent_id", error="unknown_agent")
        if node.status not in _ACTIVE_STATUSES:
            return ToolResult(
                ok=False,
                summary=f"agent_graph send: {agent_id} is already {node.status}",
                error="agent_inactive",
            )
        message = _clean_text(kwargs.get("message"))
        if not message:
            return ToolResult(ok=False, summary="agent_graph send: message is required", error="missing_message")

        self._append_message(node, sender="root", recipient=agent_id, body=message)
        skills = self._select_node_skills(
            role=node.role,
            task=node.task,
            message=message,
            declared=node.skills,
        )
        node.skills = self._merge_skill_names(node.skills, skills)
        node.skill_context = self._render_node_skill_context(
            role=node.role,
            task=node.task,
            message=message,
            skills=node.skills,
        )
        node.status = "running"
        node.updated_at = _now_iso()
        return ToolResult(
            ok=True,
            data={"agent": self._node_to_dict(node)},
            summary=f"agent_graph: sent message to {agent_id}",
        )

    def _wait(self, kwargs: dict[str, Any]) -> ToolResult:
        agent_id = _clean_text(kwargs.get("agent_id"))
        include_messages = self._bool_arg(kwargs.get("include_messages"), default=False)
        if agent_id:
            node = self._nodes.get(agent_id)
            if node is None:
                return ToolResult(ok=False, summary="agent_graph wait: unknown agent_id", error="unknown_agent")
            return ToolResult(
                ok=True,
                data={
                    "agent": self._node_to_dict(node, include_messages=include_messages),
                    "note": self._execution_note(),
                },
                summary=f"agent_graph wait: {agent_id} is {node.status}",
            )

        agents = self._limited_nodes(kwargs, active_only=True, include_messages=include_messages)
        return ToolResult(
            ok=True,
            data={
                "active_agents": agents,
                "active_count": self._active_count(),
                "total_agents": len(self._nodes),
                "note": self._execution_note(),
            },
            summary=f"agent_graph wait: {self._active_count()} active agent(s)",
        )

    async def _run_agent(self, kwargs: dict[str, Any]) -> ToolResult:
        agent_id = _clean_text(kwargs.get("agent_id"))
        node = self._nodes.get(agent_id)
        if node is None:
            return ToolResult(ok=False, summary="agent_graph run: unknown agent_id", error="unknown_agent")
        if node.status not in _ACTIVE_STATUSES:
            return ToolResult(
                ok=False,
                summary=f"agent_graph run: {agent_id} is already {node.status}",
                error="agent_inactive",
            )
        if len(node.executions) >= self._max_child_runs:
            return ToolResult(
                ok=False,
                data={
                    "agent": self._node_to_dict(node),
                    "execution_count": len(node.executions),
                    "max_child_runs": self._max_child_runs,
                },
                summary=(
                    f"agent_graph run: {agent_id} reached the child-run limit "
                    f"({self._max_child_runs}); finish it with a result or mark it blocked"
                ),
                error="run_limit_reached",
            )
        if self._executor is None:
            return ToolResult(
                ok=False,
                data={"agent": self._node_to_dict(node), "note": "executor_unavailable"},
                summary="agent_graph run: no child-agent executor is configured",
                error="executor_unavailable",
            )

        instruction = _clean_text(kwargs.get("instruction"))
        node.status = "running"
        node.updated_at = _now_iso()
        executor_result = self._coerce_tool_result(
            await self._maybe_await(self._executor(self._node_to_dict(node), instruction))
        )
        execution = self._append_execution(node, executor_result)
        node.status = "waiting"
        node.updated_at = _now_iso()
        self._append_message(
            node,
            sender=agent_id,
            recipient="root",
            body=executor_result.summary or f"child turn {execution.id} completed",
        )
        return ToolResult(
            ok=executor_result.ok,
            data={
                "agent": self._node_to_dict(node),
                "execution": self._execution_to_dict(execution),
                "active_agents": self._active_count(),
            },
            summary=f"agent_graph: ran {agent_id} -> {executor_result.summary[:120]}",
            error=executor_result.error,
        )

    def _finish(self, kwargs: dict[str, Any]) -> ToolResult:
        agent_id = _clean_text(kwargs.get("agent_id"))
        node = self._nodes.get(agent_id)
        if node is None:
            return ToolResult(ok=False, summary="agent_graph finish: unknown agent_id", error="unknown_agent")

        status = _clean_text(kwargs.get("status") or "finished").lower()
        if status not in _FINAL_STATUSES:
            return ToolResult(
                ok=False,
                summary=f"agent_graph finish: status must be one of {list(_FINAL_STATUSES)}",
                error="invalid_status",
            )

        result = _clean_text(kwargs.get("result"))
        if not result:
            return ToolResult(ok=False, summary="agent_graph finish: result is required", error="missing_result")
        if status == "finished" and _looks_like_positive_security_result(result):
            if not any(execution.ok for execution in node.executions):
                return ToolResult(
                    ok=False,
                    data={"agent": self._node_to_dict(node), "active_agents": self._active_count()},
                    summary=(
                        f"agent_graph finish: positive vulnerability result for {agent_id} "
                        "requires at least one successful child execution first"
                    ),
                    error="missing_execution_evidence",
                )
            if not _has_supporting_successful_execution(node, result):
                return ToolResult(
                    ok=False,
                    data={"agent": self._node_to_dict(node), "active_agents": self._active_count()},
                    summary=(
                        f"agent_graph finish: positive vulnerability result for {agent_id} "
                        "is not supported by the successful child execution history"
                    ),
                    error="unsupported_execution_evidence",
                )

        node.status = status
        node.result = result
        node.updated_at = _now_iso()
        self._append_message(node, sender=agent_id, recipient="root", body=result)
        return ToolResult(
            ok=True,
            data={"agent": self._node_to_dict(node), "active_agents": self._active_count()},
            summary=f"agent_graph: {agent_id} {status}",
        )

    def _view(self, kwargs: dict[str, Any]) -> ToolResult:
        agent_id = _clean_text(kwargs.get("agent_id"))
        include_messages = self._bool_arg(kwargs.get("include_messages"), default=True)
        if agent_id:
            node = self._nodes.get(agent_id)
            if node is None:
                return ToolResult(ok=False, summary="agent_graph view: unknown agent_id", error="unknown_agent")
            return ToolResult(
                ok=True,
                data={"agent": self._node_to_dict(node, include_messages=include_messages)},
                summary=f"agent_graph view: {agent_id} is {node.status}",
            )

        agents = self._limited_nodes(kwargs, active_only=False, include_messages=include_messages)
        return ToolResult(
            ok=True,
            data={"agents": agents, "active_count": self._active_count(), "total_agents": len(self._nodes)},
            summary=f"agent_graph view: {len(agents)} agent(s)",
        )

    def _next_agent_id(self) -> str:
        self._agent_counter += 1
        return f"agent-{self._agent_counter:04d}"

    def _next_message_id(self) -> str:
        self._message_counter += 1
        return f"msg-{self._message_counter:04d}"

    def _next_execution_id(self) -> str:
        self._execution_counter += 1
        return f"exec-{self._execution_counter:04d}"

    def _find_active_duplicate(
        self,
        *,
        role: str,
        task: str,
        parent_id: str | None,
    ) -> AgentGraphNode | None:
        task_key = _task_key(task)
        for node in self._nodes.values():
            if node.status not in _ACTIVE_STATUSES:
                continue
            if node.role != role or node.parent_id != parent_id:
                continue
            if _task_key(node.task) == task_key:
                return node
        return None

    @staticmethod
    def _has_recent_message(node: AgentGraphNode, body: str) -> bool:
        clean = _task_key(body)
        return any(_task_key(message.body) == clean for message in node.messages[-3:])

    def _append_message(self, node: AgentGraphNode, sender: str, recipient: str, body: str) -> None:
        node.messages.append(
            AgentGraphMessage(
                id=self._next_message_id(),
                sender=sender,
                recipient=recipient,
                body=body,
                created_at=_now_iso(),
            )
        )

    def _append_execution(self, node: AgentGraphNode, result: ToolResult) -> AgentGraphExecution:
        data = result.data if isinstance(result.data, dict) else {}
        tool_name = str(data.get("tool") or data.get("name") or "child_turn").strip() or "child_turn"
        args = data.get("args") if isinstance(data.get("args"), dict) else {}
        execution = AgentGraphExecution(
            id=self._next_execution_id(),
            tool=tool_name,
            args=dict(args),
            ok=bool(result.ok),
            summary=str(result.summary or ""),
            data=dict(data),
            error=result.error,
            created_at=_now_iso(),
        )
        node.executions.append(execution)
        return execution

    def _active_count(self) -> int:
        return sum(1 for node in self._nodes.values() if node.status in _ACTIVE_STATUSES)

    def _limited_nodes(
        self,
        kwargs: dict[str, Any],
        *,
        active_only: bool,
        include_messages: bool,
    ) -> list[dict[str, Any]]:
        try:
            limit = int(kwargs.get("limit", 20))
        except (TypeError, ValueError):
            limit = 20
        limit = max(1, min(100, limit))

        nodes = list(self._nodes.values())
        if active_only:
            nodes = [node for node in nodes if node.status in _ACTIVE_STATUSES]
        nodes.sort(key=lambda node: node.created_at)
        return [self._node_to_dict(node, include_messages=include_messages) for node in nodes[:limit]]

    def _node_to_dict(self, node: AgentGraphNode, *, include_messages: bool = True) -> dict[str, Any]:
        budget = self._worker_budget
        data: dict[str, Any] = {
            "id": node.id,
            "role": node.role,
            "task": trim_text_chars(node.task, budget.max_message_chars),
            "status": node.status,
            "parent_id": node.parent_id,
            "skills": list(node.skills),
            "skill_context": trim_text_chars(node.skill_context, budget.max_skill_chars),
            "result": trim_text_chars(node.result, budget.max_message_chars),
            "created_at": node.created_at,
            "updated_at": node.updated_at,
            "message_count": len(node.messages),
            "execution_count": len(node.executions),
        }
        if include_messages:
            recent_messages = node.messages[-budget.max_agent_messages:]
            recent_executions = node.executions[-budget.max_agent_executions:]
            data["messages"] = [
                {
                    "id": msg.id,
                    "sender": msg.sender,
                    "recipient": msg.recipient,
                    "body": trim_text_chars(msg.body, budget.max_message_chars),
                    "created_at": msg.created_at,
                }
                for msg in recent_messages
            ]
            data["executions"] = [
                self._execution_to_dict(execution, max_chars=budget.max_execution_chars)
                for execution in recent_executions
            ]
        return data

    @staticmethod
    def _execution_to_dict(
        execution: AgentGraphExecution,
        *,
        max_chars: int = 1_200,
    ) -> dict[str, Any]:
        return {
            "id": execution.id,
            "tool": execution.tool,
            "args": compact_context_value(execution.args, max_chars=max_chars),
            "ok": execution.ok,
            "summary": trim_text_chars(execution.summary, max_chars),
            "data": compact_context_value(execution.data, max_chars=max_chars),
            "error": execution.error,
            "created_at": execution.created_at,
        }

    @staticmethod
    async def _maybe_await(value: Any) -> Any:
        if inspect.isawaitable(value):
            return await value
        return value

    @staticmethod
    def _coerce_tool_result(value: Any) -> ToolResult:
        if isinstance(value, ToolResult):
            return value
        if isinstance(value, dict):
            data = value.get("data") if isinstance(value.get("data"), dict) else dict(value)
            return ToolResult(
                ok=bool(value.get("ok", True)),
                data=data,
                summary=str(value.get("summary") or ""),
                error=value.get("error"),
            )
        return ToolResult(ok=True, data={"value": value}, summary=str(value))

    def _execution_note(self) -> str:
        if self._executor is None:
            return "protocol_only_no_child_agent_execution"
        return "child_agent_executor_available"

    def _select_node_skills(
        self,
        *,
        role: str,
        task: str,
        message: str,
        declared: list[str],
    ) -> list[str]:
        recommended = recommend_skill_names(
            task=f"{task}\n{message}",
            role=role,
            explicit_skills=declared,
            target_kind=self._target_kind,
            limit=5,
            include_defaults=False,
        )
        return self._merge_skill_names(declared, recommended)

    def _render_node_skill_context(
        self,
        *,
        role: str,
        task: str,
        message: str,
        skills: list[str],
    ) -> str:
        return render_skill_context(
            task=f"{task}\n{message}",
            role=role,
            explicit_skills=skills,
            target_kind=self._target_kind,
            limit=5,
            max_chars=self._worker_budget.max_skill_chars,
            include_defaults=bool(skills),
        )

    @staticmethod
    def _merge_skill_names(*groups: list[str]) -> list[str]:
        merged: list[str] = []
        seen: set[str] = set()
        for group in groups:
            for item in group:
                skill = str(item or "").strip()
                if not skill or skill in seen:
                    continue
                seen.add(skill)
                merged.append(skill)
                if len(merged) >= 5:
                    return merged
        return merged

    @staticmethod
    def _bool_arg(value: Any, *, default: bool) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "1", "yes", "y"}:
                return True
            if lowered in {"false", "0", "no", "n"}:
                return False
        return default
