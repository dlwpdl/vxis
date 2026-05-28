"""Lightweight agent graph coordination tool.

This is the first step toward Strix-style multi-agent scanning. It records
delegated tasks, messages, statuses, and final results inside one scan runtime.
It does not execute child agents yet; later phases can attach real workers to
the same protocol without changing the Brain-facing tool contract.
"""

from __future__ import annotations

import json
import inspect
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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
_PROOF_ARTIFACT_TOKENS = (
    "baseline",
    "control",
    "negative control",
    "payload",
    "request",
    "response",
    "transcript",
    "status",
    "http/",
    "http ",
    "header",
    "body",
    "cookie",
    "session",
    "token",
    "screenshot",
    "dom",
    "sql error",
    "stack trace",
    "delta",
    "diff",
    "observed",
    "row",
    "database",
    "admin",
    "role",
    "poc",
    "proof",
)
_EVIDENCE_ARTIFACT_SCHEMA = "vxis.agent_graph.evidence_artifact.v1"
_ARTIFACT_DICT_KEYS = (
    "summary",
    "request",
    "response",
    "response_excerpt",
    "response_status",
    "status",
    "body",
    "header",
    "headers",
    "value",
)
_ARTIFACT_REQUIRED_FIELDS = (
    "claim",
    "target",
    "control",
    "payload",
    "observed_delta",
    "repro_steps",
)
_MAX_REPEATED_EVIDENCE_GAPS = 2
_ARTIFACT_FIELD_DIRECTIVES = {
    "claim": "state the exact vulnerability claim being tested",
    "target": "name the exact URL/component/account boundary",
    "control": "add baseline control request and response/status",
    "payload": "add payload/variant request and response/status",
    "observed_delta": "compare control vs payload and state the security delta",
    "repro_steps": "list concise replay steps for control, payload, and comparison",
}
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
_SNAPSHOT_SCHEMA = "vxis.agent_graph.snapshot.v1"


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
    task_envelope: dict[str, Any] = field(default_factory=dict)
    result_package: dict[str, Any] = field(default_factory=dict)
    escalation: dict[str, Any] = field(default_factory=dict)
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


def _artifact_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        return _join_nonempty(
            [str(value.get(key) or "") for key in _ARTIFACT_DICT_KEYS],
            sep=" | ",
        )
    if isinstance(value, list):
        return _join_nonempty([_artifact_text(item) for item in value], sep=" | ")
    return str(value or "").strip()


def _first_artifact_text(*values: Any) -> str:
    for value in values:
        text = _artifact_text(value)
        if text:
            return text
    return ""


def _artifact_steps(value: Any) -> list[str]:
    if isinstance(value, list):
        return [
            trim_text_chars(_artifact_text(item), 140) for item in value if _artifact_text(item)
        ][:5]
    text = _artifact_text(value)
    return [trim_text_chars(text, 140)] if text else []


def _artifact_section(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        section = {
            "summary": trim_text_chars(_first_artifact_text(value.get("summary"), value), 180)
        }
        for key in (
            "request",
            "response",
            "response_excerpt",
            "response_status",
            "status",
            "body",
        ):
            text = _artifact_text(value.get(key))
            if text:
                section[key] = trim_text_chars(text, 240)
        return section
    text = _artifact_text(value)
    return {"summary": trim_text_chars(text, 240)} if text else {}


def _proof_artifact_raw(execution: AgentGraphExecution) -> dict[str, Any]:
    result = execution.data.get("result") if isinstance(execution.data.get("result"), dict) else {}
    result_data = result.get("data") if isinstance(result.get("data"), dict) else {}
    for source in (execution.data, result, result_data):
        for key in ("evidence_artifact", "proof_artifact"):
            raw = source.get(key) if isinstance(source, dict) else None
            if isinstance(raw, dict):
                return raw
    return {}


def _target_from_execution(execution: AgentGraphExecution, node: AgentGraphNode | None) -> str:
    result = execution.data.get("result") if isinstance(execution.data.get("result"), dict) else {}
    result_data = result.get("data") if isinstance(result.get("data"), dict) else {}
    return _first_artifact_text(
        execution.args.get("target_url"),
        execution.args.get("url"),
        execution.args.get("target"),
        result.get("target"),
        result.get("url"),
        result_data.get("target"),
        result_data.get("url"),
        node.task if node is not None else "",
    )


def _execution_evidence_artifact(
    execution: AgentGraphExecution,
    *,
    node: AgentGraphNode | None = None,
) -> dict[str, Any]:
    result = execution.data.get("result") if isinstance(execution.data.get("result"), dict) else {}
    result_data = result.get("data") if isinstance(result.get("data"), dict) else {}
    raw = _proof_artifact_raw(execution)
    result_summary = str(result.get("summary") or execution.summary or "").strip()

    claim = _first_artifact_text(
        raw.get("claim"),
        raw.get("title"),
        result.get("claim"),
        result_data.get("claim"),
        result_summary,
    )
    target = _first_artifact_text(
        raw.get("target"),
        raw.get("url"),
        raw.get("endpoint"),
        raw.get("surface"),
        _target_from_execution(execution, node),
    )
    control = _artifact_section(
        raw.get("control")
        or raw.get("baseline")
        or result.get("control")
        or result.get("baseline")
        or result_data.get("control")
        or result_data.get("baseline")
    )
    payload = _artifact_section(
        raw.get("payload")
        or raw.get("exploit")
        or raw.get("attack")
        or result.get("payload")
        or result.get("control_payload")
        or result_data.get("payload")
        or result_data.get("attack")
        or result.get("evidence")
    )
    observed_delta = _first_artifact_text(
        raw.get("observed_delta"),
        raw.get("delta"),
        raw.get("evidence"),
        result.get("observed_delta"),
        result.get("delta"),
        result.get("observed"),
        result.get("evidence"),
        result_data.get("observed_delta"),
        result_data.get("delta"),
        result_data.get("observed"),
        result_data.get("evidence"),
    )
    repro_steps = _artifact_steps(
        raw.get("repro_steps")
        or raw.get("reproduction")
        or raw.get("steps")
        or result.get("repro_steps")
        or result_data.get("repro_steps")
    )
    if not repro_steps and control and payload and observed_delta:
        repro_steps = [
            "Run the recorded control input",
            "Run the recorded payload input",
            "Compare the observed delta",
        ]

    artifact: dict[str, Any] = {
        "schema": _EVIDENCE_ARTIFACT_SCHEMA,
        "claim": trim_text_chars(claim, 180),
        "target": trim_text_chars(target, 180),
        "tool": execution.tool,
        "source": "structured" if raw else "legacy_result_fields",
        "control": control,
        "payload": payload,
        "observed_delta": trim_text_chars(observed_delta, 240),
        "repro_steps": repro_steps,
    }
    missing = [
        field
        for field in _ARTIFACT_REQUIRED_FIELDS
        if (not artifact.get(field))
        or (field in {"control", "payload"} and not _artifact_text(artifact.get(field)))
    ]
    proof_blob = " ".join(
        _artifact_text(artifact.get(field))
        for field in ("control", "payload", "observed_delta", "repro_steps")
    )
    artifact["missing_fields"] = missing
    weak = _artifact_weak_fields(artifact)
    artifact["weak_fields"] = weak
    artifact["gap_fields"] = _dedupe_preserve_order([*missing, *weak])
    artifact["valid"] = not artifact["gap_fields"] and _has_proof_artifact_text(proof_blob)
    return artifact


def _artifact_weak_fields(artifact: dict[str, Any]) -> list[str]:
    weak: list[str] = []
    for artifact_field in ("control", "payload"):
        value = artifact.get(artifact_field)
        text = _artifact_text(value)
        if not text:
            continue
        if len(text) < 12:
            weak.append(artifact_field)
            continue
        if not any(
            token in text.lower()
            for token in (
                "request",
                "response",
                "status",
                "http",
                "baseline",
                "control",
                "payload",
                "error",
                "token",
                "admin",
                "200",
                "401",
                "403",
                "500",
                "body",
                "header",
                "cookie",
                "session",
            )
        ):
            weak.append(artifact_field)
    delta = _artifact_text(artifact.get("observed_delta"))
    if delta and len(delta) < 16:
        weak.append("observed_delta")
    steps = artifact.get("repro_steps")
    if isinstance(steps, list) and steps and len([step for step in steps if _artifact_text(step)]) < 2:
        weak.append("repro_steps")
    return _dedupe_preserve_order(weak)


def _artifact_gap_signature(artifact: dict[str, Any]) -> str:
    fields = [
        str(item).strip()
        for item in list(artifact.get("gap_fields") or artifact.get("missing_fields") or [])
        if str(item).strip()
    ]
    return ",".join(_dedupe_preserve_order(fields)) or "proof_artifact"


def _evidence_gap_directive(fields: list[str], artifact: dict[str, Any]) -> str:
    focused = _dedupe_preserve_order(fields)[:6]
    if not focused:
        focused = ["proof_artifact"]
    directives = [
        _ARTIFACT_FIELD_DIRECTIVES.get(field, f"strengthen {field}")
        for field in focused
    ]
    claim = trim_text_chars(artifact.get("claim"), 80)
    target = trim_text_chars(artifact.get("target"), 80)
    context = _join_nonempty([f"claim={claim}" if claim else "", f"target={target}" if target else ""])
    prefix = f"Evidence gap: add {', '.join(focused)}."
    suffix = "; ".join(directives)
    if context:
        suffix = f"{suffix}. {context}"
    return trim_text_chars(f"{prefix} {suffix}", 260)


def _execution_evidence_gap_report(
    execution: AgentGraphExecution,
    *,
    node: AgentGraphNode,
) -> dict[str, Any]:
    artifact = _execution_evidence_artifact(execution, node=node)
    if artifact.get("valid"):
        return {
            "status": "valid",
            "missing_fields": [],
            "weak_fields": [],
            "gap_fields": [],
            "gap_signature": "",
            "repeat_count": 0,
            "next_instruction": "",
        }
    fields = [
        str(item).strip()
        for item in list(artifact.get("gap_fields") or artifact.get("missing_fields") or [])
        if str(item).strip()
    ]
    if not fields:
        fields = ["proof_artifact"]
    signature = _artifact_gap_signature(artifact)
    repeat_count = 0
    for prior in node.executions:
        prior_artifact = _execution_evidence_artifact(prior, node=node)
        if prior_artifact.get("valid"):
            continue
        if _artifact_gap_signature(prior_artifact) == signature:
            repeat_count += 1
    return {
        "status": "needs_more_evidence",
        "missing_fields": list(artifact.get("missing_fields") or []),
        "weak_fields": list(artifact.get("weak_fields") or []),
        "gap_fields": _dedupe_preserve_order(fields),
        "gap_signature": signature,
        "repeat_count": repeat_count,
        "max_repeats": _MAX_REPEATED_EVIDENCE_GAPS,
        "next_instruction": _evidence_gap_directive(fields, artifact),
    }


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


def _has_proof_artifact_text(value: str) -> bool:
    text = str(value or "").lower()
    if not text:
        return False
    matched = {token for token in _PROOF_ARTIFACT_TOKENS if token in text}
    if len(matched) >= 2:
        return True
    has_status_code = any(code in text for code in (" 200", " 401", " 403", " 404", " 500"))
    has_comparison = any(token in text for token in ("baseline", "control", "delta", "diff"))
    return has_status_code and has_comparison


def _execution_has_proof_artifact(
    execution: AgentGraphExecution,
    *,
    node: AgentGraphNode | None = None,
) -> bool:
    artifact = _execution_evidence_artifact(execution, node=node)
    return bool(artifact.get("valid"))


def _has_sufficient_proof_artifact(node: AgentGraphNode, result: str) -> bool:
    return any(
        _execution_supports_result(execution, result)
        and _execution_has_proof_artifact(execution, node=node)
        for execution in node.executions
    )


def _is_service_probe_completion(node: AgentGraphNode, result: str) -> bool:
    envelope = node.task_envelope if isinstance(node.task_envelope, dict) else {}
    blob = " ".join(
        str(value or "").lower()
        for value in (
            node.role,
            node.task,
            result,
            envelope.get("objective"),
            envelope.get("expected_artifact"),
            envelope.get("stop_condition"),
            envelope.get("escalation_trigger"),
        )
    )
    if "deepen nmap service pivot" in blob:
        return True
    if "service-specific transcript" in blob:
        return True
    return "nmap_scan" in blob and any(
        token in blob
        for token in (
            "open port",
            "open service",
            "service discovery",
            "service fingerprint",
            "port ",
        )
    )


def _join_nonempty(parts: list[str], *, sep: str = " ") -> str:
    return sep.join(part for part in parts if str(part or "").strip()).strip()


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        clean = str(item or "").strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        out.append(clean)
    return out


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
            "objective": {
                "type": "string",
                "description": "Explicit bounded objective for the worker task.",
            },
            "expected_artifact": {
                "type": "string",
                "description": "Exact proof artifact the worker must bring back.",
            },
            "stop_condition": {
                "type": "string",
                "description": "Condition that should stop the bounded worker task.",
            },
            "escalation_trigger": {
                "type": "string",
                "description": "Condition that should escalate the task back to the director.",
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
        self._persistence_path: Path | None = None

    def set_executor(self, executor: AgentGraphExecutor | None) -> None:
        self._executor = executor

    def set_persistence_path(self, path: str | Path | None, *, restore: bool = True) -> None:
        self._persistence_path = Path(path) if path else None
        if restore:
            self.restore_snapshot()

    def restore_snapshot(self, path: str | Path | None = None) -> bool:
        source = Path(path) if path is not None else self._persistence_path
        if source is None or not source.exists():
            return False
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        nodes_raw = payload.get("nodes") if isinstance(payload, dict) else None
        if not isinstance(nodes_raw, list):
            return False
        nodes: dict[str, AgentGraphNode] = {}
        for item in nodes_raw:
            if not isinstance(item, dict):
                continue
            node = self._node_from_snapshot(item)
            if node.id:
                nodes[node.id] = node
        self._nodes = nodes
        self._agent_counter = max(
            self._counter_from_id("agent-", node_id) for node_id in [*nodes.keys(), "agent-0000"]
        )
        self._message_counter = max(
            [
                self._counter_from_id("msg-", message.id)
                for node in nodes.values()
                for message in node.messages
            ]
            or [0]
        )
        self._execution_counter = max(
            [
                self._counter_from_id("exec-", execution.id)
                for node in nodes.values()
                for execution in node.executions
            ]
            or [0]
        )
        return True

    def set_target_kind(self, target_kind: Any) -> None:
        self._target_kind = str(getattr(target_kind, "value", target_kind) or "web").strip().lower()

    def set_worker_model(
        self,
        provider: str,
        model: str,
        *,
        context_window: int | None = None,
    ) -> None:
        self._worker_budget = resolve_context_budget(
            "worker",
            provider=provider,
            model=model,
            context_window=context_window,
        )

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
            return ToolResult(
                ok=False, summary="agent_graph create: task is required", error="missing_task"
            )

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
        skills = self._select_node_skills(
            role=role, task=task, message=message, declared=declared_skills
        )
        skill_context = self._render_node_skill_context(
            role=role, task=task, message=message, skills=skills
        )
        duplicate = self._find_active_duplicate(role=role, task=task, parent_id=parent_id)
        if duplicate is not None:
            if message and not self._has_recent_message(duplicate, message):
                self._append_message(duplicate, sender="root", recipient=duplicate.id, body=message)
            duplicate.skills = self._merge_skill_names(duplicate.skills, skills)
            duplicate.skill_context = skill_context or duplicate.skill_context
            duplicate.status = "running"
            duplicate.updated_at = _now_iso()
            self._save_snapshot()
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
            task_envelope=self._build_task_envelope(
                role=role,
                task=task,
                message=message,
                skills=skills,
                explicit=self._explicit_envelope_from_kwargs(kwargs),
            ),
        )
        self._append_message(node, sender="root", recipient=agent_id, body=message)
        self._nodes[agent_id] = node
        self._save_snapshot()

        return ToolResult(
            ok=True,
            data={"agent": self._node_to_dict(node), "active_agents": self._active_count()},
            summary=f"agent_graph: created {agent_id} ({role})",
        )

    def _send(self, kwargs: dict[str, Any]) -> ToolResult:
        agent_id = _clean_text(kwargs.get("agent_id"))
        node = self._nodes.get(agent_id)
        if node is None:
            return ToolResult(
                ok=False, summary="agent_graph send: unknown agent_id", error="unknown_agent"
            )
        if node.status not in _ACTIVE_STATUSES:
            return ToolResult(
                ok=False,
                summary=f"agent_graph send: {agent_id} is already {node.status}",
                error="agent_inactive",
            )
        message = _clean_text(kwargs.get("message"))
        if not message:
            return ToolResult(
                ok=False, summary="agent_graph send: message is required", error="missing_message"
            )

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
        node.task_envelope = self._build_task_envelope(
            role=node.role,
            task=node.task,
            message=message,
            skills=node.skills,
            explicit=self._explicit_envelope_from_kwargs(kwargs),
        )
        node.status = "running"
        node.updated_at = _now_iso()
        self._save_snapshot()
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
                return ToolResult(
                    ok=False, summary="agent_graph wait: unknown agent_id", error="unknown_agent"
                )
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
            return ToolResult(
                ok=False, summary="agent_graph run: unknown agent_id", error="unknown_agent"
            )
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
        node.result_package = self._build_result_package(node, execution=execution)
        completion = self._executor_agent_finish(executor_result)
        completion_status = self._completion_node_status(completion)
        if completion_status:
            completion_result = _clean_text(
                completion.get("result_summary") or executor_result.summary
            )
            evidence_error = self._completion_evidence_error(
                node,
                result=completion_result,
                status=completion_status,
            )
            if evidence_error:
                node.status = "waiting"
                node.escalation = self._build_escalation_state(node)
                node.updated_at = _now_iso()
                self._append_message(
                    node,
                    sender=agent_id,
                    recipient="root",
                    body=evidence_error,
                )
                self._save_snapshot()
                return ToolResult(
                    ok=False,
                    data={
                        "agent": self._node_to_dict(node),
                        "execution": self._execution_to_dict(execution),
                        "active_agents": self._active_count(),
                    },
                    summary=f"agent_graph: {agent_id} SDK completion rejected: {evidence_error}",
                    error="insufficient_completion_evidence",
                )
            node.status = completion_status
            node.result = completion_result
            node.result_package = self._finalize_result_package(
                node,
                result=completion_result,
                status=completion_status,
            )
        else:
            node.status = "waiting"
        node.escalation = self._build_escalation_state(node)
        node.updated_at = _now_iso()
        self._append_message(
            node,
            sender=agent_id,
            recipient="root",
            body=executor_result.summary or f"child turn {execution.id} completed",
        )
        self._save_snapshot()
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

    @staticmethod
    def _executor_agent_finish(result: ToolResult) -> dict[str, Any]:
        data = result.data if isinstance(result.data, dict) else {}
        completion = data.get("agent_finish")
        return completion if isinstance(completion, dict) else {}

    @staticmethod
    def _completion_node_status(completion: dict[str, Any]) -> str:
        if not completion:
            return ""
        status = str(completion.get("status") or "").strip().lower()
        if status in {"completed", "finished"}:
            return "finished"
        if status in {"blocked", "failed", "crashed", "stopped"}:
            return "blocked"
        return ""

    @staticmethod
    def _completion_evidence_error(
        node: AgentGraphNode,
        *,
        result: str,
        status: str,
    ) -> str:
        if (
            status == "finished"
            and _is_service_probe_completion(node, result)
            and not _has_sufficient_proof_artifact(node, result)
        ):
            return (
                "service-pivot completion requires a valid EvidenceArtifact or an explicit "
                "blocked status; open port/service discovery alone is not a finding"
            )
        if status != "finished" or not _looks_like_positive_security_result(result):
            return ""
        if not any(execution.ok for execution in node.executions):
            return "positive SDK completion requires at least one successful child execution"
        if not _has_supporting_successful_execution(node, result):
            return "positive SDK completion is not supported by child execution history"
        if not _has_sufficient_proof_artifact(node, result):
            return "positive SDK completion requires a valid EvidenceArtifact"
        return ""

    def _finish(self, kwargs: dict[str, Any]) -> ToolResult:
        agent_id = _clean_text(kwargs.get("agent_id"))
        node = self._nodes.get(agent_id)
        if node is None:
            return ToolResult(
                ok=False, summary="agent_graph finish: unknown agent_id", error="unknown_agent"
            )

        status = _clean_text(kwargs.get("status") or "finished").lower()
        if status not in _FINAL_STATUSES:
            return ToolResult(
                ok=False,
                summary=f"agent_graph finish: status must be one of {list(_FINAL_STATUSES)}",
                error="invalid_status",
            )

        result = _clean_text(kwargs.get("result"))
        if not result:
            return ToolResult(
                ok=False, summary="agent_graph finish: result is required", error="missing_result"
            )
        if (
            status == "finished"
            and _is_service_probe_completion(node, result)
            and not _has_sufficient_proof_artifact(node, result)
        ):
            return ToolResult(
                ok=False,
                data={"agent": self._node_to_dict(node), "active_agents": self._active_count()},
                summary=(
                    f"agent_graph finish: service-pivot result for {agent_id} requires "
                    "valid EvidenceArtifact or blocked status; open port/service discovery alone "
                    "is not a finding"
                ),
                error="insufficient_service_evidence",
            )
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
            if not _has_sufficient_proof_artifact(node, result):
                return ToolResult(
                    ok=False,
                    data={"agent": self._node_to_dict(node), "active_agents": self._active_count()},
                    summary=(
                        f"agent_graph finish: positive vulnerability result for {agent_id} "
                        "requires a concrete PoC/control artifact, not only a positive summary"
                    ),
                    error="insufficient_proof_artifact",
                )

        node.status = status
        node.result = result
        node.result_package = self._finalize_result_package(node, result=result, status=status)
        node.escalation = self._build_escalation_state(node)
        node.updated_at = _now_iso()
        self._append_message(node, sender=agent_id, recipient="root", body=result)
        self._save_snapshot()
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
                return ToolResult(
                    ok=False, summary="agent_graph view: unknown agent_id", error="unknown_agent"
                )
            return ToolResult(
                ok=True,
                data={"agent": self._node_to_dict(node, include_messages=include_messages)},
                summary=f"agent_graph view: {agent_id} is {node.status}",
            )

        agents = self._limited_nodes(kwargs, active_only=False, include_messages=include_messages)
        return ToolResult(
            ok=True,
            data={
                "agents": agents,
                "active_count": self._active_count(),
                "total_agents": len(self._nodes),
            },
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
        tool_name = (
            str(data.get("tool") or data.get("name") or "child_turn").strip() or "child_turn"
        )
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

    def _save_snapshot(self) -> None:
        if self._persistence_path is None:
            return
        payload = {
            "schema": _SNAPSHOT_SCHEMA,
            "saved_at": _now_iso(),
            "counters": {
                "agent": self._agent_counter,
                "message": self._message_counter,
                "execution": self._execution_counter,
            },
            "nodes": [self._node_snapshot(node) for node in self._nodes.values()],
        }
        self._persistence_path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(payload, ensure_ascii=False, default=str)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(self._persistence_path.parent),
            prefix=f".{self._persistence_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(encoded)
            tmp_path = Path(tmp.name)
        tmp_path.replace(self._persistence_path)

    @staticmethod
    def _node_snapshot(node: AgentGraphNode) -> dict[str, Any]:
        return {
            "id": node.id,
            "role": node.role,
            "task": node.task,
            "status": node.status,
            "created_at": node.created_at,
            "updated_at": node.updated_at,
            "parent_id": node.parent_id,
            "skills": list(node.skills),
            "skill_context": node.skill_context,
            "task_envelope": dict(node.task_envelope),
            "result_package": dict(node.result_package),
            "escalation": dict(node.escalation),
            "result": node.result,
            "messages": [
                {
                    "id": message.id,
                    "sender": message.sender,
                    "recipient": message.recipient,
                    "body": message.body,
                    "created_at": message.created_at,
                }
                for message in node.messages
            ],
            "executions": [
                {
                    "id": execution.id,
                    "tool": execution.tool,
                    "args": dict(execution.args),
                    "ok": execution.ok,
                    "summary": execution.summary,
                    "data": dict(execution.data),
                    "error": execution.error,
                    "created_at": execution.created_at,
                }
                for execution in node.executions
            ],
        }

    @staticmethod
    def _node_from_snapshot(value: dict[str, Any]) -> AgentGraphNode:
        messages = []
        for item in value.get("messages") or []:
            if not isinstance(item, dict):
                continue
            messages.append(
                AgentGraphMessage(
                    id=str(item.get("id") or ""),
                    sender=str(item.get("sender") or "root"),
                    recipient=str(item.get("recipient") or value.get("id") or ""),
                    body=str(item.get("body") or ""),
                    created_at=str(item.get("created_at") or _now_iso()),
                )
            )
        executions = []
        for item in value.get("executions") or []:
            if not isinstance(item, dict):
                continue
            args = item.get("args") if isinstance(item.get("args"), dict) else {}
            data = item.get("data") if isinstance(item.get("data"), dict) else {}
            executions.append(
                AgentGraphExecution(
                    id=str(item.get("id") or ""),
                    tool=str(item.get("tool") or "child_turn"),
                    args=dict(args),
                    ok=bool(item.get("ok")),
                    summary=str(item.get("summary") or ""),
                    data=dict(data),
                    error=str(item.get("error")) if item.get("error") is not None else None,
                    created_at=str(item.get("created_at") or _now_iso()),
                )
            )
        task_envelope = (
            value.get("task_envelope") if isinstance(value.get("task_envelope"), dict) else {}
        )
        result_package = (
            value.get("result_package") if isinstance(value.get("result_package"), dict) else {}
        )
        escalation = value.get("escalation") if isinstance(value.get("escalation"), dict) else {}
        return AgentGraphNode(
            id=str(value.get("id") or ""),
            role=str(value.get("role") or "recon_worker"),
            task=str(value.get("task") or ""),
            status=str(value.get("status") or "running"),
            created_at=str(value.get("created_at") or _now_iso()),
            updated_at=str(value.get("updated_at") or _now_iso()),
            parent_id=str(value["parent_id"]) if value.get("parent_id") else None,
            skills=_clean_skills(value.get("skills")),
            skill_context=str(value.get("skill_context") or ""),
            task_envelope=dict(task_envelope),
            result_package=dict(result_package),
            escalation=dict(escalation),
            result=str(value.get("result") or ""),
            messages=messages,
            executions=executions,
        )

    @staticmethod
    def _counter_from_id(prefix: str, value: str) -> int:
        text = str(value or "")
        if not text.startswith(prefix):
            return 0
        try:
            return int(text.removeprefix(prefix))
        except ValueError:
            return 0

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
        return [
            self._node_to_dict(node, include_messages=include_messages) for node in nodes[:limit]
        ]

    def _node_to_dict(
        self, node: AgentGraphNode, *, include_messages: bool = True
    ) -> dict[str, Any]:
        budget = self._worker_budget
        data: dict[str, Any] = {
            "id": node.id,
            "role": node.role,
            "task": trim_text_chars(node.task, budget.max_message_chars),
            "status": node.status,
            "parent_id": node.parent_id,
            "skills": list(node.skills),
            "skill_context": trim_text_chars(node.skill_context, budget.max_skill_chars),
            "task_envelope": compact_context_value(
                node.task_envelope, max_chars=budget.max_execution_chars
            ),
            "result_package": compact_context_value(
                node.result_package, max_chars=budget.max_execution_chars
            ),
            "escalation": compact_context_value(
                node.escalation, max_chars=budget.max_execution_chars
            ),
            "result": trim_text_chars(node.result, budget.max_message_chars),
            "created_at": node.created_at,
            "updated_at": node.updated_at,
            "message_count": len(node.messages),
            "execution_count": len(node.executions),
        }
        if include_messages:
            recent_messages = node.messages[-budget.max_agent_messages :]
            recent_executions = node.executions[-budget.max_agent_executions :]
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

    def _build_task_envelope(
        self,
        *,
        role: str,
        task: str,
        message: str,
        skills: list[str],
        explicit: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        explicit = dict(explicit or {})
        surface = "desktop" if self._target_kind == "desktop" else "web"
        allowed_tools = self._allowed_tools_for_role(role=role, skills=skills)
        expected_artifact = explicit.get("expected_artifact") or self._expected_artifact_for_role(
            role, skills
        )
        stop_condition = explicit.get("stop_condition") or self._stop_condition_for_role(role)
        escalation_trigger = explicit.get(
            "escalation_trigger"
        ) or self._escalation_trigger_for_role(role)
        return {
            "objective": trim_text_chars(explicit.get("objective") or task or message, 160),
            "target_surface": surface,
            "allowed_tools": allowed_tools,
            "expected_artifact": expected_artifact,
            "stop_condition": stop_condition,
            "escalation_trigger": escalation_trigger,
        }

    @staticmethod
    def _explicit_envelope_from_kwargs(kwargs: dict[str, Any]) -> dict[str, str]:
        return {
            "objective": trim_text_chars(kwargs.get("objective") or "", 160),
            "expected_artifact": trim_text_chars(kwargs.get("expected_artifact") or "", 160),
            "stop_condition": trim_text_chars(kwargs.get("stop_condition") or "", 160),
            "escalation_trigger": trim_text_chars(kwargs.get("escalation_trigger") or "", 160),
        }

    @staticmethod
    def _allowed_tools_for_role(*, role: str, skills: list[str]) -> list[str]:
        tools = ["run_skill", "http_request"]
        if role in {"recon_worker", "exploit_worker", "post_exploit_worker"}:
            tools.append("nmap_scan")
        if role in {"recon_worker", "exploit_worker"}:
            tools.append("browser_navigate")
        if role in {"exploit_worker", "post_exploit_worker"}:
            tools.append("browser_analyze_dom")
        if skills:
            tools.append(f"skills:{','.join(skills[:3])}")
        return tools

    @staticmethod
    def _expected_artifact_for_role(role: str, skills: list[str]) -> str:
        if role == "recon_worker":
            return "surface map with concrete endpoints or auth boundaries"
        if role == "review_worker":
            return "adjudication note with blocker/clean/proven recommendation"
        if role == "post_exploit_worker":
            return "session, privilege, or data-access transcript tied to crown-jewel impact"
        skill_hint = f" via {skills[0]}" if skills else ""
        return f"raw proof artifact{skill_hint}: request/response transcript, control pair, or exploit delta"

    @staticmethod
    def _stop_condition_for_role(role: str) -> str:
        if role == "recon_worker":
            return "stop after mapping the relevant surface and naming the next proof step"
        if role == "review_worker":
            return "stop after classifying the evidence as proven, blocked, or clean"
        if role == "post_exploit_worker":
            return "stop after proving session reuse, privilege, data access, or chain closure"
        return "stop after one bounded proof attempt yields concrete evidence or a blocker"

    @staticmethod
    def _escalation_trigger_for_role(role: str) -> str:
        if role == "review_worker":
            return "escalate when evidence is ambiguous or conflicts with a positive claim"
        if role == "post_exploit_worker":
            return "escalate after blocked pivot, ambiguous privilege boundary, or crown-jewel planning"
        return "escalate after repeated blocked/clean runs or when a positive result needs a sharper next task"

    def _build_result_package(
        self,
        node: AgentGraphNode,
        *,
        execution: AgentGraphExecution,
    ) -> dict[str, Any]:
        result_data = (
            execution.data.get("result") if isinstance(execution.data.get("result"), dict) else {}
        )
        result_summary = str(result_data.get("summary") or execution.summary or "").strip()
        evidence_artifact = _execution_evidence_artifact(execution, node=node)
        control_text = _join_nonempty(
            [
                _artifact_text(evidence_artifact.get("control")),
                str(result_data.get("control") or ""),
                str(result_data.get("baseline") or ""),
            ],
            sep=" | ",
        )
        delta_text = _join_nonempty(
            [
                _artifact_text(evidence_artifact.get("observed_delta")),
                str(result_data.get("evidence") or ""),
                str(result_data.get("delta") or ""),
                str(result_data.get("observed") or ""),
            ],
            sep=" | ",
        )
        has_positive_signal = execution.ok and _looks_like_positive_security_result(result_summary)
        has_proof_artifact = bool(evidence_artifact.get("valid"))
        evidence_gap = _execution_evidence_gap_report(execution, node=node)
        if has_positive_signal and has_proof_artifact:
            verdict_guess = "candidate_positive"
        elif has_positive_signal:
            verdict_guess = "needs_proof"
        elif not execution.ok:
            verdict_guess = "blocked"
        else:
            verdict_guess = "inconclusive"
        return {
            "attempted_tool": execution.tool,
            "attempt_summary": trim_text_chars(execution.summary, 160),
            "raw_evidence_summary": trim_text_chars(result_summary or execution.summary, 180),
            "control_result": trim_text_chars(control_text, 140),
            "observed_delta": trim_text_chars(delta_text, 160),
            "proof_quality": "strong" if has_proof_artifact else "weak",
            "evidence_artifact": compact_context_value(
                evidence_artifact, max_chars=self._worker_budget.max_execution_chars
            ),
            "evidence_gap": compact_context_value(
                evidence_gap, max_chars=self._worker_budget.max_execution_chars
            ),
            "verdict_guess": verdict_guess,
            "recommended_next_step": trim_text_chars(
                self._recommended_next_step(node, execution, evidence_gap=evidence_gap), 220
            ),
        }

    def _finalize_result_package(
        self,
        node: AgentGraphNode,
        *,
        result: str,
        status: str,
    ) -> dict[str, Any]:
        package = dict(node.result_package or {})
        package.update(
            {
                "final_status": status,
                "final_result": trim_text_chars(result, 180),
                "verdict_guess": "proven"
                if status == "finished" and _looks_like_positive_security_result(result)
                else ("blocked" if status == "blocked" else package.get("verdict_guess", "clean")),
            }
        )
        if not package.get("recommended_next_step"):
            package["recommended_next_step"] = trim_text_chars(
                self._result_next_step(result, status), 180
            )
        return package

    def _build_escalation_state(self, node: AgentGraphNode) -> dict[str, Any]:
        failed_runs = sum(1 for execution in node.executions if not execution.ok)
        reason = ""
        status = "clear"
        result_package = dict(node.result_package or {})
        evidence_gap = (
            result_package.get("evidence_gap")
            if isinstance(result_package.get("evidence_gap"), dict)
            else {}
        )
        if node.status == "blocked":
            status = "blocked"
            reason = node.result or "worker blocked"
        elif (
            evidence_gap.get("status") == "needs_more_evidence"
            and str(result_package.get("verdict_guess") or "") == "needs_proof"
            and int(evidence_gap.get("repeat_count") or 0) >= _MAX_REPEATED_EVIDENCE_GAPS
        ):
            status = "blocked_with_reason"
            reason = (
                f"same EvidenceArtifact gap repeated x{int(evidence_gap.get('repeat_count') or 0)}: "
                f"{str(evidence_gap.get('next_instruction') or '')}"
            )
        elif len(node.executions) >= self._max_child_runs:
            status = "run_limit"
            reason = f"worker hit child-run limit ({self._max_child_runs})"
        elif failed_runs >= 2:
            status = "ambiguous"
            reason = "repeated blocked or failed child turns"
        elif (
            node.executions
            and node.executions[-1].ok
            and _looks_like_positive_security_result(node.executions[-1].summary)
            and not _execution_has_proof_artifact(node.executions[-1], node=node)
        ):
            status = "needs_proof"
            artifact = _execution_evidence_artifact(node.executions[-1], node=node)
            missing = ", ".join(
                str(item) for item in list(artifact.get("gap_fields") or artifact.get("missing_fields") or [])
            )
            reason = (
                f"positive-looking child output lacks valid EvidenceArtifact fields: {missing}. "
                f"{str(evidence_gap.get('next_instruction') or '')}"
                if missing
                else "positive-looking child output lacks valid EvidenceArtifact"
            )
        elif (
            node.executions
            and node.executions[-1].ok
            and _looks_like_positive_security_result(node.result or node.executions[-1].summary)
        ):
            status = "positive_needs_pivot"
            reason = "positive result needs chain/pivot decision from director"
        if status == "clear":
            return {}
        return {
            "status": status,
            "reason": trim_text_chars(reason, 160),
            "recommended_owner": "director",
        }

    def _recommended_next_step(
        self,
        node: AgentGraphNode,
        execution: AgentGraphExecution,
        *,
        evidence_gap: dict[str, Any] | None = None,
    ) -> str:
        if not execution.ok:
            return "Escalate to director with blocker details or rerun a sharper bounded task"
        summary = execution.summary.lower()
        if _looks_like_positive_security_result(summary):
            artifact = _execution_evidence_artifact(execution, node=node)
            if not artifact.get("valid"):
                gap = evidence_gap if isinstance(evidence_gap, dict) else {}
                missing = ", ".join(
                    str(item)
                    for item in list(artifact.get("gap_fields") or artifact.get("missing_fields") or [])
                )
                next_instruction = str(gap.get("next_instruction") or "").strip()
                if next_instruction:
                    return f"Rerun with bounded evidence repair: {next_instruction}"
                if missing:
                    return f"Rerun with valid EvidenceArtifact before finish; missing {missing}"
                return "Rerun with valid EvidenceArtifact before finish; positive summary alone is insufficient"
            return "Escalate to director for chain/pivot planning, then finish with concrete impact"
        if "clean" in summary or "no issue" in summary:
            return "Finish as clean or redirect worker to a new surface"
        return "Send a sharper instruction or vary the proof surface before finish"

    @staticmethod
    def _result_next_step(result: str, status: str) -> str:
        if status == "blocked":
            return "Director should re-scope or close this task based on the blocker"
        if _looks_like_positive_security_result(result):
            return "Open a post-exploit or review task before allowing finish"
        return "Record the result and close or redirect this worker"

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
