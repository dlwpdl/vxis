"""Durable scan-loop state used by ScanAgentLoop and tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

_TERMINAL_VECTOR_STATUSES = {"found", "clean", "blocked", "dead"}
_TERMINAL_TODO_STATUSES = {"done", "blocked"}
_TERMINAL_BRANCH_STATUSES = {"proven", "exhausted", "dead", "blocked"}


def _sanitize_evidence_text(value: Any, *, limit: int = 1200) -> str:
    """Render binary-ish evidence into report-safe printable text."""
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text:
        return ""
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if ch in {"\n", "\t"}:
            out.append(ch)
            continue
        if ch.isprintable() and ch != "\x00":
            out.append(ch)
            continue
        if code <= 0xFF:
            out.append(f"\\x{code:02x}")
        else:
            out.append(f"\\u{code:04x}")
    return "".join(out)[:limit]


def infer_branch_role(
    *,
    vector_id: str,
    title: str = "",
    objective: str = "",
    source_finding_id: str = "",
    crown_jewel: str = "",
) -> str:
    blob = " ".join((vector_id, title, objective, crown_jewel)).lower()
    if source_finding_id or any(
        token in blob
        for token in ("admin", "db", "dump", "key theft", "data exfil", "credential", "pivot")
    ):
        return "post_exploit_worker"
    if any(
        token in blob for token in ("review", "verify", "judge", "attestation", "chain analysis")
    ):
        return "review_worker"
    if any(
        token in blob
        for token in (
            "auth",
            "sqli",
            "sqli",
            "xss",
            "ssrf",
            "idor",
            "csrf",
            "business",
            "injection",
        )
    ):
        return "exploit_worker"
    return "recon_worker"


def infer_branch_phase(
    *,
    role: str,
    vector_id: str,
    title: str = "",
    objective: str = "",
    next_step: str = "",
    crown_jewel: str = "",
) -> str:
    blob = " ".join((vector_id, title, objective, next_step, crown_jewel)).lower()
    if role == "post_exploit_worker":
        if any(
            token in blob for token in ("cookie", "token", "session", "login", "post_auth_enum")
        ):
            return "session_reuse"
        if any(
            token in blob for token in ("/admin", "role", "privilege", "export", "state-changing")
        ):
            return "privilege_probe"
        if any(
            token in blob
            for token in ("dump", "data", "rows", "table", "exfil", "download", "enumerate")
        ):
            return "data_access"
        return "chain_closure"
    if role == "exploit_worker":
        return "exploit_validation"
    if role == "review_worker":
        return "adjudication"
    return "surface_mapping"


def action_capability(name: str, args: dict[str, Any] | Any) -> str:
    if name in {"verify_finding"}:
        return "review"
    if name in {"query_findings", "query_scan_memory"}:
        return "memory"
    if name in {"link_chain"}:
        return "chain"
    if name in {"agent_graph"}:
        return "plan"
    if name in {"finish_scan", "think", "wait"}:
        return "control" if name != "think" else "plan"
    if name in {"report_finding"}:
        return "report"
    if name in {"fingerprint_target", "load_playbook", "list_playbooks"}:
        return "recon"
    if name.startswith("browser_"):
        return "browse"
    if name in {"http_request"}:
        return "probe"
    if name in {"shell_exec", "python_exec"}:
        return "exploit"
    if name == "run_skill" and isinstance(args, dict):
        skill = str(args.get("skill", args.get("_skill_override", ""))).lower()
        if skill in {
            "enumerate_endpoints",
            "test_sensitive_files",
            "test_infra",
            "test_misconfig",
            "fingerprint_target",
        }:
            return "recon"
        if skill in {"post_auth_enum", "test_api_security"}:
            return "retrieve"
        if skill in {
            "test_injection",
            "attempt_auth",
            "test_idor",
            "test_xss",
            "test_ssrf",
            "test_auth_deep",
            "test_business_logic",
            "test_csrf",
            "test_crypto",
        }:
            return "exploit"
    return "probe"


def advance_post_exploit_phase(
    phase: str,
    name: str,
    args: dict[str, Any] | Any,
) -> str:
    capability = action_capability(name, args)
    if phase == "session_reuse" and capability in {"browse", "probe", "retrieve"}:
        blob = f"{name} {args}".lower()
        if any(
            token in blob
            for token in (
                "/admin",
                "role",
                "export",
                "post_auth_enum",
                "browser_get_cookies",
                "cookie",
                "token",
            )
        ):
            return "privilege_probe"
    if phase == "privilege_probe" and capability in {"probe", "exploit", "retrieve"}:
        blob = f"{name} {args}".lower()
        if any(
            token in blob
            for token in (
                "dump",
                "table",
                "users",
                "download",
                "export",
                "orders",
                "profile",
                "sqlmap",
            )
        ):
            return "data_access"
    if phase == "data_access" and capability in {"report", "chain", "review"}:
        return "chain_closure"
    return phase


@dataclass
class VectorCandidate:
    """A durable attack hypothesis the loop should prove, refute, or exhaust."""

    id: str
    vector_id: str
    title: str
    priority: int
    evidence: str
    status: str = "open"
    attempts: int = 0
    created_iter: int = 0
    last_iter: int = 0
    last_tool: str = ""
    last_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vector_id": self.vector_id,
            "title": self.title,
            "priority": self.priority,
            "evidence": self.evidence,
            "status": self.status,
            "attempts": self.attempts,
            "created_iter": self.created_iter,
            "last_iter": self.last_iter,
            "last_tool": self.last_tool,
            "last_summary": self.last_summary,
        }


@dataclass
class AttemptOutcome:
    """A single concrete attempt against a vector candidate."""

    candidate_id: str
    vector_id: str
    tool: str
    args_preview: str
    status: str
    summary: str
    iteration: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "vector_id": self.vector_id,
            "tool": self.tool,
            "args_preview": self.args_preview,
            "status": self.status,
            "summary": self.summary,
            "iteration": self.iteration,
        }


@dataclass
class ScanTodo:
    """Operator-facing work item that should stay visible in the TUI."""

    id: str
    title: str
    priority: int
    source_candidate_id: str = ""
    status: str = "pending"
    detail: str = ""
    last_iter: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "priority": self.priority,
            "source_candidate_id": self.source_candidate_id,
            "status": self.status,
            "detail": self.detail,
            "last_iter": self.last_iter,
        }


@dataclass
class BranchState:
    """Durable attack branch derived from a vector candidate."""

    id: str
    vector_id: str
    title: str
    priority: int
    role: str = "recon_worker"
    phase: str = "surface_mapping"
    owner: str = "root"
    parent_branch_id: str = ""
    source_candidate_id: str = ""
    source_finding_id: str = ""
    objective: str = ""
    next_step: str = ""
    blocker: str = ""
    escalation_status: str = ""
    escalation_reason: str = ""
    escalation_owner: str = ""
    crown_jewel: str = ""
    evidence: str = ""
    status: str = "open"
    attempts: int = 0
    last_tool: str = ""
    last_summary: str = ""
    last_report: str = ""
    child_ids: list[str] = field(default_factory=list)
    watch_terms: list[str] = field(default_factory=list)
    last_iter: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vector_id": self.vector_id,
            "title": self.title,
            "priority": self.priority,
            "role": self.role,
            "phase": self.phase,
            "owner": self.owner,
            "parent_branch_id": self.parent_branch_id,
            "source_candidate_id": self.source_candidate_id,
            "source_finding_id": self.source_finding_id,
            "objective": self.objective,
            "next_step": self.next_step,
            "blocker": self.blocker,
            "escalation_status": self.escalation_status,
            "escalation_reason": self.escalation_reason,
            "escalation_owner": self.escalation_owner,
            "crown_jewel": self.crown_jewel,
            "evidence": self.evidence,
            "status": self.status,
            "attempts": self.attempts,
            "last_tool": self.last_tool,
            "last_summary": self.last_summary,
            "last_report": self.last_report,
            "child_ids": list(self.child_ids),
            "watch_terms": list(self.watch_terms),
            "last_iter": self.last_iter,
        }


@dataclass
class ReviewItem:
    """A verifier/judge escalation that should stay visible across iterations."""

    id: str
    stage: str
    status: str
    title: str
    reason: str
    action_hint: str = ""
    affected_component: str = ""
    source_finding_type: str = ""
    iteration: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "stage": self.stage,
            "status": self.status,
            "title": self.title,
            "reason": self.reason,
            "action_hint": self.action_hint,
            "affected_component": self.affected_component,
            "source_finding_type": self.source_finding_type,
            "iteration": self.iteration,
        }


@dataclass
class ReviewDecision:
    """Concrete verifier/judge adjudication recorded as review telemetry."""

    stage: str
    verdict: str
    title: str
    reason: str
    action_hint: str = ""
    blocked_action: str = ""
    affected_component: str = ""
    source_finding_type: str = ""
    iteration: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "verdict": self.verdict,
            "title": self.title,
            "reason": self.reason,
            "action_hint": self.action_hint,
            "blocked_action": self.blocked_action,
            "affected_component": self.affected_component,
            "source_finding_type": self.source_finding_type,
            "iteration": self.iteration,
        }


@dataclass
class CallbackObservation:
    """Observed callback / internal reachability evidence for blind or SSRF-style pivots."""

    finding_type: str
    component: str
    signal: str
    payload: str
    summary: str
    iteration: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "component": self.component,
            "signal": self.signal,
            "payload": self.payload,
            "summary": self.summary,
            "iteration": self.iteration,
        }


@dataclass
class RetrievalObservation:
    """Observed credential/data retrieval or exfiltration evidence."""

    finding_type: str
    component: str
    retrieval_kind: str
    summary: str
    sample: str
    iteration: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "component": self.component,
            "retrieval_kind": self.retrieval_kind,
            "summary": self.summary,
            "sample": self.sample,
            "iteration": self.iteration,
        }


@dataclass
class ScanLoopState:
    target: str
    messages: list[dict[str, Any]] = field(default_factory=list)
    iteration: int = 0
    max_iters: int = 300
    completed: bool = False
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[dict[str, Any]] = field(default_factory=list)
    # Peak byte size of messages[] seen across the run — sampled each iteration.
    # Surfaced by ScanPipelineV2 into ctx.peak_context_bytes for the Task 14 benchmark.
    peak_context_bytes: int = 0
    # Phase C belief state: per-verdict counts from auto-verify interception
    verdict_counts: dict[str, int] = field(
        default_factory=lambda: {"CONFIRMED": 0, "UNCONFIRMED": 0, "REFUTED": 0}
    )
    refuted_findings: list[dict[str, Any]] = field(default_factory=list)
    confirmed_findings: list[dict[str, Any]] = field(default_factory=list)
    vector_candidates: dict[str, VectorCandidate] = field(default_factory=dict)
    attempt_outcomes: list[AttemptOutcome] = field(default_factory=list)
    scan_todos: dict[str, ScanTodo] = field(default_factory=dict)
    branches: dict[str, BranchState] = field(default_factory=dict)
    review_queue: dict[str, ReviewItem] = field(default_factory=dict)
    review_history: list[ReviewDecision] = field(default_factory=list)
    callback_observations: list[CallbackObservation] = field(default_factory=list)
    retrieval_observations: list[RetrievalObservation] = field(default_factory=list)
    waiting_reason: str = ""
    shared_notes: list[str] = field(default_factory=list)
    blocked_skill_counts: dict[str, int] = field(default_factory=dict)

    def add_message(self, role: str, content: Any) -> None:
        self.messages.append({"role": role, "content": content, "iter": self.iteration})

    def ensure_vector_candidate(
        self,
        candidate_id: str,
        vector_id: str,
        title: str,
        *,
        priority: int = 50,
        evidence: str = "",
    ) -> VectorCandidate:
        """Create or refresh a durable vector candidate."""
        existing = self.vector_candidates.get(candidate_id)
        if existing is not None:
            existing.priority = max(existing.priority, priority)
            if evidence and evidence not in existing.evidence:
                existing.evidence = (existing.evidence + "; " + evidence).strip("; ")
            if existing.status in _TERMINAL_VECTOR_STATUSES and existing.status != "found":
                existing.status = "retryable"
            self.ensure_scan_todo(
                candidate_id,
                title,
                priority=existing.priority,
                source_candidate_id=candidate_id,
            )
            self.ensure_branch(
                candidate_id,
                vector_id,
                title,
                priority=existing.priority,
                role=infer_branch_role(vector_id=vector_id, title=title),
                evidence=existing.evidence,
            )
            self._sync_candidate_control_state(existing)
            return existing

        candidate = VectorCandidate(
            id=candidate_id,
            vector_id=vector_id,
            title=title,
            priority=priority,
            evidence=evidence,
            created_iter=self.iteration,
            last_iter=self.iteration,
        )
        self.vector_candidates[candidate_id] = candidate
        self.ensure_scan_todo(
            candidate_id,
            title,
            priority=priority,
            source_candidate_id=candidate_id,
        )
        self.ensure_branch(
            candidate_id,
            vector_id,
            title,
            priority=priority,
            role=infer_branch_role(vector_id=vector_id, title=title),
            evidence=evidence,
        )
        self._sync_candidate_control_state(candidate)
        return candidate

    def ensure_scan_todo(
        self,
        todo_id: str,
        title: str,
        *,
        priority: int = 50,
        source_candidate_id: str = "",
    ) -> ScanTodo:
        todo = self.scan_todos.get(todo_id)
        if todo is None:
            todo = ScanTodo(
                id=todo_id,
                title=title,
                priority=priority,
                source_candidate_id=source_candidate_id,
                last_iter=self.iteration,
            )
            self.scan_todos[todo_id] = todo
            return todo
        todo.title = title
        todo.priority = max(todo.priority, priority)
        if source_candidate_id:
            todo.source_candidate_id = source_candidate_id
        todo.last_iter = self.iteration
        return todo

    def ensure_branch(
        self,
        branch_id: str,
        vector_id: str,
        title: str,
        *,
        priority: int = 50,
        role: str = "recon_worker",
        phase: str = "",
        owner: str = "root",
        parent_branch_id: str = "",
        source_candidate_id: str = "",
        source_finding_id: str = "",
        objective: str = "",
        next_step: str = "",
        blocker: str = "",
        escalation_status: str = "",
        escalation_reason: str = "",
        escalation_owner: str = "",
        crown_jewel: str = "",
        evidence: str = "",
        watch_terms: list[str] | None = None,
    ) -> BranchState:
        branch = self.branches.get(branch_id)
        if branch is None:
            branch = BranchState(
                id=branch_id,
                vector_id=vector_id,
                title=title,
                priority=priority,
                role=role,
                phase=phase
                or infer_branch_phase(
                    role=role,
                    vector_id=vector_id,
                    title=title,
                    objective=objective,
                    next_step=next_step,
                    crown_jewel=crown_jewel,
                ),
                owner=owner,
                parent_branch_id=parent_branch_id,
                source_candidate_id=source_candidate_id,
                source_finding_id=source_finding_id,
                objective=objective,
                next_step=next_step,
                blocker=blocker,
                escalation_status=escalation_status,
                escalation_reason=escalation_reason,
                escalation_owner=escalation_owner,
                crown_jewel=crown_jewel,
                evidence=evidence,
                watch_terms=list(watch_terms or []),
                last_iter=self.iteration,
            )
            self.branches[branch_id] = branch
            if parent_branch_id and parent_branch_id in self.branches:
                parent = self.branches[parent_branch_id]
                if branch_id not in parent.child_ids:
                    parent.child_ids.append(branch_id)
            return branch
        branch.title = title
        branch.priority = max(branch.priority, priority)
        branch.role = role or branch.role
        branch.phase = (
            phase
            or branch.phase
            or infer_branch_phase(
                role=branch.role,
                vector_id=vector_id,
                title=title,
                objective=objective or branch.objective,
                next_step=next_step or branch.next_step,
                crown_jewel=crown_jewel or branch.crown_jewel,
            )
        )
        branch.owner = owner or branch.owner
        if parent_branch_id:
            branch.parent_branch_id = parent_branch_id
        if source_candidate_id:
            branch.source_candidate_id = source_candidate_id
        if source_finding_id:
            branch.source_finding_id = source_finding_id
        if objective:
            branch.objective = objective
        if next_step:
            branch.next_step = next_step
        if blocker:
            branch.blocker = blocker
        if escalation_status:
            branch.escalation_status = escalation_status
        if escalation_reason:
            branch.escalation_reason = escalation_reason
        if escalation_owner:
            branch.escalation_owner = escalation_owner
        if crown_jewel:
            branch.crown_jewel = crown_jewel
        if evidence and evidence not in branch.evidence:
            branch.evidence = (branch.evidence + "; " + evidence).strip("; ")
        if watch_terms:
            for term in watch_terms:
                norm = str(term).strip().lower()
                if norm and norm not in branch.watch_terms:
                    branch.watch_terms.append(norm)
        if parent_branch_id and parent_branch_id in self.branches:
            parent = self.branches[parent_branch_id]
            if branch_id not in parent.child_ids:
                parent.child_ids.append(branch_id)
        branch.last_iter = self.iteration
        return branch

    def add_shared_note(self, note: str) -> None:
        clean = note.strip()
        if not clean:
            return
        clean = clean[:160]
        if clean in self.shared_notes[-4:]:
            return
        self.shared_notes.append(clean)
        if len(self.shared_notes) > 8:
            self.shared_notes = self.shared_notes[-8:]

    def set_waiting_reason(self, reason: str) -> None:
        self.waiting_reason = reason.strip()[:180]

    def clear_waiting_reason(self) -> None:
        self.waiting_reason = ""

    def record_blocked_skill(self, skill_name: str) -> None:
        clean = str(skill_name).strip().lower()
        if not clean:
            return
        self.blocked_skill_counts[clean] = self.blocked_skill_counts.get(clean, 0) + 1

    def record_review_item(
        self,
        item_id: str,
        *,
        stage: str,
        status: str,
        title: str,
        reason: str,
        action_hint: str = "",
        affected_component: str = "",
        source_finding_type: str = "",
    ) -> ReviewItem:
        item = self.review_queue.get(item_id)
        if item is None:
            item = ReviewItem(
                id=item_id,
                stage=stage,
                status=status,
                title=title[:160],
                reason=reason[:260],
                action_hint=action_hint[:200],
                affected_component=affected_component[:200],
                source_finding_type=source_finding_type[:80],
                iteration=self.iteration,
            )
            self.review_queue[item_id] = item
            return item
        item.stage = stage or item.stage
        item.status = status or item.status
        item.title = title[:160] or item.title
        item.reason = reason[:260] or item.reason
        item.action_hint = action_hint[:200] or item.action_hint
        item.affected_component = affected_component[:200] or item.affected_component
        item.source_finding_type = source_finding_type[:80] or item.source_finding_type
        item.iteration = self.iteration
        return item

    def review_queue_as_dicts(self) -> list[dict[str, Any]]:
        return [
            item.to_dict()
            for item in sorted(
                self.review_queue.values(),
                key=lambda i: (i.status == "closed", -i.iteration, i.id),
            )
        ]

    def record_review_decision(
        self,
        *,
        stage: str,
        verdict: str,
        title: str,
        reason: str,
        action_hint: str = "",
        blocked_action: str = "",
        affected_component: str = "",
        source_finding_type: str = "",
    ) -> None:
        self.review_history.append(
            ReviewDecision(
                stage=stage[:32],
                verdict=verdict[:32],
                title=title[:160],
                reason=reason[:300],
                action_hint=action_hint[:200],
                blocked_action=blocked_action[:80],
                affected_component=affected_component[:240],
                source_finding_type=source_finding_type[:80],
                iteration=self.iteration,
            )
        )

    def review_history_as_dicts(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.review_history]

    def record_callback_observation(
        self,
        *,
        finding_type: str,
        component: str,
        signal: str,
        payload: str,
        summary: str,
    ) -> None:
        self.callback_observations.append(
            CallbackObservation(
                finding_type=str(finding_type)[:80],
                component=str(component)[:240],
                signal=str(signal)[:120],
                payload=str(payload)[:300],
                summary=str(summary)[:500],
                iteration=self.iteration,
            )
        )

    def record_retrieval_observation(
        self,
        *,
        finding_type: str,
        component: str,
        retrieval_kind: str,
        summary: str,
        sample: str,
    ) -> None:
        self.retrieval_observations.append(
            RetrievalObservation(
                finding_type=str(finding_type)[:80],
                component=str(component)[:240],
                retrieval_kind=str(retrieval_kind)[:80],
                summary=str(summary)[:500],
                sample=_sanitize_evidence_text(sample, limit=1200),
                iteration=self.iteration,
            )
        )

    def callback_observations_as_dicts(self) -> list[dict[str, Any]]:
        return [obs.to_dict() for obs in self.callback_observations]

    def retrieval_observations_as_dicts(self) -> list[dict[str, Any]]:
        return [obs.to_dict() for obs in self.retrieval_observations]

    @staticmethod
    def _todo_status_for_candidate(status: str) -> str:
        return {
            "open": "pending",
            "retryable": "pending",
            "attempted": "in_progress",
            "failed": "in_progress",
            "blocked": "blocked",
            "found": "done",
            "clean": "done",
            "dead": "done",
        }.get(status, "pending")

    @staticmethod
    def _branch_status_for_candidate(status: str) -> str:
        return {
            "open": "open",
            "retryable": "retryable",
            "attempted": "active",
            "failed": "active",
            "blocked": "blocked",
            "found": "proven",
            "clean": "exhausted",
            "dead": "dead",
        }.get(status, "open")

    def _sync_candidate_control_state(self, candidate: VectorCandidate) -> None:
        todo = self.ensure_scan_todo(
            candidate.id,
            candidate.title,
            priority=candidate.priority,
            source_candidate_id=candidate.id,
        )
        todo.status = self._todo_status_for_candidate(candidate.status)
        todo.detail = (
            candidate.last_summary[:120] if candidate.last_summary else candidate.evidence[:120]
        )
        todo.last_iter = self.iteration

        branch = self.ensure_branch(
            candidate.id,
            candidate.vector_id,
            candidate.title,
            priority=candidate.priority,
            role=infer_branch_role(vector_id=candidate.vector_id, title=candidate.title),
            phase=infer_branch_phase(
                role=infer_branch_role(vector_id=candidate.vector_id, title=candidate.title),
                vector_id=candidate.vector_id,
                title=candidate.title,
            ),
            source_candidate_id=candidate.id,
            evidence=candidate.evidence,
            watch_terms=[candidate.vector_id.lower(), candidate.title.lower()],
        )
        branch.status = self._branch_status_for_candidate(candidate.status)
        branch.attempts = candidate.attempts
        branch.last_tool = candidate.last_tool
        branch.last_summary = candidate.last_summary
        branch.last_report = candidate.last_summary[:160]
        branch.last_iter = self.iteration

    def record_branch_attempt(
        self,
        branch_id: str,
        tool: str,
        args: Any | None = None,
        *,
        status: str,
        summary: str,
        blocker: str = "",
    ) -> None:
        branch = self.branches.get(branch_id)
        if branch is None:
            return
        branch.attempts += 1
        branch.last_tool = tool
        branch.last_summary = summary[:240]
        branch.last_report = summary[:160]
        branch.last_iter = self.iteration
        if branch.role == "post_exploit_worker":
            branch.phase = advance_post_exploit_phase(branch.phase, tool, args or {})
        if blocker:
            branch.blocker = blocker[:180]
        if branch.owner == "agent_graph" and tool != "agent_graph":
            branch.status = "active"
            if status == "blocked" and not blocker:
                branch.blocker = summary[:180]
        elif status == "found":
            branch.status = "proven"
        elif status == "clean":
            branch.status = "exhausted"
        elif status == "blocked":
            branch.status = "blocked"
        else:
            branch.status = "active"
        todo = self.ensure_scan_todo(
            branch.id,
            branch.title,
            priority=branch.priority,
            source_candidate_id=branch.source_candidate_id or branch.id,
        )
        todo.status = {
            "proven": "done",
            "exhausted": "done",
            "dead": "done",
            "blocked": "blocked",
            "active": "in_progress",
            "open": "pending",
            "retryable": "pending",
        }.get(branch.status, "pending")
        todo.detail = branch.last_report[:120]
        todo.last_iter = self.iteration

    def active_branches(self) -> list[BranchState]:
        return sorted(
            [b for b in self.branches.values() if b.status not in _TERMINAL_BRANCH_STATUSES],
            key=lambda b: (-b.priority, b.attempts, b.last_iter, b.id),
        )

    def scan_todos_as_dicts(self) -> list[dict[str, Any]]:
        ordered = sorted(
            self.scan_todos.values(),
            key=lambda t: (t.status in _TERMINAL_TODO_STATUSES, -t.priority, t.last_iter, t.id),
        )
        return [t.to_dict() for t in ordered]

    def branches_as_dicts(self) -> list[dict[str, Any]]:
        ordered = sorted(
            self.branches.values(),
            key=lambda b: (b.status in _TERMINAL_BRANCH_STATUSES, -b.priority, b.attempts, b.id),
        )
        return [b.to_dict() for b in ordered]

    def record_attempt_outcome(
        self,
        candidate_id: str,
        tool: str,
        args: Any,
        *,
        status: str,
        summary: str,
    ) -> None:
        """Record a concrete attempt against a candidate and update its state."""
        candidate = self.vector_candidates.get(candidate_id)
        if candidate is None:
            return
        candidate.attempts += 1
        candidate.status = status
        candidate.last_iter = self.iteration
        candidate.last_tool = tool
        candidate.last_summary = summary[:240]
        try:
            args_preview = json.dumps(args, default=str, ensure_ascii=False, sort_keys=True)[:500]
        except Exception:
            args_preview = str(args)[:500]
        self.attempt_outcomes.append(
            AttemptOutcome(
                candidate_id=candidate.id,
                vector_id=candidate.vector_id,
                tool=tool,
                args_preview=args_preview,
                status=status,
                summary=summary[:500],
                iteration=self.iteration,
            )
        )
        self._sync_candidate_control_state(candidate)
        if status == "found":
            self.add_shared_note(f"{candidate.vector_id}: {summary[:120]}")

    def open_vector_candidates(self) -> list[VectorCandidate]:
        """Return candidates that still need proof, retry, or a clear dead-end."""
        return sorted(
            [
                c
                for c in self.vector_candidates.values()
                if c.status not in _TERMINAL_VECTOR_STATUSES
            ],
            key=lambda c: (-c.priority, c.attempts, c.created_iter, c.id),
        )

    def vector_candidates_as_dicts(self) -> list[dict[str, Any]]:
        return [c.to_dict() for c in sorted(self.vector_candidates.values(), key=lambda c: c.id)]

    def attempt_outcomes_as_dicts(self) -> list[dict[str, Any]]:
        return [o.to_dict() for o in self.attempt_outcomes]

    def control_plane_snapshot(self, *, limit: int = 4) -> dict[str, Any]:
        todos = self.scan_todos_as_dicts()
        branches = self.branches_as_dicts()
        todo_counts: dict[str, int] = {}
        branch_counts: dict[str, int] = {}
        for todo in todos:
            todo_counts[todo["status"]] = todo_counts.get(todo["status"], 0) + 1
        for branch in branches:
            branch_counts[branch["status"]] = branch_counts.get(branch["status"], 0) + 1
        return {
            "iteration": self.iteration,
            "max_iters": self.max_iters,
            "waiting_reason": self.waiting_reason,
            "todo_counts": todo_counts,
            "branch_counts": branch_counts,
            "review_counts": {
                status: sum(1 for item in self.review_queue.values() if item.status == status)
                for status in {"open", "escalated", "closed"}
                if any(item.status == status for item in self.review_queue.values())
            },
            "review_decision_counts": {
                stage: sum(1 for item in self.review_history if item.stage == stage)
                for stage in {"verifier", "judge"}
                if any(item.stage == stage for item in self.review_history)
            },
            "todos": todos[:limit],
            "branches": branches[:limit],
            "reviews": self.review_queue_as_dicts()[:limit],
            "recent_attempts": self.attempt_outcomes_as_dicts()[-limit:],
            "shared_notes": list(self.shared_notes[-3:]),
        }

    def update_peak_size(self) -> int:
        """Sample current messages[] byte size and update peak_context_bytes.

        Called once per iteration in ScanAgentLoop.run so the Phase A
        instrumentation metric has a meaningful non-zero value. Deterministic
        JSON-length proxy matching ScanContext.update_peak_size for consistency.
        Returns the current size.
        """
        try:
            current = len(json.dumps(self.messages, default=str, ensure_ascii=False))
        except Exception:
            current = 0
        if current > self.peak_context_bytes:
            self.peak_context_bytes = current
        return current
