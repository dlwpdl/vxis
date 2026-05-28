from __future__ import annotations

import hashlib
import json
from typing import Any


class ScanLoopExecutionMonitorMixin:
    """Detect no-progress action loops and inject a compact reflector hint."""

    def _execution_progress_marker(self) -> tuple[int, int, int, int, int, int, int, int]:
        found_candidates = sum(
            1 for candidate in self.state.vector_candidates.values() if candidate.status == "found"
        )
        terminal_branches = sum(
            1
            for branch in self.state.branches.values()
            if branch.status in {"proven", "exhausted", "dead", "blocked"}
        )
        return (
            len(self.state.findings),
            len(self.state.confirmed_findings),
            len(self.state.callback_observations),
            len(self.state.retrieval_observations),
            found_candidates,
            terminal_branches,
            len(self.state.review_history),
            len(self.state.review_queue),
        )

    def _execution_stall_threshold(self) -> int:
        profile = self._llm_discipline_profile()
        if profile == "local_strict":
            return 2
        if profile == "frontier_loose":
            return 4
        return 3

    @staticmethod
    def _execution_monitor_key(action_key: str) -> str:
        return hashlib.sha256(action_key.encode("utf-8", "ignore")).hexdigest()[:12]

    @staticmethod
    def _execution_monitor_args_preview(args: Any) -> str:
        try:
            return json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)[:180]
        except Exception:
            return str(args)[:180]

    def _maybe_emit_execution_monitor(
        self,
        *,
        action_key: str,
        name: str,
        args: dict[str, Any] | Any,
        stagnant_count: int,
        branch_ids: list[str],
        candidate_ids: list[str],
        emitted_keys: set[str],
    ) -> bool:
        if name in {"finish_scan", "think", "wait"}:
            return False
        if stagnant_count < self._execution_stall_threshold():
            return False
        digest = self._execution_monitor_key(action_key)
        if digest in emitted_keys:
            return False
        emitted_keys.add(digest)

        args_preview = self._execution_monitor_args_preview(args)
        branch_text = ", ".join(branch_ids[:3]) if branch_ids else "none"
        candidate_text = ", ".join(candidate_ids[:3]) if candidate_ids else "none"
        title = "repeated_action_no_progress"
        reason = (
            f"{name} repeated {stagnant_count}x with same args and no evidence/branch progress. "
            f"branches={branch_text}; candidates={candidate_text}"
        )
        action_hint = (
            "Change tool/args, narrow/spawn worker, report concrete evidence, or mark the branch blocked."
        )
        self.state.record_review_item(
            f"monitor:repeat:{name}:{digest}",
            stage="monitor",
            status="escalated",
            title=title,
            reason=reason,
            action_hint=action_hint,
        )
        self.state.add_shared_note(
            f"monitor: repeated {name} x{stagnant_count} without progress; change path or block."
        )
        self.state.add_message(
            "system",
            {
                "hint": (
                    "EXECUTION MONITOR: same action is repeating without progress.\n"
                    f"tool={name}\n"
                    f"args={args_preview}\n"
                    f"repeat_count={stagnant_count}\n"
                    f"branches={branch_text}; candidates={candidate_text}\n"
                    "Next action must change tool/args, create a narrower worker, report concrete evidence, "
                    "or close the branch as blocked/exhausted with a blocker."
                ),
            },
        )
        return True
