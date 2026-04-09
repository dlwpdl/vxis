from __future__ import annotations
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from vxis.agent.tool_registry import ToolRegistry, ToolResult

logger = logging.getLogger(__name__)

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

    def add_message(self, role: str, content: Any) -> None:
        self.messages.append({"role": role, "content": content, "iter": self.iteration})

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

class ScanAgentLoop:
    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        max_iters: int = 300,
        brain: Any | None = None,
    ) -> None:
        self.state = ScanLoopState(target=target, max_iters=max_iters)
        self.registry = registry
        self.brain = brain

    async def _decide(self, state: ScanLoopState) -> list[tuple[str, dict[str, Any]]]:
        """Returns list of (tool_name, args). Delegates to brain.think_in_loop when brain is set."""
        if self.brain is None:
            return [("finish_scan", {})]
        return await self.brain.think_in_loop(state.messages, self.registry.describe_all())

    async def run(self) -> dict[str, Any]:
        import json as _json

        self.state.add_message("system", f"Scan started on {self.state.target}")
        self.state.add_message("user", f"Target: {self.state.target}. Find all vulnerabilities.")

        # Phase B fix: code-level anti-repetition. Track hash of (tool, args)
        # so we can detect when Brain is about to run an identical call a 3rd+
        # time and inject a synthetic "DEDUP" result instead of re-running.
        # This breaks the loop regardless of whether Brain's prompt adherence.
        _call_counts: dict[str, int] = {}

        while not self.state.completed and self.state.iteration < self.state.max_iters:
            self.state.iteration += 1
            actions = await self._decide(self.state)
            if not actions:
                logger.warning("iter %d: no actions returned, stopping", self.state.iteration)
                break
            for name, args in actions:
                # Compute a stable hash key for the (tool, args) pair
                try:
                    key = f"{name}::{_json.dumps(args, sort_keys=True, default=str)}"
                except Exception:
                    key = f"{name}::{args!r}"

                count = _call_counts.get(key, 0) + 1
                _call_counts[key] = count

                if count >= 3 and name != "finish_scan":
                    # Third or later time we're seeing this exact call. Skip the
                    # real dispatch and inject a nudge message so Brain sees
                    # different context on the next iteration.
                    nudge = (
                        f"DEDUP: You already ran {name} with these exact args "
                        f"{count - 1} times in this scan. The result did not "
                        f"change. STOP repeating this call and try something "
                        f"different: pick a NEW endpoint, a DIFFERENT tool, or "
                        f"call finish_scan if you truly have nothing new to try."
                    )
                    self.state.add_message("tool", {"name": name, "args": args, "result": {
                        "ok": False,
                        "summary": nudge,
                        "data": {"dedup": True, "prior_calls": count - 1},
                    }})
                    logger.warning(
                        "iter %d: dedup-blocked repeated call: %s (count=%d)",
                        self.state.iteration, name, count,
                    )
                    continue

                result = await self.registry.dispatch(name, args)
                self.state.add_message("tool", {"name": name, "args": args, "result": {
                    "ok": result.ok, "summary": result.summary, "data": result.data,
                }})
                if name == "finish_scan" and result.ok:
                    self.state.completed = True
                    break
            # Sample messages[] byte size at the end of each iteration.
            # Phase B fix: populates peak_context_bytes metric that was 0 in Task 11.
            self.state.update_peak_size()
        return {
            "target": self.state.target,
            "completed": self.state.completed,
            "iterations": self.state.iteration,
            "findings": self.state.findings,
            "messages": len(self.state.messages),
            "peak_context_bytes": self.state.peak_context_bytes,
        }
