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
        import re as _re

        self.state.add_message("system", f"Scan started on {self.state.target}")
        self.state.add_message("user", f"Target: {self.state.target}. Find all vulnerabilities.")

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
                        seen = set()
                        for code, size_s, path in rows:
                            size = int(size_s)
                            key = (code, path)
                            if key in seen:
                                continue
                            seen.add(key)
                            code_i = int(code)
                            norm_path = "/" + path.lstrip("/")
                            # Real-finding heuristics:
                            if code_i == 500:
                                findings_hint.append(
                                    f"  - {code} {size}B {norm_path} → HTTP 500 = potential injection/logic bug (severity=high, finding_type=information_disclosure)"
                                )
                            elif code_i == 401 and "basket" in norm_path.lower():
                                findings_hint.append(
                                    f"  - {code} {size}B {norm_path} → auth-protected but enumerable = IDOR candidate (severity=medium, finding_type=broken_access_control)"
                                )
                            elif code_i == 403 and any(x in norm_path.lower() for x in (".bak", ".old", ".backup", "~")):
                                findings_hint.append(
                                    f"  - {code} {size}B {norm_path} → backup file accessible (severity=medium, finding_type=information_disclosure)"
                                )
                            elif code_i == 200 and _baseline_size is not None and size != _baseline_size and size > 100:
                                # Different from SPA shell → real content
                                sensitive = any(x in norm_path.lower() for x in (
                                    "admin", "config", "api-doc", "swagger", "graphql",
                                    "ftp", ".git", ".env", "actuator", "debug", "backup",
                                    "assets", "rest/admin", "rest/user", "rest/basket",
                                ))
                                if sensitive:
                                    findings_hint.append(
                                        f"  - {code} {size}B {norm_path} → differs from SPA baseline {_baseline_size}B = real content exposed (severity=high if admin/config, medium otherwise, finding_type=information_disclosure)"
                                    )
                        if findings_hint:
                            hint_msg = (
                                "SYSTEM HINT — the previous probe output contains "
                                "likely findings. Call report_finding for each one "
                                "BEFORE running another probe:\n"
                                + "\n".join(findings_hint[:8])
                                + f"\n\nBaseline SPA shell size = {_baseline_size or 'unknown'} bytes. "
                                "Any path returning exactly that size is the SPA shell and NOT a finding. "
                                "Use report_finding with the severity and finding_type suggested above."
                            )
                            self.state.add_message("user", hint_msg)
                            logger.info(
                                "iter %d: injected finding hint with %d candidates",
                                self.state.iteration, len(findings_hint),
                            )

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
