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
    # Phase C belief state: per-verdict counts from auto-verify interception
    verdict_counts: dict[str, int] = field(default_factory=lambda: {"CONFIRMED": 0, "UNCONFIRMED": 0, "REFUTED": 0})
    refuted_findings: list[dict[str, Any]] = field(default_factory=list)
    confirmed_findings: list[dict[str, Any]] = field(default_factory=list)

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

CRITIC_PROMPT_TEMPLATE = """\
You are a senior pentest strategist reviewing an in-progress scan.
Do NOT emit tool calls. Output a SHORT critique (2-5 sentences) covering:
1. What has been discovered so far (summarize findings)
2. What is missing or unexplored (be specific — name endpoints/techniques)
3. Concrete next action(s) the executor agent should take
4. Whether to continue probing OR call finish_scan

TARGET: {target}
ITERATION: {iteration}/{max_iters}
FINDINGS SO FAR: {finding_count}
RECENT ACTIONS (last 10):
{recent_actions}

CURRENT FINDINGS:
{findings_list}

Your critique:"""


class ScanAgentLoop:
    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        max_iters: int = 300,
        brain: Any | None = None,
        critic_interval: int = 8,
    ) -> None:
        self.state = ScanLoopState(target=target, max_iters=max_iters)
        self.registry = registry
        self.brain = brain
        self.critic_interval = critic_interval
        self._last_critic_iter = 0

    async def _decide(self, state: ScanLoopState) -> list[tuple[str, dict[str, Any]]]:
        """Returns list of (tool_name, args). Delegates to brain.think_in_loop when brain is set."""
        if self.brain is None:
            return [("finish_scan", {})]
        return await self.brain.think_in_loop(state.messages, self.registry.describe_all())

    async def _critic_review(self) -> str | None:
        """Dual Brain critic: every N iterations, ask a stronger model to
        review progress and suggest next direction. Returns the critique
        text to inject as a user message, or None if unavailable.

        Uses the same brain instance but calls _call_llm_with_fallback
        directly with the critic prompt (no tool catalog). If gpt-5.4 full
        is available via OPENAI_API_KEY, it will be used instead of the
        loop's mini model for the critique.
        """
        import asyncio
        if self.brain is None or not hasattr(self.brain, "_call_llm_with_fallback"):
            return None
        try:
            from vxis.agent.tools.finding_tools import _get_findings
            current_findings = _get_findings()
        except Exception:
            current_findings = []
        # Build a compact recent-action summary
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
        prompt = CRITIC_PROMPT_TEMPLATE.format(
            target=self.state.target,
            iteration=self.state.iteration,
            max_iters=self.state.max_iters,
            finding_count=len(current_findings),
            recent_actions="\n".join(recent[-10:]) or "  (no actions)",
            findings_list=findings_summary,
        )
        # Temporarily switch to gpt-5.4 full for the critic call if OpenAI is
        # the current provider. This gives stronger reasoning at negligible cost
        # (one call per critic_interval iterations).
        import os
        orig_model = getattr(self.brain, "_model", None)
        use_stronger = False
        if (
            getattr(self.brain, "_provider", None) == "openai"
            and os.environ.get("OPENAI_API_KEY")
            and orig_model
            and "mini" in str(orig_model)
        ):
            self.brain._model = "gpt-5.4"  # upgrade for critic only
            use_stronger = True
        try:
            response = await asyncio.to_thread(
                self.brain._call_llm_with_fallback,
                "You are a senior pentest strategist. Output prose only, no JSON, no tool calls.",
                prompt,
            )
        except Exception as e:
            logger.warning("critic review failed: %s", e)
            return None
        finally:
            if use_stronger and orig_model is not None:
                self.brain._model = orig_model
        if not response:
            return None
        return response.strip()[:1500]

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
        # Sticky hint: track candidates Brain still hasn't reported yet.
        # Keyed by (finding_type, affected_component) so we can check against
        # finding_tools store and drop items once Brain reports them.
        _pending_findings: dict[tuple[str, str], str] = {}

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
                            "evidence": args.get("evidence", ""),
                        }
                        if _baseline_size is not None:
                            verify_args["baseline_size"] = _baseline_size
                        verdict_result = await self.registry.dispatch("verify_finding", verify_args)
                        if verdict_result.ok:
                            verdict_data = verdict_result.data or {}
                            verdict = verdict_data.get("verdict", "UNCONFIRMED")
                            # Phase C belief state: track verdict counts
                            self.state.verdict_counts[verdict] = self.state.verdict_counts.get(verdict, 0) + 1
                            _belief_entry = {
                                "iter": self.state.iteration,
                                "title": args.get("title", ""),
                                "severity": args.get("severity", ""),
                                "finding_type": args.get("finding_type", ""),
                                "affected_component": args.get("affected_component", ""),
                                "confidence": verdict_data.get("confidence", "low"),
                                "reasoning": str(verdict_data.get("reasoning", ""))[:300],
                            }
                            if verdict == "CONFIRMED":
                                self.state.confirmed_findings.append(_belief_entry)
                            elif verdict == "REFUTED":
                                self.state.refuted_findings.append(_belief_entry)
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
                                continue
                    except Exception:
                        logger.exception("auto-verify failed — proceeding with report_finding")

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
                            base_key = path.split("?", 1)[0].rstrip("/")
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
                if _pending_findings and name != "report_finding":
                    try:
                        from vxis.agent.tools.finding_tools import _get_findings as _fget
                        reported_components = {
                            (f["finding_type"].lower(), f["affected_component"])
                            for f in _fget()
                        }
                    except Exception:
                        reported_components = set()
                    still_pending = {
                        k: v for k, v in _pending_findings.items()
                        if k not in reported_components
                    }
                    # Only nudge if there are unreported items AND we've done
                    # at least 2 non-report actions since the last hint (avoid
                    # spam after first emission).
                    if len(still_pending) >= 2 and name in ("python_exec", "shell_exec", "http_request"):
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

                if name == "finish_scan" and result.ok:
                    self.state.completed = True
                    break
            # Sample messages[] byte size at the end of each iteration.
            # Phase B fix: populates peak_context_bytes metric that was 0 in Task 11.
            self.state.update_peak_size()

            # Dual Brain critic check: every N iterations, ask a stronger
            # model to review progress and inject strategic guidance.
            # Only fires if we have made enough iterations since last check
            # AND the loop hasn't naturally completed.
            if (
                not self.state.completed
                and self.critic_interval > 0
                and self.state.iteration - self._last_critic_iter >= self.critic_interval
                and self.state.iteration < self.state.max_iters - 2
            ):
                self._last_critic_iter = self.state.iteration
                try:
                    critique = await self._critic_review()
                except Exception:
                    logger.exception("critic_review raised")
                    critique = None
                if critique:
                    self.state.add_message(
                        "user",
                        (
                            "CRITIC REVIEW (strategic guidance from the senior "
                            f"strategist, iter {self.state.iteration}):\n\n{critique}\n\n"
                            "Incorporate this guidance in your next action."
                        ),
                    )
                    logger.info(
                        "iter %d: critic review injected (%d chars)",
                        self.state.iteration, len(critique),
                    )
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
        }
