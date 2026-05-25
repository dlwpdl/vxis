from __future__ import annotations

import logging
from typing import Any

from vxis.agent.scan_loop_policy import _DESKTOP_SKILLS
from vxis.agent.scan_loop_run_auto import ScanLoopAutoOrchestrationMixin
from vxis.agent.scan_loop_run_followups import ScanLoopRunFollowupMixin
from vxis.agent.scan_loop_run_skills import ScanLoopScheduledSkillsMixin

logger = logging.getLogger(__name__)


class ScanLoopRunMixin(
    ScanLoopAutoOrchestrationMixin, ScanLoopRunFollowupMixin, ScanLoopScheduledSkillsMixin
):
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
        self.state.add_message(
            "user",
            (
                f"Target: {self.state.target}\n\n"
                "You are a senior penetration tester. Find as many vulnerabilities as possible. "
                "The more you find, the better. If there's even the slightest hint of a weakness, "
                "dig into it — fuzz it, chain it, escalate it until you hit a dead end. "
                "Use ALL your knowledge: OWASP Top 10, business logic flaws, auth bypasses, "
                "injection variants, misconfigurations, everything. "
                "Then chain your findings into attack paths that reach crown jewels "
                "(admin takeover, DB dump, RCE, data exfil). "
                "DO NOT stop early. DO NOT be satisfied with surface-level findings."
            ),
        )
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

        def _queue_skill(
            skill_name: str,
            trigger_iter: int,
            params: dict[str, Any] | None = None,
            *,
            alias: str | None = None,
        ) -> bool:
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

                self.state.messages = await compress_history(self.state.messages, self.brain)
            except Exception:
                pass  # compression is best-effort
            if _priority_action_lane is not None:
                self.state.add_message(
                    "system",
                    {
                        "hint": (
                            f"PRIORITY ACTION LANE: execute {_priority_action_lane[0]} next "
                            f"because the judge escalated this path: {_priority_action_lane[2]}"
                        ),
                    },
                )
                actions = [(_priority_action_lane[0], dict(_priority_action_lane[1]))]
                _priority_action_lane = None
            else:
                actions = await self._decide(self.state)
            if not actions:
                _consecutive_empty += 1
                _min_iters = min(50, self.state.max_iters // 2)
                if self.state.iteration < _min_iters and _consecutive_empty <= 2:
                    self.state.add_message(
                        "user",
                        (
                            f"SYSTEM: You returned no actions at iteration "
                            f"{self.state.iteration}. Minimum {_min_iters} required. "
                            "You MUST keep scanning. Here are concrete next actions:\n"
                            f'1. browser_navigate(url="{self.state.target}/#/login") '
                            "then browser_fill_form with default creds\n"
                            f'2. shell_exec(command="curl -s {self.state.target}/rest/products/search?q=test")\n'
                            '3. load_playbook(name="injection_vectors") if not loaded\n'
                            f"4. python_exec with httpx to test /api/Users, /api/Challenges, /api/SecurityQuestions"
                        ),
                    )
                    logger.warning(
                        "iter %d: no actions but below min=%d (empty=%d) — nudge",
                        self.state.iteration,
                        _min_iters,
                        _consecutive_empty,
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
                    _action_branch_ids = self._fallback_branch_ids_for_candidates(
                        _action_candidate_ids
                    )
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
                    self.state.add_message(
                        "system",
                        {
                            "hint": (
                                "MEMORY PRIORITY HINT: this target has prior confirmed leads or unfinished branches. "
                                "Revalidate one carry-over memory branch or memory-seeded candidate first, then explore new surface."
                            ),
                        },
                    )
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
                        f"Focus branch {_focus_branch.id} [{_focus_branch.title}] "
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
                        self.state.add_message(
                            "tool",
                            {
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
                            },
                        )
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
                    self.state.add_message(
                        "tool",
                        {
                            "name": name,
                            "args": args,
                            "result": {
                                "ok": False,
                                "summary": nudge,
                                "data": {"dedup": True, "prior_calls": count - 1},
                            },
                        },
                    )
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
                        self.state.iteration,
                        name,
                        count,
                    )
                    self._emit_control_plane(f"Blocked repeated call: {name}")
                    continue

                # Phase C: egress filter — block shell/python/http commands
                # that reference off-allowlist hosts when strict mode is on.
                if _egress_strict and name in (
                    "shell_exec",
                    "python_exec",
                    "http_request",
                    "http_get",
                    "http_post",
                ):
                    blob = ""
                    if isinstance(args, dict):
                        blob = " ".join(str(v) for v in args.values() if v)
                    violations = check_violations(blob, _egress_allowlist)
                    if violations:
                        self.state.add_message(
                            "tool",
                            {
                                "name": name,
                                "args": args,
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
                            },
                        )
                        logger.warning(
                            "iter %d: egress-blocked %s (violations=%s)",
                            self.state.iteration,
                            name,
                            violations,
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
                        self._emit_control_plane(
                            f"Egress blocked for {name}: {', '.join(violations)}"
                        )
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
                                args["evidence"] = (
                                    _enriched + "\n\n--- Original evidence ---\n" + evidence
                                )
                                logger.info(
                                    "auto-enriched evidence for %s (%d → %d chars)",
                                    component,
                                    len(evidence),
                                    len(args["evidence"]),
                                )
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
                            reasoning = (
                                str(verdict_data.get("reasoning", ""))
                                or f"Verifier returned {verdict}."
                            )
                            confidence = str(verdict_data.get("confidence", "low"))
                            # Phase C belief state: track verdict counts
                            self.state.verdict_counts[verdict] = (
                                self.state.verdict_counts.get(verdict, 0) + 1
                            )
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
                            self.state.add_message(
                                "tool",
                                {
                                    "name": "verify_finding",
                                    "args": verify_args,
                                    "result": {
                                        "ok": True,
                                        "summary": verdict_result.summary,
                                        "data": verdict_data,
                                    },
                                },
                            )
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
                                self.state.add_message(
                                    "tool",
                                    {
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
                                    },
                                )
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
                        self.state.add_message(
                            "tool",
                            {
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
                            },
                        )
                        self._emit_control_plane(
                            "Memory suppressed a previously refuted finding pattern"
                        )
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
                        self.state.add_message(
                            "tool",
                            {
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
                            },
                        )
                        self.state.add_message(
                            "system",
                            {
                                "hint": (
                                    f"SYSTEM HINT: target is a macOS .app bundle (file://). "
                                    f"Web skill '{_requested_skill}' cannot apply. "
                                    f"Pick a desktop skill: {', '.join(sorted(_DESKTOP_SKILLS - _real_skills_completed))}"
                                ),
                            },
                        )
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
                        self.state.add_message(
                            "tool",
                            {
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
                            },
                        )
                        self.state.record_review_decision(
                            stage="memory",
                            verdict="SUPPRESSED",
                            title=str(
                                _memory_refuted_action.get("title")
                                or _memory_refuted_action.get("finding_type")
                                or name
                            ),
                            reason=str(
                                _memory_refuted_action.get("reasoning", "")
                                or "Repeated refuted pattern."
                            ),
                            blocked_action=name,
                            affected_component=str(
                                _memory_refuted_action.get("affected_component", "")
                            ),
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
                    self.state.add_message(
                        "system",
                        {
                            "hint": (
                                f"MEMORY TACTIC HINT: prior scan confirmed "
                                f"{_memory_success.get('finding_type', 'this tactic')} on "
                                f"{_memory_success.get('affected_component', 'this surface')}. "
                                f"Revalidate quickly with fresh transcript, then go deeper than before."
                            ),
                        },
                    )

                if name == "finish_scan":
                    _recent_finish_rejections = self._recent_finish_rejections(limit=3)
                    if len(_recent_finish_rejections) >= 2:
                        _latest_titles = {item.title for item in _recent_finish_rejections[-2:]}
                        _latest_title = next(iter(_latest_titles)) if _latest_titles else ""
                        if len(_latest_titles) == 1 and _latest_title in {
                            "needs_chains",
                            "unfinished_branches",
                            "unattempted_candidates",
                        }:
                            _chain_candidates = self._suggest_chain_candidates(limit=3)
                            _auto_linked = await self._maybe_auto_link_suggested_chain()
                            _forced_action = self._forced_replan_action(_latest_title)
                            _replan_hint = self._judge_replan_hint()
                            _candidate_text = ""
                            _auto_link_text = ""
                            _forced_text = ""
                            if _auto_linked is not None:
                                _auto_link_text = (
                                    f" Auto-linked {_auto_linked['source_id']} -> {_auto_linked['target_id']} "
                                    f"toward {_auto_linked['crown_jewel']}."
                                )
                            if _forced_action is not None:
                                _forced_text = f" Forced next action: {_forced_action[0]} ({_forced_action[2]})."
                            if _chain_candidates:
                                _candidate_lines = [
                                    f"{item['source_id']} -> {item['target_id']} ({item['crown_jewel']})"
                                    for item in _chain_candidates
                                ]
                                _candidate_text = (
                                    " Suggested chain candidates: "
                                    + "; ".join(_candidate_lines)
                                    + "."
                                )
                            _replan_msg = (
                                "JUDGE REPLAN REQUIRED: finish_scan was rejected repeatedly for the same reason. "
                                f"Last rejection: {_latest_title}.{_auto_link_text}{_forced_text} {_replan_hint}{_candidate_text}"
                            )
                            self.state.add_message(
                                "tool",
                                {
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
                                            }
                                            if _forced_action is not None
                                            else None,
                                        },
                                    },
                                },
                            )
                            self.state.add_message(
                                "system",
                                {
                                    "hint": f"SYSTEM HINT: {_replan_hint}",
                                },
                            )
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
                self.state.add_message(
                    "tool",
                    {
                        "name": name,
                        "args": args,
                        "result": {
                            "ok": result.ok,
                            "summary": result.summary,
                            "data": result.data,
                        },
                    },
                )
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
                self._sync_agent_graph_result_to_branches(name=name, args=args, result=result)
                if name == "agent_graph":
                    await self._credit_agent_graph_child_execution(
                        result,
                        skills_completed=_skills_completed,
                        real_skills_completed=_real_skills_completed,
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
                if name == "run_skill" and result.ok and isinstance(args, dict):
                    _real_sk = str(args.get("skill") or "").strip()
                    if _real_sk:
                        _real_skills_completed.add(_real_sk)
                        _skills_completed.add(_real_sk)
                        if isinstance(result.data, dict):
                            await self._promote_direct_run_skill_result(_real_sk, result.data)
                        _has_findings = bool(
                            isinstance(result.data, dict) and (result.data.get("findings") or [])
                        )
                        _promote_alias = f"promote::{_real_sk}::iter{self.state.iteration}"
                        if _has_findings and _promote_alias not in _skill_promotion_replays:
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
                            elif code_i == 403 and any(
                                x in lower for x in (".bak", ".old", ".backup", "~")
                            ):
                                findings_hint.append(
                                    f"  - {code} {size}B {norm_path} → backup file accessible via bypass = info disclosure (severity=medium, finding_type=information_disclosure)"
                                )
                            elif (
                                code_i == 200
                                and "/ftp" in lower
                                and _baseline_size
                                and size != _baseline_size
                            ):
                                # FTP directory — Juice Shop classic
                                findings_hint.append(
                                    f"  - {code} {size}B {norm_path} → directory listing exposed (size differs from shell {_baseline_size}) (severity=medium, finding_type=information_disclosure)"
                                )
                            elif (
                                code_i == 200
                                and _baseline_size is not None
                                and size != _baseline_size
                                and size > 100
                            ):
                                sensitive = any(
                                    x in lower
                                    for x in (
                                        "admin",
                                        "config",
                                        "api-doc",
                                        "swagger",
                                        "graphql",
                                        ".git",
                                        ".env",
                                        "actuator",
                                        "debug",
                                        "backup",
                                        "rest/admin",
                                        "rest/user",
                                        "rest/basket",
                                        "rest/order",
                                        "rest/memories",
                                        "rest/captcha",
                                        "rest/languages",
                                        "registration",
                                        "h2-console",
                                        "server-status",
                                        "phpinfo",
                                        "wp-config",
                                        "wp-login",
                                        "wp-admin",
                                        "phpmyadmin",
                                        "heapdump",
                                        "beans",
                                        "configprops",
                                    )
                                )
                                if sensitive:
                                    # Critical-level paths get HIGH, others MEDIUM
                                    critical_markers = (
                                        "admin",
                                        "config",
                                        ".git",
                                        ".env",
                                        "actuator",
                                        "heapdump",
                                        "phpinfo",
                                        "wp-config",
                                        "h2-console",
                                    )
                                    sev = (
                                        "high"
                                        if any(x in lower for x in critical_markers)
                                        else "medium"
                                    )
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
                                self.state.iteration,
                                len(findings_hint),
                            )

                # Sticky hint re-injection: after any tool call, check which
                # pending findings are still NOT in the finding_tools store.
                # If there are still >= 2 unreported items, re-emit a condensed
                # nudge. This catches the case where Brain reports 2 items and
                # wanders off without finishing the list.
                if (
                    _pending_findings
                    and name != "report_finding"
                    and _sticky_last_iter < self.state.iteration
                ):
                    try:
                        from vxis.agent.tools.finding_tools import _get_findings as _fget

                        reported_components = {
                            (f["finding_type"].lower(), f["affected_component"]) for f in _fget()
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
                    if len(still_pending) >= 2 and name in (
                        "python_exec",
                        "shell_exec",
                        "http_request",
                    ):
                        _sticky_last_iter = self.state.iteration
                        nudge_lines = list(still_pending.values())[:6]
                        nudge_msg = (
                            "STICKY HINT REMINDER — you still have "
                            f"{len(still_pending)} unreported findings from the earlier "
                            "probe. Emit report_finding for each of these BEFORE any "
                            "more probing:\n" + "\n".join(nudge_lines)
                        )
                        self.state.add_message("user", nudge_msg)
                        logger.info(
                            "iter %d: sticky re-injection, %d pending",
                            self.state.iteration,
                            len(still_pending),
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
                            self.state.iteration,
                            _min_iters,
                        )
                        continue

                    # Reject finish if findings exist but insufficient chains
                    # relative to finding count. Also surface concrete finding
                    # IDs + a ready-to-call link_chain template so Brain has
                    # no excuse to spin aimlessly.
                    try:
                        from vxis.agent.tools.finding_tools import (
                            _get_findings as _gf2,
                            _get_chains as _gc2,
                        )

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
                                    '  - run_skill(skill="<one of the registered skills>")\n'
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
                            _sev_order = {
                                "critical": 0,
                                "high": 1,
                                "medium": 2,
                                "low": 3,
                                "informational": 4,
                            }
                            _sorted = sorted(
                                _fin_findings,
                                key=lambda f: _sev_order.get(f.get("severity", "low"), 5),
                            )
                            # Take the top 4 and propose pairwise chains.
                            _top = [f["id"] for f in _sorted[:4]]
                            _existing_ids_in_chains = {
                                tuple(sorted(c.get("finding_ids", []))) for c in _fin_chains
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
                            _sug_block = (
                                "\n  ".join(_suggestions) or "(build any chain you can imagine)"
                            )
                            _findings_block = "\n  ".join(
                                f"{f['id']} [{f.get('severity', '?').upper()}] {f.get('finding_type', '')}: {f.get('title', '')[:60]}"
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
                                self.state.iteration,
                                len(_fin_chains),
                                _fin_desired,
                                len(_fin_findings),
                            )
                            continue
                        _blocking_branches = self._blocking_finish_branches()
                        if (
                            _blocking_branches
                            and self.state.iteration
                            < self._finish_branch_guard_until(self.state.max_iters)
                        ):
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
                                    "unfinished_branches": [
                                        b.to_dict() for b in _blocking_branches[:6]
                                    ],
                                },
                            )
                            logger.warning(
                                "iter %d: finish_scan rejected (%d blocking branches)",
                                self.state.iteration,
                                len(_blocking_branches),
                            )
                            continue
                        if self.state.max_iters >= 30:
                            _open_candidates = self._remaining_high_yield_family_candidates(
                                _fin_findings
                            )
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

            _auth_token = await self._run_scheduled_skills(
                target_kind_cls=_TK,
                skill_sequence=_skill_sequence,
                skills_completed=_skills_completed,
                real_skills_completed=_real_skills_completed,
                queue_skill=_queue_skill,
                auth_token=_auth_token,
            )

            (
                _auto_browser_done,
                _auto_login_done,
                _auto_nuclei_done,
            ) = await self._run_auto_orchestration(
                auto_browser_done=_auto_browser_done,
                auto_login_done=_auto_login_done,
                auto_nuclei_done=_auto_nuclei_done,
                baseline_size=_baseline_size,
                sandbox_invocations=_sandbox_invocations,
            )

            self._maybe_inject_chain_nudge()
            self._maybe_queue_skill_sweep(
                target_kind_cls=_TK,
                real_skills_completed=_real_skills_completed,
                auth_token=_auth_token,
                queue_skill=_queue_skill,
            )
            await self._maybe_execute_director_action(call_counts=_call_counts)

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
