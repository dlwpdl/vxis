from __future__ import annotations

import json
import logging
from typing import Any

from vxis.agent.scan_loop_policy import _DESKTOP_SKILLS

logger = logging.getLogger(__name__)


class ScanLoopRunFollowupMixin:
    def _maybe_inject_chain_nudge(self) -> None:
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
                    f'crown_jewel="<admin takeover | DB dump | RCE | data exfil>", '
                    'evidence_artifact={'
                    '"source_output":"<credential/token/endpoint/object id from source>", '
                    '"pivot_action":"<how that output was replayed into target>", '
                    '"control_result":"<baseline/control response>", '
                    '"observed_result":"<target response proving impact>", '
                    '"crown_jewel_evidence":"<admin/data/session/RCE evidence>", '
                    '"source_output_used_in_pivot":true})\n\n'
                    "For EACH chain:\n"
                    "  1. TRY IT — use tools to prove the chain works.\n"
                    "  2. Call link_chain with finding IDs + VerifiedChainArtifact.\n"
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


    def _maybe_queue_skill_sweep(
        self,
        *,
        target_kind_cls: Any,
        real_skills_completed: set[str],
        auth_token: str | None,
        queue_skill: Any,
    ) -> None:
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
                    if self._target_kind == target_kind_cls.DESKTOP:
                        _eligible = _all_registered & _DESKTOP_SKILLS
                    else:
                        _eligible = _all_registered - _DESKTOP_SKILLS
                    _untried = sorted(
                        sk for sk in (_eligible - real_skills_completed)
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
                            "test_idor": {"url_pattern": f"{_base}/api/users/{{id}}", "token": auth_token or "", "max_id": 30 if auth_token else 20},
                            "post_auth_enum": {"token": auth_token or ""},
                            "test_auth_deep": {"token": auth_token},
                            "test_csrf": {"token": auth_token},
                            "test_api_security": {"token": auth_token},
                            "test_business_logic": {"token": auth_token},
                        }
                        _queued = 0
                        for sk in _untried:
                            params = dict(_defaults.get(sk, {}))
                            params["_skill_override"] = sk
                            _alias = f"{sk}__sweep{self.state.iteration}"
                            if queue_skill(sk, self.state.iteration + 1, params, alias=_alias):
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


    async def _maybe_execute_director_action(
        self,
        *,
        call_counts: dict[str, int],
    ) -> None:
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
                    d_key = f"{d_name}::{json.dumps(d_args, sort_keys=True, default=str)}"
                except Exception:
                    d_key = f"{d_name}::{d_args!r}"
                d_count = call_counts.get(d_key, 0)
                if d_count >= 3:
                    logger.warning("iter %d: director dedup-blocked %s", self.state.iteration, d_name)
                else:
                    call_counts[d_key] = d_count + 1
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
