"""Skill runner tool — reusable attack template wrapper.

run_skill is an OPTIONAL convenience layer over frequently-reused attack
patterns (SQLi sweep, IDOR probe, sensitive files enum, etc.). Brain's
PRIMARY attack surface is shell_exec + python_exec inside the vxis-sandbox
(sqlmap, nuclei, ffuf, nikto, custom Python PoCs — unlimited creativity).

Use run_skill when evidence points to a pattern already coded as a skill
and the shortcut beats hand-rolling. Use shell_exec / python_exec when the
target needs bespoke technique, chain pivot, or post-exploitation beyond
any pre-built skill. Do NOT default to run_skill because it's shorter —
default to evidence.
"""
from __future__ import annotations
import json
import logging
from typing import Any

from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)

# Per-(skill, args) result cache. When Brain re-runs an identical call, we
# return the cached result plus a nudge that prompts it to vary the args.
# This kills pathological loops (e.g. test_idor with the same pattern 16x)
# without relying solely on the scan-loop dedup gate.
#
# Escalation policy (Brain-First: if Brain ignores nudges, ESCALATE):
#   hit #1  → cached result + "CHANGE ARGS" nudge (soft)
#   hit #2  → cached result + list of UNTRIED skills  (stronger)
#   hit #3+ → ok=False, error="stuck_loop" — force Brain to pick another skill
_skill_cache: dict[str, dict[str, Any]] = {}

# Track every skill ever called (any args) so we can tell Brain what it
# has NOT tried yet when it's stuck. Separate from _skill_cache because
# we care about skill diversity, not args identity.
_skills_ever_called: set[str] = set()


def _reset_cache_for_tests() -> None:
    """Clear the skill cache — production code should not call this."""
    _skill_cache.clear()
    _skills_ever_called.clear()


class RunSkillTool:
    name = "run_skill"
    description = (
        "OPTIONAL convenience wrapper for reusable attack templates. "
        "PRIMARY attack tools are shell_exec + python_exec (vxis-sandbox: "
        "sqlmap, nuclei, ffuf, nikto, gobuster, wapiti, curl, httpx, nmap, "
        "plus custom Python). Reach for run_skill only when evidence points "
        "to a pattern already coded below; otherwise pick the sandbox tool "
        "that fits the hypothesis.\n\n"
        "Reusable skill templates (shortcuts for recurring patterns):\n"
        "  enumerate_endpoints — scan 120+ paths, return all accessible endpoints\n"
        "  test_injection — SQLi/XSS/SSTI/CMDi rotation on URL+param\n"
        "  attempt_auth — default creds + SQLi bypass + password reset\n"
        "  post_auth_enum — with token, test all authenticated endpoints\n"
        "  test_sensitive_files — scan 60+ sensitive file/config paths\n"
        "  test_idor — iterate IDs on an endpoint, detect access control issues\n"
        "  test_xss — XSS (reflected/stored/DOM) rotation on URL+param\n"
        "  test_auth_deep — JWT alg:none, RS256->HS256, session fixation, reset poisoning\n"
        "  test_csrf — CSRF token validation + SameSite cookie checks\n"
        "  test_ssrf — SSRF: internal IPs, cloud metadata, file://, DNS rebinding\n"
        "  test_api_security — mass assignment, rate limiting, verb tampering\n"
        "  test_misconfig — security headers, CORS, debug endpoints, verbose errors\n"
        "  test_business_logic — negative qty, price manipulation, state skip, race conditions\n"
        "  test_crypto — TLS versions, hardcoded secrets in JS, weak hashes\n"
        "  test_infra — exposed .git/.env, cloud metadata, Firebase, subdomains\n"
        "\nIf the evidence demands a technique outside these templates, go to "
        "shell_exec / python_exec — do not bend the finding to fit a skill."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "skill": {
                "type": "string",
                "description": "Skill name: enumerate_endpoints, test_injection, attempt_auth, post_auth_enum, test_sensitive_files, test_idor, test_xss, test_auth_deep, test_csrf, test_ssrf, test_api_security, test_misconfig, test_business_logic, test_crypto, test_infra",
            },
            "target_url": {
                "type": "string",
                "description": "Target URL (e.g. http://localhost:3000)",
            },
            "params": {
                "type": "object",
                "description": "Additional parameters for the skill (e.g. token, param_name, url_pattern)",
            },
        },
        "required": ["skill", "target_url"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        skill_name = str(kwargs.get("skill", "")).strip()
        target_url = str(kwargs.get("target_url", "")).strip()
        params = kwargs.get("params", {}) or {}

        if not skill_name or not target_url:
            return ToolResult(
                ok=False,
                summary="run_skill: skill and target_url required",
                error="missing_args",
            )

        try:
            from vxis.agent.skills import SKILL_REGISTRY
        except ImportError as e:
            return ToolResult(ok=False, summary=f"run_skill: import error: {e}", error=str(e))

        if skill_name not in SKILL_REGISTRY:
            available = ", ".join(SKILL_REGISTRY.keys())
            return ToolResult(
                ok=False,
                summary=f"run_skill: unknown skill '{skill_name}'. Available: {available}",
                error="unknown_skill",
            )

        # Cache hit detection — normalize args so cosmetic differences
        # (key order, default-vs-explicit) still collide.
        try:
            _cache_key = json.dumps(
                {"s": skill_name, "t": target_url, "p": params},
                sort_keys=True, default=str,
            )
        except Exception:
            _cache_key = f"{skill_name}:{target_url}:{params!r}"

        _cached = _skill_cache.get(_cache_key)
        if _cached is not None:
            _cached["hits"] = _cached.get("hits", 1) + 1
            _hits = _cached["hits"]

            # Compute untried-skill hint for hits >= 2
            _untried = sorted(SKILL_REGISTRY.keys() - _skills_ever_called)

            if _hits >= 3:
                # Hard block — Brain has ignored 2 soft nudges. Refuse the
                # call entirely. This forces the Brain-First loop: pivot or
                # finish_scan (which itself is gated by chain requirements).
                _block_msg = (
                    f"run_skill BLOCKED — you've called '{skill_name}' with IDENTICAL args "
                    f"{_hits} times. STOP REPEATING. "
                )
                if _untried:
                    _block_msg += f"UNTRIED SKILLS you have not even invoked once: {', '.join(_untried[:8])}. Pick one. "
                _block_msg += (
                    "Or if the whole surface is exhausted, switch to browser-based "
                    "manual probing (browser_navigate + browser_fill_form with novel inputs). "
                    "DO NOT call this same skill with these same args again."
                )
                logger.warning(
                    "run_skill BLOCKED: skill=%s hits=%d — forcing pivot",
                    skill_name, _hits,
                )
                return ToolResult(
                    ok=False,
                    data={"blocked": True, "hits": _hits, "untried": _untried[:8]},
                    summary=_block_msg,
                    error="stuck_loop",
                )
            elif _hits == 2:
                # Escalated nudge — list concrete alternatives
                _hint = (
                    f"[CACHED — hit #{_hits}] You already ran this EXACT call. "
                    f"Next repeat will be BLOCKED. "
                )
                if _untried:
                    _hint += f"UNTRIED skills: {', '.join(_untried[:6])}. "
                _hint += "Pick one NOW or change args significantly."
            else:
                # First repeat — soft nudge
                _hint = (
                    f"[CACHED — hit #{_hits}] This exact skill call has "
                    f"already been run. Cached result returned without re-execution. "
                    f"CHANGE ARGS to probe something new — e.g. different url_pattern, "
                    f"different param, different token, or pick another skill."
                )
            logger.info(
                "run_skill cache hit: skill=%s hits=%d — returning cached + nudge",
                skill_name, _hits,
            )
            return ToolResult(
                ok=True,
                data=_cached["data"],
                summary=f"{_cached['summary']} || {_hint}",
            )

        # Record that this skill has been attempted (fresh args) so the
        # "untried skills" list stays accurate across retries.
        _skills_ever_called.add(skill_name)

        skill = SKILL_REGISTRY[skill_name]
        fn = skill["fn"]

        try:
            # Execute the skill
            # For skills that take url= (test_injection, test_xss, test_ssrf):
            # if params already contains 'url', use it instead of target_url
            # to avoid "got multiple values for keyword argument 'url'"
            if skill_name == "test_idor":
                # test_idor uses url_pattern, not target_url
                result = await fn(
                    url_pattern=params.get("url_pattern", target_url + "/api/Users/{id}"),
                    token=params.get("token"),
                    **{k: v for k, v in params.items() if k not in ("url_pattern", "token")},
                )
            elif skill_name in ("post_auth_enum",):
                result = await fn(target_url=target_url, token=params.get("token", ""), **{k: v for k, v in params.items() if k != "token"})
            elif skill_name in ("test_injection", "test_xss", "test_ssrf"):
                # These use url= as first positional arg
                effective_url = params.pop("url", target_url)
                result = await fn(url=effective_url, **params)
            elif skill_name in ("test_auth_deep", "test_csrf", "test_api_security", "test_business_logic"):
                # These accept optional token
                result = await fn(target_url=target_url, token=params.get("token"), **{k: v for k, v in params.items() if k != "token"})
            else:
                result = await fn(target_url=target_url, **params)
        except Exception as e:
            logger.exception("run_skill %s failed", skill_name)
            return ToolResult(ok=False, summary=f"run_skill {skill_name}: {type(e).__name__}: {e}", error=str(e))

        # Build a compact summary
        summary_parts = [f"skill:{skill_name}"]

        if skill_name == "enumerate_endpoints":
            accessible = result.get("accessible", [])
            auth_req = result.get("auth_required", [])
            errors = result.get("errors", [])
            summary_parts.append(f"{len(accessible)} accessible, {len(auth_req)} auth-required, {len(errors)} errors")
            if accessible:
                summary_parts.append("Top: " + ", ".join(f"{e['path']}({e['size']}B)" for e in accessible[:5]))

        elif skill_name == "test_injection":
            findings = result.get("findings", [])
            summary_parts.append(f"{'VULNERABLE' if result.get('vulnerable') else 'clean'} — {len(findings)} finding(s)")
            baseline = result.get("baseline", {})
            if baseline:
                summary_parts.append(f"baseline={baseline.get('status', '?')}/{baseline.get('size', '?')}B")
            for f in findings[:3]:
                summary_parts.append(f"  {f['type']}: {f['payload'][:30]} ({f['severity']})")

        elif skill_name == "attempt_auth":
            if result.get("authenticated"):
                summary_parts.append(f"AUTHENTICATED via {result['method']}! token={result['token'][:30]}...")
                summary_parts.append(f"user: {result.get('user_info', {})}")
                controls = result.get("control_checks", {})
                if controls:
                    summary_parts.append(f"controls: neg={controls.get('negative_control', {}).get('status', '?')} pos={controls.get('positive_control', {}).get('status', '?')}")
            else:
                summary_parts.append(f"auth failed ({len(result.get('all_attempts', []))} attempts)")

        elif skill_name == "post_auth_enum":
            acc = result.get("accessible", [])
            new = result.get("new_endpoints", [])
            exposed = result.get("user_data_exposed", [])
            summary_parts.append(f"{len(acc)} accessible, {len(new)} new (auth-only), {len(exposed)} with user data")
            controls = result.get("control_evidence", {})
            if controls:
                summary_parts.append(
                    f"controls: auth_only={len(controls.get('auth_only', []))} noauth_same={len(controls.get('same_data_without_auth', []))}"
                )

        elif skill_name == "test_sensitive_files":
            exposed = result.get("exposed", [])
            summary_parts.append(f"{len(exposed)} sensitive files found")
            for e in exposed[:5]:
                summary_parts.append(f"  [{e['severity']}] {e['path']} ({e['size']}B)")

        elif skill_name == "test_idor":
            summary_parts.append(
                f"{'VULNERABLE' if result.get('vulnerable') else 'clean'} — "
                f"{len(result.get('accessible_ids', []))} accessible, "
                f"{len(result.get('auth_bypass_ids', []))} without auth"
            )
            controls = result.get("control_evidence", {})
            if controls:
                summary_parts.append(
                    f"controls: +{len(controls.get('positive_cases', []))}/-{len(controls.get('negative_cases', []))}"
                )

        elif skill_name in ("test_xss", "test_ssrf", "test_auth_deep", "test_csrf",
                             "test_api_security", "test_misconfig", "test_business_logic",
                             "test_crypto", "test_infra"):
            findings = result.get("findings", result.get("exposed", []))
            vuln = result.get("vulnerable", len(findings) > 0)
            summary_parts.append(f"{'VULNERABLE' if vuln else 'clean'} — {len(findings)} finding(s), {result.get('tested', 0)} tested")
            baseline = result.get("baseline", {})
            if baseline:
                summary_parts.append(f"baseline={baseline.get('status', '?')}/{baseline.get('size', '?')}B")
            controls = result.get("control_evidence", {})
            if controls:
                control_count = sum(len(v) for v in controls.values() if isinstance(v, list))
                if control_count:
                    summary_parts.append(f"controls={control_count}")
            for f in findings[:3]:
                ftype = f.get("type", "unknown")
                fpayload = f.get("payload", f.get("path", ""))[:40]
                fsev = f.get("severity", "medium")
                summary_parts.append(f"  {ftype}: {fpayload} ({fsev})")

        _summary = " | ".join(summary_parts)
        # Store in cache so repeat calls short-circuit without re-execution
        _skill_cache[_cache_key] = {
            "data": result,
            "summary": _summary,
            "hits": 1,
        }
        return ToolResult(
            ok=True,
            data=result,
            summary=_summary,
        )
