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
You are the STRATEGIC DIRECTOR of a pentesting scan. The executor agent
(a weaker model) is stuck repeating the same actions. YOUR job: decide
the EXACT next tool call the executor should make.

Output ONLY a JSON object — no prose, no explanation:
{{"tool": "<tool_name>", "args": {{...}}}}

MANDATORY PRIORITY ORDER — pick the FIRST that applies:
1. If "SQLi" is NOT TESTED → shell_exec sqlmap on the target
2. If "CVE scan" is NOT TESTED → shell_exec nuclei
3. If "XSS" is NOT TESTED → browser_eval_js with XSS payload
4. If "IDOR" is NOT TESTED → http_request to /api/Users/2
5. If "Auth bypass" is NOT TESTED → browser_fill_form with SQLi creds
6. Otherwise → shell_exec with a custom recon command

Available tools: fingerprint_target, browser_navigate, browser_analyze_dom,
browser_fill_form, browser_click, browser_eval_js, browser_get_cookies,
browser_screenshot, shell_exec, python_exec, http_request, load_playbook,
report_finding, query_findings, link_chain, think, finish_scan.

shell_exec runs inside Docker with: sqlmap, nuclei, ffuf, nmap, curl.
Nuclei templates: /root/nuclei-templates/http/{{cves,exposures,default-logins,misconfiguration}}/
Wordlist: /usr/share/dirb/wordlists/common.txt

TARGET: {target}
ITERATION: {iteration}/{max_iters}
FINDINGS: {finding_count}

ATTACK VECTOR STATUS:
{vector_status}

RECENT ACTIONS (last 10):
{recent_actions}

CURRENT FINDINGS:
{findings_list}

EXACT ARG FORMATS (copy these):

shell_exec:
  {{"tool":"shell_exec","args":{{"command":"sqlmap -u 'http://TARGET/endpoint?q=1' --batch --level=2 --risk=2","timeout":120}}}}
  {{"tool":"shell_exec","args":{{"command":"nuclei -u http://TARGET -t /root/nuclei-templates/http/cves/ -silent -nc","timeout":60}}}}

browser_fill_form (login with SQLi):
  {{"tool":"browser_fill_form","args":{{"form_selector":"form","fields":{{"email":"' OR 1=1--","password":"x"}},"submit_selector":"#loginButton"}}}}

browser_eval_js:
  {{"tool":"browser_eval_js","args":{{"expression":"JSON.stringify({{localStorage: Object.keys(localStorage), cookies: document.cookie}})"}}}}

http_request (IDOR test):
  {{"tool":"http_request","args":{{"url":"http://TARGET/api/Users/2","method":"GET"}}}}

python_exec (custom fuzzer):
  {{"tool":"python_exec","args":{{"code":"import httpx\\nwith httpx.Client(verify=False) as c:\\n    for i in range(1,10):\\n        r=c.get('http://TARGET/api/Users/'+str(i))\\n        print(r.status_code, len(r.content), '/api/Users/'+str(i))"}}}}

Replace TARGET with the actual target URL. Pick ONE action."""


class ScanAgentLoop:
    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        max_iters: int = 300,
        brain: Any | None = None,
        critic_interval: int = 6,
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

        lines: list[str] = [f"═══ SCAN DASHBOARD (iter {s.iteration}) ═══"]

        # Findings
        if reported:
            lines.append(f"Findings ({len(reported)}):")
            for f in reported[-5:]:
                lines.append(f"  [{f.get('severity','?').upper()}] {f.get('title','?')[:60]}")
        else:
            lines.append("Findings: 0")

        # Attack vector checklist
        lines.append("Attack vectors:")
        for name, status in tested_vectors.items():
            lines.append(f"  {status} {name}")

        # Endpoints
        if endpoints_seen:
            lines.append(f"Known endpoints: {', '.join(sorted(endpoints_seen)[:8])}")

        # Current goal
        if untested:
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
        elif reported:
            lines.append("\n>> All vectors tested. Deepen: exploit confirmed findings further or finish_scan.")
        else:
            lines.append("\n>> No findings yet. Be more aggressive.")

        lines.append("═══ Pick a NEW action you haven't tried. Do NOT repeat previous calls. ═══")
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
        # Phase C auto-orchestration flags — code does what Brain should
        _auto_browser_done = False
        _auto_nuclei_done = False
        _auto_login_done = False
        _tools_used: set[str] = set()

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
                    nudge = (
                        f"BLOCKED: {name} with same args was already called "
                        f"{count - 1} times. You MUST use a DIFFERENT tool now. "
                        f"Look at the dashboard — find a 'NOT TESTED' attack "
                        f"vector and test it. Options:\n"
                        f"  shell_exec: sqlmap, nuclei, ffuf, nmap\n"
                        f"  browser_fill_form: try login with payloads\n"
                        f"  browser_eval_js: check tokens, test XSS\n"
                        f"  python_exec: custom HTTP fuzzing script\n"
                        f"  think: reason about what you've learned so far"
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
                            import httpx as _httpx
                            async with _httpx.AsyncClient(timeout=5, verify=False, follow_redirects=True) as _c:
                                _resp = await _c.get(component)
                                _enriched = (
                                    f"HTTP/{_resp.http_version} {_resp.status_code}\n"
                                    + "\n".join(f"{k}: {v}" for k, v in list(_resp.headers.items())[:15])
                                    + f"\n\n{_resp.text[:1500]}"
                                )
                                args["evidence"] = _enriched + "\n\n--- Original evidence ---\n" + evidence
                                logger.info("auto-enriched evidence for %s (%d → %d chars)",
                                           component, len(evidence), len(args["evidence"]))
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
                    if result.ok:
                        self.state.completed = True
                        break
            # Track which tools Brain actually called this iteration
            for name, _ in actions:
                _tools_used.add(name)

            # Sample messages[] byte size at the end of each iteration.
            # Phase B fix: populates peak_context_bytes metric that was 0 in Task 11.
            self.state.update_peak_size()

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
                        if not has_password:
                            # Try navigating to common login paths
                            for login_path in ["/#/login", "/login", "/auth/login"]:
                                login_url = self.state.target.rstrip("/") + login_path
                                lr = await self.registry.dispatch("browser_navigate", {"url": login_url})
                                if lr.ok:
                                    lr_inputs = lr.data.get("inputs", []) if lr.data else []
                                    has_password = any(i.get("type") == "password" for i in lr_inputs)
                                    if has_password:
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

                        # Auto-login: dismiss banners, try credentials directly
                        # via Playwright page (not through fill_form tool which
                        # can't handle Angular Material / overlay dialogs).
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
                                    ]:
                                        try:
                                            await _bp.click(dismiss_sel, timeout=2000)
                                        except Exception:
                                            pass

                                    _login_creds = [
                                        ("' OR 1=1--", "x"),           # SQLi bypass
                                        ("admin@juice-sh.op", "admin123"),  # default
                                        ("admin", "admin"),
                                    ]
                                    for email, pwd in _login_creds:
                                        try:
                                            # Navigate to login each attempt
                                            await _bp.navigate(self.state.target.rstrip("/") + "/#/login")
                                            import asyncio as _aio
                                            await _aio.sleep(0.5)
                                            await _bp.fill("#email", email)
                                            await _bp.fill("#password", pwd)
                                            await _bp.click("#loginButton", timeout=5000)
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
                                                    "affected_component": self.state.target.rstrip("/") + "/#/login",
                                                    "description": finding_msg,
                                                    "evidence": evidence,
                                                })
                                                break
                                        except Exception as _le:
                                            logger.debug("auto-login attempt %s failed: %s", email, _le)
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
        }
