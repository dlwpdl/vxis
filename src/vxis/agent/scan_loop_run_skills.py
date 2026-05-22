from __future__ import annotations

import logging
from typing import Any

from vxis.agent.scan_loop_policy import _DESKTOP_SKILLS

logger = logging.getLogger(__name__)


class ScanLoopScheduledSkillsMixin:
    async def _run_scheduled_skills(
        self,
        *,
        target_kind_cls: Any,
        skill_sequence: list[tuple[str, int, dict[str, Any]]],
        skills_completed: set[str],
        real_skills_completed: set[str],
        queue_skill: Any,
        auth_token: str | None,
    ) -> str | None:
        # ── Phase E: skill auto-execution ────────────────────────────
        # Skills run on schedule. Brain sees the results and decides
        # what to report. This is the "skills for known attacks,
        # Brain for creative thinking" pattern.
        if "run_skill" in self.registry.list_tools():
            for skill_name, trigger_iter, extra_params in skill_sequence:
                if (
                    skill_name not in skills_completed
                    and self.state.iteration >= trigger_iter
                ):
                    # Phase Q: surface gate. skill_sequence is a hardcoded
                    # web recon ladder (enumerate_endpoints → test_infra →
                    # attempt_auth → ...). On desktop targets these all hit
                    # file:// and produce noise / false positives. Skip the
                    # web ladder entirely; the kind-aware sweep at L~2150
                    # surfaces the real desktop skills instead.
                    _real_skill_check = extra_params.get("_skill_override") or skill_name
                    if (
                        self._target_kind == target_kind_cls.DESKTOP
                        and _real_skill_check not in _DESKTOP_SKILLS
                    ):
                        skills_completed.add(skill_name)
                        continue
                    skills_completed.add(skill_name)
                    try:
                        params = {**extra_params}
                        # Allow a queue entry to alias an existing skill
                        # (e.g. test_idor_1 → test_idor with different
                        # url_pattern). This lets us run the same skill
                        # multiple times with distinct parameters without
                        # confusing the de-dup set.
                        _real_skill = params.pop("_skill_override", None) or skill_name
                        _real_skill, params = self._reroute_blocked_skill(_real_skill, params)
                        if not _real_skill:
                            logger.info(
                                "iter %d: auto skill queue=%s skipped after blocked-skill reroute",
                                self.state.iteration,
                                skill_name,
                            )
                            continue
                        # Track the real skill even when called via alias,
                        # so the sweep block can detect untouched skills.
                        real_skills_completed.add(_real_skill)
                        self._emit_action_progress(
                            "run_skill",
                            {"skill": _real_skill, "target_url": self.state.target},
                            "Auto skill dispatch",
                        )
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
                                    auth_token = sr.data.get("token", "")
                                    method = sr.data.get("method", "?")
                                    creds = sr.data.get("credentials_used", {})
                                    # Auto-report auth finding
                                    severity = "critical" if "sqli" in method else "high"
                                    ftype = "sql_injection" if "sqli" in method else "weak_auth"
                                    login_endpoint = sr.data.get("login_endpoint", self.state.target)
                                    control_checks = sr.data.get("control_checks", {}) or {}
                                    poc_blob = (
                                        sr.data.get("poc_http_exchange")
                                        or (
                                            f"Method: {method}\n"
                                            f"Credentials used: {creds}\n"
                                            f"Token: {auth_token[:120]}\n"
                                            f"User info: {sr.data.get('user_info', {})}\n"
                                            f"Control checks: {control_checks}"
                                        )
                                    )
                                    await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                        title=f"Authentication bypass via {method}",
                                        severity=severity,
                                        finding_type=ftype,
                                        affected_component=login_endpoint,
                                        description=f"Authentication succeeded via {method}.",
                                        impact="An unauthenticated actor can obtain a valid session or token and pivot into post-authenticated functionality.",
                                        technical_analysis=(
                                            f"The attempt_auth skill reported authenticated=True using method={method}. "
                                            f"Negative control: {control_checks.get('negative_control', {})}. "
                                            f"Positive control: {control_checks.get('positive_control', {})}. "
                                            "This indicates the login boundary can be bypassed under the observed conditions."
                                        ),
                                        poc_description="Replay the authentication flow with the same bypass technique and confirm that the application returns an authenticated token or session.",
                                        poc_script_code=poc_blob,
                                        remediation_steps="Enforce server-side authentication checks, normalize credential validation, and add regression tests for the bypass condition.",
                                        endpoint=login_endpoint,
                                        method="POST",
                                    ))
                                    # Queue post-auth skills
                                    _post_auth_skills = [
                                        ("post_auth_enum", self.state.iteration + 2, {"token": auth_token}),
                                        ("test_idor", self.state.iteration + 4, {"token": auth_token}),
                                        ("test_auth_deep", self.state.iteration + 5, {"token": auth_token}),
                                    ]
                                    for _queued_skill, _queued_iter, _queued_params in _post_auth_skills:
                                        queue_skill(_queued_skill, _queued_iter, _queued_params)
                                    self.state.add_message("user", (
                                        f"SKILL CHAIN: Auth bypass confirmed via {method}! "
                                        f"Token acquired. Post-auth skills queued."
                                    ))

                            # Auto-report sensitive files
                            if _real_skill == "test_sensitive_files" and sr.data:
                                for exposed in (sr.data.get("exposed") or [])[:10]:
                                    sev = exposed.get("severity", "medium")
                                    if sev in ("critical", "high"):
                                        exposed_path = self.state.target + exposed["path"]
                                        preview = exposed.get("preview", "")[:1000]
                                        poc_blob = self._build_simple_http_poc(
                                            url=exposed_path,
                                            status=exposed.get("status", "?"),
                                            response_preview=preview,
                                        )
                                        self.state.record_retrieval_observation(
                                            finding_type="information_disclosure",
                                            component=exposed_path,
                                            retrieval_kind="sensitive_file",
                                            summary=f"Sensitive file content retrieved from {exposed['path']}",
                                            sample=preview,
                                        )
                                        await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                            title=f"Sensitive file exposed: {exposed['path']}",
                                            severity=sev,
                                            finding_type="information_disclosure",
                                            affected_component=exposed_path,
                                            description=exposed.get("description", "") or f"Sensitive file {exposed['path']} is externally accessible.",
                                            impact="Sensitive configuration or credential material may be retrievable without authorization, enabling follow-on compromise.",
                                            technical_analysis=(
                                                f"The sensitive files skill marked {exposed['path']} as exposed and returned response content preview, "
                                                "which indicates direct unauthenticated access to non-public file content."
                                            ),
                                            poc_description="Request the exposed file path directly and verify that the server returns the file contents without an authorization challenge.",
                                            poc_script_code=poc_blob,
                                            remediation_steps="Deny public access to sensitive files, remove secrets from web roots, and return 403/404 for internal artifacts.",
                                            endpoint=exposed_path,
                                            method="GET",
                                            extra_evidence=[
                                                self._retrieval_evidence_item(
                                                    title="Retrieved Sensitive File Preview",
                                                    retrieval_kind="sensitive_file",
                                                    summary=f"Unauthenticated retrieval of {exposed['path']}",
                                                    sample=preview,
                                                )
                                            ],
                                        ))

                            # Auto-report injection findings
                            if _real_skill == "test_injection" and sr.data:
                                for finding in (sr.data.get("findings") or []):
                                    inj_sev = finding.get("severity", "medium")
                                    if inj_sev not in ("high", "critical"):
                                        continue
                                    inj_url = sr.data.get("url", self.state.target)
                                    inj_param = sr.data.get("param", finding.get("param", "?"))
                                    control = finding.get("control", {}) or {}
                                    payload_text = finding.get("payload", "")
                                    poc_blob = self._build_reflected_get_poc(
                                        url=inj_url,
                                        param=inj_param,
                                        payload=payload_text,
                                        control=control,
                                        response_preview=finding.get("response_preview", "")[:1200],
                                    )
                                    args = {
                                        "title": f"{finding['type'].upper()} on {inj_param}",
                                        "severity": inj_sev,
                                        "finding_type": finding["type"],
                                        "affected_component": inj_url,
                                        "description": f"Payload: {payload_text[:80]}",
                                        "evidence": finding.get("response_preview", finding.get("evidence", ""))[:500],
                                    }
                                    args.update(self._build_report_finding_args(
                                        title=args["title"],
                                        severity=inj_sev,
                                        finding_type=finding["type"],
                                        affected_component=inj_url,
                                        description=f"Injection behavior was observed on parameter {inj_param}.",
                                        impact="Successful injection may expose backend data, execute attacker-controlled logic, or cross trust boundaries depending on the sink.",
                                        technical_analysis=(
                                            f"The injection skill recorded baseline/control data {control} alongside the payload response, "
                                            "which indicates the parameter reacts differently under attacker-controlled input."
                                        ),
                                        poc_description="Replay the payload against the same parameter and compare the baseline response to the injected response or delay/output delta.",
                                        poc_script_code=poc_blob,
                                        remediation_steps="Apply sink-specific input handling such as parameterized queries, output encoding, and strict server-side validation.",
                                        endpoint=inj_url,
                                        method="GET",
                                    ))
                                    await self._dispatch_report_finding_checked(args)

                            # Auto-report enumeration results
                            if _real_skill == "enumerate_endpoints" and sr.data:
                                # Queue injection/XSS/SSRF on search/query endpoints
                                accessible = sr.data.get("accessible", [])
                                for ep in accessible:
                                    path = ep.get("path", "")
                                    if "?" in path or "search" in path.lower():
                                        full_url = self.state.target.rstrip("/") + path
                                        queue_skill("test_injection", self.state.iteration + 2, {"url": full_url})
                                        queue_skill("test_xss", self.state.iteration + 3, {"url": full_url})
                                        queue_skill("test_ssrf", self.state.iteration + 4, {"url": full_url})
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
                                            queue_skill(
                                                "test_idor",
                                                self.state.iteration + 5,
                                                {"url_pattern": pattern, "_skill_override": "test_idor"},
                                                alias=f"test_idor_{len(_idor_patterns_seen)}",
                                            )
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
                                        queue_skill(
                                            "test_idor",
                                            self.state.iteration + 5,
                                            {"url_pattern": pattern, "_skill_override": "test_idor"},
                                            alias=f"test_idor_probe_{_candidate.strip('/').replace('/','_')}",
                                        )
                                # Report error endpoints
                                for ep in (sr.data.get("errors") or [])[:5]:
                                    preview = (ep.get("error_preview", "") or "")[:300]
                                    if not self._error_oracle_preview_is_actionable(preview):
                                        continue
                                    await self._dispatch_report_finding_checked({
                                        "title": f"HTTP 500 on {ep['path']}",
                                        "severity": "medium",
                                        "finding_type": "error_oracle",
                                        "affected_component": self.state.target + ep["path"],
                                        "description": f"Endpoint returns HTTP 500 ({ep.get('size', '?')}B) with actionable backend error details.",
                                        "evidence": preview,
                                    })

                            # IDOR results
                            if _real_skill == "test_idor" and sr.data:
                                if sr.data.get("vulnerable"):
                                    ids = sr.data.get("accessible_ids", [])
                                    pattern = sr.data.get("url_pattern", "")
                                    control_evidence = sr.data.get("control_evidence", {}) or {}
                                    comparisons = sr.data.get("comparisons", []) or []
                                    exfil_sample = str(sr.data.get("data_samples", [])[:2])[:1200]
                                    self.state.record_retrieval_observation(
                                        finding_type="idor",
                                        component=pattern,
                                        retrieval_kind="unauthorized_object_access",
                                        summary=f"Accessible IDs: {ids[:10]} / auth bypass IDs: {sr.data.get('auth_bypass_ids', [])[:10]}",
                                        sample=exfil_sample,
                                    )
                                    poc_blob = (
                                        f"Accessible IDs: {ids[:10]}\n"
                                        f"Auth bypass IDs: {sr.data.get('auth_bypass_ids', [])[:10]}\n"
                                        f"Control evidence: {control_evidence}\n"
                                        f"Comparisons: {comparisons[:4]}\n"
                                        f"Samples: {sr.data.get('data_samples', [])[:2]}"
                                    )
                                    await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                        title=f"IDOR on {pattern}",
                                        severity="high",
                                        finding_type="idor",
                                        affected_component=pattern,
                                        description=f"{len(ids)} object identifier(s) were accessible outside the expected authorization boundary.",
                                        impact="Attackers may enumerate and retrieve other users' records or privileged objects without proper authorization.",
                                        technical_analysis=(
                                            f"The test_idor skill marked the pattern {pattern} as vulnerable and returned per-object comparisons. "
                                            f"Positive/negative controls: {control_evidence}. This demonstrates a broken object-level authorization check."
                                        ),
                                        poc_description="Repeat the same object access request across multiple IDs and verify that unrelated records are returned successfully.",
                                        poc_script_code=poc_blob,
                                        remediation_steps="Enforce server-side ownership and authorization checks on every object reference before returning data.",
                                        endpoint=pattern,
                                        method="GET",
                                        cwe="CWE-639",
                                        extra_evidence=[
                                            self._retrieval_evidence_item(
                                                title="Unauthorized Object Retrieval",
                                                retrieval_kind="unauthorized_object_access",
                                                summary=f"Multiple object identifiers returned data across the same pattern {pattern}.",
                                                sample=exfil_sample,
                                            ),
                                            self._exfil_evidence_item(
                                                title="Potential Bulk Data Exfiltration Path",
                                                summary="The vulnerable object pattern can be iterated across IDs to extract unrelated records.",
                                                sample=str(comparisons[:4])[:1200],
                                            ),
                                        ],
                                    ))

                            # Post-auth enum results
                            if _real_skill == "post_auth_enum" and sr.data:
                                user_data = sr.data.get("user_data_exposed", [])
                                if user_data:
                                    paths = [e["path"] for e in user_data[:5]]
                                    control_evidence = sr.data.get("control_evidence", {}) or {}
                                    user_data_sample = str(user_data[:3])[:1200]
                                    self.state.record_retrieval_observation(
                                        finding_type="broken_access_control",
                                        component=self.state.target,
                                        retrieval_kind="post_auth_data_access",
                                        summary=f"Sensitive user data observed on {len(user_data)} authenticated endpoint(s): {paths}",
                                        sample=user_data_sample,
                                    )
                                    await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                        title=f"Sensitive user data exposed on {len(user_data)} endpoint(s)",
                                        severity="high",
                                        finding_type="broken_access_control",
                                        affected_component=self.state.target,
                                        description=f"Authenticated functionality exposed sensitive user data on endpoints including: {paths}",
                                        impact="Low-privilege or bypassed access can disclose user records and enable lateral movement into other accounts.",
                                        technical_analysis=(
                                            "The post_auth_enum skill collected user-data-bearing endpoints after authentication and compared them with unauthenticated access results. "
                                            f"Control evidence: {control_evidence}."
                                        ),
                                        poc_description="Access the listed post-auth endpoints with the acquired session and confirm that user data is returned beyond the minimum necessary scope.",
                                        poc_script_code=(
                                            f"Control evidence: {control_evidence}\n"
                                            f"User data samples: {user_data_sample}"
                                        ),
                                        remediation_steps="Apply object- and field-level authorization checks on user data endpoints and minimize exposed record fields.",
                                        endpoint=self.state.target,
                                        method="GET",
                                        extra_evidence=[
                                            self._retrieval_evidence_item(
                                                title="Authenticated Data Retrieval",
                                                retrieval_kind="post_auth_data_access",
                                                summary=f"Authenticated access exposed user data on {len(user_data)} endpoint(s).",
                                                sample=user_data_sample,
                                            ),
                                            self._exfil_evidence_item(
                                                title="Post-Authentication Exfiltration Surface",
                                                summary=f"The acquired session unlocks reusable data-bearing endpoints: {paths}",
                                                sample=str(control_evidence)[:1200],
                                            ),
                                        ],
                                    ))

                            # Auto-report: XSS findings
                            if _real_skill == "test_xss" and sr.data:
                                for finding in (sr.data.get("findings") or []):
                                    xss_sev = finding.get("severity", "high")
                                    xss_url = sr.data.get("url", self.state.target)
                                    xss_param = finding.get("param", sr.data.get("param", "?"))
                                    payload = finding.get("payload", "")[:200]
                                    response_preview = finding.get("response_preview", finding.get("evidence", ""))[:1200]
                                    control = finding.get("control", {}) or {}
                                    xss_poc = self._build_reflected_get_poc(
                                        url=xss_url,
                                        param=xss_param,
                                        payload=payload,
                                        control=control,
                                        response_preview=response_preview,
                                    )
                                    args = {
                                        "title": f"XSS ({finding.get('type', 'reflected')}) on {xss_param}",
                                        "severity": xss_sev,
                                        "finding_type": f"xss_{finding.get('type', 'reflected')}",
                                        "affected_component": xss_url,
                                        "description": f"Cross-site scripting payload reflected or executed via parameter {xss_param}.",
                                        "evidence": response_preview,
                                    }
                                    if xss_sev in ("high", "critical"):
                                        args.update(self._build_report_finding_args(
                                            title=args["title"],
                                            severity=xss_sev,
                                            finding_type=args["finding_type"],
                                            affected_component=xss_url,
                                            description=args["description"],
                                            impact="An attacker may execute script in a victim browser, enabling session theft or authenticated action execution.",
                                            technical_analysis=(
                                                "The XSS skill returned a concrete payload and response evidence indicating that attacker-controlled script content was reflected or executed. "
                                                f"Baseline/control data: {control}."
                                            ),
                                            poc_description="Submit the supplied payload to the vulnerable parameter and confirm that it is reflected/executed in the response context.",
                                            poc_script_code=xss_poc,
                                            remediation_steps="Contextually encode untrusted input, apply output escaping, and deploy CSP as a secondary control.",
                                            endpoint=xss_url,
                                            method="GET",
                                            cwe="CWE-79",
                                        ))
                                    await self._dispatch_report_finding_checked(args)

                            # Payload rotation: if injection/xss/ssrf came up
                            # CLEAN at round R<3, re-queue at round R+1
                            # against the same URL. Round 2 = blind/time
                            # + filter bypass; round 3 = WAF-evasion
                            # polyglots. This prevents "one cheap classic
                            # pass, declare clean" when a WAF is in play.
                            if _real_skill in ("test_injection", "test_xss", "test_ssrf") and sr.data:
                                _cur_round = sr.data.get("round", 1)
                                if not sr.data.get("vulnerable") and _cur_round < 3:
                                    _url = sr.data.get("url")
                                    if _url:
                                        self._mark_family_probe_retryable(
                                            _real_skill,
                                            url=_url,
                                            round_num=_cur_round,
                                            tested_params=list(sr.data.get("tested_params") or []),
                                        )
                                        _next = _cur_round + 1
                                        _alias_r = (
                                            f"{_real_skill}__round{_next}_iter{self.state.iteration}"
                                        )
                                        queue_skill(
                                            _real_skill,
                                            self.state.iteration + 2,
                                            {
                                                "_skill_override": _real_skill,
                                                "url": _url,
                                                "round": _next,
                                            },
                                            alias=_alias_r,
                                        )
                                        logger.info(
                                            "payload rotation: re-queue %s round=%d on %s",
                                            _real_skill, _next, _url,
                                        )

                            # Auto-report: SSRF findings
                            if _real_skill == "test_ssrf" and sr.data:
                                for finding in (sr.data.get("findings") or []):
                                    ssrf_sev = finding.get("severity", "high")
                                    ssrf_url = sr.data.get("url", self.state.target)
                                    ssrf_param = finding.get("param", sr.data.get("param", "?"))
                                    payload = finding.get("payload", "")[:200]
                                    response_preview = finding.get("response_preview", finding.get("evidence", ""))[:1200]
                                    control = finding.get("control", {}) or {}
                                    matched_signal = str(control.get("matched_signal") or finding.get("type", "internal_response"))
                                    callback_summary = response_preview[:500] or str(finding.get("evidence", ""))[:500]
                                    self.state.record_callback_observation(
                                        finding_type="ssrf",
                                        component=ssrf_url,
                                        signal=matched_signal,
                                        payload=payload,
                                        summary=callback_summary,
                                    )
                                    ssrf_poc = self._build_reflected_get_poc(
                                        url=ssrf_url,
                                        param=ssrf_param,
                                        payload=payload,
                                        control=control,
                                        response_preview=response_preview,
                                    )
                                    args = {
                                        "title": f"SSRF via {finding.get('type', 'ssrf')} on {ssrf_param}",
                                        "severity": ssrf_sev,
                                        "finding_type": "ssrf",
                                        "affected_component": ssrf_url,
                                        "description": f"Server-side request behavior was influenced via parameter {ssrf_param}.",
                                        "evidence": response_preview,
                                    }
                                    if ssrf_sev in ("high", "critical"):
                                        args.update(self._build_report_finding_args(
                                            title=args["title"],
                                            severity=ssrf_sev,
                                            finding_type="ssrf",
                                            affected_component=ssrf_url,
                                            description=args["description"],
                                            impact="Attackers may force the server to reach internal services, cloud metadata endpoints, or trust-bound internal resources.",
                                            technical_analysis=(
                                                "The SSRF skill produced a payload and corresponding response preview suggesting server-side fetching or internal reachability. "
                                                f"Baseline/control data: {control}."
                                            ),
                                            poc_description="Submit the SSRF payload to the target parameter and confirm that the server fetches or leaks data from the supplied internal URL.",
                                            poc_script_code=ssrf_poc,
                                            remediation_steps="Restrict outbound requests, enforce URL allowlists, and block internal address spaces from user-controlled fetches.",
                                            endpoint=ssrf_url,
                                            method="GET",
                                            cwe="CWE-918",
                                            extra_evidence=[
                                                self._callback_evidence_item(
                                                    title="Callback / Internal Reachability",
                                                    signal=matched_signal,
                                                    payload=payload,
                                                    summary=callback_summary,
                                                )
                                            ],
                                        ))
                                    await self._dispatch_report_finding_checked(args)

                            # Auto-report: CSRF findings
                            if _real_skill == "test_csrf" and sr.data:
                                for finding in (sr.data.get("findings") or [])[:5]:
                                    csrf_component = self.state.target + finding.get("endpoint", "")
                                    csrf_method = finding.get("method", "POST")
                                    csrf_evidence = finding.get("evidence", "")[:1200]
                                    csrf_sev = finding.get("severity", "medium")
                                    args = {
                                        "title": f"CSRF: no protection on {csrf_method} {finding.get('endpoint', '?')}",
                                        "severity": csrf_sev,
                                        "finding_type": "csrf",
                                        "affected_component": csrf_component,
                                        "description": f"No CSRF token on {csrf_method} {finding.get('endpoint', '?')}",
                                        "evidence": csrf_evidence[:500],
                                    }
                                    if csrf_sev in ("high", "critical"):
                                        args.update(self._build_report_finding_args(
                                            title=args["title"],
                                            severity=csrf_sev,
                                            finding_type="csrf",
                                            affected_component=csrf_component,
                                            description=args["description"],
                                            impact="Victims may be forced to execute authenticated state-changing actions from an attacker-controlled origin.",
                                            technical_analysis=f"The CSRF skill observed tokenless or invalid-token acceptance: {csrf_evidence}",
                                            poc_description="Replay the state-changing request with no CSRF token and then with an invalid token; both should be rejected if protection is working.",
                                            poc_script_code=csrf_evidence,
                                            remediation_steps="Require unpredictable CSRF tokens on state-changing requests and pair them with SameSite-aware session handling.",
                                            endpoint=csrf_component,
                                            method=csrf_method,
                                            cwe="CWE-352",
                                        ))
                                    await self._dispatch_report_finding_checked(args)

                            # Auto-report: deep auth findings
                            if _real_skill == "test_auth_deep" and sr.data:
                                auth_controls = sr.data.get("control_evidence", {}) or {}
                                for finding in (sr.data.get("findings") or [])[:5]:
                                    auth_sev = finding.get("severity", "high")
                                    auth_type = finding.get("type", "weak_auth")
                                    poc_blob = (
                                        f"Payload: {finding.get('payload', '')}\n"
                                        f"Evidence: {finding.get('evidence', '')}\n"
                                        f"Control: {finding.get('control', {})}\n\n"
                                        f"{finding.get('response_preview', '')[:1200]}"
                                    )
                                    await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                        title=f"{auth_type.replace('_', ' ').title()} on authentication surface",
                                        severity=auth_sev,
                                        finding_type=auth_type,
                                        affected_component=self.state.target,
                                        description=f"Authentication weakness detected: {auth_type}.",
                                        impact="Attackers may forge tokens, fixate sessions, or poison password reset flows to obtain or retain unauthorized access.",
                                        technical_analysis=(
                                            f"The deep-auth skill returned a positive signal for {auth_type}. "
                                            f"Skill-level control evidence: {auth_controls}. Finding-level control: {finding.get('control', {})}."
                                        ),
                                        poc_description="Replay the supplied token/session/reset manipulation and compare the protected endpoint behavior against the normal authenticated baseline.",
                                        poc_script_code=poc_blob,
                                        remediation_steps="Enforce strict JWT verification, rotate sessions on privilege changes/login, and pin reset link generation to trusted host configuration.",
                                        endpoint=self.state.target,
                                        method="GET",
                                    ))

                            # Auto-report: business logic findings
                            if _real_skill == "test_business_logic" and sr.data:
                                logic_controls = sr.data.get("control_evidence", {}) or {}
                                for finding in (sr.data.get("findings") or [])[:5]:
                                    logic_sev = finding.get("severity", "high")
                                    logic_type = finding.get("type", "business_logic")
                                    poc_blob = (
                                        f"Payload: {finding.get('payload', '')}\n"
                                        f"Evidence: {finding.get('evidence', '')}\n"
                                        f"Control: {finding.get('control', {})}\n\n"
                                        f"{finding.get('response_preview', '')[:1200]}"
                                    )
                                    await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                        title=f"{logic_type.replace('_', ' ').title()} on business flow",
                                        severity=logic_sev,
                                        finding_type=logic_type,
                                        affected_component=self.state.target,
                                        description=f"Business workflow accepted an invalid or concurrency-sensitive action: {logic_type}.",
                                        impact="Attackers may manipulate state transitions, financial values, or concurrency windows to gain unauthorized business advantage.",
                                        technical_analysis=(
                                            f"The business-logic skill returned accepted vs rejected control data {logic_controls} "
                                            f"and recorded a positive case for {logic_type}: {finding.get('control', {})}."
                                        ),
                                        poc_description="Replay the supplied workflow mutation and compare it against the rejected or normal business control cases recorded by the skill.",
                                        poc_script_code=poc_blob,
                                        remediation_steps="Enforce server-side business invariants, validate state transitions, and serialize concurrency-sensitive mutations.",
                                        endpoint=self.state.target,
                                        method="POST",
                                    ))

                            # Auto-report: Misconfig findings (headers, CORS, debug)
                            if _real_skill == "test_misconfig" and sr.data:
                                for finding in (sr.data.get("findings") or [])[:5]:
                                    mis_sev = finding.get("severity", "medium")
                                    mis_type = finding.get("type", "misconfiguration")
                                    mis_desc = finding.get("description", finding.get("type", ""))[:200]
                                    mis_evidence = finding.get("evidence", finding.get("payload", ""))[:1200]
                                    args = {
                                        "title": f"Misconfiguration: {mis_type}",
                                        "severity": mis_sev,
                                        "finding_type": "misconfiguration",
                                        "affected_component": self.state.target,
                                        "description": mis_desc,
                                        "evidence": mis_evidence[:500],
                                    }
                                    if mis_sev in ("high", "critical"):
                                        args.update(self._build_report_finding_args(
                                            title=args["title"],
                                            severity=mis_sev,
                                            finding_type="misconfiguration",
                                            affected_component=self.state.target,
                                            description=mis_desc,
                                            impact="Application security posture is weakened by an externally observable misconfiguration that may enable follow-on compromise.",
                                            technical_analysis=f"The misconfiguration skill returned the following evidence: {mis_evidence}",
                                            poc_description="Request the affected resource or replay the header/origin probe and confirm that the unsafe configuration is returned consistently.",
                                            poc_script_code=mis_evidence,
                                            remediation_steps="Harden the affected configuration, remove unnecessary exposure, and add regression checks for the missing control.",
                                            endpoint=self.state.target,
                                            method="GET",
                                        ))
                                    await self._dispatch_report_finding_checked(args)

                            # Auto-report: API security findings
                            if _real_skill == "test_api_security" and sr.data:
                                for finding in (sr.data.get("findings") or [])[:5]:
                                    api_sev = finding.get("severity", "medium")
                                    api_type = finding.get("type", "api_security")
                                    api_component = self.state.target + finding.get("endpoint", "")
                                    api_desc = finding.get("description", finding.get("payload", ""))[:200]
                                    api_evidence = finding.get("evidence", "")[:1400]
                                    api_payload = finding.get("payload", "")[:300]
                                    args = {
                                        "title": f"API Security: {api_type}",
                                        "severity": api_sev,
                                        "finding_type": api_type,
                                        "affected_component": api_component,
                                        "description": api_desc,
                                        "evidence": api_evidence[:500],
                                    }
                                    if api_sev in ("high", "critical"):
                                        args.update(self._build_report_finding_args(
                                            title=args["title"],
                                            severity=api_sev,
                                            finding_type=api_type,
                                            affected_component=api_component,
                                            description=api_desc,
                                            impact="Attackers may bypass API authorization or mutate protected fields through unsafe action handling.",
                                            technical_analysis=f"The API security skill reported payload={api_payload} with evidence={api_evidence}",
                                            poc_description="Replay the documented API request variant and compare the unauthorized or over-permissive response against the expected access policy.",
                                            poc_script_code=f"Payload: {api_payload}\n\nEvidence: {api_evidence}",
                                            remediation_steps="Enforce server-side authorization and field allowlists for every action-based or object-mutating API path.",
                                            endpoint=api_component,
                                            method="POST",
                                        ))
                                    await self._dispatch_report_finding_checked(args)

                            # Auto-report: Crypto findings
                            if _real_skill == "test_crypto" and sr.data:
                                for finding in (sr.data.get("findings") or []):
                                    crypto_sev = finding.get("severity", "medium")
                                    crypto_component = self.state.target + finding.get("path", "")
                                    crypto_desc = finding.get("description", finding.get("payload", ""))[:200]
                                    crypto_evidence = finding.get("evidence", "")[:1200]
                                    args = {
                                        "title": f"Crypto weakness: {finding.get('type', 'unknown')}",
                                        "severity": crypto_sev,
                                        "finding_type": "weak_crypto",
                                        "affected_component": crypto_component,
                                        "description": crypto_desc,
                                        "evidence": crypto_evidence[:500],
                                    }
                                    if crypto_sev in ("high", "critical"):
                                        args.update(self._build_report_finding_args(
                                            title=args["title"],
                                            severity=crypto_sev,
                                            finding_type="weak_crypto",
                                            affected_component=crypto_component,
                                            description=crypto_desc,
                                            impact="Weak cryptographic handling may expose secrets, reduce transport security, or enable credential cracking or token compromise.",
                                            technical_analysis=f"The crypto skill reported the following concrete indicator: {crypto_evidence}",
                                            poc_description="Replay the protocol or artifact inspection and confirm that the weak protocol, secret exposure, or weak hash indicator is present.",
                                            poc_script_code=crypto_evidence,
                                            remediation_steps="Disable weak protocols, remove hardcoded secrets, and replace legacy hashes with modern password hashing and secret management.",
                                            endpoint=crypto_component,
                                            method="GET",
                                        ))
                                    await self._dispatch_report_finding_checked(args)

                            # Auto-report: Infra findings (git, env, cloud)
                            if _real_skill == "test_infra" and sr.data:
                                for finding in (sr.data.get("findings") or []):
                                    infra_component = self.state.target + finding.get("path", "")
                                    infra_desc = finding.get("description", finding.get("payload", ""))[:200]
                                    infra_evidence = finding.get("evidence", "")[:1200]
                                    infra_poc = self._build_simple_http_poc(
                                        url=infra_component,
                                        status=finding.get("status", "?"),
                                        response_preview=finding.get("response_preview", infra_evidence)[:1200],
                                    )
                                    await self._dispatch_report_finding_checked(self._build_report_finding_args(
                                        title=f"Infrastructure exposure: {finding.get('type', 'unknown')}",
                                        severity=finding.get("severity", "high"),
                                        finding_type="misconfiguration",
                                        affected_component=infra_component,
                                        description=infra_desc,
                                        impact="Attackers may leverage exposed infrastructure artifacts to obtain secrets, internal topology, or privileged administrative access.",
                                        technical_analysis=f"The infrastructure skill surfaced the following externally reachable artifact or service evidence: {infra_evidence}",
                                        poc_description="Request the exposed infrastructure path or service directly and verify that the sensitive artifact or administrative surface is reachable.",
                                        poc_script_code=infra_poc,
                                        remediation_steps="Remove public exposure of infrastructure artifacts, restrict administrative services, and block direct access to internal metadata or repository content.",
                                        endpoint=infra_component,
                                        method="GET",
                                    ))

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
                                    # Phase Q2: dedup discriminator. Without
                                    # it, 12 dylib_hijack findings all share
                                    # the binary path → finding_tools dedupes
                                    # them to a single VXIS-NNNN entry. Each
                                    # finding type carries its own
                                    # distinguishing key (dylib name,
                                    # entitlement, scheme, flag) — append it
                                    # to affected_component as a fragment so
                                    # the binary stays the same but each
                                    # specific issue gets its own slot.
                                    _disc = (
                                        finding.get("dylib")
                                        or finding.get("entitlement_key")
                                        or finding.get("entitlement")
                                        or finding.get("scheme")
                                        or finding.get("flag")
                                        or finding.get("secret_type")
                                        or finding.get("vector")
                                    )
                                    if _disc and "#" not in _loc:
                                        _loc_with_disc = f"{_loc}#{_disc}"
                                    else:
                                        _loc_with_disc = _loc
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
                                    await self._dispatch_report_finding_checked({
                                        "title": finding.get("title", f"Desktop finding: {finding.get('vector', '?')}"),
                                        "severity": finding.get("severity", "medium"),
                                        "finding_type": finding.get("vector", "desktop_misconfiguration"),
                                        "affected_component": _loc_with_disc,
                                        "description": finding.get("description", "")[:1500],
                                        "evidence": str(_ev)[:500],
                                    })

                    except Exception:
                        logger.exception("skill %s failed", skill_name)
        return auth_token
