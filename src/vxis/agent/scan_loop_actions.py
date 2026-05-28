from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from vxis.agent.scan_loop_state import (
    _TERMINAL_BRANCH_STATUSES,
    ScanLoopState,
    _sanitize_evidence_text,
)
from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)


class ScanLoopActionMixin:
    def _emit_event(self, event_type: str, data: dict[str, Any]) -> None:
        if self._event_callback is None:
            return
        try:
            self._event_callback(event_type, data)
        except Exception:
            logger.debug("scan loop event_callback failed for %s", event_type, exc_info=True)

    @staticmethod
    def _truncate_ui_text(value: Any, limit: int = 96) -> str:
        text = str(value).replace("\n", " ").strip()
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

    def _ui_action_details(self, name: str, args: dict[str, Any] | Any) -> tuple[str, str, str, str]:
        vector_id = name
        method = "TOOL"
        endpoint = self.state.target
        summary = name

        if not isinstance(args, dict):
            return vector_id, method, endpoint, summary

        if name == "run_skill":
            skill = self._truncate_ui_text(args.get("skill") or "unknown", 40)
            vector_id = f"skill:{skill}"
            method = "SKILL"
            endpoint = self._truncate_ui_text(args.get("target_url") or self.state.target, 80)
            summary = f"run_skill {skill}"
            return vector_id, method, endpoint, summary

        if name == "http_request":
            method = str(args.get("method") or "HTTP").upper()
            endpoint = self._truncate_ui_text(args.get("url") or self.state.target, 80)
            summary = f"{method} {endpoint}"
            return vector_id, method, endpoint, summary

        if name == "wait":
            seconds = self._truncate_ui_text(args.get("seconds") or "0", 12)
            return "scan:wait", "WAIT", f"{seconds}s", f"wait {seconds}s"

        if name == "agent_graph":
            action = self._truncate_ui_text(args.get("action") or "view", 20)
            agent = self._truncate_ui_text(args.get("agent_id") or args.get("role") or "root", 40)
            task = self._truncate_ui_text(args.get("task") or args.get("message") or agent, 80)
            return "scan:agent-graph", "GRAPH", agent, f"agent_graph {action}: {task}"

        if name.startswith("browser_"):
            method = "BROWSER"
            endpoint = self._truncate_ui_text(
                args.get("url")
                or args.get("selector")
                or args.get("form_selector")
                or args.get("expression")
                or self.state.target,
                80,
            )
            summary = f"{name} {endpoint}"
            return vector_id, method, endpoint, summary

        if name in ("shell_exec", "python_exec"):
            method = "EXEC"
            endpoint = self._truncate_ui_text(
                args.get("command") or args.get("cmd") or args.get("code") or self.state.target,
                80,
            )
            summary = f"{name} {endpoint}"
            return vector_id, method, endpoint, summary

        if name == "report_finding":
            ftype = self._truncate_ui_text(args.get("finding_type") or "finding", 40)
            vector_id = f"finding:{ftype}"
            method = "REPORT"
            endpoint = self._truncate_ui_text(
                args.get("affected_component") or args.get("title") or self.state.target,
                80,
            )
            summary = f"report {ftype}"
            return vector_id, method, endpoint, summary

        if name == "finish_scan":
            return "scan:finish", "CONTROL", self.state.target, "finish scan"

        for key in (
            "url",
            "target_url",
            "affected_component",
            "path",
            "selector",
            "form_selector",
            "title",
            "name",
        ):
            value = args.get(key)
            if value:
                endpoint = self._truncate_ui_text(value, 80)
                break

        summary = f"{name} {endpoint}"
        return vector_id, method, endpoint, summary

    def _emit_brain_status(self, summary: str, *, vector_id: str = "scan_loop") -> None:
        self._emit_event(
            "brain_thinking",
            {
                "phase": "scan_loop",
                "iteration": self.state.iteration,
                "max_iters": self.state.max_iters,
                "vector_count": 1,
                "vectors": [
                    {
                        "id": vector_id,
                        "reasoning": self._truncate_ui_text(summary, 220),
                    }
                ],
            },
        )

    def _build_report_finding_args(
        self,
        *,
        title: str,
        severity: str,
        finding_type: str,
        affected_component: str,
        description: str,
        impact: str,
        technical_analysis: str,
        poc_description: str,
        poc_script_code: str,
        remediation_steps: str,
        endpoint: str = "",
        method: str = "",
        cwe: str = "",
        extra_evidence: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        _safe_poc = _sanitize_evidence_text(poc_script_code, limit=4000)
        args = {
            "title": title,
            "severity": severity,
            "finding_type": finding_type,
            "affected_component": affected_component,
            "description": description,
            "impact": impact,
            "technical_analysis": technical_analysis,
            "poc_description": poc_description,
            "poc_script_code": _safe_poc,
            "remediation_steps": remediation_steps,
            "endpoint": endpoint or affected_component,
            "method": method,
            "cwe": cwe,
            # Keep legacy alias populated so older downstream code still sees it.
            "evidence": _safe_poc,
        }
        if extra_evidence:
            args["extra_evidence"] = list(extra_evidence)
        return args

    def _compact_local_reasoning_blob(self, value: Any, *, limit: int) -> str:
        text = _sanitize_evidence_text(str(value or ""), limit=max(120, limit * 2))
        if not text:
            return ""
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) <= 6 and len(text) <= limit:
            return text[:limit]
        picked: list[str] = []
        keywords = ("http/", "host:", "payload", "baseline", "control", "status", "response", "error", "token", "cookie", "admin", "select", "union")
        for line in lines:
            lower = line.lower()
            if any(token in lower for token in keywords):
                picked.append(line)
            if len(picked) >= 6:
                break
        if not picked:
            picked = lines[:6]
        compact = "\n".join(picked)
        return compact[:limit]

    def _compact_local_finding_payload(self, args: dict[str, Any]) -> dict[str, Any]:
        if self._llm_discipline_profile() != "local_strict":
            return dict(args)
        compact = dict(args)
        compact["description"] = str(compact.get("description", ""))[:220]
        compact["impact"] = str(compact.get("impact", ""))[:240]
        compact["technical_analysis"] = self._compact_local_reasoning_blob(
            compact.get("technical_analysis", ""),
            limit=520,
        )
        compact["poc_description"] = self._compact_local_reasoning_blob(
            compact.get("poc_description", ""),
            limit=420,
        )
        compact["poc_script_code"] = self._compact_local_reasoning_blob(
            compact.get("poc_script_code", ""),
            limit=1200,
        )
        compact["evidence"] = self._compact_local_reasoning_blob(
            compact.get("evidence", compact.get("poc_script_code", "")),
            limit=1200,
        )
        if compact.get("extra_evidence"):
            trimmed_extra: list[dict[str, Any]] = []
            for item in list(compact.get("extra_evidence") or [])[:2]:
                if not isinstance(item, dict):
                    continue
                trimmed_extra.append({
                    **item,
                    "title": str(item.get("title", ""))[:60],
                    "content": self._compact_local_reasoning_blob(item.get("content", ""), limit=700),
                })
            compact["extra_evidence"] = trimmed_extra
        return compact

    @staticmethod
    def _callback_evidence_item(*, title: str, signal: str, payload: str, summary: str) -> dict[str, str]:
        return {
            "evidence_type": "callback",
            "title": title,
            "content_type": "text/plain",
            "content": (
                f"Signal: {signal}\n"
                f"Payload: {payload}\n"
                f"Summary: {summary}"
            )[:4000],
        }

    @staticmethod
    def _retrieval_evidence_item(*, title: str, retrieval_kind: str, summary: str, sample: str) -> dict[str, str]:
        return {
            "evidence_type": "retrieval",
            "title": title,
            "content_type": "text/plain",
            "content": (
                f"Retrieval kind: {retrieval_kind}\n"
                f"Summary: {summary}\n\n"
                f"Sample:\n{_sanitize_evidence_text(sample, limit=3000)}"
            )[:4000],
        }

    @staticmethod
    def _exfil_evidence_item(*, title: str, summary: str, sample: str) -> dict[str, str]:
        return {
            "evidence_type": "exfil",
            "title": title,
            "content_type": "text/plain",
            "content": (
                f"Summary: {summary}\n\n"
                f"Sample:\n{_sanitize_evidence_text(sample, limit=3000)}"
            )[:4000],
        }

    def _build_reflected_get_poc(
        self,
        *,
        url: str,
        param: str,
        payload: str,
        control: dict[str, Any],
        response_preview: str,
    ) -> str:
        parsed = urlparse(url)
        path = parsed.path or "/"
        original_params = parse_qs(parsed.query, keep_blank_values=True)
        original_value = ""
        if param in original_params and original_params[param]:
            original_value = original_params[param][0]
        payload_params = dict(original_params)
        payload_params[param] = [original_value + payload]
        baseline_query = urlencode({k: v[0] for k, v in original_params.items()}) if original_params else ""
        payload_query = urlencode({k: v[0] for k, v in payload_params.items()})
        baseline_target = path + (f"?{baseline_query}" if baseline_query else "")
        payload_target = path + (f"?{payload_query}" if payload_query else "")
        host = parsed.netloc or urlparse(self.state.target).netloc or "target"
        baseline_preview = str(control.get("baseline_preview", ""))[:500]
        payload_preview = str(control.get("payload_preview", response_preview))[:700]
        baseline_status = control.get("baseline_status", "?")
        payload_status = control.get("payload_status", "?")
        return (
            f"GET {baseline_target} HTTP/1.1\n"
            f"Host: {host}\n\n"
            f"HTTP/1.1 {baseline_status}\n\n"
            f"{baseline_preview}\n\n"
            f"GET {payload_target} HTTP/1.1\n"
            f"Host: {host}\n\n"
            f"HTTP/1.1 {payload_status}\n\n"
            f"{payload_preview}"
        )

    def _build_simple_http_poc(
        self,
        *,
        url: str,
        method: str = "GET",
        status: Any = "?",
        response_preview: str,
    ) -> str:
        parsed = urlparse(url)
        host = parsed.netloc or urlparse(self.state.target).netloc or "target"
        target = parsed.path or "/"
        if parsed.query:
            target += f"?{parsed.query}"
        preview = _sanitize_evidence_text(response_preview, limit=2500)
        return (
            f"{method.upper()} {target} HTTP/1.1\n"
            f"Host: {host}\n\n"
            f"HTTP/1.1 {status}\n\n"
            f"{preview}"
        )

    def _settle_branches_after_chain(self, finding_ids: list[str]) -> None:
        chain_ids = {str(fid) for fid in finding_ids if fid}
        if not chain_ids:
            return
        findings_by_id: dict[str, dict[str, Any]] = {}
        try:
            from vxis.agent.tools.finding_tools import _get_findings
            findings_by_id = {
                str(item.get("id")): item
                for item in (_get_findings() or [])
                if isinstance(item, dict) and item.get("id")
            }
        except Exception:
            findings_by_id = {}

        branch_ids_to_settle: set[str] = set()
        for fid in chain_ids:
            finding = findings_by_id.get(fid) or {}
            if finding:
                for branch_id in self._parent_branch_ids_for_finding(finding):
                    branch_ids_to_settle.add(branch_id)
        for branch in self.state.branches.values():
            if branch.status in _TERMINAL_BRANCH_STATUSES:
                continue
            if branch.source_finding_id and branch.source_finding_id in chain_ids:
                branch_ids_to_settle.add(branch.id)
                if branch.parent_branch_id:
                    branch_ids_to_settle.add(branch.parent_branch_id)
                branch_ids_to_settle.update(branch.child_ids)
        for branch_id in list(branch_ids_to_settle):
            branch = self.state.branches.get(branch_id)
            if branch is None:
                continue
            if branch.parent_branch_id:
                branch_ids_to_settle.add(branch.parent_branch_id)
            branch_ids_to_settle.update(branch.child_ids)

        for branch in self.state.branches.values():
            if branch.status in _TERMINAL_BRANCH_STATUSES:
                continue
            if branch.id in branch_ids_to_settle:
                branch.status = "proven"
                branch.last_report = (branch.last_report or "linked into attack chain")[:160]
                continue
            if branch.parent_branch_id and branch.parent_branch_id in branch_ids_to_settle:
                branch.status = "exhausted"
                branch.last_report = (branch.last_report or "superseded by linked attack chain")[:160]

    async def _dispatch_report_finding_checked(
        self,
        args: dict[str, Any],
        *,
        require_confirmed: bool = True,
    ) -> ToolResult:
        args = self._compact_local_finding_payload(args)
        severity = str(args.get("severity", "")).lower()
        if severity in {"high", "critical"} and "verify_finding" in self.registry.list_tools():
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
            verdict_result = await self.registry.dispatch("verify_finding", verify_args)
            if verdict_result.ok:
                verdict_data = verdict_result.data or {}
                verdict = str(verdict_data.get("verdict", "UNCONFIRMED"))
                reasoning = str(verdict_data.get("reasoning", "")) or f"Verifier returned {verdict}."
                confidence = str(verdict_data.get("confidence", "low"))
                self.state.verdict_counts[verdict] = self.state.verdict_counts.get(verdict, 0) + 1
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
                elif verdict == "REFUTED":
                    self.state.refuted_findings.append(_belief_entry)
                self._record_verifier_decision(
                    args=args,
                    verdict=verdict,
                    reasoning=reasoning,
                    confidence=confidence,
                )
                self.state.add_message("tool", {
                    "name": "verify_finding",
                    "args": verify_args,
                    "result": {
                        "ok": True,
                        "summary": verdict_result.summary,
                        "data": verdict_data,
                    },
                })
                if verdict != "CONFIRMED" and require_confirmed:
                    return ToolResult(
                        ok=False,
                        summary=(
                            "report_finding BLOCKED by auto-verifier "
                            f"({verdict}). Reason: {reasoning[:220]}"
                        ),
                        data={"verifier_blocked": True, "verdict": verdict, "reasoning": reasoning},
                        error="verifier_blocked",
                    )
                if verdict == "REFUTED":
                    return ToolResult(
                        ok=False,
                        summary=(
                            "report_finding BLOCKED by auto-verifier "
                            f"(REFUTED). Reason: {reasoning[:220]}"
                        ),
                        data={"verifier_blocked": True, "verdict": verdict, "reasoning": reasoning},
                        error="verifier_blocked",
                    )

        result = await self.registry.dispatch("report_finding", args)
        if result.ok:
            self._mark_candidates_for_finding(args)
            finding_id = ""
            if isinstance(result.data, dict):
                finding_id = str(result.data.get("id") or "")
            if finding_id:
                self._spawn_followup_branches_from_finding(finding_id, args)
                await self._maybe_auto_link_chain(finding_id)
        return result

    async def _promote_direct_run_skill_result(
        self,
        real_skill: str,
        data: dict[str, Any],
    ) -> None:
        if real_skill == "test_injection":
            for finding in (data.get("findings") or []):
                inj_sev = finding.get("severity", "medium")
                if inj_sev not in ("high", "critical"):
                    continue
                inj_url = data.get("url", self.state.target)
                inj_param = data.get("param", finding.get("param", "?"))
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
            return

        if real_skill == "test_xss":
            for finding in (data.get("findings") or []):
                xss_sev = finding.get("severity", "high")
                xss_url = data.get("url", self.state.target)
                xss_param = finding.get("param", data.get("param", "?"))
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
            return

        if real_skill == "test_ssrf":
            for finding in (data.get("findings") or []):
                ssrf_sev = finding.get("severity", "high")
                ssrf_url = data.get("url", self.state.target)
                ssrf_param = finding.get("param", data.get("param", "?"))
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

    def _emit_iteration_status(self, note: str) -> None:
        self.state.clear_waiting_reason()
        active_branches = self.state.active_branches()
        if active_branches:
            focus_branch = active_branches[0]
            self._emit_brain_status(
                f"iter {self.state.iteration}/{self.state.max_iters} - {note}. "
                f"Focus branch: {focus_branch.title}",
                vector_id=focus_branch.id,
            )
            self._emit_control_plane(note)
            return
        open_candidates = self.state.open_vector_candidates()
        if open_candidates:
            focus = open_candidates[0]
            self._emit_brain_status(
                f"iter {self.state.iteration}/{self.state.max_iters} - {note}. "
                f"Focus: {focus.title}",
                vector_id=focus.id,
            )
        else:
            self._emit_brain_status(
                f"iter {self.state.iteration}/{self.state.max_iters} - {note}",
                vector_id="scan_loop",
            )
        self._emit_control_plane(note)

    def _emit_action_progress(self, name: str, args: dict[str, Any] | Any, prefix: str) -> None:
        vector_id, method, endpoint, summary = self._ui_action_details(name, args)
        self.state.set_waiting_reason(f"{prefix}: {summary}")
        self._emit_brain_status(
            f"iter {self.state.iteration}/{self.state.max_iters} - {prefix}: {summary}",
            vector_id=vector_id,
        )
        self._emit_event(
            "attack",
            {
                "vector_id": vector_id,
                "method": method,
                "endpoint": endpoint,
            },
        )
        self._emit_control_plane(f"{prefix}: {summary}")

    def _emit_control_plane(self, note: str = "") -> None:
        import os

        telemetry: dict[str, Any] = {}
        proxy_status: dict[str, Any] = {}
        try:
            from vxis.agent.brain import (
                get_brain_decision_count as _get_brain_decision_count,
                get_llm_call_count as _get_llm_call_count,
                get_llm_usage_stats as _get_llm_usage_stats,
            )
            from vxis.agent.memory_compressor import get_memory_compression_stats
            from vxis.agent.tools.proxy_runtime import get_proxy_status_snapshot

            telemetry = _get_llm_usage_stats()
            telemetry["llm_calls"] = _get_llm_call_count()
            telemetry["brain_decisions"] = _get_brain_decision_count()
            telemetry["memory_compression"] = get_memory_compression_stats()
            proxy_status = get_proxy_status_snapshot()
        except Exception:
            telemetry = {}
            proxy_status = {}
        if not telemetry.get("provider"):
            telemetry["provider"] = getattr(self.brain, "_provider", "")
        if not telemetry.get("model"):
            telemetry["model"] = getattr(self.brain, "_model", "")
        if not telemetry.get("base_url"):
            provider = str(telemetry.get("provider") or "").strip().lower()
            if provider == "ollama":
                telemetry["base_url"] = os.environ.get("VXIS_OLLAMA_BASE_URL", "").rstrip("/")
            elif provider == "llamacpp":
                telemetry["base_url"] = os.environ.get("VXIS_LLAMACPP_BASE_URL", "").rstrip("/")
        telemetry["discipline_profile"] = self._llm_discipline_profile()

        snapshot = self.state.control_plane_snapshot()
        focus = self._focus_branch()
        if focus is not None:
            snapshot["focus_branch"] = {
                "id": focus.id,
                "title": focus.title,
                "vector_id": focus.vector_id,
                "role": focus.role,
                "phase": focus.phase,
                "status": focus.status,
                "objective": focus.objective,
                "next_step": focus.next_step,
                "crown_jewel": focus.crown_jewel,
                "blocker": focus.blocker,
                "owner": focus.owner,
            }
        snapshot["blocking_branches"] = [
            {
                "id": branch.id,
                "title": branch.title,
                "vector_id": branch.vector_id,
                "status": branch.status,
                "role": branch.role,
                "phase": branch.phase,
                "priority": branch.priority,
                "attempts": branch.attempts,
                "objective": branch.objective,
                "next_step": branch.next_step,
                "blocker": branch.blocker,
            }
            for branch in self._blocking_finish_branches()[:4]
        ]
        snapshot["campaign_groups"] = self._campaign_groups_for_ui(limit=4)
        snapshot["focus_campaign"] = self._focus_campaign_for_ui()
        snapshot["memory_directives"] = [
            note for note in self.state.shared_notes
            if str(note).startswith("memory")
        ][-4:]
        snapshot["chain_candidates"] = self._suggest_chain_candidates(limit=3)
        snapshot["agents"] = self._agent_graph_agents_from_messages()[:6]
        snapshot["service_pivots"] = [
            {
                "id": branch.id,
                "title": branch.title,
                "status": branch.status,
                "priority": branch.priority,
                "role": branch.role,
                "parent_branch_id": branch.parent_branch_id,
                "objective": branch.objective,
                "next_step": branch.next_step,
                "evidence": branch.evidence,
                "child_ids": list(branch.child_ids),
            }
            for branch in self.state.active_branches()
            if branch.vector_id == "NET-SERVICE-PIVOT"
        ][:6]
        sdk_loop = getattr(self, "_sdk_agent_loop", None)
        if sdk_loop is not None and callable(getattr(sdk_loop, "control_plane_snapshot", None)):
            sdk_runtime = sdk_loop.control_plane_snapshot(limit=6)
            snapshot["sdk_runtime"] = sdk_runtime
            sdk_agents = {
                str((item.get("agent") or {}).get("agent_id") or ""): item
                for item in list(sdk_runtime.get("agents") or [])
                if isinstance(item, dict) and isinstance(item.get("agent"), dict)
            }
            for agent in snapshot["agents"]:
                agent_id = str(agent.get("id") or "")
                if agent_id in sdk_agents:
                    agent["sdk_runtime"] = sdk_agents[agent_id]
        snapshot["note"] = self._truncate_ui_text(note, 140) if note else ""
        snapshot["telemetry"] = telemetry
        snapshot["proxy"] = proxy_status
        self._latest_control_plane = dict(snapshot)
        self._emit_event("control_plane", snapshot)

    async def _maybe_autostart_proxy(self) -> None:
        import os
        try:
            from vxis.interaction.surface import TargetKind as _TK
            from vxis.agent.tools.proxy_runtime import get_proxy_runtime
        except Exception:
            return
        if os.environ.get("VXIS_PROXY_AUTOSTART", "1").strip().lower() in {"0", "false", "no"}:
            return
        if self._target_kind != _TK.WEB and not str(self.state.target).startswith(("http://", "https://")):
            return
        try:
            status = await get_proxy_runtime().start(
                port=int(os.environ.get("VXIS_PROXY_PORT", "8081")),
                backend=os.environ.get("VXIS_PROXY_BACKEND", "auto"),
            )
        except Exception as exc:
            logger.info("proxy autostart failed: %s", exc)
            return
        if status.get("running"):
            backend = status.get("backend") or "proxy"
            proxy_url = status.get("proxy_url") or ""
            self.state.add_shared_note(f"Proxy online: {backend} {proxy_url}".strip())
            self._emit_control_plane(f"Proxy online via {backend}")
        elif status.get("last_error"):
            self.state.add_shared_note(f"Proxy unavailable: {status.get('last_error')}")

    @staticmethod
    def _preview_args(args: Any) -> str:
        try:
            return json.dumps(args, default=str, ensure_ascii=False, sort_keys=True).lower()
        except Exception:
            return str(args).lower()

    def _candidate_ids_for_action(self, name: str, args: dict[str, Any] | Any) -> list[str]:
        """Infer which durable vector candidates a tool call is attempting."""
        if name == "finish_scan":
            return []
        blob = f"{name} {self._preview_args(args)}"
        candidates: list[str] = []

        if name == "run_skill" and isinstance(args, dict):
            skill = str(args.get("skill") or "").lower()
            skill_map = {
                "attempt_auth": ["web:auth-bypass"],
                "test_auth_deep": ["web:auth-bypass"],
                "test_injection": ["web:sqli"],
                "test_idor": ["web:idor"],
                "test_sensitive_files": ["web:sensitive-files"],
                "enumerate_endpoints": ["web:dir-bruteforce"],
                "test_xss": ["web:xss"],
                "test_ssrf": ["web:ssrf"],
                "test_local_storage_secrets": ["desktop:local-storage-secrets"],
                "test_signature_audit": ["desktop:signature-audit"],
                "test_dylib_hijack": ["desktop:dylib-hijack"],
                "test_ipc_injection": ["desktop:ipc-injection"],
            }
            candidates.extend(skill_map.get(skill, []))

        keyword_map = [
            ("sqlmap", "web:sqli"),
            ("sqli", "web:sqli"),
            ("union select", "web:sqli"),
            (" or 1=1", "web:sqli"),
            ("ffuf", "web:dir-bruteforce"),
            ("gobuster", "web:dir-bruteforce"),
            ("dirb", "web:dir-bruteforce"),
            ("nuclei", "web:cve-scan"),
            ("/api/users", "web:idor"),
            ("/api/orders", "web:idor"),
            ("idor", "web:idor"),
            ("jwt", "web:auth-bypass"),
            ("login", "web:auth-bypass"),
            ("password", "web:auth-bypass"),
            ("xss", "web:xss"),
            ("<script", "web:xss"),
            ("ssrf", "web:ssrf"),
            ("169.254.169.254", "web:ssrf"),
            ("../", "web:sensitive-files"),
            ("/ftp", "web:sensitive-files"),
            ("backup", "web:sensitive-files"),
        ]
        for needle, cid in keyword_map:
            if needle in blob:
                candidates.append(cid)

        if name == "browser_fill_form":
            candidates.append("web:auth-bypass")
        elif name == "browser_eval_js":
            candidates.append("web:xss")

        # Preserve order while removing duplicates and unknown candidates.
        seen: set[str] = set()
        result: list[str] = []
        for cid in candidates:
            if cid in self.state.vector_candidates and cid not in seen:
                seen.add(cid)
                result.append(cid)
        return result

    @staticmethod
    def _status_from_tool_result(result: ToolResult) -> str:
        if not result.ok:
            data = result.data if isinstance(result.data, dict) else {}
            if any(data.get(k) for k in ("egress_blocked", "surface_guard_blocked", "dedup", "blocked")):
                return "blocked"
            if str(result.error or "").strip().lower() in {"stuck_loop", "non_text_response"}:
                return "blocked"
            return "failed"
        text = f"{result.summary} {result.data}".lower()
        if any(tok in text for tok in (
            "confirmed", "vulnerable", "succeeded", "jwt payload",
            "sql injection", "xss", "idor", "admin", "token",
            "finding recorded", "finding grouped",
        )):
            return "found"
        if any(tok in text for tok in ("no finding", "not vulnerable", "nothing found", "no issue")):
            return "clean"
        return "attempted"

    def _mark_candidates_for_finding(self, args: dict[str, Any]) -> None:
        ftype = str(args.get("finding_type") or "").lower()
        title = str(args.get("title") or "").lower()
        text = f"{ftype} {title}"
        mapping = [
            (("sql", "sqli"), "web:sqli"),
            (("auth", "login", "jwt"), "web:auth-bypass"),
            (("idor", "access", "privilege"), "web:idor"),
            (("xss",), "web:xss"),
            (("ssrf",), "web:ssrf"),
            (("info", "sensitive", "disclosure", "traversal"), "web:sensitive-files"),
            (("cve",), "web:cve-scan"),
        ]
        for needles, cid in mapping:
            if any(n in text for n in needles) and cid in self.state.vector_candidates:
                self.state.record_attempt_outcome(
                    cid,
                    "report_finding",
                    args,
                    status="found",
                    summary=f"finding reported: {args.get('title', '')}",
                )

    def _mark_retryable_candidate(
        self,
        candidate_id: str,
        *,
        tool: str,
        summary: str,
        evidence: str = "",
    ) -> None:
        candidate = self.state.vector_candidates.get(candidate_id)
        if candidate is None:
            return
        candidate.status = "retryable"
        candidate.last_tool = tool[:80]
        candidate.last_summary = summary[:240]
        candidate.last_iter = self.state.iteration
        if evidence and evidence not in candidate.evidence:
            candidate.evidence = (candidate.evidence + "; " + evidence).strip("; ")
        self.state._sync_candidate_control_state(candidate)

    def _mark_family_probe_retryable(
        self,
        skill_name: str,
        *,
        url: str = "",
        round_num: int = 1,
        tested_params: list[str] | None = None,
    ) -> None:
        skill = str(skill_name).strip().lower()
        candidate_map = {
            "test_injection": "web:sqli",
            "test_xss": "web:xss",
            "test_ssrf": "web:ssrf",
        }
        candidate_id = candidate_map.get(skill)
        if not candidate_id:
            return
        params = ", ".join((tested_params or [])[:4]) or "default params"
        retry_summary = (
            f"{skill} remained inconclusive at round {round_num}; "
            f"retry with stronger payload variant on {url or self.state.target} "
            f"against params [{params}]"
        )
        self._mark_retryable_candidate(
            candidate_id,
            tool=skill,
            summary=retry_summary,
            evidence=f"{url} round={round_num} params={params}".strip(),
        )
        self.state.add_shared_note(f"Retryable {candidate_id}: round {round_num} inconclusive on {url or self.state.target}")

    def _parent_branch_ids_for_finding(self, args: dict[str, Any]) -> list[str]:
        ftype = str(args.get("finding_type") or "").lower()
        title = str(args.get("title") or "").lower()
        component = str(args.get("affected_component") or "").lower()
        blob = f"{ftype} {title} {component}"
        matches: list[str] = []
        mapping = [
            (("sql", "sqli"), "web:sqli"),
            (("auth", "login", "jwt", "session"), "web:auth-bypass"),
            (("idor", "access", "privilege"), "web:idor"),
            (("xss",), "web:xss"),
            (("ssrf",), "web:ssrf"),
            (("info", "sensitive", "disclosure", "traversal", "config"), "web:sensitive-files"),
            (("cve",), "web:cve-scan"),
        ]
        for needles, cid in mapping:
            if any(needle in blob for needle in needles):
                matches.append(cid)
        seen: set[str] = set()
        result: list[str] = []
        for branch_id in matches:
            if branch_id in self.state.branches and branch_id not in seen:
                seen.add(branch_id)
                result.append(branch_id)
        return result

    def _spawn_followup_branches_from_finding(
        self,
        finding_id: str,
        args: dict[str, Any],
    ) -> None:
        ftype = str(args.get("finding_type") or "").lower()
        title = str(args.get("title") or "").strip()
        component = str(args.get("affected_component") or "").strip()
        severity = str(args.get("severity") or "").lower()
        parent_branch_ids = self._parent_branch_ids_for_finding(args) or ["root"]
        severity_boost = {"critical": 10, "high": 8, "medium": 5, "low": 2, "informational": 1}.get(severity, 0)

        pivot_rules: list[tuple[tuple[str, ...], list[dict[str, Any]]]] = [
            (
                ("auth", "login", "jwt", "session", "credential"),
                [
                    {
                        "suffix": "post-auth-enum",
                        "vector_id": "WEB-AUTH-PIVOT",
                        "title": "Expand authenticated route coverage",
                        "priority": 90,
                        "objective": "Use the obtained session to map authenticated APIs, admin pages, and role-protected flows.",
                        "next_step": "Reuse the live session with browser_get_cookies, browser_eval_js, post_auth_enum, then browse /admin and authenticated API paths.",
                        "crown_jewel": "admin takeover or broad data access",
                        "watch_terms": ["token", "cookie", "/admin", "/api/users", "post_auth_enum"],
                    },
                    {
                        "suffix": "admin-access-control",
                        "vector_id": "WEB-AC-PIVOT",
                        "title": "Probe admin-only access controls with the new session",
                        "priority": 95,
                        "objective": "Confirm whether the authenticated state crosses privilege boundaries into admin-only actions.",
                        "next_step": "Directly test /admin, /admin/users, role changes, and privileged exports with the current session.",
                        "crown_jewel": "admin takeover",
                        "watch_terms": ["/admin", "role", "export", "browser_navigate", "http_request"],
                    },
                ],
            ),
            (
                ("idor", "access", "privilege"),
                [
                    {
                        "suffix": "write-idor",
                        "vector_id": "WEB-IDOR-PIVOT",
                        "title": "Escalate access control weakness into write/delete impact",
                        "priority": 94,
                        "objective": "Push the access-control bug past read-only confirmation into write, delete, or role-changing impact.",
                        "next_step": "Replay the vulnerable object reference against PATCH/PUT/DELETE or role/state-changing endpoints.",
                        "crown_jewel": "account takeover or broad data manipulation",
                        "watch_terms": ["put", "patch", "delete", "role", "user", "account", "idor"],
                    },
                    {
                        "suffix": "data-exfil",
                        "vector_id": "WEB-EXFIL-PIVOT",
                        "title": "Test whether the access-control gap scales to bulk data access",
                        "priority": 88,
                        "objective": "Check whether the same boundary failure opens mass export or neighboring-account traversal.",
                        "next_step": "Enumerate adjacent IDs, list endpoints, and export/download flows to quantify blast radius.",
                        "crown_jewel": "full data exfiltration",
                        "watch_terms": ["list", "export", "download", "users", "orders", "idor"],
                    },
                ],
            ),
            (
                ("sql", "sqli"),
                [
                    {
                        "suffix": "credential-pivot",
                        "vector_id": "WEB-SQLI-PIVOT",
                        "title": "Harvest credentials or tokens from SQLi impact",
                        "priority": 96,
                        "objective": "Turn the injection into usable credentials, session material, or privilege context.",
                        "next_step": "Dump users/auth tables or config values, then attempt login/session reuse with anything exposed.",
                        "crown_jewel": "admin takeover or DB dump",
                        "watch_terms": ["sqlmap", "dump", "users", "token", "password", "select"],
                    },
                    {
                        "suffix": "db-impact",
                        "vector_id": "WEB-SQLI-IMPACT",
                        "title": "Expand SQLi toward full database impact",
                        "priority": 92,
                        "objective": "Prove the injection reaches crown-jewel data, not just a boolean/oracle condition.",
                        "next_step": "Enumerate schemas/tables and retrieve high-value rows or admin secrets from the database.",
                        "crown_jewel": "DB dump",
                        "watch_terms": ["sqlmap", "schema", "table", "dump", "union select"],
                    },
                ],
            ),
            (
                ("info", "sensitive", "disclosure", "traversal", "config", "secret"),
                [
                    {
                        "suffix": "credential-reuse",
                        "vector_id": "WEB-DISCLOSURE-PIVOT",
                        "title": "Turn disclosed material into authenticated access",
                        "priority": 89,
                        "objective": "Check whether leaked config, keys, or tokens grant privileged access.",
                        "next_step": "Validate any disclosed credentials, tokens, or internal routes against live login or admin/API endpoints.",
                        "crown_jewel": "admin takeover",
                        "watch_terms": ["token", "key", "password", "config", "admin", "login"],
                    },
                    {
                        "suffix": "admin-surface",
                        "vector_id": "WEB-ADMIN-PIVOT",
                        "title": "Use the disclosure to map privileged routes and internal surfaces",
                        "priority": 84,
                        "objective": "Pivot from leaked route/config hints into direct access checks on privileged endpoints.",
                        "next_step": "Follow leaked URLs, JS routes, backups, and internal paths to admin consoles or sensitive APIs.",
                        "crown_jewel": "privileged route exposure",
                        "watch_terms": ["/admin", "backup", "config", ".env", ".git", "actuator"],
                    },
                ],
            ),
            (
                ("xss",),
                [
                    {
                        "suffix": "session-pivot",
                        "vector_id": "WEB-XSS-PIVOT",
                        "title": "Turn XSS into session or privileged action impact",
                        "priority": 90,
                        "objective": "Move from script execution proof into session theft or admin-only action execution.",
                        "next_step": "Read cookies/localStorage tokens and test whether the session reaches admin pages or sensitive actions.",
                        "crown_jewel": "session takeover",
                        "watch_terms": ["document.cookie", "localStorage", "token", "/admin", "browser_eval_js"],
                    },
                ],
            ),
        ]

        for parent_branch_id in parent_branch_ids:
            parent = self.state.branches.get(parent_branch_id)
            if parent is None:
                continue
            parent.status = "active"
            parent.last_report = f"Finding {finding_id} reported: {title[:120]}"
            parent.last_summary = parent.last_report
            if component:
                parent.evidence = (parent.evidence + "; " + component).strip("; ")
            for needles, pivots in pivot_rules:
                if not any(needle in ftype or needle in title.lower() for needle in needles):
                    continue
                for pivot in pivots:
                    branch_id = self._reuse_or_allocate_followup_branch_id(
                        parent_branch_id=parent_branch_id,
                        finding_id=finding_id,
                        vector_id=str(pivot["vector_id"]),
                        suffix=str(pivot["suffix"]),
                        crown_jewel=str(pivot["crown_jewel"]),
                    )
                    branch = self.state.ensure_branch(
                        branch_id,
                        str(pivot["vector_id"]),
                        str(pivot["title"]),
                        priority=int(pivot["priority"]) + severity_boost,
                        role=self._infer_branch_role(
                            vector_id=str(pivot["vector_id"]),
                            title=str(pivot["title"]),
                            objective=str(pivot["objective"]),
                            source_finding_id=finding_id,
                            crown_jewel=str(pivot["crown_jewel"]),
                        ),
                        owner="root",
                        parent_branch_id=parent_branch_id,
                        source_candidate_id=parent.source_candidate_id or parent_branch_id,
                        source_finding_id=finding_id,
                        objective=str(pivot["objective"]),
                        next_step=str(pivot["next_step"]),
                        crown_jewel=str(pivot["crown_jewel"]),
                        evidence=f"{finding_id}: {title} @ {component}".strip(),
                        watch_terms=list(pivot.get("watch_terms") or []),
                    )
                    branch.status = "open"
                    branch.last_report = f"Spawned from {finding_id}: {title[:100]}"
                    self.state.ensure_scan_todo(
                        branch_id,
                        branch.title,
                        priority=branch.priority,
                        source_candidate_id=branch.source_candidate_id or branch_id,
                    )
                    self.state.add_shared_note(
                        f"{parent.vector_id} -> {branch.vector_id}: {branch.title}"
                    )
            self._emit_control_plane(f"Root spawned follow-up branches from {finding_id}")

    def _reuse_or_allocate_followup_branch_id(
        self,
        *,
        parent_branch_id: str,
        finding_id: str,
        vector_id: str,
        suffix: str,
        crown_jewel: str,
    ) -> str:
        for branch in self.state.branches.values():
            if branch.source_finding_id != finding_id:
                continue
            if str(branch.vector_id) != str(vector_id):
                continue
            if str(branch.crown_jewel) != str(crown_jewel):
                continue
            return branch.id
        return f"{parent_branch_id}:{suffix}"

    def _branch_ids_for_action(self, name: str, args: dict[str, Any] | Any) -> list[str]:
        blob = f"{name} {self._preview_args(args)}"
        matches: list[str] = []
        if name == "agent_graph" and isinstance(args, dict):
            agent_id = str(args.get("agent_id") or "").strip()
            branch_id = self._agent_graph_branch_id(agent_id)
            if branch_id in self.state.branches:
                matches.append(branch_id)
        for branch in self.state.active_branches():
            terms = branch.watch_terms or []
            if not terms:
                continue
            if branch.id not in matches and any(term in blob for term in terms):
                matches.append(branch.id)
        return matches

    def _fallback_branch_ids_for_candidates(self, candidate_ids: list[str]) -> list[str]:
        if not candidate_ids:
            return []
        matches: list[str] = []
        seen: set[str] = set()
        candidate_set = {str(cid) for cid in candidate_ids if cid}
        for branch in self.state.active_branches():
            if (
                branch.id in candidate_set
                or branch.source_candidate_id in candidate_set
                or branch.parent_branch_id in candidate_set
            ):
                if branch.id not in seen:
                    seen.add(branch.id)
                    matches.append(branch.id)
        return matches

    @staticmethod
    def _chain_candidate_for_pair(prior: dict[str, Any], current: dict[str, Any]) -> dict[str, Any] | None:
        try:
            from vxis.agent.tools.finding_tools import _canonical_finding_type
        except Exception:
            def _canonical_finding_type(value: str) -> str:
                return str(value or "").lower().strip()

        prior_type = _canonical_finding_type(str(prior.get("finding_type", "")))
        current_type = _canonical_finding_type(str(current.get("finding_type", "")))
        prior_blob = " ".join(
            str(prior.get(key, "")).lower()
            for key in ("title", "description", "impact", "technical_analysis")
        )
        current_blob = " ".join(
            str(current.get(key, "")).lower()
            for key in ("title", "description", "impact", "technical_analysis")
        )

        if current_type in {"broken_access_control", "idor"}:
            if prior_type in {"weak_auth", "sql_injection"} and any(
                token in prior_blob for token in ("authentication bypass", "authenticated", "login", "token", "session")
            ):
                return {
                    "score": 300,
                    "rationale": "A proven authentication foothold was immediately reused to access data-bearing authenticated endpoints, demonstrating a concrete post-auth pivot.",
                    "crown_jewel": "authenticated data exfiltration",
                }
            if prior_type in {"weak_auth", "sql_injection"}:
                return {
                    "score": 240,
                    "rationale": "The initial foothold enables unauthorized object access and broader post-authenticated data reach.",
                    "crown_jewel": "account takeover or data exfiltration",
                }
            if prior_type == "information_disclosure":
                return {
                    "score": 170,
                    "rationale": "Leaked context shortened the path to unauthorized object access and wider data retrieval.",
                    "crown_jewel": "sensitive record exposure",
                }
        if current_type == "weak_auth":
            if prior_type in {"information_disclosure", "misconfiguration"}:
                return {
                    "score": 180,
                    "rationale": "Leaked deployment details or exposed configuration shortened the path to a working authentication bypass.",
                    "crown_jewel": "authenticated foothold",
                }
        if current_type == "sql_injection":
            if prior_type == "information_disclosure":
                return {
                    "score": 150,
                    "rationale": "Exposed routes or configuration pointed the attacker toward an injectable surface that now yields backend data.",
                    "crown_jewel": "DB dump",
                }
        if current_type == "ssrf":
            if prior_type in {"information_disclosure", "misconfiguration"}:
                return {
                    "score": 160,
                    "rationale": "Recon or exposed infrastructure details feed into a server-side fetch pivot toward internal resources.",
                    "crown_jewel": "internal service access",
                }
        if current_type == "xss":
            if prior_type in {"weak_auth", "broken_access_control", "information_disclosure"}:
                return {
                    "score": 130,
                    "rationale": "The existing session or weak authorization context makes script execution materially useful for takeover or privileged action abuse.",
                    "crown_jewel": "session takeover",
                }
        if prior_type == "sql_injection" and current_type in {"broken_access_control", "idor"} and any(
            token in current_blob for token in ("authenticated", "user data", "post-auth", "token", "session")
        ):
            return {
                "score": 220,
                "rationale": "The injection-derived foothold opened post-authenticated data-bearing endpoints, turning code/data execution into concrete data access.",
                "crown_jewel": "privileged data exfiltration",
            }
        return None

    async def _maybe_auto_link_chain(self, finding_id: str) -> None:
        try:
            from vxis.agent.tools.finding_tools import (
                _get_chains,
                _get_findings,
            )
        except Exception:
            return

        findings = _get_findings()
        current = next((f for f in findings if f.get("id") == finding_id), None)
        if not current:
            return

        existing_pairs = {
            tuple(c.get("finding_ids", []))
            for c in _get_chains()
            if isinstance(c.get("finding_ids"), list)
        }
        severity = str(current.get("severity", "low")).lower()
        if severity not in {"critical", "high", "medium"}:
            return
        best_candidate: dict[str, Any] | None = None
        for prior in reversed(findings[:-1]):
            pair = (str(prior["id"]), finding_id)
            if pair in existing_pairs:
                continue
            candidate = self._chain_candidate_for_pair(prior, current)
            if not candidate:
                continue
            candidate.update({"source_id": pair[0], "target_id": pair[1]})
            if best_candidate is None or int(candidate["score"]) > int(best_candidate["score"]):
                best_candidate = candidate
        if best_candidate is None:
            return
        result = await self.registry.dispatch("link_chain", {
            "finding_ids": [best_candidate["source_id"], best_candidate["target_id"]],
            "rationale": best_candidate["rationale"],
            "crown_jewel": best_candidate["crown_jewel"],
        })
        if result.ok:
            self._settle_branches_after_chain([best_candidate["source_id"], best_candidate["target_id"]])
            logger.info("auto-linked chain %s -> %s", best_candidate["source_id"], finding_id)

    def _suggest_chain_candidates(self, *, limit: int = 3) -> list[dict[str, str]]:
        try:
            from vxis.agent.tools.finding_tools import _get_chains, _get_findings
        except Exception:
            return []

        findings = list(_get_findings() or [])
        if len(findings) < 2:
            return []

        existing_pairs = {
            tuple(c.get("finding_ids", []))
            for c in _get_chains()
            if isinstance(c.get("finding_ids"), list)
        }
        suggestions: list[dict[str, Any]] = []
        for current in reversed(findings):
            severity = str(current.get("severity", "low")).lower()
            if severity not in {"critical", "high", "medium"}:
                continue
            for prior in reversed(findings):
                if prior.get("id") == current.get("id"):
                    continue
                pair = (str(prior.get("id", "")), str(current.get("id", "")))
                if not pair[0] or not pair[1] or pair in existing_pairs:
                    continue
                candidate = self._chain_candidate_for_pair(prior, current)
                if not candidate:
                    continue
                suggestions.append({
                    "source_id": pair[0],
                    "target_id": pair[1],
                    "source_type": str(prior.get("finding_type", "")),
                    "target_type": str(current.get("finding_type", "")),
                    "source_title": str(prior.get("title", "")),
                    "target_title": str(current.get("title", "")),
                    "source_component": str(prior.get("affected_component", "")),
                    "target_component": str(current.get("affected_component", "")),
                    "rationale": candidate["rationale"],
                    "crown_jewel": candidate["crown_jewel"],
                    "score": candidate["score"],
                })
        suggestions.sort(key=lambda item: int(item.get("score", 0)), reverse=True)
        deduped: list[dict[str, Any]] = []
        seen_pairs: set[tuple[str, str]] = set()
        seen_target_paths: set[tuple[str, str, str]] = set()
        seen_target_families: set[tuple[str, str]] = set()
        seen_family_pairs: set[tuple[str, str, str]] = set()
        for item in suggestions:
            pair = (str(item["source_id"]), str(item["target_id"]))
            if pair in seen_pairs:
                continue
            target_sig = (
                str(item.get("target_id", "")),
                str(item.get("target_type", "")),
                str(item.get("crown_jewel", "")),
            )
            if target_sig in seen_target_paths:
                continue
            family_sig = (
                str(item.get("target_type", "")),
                str(item.get("crown_jewel", "")),
            )
            if family_sig in seen_target_families:
                continue
            family_pair_sig = (
                str(item.get("source_type", "")),
                str(item.get("target_type", "")),
                str(item.get("crown_jewel", "")),
            )
            if family_pair_sig in seen_family_pairs:
                continue
            seen_pairs.add(pair)
            seen_target_paths.add(target_sig)
            seen_target_families.add(family_sig)
            seen_family_pairs.add(family_pair_sig)
            deduped.append(item)
            if len(deduped) >= limit:
                break
        return [
            {
                "source_id": str(item["source_id"]),
                "target_id": str(item["target_id"]),
                "source_type": str(item.get("source_type", "")),
                "target_type": str(item.get("target_type", "")),
                "source_title": str(item.get("source_title", "")),
                "target_title": str(item.get("target_title", "")),
                "source_component": str(item.get("source_component", "")),
                "target_component": str(item.get("target_component", "")),
                "rationale": str(item["rationale"]),
                "crown_jewel": str(item["crown_jewel"]),
            }
            for item in deduped
        ]

    async def _maybe_auto_link_suggested_chain(self) -> dict[str, Any] | None:
        candidates = self._suggest_chain_candidates(limit=3)
        if not candidates:
            return None
        candidate = candidates[0]
        result = await self.registry.dispatch("link_chain", {
            "finding_ids": [candidate["source_id"], candidate["target_id"]],
            "rationale": candidate["rationale"],
            "crown_jewel": candidate["crown_jewel"],
        })
        if not result.ok:
            return None
        if isinstance(result.data, dict) and result.data.get("dedup"):
            return None
        self._settle_branches_after_chain([candidate["source_id"], candidate["target_id"]])
        logger.info(
            "judge auto-linked suggested chain %s -> %s",
            candidate["source_id"],
            candidate["target_id"],
        )
        self.state.add_message("system", {
            "hint": (
                f"SYSTEM HINT: auto-linked chain {candidate['source_id']} -> {candidate['target_id']} "
                f"toward {candidate['crown_jewel']}. Re-evaluate whether finish_scan is now justified."
            ),
        })
        return {
            "source_id": candidate["source_id"],
            "target_id": candidate["target_id"],
            "crown_jewel": candidate["crown_jewel"],
        }

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
        return await self.brain.think_in_loop(messages, self._brain_tool_catalog())

    def _brain_tool_catalog(self) -> list[dict[str, Any]]:
        catalog = self.registry.describe_all()
        profile = self._llm_discipline_profile()
        if profile != "local_strict":
            return catalog

        focus = self._focus_branch()
        findings_count = len(self.state.findings)
        early = self.state.iteration <= self._focus_grace_iterations() and findings_count == 0

        core = {
            "finish_scan",
            "think",
            "wait",
            "report_finding",
            "query_findings",
            "link_chain",
            "verify_finding",
            "run_skill",
            "agent_graph",
        }
        recon = {
            "fingerprint_target",
            "list_playbooks",
            "load_playbook",
            "http_request",
            "browser_render",
            "browser_navigate",
            "browser_analyze_dom",
            "shell_exec",
        }
        auth = {
            "browser_fill_form",
            "browser_get_cookies",
            "browser_eval_js",
            "http_request",
            "browser_navigate",
            "shell_exec",
            "run_skill",
        }
        post_auth = {
            "browser_get_cookies",
            "browser_eval_js",
            "browser_navigate",
            "http_request",
            "shell_exec",
            "python_exec",
            "run_skill",
            "query_scan_memory",
        }
        xss_ssrf = {
            "browser_render",
            "browser_navigate",
            "browser_eval_js",
            "http_request",
            "shell_exec",
            "python_exec",
            "run_skill",
        }

        allowed = set(core)
        if early or focus is None:
            allowed |= recon
        if focus is not None:
            family = self._branch_family(focus)
            if family in {"auth", "injection"}:
                allowed |= auth
            if focus.role == "post_exploit_worker" or focus.phase in {"session_reuse", "privilege_probe", "data_access"}:
                allowed |= post_auth
            if family in {"xss", "ssrf"}:
                allowed |= xss_ssrf
            if family == "disclosure":
                allowed |= {"http_request", "browser_navigate", "shell_exec", "run_skill", "query_scan_memory"}
            if family == "idor":
                allowed |= {"http_request", "browser_navigate", "browser_get_cookies", "run_skill", "shell_exec"}

        filtered = [tool for tool in catalog if str(tool.get("name") or "") in allowed]
        return filtered or catalog
