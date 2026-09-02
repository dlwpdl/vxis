from __future__ import annotations

import logging
import re
from typing import Any

from vxis.agent.skills.enumerate_endpoints import classify_endpoint_error_preview
from vxis.agent.tools.skill_runner import redact_sensitive_output

logger = logging.getLogger(__name__)


class ScanLoopRunSkillHandoffMixin:
    async def _handle_auth_success_handoff(
        self, data: dict[str, Any], queue_skill: Any
    ) -> str | None:
        if not data.get("authenticated"):
            return None
        auth_token = str(data.get("token") or "")
        identities = list(data.get("identities") or [])
        if not identities and auth_token:
            user_info = dict(data.get("user_info") or {})
            identities = [
                {
                    "name": data.get("primary_identity") or "authenticated",
                    "token": auth_token,
                    "role": user_info.get("role", ""),
                    "email": user_info.get("email", ""),
                }
            ]
        self.state.record_auth_identities(identities)
        if isinstance(data.get("owner_map"), dict):
            self.state.object_owner_map.update(
                {str(key): str(value) for key, value in data.get("owner_map", {}).items()}
            )
        authz_params = self.state.authz_context_params()
        method = str(data.get("method") or "?")
        severity = "critical" if "sqli" in method else "high"
        finding_type = "sql_injection" if "sqli" in method else "weak_auth"
        login_endpoint = str(data.get("login_endpoint") or self.state.target)
        control_checks = dict(data.get("control_checks") or {})
        poc_blob = redact_sensitive_output(
            data.get("poc_http_exchange")
            or (
                f"Method: {method}\n"
                "Credentials used: [redacted]\n"
                "Token: [redacted]\n"
                "User info: [redacted]\n"
                f"Control checks: {control_checks}"
            )
        )
        await self._dispatch_report_finding_checked(
            self._build_report_finding_args(
                title=f"Authentication bypass via {method}",
                severity=severity,
                finding_type=finding_type,
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
            )
        )
        queue_skill(
            "execute_chain",
            self.state.iteration + 2,
            {
                "template": "post_auth_crown",
                "token": auth_token,
                **authz_params,
                "url_pattern": self.state.target.rstrip("/") + "/api/users/{id}",
            },
        )
        self.state.add_message(
            "user",
            (
                f"SKILL CHAIN: Auth bypass confirmed via {method}! "
                "Token acquired. Post-auth chain executor queued."
            ),
        )
        return auth_token or None

    def _queue_recon_surface_followups(
        self, accessible: list[dict[str, Any]], queue_skill: Any
    ) -> None:
        interesting_urls: list[str] = []
        seen_urls: set[str] = set()
        for endpoint in accessible:
            path = str(endpoint.get("path") or "")
            if "?" not in path and "search" not in path.lower():
                continue
            full_url = self.state.target.rstrip("/") + path
            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)
            interesting_urls.append(full_url)
            if len(interesting_urls) >= 3:
                break
        for index, full_url in enumerate(interesting_urls, start=1):
            queue_skill(
                "test_injection",
                self.state.iteration + 2,
                {"url": full_url},
                alias=f"test_injection__recon{index}",
            )
            queue_skill(
                "test_xss",
                self.state.iteration + 3,
                {"url": full_url},
                alias=f"test_xss__recon{index}",
            )
            queue_skill(
                "test_ssrf",
                self.state.iteration + 4,
                {"url": full_url},
                alias=f"test_ssrf__recon{index}",
            )

    def _queue_recon_idor_followups(
        self, accessible: list[dict[str, Any]], queue_skill: Any
    ) -> None:
        idor_patterns_seen: set[str] = set()
        for endpoint in accessible:
            path = str(endpoint.get("path") or "")
            match = re.search(r"^(/[^?]*?/)\d+(/|$)", path)
            if not match:
                continue
            base = match.group(1).rstrip("/")
            pattern = self.state.target.rstrip("/") + base + "/{id}"
            if pattern in idor_patterns_seen:
                continue
            idor_patterns_seen.add(pattern)
            queue_skill(
                "test_idor",
                self.state.iteration + 5,
                {
                    "url_pattern": pattern,
                    **self.state.authz_context_params(),
                    "_skill_override": "test_idor",
                },
                alias=f"test_idor_{len(idor_patterns_seen)}",
            )
            if len(idor_patterns_seen) >= 4:
                break
        if idor_patterns_seen:
            return
        for candidate in (
            "/api/users/{id}",
            "/api/user/{id}",
            "/api/orders/{id}",
            "/api/account/{id}",
            "/users/{id}",
            "/profile/{id}",
        ):
            pattern = self.state.target.rstrip("/") + candidate
            queue_skill(
                "test_idor",
                self.state.iteration + 5,
                {
                    "url_pattern": pattern,
                    **self.state.authz_context_params(),
                    "_skill_override": "test_idor",
                },
                alias=f"test_idor_probe_{candidate.strip('/').replace('/', '_')}",
            )

    async def _handle_enumerate_endpoints_handoff(
        self,
        data: dict[str, Any],
        queue_skill: Any,
    ) -> None:
        accessible = list(data.get("accessible") or [])
        self._queue_recon_surface_followups(accessible, queue_skill)
        self._queue_recon_idor_followups(accessible, queue_skill)
        for endpoint in list(data.get("errors") or [])[:5]:
            preview = str(endpoint.get("error_preview") or "")[:300]
            if (
                str(endpoint.get("error_kind") or classify_endpoint_error_preview(preview))
                != "actionable"
            ):
                continue
            await self._dispatch_report_finding_checked(
                {
                    "title": f"HTTP 500 on {endpoint['path']}",
                    "severity": "medium",
                    "finding_type": "error_oracle",
                    "affected_component": self.state.target + endpoint["path"],
                    "description": f"Endpoint returns HTTP 500 ({endpoint.get('size', '?')}B) with actionable backend error details.",
                    "evidence": preview,
                }
            )

    async def _handle_execute_chain_handoff(self, data: dict[str, Any]) -> None:
        for finding in list(data.get("findings") or [])[:10]:
            if not isinstance(finding, dict):
                continue
            args = self._build_report_finding_args(
                title=str(finding.get("title") or "Validated attack chain finding"),
                severity=str(finding.get("severity") or "high"),
                finding_type=str(finding.get("finding_type") or "attack_chain"),
                affected_component=str(
                    finding.get("affected_component") or finding.get("endpoint") or self.state.target
                ),
                description=str(
                    finding.get("description")
                    or "The chain executor validated a post-authenticated follow-up finding."
                ),
                impact=str(
                    finding.get("impact")
                    or "A foothold can be chained into protected data or authorization impact."
                ),
                technical_analysis=str(
                    finding.get("technical_analysis") or finding.get("evidence") or data.get("steps", [])[:3]
                ),
                poc_description=str(
                    finding.get("poc_description")
                    or "Replay the chain steps and compare each child control."
                ),
                poc_script_code=str(finding.get("poc_script_code") or data.get("steps", [])[:3]),
                remediation_steps=str(
                    finding.get("remediation_steps")
                    or "Fix the broken trust boundary identified by the validated chain."
                ),
                endpoint=str(finding.get("endpoint") or self.state.target),
                method=str(finding.get("method") or "GET"),
                cwe=str(finding.get("cwe") or ""),
            )
            if finding.get("verification_method"):
                args["verification_method"] = str(finding.get("verification_method"))
            if isinstance(finding.get("evidence_artifact"), dict):
                args["evidence_artifact"] = dict(finding["evidence_artifact"])
            if finding.get("proof") is not None:
                args["proof"] = finding.get("proof")
            await self._dispatch_report_finding_checked(args)

    async def _handle_post_auth_enum_handoff(self, data: dict[str, Any]) -> None:
        if data.get("identities"):
            self.state.record_auth_identities(data.get("identities"))
        if isinstance(data.get("owner_map"), dict):
            self.state.object_owner_map.update(
                {str(key): str(value) for key, value in data.get("owner_map", {}).items()}
            )
        control_evidence = dict(data.get("control_evidence") or {})
        same_data_without_auth = list(control_evidence.get("same_data_without_auth") or [])
        if same_data_without_auth:
            same_paths = [entry["path"] for entry in same_data_without_auth[:5]]
            same_data_sample = str(same_data_without_auth[:3])[:1200]
            same_data_severity = "high" if len(same_data_without_auth) >= 2 else "medium"
            self.state.record_retrieval_observation(
                finding_type="broken_access_control",
                component=self.state.target,
                retrieval_kind="missing_auth_on_authenticated_surface",
                summary=(
                    "Authenticated-route data was returned without authentication on "
                    f"{len(same_data_without_auth)} endpoint(s): {same_paths}"
                ),
                sample=same_data_sample,
            )
            await self._dispatch_report_finding_checked(
                self._build_report_finding_args(
                    title=f"Missing authentication on {len(same_data_without_auth)} endpoint(s)",
                    severity=same_data_severity,
                    finding_type="broken_access_control",
                    affected_component=self.state.target,
                    description=(
                        "Endpoints returned the same data with and without authentication, "
                        f"including: {same_paths}"
                    ),
                    impact=(
                        "Anonymous users may retrieve authenticated-route data or configuration, "
                        "which weakens trust boundaries and can expose privileged context."
                    ),
                    technical_analysis=(
                        "The post_auth_enum skill compared authenticated and unauthenticated "
                        "responses and observed identical content on authenticated-route probes. "
                        f"Control evidence: {control_evidence}."
                    ),
                    poc_description=(
                        "Request the listed endpoints with and without the acquired session and "
                        "confirm that the same data is returned in both cases."
                    ),
                    poc_script_code=(
                        "Same-data-without-auth evidence: "
                        f"{same_data_sample}\nFull control evidence: {control_evidence}"
                    ),
                    remediation_steps=(
                        "Enforce authentication before returning authenticated-route data and "
                        "verify anonymous requests receive 401/403 or a redacted response."
                    ),
                    endpoint=self.state.target,
                    method="GET",
                    extra_evidence=[
                        self._retrieval_evidence_item(
                            title="Same Data Returned Without Authentication",
                            retrieval_kind="missing_auth_on_authenticated_surface",
                            summary=(
                                "Authenticated-route probes returned identical content without "
                                f"authentication on {len(same_data_without_auth)} endpoint(s)."
                            ),
                            sample=same_data_sample,
                        ),
                    ],
                )
            )
        user_data = list(data.get("user_data_exposed") or [])
        if not user_data:
            return
        paths = [entry["path"] for entry in user_data[:5]]
        user_data_sample = str(user_data[:3])[:1200]
        self.state.record_retrieval_observation(
            finding_type="broken_access_control",
            component=self.state.target,
            retrieval_kind="post_auth_data_access",
            summary=f"Sensitive user data observed on {len(user_data)} authenticated endpoint(s): {paths}",
            sample=user_data_sample,
        )
        await self._dispatch_report_finding_checked(
            self._build_report_finding_args(
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
                    f"Control evidence: {control_evidence}\nUser data samples: {user_data_sample}"
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
            )
        )
