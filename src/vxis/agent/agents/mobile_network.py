"""MobileNetworkAgent — 모바일 앱 네트워크 트래픽 분석 에이전트."""

from __future__ import annotations

import json
import re
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class MobileNetworkAgent(BaseAgent):
    """모바일 네트워크 트래픽 분석 — API 엔드포인트 맵핑, 인증 분석, 민감 데이터 누출."""

    agent_id = "mobile_network"
    description = "Mobile network traffic analysis: API mapping, auth tokens, sensitive data leakage"

    # 탐지 패턴
    _JWT_PATTERN = re.compile(
        r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'
    )
    _SENSITIVE_RESPONSE_PATTERN = re.compile(
        r'"(?:password|passwd|secret|api_key|ssn|credit_card|cvv|pin)["\s]*:',
        re.IGNORECASE,
    )
    _HTTP_ENDPOINT_PATTERN = re.compile(
        r'https?://[^\s"\'<>]+(?:/api/|/v\d+/|/graphql|/rest/)[^\s"\'<>]*',
    )

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []
        metadata: dict[str, Any] = {}

        # 1. 프록시 기반 트래픽 캡처
        flows = await self._capture_traffic(target)
        metadata["captured_flows"] = len(flows)

        # 2. 캡처된 트래픽 분석
        for flow in flows:
            # JWT 토큰 분석
            auth_header = flow.get("request_headers", {}).get("Authorization", "")
            jwt_match = self._JWT_PATTERN.search(auth_header)
            if jwt_match:
                jwt = jwt_match.group(0)
                jwt_issues = self._analyze_jwt(jwt)
                for issue in jwt_issues:
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"JWT Issue in Traffic: {issue['type']}",
                        severity=Severity.HIGH if issue["type"] == "alg_none" else Severity.MEDIUM,
                        evidence_type=EvidenceType.HTTP_EXCHANGE,
                        description=issue["description"],
                        request=f"{flow.get('method', 'GET')} {flow.get('url', '')}",
                        response=f"JWT: {jwt[:50]}...",
                        tags=["mobile", "jwt", "auth", issue["type"]],
                    ))

            # 응답에 민감 데이터 노출
            response_body = flow.get("response_body", "")
            if self._SENSITIVE_RESPONSE_PATTERN.search(response_body):
                url = flow.get("url", "")
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Sensitive Data in API Response: {self._short_url(url)}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.HTTP_EXCHANGE,
                    description=(
                        "API response contains sensitive field names "
                        "(password, secret, api_key, etc.). "
                        "Verify if sensitive data is returned unnecessarily."
                    ),
                    request=f"{flow.get('method', 'GET')} {url}",
                    response=response_body[:500],
                    tags=["mobile", "api", "sensitive_data"],
                ))
                hypotheses.append(Hypothesis(
                    title=f"Data over-exposure in mobile API on {target}",
                    rationale="Sensitive fields returned in response — OWASP API3 pattern",
                    probability=0.7,
                    impact=0.85,
                    suggested_agent="api",
                ))

            # HTTP (비HTTPS) 통신
            url = flow.get("url", "")
            if url.startswith("http://"):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Cleartext HTTP Communication: {self._short_url(url)}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.HTTP_EXCHANGE,
                    description=(
                        f"App communicates over unencrypted HTTP: {url}. "
                        "All data including credentials is transmitted in plaintext."
                    ),
                    request=f"{flow.get('method', 'GET')} {url}",
                    tags=["mobile", "http", "cleartext", "insecure_communication"],
                ))

        # 3. API 엔드포인트 맵 생성
        endpoints = self._extract_endpoints(flows)
        metadata["discovered_endpoints"] = endpoints

        if len(endpoints) > 0:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Mobile API Attack Surface: {len(endpoints)} endpoints discovered",
                severity=Severity.INFO,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=(
                    f"Discovered {len(endpoints)} API endpoints from mobile traffic. "
                    f"Sample: {', '.join(endpoints[:5])}"
                ),
                response=json.dumps(endpoints[:30], ensure_ascii=False),
                tags=["mobile", "api", "discovery", "attack_surface"],
            ))
            if len(endpoints) > 10:
                hypotheses.append(Hypothesis(
                    title=f"IDOR/mass assignment across {len(endpoints)} endpoints on {target}",
                    rationale="Large API surface increases attack opportunity",
                    probability=0.6,
                    impact=0.8,
                    suggested_agent="api",
                ))

        # 4. App Links / Deep Link 검증
        deep_link_findings = await self._check_deep_links(target)
        findings.extend(deep_link_findings)

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata=metadata,
        )

    async def _capture_traffic(self, target: str) -> list[dict[str, Any]]:
        """X-Ray (mitmproxy) 또는 캐시된 플로우에서 트래픽 읽기."""
        try:
            from vxis.interaction.xray import FlowAnalyzer
            analyzer = FlowAnalyzer()
            # 이미 캡처된 플로우 파일이 있으면 로드
            import shutil
            if not shutil.which("mitmdump"):
                return []
            flows = analyzer.load_flows() if hasattr(analyzer, "load_flows") else []
            return [
                {
                    "url": f.url if hasattr(f, "url") else "",
                    "method": f.method if hasattr(f, "method") else "",
                    "request_headers": f.request_headers if hasattr(f, "request_headers") else {},
                    "response_body": f.response_body if hasattr(f, "response_body") else "",
                    "status_code": f.status_code if hasattr(f, "status_code") else 0,
                }
                for f in flows
            ]
        except Exception:
            return []

    def _analyze_jwt(self, token: str) -> list[dict[str, str]]:
        """JWT 취약점 분석."""
        import base64
        issues = []
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return issues
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            if header.get("alg", "").lower() == "none":
                issues.append({
                    "type": "alg_none",
                    "description": "JWT uses alg:none — signatures not verified",
                })
            if "exp" not in payload:
                issues.append({
                    "type": "no_expiry",
                    "description": "JWT has no 'exp' claim — token never expires",
                })
            if header.get("alg", "").upper() in ("HS256",) and len(parts[2]) < 43:
                issues.append({
                    "type": "weak_signature",
                    "description": "JWT signature appears short — possible weak secret",
                })
        except Exception:
            pass
        return issues

    def _extract_endpoints(self, flows: list[dict[str, Any]]) -> list[str]:
        """트래픽에서 API 엔드포인트 추출."""
        from urllib.parse import urlparse
        endpoints: set[str] = set()
        for flow in flows:
            url = flow.get("url", "")
            if url:
                parsed = urlparse(url)
                path = parsed.path
                if any(k in path for k in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
                    endpoints.add(path)
        return sorted(endpoints)

    async def _check_deep_links(self, target: str) -> list[Evidence]:
        """App Links / Universal Links 보안 확인."""
        results: list[Evidence] = []
        try:
            from vxis.interaction.hands import SessionManager
            api_base = target if target.startswith("http") else f"https://{target}"
            mgr = SessionManager()
            session = await mgr.get_session(api_base)

            for path, platform in [
                ("/.well-known/assetlinks.json", "Android"),
                ("/.well-known/apple-app-site-association", "iOS"),
            ]:
                try:
                    resp = await session.get(path)
                    if resp.status == 200:
                        results.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"{platform} App Links configured: {path}",
                            severity=Severity.INFO,
                            evidence_type=EvidenceType.HTTP_EXCHANGE,
                            description=f"{path} found — {platform} App/Universal Links active",
                            response=resp.text[:500],
                            tags=["mobile", "deep_link", platform.lower()],
                        ))
                    elif resp.status == 404:
                        results.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"{platform} App Links NOT configured",
                            severity=Severity.LOW,
                            evidence_type=EvidenceType.MISCONFIGURATION,
                            description=(
                                f"{path} not found. Without App Links, "
                                "URL schemes may be hijackable."
                            ),
                            tags=["mobile", "deep_link", platform.lower(), "missing"],
                        ))
                except Exception:
                    continue

            await mgr.close_all()
        except Exception:
            pass

        return results

    def _short_url(self, url: str, max_len: int = 60) -> str:
        if len(url) <= max_len:
            return url
        return url[:max_len] + "..."
