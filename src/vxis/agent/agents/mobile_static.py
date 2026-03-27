"""MobileStaticAgent — 모바일 앱 정적 분석 오케스트레이션 에이전트."""

from __future__ import annotations

import json
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class MobileStaticAgent(BaseAgent):
    """APK/IPA 정적 분석 — 시크릿, 매니페스트, 바이너리 보호, SDK 탐지."""

    agent_id = "mobile_static"
    description = "Android APK / iOS IPA static analysis: secrets, manifest, binary protections"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []
        metadata: dict[str, Any] = {}

        # 바이너리 경로는 context 또는 target에서 추론
        binary_path = getattr(context, "binary_path", "") or ""
        platform = getattr(context, "platform", "android")

        # 플랫폼 감지
        if binary_path.endswith(".apk"):
            platform = "android"
        elif binary_path.endswith(".ipa"):
            platform = "ios"

        if not binary_path:
            return AgentResult(
                agent_id=self.agent_id,
                findings=findings,
                hypotheses=hypotheses,
                status="skipped",
                metadata={"reason": "No binary path provided"},
            )

        # 1. 전체 정적 분석 실행
        analysis = await self._run_static_analysis(binary_path, platform)
        metadata["analysis"] = analysis

        # 2. 하드코딩 시크릿 → Evidence
        for secret in analysis.get("secrets", []):
            sev = self._secret_severity(secret["type"])
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Hardcoded {secret['type']}: {secret['value_preview']}",
                severity=sev,
                evidence_type=EvidenceType.CODE_FINDING,
                description=(
                    f"Found {secret['type']} hardcoded at "
                    f"{secret['file']}:{secret['line']}. "
                    f"Preview: {secret['value_preview']}"
                ),
                response=json.dumps(secret, ensure_ascii=False),
                tags=["mobile", "secret", "hardcoded", platform],
            ))
            hypotheses.append(Hypothesis(
                title=f"Exploit hardcoded {secret['type']} for {target}",
                rationale=(
                    "Hardcoded credential found in binary. "
                    "Key can be extracted to access backend services."
                ),
                probability=0.85,
                impact=0.9,
                suggested_agent="api",
            ))

        # 3. 내보낸 컴포넌트 → Evidence
        for comp_list_key in ("exported_activities", "exported_services",
                               "exported_receivers", "exported_providers"):
            for comp in analysis.get(comp_list_key, []):
                comp_name = comp.get("name", "")
                comp_type = comp_list_key.replace("exported_", "").rstrip("s")
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Exported {comp_type}: {comp_name.split('.')[-1]}",
                    severity=Severity.HIGH if comp_type in ("activity", "provider") else Severity.MEDIUM,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"{comp_name} is exported without explicit permission. "
                        f"Intent filters: {comp.get('intent_filters', [])}"
                    ),
                    response=json.dumps(comp, ensure_ascii=False),
                    tags=["mobile", "android", "component", comp_type],
                ))

        # 4. debuggable APK
        if analysis.get("debuggable"):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title="Debuggable APK — attach debugger possible",
                severity=Severity.CRITICAL,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    "APK is compiled with android:debuggable=true. "
                    "Attackers can attach debuggers via ADB to inspect memory and bypass logic."
                ),
                tags=["mobile", "android", "debuggable"],
            ))
            hypotheses.append(Hypothesis(
                title=f"Runtime memory extraction via debuggable APK on {target}",
                rationale="Debuggable flag allows ADB debug attachment",
                probability=0.9,
                impact=0.95,
                suggested_agent="mobile_dynamic",
            ))

        # 5. 바이너리 보호 누락 → 가설
        bp = analysis.get("binary_protection", {})
        if not bp.get("pie") or not bp.get("stack_canary"):
            missing = []
            if not bp.get("pie"):
                missing.append("PIE")
            if not bp.get("stack_canary"):
                missing.append("Stack Canary")
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Binary protections missing: {', '.join(missing)}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"Binary lacks {', '.join(missing)} protections. "
                    "Memory corruption vulnerabilities are more exploitable."
                ),
                tags=["mobile", "binary", "protection"] + [m.lower() for m in missing],
            ))

        status = "completed" if not analysis.get("error") else "partial"
        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status=status,
            metadata=metadata,
        )

    async def _run_static_analysis(
        self, binary_path: str, platform: str,
    ) -> dict[str, Any]:
        """MobileAnalyzer로 정적 분석 실행."""
        try:
            from vxis.plugins.mobile.apk_analyzer import APKAnalyzerPlugin
            from vxis.plugins.mobile.ipa_analyzer import IPAAnalyzerPlugin

            if platform == "android":
                plugin = APKAnalyzerPlugin()
                return await plugin.run_full_analysis(binary_path)
            else:
                plugin = IPAAnalyzerPlugin()
                return await plugin.run_full_analysis(binary_path)
        except Exception as exc:
            return {"error": str(exc), "secrets": [], "binary_protection": {}}

    def _secret_severity(self, secret_type: str) -> Severity:
        critical_types = {
            "AWS Access Key ID", "AWS Secret Key", "Private Key Header",
            "Stripe Live Key", "Bearer Token Hardcoded",
        }
        high_types = {
            "GitHub Token", "Generic Password", "Generic Secret",
            "Google API Key", "Generic API Key",
        }
        if secret_type in critical_types:
            return Severity.CRITICAL
        if secret_type in high_types:
            return Severity.HIGH
        return Severity.MEDIUM
