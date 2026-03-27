"""MobileDynamicAgent — Frida 동적 분석 에이전트."""

from __future__ import annotations

import json
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class MobileDynamicAgent(BaseAgent):
    """Frida 기반 런타임 분석 — SSL 피닝 우회, 루트 탐지 우회, 메서드 트레이싱."""

    agent_id = "mobile_dynamic"
    description = "Frida-based dynamic analysis: SSL bypass, root bypass, method tracing, crypto monitoring"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []
        metadata: dict[str, Any] = {}

        package = getattr(context, "app_package", "") or ""
        platform = getattr(context, "platform", "android")

        if not package:
            return AgentResult(
                agent_id=self.agent_id,
                findings=findings,
                hypotheses=hypotheses,
                status="skipped",
                metadata={"reason": "No app package provided"},
            )

        frida_available = self._check_frida()
        metadata["frida_available"] = frida_available

        if not frida_available:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title="Frida Not Available — Dynamic Analysis Skipped",
                severity=Severity.INFO,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    "Frida is not installed or device not connected. "
                    "Install frida-server on the target device and frida-tools on host."
                ),
                tags=["mobile", "frida", "setup"],
            ))
            return AgentResult(
                agent_id=self.agent_id,
                findings=findings,
                hypotheses=hypotheses,
                status="skipped",
                metadata=metadata,
            )

        # 1. SSL 피닝 우회 시도
        ssl_result = await self._attempt_ssl_bypass(package, platform)
        metadata["ssl_bypass"] = ssl_result
        if ssl_result.get("bypassed"):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title="SSL Certificate Pinning Bypassed via Frida",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=(
                    f"SSL pinning bypassed using script: {ssl_result.get('script', 'unknown')}. "
                    "All HTTPS traffic can now be intercepted with a MITM proxy."
                ),
                response=json.dumps(ssl_result),
                tags=["mobile", "ssl", "pinning", "bypass", platform],
            ))
            hypotheses.append(Hypothesis(
                title=f"Full API traffic interception on {target}",
                rationale="SSL pinning bypassed — all encrypted traffic visible",
                probability=0.95,
                impact=0.9,
                suggested_agent="mobile_network",
            ))

        # 2. 루트/탈옥 탐지 우회
        root_result = await self._attempt_root_bypass(package, platform)
        metadata["root_bypass"] = root_result
        if root_result.get("bypassed"):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title="Root/Jailbreak Detection Bypassed",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"Root detection bypassed using: {root_result.get('script', 'unknown')}. "
                    "Security controls relying solely on root detection can be circumvented."
                ),
                response=json.dumps(root_result),
                tags=["mobile", "root", "bypass", platform],
            ))

        # 3. 생체 인증 우회
        bio_result = await self._attempt_biometric_bypass(package, platform)
        metadata["biometric_bypass"] = bio_result
        if bio_result.get("bypassed"):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title="Biometric Authentication Bypassed at Runtime",
                severity=Severity.CRITICAL,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=(
                    "Biometric (fingerprint/face) authentication bypassed using Frida. "
                    "App authentication can be circumvented without valid biometrics."
                ),
                response=json.dumps(bio_result),
                tags=["mobile", "biometric", "bypass", "auth", platform],
            ))
            hypotheses.append(Hypothesis(
                title=f"Account takeover via biometric bypass on {target}",
                rationale="Biometric authentication bypassed — full account access possible",
                probability=0.8,
                impact=0.95,
                suggested_agent="api",
            ))

        # 4. 크립토 API 모니터링
        crypto_result = await self._monitor_crypto(package, platform)
        metadata["crypto"] = crypto_result
        for weak_algo in crypto_result.get("weak_algorithms", []):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Weak Cryptography at Runtime: {weak_algo}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.CODE_FINDING,
                description=(
                    f"App uses {weak_algo} at runtime. "
                    "Weak algorithms can be broken to decrypt intercepted data."
                ),
                tags=["mobile", "crypto", "weak", platform],
            ))

        # 5. 인앱 구매 우회
        iap_result = await self._attempt_iap_bypass(package, platform)
        metadata["iap_bypass"] = iap_result
        if iap_result.get("bypassed"):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title="In-App Purchase Verification Bypassed",
                severity=Severity.CRITICAL,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"IAP verification bypassed: {iap_result.get('method', 'unknown')}. "
                    "Premium features accessible without payment."
                ),
                response=json.dumps(iap_result),
                tags=["mobile", "iap", "bypass", "business_logic", platform],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata=metadata,
        )

    def _check_frida(self) -> bool:
        import shutil
        return shutil.which("frida") is not None or shutil.which("frida-ps") is not None

    async def _attempt_ssl_bypass(
        self, package: str, platform: str,
    ) -> dict[str, Any]:
        try:
            from vxis.plugins.mobile.frida_scanner import FridaScannerPlugin
            plugin = FridaScannerPlugin()
            results = await plugin.run_script_suite(package, platform, ["ssl_bypass"])
            for script_name, result in results.items():
                if isinstance(result, dict) and result.get("bypassed"):
                    return {"bypassed": True, "script": script_name}
        except Exception as exc:
            return {"bypassed": False, "error": str(exc)}
        return {"bypassed": False}

    async def _attempt_root_bypass(
        self, package: str, platform: str,
    ) -> dict[str, Any]:
        try:
            from vxis.plugins.mobile.frida_scanner import FridaScannerPlugin
            plugin = FridaScannerPlugin()
            results = await plugin.run_script_suite(package, platform, ["root_bypass"])
            for script_name, result in results.items():
                if isinstance(result, dict) and result.get("bypassed"):
                    return {"bypassed": True, "script": script_name}
        except Exception as exc:
            return {"bypassed": False, "error": str(exc)}
        return {"bypassed": False}

    async def _attempt_biometric_bypass(
        self, package: str, platform: str,
    ) -> dict[str, Any]:
        try:
            from vxis.plugins.mobile.frida_scanner import FridaScannerPlugin
            plugin = FridaScannerPlugin()
            results = await plugin.run_script_suite(package, platform, ["auth_bypass"])
            for script_name, result in results.items():
                if isinstance(result, dict) and result.get("bypassed"):
                    return {"bypassed": True, "script": script_name}
        except Exception as exc:
            return {"bypassed": False, "error": str(exc)}
        return {"bypassed": False}

    async def _monitor_crypto(
        self, package: str, platform: str,
    ) -> dict[str, Any]:
        try:
            from vxis.plugins.mobile.frida_scanner import FridaScannerPlugin
            plugin = FridaScannerPlugin()
            results = await plugin.run_script_suite(package, platform, ["crypto"])
            weak_algos: list[str] = []
            for result in results.values():
                if isinstance(result, dict):
                    weak_algos.extend(result.get("weak_algorithms", []))
            return {"weak_algorithms": weak_algos}
        except Exception as exc:
            return {"weak_algorithms": [], "error": str(exc)}

    async def _attempt_iap_bypass(
        self, package: str, platform: str,
    ) -> dict[str, Any]:
        try:
            from vxis.plugins.mobile.frida_scanner import FridaScannerPlugin
            plugin = FridaScannerPlugin()
            results = await plugin.run_script_suite(package, platform, ["iap_bypass"])
            for script_name, result in results.items():
                if isinstance(result, dict) and result.get("bypassed"):
                    return {"bypassed": True, "method": script_name}
        except Exception as exc:
            return {"bypassed": False, "error": str(exc)}
        return {"bypassed": False}
