"""MobileScanContext — Mobile pentesting phase 간 공유 상태.

ScanContext를 확장하여 iOS/Android 모바일 앱 분석에 필요한
모든 모바일 특화 필드를 추가.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from vxis.models.finding import Finding
from vxis.pipeline.context import ScanContext

logger = logging.getLogger(__name__)


@dataclass
class MobileScanContext(ScanContext):
    """모든 Mobile Phase가 공유하는 스캔 상태.

    ScanContext를 상속하여 모바일 앱 분석에 특화된 필드를 추가.
    iOS/Android 정적·동적 분석, 네트워크 분석, 스토리지 분석 결과를 통합 관리.

    Usage:
        ctx = MobileScanContext(
            target="com.example.app",
            platform="android",
            app_binary_path="/path/to/app.apk",
        )
    """

    # ── 앱 기본 정보 ──
    platform: str = "android"  # "ios" | "android"
    app_package: str = ""  # bundle ID (iOS) / package name (Android)
    app_version: str = ""
    app_binary_path: str = ""  # APK or IPA 경로

    # ── Android SDK 버전 ──
    min_sdk: int | None = None
    target_sdk: int | None = None

    # ── 퍼미션 + 컴포넌트 ──
    permissions: list[str] = field(default_factory=list)
    exported_components: list[dict[str, Any]] = field(default_factory=list)

    # ── URL Scheme / Deep Link ──
    url_schemes: list[str] = field(default_factory=list)

    # ── API 엔드포인트 (정적 + 동적 합산) ──
    # api_endpoints는 ScanContext에 이미 있음 — 모바일에서 재사용

    # ── 하드코딩된 시크릿 ──
    hardcoded_secrets: list[dict[str, Any]] = field(default_factory=list)

    # ── 로컬 스토리지 취약점 ──
    storage_findings: list[dict[str, Any]] = field(default_factory=list)

    # ── SSL Pinning / Root Detection ──
    ssl_pinning_detected: bool = False
    root_detection_detected: bool = False

    # ── 난독화 수준 ──
    obfuscation_level: str = "none"  # "none" | "basic" | "advanced"

    # ── 서드파티 SDK ──
    third_party_sdks: list[dict[str, Any]] = field(default_factory=list)

    # ── Frida 스크립트 추적 ──
    frida_scripts_used: list[str] = field(default_factory=list)

    # ── 바이너리 보호 수준 ──
    binary_protections: dict[str, Any] = field(default_factory=dict)

    # ── 네트워크 트래픽 캡처 결과 ──
    intercepted_flows: list[dict[str, Any]] = field(default_factory=list)

    # ── OWASP Mobile Top 10 매핑 ──
    owasp_mobile_coverage: dict[str, list[str]] = field(default_factory=dict)

    # ── 백업 분석 결과 ──
    backup_findings: list[dict[str, Any]] = field(default_factory=list)

    # ── IPC 보안 결과 ──
    ipc_findings: list[dict[str, Any]] = field(default_factory=list)

    # ── 비즈니스 로직 결과 ──
    business_logic_findings: list[dict[str, Any]] = field(default_factory=list)

    def add_owasp_finding(self, owasp_id: str, finding_id: str) -> None:
        """OWASP Mobile Top 10 분류에 Finding ID를 등록."""
        if owasp_id not in self.owasp_mobile_coverage:
            self.owasp_mobile_coverage[owasp_id] = []
        if finding_id not in self.owasp_mobile_coverage[owasp_id]:
            self.owasp_mobile_coverage[owasp_id].append(finding_id)

    def add_secret(
        self,
        secret_type: str,
        value: str,
        location: str,
        context: str = "",
    ) -> None:
        """하드코딩된 시크릿 등록."""
        self.hardcoded_secrets.append({
            "type": secret_type,
            "value_preview": value[:20] + "..." if len(value) > 20 else value,
            "location": location,
            "context": context[:200],
        })
        logger.info(
            "[SECRET] %s found in %s: %s...",
            secret_type, location, value[:15],
        )

    def add_storage_finding(
        self,
        storage_type: str,
        description: str,
        location: str,
        data_preview: str = "",
        severity: str = "medium",
    ) -> None:
        """로컬 스토리지 취약점 등록."""
        self.storage_findings.append({
            "storage_type": storage_type,
            "description": description,
            "location": location,
            "data_preview": data_preview[:200],
            "severity": severity,
        })

    def add_sdk(self, name: str, version: str, category: str, risk: str = "low") -> None:
        """서드파티 SDK 등록."""
        for sdk in self.third_party_sdks:
            if sdk["name"] == name:
                return
        self.third_party_sdks.append({
            "name": name,
            "version": version,
            "category": category,
            "risk": risk,
        })

    @property
    def is_android(self) -> bool:
        return self.platform.lower() == "android"

    @property
    def is_ios(self) -> bool:
        return self.platform.lower() == "ios"

    @property
    def critical_findings(self) -> list[Finding]:
        from vxis.models.finding import Severity
        return [f for f in self.findings if f.severity == Severity.critical]

    @property
    def high_findings(self) -> list[Finding]:
        from vxis.models.finding import Severity
        return [f for f in self.findings if f.severity == Severity.high]

    @property
    def owasp_coverage_summary(self) -> str:
        """OWASP Mobile Top 10 커버리지 요약 문자열 반환."""
        covered = len(self.owasp_mobile_coverage)
        return f"{covered}/10 OWASP Mobile Top 10 categories covered"
