"""MobilePipeline — 20 Phase 모바일 앱 펜테스트 오케스트레이터.

iOS/Android 앱 보안 분석 전 과정을 자동화.
ScanPipeline과 동일한 패턴: async phase 메서드, graceful degradation,
bilingual 텍스트(|||), MobileScanContext 데이터 버스.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable

from vxis.pipeline.mobile_context import MobileScanContext

logger = logging.getLogger(__name__)

# OWASP Mobile Top 10 2024
_OWASP_MOBILE = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}


class MobilePipeline:
    """20 Phase 모바일 펜테스트 파이프라인.

    Usage:
        pipeline = MobilePipeline(config=config)
        ctx = await pipeline.run(
            target="com.example.app",
            platform="android",
            app_binary_path="/path/to/app.apk",
        )
    """

    def __init__(
        self,
        config: Any | None = None,
        enable_dynamic: bool = True,
        enable_frida: bool = True,
        approval_callback: Callable[[list[Any]], Awaitable[list[bool]]] | None = None,
    ) -> None:
        self.config = config
        self.enable_dynamic = enable_dynamic
        self.enable_frida = enable_frida
        self._approval_callback = approval_callback

    async def run(
        self,
        target: str,
        platform: str = "android",
        app_binary_path: str = "",
        app_package: str = "",
        app_context_en: str = "",
        app_context_ko: str = "",
    ) -> MobileScanContext:
        """전체 20 Phase 모바일 파이프라인 실행."""
        ctx = MobileScanContext(
            target=target,
            platform=platform.lower(),
            app_binary_path=app_binary_path,
            app_package=app_package,
            app_context_en=app_context_en,
            app_context_ko=app_context_ko,
            scan_id=f"VXIS-MOB-{time.strftime('%Y%m%d-%H%M%S')}",
        )

        platform_label = "iOS" if ctx.is_ios else "Android"
        logger.info("=" * 70)
        logger.info("  VXIS MobilePipeline — 20 Phase Mobile Pentesting")
        logger.info("  Target: %s  Platform: %s", target, platform_label)
        logger.info("  Binary: %s", app_binary_path or "(none)")
        logger.info("  Scan ID: %s", ctx.scan_id)
        logger.info("=" * 70)

        phases = [
            ("Phase 0: Foundation — Config & Platform Detection", self._phase0_foundation),
            ("Phase 1: Static Analysis — Decompile & Manifest", self._phase1_static),
            ("Phase 2: Secret Scanning — Hardcoded Creds & Keys", self._phase2_secrets),
            ("Phase 3: Permission Analysis — Over-privilege Check", self._phase3_permissions),
            ("Phase 4: Component Analysis — Exported & Deep Links", self._phase4_components),
            ("Phase 5: Binary Protection — PIE/Canary/Obfuscation", self._phase5_binary),
            ("Phase 6: Network Setup — Proxy & Cert Pinning Detect", self._phase6_network),
            ("Phase 7: SSL Pinning Bypass — Frida Interception", self._phase7_ssl_bypass),
            ("Phase 8: API Discovery — Static + Dynamic Map", self._phase8_api_discovery),
            ("Phase 9: API Testing — Auth, IDOR, Injection", self._phase9_api_testing),
            ("Phase 10: Auth Testing — Token & Biometric Bypass", self._phase10_auth),
            ("Phase 11: Data Storage — SQLite/Keychain/SharedPrefs", self._phase11_storage),
            ("Phase 12: Backup Analysis — ADB/iTunes Backup", self._phase12_backup),
            ("Phase 13: Dynamic Analysis — Frida Runtime Hooks", self._phase13_dynamic),
            ("Phase 14: Root/Jailbreak Bypass", self._phase14_root_bypass),
            ("Phase 15: Anti-Tampering — Integrity Check Bypass", self._phase15_tampering),
            ("Phase 16: Business Logic — IAP & Feature Flag Bypass", self._phase16_business),
            ("Phase 17: Deep Link Hijacking — URL Scheme Security", self._phase17_deeplink),
            ("Phase 18: IPC Security — Intent/Pasteboard/Extension", self._phase18_ipc),
            ("Phase 19: Report — NCC Style + OWASP Mobile Top 10", self._phase19_report),
        ]

        for name, func in phases:
            await self._run_phase(name, func, ctx)

        logger.info("\n" + "=" * 70)
        logger.info("  MOBILE PIPELINE COMPLETE")
        logger.info("  Phases: %d/%d", len(ctx.phases_completed), len(phases))
        logger.info("  Findings: %d", len(ctx.findings))
        logger.info("  Secrets: %d", len(ctx.hardcoded_secrets))
        logger.info("  OWASP Coverage: %s", ctx.owasp_coverage_summary)
        logger.info("  Duration: %.1fs", ctx.duration_seconds)
        logger.info("=" * 70)

        return ctx

    async def _run_phase(
        self,
        name: str,
        func: Callable[[MobileScanContext], Awaitable[None]],
        ctx: MobileScanContext,
    ) -> None:
        logger.info("\n[%s]", name)
        t0 = time.monotonic()
        pre_count = len(ctx.findings)
        try:
            await func(ctx)
        except Exception as exc:
            logger.warning("  %s failed: %s (continuing)", name, exc)
        elapsed = (time.monotonic() - t0) * 1000
        new_findings = len(ctx.findings) - pre_count
        ctx.log_phase(name, duration_ms=elapsed, findings_count=new_findings)

    # ══════════════════════════════════════════════════════════
    # Phase 0: Foundation
    # ══════════════════════════════════════════════════════════

    async def _phase0_foundation(self, ctx: MobileScanContext) -> None:
        """Config 초기화, 플랫폼 검증, 바이너리 유효성 확인."""
        from pathlib import Path

        try:
            from vxis.config.schema import VXISConfig
            if self.config is None:
                self.config = VXISConfig()
        except Exception:
            pass

        # 플랫폼 정규화
        if ctx.platform not in ("android", "ios"):
            logger.warning("  Unknown platform '%s' — defaulting to android", ctx.platform)
            ctx.platform = "android"

        # 바이너리 파일 검증
        if ctx.app_binary_path:
            binary = Path(ctx.app_binary_path)
            if not binary.exists():
                logger.warning("  Binary not found: %s", ctx.app_binary_path)
                ctx.app_binary_path = ""
            else:
                size_mb = binary.stat().st_size / (1024 * 1024)
                logger.info(
                    "  Binary: %s (%.1f MB)", binary.name, size_mb,
                )
                # 확장자로 플랫폼 추론
                if binary.suffix.lower() == ".apk" and ctx.platform != "android":
                    logger.info("  APK detected — overriding platform to android")
                    ctx.platform = "android"
                elif binary.suffix.lower() == ".ipa" and ctx.platform != "ios":
                    logger.info("  IPA detected — overriding platform to ios")
                    ctx.platform = "ios"
        else:
            logger.warning(
                "  No binary provided — static analysis phases will be limited",
            )

        platform_label = "iOS" if ctx.is_ios else "Android"
        logger.info("  Platform: %s | Package: %s", platform_label, ctx.app_package or "(unknown)")

    # ══════════════════════════════════════════════════════════
    # Phase 1: Static Analysis
    # ══════════════════════════════════════════════════════════

    async def _phase1_static(self, ctx: MobileScanContext) -> None:
        """APK/IPA 디컴파일, 매니페스트 파싱, SDK 탐지."""
        if not ctx.app_binary_path:
            logger.info("  No binary — skipping static analysis")
            return

        from vxis.interaction.mobile_analyzer import MobileAnalyzer

        analyzer = MobileAnalyzer()

        if ctx.is_android:
            analysis = await analyzer.analyze_apk(ctx.app_binary_path)
            if analysis.error:
                logger.warning("  APK analysis error: %s", analysis.error)
                return

            ctx.app_package = analysis.package_name or ctx.app_package
            ctx.app_version = analysis.manifest.version_name
            ctx.min_sdk = analysis.manifest.min_sdk
            ctx.target_sdk = analysis.manifest.target_sdk
            ctx.permissions = analysis.manifest.permissions
            ctx.url_schemes = analysis.manifest.url_schemes
            ctx.obfuscation_level = analysis.binary_protection.obfuscation_level
            ctx.binary_protections = {
                "pie": analysis.binary_protection.pie_enabled,
                "stack_canary": analysis.binary_protection.stack_canary_enabled,
                "nx_bit": analysis.binary_protection.nx_bit_enabled,
                "stripped": analysis.binary_protection.stripped_symbols,
                "proguard": analysis.binary_protection.proguard_enabled,
                "obfuscation": analysis.binary_protection.obfuscation_level,
            }

            for sdk in analysis.third_party_sdks:
                ctx.add_sdk(
                    sdk["name"], sdk.get("version", "?"),
                    sdk["category"], sdk["risk"],
                )

            # 내보낸 컴포넌트 통합
            for comp_list in [
                analysis.manifest.exported_activities,
                analysis.manifest.exported_services,
                analysis.manifest.exported_receivers,
                analysis.manifest.exported_providers,
            ]:
                ctx.exported_components.extend(comp_list)

            # debuggable APK는 즉각 critical finding
            if analysis.manifest.debuggable:
                f = ctx.add_finding(
                    title="Debuggable APK Build|||디버그 모드 APK 배포",
                    severity="critical",
                    finding_type="security_misconfiguration",
                    description=(
                        "The APK is built with android:debuggable=true. "
                        "Attackers can attach debuggers and extract sensitive data."
                        "|||"
                        "android:debuggable=true로 빌드된 APK입니다. "
                        "공격자가 디버거를 연결해 민감한 데이터를 추출할 수 있습니다."
                    ),
                    target=ctx.target,
                    affected_component="AndroidManifest.xml",
                    source_plugin="vxis-mobile-pipeline",
                    cwe_ids=["CWE-489"],
                )
                ctx.add_owasp_finding("M8", f.id)

            # allowBackup warning
            if analysis.manifest.allow_backup:
                f = ctx.add_finding(
                    title="Android Backup Enabled|||Android 백업 허용됨",
                    severity="medium",
                    finding_type="security_misconfiguration",
                    description=(
                        "android:allowBackup=true allows ADB backup extraction without root. "
                        "Sensitive app data may be extracted via 'adb backup'."
                        "|||"
                        "android:allowBackup=true 설정으로 루트 없이 ADB 백업 추출이 가능합니다. "
                        "'adb backup' 명령으로 민감 데이터가 유출될 수 있습니다."
                    ),
                    target=ctx.target,
                    affected_component="AndroidManifest.xml",
                    source_plugin="vxis-mobile-pipeline",
                    cwe_ids=["CWE-312"],
                )
                ctx.add_owasp_finding("M9", f.id)

            logger.info(
                "  Package: %s | Version: %s | minSDK: %s | targetSDK: %s",
                ctx.app_package, ctx.app_version, ctx.min_sdk, ctx.target_sdk,
            )
            logger.info(
                "  Permissions: %d | Exported components: %d | URL schemes: %d",
                len(ctx.permissions), len(ctx.exported_components), len(ctx.url_schemes),
            )

        else:  # iOS
            analysis = await analyzer.analyze_ipa(ctx.app_binary_path)
            if analysis.error:
                logger.warning("  IPA analysis error: %s", analysis.error)
                return

            ctx.app_package = analysis.bundle_id or ctx.app_package
            ctx.app_version = analysis.manifest.version_name
            ctx.permissions = analysis.manifest.permissions
            ctx.url_schemes = analysis.manifest.url_schemes
            ctx.binary_protections = {
                "pie": analysis.binary_protection.pie_enabled,
                "stack_canary": analysis.binary_protection.stack_canary_enabled,
                "arc": analysis.binary_protection.arc_enabled,
                "stripped": analysis.binary_protection.stripped_symbols,
                "obfuscation": analysis.binary_protection.obfuscation_level,
            }
            ctx.obfuscation_level = analysis.binary_protection.obfuscation_level

            for sdk in analysis.third_party_sdks:
                ctx.add_sdk(
                    sdk["name"], sdk.get("version", "?"),
                    sdk["category"], sdk.get("risk", "low"),
                )

            # ATS 비활성화 체크
            ats = analysis.manifest.ats_config
            if ats.get("ats_disabled"):
                f = ctx.add_finding(
                    title="App Transport Security Disabled|||ATS 비활성화",
                    severity="high",
                    finding_type="insecure_communication",
                    description=(
                        "NSAllowsArbitraryLoads=true disables ATS, allowing HTTP traffic. "
                        "All network communication should use HTTPS with valid certificates."
                        "|||"
                        "NSAllowsArbitraryLoads=true로 ATS가 비활성화되어 HTTP 트래픽이 허용됩니다. "
                        "모든 네트워크 통신은 유효한 인증서를 사용한 HTTPS여야 합니다."
                    ),
                    target=ctx.target,
                    affected_component="Info.plist",
                    source_plugin="vxis-mobile-pipeline",
                    cwe_ids=["CWE-311"],
                )
                ctx.add_owasp_finding("M5", f.id)

            logger.info(
                "  Bundle ID: %s | Version: %s | URL schemes: %d",
                ctx.app_package, ctx.app_version, len(ctx.url_schemes),
            )

    # ══════════════════════════════════════════════════════════
    # Phase 2: Secret Scanning
    # ══════════════════════════════════════════════════════════

    async def _phase2_secrets(self, ctx: MobileScanContext) -> None:
        """바이너리/리소스에서 하드코딩 시크릿, API 키, 비밀번호 스캔."""
        if not ctx.app_binary_path:
            logger.info("  No binary — skipping secret scan")
            return

        from pathlib import Path
        from vxis.interaction.mobile_analyzer import MobileAnalyzer

        analyzer = MobileAnalyzer()

        # 이미 Phase 1에서 analysis 객체를 만들었지만 context에 저장하지 않았으므로
        # 여기서 scan_secrets만 다시 실행 (work dir 재사용)
        import tempfile
        work_dir = tempfile.mkdtemp(prefix="vxis_secrets_")
        import zipfile
        apk_path = ctx.app_binary_path
        extract_dir = Path(work_dir) / "extracted"

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                zf.extractall(extract_dir)
        except Exception as exc:
            logger.warning("  Extraction failed: %s", exc)
            return

        secrets = await analyzer.scan_secrets(str(extract_dir))

        severity_map = {
            "AWS Access Key ID": "critical",
            "AWS Secret Key": "critical",
            "Private Key Header": "critical",
            "Stripe Live Key": "critical",
            "GitHub Token": "high",
            "Generic Password": "high",
            "Generic Secret": "high",
            "Google API Key": "high",
            "Firebase URL": "medium",
            "Generic API Key": "medium",
            "Bearer Token Hardcoded": "high",
        }

        for secret in secrets:
            ctx.add_secret(
                secret.secret_type,
                secret.value,
                secret.file_path,
                secret.context,
            )
            sev = severity_map.get(secret.secret_type, "medium")
            f = ctx.add_finding(
                title=f"Hardcoded {secret.secret_type} in Binary|||바이너리에 {secret.secret_type} 하드코딩",
                severity=sev,
                finding_type="sensitive_data_exposure",
                description=(
                    f"Found {secret.secret_type} at {secret.file_path}:{secret.line_number}. "
                    f"Value preview: {secret.value_preview}. "
                    "Hardcoded credentials can be extracted by decompiling the app."
                    "|||"
                    f"{secret.file_path}:{secret.line_number}에서 {secret.secret_type} 발견. "
                    f"값 미리보기: {secret.value_preview}. "
                    "앱 디컴파일로 하드코딩된 자격증명을 추출할 수 있습니다."
                ),
                target=ctx.target,
                affected_component=secret.file_path,
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-798"],
            )
            ctx.add_owasp_finding("M1", f.id)

        logger.info("  Secrets found: %d → %d findings", len(secrets), len(secrets))

    # ══════════════════════════════════════════════════════════
    # Phase 3: Permission Analysis
    # ══════════════════════════════════════════════════════════

    async def _phase3_permissions(self, ctx: MobileScanContext) -> None:
        """과도한 퍼미션 + 위험 퍼미션 조합 분석."""
        from vxis.interaction.mobile_analyzer import _DANGEROUS_PERMISSIONS

        dangerous = [p for p in ctx.permissions if p in _DANGEROUS_PERMISSIONS]
        total = len(ctx.permissions)

        if not ctx.permissions:
            logger.info("  No permissions to analyze")
            return

        logger.info("  Permissions: %d total, %d dangerous", total, len(dangerous))

        # 위험 퍼미션 조합 패턴
        comms_perms = {
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CALL_LOG",
        }

        perm_set = set(ctx.permissions)

        # Background location 별도 체크
        if "android.permission.ACCESS_BACKGROUND_LOCATION" in perm_set:
            f = ctx.add_finding(
                title="Background Location Access Declared|||백그라운드 위치 접근 선언",
                severity="high",
                finding_type="excessive_permissions",
                description=(
                    "App declares ACCESS_BACKGROUND_LOCATION. "
                    "Background location tracking can enable covert surveillance."
                    "|||"
                    "앱이 ACCESS_BACKGROUND_LOCATION을 선언합니다. "
                    "백그라운드 위치 추적은 은밀한 감시를 가능하게 합니다."
                ),
                target=ctx.target,
                affected_component="AndroidManifest.xml",
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-359"],
            )
            ctx.add_owasp_finding("M6", f.id)

        # SMS 읽기 능력
        if comms_perms & perm_set:
            found_comms = comms_perms & perm_set
            f = ctx.add_finding(
                title="SMS/Call Log Access Permission|||SMS/통화 기록 접근 권한",
                severity="high",
                finding_type="excessive_permissions",
                description=(
                    f"App requests sensitive communication permissions: {', '.join(found_comms)}. "
                    "These permissions enable reading private messages and call history."
                    "|||"
                    f"앱이 민감한 통신 퍼미션을 요청합니다: {', '.join(found_comms)}. "
                    "개인 메시지와 통화 기록을 읽을 수 있습니다."
                ),
                target=ctx.target,
                affected_component="AndroidManifest.xml",
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-359"],
            )
            ctx.add_owasp_finding("M6", f.id)

        # 과도한 퍼미션 (전체 위험 퍼미션의 50% 이상)
        if len(dangerous) > len(_DANGEROUS_PERMISSIONS) * 0.5:
            f = ctx.add_finding(
                title=f"Over-Privileged App ({len(dangerous)} dangerous permissions)|||과도한 권한 앱",
                severity="medium",
                finding_type="excessive_permissions",
                description=(
                    f"App requests {len(dangerous)}/{len(_DANGEROUS_PERMISSIONS)} dangerous permissions. "
                    "Excessive permissions violate the principle of least privilege."
                    "|||"
                    f"앱이 {len(dangerous)}/{len(_DANGEROUS_PERMISSIONS)}개 위험 퍼미션을 요청합니다. "
                    "최소 권한 원칙을 위반합니다."
                ),
                target=ctx.target,
                affected_component="AndroidManifest.xml",
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-250"],
            )
            ctx.add_owasp_finding("M6", f.id)

        # Android SDK 버전 체크
        if ctx.min_sdk is not None and ctx.min_sdk < 21:
            f = ctx.add_finding(
                title=f"Low minSdkVersion ({ctx.min_sdk})|||낮은 최소 SDK 버전",
                severity="medium",
                finding_type="security_misconfiguration",
                description=(
                    f"App supports Android {ctx.min_sdk} (API {ctx.min_sdk}). "
                    "Devices older than Android 5.0 lack many security features including "
                    "full disk encryption, SELinux enforcement, and modern TLS."
                    "|||"
                    f"앱이 Android API {ctx.min_sdk} 이상을 지원합니다. "
                    "Android 5.0 미만 기기는 전체 디스크 암호화, SELinux, 최신 TLS 등 "
                    "다수의 보안 기능이 없습니다."
                ),
                target=ctx.target,
                affected_component="AndroidManifest.xml",
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-693"],
            )
            ctx.add_owasp_finding("M8", f.id)

    # ══════════════════════════════════════════════════════════
    # Phase 4: Component Analysis
    # ══════════════════════════════════════════════════════════

    async def _phase4_components(self, ctx: MobileScanContext) -> None:
        """내보낸 컴포넌트 분석, 딥링크 보안 검토."""
        if not ctx.exported_components and not ctx.url_schemes:
            logger.info("  No exported components or URL schemes to analyze")
            return

        # 내보낸 컴포넌트 분석
        for comp in ctx.exported_components:
            comp_name = comp.get("name", "")
            comp_type = comp.get("type", "")
            comp.get("intent_filters", [])

            # 퍼미션 없이 내보낸 Activity
            if comp_type == "activity" and not comp.get("permission"):
                f = ctx.add_finding(
                    title=f"Exported Activity Without Permission: {comp_name.split('.')[-1]}|||퍼미션 없는 내보낸 액티비티",
                    severity="high",
                    finding_type="insecure_component",
                    description=(
                        f"Activity {comp_name} is exported without android:permission. "
                        "Any application can launch this activity, potentially bypassing "
                        "authentication screens or triggering sensitive functionality."
                        "|||"
                        f"액티비티 {comp_name}이 android:permission 없이 내보내졌습니다. "
                        "모든 앱이 이 액티비티를 실행할 수 있어 인증 우회나 "
                        "민감한 기능 트리거가 가능합니다."
                    ),
                    target=ctx.target,
                    affected_component=comp_name,
                    source_plugin="vxis-mobile-pipeline",
                    cwe_ids=["CWE-926"],
                )
                ctx.add_owasp_finding("M3", f.id)

            # 내보낸 ContentProvider
            if comp_type == "provider":
                f = ctx.add_finding(
                    title=f"Exported ContentProvider: {comp_name.split('.')[-1]}|||내보낸 ContentProvider",
                    severity="high",
                    finding_type="insecure_component",
                    description=(
                        f"ContentProvider {comp_name} is exported. "
                        "Exported providers may allow unauthorized data access or SQL injection "
                        "via content URIs if queries are not properly sanitized."
                        "|||"
                        f"ContentProvider {comp_name}이 내보내졌습니다. "
                        "내보낸 provider는 content URI를 통한 비인가 데이터 접근이나 "
                        "SQL 인젝션을 허용할 수 있습니다."
                    ),
                    target=ctx.target,
                    affected_component=comp_name,
                    source_plugin="vxis-mobile-pipeline",
                    cwe_ids=["CWE-926", "CWE-89"],
                )
                ctx.add_owasp_finding("M4", f.id)

            # BroadcastReceiver — 동적 인텐트 처리
            if comp_type == "receiver":
                f = ctx.add_finding(
                    title=f"Exported BroadcastReceiver: {comp_name.split('.')[-1]}|||내보낸 BroadcastReceiver",
                    severity="medium",
                    finding_type="insecure_component",
                    description=(
                        f"BroadcastReceiver {comp_name} is exported. "
                        "Malicious apps may send crafted intents to trigger unintended behavior."
                        "|||"
                        f"BroadcastReceiver {comp_name}이 내보내졌습니다. "
                        "악성 앱이 인텐트를 전송해 의도치 않은 동작을 트리거할 수 있습니다."
                    ),
                    target=ctx.target,
                    affected_component=comp_name,
                    source_plugin="vxis-mobile-pipeline",
                    cwe_ids=["CWE-926"],
                )
                ctx.add_owasp_finding("M4", f.id)

        # URL Scheme 분석
        for scheme in ctx.url_schemes:
            if scheme not in ("http", "https", "mailto", "tel"):
                f = ctx.add_finding(
                    title=f"Custom URL Scheme Registered: {scheme}://|||커스텀 URL 스킴 등록",
                    severity="medium",
                    finding_type="url_scheme_hijacking",
                    description=(
                        f"App registers custom URL scheme '{scheme}://'. "
                        "On Android, URL schemes can be hijacked by malicious apps with "
                        "the same scheme. iOS Universal Links are more secure."
                        "|||"
                        f"앱이 커스텀 URL 스킴 '{scheme}://'을 등록합니다. "
                        "Android에서 동일 스킴을 가진 악성 앱이 스킴을 가로챌 수 있습니다. "
                        "iOS Universal Links가 더 안전합니다."
                    ),
                    target=ctx.target,
                    affected_component=f"URL scheme: {scheme}",
                    source_plugin="vxis-mobile-pipeline",
                    cwe_ids=["CWE-939"],
                )
                ctx.add_owasp_finding("M8", f.id)

        logger.info(
            "  Exported components: %d | URL schemes: %d",
            len(ctx.exported_components), len(ctx.url_schemes),
        )

    # ══════════════════════════════════════════════════════════
    # Phase 5: Binary Protection
    # ══════════════════════════════════════════════════════════

    async def _phase5_binary(self, ctx: MobileScanContext) -> None:
        """PIE, Stack Canary, ASLR, ARC, 난독화 수준 평가."""
        if not ctx.binary_protections:
            logger.info("  No binary protection data — static analysis not completed")
            return

        bp = ctx.binary_protections
        issues = []

        if not bp.get("pie"):
            issues.append("PIE disabled")
            f = ctx.add_finding(
                title="PIE (ASLR) Not Enabled|||PIE(ASLR) 미적용",
                severity="high",
                finding_type="binary_protection",
                description=(
                    "Binary is not compiled with Position Independent Executable (PIE). "
                    "Without PIE, ASLR cannot randomize the base address, making "
                    "ROP/JOP attacks easier."
                    "|||"
                    "바이너리가 PIE(Position Independent Executable) 없이 컴파일되었습니다. "
                    "PIE 없이는 ASLR이 기반 주소를 무작위화할 수 없어 "
                    "ROP/JOP 공격이 쉬워집니다."
                ),
                target=ctx.target,
                affected_component="native binary",
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-119"],
            )
            ctx.add_owasp_finding("M7", f.id)

        if not bp.get("stack_canary"):
            issues.append("Stack canary absent")
            f = ctx.add_finding(
                title="Stack Canary Not Present|||스택 카나리 부재",
                severity="high",
                finding_type="binary_protection",
                description=(
                    "Binary lacks stack canary protection (__stack_chk_fail). "
                    "Stack buffer overflows can overwrite return addresses without detection."
                    "|||"
                    "바이너리에 스택 카나리 보호(__stack_chk_fail)가 없습니다. "
                    "스택 버퍼 오버플로우가 반환 주소를 탐지 없이 덮어쓸 수 있습니다."
                ),
                target=ctx.target,
                affected_component="native binary",
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-121"],
            )
            ctx.add_owasp_finding("M7", f.id)

        if ctx.is_android and not bp.get("proguard"):
            f = ctx.add_finding(
                title="ProGuard/R8 Obfuscation Not Detected|||ProGuard/R8 난독화 미적용",
                severity="medium",
                finding_type="binary_protection",
                description=(
                    "Android app does not appear to use ProGuard or R8 code shrinking/obfuscation. "
                    "Clear class and method names make reverse engineering trivial."
                    "|||"
                    "Android 앱이 ProGuard 또는 R8 코드 축소/난독화를 사용하지 않는 것으로 보입니다. "
                    "명확한 클래스/메서드 이름으로 리버스 엔지니어링이 매우 쉬워집니다."
                ),
                target=ctx.target,
                affected_component="APK",
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-656"],
            )
            ctx.add_owasp_finding("M7", f.id)

        if ctx.is_ios and not bp.get("arc"):
            f = ctx.add_finding(
                title="Automatic Reference Counting (ARC) Not Detected|||ARC 미적용",
                severity="medium",
                finding_type="binary_protection",
                description=(
                    "iOS binary does not appear to use ARC. Manual memory management "
                    "increases the risk of use-after-free and dangling pointer vulnerabilities."
                    "|||"
                    "iOS 바이너리가 ARC를 사용하지 않는 것으로 보입니다. 수동 메모리 관리는 "
                    "use-after-free와 댕글링 포인터 취약점 위험을 높입니다."
                ),
                target=ctx.target,
                affected_component="iOS binary",
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-416"],
            )
            ctx.add_owasp_finding("M7", f.id)

        logger.info(
            "  Binary protections: PIE=%s Canary=%s Stripped=%s Obfusc=%s",
            bp.get("pie"), bp.get("stack_canary"),
            bp.get("stripped"), bp.get("obfuscation"),
        )

    # ══════════════════════════════════════════════════════════
    # Phase 6: Network Setup
    # ══════════════════════════════════════════════════════════

    async def _phase6_network(self, ctx: MobileScanContext) -> None:
        """X-Ray 프록시 구성, 인증서 피닝 탐지."""
        if not self.enable_dynamic:
            logger.info("  Dynamic analysis disabled — skipping network setup")
            return

        # X-Ray (mitmproxy 래퍼) 초기화 — 설정만, 실제 시작은 Phase 7에서
        try:
            from vxis.interaction.xray import TrafficInterceptor
            interceptor = TrafficInterceptor(
                proxy_port=8888,
                target_filter=ctx.target,
            )
            self._interceptor = interceptor
            logger.info("  X-Ray interceptor configured on port 8888")
        except Exception as exc:
            self._interceptor = None
            logger.warning("  X-Ray not available: %s", exc)

        # 서버에서 인증서 피닝 단서 수집 (헤더 분석)
        try:
            from vxis.interaction.hands import SessionManager
            mgr = SessionManager()
            # target이 도메인이면 API 베이스 URL 추론
            api_base = ctx.target if ctx.target.startswith("http") else f"https://{ctx.target}"
            session = await mgr.get_session(api_base)
            resp = await session.get("/")

            # Public-Key-Pins 헤더가 있으면 HPKP 피닝 사용
            pkp = resp.headers.get("Public-Key-Pins", "")
            hsts = resp.headers.get("Strict-Transport-Security", "")
            if pkp:
                ctx.ssl_pinning_detected = True
                logger.info("  HPKP header found — SSL pinning via server-side HPKP")

            if hsts:
                logger.info("  HSTS configured: %s", hsts[:80])

            await mgr.close_all()
        except Exception as exc:
            logger.info("  Network probe skipped: %s", exc)

        # 정적 분석에서 인증서 피닝 코드 패턴 탐지
        if ctx.app_binary_path:
            ctx.ssl_pinning_detected = ctx.ssl_pinning_detected or self._detect_ssl_pinning_static(ctx)

        if ctx.ssl_pinning_detected:
            logger.info("  SSL Pinning DETECTED — bypass required for traffic interception")
        else:
            logger.info("  SSL Pinning not detected")

    def _detect_ssl_pinning_static(self, ctx: MobileScanContext) -> bool:
        """정적 분석으로 SSL 피닝 코드 패턴 탐지."""
        from pathlib import Path
        import zipfile
        import tempfile
        import re

        pinning_patterns = [
            # Android
            re.compile(r'CertificatePinner|TrustManagerImpl|checkServerTrusted|PinningTrustManager'),
            re.compile(r'okhttp.*CertificatePinner|conscrypt.*pinning'),
            re.compile(r'TrustKit|TrustKit\.initSharedInstance'),
            # iOS
            re.compile(r'TrustKit|pinnedCertificates|pinnedPublicKeys'),
            re.compile(r'SecPolicyCreateSSL|kSecTrustEvaluateWithError'),
            re.compile(r'URLSessionDelegate.*didReceiveChallenge'),
        ]

        try:
            tmp = tempfile.mkdtemp(prefix="vxis_pin_")
            with zipfile.ZipFile(ctx.app_binary_path, "r") as zf:
                zf.extractall(tmp)

            sample_files: list[Path] = []
            for ext in (".java", ".kt", ".swift", ".smali"):
                sample_files.extend(list(Path(tmp).rglob(f"*{ext}"))[:50])

            for f in sample_files:
                try:
                    content = f.read_text(errors="replace")
                    for pattern in pinning_patterns:
                        if pattern.search(content):
                            logger.info("  Pinning pattern found in %s", f.name)
                            return True
                except OSError:
                    continue
        except Exception:
            pass

        return False

    # ══════════════════════════════════════════════════════════
    # Phase 7: SSL Pinning Bypass
    # ══════════════════════════════════════════════════════════

    async def _phase7_ssl_bypass(self, ctx: MobileScanContext) -> None:
        """Frida 기반 SSL 피닝 우회, 트래픽 인터셉션 시작."""
        if not self.enable_frida:
            logger.info("  Frida disabled — skipping SSL pinning bypass")
            return

        try:
            from vxis.interaction.frida_bridge import FridaBridge
            bridge = FridaBridge()
            self._frida = bridge
        except ImportError:
            logger.warning(
                "  FridaBridge not available (being created by parallel agent) — "
                "SSL bypass via Frida skipped"
            )
            self._frida = None
            return
        except Exception as exc:
            logger.warning("  FridaBridge init failed: %s", exc)
            self._frida = None
            return

        # SSL 피닝 우회 스크립트 선택
        if ctx.ssl_pinning_detected:
            scripts = self._get_ssl_bypass_scripts(ctx.platform)
            for script_name in scripts:
                try:
                    await self._frida.inject_script(script_name, ctx.app_package)
                    ctx.frida_scripts_used.append(script_name)
                    logger.info("  Injected: %s", script_name)
                except Exception as exc:
                    logger.warning("  Script %s failed: %s", script_name, exc)

            if ctx.frida_scripts_used:
                f = ctx.add_finding(
                    title="SSL Certificate Pinning Bypassed|||SSL 인증서 피닝 우회 성공",
                    severity="high",
                    finding_type="ssl_pinning_bypass",
                    description=(
                        f"SSL certificate pinning was successfully bypassed using Frida scripts: "
                        f"{', '.join(ctx.frida_scripts_used)}. "
                        "Traffic can now be intercepted by a MITM proxy."
                        "|||"
                        f"Frida 스크립트({', '.join(ctx.frida_scripts_used)})로 "
                        "SSL 인증서 피닝을 우회했습니다. "
                        "MITM 프록시로 트래픽 인터셉션이 가능합니다."
                    ),
                    target=ctx.target,
                    affected_component="SSL/TLS Layer",
                    source_plugin="vxis-mobile-pipeline",
                    cwe_ids=["CWE-295"],
                )
                ctx.add_owasp_finding("M5", f.id)
        else:
            logger.info("  No SSL pinning detected — skipping bypass")

        # 트래픽 인터셉터 시작
        if hasattr(self, "_interceptor") and self._interceptor is not None:
            try:
                await self._interceptor.start()
                logger.info("  X-Ray traffic interceptor started")
            except Exception as exc:
                logger.warning("  Interceptor start failed: %s", exc)

    def _get_ssl_bypass_scripts(self, platform: str) -> list[str]:
        """플랫폼별 SSL 피닝 우회 스크립트 목록."""
        if platform == "android":
            return [
                "ssl_pinning_bypass_android_universal",
                "ssl_pinning_bypass_okhttp3",
                "ssl_pinning_bypass_trustkit_android",
                "ssl_pinning_bypass_conscrypt",
            ]
        else:
            return [
                "ssl_pinning_bypass_ios_universal",
                "ssl_pinning_bypass_afnetworking",
                "ssl_pinning_bypass_trustkit_ios",
                "ssl_pinning_bypass_nsurlsession",
            ]

    # ══════════════════════════════════════════════════════════
    # Phase 8: API Discovery
    # ══════════════════════════════════════════════════════════

    async def _phase8_api_discovery(self, ctx: MobileScanContext) -> None:
        """정적 분석 + 동적 트래픽에서 API 엔드포인트 맵 구성."""
        from pathlib import Path
        import zipfile
        import tempfile
        import re

        endpoints: set[str] = set()

        # 정적: 디컴파일 소스에서 URL 추출
        if ctx.app_binary_path:
            try:
                tmp = tempfile.mkdtemp(prefix="vxis_api_")
                with zipfile.ZipFile(ctx.app_binary_path, "r") as zf:
                    zf.extractall(tmp)

                url_pattern = re.compile(
                    r'["\'`](/(?:api|v\d+|graphql|rest|service)[^\s"\'`<>]{2,80})["\'`]',
                    re.IGNORECASE,
                )
                full_url_pattern = re.compile(
                    r'https?://[^\s"\'`<>]{5,120}(?:/api/|/v\d+/|/graphql)[^\s"\'`<>]*',
                )

                source_files = []
                for ext in (".java", ".kt", ".swift", ".js", ".smali"):
                    source_files.extend(list(Path(tmp).rglob(f"*{ext}"))[:100])

                for sf in source_files:
                    try:
                        content = sf.read_text(errors="replace")
                        for m in url_pattern.finditer(content):
                            endpoints.add(m.group(1))
                        for m in full_url_pattern.finditer(content):
                            endpoints.add(m.group(0))
                    except OSError:
                        continue

                logger.info("  Static API discovery: %d endpoints", len(endpoints))
            except Exception as exc:
                logger.warning("  Static API discovery error: %s", exc)

        # 동적: X-Ray 캡처된 플로우에서 엔드포인트 추출
        if hasattr(self, "_interceptor") and self._interceptor is not None:
            try:
                flows = await self._interceptor.get_captured_flows()
                for flow in flows:
                    if hasattr(flow, "url") and flow.url:
                        from urllib.parse import urlparse
                        parsed = urlparse(flow.url)
                        if parsed.path:
                            endpoints.add(parsed.path)
                logger.info("  Dynamic API discovery: %d flows captured", len(flows))
            except Exception as exc:
                logger.info("  Dynamic capture: %s", exc)

        # ctx에 통합
        existing_paths = {e.get("path") for e in ctx.api_endpoints}
        for ep in endpoints:
            if ep not in existing_paths:
                ctx.api_endpoints.append({
                    "path": ep,
                    "source": "mobile_static",
                    "method": "unknown",
                    "auth_required": None,
                })

        logger.info("  Total API endpoints discovered: %d", len(ctx.api_endpoints))

    # ══════════════════════════════════════════════════════════
    # Phase 9: API Testing
    # ══════════════════════════════════════════════════════════

    async def _phase9_api_testing(self, ctx: MobileScanContext) -> None:
        """발견된 API 엔드포인트 펜테스트 — 인증, IDOR, 인젝션."""
        if not ctx.api_endpoints:
            logger.info("  No API endpoints to test")
            return

        api_base = ctx.target if ctx.target.startswith("http") else f"https://{ctx.target}"

        try:
            from vxis.interaction.hands import SessionManager
            mgr = SessionManager()
            session = await mgr.get_session(api_base)

            tested = 0
            unauthenticated = []

            for endpoint in ctx.api_endpoints[:50]:  # 최대 50개
                path = endpoint.get("path", "")
                if not path or not path.startswith("/"):
                    continue

                try:
                    resp = await session.get(path)
                    tested += 1

                    # 인증 없이 200 반환 시
                    if resp.status == 200:
                        unauthenticated.append(path)
                        # JSON 응답에 민감 데이터 패턴
                        import re
                        body = resp.text[:2000]
                        if re.search(r'"(?:password|token|secret|api_key|ssn|credit_card)"', body, re.I):
                            f = ctx.add_finding(
                                title=f"Unauthenticated API Exposes Sensitive Data: {path}|||미인증 API 민감 데이터 노출",
                                severity="critical",
                                finding_type="broken_access_control",
                                description=(
                                    f"Endpoint {path} returns HTTP 200 without authentication "
                                    "and response contains sensitive field names."
                                    "|||"
                                    f"엔드포인트 {path}가 인증 없이 HTTP 200을 반환하며 "
                                    "응답에 민감한 필드명이 포함되어 있습니다."
                                ),
                                target=api_base,
                                affected_component=path,
                                source_plugin="vxis-mobile-pipeline",
                                cwe_ids=["CWE-306", "CWE-200"],
                            )
                            ctx.add_owasp_finding("M3", f.id)
                        else:
                            f = ctx.add_finding(
                                title=f"Unauthenticated API Access: {path}|||미인증 API 접근",
                                severity="high",
                                finding_type="broken_access_control",
                                description=(
                                    f"Endpoint {path} returns HTTP 200 without authentication. "
                                    "Verify if authentication is required for this resource."
                                    "|||"
                                    f"엔드포인트 {path}가 인증 없이 HTTP 200을 반환합니다. "
                                    "이 리소스에 인증이 필요한지 확인하세요."
                                ),
                                target=api_base,
                                affected_component=path,
                                source_plugin="vxis-mobile-pipeline",
                                cwe_ids=["CWE-306"],
                            )
                            ctx.add_owasp_finding("M3", f.id)

                    # JWT 없이 접근 가능한 GraphQL
                    if "graphql" in path.lower() and resp.status in (200, 400):
                        f = ctx.add_finding(
                            title=f"GraphQL Endpoint Accessible Without Auth: {path}|||인증 없이 접근 가능한 GraphQL",
                            severity="high",
                            finding_type="broken_access_control",
                            description=(
                                f"GraphQL endpoint {path} is accessible without authentication. "
                                "GraphQL introspection may expose the full API schema."
                                "|||"
                                f"GraphQL 엔드포인트 {path}에 인증 없이 접근 가능합니다. "
                                "GraphQL 인트로스펙션으로 전체 API 스키마가 노출될 수 있습니다."
                            ),
                            target=api_base,
                            affected_component=path,
                            source_plugin="vxis-mobile-pipeline",
                            cwe_ids=["CWE-306"],
                        )
                        ctx.add_owasp_finding("M3", f.id)

                except Exception:
                    continue

            await mgr.close_all()
            logger.info(
                "  API testing: %d tested, %d unauthenticated",
                tested, len(unauthenticated),
            )

        except Exception as exc:
            logger.warning("  API testing error: %s", exc)

    # ══════════════════════════════════════════════════════════
    # Phase 10: Auth Testing
    # ══════════════════════════════════════════════════════════

    async def _phase10_auth(self, ctx: MobileScanContext) -> None:
        """토큰 분석, 세션 관리, 생체 인증 우회 테스트."""
        # Frida로 생체 인증 우회
        if self._frida_available() and ctx.app_package:
            biometric_scripts = (
                ["biometric_bypass_android", "fingerprint_bypass_android"]
                if ctx.is_android
                else ["biometric_bypass_ios", "touchid_bypass_ios"]
            )
            for script in biometric_scripts:
                try:
                    result = await self._run_frida_script(script, ctx)
                    if result.get("bypassed"):
                        f = ctx.add_finding(
                            title="Biometric Authentication Bypass|||생체 인증 우회",
                            severity="critical",
                            finding_type="authentication_bypass",
                            description=(
                                f"Biometric authentication bypassed using Frida script '{script}'. "
                                "The app's biometric check can be bypassed at runtime."
                                "|||"
                                f"Frida 스크립트 '{script}'로 생체 인증을 우회했습니다. "
                                "앱의 생체 인증 체크를 런타임에 우회할 수 있습니다."
                            ),
                            target=ctx.target,
                            affected_component="Biometric Auth",
                            source_plugin="vxis-mobile-pipeline",
                            cwe_ids=["CWE-287"],
                        )
                        ctx.add_owasp_finding("M3", f.id)
                        ctx.frida_scripts_used.append(script)
                        break
                except Exception as exc:
                    logger.debug("  Biometric bypass script %s: %s", script, exc)

        # JWT 토큰 분석 (인터셉트된 트래픽에서)
        jwt_pattern = __import__("re").compile(
            r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'
        )
        for flow in ctx.intercepted_flows:
            headers = flow.get("request_headers", {})
            auth_header = headers.get("Authorization", "") or headers.get("authorization", "")
            body = flow.get("request_body", "") + flow.get("response_body", "")

            for text in (auth_header, body):
                match = jwt_pattern.search(text)
                if match:
                    jwt = match.group(0)
                    jwt_analysis = self._analyze_jwt(jwt)
                    if jwt_analysis.get("alg") == "none":
                        f = ctx.add_finding(
                            title="JWT 'alg:none' Vulnerability|||JWT alg:none 취약점",
                            severity="critical",
                            finding_type="jwt_vulnerability",
                            description=(
                                "JWT token uses 'alg:none' which disables signature verification. "
                                "Attackers can forge arbitrary tokens without the secret key."
                                "|||"
                                "JWT 토큰이 'alg:none'을 사용해 서명 검증이 비활성화됩니다. "
                                "공격자가 시크릿 키 없이 임의 토큰을 위조할 수 있습니다."
                            ),
                            target=ctx.target,
                            affected_component="JWT Authentication",
                            source_plugin="vxis-mobile-pipeline",
                            cwe_ids=["CWE-347"],
                        )
                        ctx.add_owasp_finding("M3", f.id)

                    if jwt_analysis.get("exp_missing"):
                        f = ctx.add_finding(
                            title="JWT Missing Expiration Claim|||JWT 만료 클레임 누락",
                            severity="high",
                            finding_type="jwt_vulnerability",
                            description=(
                                "JWT token does not contain an 'exp' (expiration) claim. "
                                "Tokens never expire, allowing long-term session replay attacks."
                                "|||"
                                "JWT 토큰에 'exp'(만료) 클레임이 없습니다. "
                                "토큰이 만료되지 않아 장기 세션 리플레이 공격이 가능합니다."
                            ),
                            target=ctx.target,
                            affected_component="JWT Authentication",
                            source_plugin="vxis-mobile-pipeline",
                            cwe_ids=["CWE-613"],
                        )
                        ctx.add_owasp_finding("M3", f.id)
                    break

        logger.info("  Auth testing complete")

    def _analyze_jwt(self, token: str) -> dict[str, object]:
        """JWT 토큰 간단 분석 (서명 검증 없이 헤더/페이로드 디코딩)."""
        import base64
        import json
        result: dict[str, object] = {}
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return result
            # base64 패딩 보정
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            result["alg"] = header.get("alg", "")
            result["exp_missing"] = "exp" not in payload
            result["sub"] = payload.get("sub", "")
        except Exception:
            pass
        return result

    def _frida_available(self) -> bool:
        return getattr(self, "_frida", None) is not None

    async def _run_frida_script(
        self, script_name: str, ctx: MobileScanContext,
    ) -> dict[str, object]:
        """Frida 스크립트 실행 헬퍼."""
        if not self._frida_available():
            return {}
        try:
            result = await self._frida.run_script(script_name, ctx.app_package)  # type: ignore[union-attr]
            return result if isinstance(result, dict) else {}
        except Exception as exc:
            logger.debug("  Frida script %s: %s", script_name, exc)
            return {}

    # ══════════════════════════════════════════════════════════
    # Phase 11: Data Storage
    # ══════════════════════════════════════════════════════════

    async def _phase11_storage(self, ctx: MobileScanContext) -> None:
        """SQLite, Keychain/Keystore, SharedPreferences, 캐시/로그 검사."""
        # ADB를 통한 Android 내부 스토리지 접근
        if ctx.is_android:
            await self._inspect_android_storage(ctx)
        else:
            await self._inspect_ios_storage(ctx)

        # 스토리지 취약점 → Finding 변환
        for sf in ctx.storage_findings:
            severity = sf.get("severity", "medium")
            f = ctx.add_finding(
                title=f"Insecure Data Storage — {sf['storage_type']}|||안전하지 않은 데이터 스토리지",
                severity=severity,
                finding_type="insecure_data_storage",
                description=(
                    f"{sf['description']} Location: {sf['location']}. "
                    + (f"Data preview: {sf['data_preview'][:100]}" if sf.get("data_preview") else "")
                    + "|||"
                    + f"{sf['description']} 위치: {sf['location']}."
                ),
                target=ctx.target,
                affected_component=sf["location"],
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-312", "CWE-922"],
            )
            ctx.add_owasp_finding("M9", f.id)

        logger.info("  Storage findings: %d", len(ctx.storage_findings))

    async def _inspect_android_storage(self, ctx: MobileScanContext) -> None:
        """ADB로 Android 앱 데이터 디렉터리 검사."""
        import shutil

        adb = shutil.which("adb")
        if not adb:
            logger.info("  adb not found — storage inspection skipped")
            return

        package = ctx.app_package
        if not package:
            return

        # SharedPreferences 파일 목록
        try:
            proc = await asyncio.create_subprocess_exec(
                adb, "shell", "run-as", package,
                "ls", f"/data/data/{package}/shared_prefs/",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            prefs_files = stdout.decode(errors="replace").strip().splitlines()

            for pref_file in prefs_files:
                if not pref_file.strip():
                    continue
                # 파일 내용 읽기
                proc2 = await asyncio.create_subprocess_exec(
                    adb, "shell", "run-as", package,
                    "cat", f"/data/data/{package}/shared_prefs/{pref_file}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                content_out, _ = await asyncio.wait_for(proc2.communicate(), timeout=10)
                content = content_out.decode(errors="replace")

                import re
                sensitive_patterns = [
                    ("password", re.compile(r'(?i)password|passwd|pwd')),
                    ("token", re.compile(r'(?i)token|jwt|bearer|api[_-]?key')),
                    ("pii", re.compile(r'(?i)email|phone|ssn|credit|card')),
                ]
                for data_type, pattern in sensitive_patterns:
                    if pattern.search(content):
                        ctx.add_storage_finding(
                            storage_type="SharedPreferences",
                            description=f"SharedPreferences file contains {data_type} data in plaintext",
                            location=f"shared_prefs/{pref_file}",
                            data_preview=content[:200],
                            severity="high",
                        )
                        break
        except asyncio.TimeoutError:
            logger.warning("  ADB SharedPreferences check timeout")
        except Exception as exc:
            logger.info("  ADB storage: %s", exc)

        # SQLite 데이터베이스 파일 목록
        try:
            proc = await asyncio.create_subprocess_exec(
                adb, "shell", "run-as", package,
                "ls", f"/data/data/{package}/databases/",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            db_files = stdout.decode(errors="replace").strip().splitlines()

            for db_file in db_files:
                if db_file.strip().endswith(".db"):
                    ctx.add_storage_finding(
                        storage_type="SQLite Database",
                        description="SQLite database file found — requires content analysis",
                        location=f"databases/{db_file}",
                        severity="low",
                    )
        except Exception as exc:
            logger.info("  ADB database listing: %s", exc)

    async def _inspect_ios_storage(self, ctx: MobileScanContext) -> None:
        """iOS 키체인/NSUserDefaults 검사 (Frida 활용)."""
        if not self._frida_available() or not ctx.app_package:
            logger.info("  Frida not available — iOS storage inspection skipped")
            return

        keychain_script = "keychain_dump_ios"
        try:
            result = await self._run_frida_script(keychain_script, ctx)
            entries = result.get("entries", [])
            for entry in entries if isinstance(entries, list) else []:
                account = entry.get("account", "")
                service = entry.get("service", "")
                data_preview = str(entry.get("data", ""))[:100]
                ctx.add_storage_finding(
                    storage_type="iOS Keychain",
                    description=f"Keychain entry: service={service}, account={account}",
                    location="iOS Keychain",
                    data_preview=data_preview,
                    severity="informational",
                )
            ctx.frida_scripts_used.append(keychain_script)
            logger.info("  Keychain: %d entries extracted", len(entries))
        except Exception as exc:
            logger.info("  Keychain dump: %s", exc)

    # ══════════════════════════════════════════════════════════
    # Phase 12: Backup Analysis
    # ══════════════════════════════════════════════════════════

    async def _phase12_backup(self, ctx: MobileScanContext) -> None:
        """iTunes/ADB 백업 추출, 민감 데이터 확인."""
        import shutil
        import tempfile
        from pathlib import Path

        if ctx.is_android:
            adb = shutil.which("adb")
            if not adb or not ctx.app_package:
                logger.info("  ADB not available or no package — backup analysis skipped")
                return

            backup_file = Path(tempfile.mkdtemp()) / "backup.ab"
            try:
                # allowBackup=true인 경우만 실제 데이터가 있음
                proc = await asyncio.create_subprocess_exec(
                    adb, "backup", "-f", str(backup_file),
                    "-noapk", ctx.app_package,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=60)

                if backup_file.exists() and backup_file.stat().st_size > 100:
                    size_kb = backup_file.stat().st_size / 1024
                    ctx.backup_findings.append({
                        "type": "adb_backup",
                        "file": str(backup_file),
                        "size_kb": size_kb,
                        "extractable": True,
                    })
                    f = ctx.add_finding(
                        title="Sensitive Data Extractable via ADB Backup|||ADB 백업으로 민감 데이터 추출 가능",
                        severity="high",
                        finding_type="insecure_data_storage",
                        description=(
                            f"ADB backup extracted {size_kb:.1f} KB of app data. "
                            "Sensitive data including databases, shared preferences, and files "
                            "can be extracted without root access."
                            "|||"
                            f"ADB 백업으로 {size_kb:.1f} KB의 앱 데이터가 추출되었습니다. "
                            "데이터베이스, SharedPreferences, 파일 등 민감 데이터를 "
                            "루트 없이 추출할 수 있습니다."
                        ),
                        target=ctx.target,
                        affected_component="ADB Backup",
                        source_plugin="vxis-mobile-pipeline",
                        cwe_ids=["CWE-312"],
                    )
                    ctx.add_owasp_finding("M9", f.id)
                else:
                    logger.info("  ADB backup empty or disabled")
            except asyncio.TimeoutError:
                logger.warning("  ADB backup timeout (user confirmation required on device)")
            except Exception as exc:
                logger.info("  ADB backup: %s", exc)
        else:
            # iOS: idevicebackup2 (libimobiledevice)
            idevice = shutil.which("idevicebackup2")
            if not idevice:
                logger.info("  idevicebackup2 not found — iOS backup analysis skipped")
                return

            backup_dir = Path(tempfile.mkdtemp()) / "ios_backup"
            try:
                proc = await asyncio.create_subprocess_exec(
                    idevice, "backup", "--full", str(backup_dir),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=300)

                if backup_dir.exists():
                    files = list(backup_dir.rglob("*"))
                    logger.info("  iOS backup extracted: %d files", len(files))
                    ctx.backup_findings.append({
                        "type": "itunes_backup",
                        "path": str(backup_dir),
                        "file_count": len(files),
                    })
            except Exception as exc:
                logger.info("  iOS backup: %s", exc)

        logger.info("  Backup analysis: %d findings", len(ctx.backup_findings))

    # ══════════════════════════════════════════════════════════
    # Phase 13: Dynamic Analysis
    # ══════════════════════════════════════════════════════════

    async def _phase13_dynamic(self, ctx: MobileScanContext) -> None:
        """Frida 런타임 훅킹, 메서드 트레이싱, 클래스 덤핑."""
        if not self.enable_frida or not self._frida_available():
            logger.info("  Frida not available — dynamic analysis skipped")
            return

        if not ctx.app_package:
            logger.info("  No app package — dynamic analysis skipped")
            return

        dynamic_scripts = []
        if ctx.is_android:
            dynamic_scripts = [
                "method_tracer_android",
                "class_dumper_android",
                "crypto_monitor_android",
                "network_monitor_android",
                "intent_monitor_android",
            ]
        else:
            dynamic_scripts = [
                "method_tracer_ios",
                "class_dumper_ios",
                "crypto_monitor_ios",
                "network_monitor_ios",
                "objc_method_trace",
            ]

        for script in dynamic_scripts:
            try:
                result = await self._run_frida_script(script, ctx)
                ctx.frida_scripts_used.append(script)

                # 크립토 API 미스사용 탐지
                if "crypto_monitor" in script:
                    weak_algos = result.get("weak_algorithms", [])
                    for algo in weak_algos if isinstance(weak_algos, list) else []:
                        f = ctx.add_finding(
                            title=f"Weak Cryptography Detected at Runtime: {algo}|||런타임에서 취약한 암호화 알고리즘 탐지",
                            severity="high",
                            finding_type="weak_cryptography",
                            description=(
                                f"App uses {algo} cryptographic algorithm at runtime. "
                                "Weak algorithms (MD5, SHA1, DES, ECB mode) can be broken."
                                "|||"
                                f"앱이 런타임에 {algo} 암호화 알고리즘을 사용합니다. "
                                "취약한 알고리즘(MD5, SHA1, DES, ECB 모드)은 해독될 수 있습니다."
                            ),
                            target=ctx.target,
                            affected_component="Cryptography",
                            source_plugin="vxis-mobile-pipeline",
                            cwe_ids=["CWE-327"],
                        )
                        ctx.add_owasp_finding("M10", f.id)

                logger.info("  Frida script %s: done", script)

            except Exception as exc:
                logger.debug("  Frida %s: %s", script, exc)

        logger.info(
            "  Dynamic analysis: %d scripts executed", len(ctx.frida_scripts_used),
        )

    # ══════════════════════════════════════════════════════════
    # Phase 14: Root/Jailbreak Bypass
    # ══════════════════════════════════════════════════════════

    async def _phase14_root_bypass(self, ctx: MobileScanContext) -> None:
        """루트/탈옥 탐지 우회 테스트."""
        # 정적으로 루트 탐지 코드 패턴 확인
        if ctx.app_binary_path:
            ctx.root_detection_detected = self._detect_root_check_static(ctx)

        if ctx.root_detection_detected:
            logger.info("  Root/jailbreak detection found — attempting bypass")

            if self._frida_available() and ctx.app_package:
                bypass_scripts = (
                    ["root_detection_bypass_android", "safetynet_bypass", "play_integrity_bypass"]
                    if ctx.is_android
                    else ["jailbreak_bypass_ios", "liberty_lite_bypass"]
                )
                for script in bypass_scripts:
                    try:
                        result = await self._run_frida_script(script, ctx)
                        if result.get("bypassed"):
                            f = ctx.add_finding(
                                title="Root/Jailbreak Detection Bypass|||루트/탈옥 탐지 우회",
                                severity="medium",
                                finding_type="root_detection_bypass",
                                description=(
                                    f"Root/jailbreak detection bypassed using '{script}'. "
                                    "Security controls relying solely on root detection can be circumvented."
                                    "|||"
                                    f"'{script}'로 루트/탈옥 탐지를 우회했습니다. "
                                    "루트 탐지에만 의존하는 보안 제어는 우회될 수 있습니다."
                                ),
                                target=ctx.target,
                                affected_component="Root/Jailbreak Detection",
                                source_plugin="vxis-mobile-pipeline",
                                cwe_ids=["CWE-693"],
                            )
                            ctx.add_owasp_finding("M8", f.id)
                            ctx.frida_scripts_used.append(script)
                            break
                    except Exception:
                        continue
        else:
            # 루트 탐지 없음도 finding
            f = ctx.add_finding(
                title="No Root/Jailbreak Detection Implemented|||루트/탈옥 탐지 미구현",
                severity="low",
                finding_type="missing_security_control",
                description=(
                    "App does not appear to implement root or jailbreak detection. "
                    "On compromised devices, app data and runtime may be more easily accessed."
                    "|||"
                    "앱이 루트 또는 탈옥 탐지를 구현하지 않은 것으로 보입니다. "
                    "침해된 기기에서 앱 데이터와 런타임에 더 쉽게 접근할 수 있습니다."
                ),
                target=ctx.target,
                affected_component="Security Controls",
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-693"],
            )
            ctx.add_owasp_finding("M8", f.id)

        logger.info(
            "  Root detection: %s", "detected" if ctx.root_detection_detected else "not found",
        )

    def _detect_root_check_static(self, ctx: MobileScanContext) -> bool:
        """정적 분석으로 루트/탈옥 탐지 코드 패턴 확인."""
        import re
        import zipfile
        import tempfile
        from pathlib import Path

        root_patterns_android = [
            re.compile(r'RootBeer|RootTools|SafetyNet|PlayIntegrity'),
            re.compile(r'su\b.*which|/system/xbin/su|/system/bin/su'),
            re.compile(r'checkForRoot|isRooted|detectRoot'),
        ]
        jb_patterns_ios = [
            re.compile(r'Cydia|cydia|jailbreak|jailbroken'),
            re.compile(r'/Applications/Cydia\.app|/private/var/lib/apt'),
            re.compile(r'JailbreakDetection|DTTJailbreakDetection'),
        ]
        patterns = root_patterns_android if ctx.is_android else jb_patterns_ios

        try:
            tmp = tempfile.mkdtemp(prefix="vxis_root_")
            with zipfile.ZipFile(ctx.app_binary_path, "r") as zf:
                zf.extractall(tmp)

            for ext in (".java", ".kt", ".swift", ".smali"):
                for f in list(Path(tmp).rglob(f"*{ext}"))[:100]:
                    try:
                        content = f.read_text(errors="replace")
                        for p in patterns:
                            if p.search(content):
                                return True
                    except OSError:
                        continue
        except Exception:
            pass

        return False

    # ══════════════════════════════════════════════════════════
    # Phase 15: Anti-Tampering
    # ══════════════════════════════════════════════════════════

    async def _phase15_tampering(self, ctx: MobileScanContext) -> None:
        """무결성 검사 우회, 코드 서명 검증 테스트."""
        has_tampering = False

        # 정적: 무결성 검사 코드 패턴
        if ctx.app_binary_path:
            import re
            import zipfile
            import tempfile
            from pathlib import Path

            tampering_patterns = [
                re.compile(r'PackageManager.*getSignatures|SignatureVerification'),
                re.compile(r'getApkCertDigest|checkIntegrity|verifySignature'),
                re.compile(r'SecureRandom.*signature|CRC32.*dex'),
                # iOS
                re.compile(r'CodeSigningCheck|MachOHeader.*signature'),
            ]

            try:
                tmp = tempfile.mkdtemp(prefix="vxis_tamper_")
                with zipfile.ZipFile(ctx.app_binary_path, "r") as zf:
                    zf.extractall(tmp)

                for ext in (".java", ".kt", ".swift", ".smali"):
                    for f in list(Path(tmp).rglob(f"*{ext}"))[:100]:
                        try:
                            content = f.read_text(errors="replace")
                            for p in tampering_patterns:
                                if p.search(content):
                                    has_tampering = True
                                    break
                        except OSError:
                            continue
                        if has_tampering:
                            break
            except Exception:
                pass

        if has_tampering and self._frida_available() and ctx.app_package:
            bypass_scripts = (
                ["signature_bypass_android", "apk_integrity_bypass"]
                if ctx.is_android
                else ["code_signing_bypass_ios"]
            )
            for script in bypass_scripts:
                try:
                    result = await self._run_frida_script(script, ctx)
                    if result.get("bypassed"):
                        f = ctx.add_finding(
                            title="Anti-Tampering Check Bypassed|||앱 무결성 검사 우회",
                            severity="medium",
                            finding_type="anti_tampering_bypass",
                            description=(
                                f"Code integrity/signature verification bypassed via '{script}'. "
                                "Modified APKs/IPAs can be sideloaded and run as if legitimate."
                                "|||"
                                f"'{script}'로 코드 무결성/서명 검증을 우회했습니다. "
                                "수정된 APK/IPA를 합법적인 것처럼 사이드로드하여 실행할 수 있습니다."
                            ),
                            target=ctx.target,
                            affected_component="Integrity Verification",
                            source_plugin="vxis-mobile-pipeline",
                            cwe_ids=["CWE-345"],
                        )
                        ctx.add_owasp_finding("M7", f.id)
                        ctx.frida_scripts_used.append(script)
                        break
                except Exception:
                    continue

        if not has_tampering:
            f = ctx.add_finding(
                title="No Anti-Tampering Protection Detected|||앱 무결성 보호 미탐지",
                severity="low",
                finding_type="missing_security_control",
                description=(
                    "App does not appear to implement signature or integrity verification. "
                    "Repackaged malicious versions can impersonate the legitimate app."
                    "|||"
                    "앱이 서명 또는 무결성 검증을 구현하지 않은 것으로 보입니다. "
                    "리패키징된 악성 버전이 합법적인 앱을 사칭할 수 있습니다."
                ),
                target=ctx.target,
                affected_component="Integrity Verification",
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-345"],
            )
            ctx.add_owasp_finding("M7", f.id)

        logger.info("  Anti-tampering check: %s", "detected" if has_tampering else "not found")

    # ══════════════════════════════════════════════════════════
    # Phase 16: Business Logic
    # ══════════════════════════════════════════════════════════

    async def _phase16_business(self, ctx: MobileScanContext) -> None:
        """인앱 구매 우회, 구독 검증, 기능 플래그 조작."""
        iap_scripts = []
        if ctx.is_android:
            iap_scripts = ["iap_bypass_android", "play_billing_bypass", "feature_flag_dump_android"]
        else:
            iap_scripts = ["iap_bypass_ios", "storekit_bypass", "feature_flag_dump_ios"]

        for sdk in ctx.third_party_sdks:
            # RevenueCat 사용 시 특화 스크립트
            if "revenuecat" in sdk.get("name", "").lower():
                iap_scripts.insert(0, "revenuecat_bypass")
            if "stripe" in sdk.get("name", "").lower():
                ctx.business_logic_findings.append({
                    "type": "payment_sdk",
                    "sdk": sdk["name"],
                    "note": "Stripe SDK detected — verify server-side payment verification",
                })

        if self._frida_available() and ctx.app_package:
            for script in iap_scripts:
                try:
                    result = await self._run_frida_script(script, ctx)
                    if result.get("bypassed"):
                        f = ctx.add_finding(
                            title="In-App Purchase Bypass Possible|||인앱 구매 우회 가능",
                            severity="critical",
                            finding_type="business_logic_bypass",
                            description=(
                                f"In-app purchase verification bypassed using '{script}'. "
                                "Premium features can be unlocked without payment."
                                "|||"
                                f"'{script}'로 인앱 구매 검증을 우회했습니다. "
                                "결제 없이 프리미엄 기능을 사용할 수 있습니다."
                            ),
                            target=ctx.target,
                            affected_component="In-App Purchase",
                            source_plugin="vxis-mobile-pipeline",
                            cwe_ids=["CWE-602"],
                        )
                        ctx.add_owasp_finding("M8", f.id)
                        ctx.frida_scripts_used.append(script)
                        break
                except Exception:
                    continue

        # RevenueCat/Stripe SDK → 서버사이드 검증 없으면 우회 위험 경고
        if any("revenuecat" in sdk.get("name", "").lower() for sdk in ctx.third_party_sdks):
            f = ctx.add_finding(
                title="RevenueCat SDK Detected — Verify Server-Side Receipt Validation|||RevenueCat SDK — 서버사이드 영수증 검증 확인 필요",
                severity="informational",
                finding_type="business_logic_review",
                description=(
                    "RevenueCat SDK is used for in-app purchase management. "
                    "Ensure server-side receipt validation is implemented to prevent bypass."
                    "|||"
                    "인앱 구매 관리에 RevenueCat SDK가 사용됩니다. "
                    "우회 방지를 위해 서버사이드 영수증 검증이 구현되어 있는지 확인하세요."
                ),
                target=ctx.target,
                affected_component="RevenueCat SDK",
                source_plugin="vxis-mobile-pipeline",
                cwe_ids=["CWE-602"],
            )

        logger.info("  Business logic analysis complete")

    # ══════════════════════════════════════════════════════════
    # Phase 17: Deep Link Hijacking
    # ══════════════════════════════════════════════════════════

    async def _phase17_deeplink(self, ctx: MobileScanContext) -> None:
        """URL 스킴 하이재킹, Universal/App Links 보안 검토."""
        if not ctx.url_schemes and not ctx.target.startswith("http"):
            logger.info("  No URL schemes to test")
            return

        api_base = ctx.target if ctx.target.startswith("http") else f"https://{ctx.target}"

        try:
            from vxis.interaction.hands import SessionManager
            mgr = SessionManager()
            session = await mgr.get_session(api_base)

            # Android App Links: /.well-known/assetlinks.json
            if ctx.is_android:
                resp = await session.get("/.well-known/assetlinks.json")
                if resp.status == 200:
                    import json
                    try:
                        data = json.loads(resp.text)
                        # 패키지명 일치 확인
                        declared_packages = []
                        for entry in data if isinstance(data, list) else []:
                            target_info = entry.get("target", {})
                            if target_info.get("namespace") == "android_app":
                                declared_packages.append(target_info.get("package_name", ""))

                        if ctx.app_package and ctx.app_package not in declared_packages:
                            f = ctx.add_finding(
                                title="Android App Links Package Mismatch|||Android App Links 패키지 불일치",
                                severity="medium",
                                finding_type="deep_link_misconfiguration",
                                description=(
                                    f"assetlinks.json declares packages {declared_packages} but "
                                    f"app package is {ctx.app_package}. "
                                    "Mismatched App Links may fall back to browser-based deep links."
                                    "|||"
                                    f"assetlinks.json에 선언된 패키지 {declared_packages}가 "
                                    f"앱 패키지 {ctx.app_package}와 불일치합니다. "
                                    "불일치 시 브라우저 기반 딥링크로 폴백될 수 있습니다."
                                ),
                                target=ctx.target,
                                affected_component="/.well-known/assetlinks.json",
                                source_plugin="vxis-mobile-pipeline",
                                cwe_ids=["CWE-939"],
                            )
                            ctx.add_owasp_finding("M8", f.id)
                        else:
                            logger.info("  Android App Links: properly configured")
                    except Exception as exc:
                        logger.info("  assetlinks.json parse: %s", exc)
                elif resp.status == 404:
                    f = ctx.add_finding(
                        title="Android App Links Not Configured|||Android App Links 미설정",
                        severity="low",
                        finding_type="deep_link_misconfiguration",
                        description=(
                            "/.well-known/assetlinks.json not found. "
                            "Without App Links, custom URL schemes may be hijackable."
                            "|||"
                            "/.well-known/assetlinks.json이 없습니다. "
                            "App Links 없이는 커스텀 URL 스킴이 하이재킹될 수 있습니다."
                        ),
                        target=ctx.target,
                        affected_component="Android App Links",
                        source_plugin="vxis-mobile-pipeline",
                        cwe_ids=["CWE-939"],
                    )

            # iOS Universal Links: /.well-known/apple-app-site-association
            if ctx.is_ios:
                resp = await session.get("/.well-known/apple-app-site-association")
                if resp.status == 404:
                    f = ctx.add_finding(
                        title="iOS Universal Links Not Configured|||iOS Universal Links 미설정",
                        severity="low",
                        finding_type="deep_link_misconfiguration",
                        description=(
                            "/.well-known/apple-app-site-association not found. "
                            "Custom URL schemes are vulnerable to hijacking by malicious apps."
                            "|||"
                            "/.well-known/apple-app-site-association이 없습니다. "
                            "커스텀 URL 스킴이 악성 앱에 의해 하이재킹될 수 있습니다."
                        ),
                        target=ctx.target,
                        affected_component="iOS Universal Links",
                        source_plugin="vxis-mobile-pipeline",
                        cwe_ids=["CWE-939"],
                    )
                    ctx.add_owasp_finding("M8", f.id)

            await mgr.close_all()

        except Exception as exc:
            logger.info("  Deep link testing: %s", exc)

        logger.info("  Deep link analysis: %d URL schemes", len(ctx.url_schemes))

    # ══════════════════════════════════════════════════════════
    # Phase 18: IPC Security
    # ══════════════════════════════════════════════════════════

    async def _phase18_ipc(self, ctx: MobileScanContext) -> None:
        """인텐트 인젝션(Android), 페이스트보드(iOS), 앱 확장 보안."""
        if ctx.is_android:
            await self._test_android_ipc(ctx)
        else:
            await self._test_ios_ipc(ctx)

    async def _test_android_ipc(self, ctx: MobileScanContext) -> None:
        """Android IPC — 인텐트 인젝션, Content Provider SQL 인젝션."""
        import shutil

        adb = shutil.which("adb")
        if not adb:
            logger.info("  adb not found — Android IPC testing skipped")
            return

        # 내보낸 액티비티에 빈 인텐트 전송
        for comp in ctx.exported_components:
            if comp.get("type") not in ("activity", "service", "receiver"):
                continue

            comp_name = comp.get("name", "")
            if not comp_name or not ctx.app_package:
                continue

            try:
                import asyncio
                proc = await asyncio.create_subprocess_exec(
                    adb, "shell", "am", "start",
                    "-n", f"{ctx.app_package}/{comp_name}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode() + stderr.decode()

                if "Error" not in output and "Exception" not in output:
                    ctx.ipc_findings.append({
                        "type": "intent_launch",
                        "component": comp_name,
                        "result": "Launched successfully without permission",
                    })
                    f = ctx.add_finding(
                        title=f"Unauthorized Intent Launch: {comp_name.split('.')[-1]}|||비인가 인텐트 실행",
                        severity="high",
                        finding_type="intent_injection",
                        description=(
                            f"Component {comp_name} launched via ADB intent without "
                            "required permissions or authentication."
                            "|||"
                            f"컴포넌트 {comp_name}이 필요한 퍼미션이나 인증 없이 "
                            "ADB 인텐트로 실행되었습니다."
                        ),
                        target=ctx.target,
                        affected_component=comp_name,
                        source_plugin="vxis-mobile-pipeline",
                        cwe_ids=["CWE-926"],
                    )
                    ctx.add_owasp_finding("M4", f.id)
            except Exception:
                continue

        logger.info("  Android IPC: %d findings", len(ctx.ipc_findings))

    async def _test_ios_ipc(self, ctx: MobileScanContext) -> None:
        """iOS IPC — UIPasteboard 민감 데이터, App Extensions."""
        if not self._frida_available() or not ctx.app_package:
            logger.info("  Frida not available — iOS IPC testing skipped")
            return

        # UIPasteboard 모니터링
        pasteboard_script = "pasteboard_monitor_ios"
        try:
            result = await self._run_frida_script(pasteboard_script, ctx)
            sensitive_data = result.get("sensitive_data", [])
            for item in sensitive_data if isinstance(sensitive_data, list) else []:
                ctx.ipc_findings.append({
                    "type": "pasteboard_leak",
                    "data": str(item)[:100],
                })
                f = ctx.add_finding(
                    title="Sensitive Data in UIPasteboard|||UIPasteboard에 민감 데이터",
                    severity="medium",
                    finding_type="data_leakage_ipc",
                    description=(
                        "Sensitive data detected in UIPasteboard (clipboard). "
                        "Other apps may read clipboard contents on iOS 13 and earlier."
                        "|||"
                        "UIPasteboard(클립보드)에서 민감한 데이터가 탐지되었습니다. "
                        "iOS 13 이하에서는 다른 앱이 클립보드 내용을 읽을 수 있습니다."
                    ),
                    target=ctx.target,
                    affected_component="UIPasteboard",
                    source_plugin="vxis-mobile-pipeline",
                    cwe_ids=["CWE-200"],
                )
                ctx.add_owasp_finding("M6", f.id)
            ctx.frida_scripts_used.append(pasteboard_script)
        except Exception as exc:
            logger.info("  Pasteboard monitoring: %s", exc)

        logger.info("  iOS IPC: %d findings", len(ctx.ipc_findings))

    # ══════════════════════════════════════════════════════════
    # Phase 19: Report
    # ══════════════════════════════════════════════════════════

    async def _phase19_report(self, ctx: MobileScanContext) -> None:
        """NCC Group 스타일 리포트 + OWASP Mobile Top 10 매핑."""
        from vxis.report.generator import ReportGenerator, ReportData
        from vxis.models.finding import Severity
        from pathlib import Path

        platform_label = "iOS" if ctx.is_ios else "Android"
        c = sum(1 for f in ctx.findings if f.severity == Severity.critical)
        h = sum(1 for f in ctx.findings if f.severity == Severity.high)
        m = sum(1 for f in ctx.findings if f.severity == Severity.medium)
        low = sum(1 for f in ctx.findings if f.severity == Severity.low)
        i = sum(1 for f in ctx.findings if f.severity == Severity.informational)

        owasp_summary_lines = []
        for owasp_id, owasp_name in _OWASP_MOBILE.items():
            count = len(ctx.owasp_mobile_coverage.get(owasp_id, []))
            owasp_summary_lines.append(f"  {owasp_id} {owasp_name}: {count} finding(s)")
        owasp_summary = "\n".join(owasp_summary_lines)

        sdk_list = ", ".join(
            f"{s['name']} ({s['risk']} risk)" for s in ctx.third_party_sdks[:10]
        )

        rd = ReportData(
            scan_id=ctx.scan_id,
            client_name="",
            target=ctx.target,
            scan_date=ctx.started_at.strftime("%Y-%m-%d"),
            findings=ctx.findings,
            company_name="VXIS Security",
            author="VXIS MobilePipeline",
            executive_summary=(
                f"VXIS MobilePipeline executed all 20 phases against {platform_label} app "
                f"'{ctx.app_package or ctx.target}'.\n\n"
                f"Platform: {platform_label} | Version: {ctx.app_version or 'unknown'}\n"
                f"Package: {ctx.app_package or 'unknown'}\n"
                f"Binary: {ctx.app_binary_path or 'not provided'}\n\n"
                f"Findings Summary:\n"
                f"  Critical: {c} | High: {h} | Medium: {m} | Low: {low} | Info: {i}\n"
                f"  Total: {len(ctx.findings)}\n\n"
                f"Hardcoded Secrets: {len(ctx.hardcoded_secrets)}\n"
                f"Permissions: {len(ctx.permissions)} ({len([p for p in ctx.permissions if 'dangerous' not in p])} standard)\n"
                f"Exported Components: {len(ctx.exported_components)}\n"
                f"SSL Pinning: {'Detected' if ctx.ssl_pinning_detected else 'Not detected'}\n"
                f"Root Detection: {'Detected' if ctx.root_detection_detected else 'Not detected'}\n"
                f"Third-party SDKs: {len(ctx.third_party_sdks)}\n"
                f"  {sdk_list}\n\n"
                f"OWASP Mobile Top 10 Coverage:\n{owasp_summary}\n\n"
                f"Frida Scripts Used: {len(ctx.frida_scripts_used)}\n"
                f"Duration: {ctx.duration_seconds:.0f}s"
            ),
            methodology=(
                "20-Phase VXIS Mobile Pentesting Pipeline. "
                "Static analysis (jadx/apktool/plistlib), "
                "dynamic analysis (Frida instrumentation), "
                "network interception (mitmproxy/X-Ray), "
                "OWASP Mobile Top 10 2024 coverage."
            ),
        )

        gen = ReportGenerator()
        safe_name = (ctx.app_package or ctx.target).replace(".", "_").replace("/", "_")
        output = Path("reports") / f"VXIS_Mobile_{platform_label}_{safe_name}.html"
        output.parent.mkdir(exist_ok=True)

        try:
            gen.generate_html_file(rd, output)
            logger.info("  Report: %s", output)
        except Exception as exc:
            logger.warning("  Report generation failed: %s", exc)

        # OWASP 커버리지 요약 로깅
        covered = len(ctx.owasp_mobile_coverage)
        logger.info("  OWASP Mobile Top 10 coverage: %d/10", covered)
        for owasp_id, finding_ids in ctx.owasp_mobile_coverage.items():
            logger.info(
                "    %s %s: %d finding(s)",
                owasp_id, _OWASP_MOBILE.get(owasp_id, ""), len(finding_ids),
            )
