"""MobileAnalyzer — 모바일 앱 정적 분석 엔진.

iOS IPA / Android APK 이진 분석:
    - 디컴파일 (jadx / apktool)
    - AndroidManifest.xml / Info.plist 파싱
    - 하드코딩된 시크릿 스캔 (API 키, 비밀번호, 토큰)
    - 내보낸 컴포넌트 분석
    - 퍼미션 분석
    - 바이너리 보호 확인 (PIE, Stack Canary, ARC, ProGuard)
    - 서드파티 SDK 탐지
    - iOS ATS 구성 분석
    - 엔타이틀먼트(Entitlement) 분석

jadx/apktool은 subprocess로 호출. 미설치 시 경고 로그 후 스킵.
"""

from __future__ import annotations

import asyncio
import logging
import plistlib
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

logger = logging.getLogger(__name__)

# ── 시크릿 패턴 사전 ─────────────────────────────────────────────

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key ID",       re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ("AWS Secret Key",          re.compile(r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']')),
    ("Google API Key",          re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')),
    ("Firebase URL",            re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com')),
    ("Firebase API Key",        re.compile(r'(?i)firebase.*api[_-]?key.*["\'][A-Za-z0-9_\-]{30,}["\']')),
    ("JWT Secret",              re.compile(r'(?i)(jwt|json.web.token).{0,20}["\'][a-zA-Z0-9+/=]{32,}["\']')),
    ("Private Key Header",      re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----')),
    ("Stripe Live Key",         re.compile(r'\bsk_live_[0-9a-zA-Z]{24,}\b')),
    ("Stripe Test Key",         re.compile(r'\bsk_test_[0-9a-zA-Z]{24,}\b')),
    ("SendGrid API Key",        re.compile(r'\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b')),
    ("Slack Token",             re.compile(r'\bxox[baprs]-[0-9]{12}-[0-9a-zA-Z]{12,}\b')),
    ("GitHub Token",            re.compile(r'\bghp_[a-zA-Z0-9]{36}\b')),
    ("Generic API Key",         re.compile(r'(?i)api[_\-]?key\s*[=:]\s*["\'][a-zA-Z0-9_\-]{20,}["\']')),
    ("Generic Password",        re.compile(r'(?i)password\s*[=:]\s*["\'][^"\']{8,}["\']')),
    ("Generic Secret",          re.compile(r'(?i)secret\s*[=:]\s*["\'][a-zA-Z0-9_\-+/=]{16,}["\']')),
    ("Bearer Token Hardcoded",  re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}')),
    ("Telegram Bot Token",      re.compile(r'\b[0-9]{9}:[a-zA-Z0-9_\-]{35}\b')),
    ("Twilio Account SID",      re.compile(r'\bAC[a-f0-9]{32}\b')),
    ("Twilio Auth Token",       re.compile(r'(?i)twilio.{0,30}["\'][a-f0-9]{32}["\']')),
    ("Mapbox Token",            re.compile(r'\bpk\.eyJ1[a-zA-Z0-9\.\_\-]{50,}\b')),
]

# ── 위험 퍼미션 목록 (Android) ──────────────────────────────────

_DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.BODY_SENSORS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.MANAGE_ACCOUNTS",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.UWB_RANGING",
}

# ── SDK 탐지 패턴 ────────────────────────────────────────────────

_SDK_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    # (name, category, risk_level, pattern)
    ("Facebook SDK", "analytics", "medium", re.compile(r'com\.facebook\.android|FacebookSdk')),
    ("Google Analytics / Firebase Analytics", "analytics", "low", re.compile(r'com\.google\.firebase\.analytics|GoogleAnalytics')),
    ("Adjust", "analytics", "low", re.compile(r'com\.adjust\.sdk')),
    ("AppsFlyer", "analytics", "low", re.compile(r'com\.appsflyer|AppsFlyerLib')),
    ("Crashlytics / Firebase Crashlytics", "crash_reporting", "low", re.compile(r'com\.crashlytics|firebase\.crashlytics')),
    ("Sentry", "crash_reporting", "low", re.compile(r'io\.sentry\.android')),
    ("Mixpanel", "analytics", "low", re.compile(r'com\.mixpanel\.android')),
    ("Amplitude", "analytics", "low", re.compile(r'com\.amplitude\.android')),
    ("Braze / Appboy", "marketing", "medium", re.compile(r'com\.appboy|com\.braze')),
    ("Intercom", "support", "low", re.compile(r'io\.intercom\.android')),
    ("Stripe", "payment", "high", re.compile(r'com\.stripe\.android')),
    ("Braintree", "payment", "high", re.compile(r'com\.braintreepayments')),
    ("PayPal", "payment", "high", re.compile(r'com\.paypal\.android')),
    ("RevenueCat", "iap", "medium", re.compile(r'com\.revenuecat\.purchases')),
    ("OkHttp", "networking", "low", re.compile(r'okhttp3|com\.squareup\.okhttp')),
    ("Retrofit", "networking", "low", re.compile(r'retrofit2|com\.squareup\.retrofit')),
    ("Glide", "media", "low", re.compile(r'com\.bumptech\.glide')),
    ("Picasso", "media", "low", re.compile(r'com\.squareup\.picasso')),
    ("LeakCanary", "debugging", "high", re.compile(r'com\.squareup\.leakcanary')),
    ("Timber", "logging", "medium", re.compile(r'timber\.log')),
    ("RxJava", "reactive", "low", re.compile(r'io\.reactivex')),
    ("Dagger", "di", "low", re.compile(r'dagger\.android|com\.google\.dagger')),
    ("Unity Ads", "advertising", "medium", re.compile(r'com\.unity3d\.ads')),
    ("AdMob", "advertising", "medium", re.compile(r'com\.google\.android\.gms\.ads')),
]


# ════════════════════════════════════════════════════════════════
# Data Classes
# ════════════════════════════════════════════════════════════════


@dataclass
class SecretFinding:
    """바이너리/리소스에서 발견된 하드코딩 시크릿."""

    secret_type: str
    value: str
    file_path: str
    line_number: int = 0
    context: str = ""

    @property
    def value_preview(self) -> str:
        return self.value[:30] + "..." if len(self.value) > 30 else self.value


@dataclass
class BinaryProtection:
    """바이너리 보호 기능 평가 결과."""

    pie_enabled: bool = False          # Position Independent Executable
    stack_canary_enabled: bool = False  # 스택 카나리
    arc_enabled: bool = False          # Automatic Reference Counting (iOS)
    nx_bit_enabled: bool = False       # Non-Executable bit
    stripped_symbols: bool = False     # 디버그 심볼 제거
    proguard_enabled: bool = False     # Android ProGuard/R8 난독화
    obfuscation_level: str = "none"    # "none" | "basic" | "advanced"
    rpath_safe: bool = True            # @rpath injection (iOS)

    @property
    def risk_summary(self) -> str:
        issues = []
        if not self.pie_enabled:
            issues.append("No PIE")
        if not self.stack_canary_enabled:
            issues.append("No Stack Canary")
        if not self.nx_bit_enabled:
            issues.append("No NX bit")
        if not self.stripped_symbols:
            issues.append("Debug symbols present")
        if not self.proguard_enabled:
            issues.append("No ProGuard")
        return ", ".join(issues) if issues else "All protections enabled"


@dataclass
class ManifestInfo:
    """파싱된 AndroidManifest.xml 또는 Info.plist 정보."""

    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions: list[str] = field(default_factory=list)
    exported_activities: list[dict[str, Any]] = field(default_factory=list)
    exported_services: list[dict[str, Any]] = field(default_factory=list)
    exported_receivers: list[dict[str, Any]] = field(default_factory=list)
    exported_providers: list[dict[str, Any]] = field(default_factory=list)
    url_schemes: list[str] = field(default_factory=list)
    deep_links: list[str] = field(default_factory=list)
    debuggable: bool = False
    allow_backup: bool = True
    network_security_config: bool = False
    # iOS only
    ats_config: dict[str, Any] = field(default_factory=dict)
    entitlements: dict[str, Any] = field(default_factory=dict)


@dataclass
class APKAnalysis:
    """Android APK 전체 정적 분석 결과."""

    package_name: str = ""
    manifest: ManifestInfo = field(default_factory=ManifestInfo)
    binary_protection: BinaryProtection = field(default_factory=BinaryProtection)
    secrets: list[SecretFinding] = field(default_factory=list)
    third_party_sdks: list[dict[str, Any]] = field(default_factory=list)
    decompile_path: str = ""
    error: str = ""

    @property
    def dangerous_permissions(self) -> list[str]:
        return [p for p in self.manifest.permissions if p in _DANGEROUS_PERMISSIONS]


@dataclass
class IPAAnalysis:
    """iOS IPA 전체 정적 분석 결과."""

    bundle_id: str = ""
    manifest: ManifestInfo = field(default_factory=ManifestInfo)
    binary_protection: BinaryProtection = field(default_factory=BinaryProtection)
    secrets: list[SecretFinding] = field(default_factory=list)
    third_party_sdks: list[dict[str, Any]] = field(default_factory=list)
    extract_path: str = ""
    error: str = ""


# ════════════════════════════════════════════════════════════════
# MobileAnalyzer
# ════════════════════════════════════════════════════════════════


class MobileAnalyzer:
    """모바일 앱 정적 분석 오케스트레이터.

    APK/IPA 파일을 받아 전체 정적 분석 결과를 반환.
    외부 도구(jadx, apktool, aapt2)가 없으면 가능한 분석만 수행.
    """

    def __init__(self, work_dir: str | None = None) -> None:
        self._work_dir = work_dir or tempfile.mkdtemp(prefix="vxis_mobile_")
        self._jadx_bin = shutil.which("jadx")
        self._apktool_bin = shutil.which("apktool")
        self._aapt2_bin = shutil.which("aapt2") or shutil.which("aapt")
        self._otool_bin = shutil.which("otool")
        self._nm_bin = shutil.which("nm")

        if not self._jadx_bin:
            logger.warning("[MobileAnalyzer] jadx not installed — decompilation skipped")
        if not self._apktool_bin:
            logger.warning("[MobileAnalyzer] apktool not installed — resource decoding skipped")

    # ── APK Analysis ─────────────────────────────────────────────

    async def analyze_apk(self, apk_path: str) -> APKAnalysis:
        """Android APK 전체 정적 분석."""
        result = APKAnalysis()
        apk = Path(apk_path)

        if not apk.exists():
            result.error = f"APK not found: {apk_path}"
            logger.error("[APK] %s", result.error)
            return result

        logger.info("[APK] Analyzing: %s", apk_path)

        # 1. 압축 풀기 (APK는 ZIP 형식)
        unzip_dir = Path(self._work_dir) / f"apk_raw_{apk.stem}"
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                zf.extractall(unzip_dir)
            logger.info("[APK] Extracted to %s", unzip_dir)
        except zipfile.BadZipFile as exc:
            result.error = f"Bad ZIP: {exc}"
            return result

        # 2. jadx 디컴파일
        decompile_dir = Path(self._work_dir) / f"apk_jadx_{apk.stem}"
        if self._jadx_bin:
            await self._run_jadx(apk_path, str(decompile_dir))
            result.decompile_path = str(decompile_dir)
        else:
            result.decompile_path = str(unzip_dir)

        # 3. AndroidManifest.xml 파싱
        manifest = await self._parse_android_manifest(str(unzip_dir), str(decompile_dir))
        result.manifest = manifest
        result.package_name = manifest.package_name

        # 4. 시크릿 스캔
        scan_dirs = [str(decompile_dir)] if decompile_dir.exists() else [str(unzip_dir)]
        result.secrets = await self.scan_secrets(scan_dirs[0])
        logger.info("[APK] Secrets found: %d", len(result.secrets))

        # 5. SDK 탐지
        result.third_party_sdks = self._detect_sdks_in_dir(scan_dirs[0])
        logger.info("[APK] Third-party SDKs: %d", len(result.third_party_sdks))

        # 6. 바이너리 보호 분석
        result.binary_protection = self._analyze_apk_protections(
            str(unzip_dir), scan_dirs[0],
        )

        return result

    async def _run_jadx(self, apk_path: str, output_dir: str) -> None:
        """jadx 디컴파일 실행."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self._jadx_bin,  # type: ignore[arg-type]
                "-d", output_dir,
                "--no-res",
                apk_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            if proc.returncode != 0:
                logger.warning("[jadx] Exit %d: %s", proc.returncode, stderr.decode()[:200])
            else:
                logger.info("[jadx] Decompiled to %s", output_dir)
        except asyncio.TimeoutError:
            logger.warning("[jadx] Timeout after 300s")
        except Exception as exc:
            logger.warning("[jadx] Failed: %s", exc)

    async def _parse_android_manifest(
        self, unzip_dir: str, decompile_dir: str,
    ) -> ManifestInfo:
        """AndroidManifest.xml 파싱."""
        info = ManifestInfo()

        # jadx 디컴파일된 버전에서 먼저 시도 (XML이 읽기 좋음)
        manifest_paths = [
            Path(decompile_dir) / "resources" / "AndroidManifest.xml",
            Path(unzip_dir) / "AndroidManifest.xml",  # raw binary (일반적으로 파싱 불가)
        ]

        manifest_text = ""
        for mp in manifest_paths:
            if mp.exists():
                try:
                    manifest_text = mp.read_text(errors="replace")
                    if "<manifest" in manifest_text:
                        break
                except OSError:
                    continue

        if not manifest_text or "<manifest" not in manifest_text:
            # apktool로 디코딩 시도
            if self._apktool_bin:
                manifest_text = await self._decode_manifest_with_apktool(
                    str(Path(unzip_dir).parent / (Path(unzip_dir).name.replace("apk_raw_", "") + ".apk")),
                    unzip_dir,
                )

        if not manifest_text:
            logger.warning("[Manifest] Could not read AndroidManifest.xml")
            return info

        try:
            root = ElementTree.fromstring(manifest_text)
        except ElementTree.ParseError as exc:
            logger.warning("[Manifest] XML parse error: %s", exc)
            return info

        ns = "{http://schemas.android.com/apk/res/android}"
        info.package_name = root.get("package", "")
        info.version_name = root.get(f"{ns}versionName", "")
        info.version_code = root.get(f"{ns}versionCode", "")

        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            min_sdk = uses_sdk.get(f"{ns}minSdkVersion")
            target_sdk = uses_sdk.get(f"{ns}targetSdkVersion")
            info.min_sdk = int(min_sdk) if min_sdk and min_sdk.isdigit() else None
            info.target_sdk = int(target_sdk) if target_sdk and target_sdk.isdigit() else None

        # 퍼미션
        for perm in root.findall("uses-permission"):
            perm_name = perm.get(f"{ns}name", "")
            if perm_name:
                info.permissions.append(perm_name)

        # Application 속성
        app = root.find("application")
        if app is not None:
            debuggable_val = app.get(f"{ns}debuggable", "false")
            info.debuggable = debuggable_val.lower() in ("true", "1")
            allow_backup_val = app.get(f"{ns}allowBackup", "true")
            info.allow_backup = allow_backup_val.lower() not in ("false", "0")
            info.network_security_config = app.get(f"{ns}networkSecurityConfig") is not None

            # 컴포넌트 분석
            for tag, target_list in [
                ("activity", info.exported_activities),
                ("service", info.exported_services),
                ("receiver", info.exported_receivers),
                ("provider", info.exported_providers),
            ]:
                for comp in app.findall(tag):
                    exported = comp.get(f"{ns}exported", "")
                    name = comp.get(f"{ns}name", "")
                    has_intent_filter = comp.find("intent-filter") is not None

                    # exported 기본값: intent-filter가 있으면 true
                    is_exported = (
                        exported.lower() in ("true", "1")
                        or (exported == "" and has_intent_filter)
                    )

                    if is_exported:
                        entry: dict[str, Any] = {
                            "name": name,
                            "type": tag,
                            "exported": True,
                            "intent_filters": [],
                        }
                        for intent_filter in comp.findall("intent-filter"):
                            actions = [
                                a.get(f"{ns}name", "")
                                for a in intent_filter.findall("action")
                            ]
                            entry["intent_filters"].extend(actions)
                        target_list.append(entry)

                    # Deep links 수집
                    for intent_filter in comp.findall("intent-filter"):
                        for data in intent_filter.findall("data"):
                            scheme = data.get(f"{ns}scheme", "")
                            host = data.get(f"{ns}host", "")
                            path_prefix = data.get(f"{ns}pathPrefix", "")
                            if scheme and scheme not in ("http", "https"):
                                info.url_schemes.append(scheme)
                                deep_link = f"{scheme}://{host}{path_prefix}"
                                info.deep_links.append(deep_link)

        return info

    async def _decode_manifest_with_apktool(
        self, apk_path: str, output_dir: str,
    ) -> str:
        """apktool로 AndroidManifest.xml 바이너리 XML 디코딩."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self._apktool_bin,  # type: ignore[arg-type]
                "d", apk_path,
                "-o", output_dir,
                "-f",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            manifest = Path(output_dir) / "AndroidManifest.xml"
            if manifest.exists():
                return manifest.read_text(errors="replace")
        except Exception as exc:
            logger.warning("[apktool] %s", exc)
        return ""

    def _analyze_apk_protections(
        self, unzip_dir: str, source_dir: str,
    ) -> BinaryProtection:
        """APK 바이너리 보호 기능 분석."""
        bp = BinaryProtection()

        # ProGuard 탐지: 소스에 난독화된 클래스명 패턴 (a.a.a, b.c.d)
        obf_count = 0
        source_path = Path(source_dir)
        if source_path.exists():
            java_files = list(source_path.rglob("*.java"))[:50]
            for jf in java_files:
                try:
                    content = jf.read_text(errors="replace")
                    # 단일 문자 클래스명은 ProGuard 난독화 징표
                    if re.search(r'\bclass [a-z]\b', content):
                        obf_count += 1
                except OSError:
                    continue

        if obf_count > 5:
            bp.proguard_enabled = True
            bp.obfuscation_level = "advanced" if obf_count > 20 else "basic"

        # .so 라이브러리에서 PIE/NX/스택 카나리 확인
        lib_dir = Path(unzip_dir) / "lib"
        if lib_dir.exists():
            so_files = list(lib_dir.rglob("*.so"))[:5]
            for so_file in so_files:
                bp_result = self._check_elf_protections(str(so_file))
                bp.pie_enabled = bp.pie_enabled or bp_result.get("pie", False)
                bp.stack_canary_enabled = (
                    bp.stack_canary_enabled or bp_result.get("canary", False)
                )
                bp.nx_bit_enabled = bp.nx_bit_enabled or bp_result.get("nx", False)

        # 디버그 심볼 확인
        bp.stripped_symbols = not self._has_debug_symbols_apk(unzip_dir)

        if not bp.obfuscation_level or bp.obfuscation_level == "none":
            bp.obfuscation_level = "basic" if bp.proguard_enabled else "none"

        return bp

    def _check_elf_protections(self, so_path: str) -> dict[str, bool]:
        """ELF 바이너리 보호 기능 확인 (readelf/nm 사용)."""
        result: dict[str, bool] = {"pie": False, "canary": False, "nx": False}
        readelf_bin = shutil.which("readelf")
        if not readelf_bin:
            return result
        try:
            proc = subprocess.run(
                [readelf_bin, "-h", so_path],
                capture_output=True, text=True, timeout=10,
            )
            output = proc.stdout
            if "DYN (Shared object file)" in output or "DYN (Position-Independent Executable)" in output:
                result["pie"] = True

            proc2 = subprocess.run(
                [readelf_bin, "-s", so_path],
                capture_output=True, text=True, timeout=10,
            )
            symbols = proc2.stdout
            result["canary"] = "__stack_chk_fail" in symbols or "__stack_chk_guard" in symbols
        except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError):
            pass
        return result

    def _has_debug_symbols_apk(self, unzip_dir: str) -> bool:
        """APK에 디버그 심볼이 있는지 확인."""
        # mapping.txt가 있으면 ProGuard 사용 확인 가능
        # 실제로는 DEX 파싱이 필요하지만 단순히 파일 크기로 추론
        dex_path = Path(unzip_dir) / "classes.dex"
        if dex_path.exists():
            # 10MB 이상이면 디버그 심볼 포함 가능성 높음 (휴리스틱)
            return dex_path.stat().st_size > 10 * 1024 * 1024
        return False

    def _detect_sdks_in_dir(self, source_dir: str) -> list[dict[str, Any]]:
        """소스/리소스 디렉터리에서 서드파티 SDK 탐지."""
        found: list[dict[str, Any]] = []
        detected_names: set[str] = set()
        source_path = Path(source_dir)

        if not source_path.exists():
            return found

        # 소스 파일 샘플링 (너무 많으면 느림)
        all_files = list(source_path.rglob("*.java"))[:200]
        all_files += list(source_path.rglob("*.kt"))[:100]
        all_files += list(source_path.rglob("*.smali"))[:100]

        combined_text = ""
        for f in all_files:
            try:
                combined_text += f.read_text(errors="replace")[:2000]
            except OSError:
                continue

        for name, category, risk, pattern in _SDK_PATTERNS:
            if name not in detected_names and pattern.search(combined_text):
                detected_names.add(name)
                found.append({
                    "name": name,
                    "category": category,
                    "risk": risk,
                    "version": "unknown",
                })

        logger.info("[SDK] Detected %d SDKs", len(found))
        return found

    # ── IPA Analysis ─────────────────────────────────────────────

    async def analyze_ipa(self, ipa_path: str) -> IPAAnalysis:
        """iOS IPA 전체 정적 분석."""
        result = IPAAnalysis()
        ipa = Path(ipa_path)

        if not ipa.exists():
            result.error = f"IPA not found: {ipa_path}"
            logger.error("[IPA] %s", result.error)
            return result

        logger.info("[IPA] Analyzing: %s", ipa_path)

        # 1. 압축 풀기 (IPA는 ZIP)
        extract_dir = Path(self._work_dir) / f"ipa_{ipa.stem}"
        try:
            with zipfile.ZipFile(ipa_path, "r") as zf:
                zf.extractall(extract_dir)
        except zipfile.BadZipFile as exc:
            result.error = f"Bad ZIP: {exc}"
            return result

        result.extract_path = str(extract_dir)

        # .app 번들 찾기
        app_bundles = list(extract_dir.glob("Payload/*.app"))
        if not app_bundles:
            result.error = "No .app bundle found in IPA Payload/"
            return result

        app_bundle = app_bundles[0]
        logger.info("[IPA] App bundle: %s", app_bundle.name)

        # 2. Info.plist 파싱
        manifest = await self._parse_info_plist(app_bundle)
        result.manifest = manifest
        result.bundle_id = manifest.package_name

        # 3. 엔타이틀먼트 분석
        manifest.entitlements = self._extract_entitlements(app_bundle)

        # 4. ATS 구성 분석
        manifest.ats_config = self._analyze_ats(manifest.entitlements, app_bundle)

        # 5. 시크릿 스캔 — 바이너리 strings + 리소스
        result.secrets = await self.scan_secrets(str(app_bundle))
        # 바이너리에서 strings 추출
        main_binary = app_bundle / app_bundle.stem
        if main_binary.exists():
            binary_secrets = self._scan_binary_strings(str(main_binary))
            result.secrets.extend(binary_secrets)

        logger.info("[IPA] Secrets found: %d", len(result.secrets))

        # 6. SDK 탐지 (Frameworks 디렉터리)
        frameworks_dir = app_bundle / "Frameworks"
        if frameworks_dir.exists():
            result.third_party_sdks = self._detect_ios_sdks(frameworks_dir)
        result.third_party_sdks.extend(self._detect_sdks_in_dir(str(app_bundle)))

        # 7. 바이너리 보호 분석
        result.binary_protection = self._analyze_ios_binary_protections(app_bundle)

        return result

    async def _parse_info_plist(self, app_bundle: Path) -> ManifestInfo:
        """Info.plist 파싱."""
        info = ManifestInfo()
        plist_path = app_bundle / "Info.plist"

        if not plist_path.exists():
            logger.warning("[IPA] Info.plist not found in %s", app_bundle)
            return info

        try:
            with open(plist_path, "rb") as f:
                plist_data = plistlib.load(f)
        except (plistlib.InvalidFileException, OSError) as exc:
            logger.warning("[IPA] Info.plist parse error: %s", exc)
            return info

        info.package_name = plist_data.get("CFBundleIdentifier", "")
        info.version_name = plist_data.get("CFBundleShortVersionString", "")
        info.version_code = str(plist_data.get("CFBundleVersion", ""))

        # URL Schemes
        url_types = plist_data.get("CFBundleURLTypes", [])
        for url_type in url_types:
            schemes = url_type.get("CFBundleURLSchemes", [])
            info.url_schemes.extend(schemes)

        # Required Device Capabilities → permissions 역할
        capabilities = plist_data.get("UIRequiredDeviceCapabilities", [])
        if isinstance(capabilities, list):
            info.permissions.extend(capabilities)

        # Privacy usage descriptions (카메라, 마이크 등)
        for key in plist_data:
            if key.endswith("UsageDescription"):
                info.permissions.append(key)

        return info

    def _extract_entitlements(self, app_bundle: Path) -> dict[str, Any]:
        """바이너리 엔타이틀먼트 추출 (codesign --display)."""
        entitlements: dict[str, Any] = {}
        codesign_bin = shutil.which("codesign")
        if not codesign_bin:
            return entitlements

        main_binary = app_bundle / app_bundle.stem
        if not main_binary.exists():
            return entitlements

        try:
            proc = subprocess.run(
                [codesign_bin, "--display", "--entitlements", "-", str(main_binary)],
                capture_output=True, timeout=30,
            )
            stdout = proc.stdout
            if stdout:
                # codesign 출력은 바이너리 plist 또는 XML plist일 수 있음
                try:
                    entitlements = plistlib.loads(stdout)
                except Exception:
                    # XML 파싱 시도
                    try:
                        # stdout에서 plist XML 추출
                        text = stdout.decode(errors="replace")
                        start = text.find("<?xml")
                        if start >= 0:
                            entitlements = plistlib.loads(text[start:].encode())
                    except Exception:
                        pass
        except (subprocess.TimeoutExpired, OSError):
            pass

        return entitlements

    def _analyze_ats(
        self,
        entitlements: dict[str, Any],
        app_bundle: Path,
    ) -> dict[str, Any]:
        """App Transport Security (ATS) 구성 분석."""
        ats: dict[str, Any] = {"ats_disabled": False, "exceptions": []}

        plist_path = app_bundle / "Info.plist"
        if not plist_path.exists():
            return ats

        try:
            with open(plist_path, "rb") as f:
                plist_data = plistlib.load(f)
        except Exception:
            return ats

        nsa = plist_data.get("NSAppTransportSecurity", {})
        ats["ats_disabled"] = nsa.get("NSAllowsArbitraryLoads", False)
        exception_domains = nsa.get("NSExceptionDomains", {})

        for domain, config in exception_domains.items():
            allows_http = config.get("NSExceptionAllowsInsecureHTTPLoads", False)
            min_tls = config.get("NSExceptionMinimumTLSVersion", "")
            ats["exceptions"].append({
                "domain": domain,
                "allows_http": allows_http,
                "min_tls": min_tls,
            })

        return ats

    def _analyze_ios_binary_protections(self, app_bundle: Path) -> BinaryProtection:
        """iOS 바이너리 보호 기능 분석."""
        bp = BinaryProtection()
        main_binary = app_bundle / app_bundle.stem

        if not main_binary.exists() or not self._otool_bin:
            return bp

        try:
            # otool -hv — 헤더 확인
            proc = subprocess.run(
                [self._otool_bin, "-hv", str(main_binary)],
                capture_output=True, text=True, timeout=30,
            )
            header = proc.stdout
            bp.pie_enabled = "PIE" in header

            # otool -l — 로드 커맨드 확인
            proc2 = subprocess.run(
                [self._otool_bin, "-l", str(main_binary)],
                capture_output=True, text=True, timeout=30,
            )
            load_cmds = proc2.stdout
            # ARC 확인: _objc_release 심볼
            bp.arc_enabled = "_objc_release" in load_cmds

            # 스택 카나리 확인
            if self._nm_bin:
                proc3 = subprocess.run(
                    [self._nm_bin, str(main_binary)],
                    capture_output=True, text=True, timeout=30,
                )
                symbols = proc3.stdout
                bp.stack_canary_enabled = (
                    "___stack_chk_fail" in symbols or "___stack_chk_guard" in symbols
                )

            # 심볼 strip 확인
            proc4 = subprocess.run(
                [self._otool_bin, "-Sv", str(main_binary)],
                capture_output=True, text=True, timeout=30,
            )
            bp.stripped_symbols = "No symbols" in proc4.stdout

        except (subprocess.TimeoutExpired, OSError):
            pass

        bp.obfuscation_level = "none"
        return bp

    def _detect_ios_sdks(self, frameworks_dir: Path) -> list[dict[str, Any]]:
        """iOS Frameworks 디렉터리에서 SDK 탐지."""
        found = []
        for framework in frameworks_dir.iterdir():
            if framework.suffix == ".framework":
                name = framework.stem
                found.append({
                    "name": name,
                    "category": "framework",
                    "risk": "low",
                    "version": "unknown",
                })
        return found

    def _scan_binary_strings(self, binary_path: str) -> list[SecretFinding]:
        """바이너리에서 strings 추출 후 시크릿 스캔."""
        findings = []
        strings_bin = shutil.which("strings")
        if not strings_bin:
            return findings

        try:
            proc = subprocess.run(
                [strings_bin, "-n", "8", binary_path],
                capture_output=True, text=True, timeout=60,
            )
            content = proc.stdout
        except (subprocess.TimeoutExpired, OSError):
            return findings

        for line_num, line in enumerate(content.splitlines(), 1):
            for secret_type, pattern in _SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    findings.append(SecretFinding(
                        secret_type=secret_type,
                        value=match.group(0),
                        file_path=binary_path,
                        line_number=line_num,
                        context=line[:200],
                    ))

        return findings

    # ── Secret Scanning ──────────────────────────────────────────

    async def scan_secrets(self, source_dir: str) -> list[SecretFinding]:
        """소스 디렉터리에서 하드코딩 시크릿 스캔.

        지원 파일: .java, .kt, .swift, .m, .h, .js, .ts, .json,
                   .xml, .plist, .properties, .gradle, .yaml, .yml
        """
        findings: list[SecretFinding] = []
        source_path = Path(source_dir)

        if not source_path.exists():
            return findings

        extensions = {
            ".java", ".kt", ".swift", ".m", ".h",
            ".js", ".ts", ".json", ".xml", ".plist",
            ".properties", ".gradle", ".yaml", ".yml",
            ".config", ".env", ".txt",
        }

        # 파일 수집 (최대 1000개)
        files: list[Path] = []
        for ext in extensions:
            files.extend(list(source_path.rglob(f"*{ext}"))[:200])
        files = files[:1000]

        for file_path in files:
            try:
                content = file_path.read_text(errors="replace")
            except OSError:
                continue

            for line_num, line in enumerate(content.splitlines(), 1):
                # 짧은 줄은 스킵
                if len(line.strip()) < 10:
                    continue
                # 주석 줄은 낮은 우선순위 (완전히 스킵하지 않음 — 시크릿 있을 수 있음)
                for secret_type, pattern in _SECRET_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        findings.append(SecretFinding(
                            secret_type=secret_type,
                            value=match.group(0),
                            file_path=str(file_path.relative_to(source_path)),
                            line_number=line_num,
                            context=line[:300],
                        ))

        # 중복 제거 (같은 값, 같은 파일)
        seen: set[tuple[str, str]] = set()
        unique_findings = []
        for sf in findings:
            key = (sf.value[:30], sf.file_path)
            if key not in seen:
                seen.add(key)
                unique_findings.append(sf)

        logger.info("[SecretScan] %d unique secrets in %s", len(unique_findings), source_dir)
        return unique_findings
