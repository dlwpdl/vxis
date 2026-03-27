"""SSLPinningPlugin — SSL 인증서 피닝 탐지 및 우회 플러그인."""

from __future__ import annotations

import re
import zipfile
import tempfile
from pathlib import Path
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# SSL 피닝 탐지 패턴
_PINNING_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OkHttp CertificatePinner",  re.compile(r'CertificatePinner|okhttp3.*pin')),
    ("TrustKit Android",          re.compile(r'TrustKit\.initSharedInstance|TrustKitConfiguration')),
    ("Custom TrustManager",       re.compile(r'X509TrustManager|checkServerTrusted')),
    ("Network Security Config",   re.compile(r'network_security_config|@xml/network_security')),
    ("Conscrypt Pinning",         re.compile(r'conscrypt.*pin|ConscryptProvider')),
    ("AFNetworking Pinning",      re.compile(r'AFSSLPinningMode|pinnedCertificates')),
    ("TrustKit iOS",              re.compile(r'TrustKit|kTSKPinnedDomains')),
    ("URLSession Challenge",      re.compile(r'didReceiveChallenge|ServerTrustPolicy')),
    ("SecTrust API",              re.compile(r'SecTrustEvaluate|SecPolicyCreateSSL')),
    ("Alamofire ServerTrust",     re.compile(r'ServerTrustManager|PinnedCertificatesTrustEvaluator')),
]


class SSLPinningPlugin(BasePlugin):
    """SSL 피닝 탐지 플러그인.

    정적 분석으로 SSL 피닝 구현 여부 탐지.
    mitmproxy로 실제 피닝 동작 확인.
    Frida 스크립트 선택 로직 포함.
    """

    _meta = PluginMeta(
        name="ssl_pinning",
        version="1.0.0",
        tool_binary="mitmproxy",
        category="mobile",
        tier=2,
        depends_on=(),
        optional_depends=("frida",),
        timeout_seconds=300,
        produces=("ssl_pinning_detected", "bypass_scripts"),
    )

    @property
    def meta(self) -> PluginMeta:
        return self._meta

    def build_command(
        self,
        target: str,
        scan_profile: str,
        ctx: DAGContext,
        tool_config: dict[str, Any],
    ) -> str:
        """mitmproxy 프록시 시작 명령."""
        port = tool_config.get("proxy_port", 8888)
        return f"mitmproxy --listen-port {port} --mode regular --ssl-insecure"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """mitmproxy 출력에서 SSL 오류 파싱."""
        pinning_errors = []
        for line in (raw_stdout + raw_stderr).splitlines():
            if "certificate" in line.lower() and "error" in line.lower():
                pinning_errors.append(line.strip())
            elif "ssl" in line.lower() and "handshake" in line.lower():
                pinning_errors.append(line.strip())

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={
                "pinning_errors": pinning_errors[:20],
                "pinning_detected": len(pinning_errors) > 0,
            },
        )

    def detect_pinning_static(
        self,
        binary_path: str,
        platform: str = "android",
    ) -> dict[str, Any]:
        """APK/IPA 정적 분석으로 SSL 피닝 탐지."""
        detected: list[dict[str, str]] = []

        if not Path(binary_path).exists():
            return {"detected": False, "patterns": [], "error": "Binary not found"}

        try:
            with zipfile.ZipFile(binary_path, "r") as zf:
                tmp = tempfile.mkdtemp(prefix="vxis_ssl_")
                zf.extractall(tmp)
        except zipfile.BadZipFile:
            return {"detected": False, "patterns": [], "error": "Invalid ZIP/APK/IPA"}

        extensions = (
            [".java", ".kt", ".smali", ".xml"]
            if platform == "android"
            else [".swift", ".m", ".h", ".plist"]
        )

        for ext in extensions:
            for f in list(Path(tmp).rglob(f"*{ext}"))[:100]:
                try:
                    content = f.read_text(errors="replace")
                    for pattern_name, pattern in _PINNING_PATTERNS:
                        if pattern.search(content):
                            detected.append({
                                "pattern": pattern_name,
                                "file": f.name,
                            })
                except OSError:
                    continue

        return {
            "detected": len(detected) > 0,
            "patterns": detected,
            "bypass_scripts": self.get_bypass_scripts(platform, detected),
        }

    def get_bypass_scripts(
        self,
        platform: str,
        detected_patterns: list[dict[str, str]],
    ) -> list[str]:
        """탐지된 피닝 패턴에 맞는 Frida 우회 스크립트 추천."""
        scripts = []
        pattern_names = {p["pattern"] for p in detected_patterns}

        if platform == "android":
            scripts.append("ssl_pinning_bypass_android_universal")
            if "OkHttp CertificatePinner" in pattern_names:
                scripts.append("ssl_pinning_bypass_okhttp3")
            if "TrustKit Android" in pattern_names:
                scripts.append("ssl_pinning_bypass_trustkit_android")
            if "Conscrypt Pinning" in pattern_names:
                scripts.append("ssl_pinning_bypass_conscrypt")
            if "Network Security Config" in pattern_names:
                scripts.append("ssl_pinning_bypass_netsec_config")
        else:
            scripts.append("ssl_pinning_bypass_ios_universal")
            if "AFNetworking Pinning" in pattern_names:
                scripts.append("ssl_pinning_bypass_afnetworking")
            if "TrustKit iOS" in pattern_names:
                scripts.append("ssl_pinning_bypass_trustkit_ios")
            if "Alamofire ServerTrust" in pattern_names:
                scripts.append("ssl_pinning_bypass_alamofire")

        return scripts

    def validate_environment(self) -> bool:
        """mitmproxy가 없어도 정적 분석은 가능."""
        return True  # Python zipfile + regex는 항상 사용 가능
