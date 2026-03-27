"""FridaScannerPlugin — Frida 동적 분석 플러그인."""

from __future__ import annotations

import shutil
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


# Frida 스크립트 카탈로그 — 목적별 분류
_FRIDA_SCRIPT_CATALOG: dict[str, dict[str, Any]] = {
    # SSL Pinning Bypass
    "ssl_pinning_bypass_android_universal": {
        "platform": "android",
        "category": "ssl_bypass",
        "description": "Universal Android SSL pinning bypass",
        "risk": "high",
    },
    "ssl_pinning_bypass_okhttp3": {
        "platform": "android",
        "category": "ssl_bypass",
        "description": "OkHttp3 CertificatePinner bypass",
        "risk": "high",
    },
    "ssl_pinning_bypass_ios_universal": {
        "platform": "ios",
        "category": "ssl_bypass",
        "description": "Universal iOS SSL pinning bypass",
        "risk": "high",
    },
    # Root Detection Bypass
    "root_detection_bypass_android": {
        "platform": "android",
        "category": "root_bypass",
        "description": "Android root detection bypass (RootBeer, SafetyNet)",
        "risk": "medium",
    },
    "jailbreak_bypass_ios": {
        "platform": "ios",
        "category": "root_bypass",
        "description": "iOS jailbreak detection bypass",
        "risk": "medium",
    },
    # Dynamic Analysis
    "method_tracer_android": {
        "platform": "android",
        "category": "tracing",
        "description": "Android method call tracer",
        "risk": "low",
    },
    "class_dumper_android": {
        "platform": "android",
        "category": "recon",
        "description": "Android loaded class dumper",
        "risk": "low",
    },
    "crypto_monitor_android": {
        "platform": "android",
        "category": "crypto",
        "description": "Android crypto API monitor",
        "risk": "low",
    },
    "method_tracer_ios": {
        "platform": "ios",
        "category": "tracing",
        "description": "iOS Objective-C/Swift method tracer",
        "risk": "low",
    },
    "class_dumper_ios": {
        "platform": "ios",
        "category": "recon",
        "description": "iOS class list dumper",
        "risk": "low",
    },
    "crypto_monitor_ios": {
        "platform": "ios",
        "category": "crypto",
        "description": "iOS CommonCrypto/CryptoKit monitor",
        "risk": "low",
    },
    # Biometric Bypass
    "biometric_bypass_android": {
        "platform": "android",
        "category": "auth_bypass",
        "description": "Android BiometricPrompt bypass",
        "risk": "critical",
    },
    "biometric_bypass_ios": {
        "platform": "ios",
        "category": "auth_bypass",
        "description": "iOS LocalAuthentication bypass",
        "risk": "critical",
    },
    # IAP Bypass
    "iap_bypass_android": {
        "platform": "android",
        "category": "iap_bypass",
        "description": "Android Google Play Billing bypass",
        "risk": "critical",
    },
    "iap_bypass_ios": {
        "platform": "ios",
        "category": "iap_bypass",
        "description": "iOS StoreKit purchase bypass",
        "risk": "critical",
    },
    # Storage
    "keychain_dump_ios": {
        "platform": "ios",
        "category": "storage",
        "description": "iOS Keychain data dumper",
        "risk": "high",
    },
    # IPC
    "pasteboard_monitor_ios": {
        "platform": "ios",
        "category": "ipc",
        "description": "iOS UIPasteboard content monitor",
        "risk": "medium",
    },
    "intent_monitor_android": {
        "platform": "android",
        "category": "ipc",
        "description": "Android Intent traffic monitor",
        "risk": "low",
    },
}


class FridaScannerPlugin(BasePlugin):
    """Frida 동적 분석 플러그인.

    FridaBridge를 통해 대상 앱에 Frida 스크립트를 주입하고
    런타임 동작을 분석.
    """

    _meta = PluginMeta(
        name="frida_scanner",
        version="1.0.0",
        tool_binary="frida",
        category="mobile",
        tier=2,
        depends_on=(),
        optional_depends=(),
        timeout_seconds=600,
        produces=(
            "frida_traces",
            "ssl_bypass_result",
            "root_bypass_result",
            "crypto_findings",
            "keychain_data",
        ),
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
        """frida-ps 로 실행 중인 프로세스 목록 조회."""
        return "frida-ps -Ua"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """frida-ps 출력 파싱 — 대상 앱이 실행 중인지 확인."""
        processes = []
        for line in raw_stdout.splitlines():
            if line.strip() and not line.startswith("PID"):
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    processes.append({
                        "pid": parts[0],
                        "name": parts[1] if len(parts) > 1 else "",
                        "identifier": parts[2].strip() if len(parts) > 2 else "",
                    })

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"running_processes": processes},
        )

    def get_scripts_for_platform(
        self,
        platform: str,
        categories: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """플랫폼 + 카테고리 필터로 스크립트 목록 반환."""
        result = []
        for name, info in _FRIDA_SCRIPT_CATALOG.items():
            if info["platform"] != platform:
                continue
            if categories and info["category"] not in categories:
                continue
            result.append({"name": name, **info})
        return result

    async def run_script_suite(
        self,
        package: str,
        platform: str,
        categories: list[str],
    ) -> dict[str, Any]:
        """FridaBridge를 통해 스크립트 묶음 실행."""
        results: dict[str, Any] = {}

        try:
            from vxis.interaction.frida_bridge import FridaBridge
            bridge = FridaBridge()
        except ImportError:
            return {"error": "FridaBridge not available"}

        scripts = self.get_scripts_for_platform(platform, categories)
        for script_info in scripts:
            script_name = script_info["name"]
            try:
                result = await bridge.run_script(script_name, package)
                results[script_name] = result
            except Exception as exc:
                results[script_name] = {"error": str(exc)}

        return results

    def validate_environment(self) -> bool:
        return shutil.which("frida") is not None or shutil.which("frida-ps") is not None
