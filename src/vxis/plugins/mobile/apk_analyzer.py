"""APKAnalyzerPlugin — Android APK 정적 분석 플러그인.

jadx/apktool을 래핑하여 DAG 파이프라인에서 사용 가능한 플러그인.
"""

from __future__ import annotations

import shutil
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class APKAnalyzerPlugin(BasePlugin):
    """Android APK 정적 분석 — jadx 디컴파일 + 시크릿 스캔 + 매니페스트 파싱."""

    _meta = PluginMeta(
        name="apk_analyzer",
        version="1.0.0",
        tool_binary="jadx",
        category="mobile",
        tier=1,
        depends_on=(),
        optional_depends=("apktool",),
        timeout_seconds=600,
        produces=("apk_manifest", "apk_secrets", "apk_components", "apk_sdks"),
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
        """jadx 디컴파일 명령 구성."""
        apk_path = tool_config.get("apk_path") or ctx.get_data("mobile", "apk_path", target)
        output_dir = tool_config.get("output_dir", f"/tmp/vxis_jadx_{hash(apk_path) & 0xFFFF:04x}")
        threads = "4" if scan_profile == "aggressive" else "2"

        return (
            f"jadx -d {output_dir} --threads-count {threads} "
            f"--no-res {apk_path}"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """jadx 출력 파싱 — 에러/경고 추출."""
        errors = []
        warnings = []

        for line in (raw_stdout + raw_stderr).splitlines():
            if "ERROR" in line:
                errors.append(line.strip())
            elif "WARN" in line:
                warnings.append(line.strip())

        success = not any("ERROR" in e for e in errors)

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={
                "success": success,
                "warnings": warnings[:20],
                "error_count": len(errors),
            },
            errors=errors[:10],
        )

    async def run_full_analysis(self, apk_path: str) -> dict[str, Any]:
        """MobileAnalyzer를 통한 전체 APK 분석 (DAG 외부 직접 호출용)."""
        from vxis.interaction.mobile_analyzer import MobileAnalyzer

        analyzer = MobileAnalyzer()
        result = await analyzer.analyze_apk(apk_path)

        return {
            "package_name": result.package_name,
            "version": result.manifest.version_name,
            "min_sdk": result.manifest.min_sdk,
            "target_sdk": result.manifest.target_sdk,
            "permissions": result.manifest.permissions,
            "exported_activities": result.manifest.exported_activities,
            "exported_services": result.manifest.exported_services,
            "exported_receivers": result.manifest.exported_receivers,
            "exported_providers": result.manifest.exported_providers,
            "url_schemes": result.manifest.url_schemes,
            "deep_links": result.manifest.deep_links,
            "debuggable": result.manifest.debuggable,
            "allow_backup": result.manifest.allow_backup,
            "secrets": [
                {
                    "type": s.secret_type,
                    "value_preview": s.value_preview,
                    "file": s.file_path,
                    "line": s.line_number,
                }
                for s in result.secrets
            ],
            "third_party_sdks": result.third_party_sdks,
            "binary_protection": {
                "pie": result.binary_protection.pie_enabled,
                "stack_canary": result.binary_protection.stack_canary_enabled,
                "nx_bit": result.binary_protection.nx_bit_enabled,
                "stripped": result.binary_protection.stripped_symbols,
                "proguard": result.binary_protection.proguard_enabled,
                "obfuscation": result.binary_protection.obfuscation_level,
            },
            "dangerous_permissions": result.dangerous_permissions,
            "error": result.error,
        }

    def validate_environment(self) -> bool:
        """jadx 또는 apktool 중 하나만 있어도 동작 가능."""
        return shutil.which("jadx") is not None or shutil.which("apktool") is not None
