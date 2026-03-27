"""IPAAnalyzerPlugin — iOS IPA 정적 분석 플러그인."""

from __future__ import annotations

import shutil
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class IPAAnalyzerPlugin(BasePlugin):
    """iOS IPA 정적 분석 — Info.plist 파싱, 엔타이틀먼트, ATS, 바이너리 보호."""

    _meta = PluginMeta(
        name="ipa_analyzer",
        version="1.0.0",
        tool_binary="otool",
        category="mobile",
        tier=1,
        depends_on=(),
        optional_depends=("nm", "codesign", "strings"),
        timeout_seconds=600,
        produces=("ipa_manifest", "ipa_secrets", "ipa_entitlements", "ipa_sdks"),
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
        """IPA 추출 + otool 헤더 분석 명령."""
        ipa_path = tool_config.get("ipa_path") or ctx.get_data("mobile", "ipa_path", target)
        output_dir = tool_config.get("output_dir", f"/tmp/vxis_ipa_{hash(ipa_path) & 0xFFFF:04x}")
        # IPA는 ZIP이므로 unzip으로 추출 후 otool 실행
        return f"unzip -q -o {ipa_path} -d {output_dir}"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """unzip 출력 파싱."""
        errors = []
        if "error" in raw_stderr.lower() or "cannot" in raw_stderr.lower():
            errors.append(raw_stderr.strip()[:200])

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={
                "extracted": len(errors) == 0,
            },
            errors=errors,
        )

    async def run_full_analysis(self, ipa_path: str) -> dict[str, Any]:
        """MobileAnalyzer를 통한 전체 IPA 분석 (직접 호출용)."""
        from vxis.interaction.mobile_analyzer import MobileAnalyzer

        analyzer = MobileAnalyzer()
        result = await analyzer.analyze_ipa(ipa_path)

        return {
            "bundle_id": result.bundle_id,
            "version": result.manifest.version_name,
            "permissions": result.manifest.permissions,
            "url_schemes": result.manifest.url_schemes,
            "ats_disabled": result.manifest.ats_config.get("ats_disabled", False),
            "ats_exceptions": result.manifest.ats_config.get("exceptions", []),
            "entitlements": result.manifest.entitlements,
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
                "arc": result.binary_protection.arc_enabled,
                "stripped": result.binary_protection.stripped_symbols,
                "obfuscation": result.binary_protection.obfuscation_level,
            },
            "error": result.error,
        }

    def validate_environment(self) -> bool:
        """unzip과 Python plistlib으로 동작 (otool 옵션)."""
        return shutil.which("unzip") is not None
