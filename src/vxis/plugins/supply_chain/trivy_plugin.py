"""Trivy plugin — scan container images and repositories for CVE vulnerabilities.

SECURITY NOTE (CVE-2026-33634):
    Aquasecurity Trivy 0.62.0~0.62.2 contains embedded malicious code
    that steals CI/CD credentials (tokens, SSH keys, cloud keys).
    CISA KEV due date: 2026-04-09.
    This plugin refuses to run compromised versions.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

logger = logging.getLogger(__name__)

# CVE-2026-33634: Trivy supply chain compromise
# 이 버전들은 악성 코드가 포함되어 있음 — 절대 실행 금지
_TRIVY_BLOCKED_VERSIONS = {"0.62.0", "0.62.1", "0.62.2"}
# 안전 확인된 최소 버전
_TRIVY_SAFE_MIN_VERSION = "0.63.0"


def _is_version_blocked(version: str) -> bool:
    """Trivy 버전이 차단 대상인지 확인."""
    # 정확한 버전 매칭
    clean = version.strip().lstrip("v")
    if clean in _TRIVY_BLOCKED_VERSIONS:
        return True
    # 0.62.x 범위 전체 차단
    if clean.startswith("0.62."):
        return True
    return False


def _is_version_safe(version: str) -> bool:
    """Trivy 버전이 안전한지 확인 (>= 0.63.0)."""
    clean = version.strip().lstrip("v")
    try:
        parts = [int(p) for p in clean.split(".")[:3]]
        safe_parts = [int(p) for p in _TRIVY_SAFE_MIN_VERSION.split(".")]
        return parts >= safe_parts
    except (ValueError, IndexError):
        return False  # 파싱 실패 시 안전하지 않은 것으로 간주


class TrivyPlugin(BasePlugin):
    """Scan repositories or local filesystems for dependency vulnerabilities with Trivy.

    WARNING: CVE-2026-33634 대응으로 0.62.x 버전은 자동 차단됩니다.
    """

    _meta = PluginMeta(
        name="trivy",
        version="1.0.0",
        tool_binary="trivy",
        category="supply_chain",
        tier=2,
        depends_on=(),
        produces=("dependency_vulns",),
        timeout_seconds=600,
    )

    @property
    def meta(self) -> PluginMeta:
        return self._meta

    def validate_environment(self) -> bool:
        """Trivy 설치 + 안전 버전 확인."""
        if not super().validate_environment():
            return False

        version = self.get_tool_version()
        if _is_version_blocked(version):
            logger.critical(
                "BLOCKED: Trivy %s is compromised (CVE-2026-33634). "
                "DO NOT RUN. Upgrade to >= %s immediately.",
                version,
                _TRIVY_SAFE_MIN_VERSION,
            )
            return False

        if not _is_version_safe(version) and version not in ("not installed", "unknown"):
            logger.warning(
                "Trivy %s — version not verified safe. Recommended: >= %s (CVE-2026-33634)",
                version,
                _TRIVY_SAFE_MIN_VERSION,
            )

        return True

    def build_command(
        self,
        target: str,
        scan_profile: str,
        ctx: DAGContext,
        tool_config: dict[str, Any],
    ) -> str:
        # 실행 전 한 번 더 버전 체크 (안전장치)
        version = self.get_tool_version()
        if _is_version_blocked(version):
            raise RuntimeError(
                f"SECURITY BLOCK: Trivy {version} is compromised (CVE-2026-33634). "
                f"Refusing to execute. Upgrade to >= {_TRIVY_SAFE_MIN_VERSION}."
            )

        repo_url = tool_config.get("repo_url", "")
        source_path = tool_config.get("source_path", ".")

        common_flags = (
            "--scanners vuln,secret,misconfig --format json --severity CRITICAL,HIGH,MEDIUM"
        )

        if repo_url:
            return f"trivy repo {common_flags} {repo_url}"

        return f"trivy fs {common_flags} {source_path}"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        parsed_data: dict[str, Any] = {"dependency_vulns": []}

        raw_stdout = raw_stdout.strip()
        if not raw_stdout:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data=parsed_data,
                findings=findings,
            )

        try:
            data = json.loads(raw_stdout)
        except json.JSONDecodeError:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data=parsed_data,
                findings=findings,
                errors=["Failed to parse Trivy JSON output"],
            )

        results: list[dict[str, Any]] = data.get("Results", []) if isinstance(data, dict) else []
        vulns: list[dict[str, Any]] = []

        for result in results:
            vulnerabilities: list[dict[str, Any]] = result.get("Vulnerabilities") or []
            for vuln in vulnerabilities:
                finding: dict[str, Any] = {
                    "vulnerability_id": vuln.get("VulnerabilityID", ""),
                    "pkg_name": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "severity": vuln.get("Severity", ""),
                    "title": vuln.get("Title", ""),
                    "description": vuln.get("Description", ""),
                }
                vulns.append(finding)
                findings.append(finding)

        parsed_data["dependency_vulns"] = vulns

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )
