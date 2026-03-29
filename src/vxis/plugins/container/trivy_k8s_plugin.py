"""Trivy K8s plugin — Kubernetes cluster vulnerability and misconfiguration scanning.

SECURITY NOTE: CVE-2026-33634 대응 — trivy_plugin.py의 버전 차단 로직 공유.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta
from vxis.plugins.supply_chain.trivy_plugin import _is_version_blocked, _TRIVY_SAFE_MIN_VERSION

logger = logging.getLogger(__name__)


class TrivyK8sPlugin(BasePlugin):
    """Scan a running Kubernetes cluster with trivy for CRITICAL/HIGH vulnerabilities.

    WARNING: CVE-2026-33634 대응으로 0.62.x 버전은 자동 차단됩니다.
    """

    _meta = PluginMeta(
        name="trivy-k8s",
        version="1.0.0",
        tool_binary="trivy",
        category="container",
        tier=2,
        depends_on=(),
        produces=("k8s_vulns",),
        timeout_seconds=900,
    )

    def validate_environment(self) -> bool:
        if not super().validate_environment():
            return False
        version = self.get_tool_version()
        if _is_version_blocked(version):
            logger.critical(
                "BLOCKED: Trivy %s is compromised (CVE-2026-33634). "
                "Upgrade to >= %s.", version, _TRIVY_SAFE_MIN_VERSION,
            )
            return False
        return True

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
        return "trivy k8s --report all --format json --severity CRITICAL,HIGH"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        parsed_data: dict[str, Any] = {"k8s_vulns": []}

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
                errors=["Failed to parse trivy k8s JSON output"],
            )

        cluster_name: str = data.get("ClusterName", "")
        raw_vulns: list[dict[str, Any]] = data.get("Vulnerabilities", [])
        if not isinstance(raw_vulns, list):
            raw_vulns = []

        k8s_vulns: list[dict[str, Any]] = []
        for vuln in raw_vulns:
            finding: dict[str, Any] = {
                "cluster_name": cluster_name,
                "vulnerability_id": vuln.get("VulnerabilityID", ""),
                "severity": vuln.get("Severity", ""),
                "title": vuln.get("Title", ""),
                "misconf_summary": vuln.get("MisconfSummary", {}),
            }
            k8s_vulns.append(finding)
            findings.append(finding)

        parsed_data["k8s_vulns"] = k8s_vulns

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )
