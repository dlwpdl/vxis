"""Trivy plugin — scan container images and repositories for CVE vulnerabilities."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class TrivyPlugin(BasePlugin):
    """Scan repositories or local filesystems for dependency vulnerabilities with Trivy."""

    _meta = PluginMeta(
        name="trivy",
        version="1.0.0",
        tool_binary="trivy",
        category="supply_chain",
        depends_on=(),
        produces=("dependency_vulns",),
        timeout_seconds=600,
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
        repo_url = tool_config.get("repo_url", "")
        if repo_url:
            return (
                f"trivy repo"
                " --format json"
                " --severity CRITICAL,HIGH,MEDIUM"
                f" {repo_url}"
            )
        return (
            "trivy fs"
            " --format json"
            " --severity CRITICAL,HIGH,MEDIUM"
            " ."
        )

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
