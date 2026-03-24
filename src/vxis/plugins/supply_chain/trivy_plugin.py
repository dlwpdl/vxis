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
        tier=2,
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
        source_path = tool_config.get("source_path", ".")

        # --scanners vuln,secret,misconfig broadens coverage beyond pure CVE
        # matching: 'secret' catches hard-coded credentials in dependency
        # manifests or lock files; 'misconfig' catches IaC misconfigurations
        # embedded in supply-chain artifacts (e.g. Docker images, Helm charts).
        # LOW severity is excluded to reduce noise; CRITICAL/HIGH/MEDIUM are
        # the actionable tiers for a supply-chain scan.
        common_flags = (
            "--scanners vuln,secret,misconfig"
            " --format json"
            " --severity CRITICAL,HIGH,MEDIUM"
        )

        if repo_url:
            # Remote repository clone-and-scan path (GitHub URL or git remote).
            return f"trivy repo {common_flags} {repo_url}"

        # Local filesystem path — preferred for code-scan workflows where the
        # repo is already checked out.  Falls back to "." when source_path is
        # not explicitly configured.
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
