"""Poutine plugin — CI/CD pipeline security analysis (GitHub Actions, etc.)."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class PoutinePlugin(BasePlugin):
    """Analyze a repository's CI/CD pipelines for security anti-patterns using poutine."""

    _meta = PluginMeta(
        name="poutine",
        version="1.0.0",
        tool_binary="poutine",
        category="cicd",
        tier=2,
        depends_on=(),
        produces=("cicd_findings",),
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
        source_path = tool_config.get("source_path", "")

        if source_path:
            # Local filesystem path — use analyze_local_repo so poutine does not
            # attempt to resolve a GitHub API slug or clone anything.
            return f"poutine analyze_local_repo {source_path} --format json"

        if repo_url:
            # Explicit remote URL/slug (e.g. "org/repo" for GitHub) — use the
            # network-aware subcommand.
            return f"poutine analyze_repo {repo_url} --format json"

        # Last-resort fallback: treat the target string as a GitHub org/repo slug.
        # This maintains backward compatibility with callers that pass a GitHub URL
        # as the top-level target.
        return f"poutine analyze_repo {target} --format json"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        parsed_data: dict[str, Any] = {"cicd_findings": []}

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
                errors=["Failed to parse poutine JSON output"],
            )

        rules: list[dict[str, Any]] = data.get("rules", [])
        if not isinstance(rules, list):
            rules = []

        cicd_findings: list[dict[str, Any]] = []
        for rule in rules:
            finding: dict[str, Any] = {
                "id": rule.get("id", ""),
                "title": rule.get("title", ""),
                "severity": rule.get("severity", ""),
                "details": rule.get("details", ""),
            }
            cicd_findings.append(finding)
            findings.append(finding)

        parsed_data["cicd_findings"] = cicd_findings

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )
