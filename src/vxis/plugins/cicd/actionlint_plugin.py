"""Actionlint plugin — GitHub Actions workflow static analysis."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# Actionlint issue kinds that carry security relevance and warrant medium severity.
_SECURITY_RELEVANT_KINDS: frozenset[str] = frozenset(
    {
        "expression",
        "shellcheck",
        "credentials",
        "permissions",
        "secret",
        "injection",
    }
)


class ActionlintPlugin(BasePlugin):
    """Lint GitHub Actions workflow files for syntax and security issues."""

    _meta = PluginMeta(
        name="actionlint",
        version="1.0.0",
        tool_binary="actionlint",
        category="cicd",
        tier=2,
        depends_on=(),
        produces=("gha_lint",),
        timeout_seconds=120,
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
        # Prefer an explicit workflow_dir override; otherwise derive it from
        # source_path so that scans of a cloned repository work out of the box.
        source_path = tool_config.get("source_path", "")
        default_dir = f"{source_path}/.github/workflows" if source_path else ".github/workflows"
        workflow_dir = tool_config.get("workflow_dir", default_dir)

        # actionlint's -format flag accepts a Go template.  The built-in
        # {{json .}} template renders each issue as a single-line JSON object
        # (JSON Lines / NDJSON), which parse_output processes line by line.
        # Single braces are used here because Python's f-string escaping
        # requires doubling, so {{json .}} in the source produces {json .} in
        # the shell argument — which is the correct Go template syntax.
        return f"actionlint -format '{{{{json .}}}}' {workflow_dir}"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        parsed_data: dict[str, Any] = {"gha_lint": []}

        raw_stdout = raw_stdout.strip()
        if not raw_stdout:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data=parsed_data,
                findings=findings,
            )

        # actionlint outputs JSON Lines (one JSON object per line) when using
        # -format '{{json .}}'. Each line is a single lint issue object.
        gha_lint: list[dict[str, Any]] = []
        errors: list[str] = []

        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                issue = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"Failed to parse actionlint JSON line: {line[:120]}")
                continue

            if not isinstance(issue, dict):
                continue

            kind: str = issue.get("kind", "")
            # Security-relevant kinds are bumped to medium; everything else is low/info.
            severity: str = "medium" if kind.lower() in _SECURITY_RELEVANT_KINDS else "low"

            finding: dict[str, Any] = {
                "filepath": issue.get("filepath", ""),
                "line": issue.get("line", 0),
                "column": issue.get("col", issue.get("column", 0)),
                "message": issue.get("message", ""),
                "kind": kind,
                "severity": severity,
            }
            gha_lint.append(finding)
            findings.append(finding)

        parsed_data["gha_lint"] = gha_lint

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
            errors=errors,
        )
