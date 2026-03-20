"""kube-bench plugin — CIS Kubernetes Benchmark compliance scanning."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class KubeBenchPlugin(BasePlugin):
    """Run kube-bench against the current cluster and report CIS benchmark failures."""

    _meta = PluginMeta(
        name="kube-bench",
        version="1.0.0",
        tool_binary="kube-bench",
        category="container",
        depends_on=(),
        produces=("k8s_cis",),
        timeout_seconds=300,
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
        return "kube-bench run --json"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        parsed_data: dict[str, Any] = {"k8s_cis": []}

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
                errors=["Failed to parse kube-bench JSON output"],
            )

        # kube-bench JSON structure: top-level "Controls" list or a single Controls object
        controls_list: list[dict[str, Any]] = []
        if isinstance(data, dict):
            controls_list = data.get("Controls", [])
        elif isinstance(data, list):
            controls_list = data

        k8s_cis: list[dict[str, Any]] = []
        for control in controls_list:
            tests: list[dict[str, Any]] = control.get("tests", control.get("Tests", []))
            for test_group in tests:
                results: list[dict[str, Any]] = test_group.get(
                    "results", test_group.get("Results", [])
                )
                for result in results:
                    status = result.get("status", result.get("Status", ""))
                    if str(status).upper() != "FAIL":
                        continue

                    finding: dict[str, Any] = {
                        "test_number": result.get("test_number", result.get("TestNumber", "")),
                        "test_desc": result.get("test_desc", result.get("TestDesc", "")),
                        "remediation": result.get("remediation", result.get("Remediation", "")),
                        "status": "FAIL",
                        "scored": result.get("scored", result.get("Scored", True)),
                    }
                    k8s_cis.append(finding)
                    findings.append(finding)

        parsed_data["k8s_cis"] = k8s_cis

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )
