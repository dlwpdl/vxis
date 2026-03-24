"""wafw00f plugin — Web Application Firewall detection."""

from __future__ import annotations

import json
import tempfile
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class Wafw00fPlugin(BasePlugin):
    """Detect WAFs protecting live HTTP endpoints."""

    _meta = PluginMeta(
        name="wafw00f",
        version="1.0.0",
        tool_binary="wafw00f",
        category="scan",
        depends_on=(),
        optional_depends=("httpx",),
        produces=("waf_results",),
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
        live_urls: list[str] = ctx.get_data("httpx", "live_urls", [])
        if not live_urls:
            live_urls = [f"https://{target}"]

        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            prefix="vxis_waf_",
            delete=False,
        )
        tmp.write("\n".join(live_urls))
        tmp.close()
        input_file = tmp.name

        return f"wafw00f -i {input_file} -o - -f json -a"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        waf_results: list[dict[str, Any]] = []

        if not raw_stdout.strip():
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"waf_results": waf_results},
            )

        try:
            records = json.loads(raw_stdout)
        except json.JSONDecodeError:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"waf_results": waf_results},
                errors=["Failed to parse wafw00f JSON output"],
            )

        if not isinstance(records, list):
            records = [records]

        for record in records:
            waf_results.append({
                "url": record.get("url", ""),
                "detected": record.get("detected", False),
                "firewall": record.get("firewall", ""),
                "manufacturer": record.get("manufacturer", ""),
            })

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"waf_results": waf_results},
        )
