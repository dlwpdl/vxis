"""Subfinder plugin — passive/active subdomain enumeration."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class SubfinderPlugin(BasePlugin):
    """Enumerate subdomains using subfinder with all sources."""

    _meta = PluginMeta(
        name="subfinder",
        version="1.0.0",
        tool_binary="subfinder",
        category="recon",
        depends_on=(),
        produces=("subdomains",),
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
        threads_map = {
            "stealth": 2,
            "standard": 10,
            "aggressive": 30,
        }
        threads = threads_map.get(scan_profile, 10)
        return (
            f"subfinder -d {target} -all -recursive -timeout 30"
            f" -t {threads} -oJ -silent"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        subdomains: list[str] = []
        seen: set[str] = set()

        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                host = record.get("host", "")
                if host and host not in seen:
                    seen.add(host)
                    subdomains.append(host)
            except json.JSONDecodeError:
                continue

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"subdomains": subdomains},
        )
