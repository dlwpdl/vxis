"""nuclei plugin — template-based vulnerability scanning."""

from __future__ import annotations

import json
import tempfile
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class NucleiPlugin(BasePlugin):
    """Run nuclei templates against live HTTP endpoints."""

    _meta = PluginMeta(
        name="nuclei",
        version="1.0.0",
        tool_binary="nuclei",
        category="vuln",
        depends_on=("httpx",),
        optional_depends=("wafw00f",),
        produces=("vulnerabilities",),
        timeout_seconds=5400,
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
        base_rate_map = {
            "stealth": 5,
            "standard": 50,
            "aggressive": 150,
        }
        rate = base_rate_map.get(scan_profile, 50)

        # Reduce rate when a WAF is detected to avoid triggering blocks.
        if scan_profile == "standard":
            waf_results: list[dict[str, Any]] = ctx.get_data(
                "wafw00f", "waf_results", []
            )
            waf_detected = any(r.get("detected", False) for r in waf_results)
            if waf_detected:
                rate = 25

        # Collect all live URLs from httpx + subdomains for wider coverage
        live_urls: list[str] = ctx.get_data("httpx", "live_urls", [])
        if not live_urls:
            live_urls = [f"https://{target}"]

        # Also add subdomains discovered by subfinder (httpx may not have probed all)
        subdomains: list[str] = ctx.get_data("subfinder", "subdomains", [])
        seen = set(live_urls)
        for sub in subdomains:
            url = f"https://{sub}"
            if url not in seen:
                live_urls.append(url)
                seen.add(url)

        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            prefix="vxis_nuclei_",
            delete=False,
        )
        tmp.write("\n".join(live_urls))
        tmp.close()
        input_file = tmp.name

        severity = "critical,high,medium,low" if scan_profile == "aggressive" else "critical,high,medium"

        return (
            f"nuclei -l {input_file} -severity {severity}"
            f" -etags dos,fuzz -rate-limit {rate} -json -irr -silent"
            f" -header 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)'"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []

        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            info: dict[str, Any] = record.get("info", {})
            tags: list[str] = info.get("tags", [])

            # Extract CVE ID — check dedicated field, tags, then template-id.
            cve_id: str = record.get("cve-id", "")
            if not cve_id:
                for tag in tags:
                    if tag.upper().startswith("CVE-"):
                        cve_id = tag.upper()
                        break
            if not cve_id:
                template_id: str = record.get("template-id", "")
                if template_id.upper().startswith("CVE-"):
                    cve_id = template_id.upper()

            findings.append({
                "template_id": record.get("template-id", ""),
                "name": info.get("name", ""),
                "severity": info.get("severity", ""),
                "matched_at": record.get("matched-at", ""),
                "request": record.get("request", ""),
                "response": record.get("response", ""),
                "ip": record.get("ip", ""),
                "cve_id": cve_id,
                "tags": tags,
                "matcher_status": record.get("matcher-status", False),
            })

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"vulnerabilities": findings},
            findings=findings,
        )
