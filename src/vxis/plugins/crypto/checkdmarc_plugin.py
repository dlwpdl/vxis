"""checkdmarc plugin — email security policy (SPF / DMARC) analysis."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class CheckdmarcPlugin(BasePlugin):
    """Validate SPF and DMARC records for the target domain."""

    _meta = PluginMeta(
        name="checkdmarc",
        version="1.0.0",
        tool_binary="checkdmarc",
        category="crypto",
        depends_on=(),
        produces=("email_security",),
        timeout_seconds=60,
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
        return f"checkdmarc {target} -f json"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []

        if not raw_stdout.strip():
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"email_security": {}},
                findings=findings,
            )

        try:
            data: dict[str, Any] = json.loads(raw_stdout)
        except json.JSONDecodeError:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"email_security": {}},
                errors=["Failed to parse checkdmarc JSON output"],
            )

        spf: dict[str, Any] = data.get("spf", {})
        dmarc: dict[str, Any] = data.get("dmarc", {})
        dmarc_tags: dict[str, Any] = dmarc.get("tags", {})
        dmarc_policy_info: dict[str, Any] = dmarc_tags.get("p", {})
        dmarc_policy: str = dmarc_policy_info.get("value", "")

        # --- SPF analysis ---
        if not spf.get("valid", False):
            findings.append({
                "type": "spf_invalid",
                "severity": "high",
                "title": "SPF record is invalid or missing",
                "detail": spf.get("error", "No valid SPF record found"),
            })
        else:
            spf_record: str = spf.get("record", "")
            if "+all" in spf_record:
                findings.append({
                    "type": "spf_too_permissive",
                    "severity": "critical",
                    "title": "SPF record uses '+all' (accept all senders)",
                    "detail": (
                        "The '+all' mechanism allows any host to send email on "
                        "behalf of the domain, completely bypassing SPF protection."
                    ),
                })
            elif "~all" in spf_record:
                findings.append({
                    "type": "spf_softfail",
                    "severity": "medium",
                    "title": "SPF record uses '~all' (softfail)",
                    "detail": (
                        "Softfail '~all' marks unauthorized senders but does not "
                        "reject them. Consider upgrading to '-all' (hardfail)."
                    ),
                })

        # --- DMARC analysis ---
        if not dmarc.get("valid", False):
            findings.append({
                "type": "dmarc_invalid",
                "severity": "high",
                "title": "DMARC record is invalid or missing",
                "detail": dmarc.get("error", "No valid DMARC record found"),
            })
        elif dmarc_policy == "none":
            findings.append({
                "type": "dmarc_policy_none",
                "severity": "medium",
                "title": "DMARC policy is 'none' (monitor only)",
                "detail": (
                    "A DMARC policy of 'none' does not instruct receiving mail "
                    "servers to reject or quarantine failing messages. Upgrade to "
                    "'quarantine' or 'reject' to enforce protection."
                ),
            })
        elif dmarc_policy == "quarantine":
            findings.append({
                "type": "dmarc_policy_quarantine",
                "severity": "low",
                "title": "DMARC policy is 'quarantine' (not fully enforced)",
                "detail": (
                    "DMARC policy 'quarantine' moves failing messages to spam but "
                    "does not outright reject them. Consider upgrading to 'reject'."
                ),
            })

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"email_security": data},
            findings=findings,
        )
