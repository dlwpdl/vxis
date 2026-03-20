"""Swaks plugin — SMTP open relay detection via test email delivery."""

from __future__ import annotations

from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class SwaksPlugin(BasePlugin):
    """Test SMTP open relay using swaks (Swiss Army Knife for SMTP)."""

    _meta = PluginMeta(
        name="swaks",
        version="1.0.0",
        tool_binary="swaks",
        category="email",
        depends_on=(),
        produces=("email_relay_results",),
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
        # Prefer explicit MX server from tool_config, then context, fallback to target
        mx_server = tool_config.get("mx_server", "")
        if not mx_server:
            # Attempt to read MX info from a previous DNS/recon plugin output
            mx_server = ctx.get_data("dns_recon", "mx_server", "") or target

        return (
            f"swaks --to test@{target} --from test@{target}"
            f" --server {mx_server} --quit-after RCPT --timeout 10"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        combined = raw_stdout + raw_stderr

        # "250" in the RCPT TO response indicates the server accepted the recipient
        # for a domain it does not own — open relay indicator.
        if not combined.strip():
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"email_relay_results": {"open_relay": False, "reason": "no_output"}},
            )

        lines = combined.splitlines()

        # Detect RCPT TO acceptance (open relay)
        rcpt_accepted = False
        connection_failed = False

        for line in lines:
            stripped = line.strip()
            # A 250 on a RCPT TO line to a foreign domain = open relay
            if "<~~ 250" in stripped or (stripped.startswith("<~~") and " 250 " in stripped):
                rcpt_accepted = True
            # Connection-level failures mean not vulnerable
            if any(indicator in stripped for indicator in (
                "Connection refused",
                "connection refused",
                "timed out",
                "Timed out",
                "ECONNREFUSED",
                "Unable to connect",
                "unable to connect",
                "No route to host",
            )):
                connection_failed = True

        # Also check for explicit relay denial codes
        relay_denied = any(
            code in combined
            for code in ("550", "554", "relay not permitted", "Relay access denied")
        )

        if rcpt_accepted and not relay_denied:
            open_relay = True
            findings.append({
                "type": "open_relay",
                "severity": "high",
                "title": "SMTP Open Relay Detected",
                "description": (
                    "The mail server accepted a RCPT TO for a domain it does not own "
                    "(250 response), indicating a potential open relay. Open relays can "
                    "be abused to send spam or phishing emails on behalf of the target."
                ),
                "evidence": raw_stdout,
            })
        elif connection_failed:
            open_relay = False
        else:
            open_relay = False

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={
                "email_relay_results": {
                    "open_relay": open_relay,
                    "connection_failed": connection_failed,
                    "relay_denied": relay_denied,
                }
            },
            findings=findings,
        )
