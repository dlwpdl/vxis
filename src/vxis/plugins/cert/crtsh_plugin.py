"""crt.sh plugin — certificate transparency log enumeration via curl."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# Well-known trusted CA name fragments; anything not matching is flagged.
_EXPECTED_CA_FRAGMENTS: tuple[str, ...] = (
    "let's encrypt",
    "letsencrypt",
    "digicert",
    "comodo",
    "sectigo",
    "globalsign",
    "entrust",
    "geotrust",
    "godaddy",
    "go daddy",
    "amazon",
    "microsoft",
    "google",
    "zerossl",
    "trust asia",
    "identrust",
    "actalis",
    "buypass",
    "certum",
    "ssl.com",
)


def _parse_dt(dt_str: str) -> datetime | None:
    """Parse an ISO-8601 or crt.sh-style date string into an aware datetime."""
    if not dt_str:
        return None
    # crt.sh returns dates like "2025-01-01T00:00:00" (no tz) — treat as UTC
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(dt_str[:19], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class CrtshPlugin(BasePlugin):
    """Enumerate certificates via crt.sh Certificate Transparency logs."""

    _meta = PluginMeta(
        name="crtsh",
        version="1.0.0",
        tool_binary="curl",
        category="cert",
        depends_on=(),
        produces=("certificates",),
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
        # %.domain matches the domain and all subdomains in CT logs
        return f'curl -s "https://crt.sh/?q=%.{target}&output=json"'

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []

        if not raw_stdout.strip():
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"certificates": []},
            )

        try:
            raw_certs: list[dict[str, Any]] = json.loads(raw_stdout)
        except json.JSONDecodeError:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"certificates": []},
                errors=["Failed to parse crt.sh JSON response"],
            )

        if not isinstance(raw_certs, list):
            raw_certs = []

        now = datetime.now(tz=timezone.utc)
        certificates: list[dict[str, Any]] = []
        seen_common_names: dict[str, dict[str, Any]] = {}

        for cert in raw_certs:
            common_name: str = cert.get("common_name", "")
            name_value: str = cert.get("name_value", "")
            issuer_name: str = cert.get("issuer_name", "")
            issuer_ca_id: int | None = cert.get("issuer_ca_id")
            not_before_str: str = cert.get("not_before", "")
            not_after_str: str = cert.get("not_after", "")

            not_before = _parse_dt(not_before_str)
            not_after = _parse_dt(not_after_str)

            entry: dict[str, Any] = {
                "issuer_ca_id": issuer_ca_id,
                "issuer_name": issuer_name,
                "common_name": common_name,
                "name_value": name_value,
                "not_before": not_before_str,
                "not_after": not_after_str,
            }

            # Deduplicate by common_name — keep latest not_after
            if common_name not in seen_common_names:
                seen_common_names[common_name] = entry
                certificates.append(entry)
            else:
                existing = seen_common_names[common_name]
                existing_exp = _parse_dt(existing.get("not_after", ""))
                if not_after and existing_exp and not_after > existing_exp:
                    seen_common_names[common_name].update(entry)

            # --- Finding: expired certificate ---
            if not_after and not_after < now:
                findings.append({
                    "type": "expired_certificate",
                    "severity": "high",
                    "title": f"Expired Certificate: {common_name}",
                    "description": (
                        f"The certificate for '{common_name}' expired on {not_after_str}. "
                        "Expired certificates cause browser warnings and can indicate "
                        "neglected certificate management processes."
                    ),
                    "common_name": common_name,
                    "expired_at": not_after_str,
                    "issuer": issuer_name,
                })

            # --- Finding: wildcard certificate ---
            if "*." in common_name or "*." in name_value:
                findings.append({
                    "type": "wildcard_certificate",
                    "severity": "informational",
                    "title": f"Wildcard Certificate Detected: {common_name}",
                    "description": (
                        f"A wildcard certificate '{common_name}' was found. "
                        "Wildcard certificates cover all subdomains but increase blast radius "
                        "if the private key is compromised."
                    ),
                    "common_name": common_name,
                    "issuer": issuer_name,
                })

            # --- Finding: unexpected/untrusted CA ---
            issuer_lower = issuer_name.lower()
            is_known_ca = any(frag in issuer_lower for frag in _EXPECTED_CA_FRAGMENTS)
            if issuer_name and not is_known_ca:
                findings.append({
                    "type": "unexpected_ca",
                    "severity": "medium",
                    "title": f"Certificate Issued by Unexpected CA: {issuer_name}",
                    "description": (
                        f"The certificate for '{common_name}' was issued by '{issuer_name}', "
                        "which is not a commonly recognized public CA. "
                        "This may indicate a private/internal CA, a misissued certificate, "
                        "or a potential man-in-the-middle attack."
                    ),
                    "common_name": common_name,
                    "issuer": issuer_name,
                })

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"certificates": certificates},
            findings=findings,
        )
