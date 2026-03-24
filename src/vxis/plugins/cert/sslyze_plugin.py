"""SSLyze plugin — deep TLS/SSL configuration analysis."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# TLS protocol fields in sslyze JSON that correspond to deprecated protocols
_WEAK_PROTOCOL_FIELDS: dict[str, str] = {
    "tls_1_0_cipher_suites": "TLS 1.0",
    "tls_1_1_cipher_suites": "TLS 1.1",
    "ssl_2_0_cipher_suites": "SSL 2.0",
    "ssl_3_0_cipher_suites": "SSL 3.0",
}

_MINIMUM_RSA_KEY_SIZE = 2048
_MINIMUM_EC_KEY_SIZE = 224


def _parse_iso_dt(dt_str: str) -> datetime | None:
    """Parse an ISO-8601 datetime string into a timezone-aware datetime."""
    if not dt_str:
        return None
    # sslyze uses format "2025-12-31T00:00:00"
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(dt_str[:19], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class SSLyzePlugin(BasePlugin):
    """Perform deep TLS/SSL configuration analysis using sslyze."""

    _meta = PluginMeta(
        name="sslyze",
        version="1.0.0",
        tool_binary="sslyze",
        category="cert",
        depends_on=("httpx",),
        produces=("tls_detailed",),
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
        # Read live HTTPS hosts discovered by the upstream httpx plugin.
        # live_hosts may be a list of strings (URLs) or dicts (JSON records).
        live_hosts_raw = ctx.get_data("httpx", "live_hosts", [])

        # Filter to HTTPS-only hosts and format as host:port
        https_hosts: list[str] = []
        for entry in live_hosts_raw:
            # Normalise: extract URL string from dict or use directly
            if isinstance(entry, dict):
                host = entry.get("url", entry.get("host", ""))
            else:
                host = str(entry)

            if not host:
                continue

            if host.startswith("https://"):
                host_part = host.replace("https://", "").rstrip("/")
                if ":" not in host_part.split("/")[0]:
                    host_part = f"{host_part}:443"
                https_hosts.append(host_part)
            elif ":" in host and not host.startswith("http"):
                https_hosts.append(host)

        # Fallback: scan the primary target directly
        if not https_hosts:
            https_hosts = [f"{target}:443"]

        hosts_str = " ".join(https_hosts)
        return f"sslyze --json_out=- {hosts_str}"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        tls_results: list[dict[str, Any]] = []

        if not raw_stdout.strip():
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"tls_detailed": []},
            )

        try:
            data: dict[str, Any] = json.loads(raw_stdout)
        except json.JSONDecodeError:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"tls_detailed": []},
                errors=["Failed to parse sslyze JSON output"],
            )

        server_scan_results: list[dict[str, Any]] = data.get("server_scan_results", [])
        now = datetime.now(tz=timezone.utc)

        for server_result in server_scan_results:
            server_location = server_result.get("server_location", {})
            hostname: str = server_location.get("hostname", "")
            port: int = server_location.get("port", 443)
            host_label = f"{hostname}:{port}"

            scan_result: dict[str, Any] = server_result.get("scan_result", {})

            host_entry: dict[str, Any] = {
                "host": host_label,
                "hostname": hostname,
                "port": port,
                "weak_protocols": [],
                "certificate_issues": [],
                "weak_keys": [],
            }

            # --- Check for weak/deprecated protocol support ---
            for protocol_field, protocol_label in _WEAK_PROTOCOL_FIELDS.items():
                protocol_data = scan_result.get(protocol_field, {})
                if protocol_data is None:
                    continue
                accepted_suites: list[Any] = protocol_data.get("accepted_cipher_suites", [])
                if accepted_suites:
                    host_entry["weak_protocols"].append(protocol_label)
                    findings.append({
                        "type": "weak_tls_protocol",
                        "severity": "high" if protocol_label.startswith("SSL") else "medium",
                        "title": f"Deprecated Protocol Supported: {protocol_label} on {host_label}",
                        "description": (
                            f"The server {host_label} supports {protocol_label}, which is deprecated "
                            "and known to have cryptographic vulnerabilities (POODLE, BEAST, etc.). "
                            "All modern clients should use TLS 1.2 or TLS 1.3 exclusively."
                        ),
                        "host": host_label,
                        "protocol": protocol_label,
                        "accepted_cipher_suites": [
                            s.get("name", "") for s in accepted_suites if isinstance(s, dict)
                        ],
                    })

            # --- Check certificate deployments ---
            cert_deployments: list[dict[str, Any]] = scan_result.get(
                "certificate_deployments", []
            )
            for deployment in cert_deployments:
                received_chain: list[dict[str, Any]] = deployment.get(
                    "received_certificate_chain", []
                )
                for cert in received_chain:
                    subject = cert.get("subject", {})
                    common_name = subject.get("common_name", hostname) if isinstance(subject, dict) else str(subject)
                    not_valid_after_str: str = cert.get("not_valid_after", "")
                    not_valid_after = _parse_iso_dt(not_valid_after_str)

                    # Expired certificate
                    if not_valid_after and not_valid_after < now:
                        host_entry["certificate_issues"].append("expired")
                        findings.append({
                            "type": "expired_certificate",
                            "severity": "high",
                            "title": f"Expired TLS Certificate on {host_label}",
                            "description": (
                                f"The TLS certificate for '{common_name}' on {host_label} "
                                f"expired on {not_valid_after_str}. "
                                "Expired certificates cause TLS handshake failures and browser "
                                "security warnings, disrupting service availability."
                            ),
                            "host": host_label,
                            "common_name": common_name,
                            "expired_at": not_valid_after_str,
                        })

                    # Self-signed certificate detection (issuer == subject)
                    issuer = cert.get("issuer", {})
                    issuer_cn = issuer.get("common_name", "") if isinstance(issuer, dict) else ""
                    subject_cn = subject.get("common_name", "") if isinstance(subject, dict) else ""
                    if issuer_cn and subject_cn and issuer_cn == subject_cn:
                        host_entry["certificate_issues"].append("self_signed")
                        findings.append({
                            "type": "self_signed_certificate",
                            "severity": "medium",
                            "title": f"Self-Signed Certificate on {host_label}",
                            "description": (
                                f"The TLS certificate for '{common_name}' on {host_label} "
                                "appears to be self-signed (issuer CN equals subject CN). "
                                "Self-signed certificates are not trusted by browsers and clients "
                                "by default, and cannot be validated against a trusted CA chain."
                            ),
                            "host": host_label,
                            "common_name": common_name,
                        })

                    # Weak key size
                    public_key: dict[str, Any] = cert.get("public_key", {})
                    if isinstance(public_key, dict):
                        algorithm: str = public_key.get("algorithm", "")
                        key_size: int | None = public_key.get("key_size")
                        if key_size is not None:
                            is_weak = False
                            if algorithm.upper() == "RSA" and key_size < _MINIMUM_RSA_KEY_SIZE:
                                is_weak = True
                            elif algorithm.upper() in ("EC", "ECDSA") and key_size < _MINIMUM_EC_KEY_SIZE:
                                is_weak = True

                            if is_weak:
                                host_entry["weak_keys"].append(f"{algorithm}-{key_size}")
                                findings.append({
                                    "type": "weak_key_size",
                                    "severity": "medium",
                                    "title": f"Weak {algorithm} Key Size ({key_size} bits) on {host_label}",
                                    "description": (
                                        f"The TLS certificate for '{common_name}' on {host_label} "
                                        f"uses a {algorithm} key of only {key_size} bits. "
                                        f"Minimum recommended size for {algorithm} is "
                                        f"{_MINIMUM_RSA_KEY_SIZE if algorithm.upper() == 'RSA' else _MINIMUM_EC_KEY_SIZE} bits. "
                                        "Weak keys can be factored or broken with sufficient computing resources."
                                    ),
                                    "host": host_label,
                                    "algorithm": algorithm,
                                    "key_size": key_size,
                                })

            tls_results.append(host_entry)

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"tls_detailed": tls_results},
            findings=findings,
        )
