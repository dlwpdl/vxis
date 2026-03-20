"""NetExec (nxc) plugin — SMB enumeration and credential validation."""

from __future__ import annotations

import re
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# Regex patterns for parsing nxc SMB output
_SHARE_PATTERN = re.compile(
    r"SMB\s+[\d.]+\s+\d+\s+\S+\s+\[\*\]\s+Share:\s*(\S+)\s+Permissions?:\s*(.+)",
    re.IGNORECASE,
)
_PASS_POL_PATTERN = re.compile(
    r"SMB\s+[\d.]+\s+\d+\s+\S+\s+\[\+\]\s+Password\s+Policy:(.+)",
    re.IGNORECASE,
)
_MIN_LENGTH_PATTERN = re.compile(r"MinLength=(\d+)", re.IGNORECASE)
_COMPLEXITY_PATTERN = re.compile(r"Complexity=(True|False)", re.IGNORECASE)


class NetexecPlugin(BasePlugin):
    """Enumerate SMB shares, sessions, users, groups, and password policy via nxc."""

    _meta = PluginMeta(
        name="netexec",
        version="1.0.0",
        tool_binary="nxc",
        category="ad",
        depends_on=(),
        produces=("ad_enum",),
        timeout_seconds=900,
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
        username: str = tool_config.get("username", "")
        password: str = tool_config.get("password", "")
        return (
            f"nxc smb {target} -u {username} -p {password}"
            f" --shares --sessions --users --groups --pass-pol"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """Parse nxc text output for shares, password policy, and user enumeration."""
        parsed_data: dict[str, Any] = {}
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        if not raw_stdout.strip():
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data=parsed_data,
                findings=findings,
                errors=errors,
            )

        readable_shares: list[dict[str, str]] = []
        password_policy: dict[str, Any] = {}

        for line in raw_stdout.splitlines():
            # Parse share lines
            share_match = _SHARE_PATTERN.search(line)
            if share_match:
                share_name = share_match.group(1).strip()
                permissions_raw = share_match.group(2).strip()
                permissions = [p.strip() for p in permissions_raw.split(",")]
                # Only flag shares that we can READ (admin shares or readable data)
                if any(p.upper() in ("READ", "READ,WRITE", "WRITE") for p in permissions):
                    readable_shares.append({
                        "share": share_name,
                        "permissions": permissions_raw,
                    })
                    findings.append({
                        "type": "readable_share",
                        "severity": "medium",
                        "title": f"Readable SMB Share: {share_name}",
                        "description": (
                            f"SMB share '{share_name}' is accessible with permissions: "
                            f"{permissions_raw}. Unauthorised access to network shares may "
                            "expose sensitive data."
                        ),
                        "share": share_name,
                        "permissions": permissions_raw,
                    })
                continue

            # Parse password policy lines
            pol_match = _PASS_POL_PATTERN.search(line)
            if pol_match:
                pol_str = pol_match.group(1).strip()
                min_len_match = _MIN_LENGTH_PATTERN.search(pol_str)
                complexity_match = _COMPLEXITY_PATTERN.search(pol_str)

                min_length = int(min_len_match.group(1)) if min_len_match else None
                complexity = (
                    complexity_match.group(1).lower() == "true"
                    if complexity_match
                    else None
                )

                password_policy = {
                    "raw": pol_str,
                    "min_length": min_length,
                    "complexity": complexity,
                }

                # Weak policy: short minimum length or no complexity requirement
                is_weak = (min_length is not None and min_length < 8) or (
                    complexity is False
                )
                if is_weak:
                    findings.append({
                        "type": "weak_password_policy",
                        "severity": "high",
                        "title": "Weak Domain Password Policy",
                        "description": (
                            f"The domain password policy is weak: {pol_str}. "
                            "A minimum password length below 8 characters or disabled "
                            "complexity requirements significantly increases brute-force risk."
                        ),
                        "policy": pol_str,
                    })

        parsed_data = {
            "readable_shares": readable_shares,
            "password_policy": password_policy,
            "total_readable_shares": len(readable_shares),
        }

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
            errors=errors,
        )
