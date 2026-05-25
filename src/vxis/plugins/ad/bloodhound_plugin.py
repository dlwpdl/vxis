"""BloodHound plugin — Active Directory graph collection and analysis."""

from __future__ import annotations

import json
import zipfile
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class BloodhoundPlugin(BasePlugin):
    """Collect AD data via bloodhound-python and parse the resulting ZIP."""

    _meta = PluginMeta(
        name="bloodhound",
        version="1.0.0",
        tool_binary="bloodhound-python",
        category="ad",
        tier=2,
        depends_on=(),
        produces=("ad_graph",),
        timeout_seconds=1800,
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
        domain: str = tool_config.get("domain", target)
        username: str = tool_config.get("username", "")
        password: str = tool_config.get("password", "")
        nameserver: str = tool_config.get("nameserver", "")

        if not username or not password:
            raise ValueError("bloodhound-python requires 'username' and 'password' in tool_config")

        # Collection methods: All covers group, localadmin, session, trusts, acl, etc.
        # bloodhound-python accepts a comma-separated list or the shorthand "All".
        collection: str = tool_config.get("collection", "All,Group,LocalAdmin,Session,Trusts")

        cmd = f"bloodhound-python -d {domain} -u {username} -p {password} -c {collection} --zip"
        if nameserver:
            cmd += f" -ns {nameserver}"
        return cmd

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """Parse BloodHound ZIP output containing JSON files.

        Accepts either:
        - A raw JSON string (pre-parsed summary, used in tests / direct injection)
        - Base64-encoded or raw bytes of a ZIP file (future integration path)

        In practice during testing we inject the summary JSON directly via
        raw_stdout so the parse logic supports both paths.
        """
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

        # Path 1: raw_stdout is already a JSON summary dict (test / direct mode)
        try:
            data = json.loads(raw_stdout.strip())
            if isinstance(data, dict):
                parsed_data = self._extract_summary(data)
                findings = self._build_findings(parsed_data)
                return PluginOutput(
                    plugin_name=self.meta.name,
                    raw_output=raw_stdout,
                    parsed_data=parsed_data,
                    findings=findings,
                    errors=errors,
                )
        except (json.JSONDecodeError, ValueError):
            pass

        # Path 2: raw_stdout is a path to a ZIP file produced by bloodhound-python
        zip_path = raw_stdout.strip()
        try:
            parsed_data = self._parse_zip(zip_path)
            findings = self._build_findings(parsed_data)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Failed to parse BloodHound output: {exc}")

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_zip(self, zip_path: str) -> dict[str, Any]:
        """Open a BloodHound ZIP and aggregate statistics from its JSON files."""
        counts: dict[str, int] = {
            "users": 0,
            "admins": 0,
            "kerberoastable": 0,
            "asreproastable": 0,
            "unconstrained_delegation": 0,
        }

        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                with zf.open(name) as fh:
                    try:
                        blob = json.load(fh)
                    except json.JSONDecodeError:
                        continue

                meta_type = blob.get("meta", {}).get("type", "")
                data_list: list[dict[str, Any]] = blob.get("data", [])

                if meta_type == "users":
                    counts["users"] += len(data_list)
                    for user in data_list:
                        props = user.get("Properties", {})
                        if props.get("admincount", False):
                            counts["admins"] += 1
                        if props.get("hasspn", False):
                            counts["kerberoastable"] += 1
                        if not props.get("enabled", True):
                            continue
                        if props.get("dontreqpreauth", False):
                            counts["asreproastable"] += 1
                        if props.get("unconstraineddelegation", False):
                            counts["unconstrained_delegation"] += 1

        return self._extract_summary(counts)

    def _extract_summary(self, data: dict[str, Any]) -> dict[str, Any]:
        """Normalise raw count dict into canonical parsed_data structure."""
        return {
            "users": int(data.get("users", 0)),
            "admins": int(data.get("admins", 0)),
            "kerberoastable": int(data.get("kerberoastable", 0)),
            "asreproastable": int(data.get("asreproastable", 0)),
            "unconstrained_delegation": int(data.get("unconstrained_delegation", 0)),
        }

    def _build_findings(self, summary: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate raw finding dicts from AD summary statistics."""
        findings: list[dict[str, Any]] = []

        kerberoastable = summary.get("kerberoastable", 0)
        if kerberoastable > 0:
            findings.append(
                {
                    "type": "kerberoastable_users",
                    "severity": "high",
                    "title": f"Kerberoastable Users Detected ({kerberoastable})",
                    "description": (
                        f"{kerberoastable} user account(s) have Service Principal Names (SPNs) "
                        "set and are vulnerable to Kerberoasting attacks."
                    ),
                    "count": kerberoastable,
                }
            )

        unconstrained = summary.get("unconstrained_delegation", 0)
        if unconstrained > 0:
            findings.append(
                {
                    "type": "unconstrained_delegation",
                    "severity": "critical",
                    "title": f"Unconstrained Delegation Enabled ({unconstrained})",
                    "description": (
                        f"{unconstrained} object(s) have unconstrained delegation enabled. "
                        "An attacker who compromises these accounts can impersonate any domain user."
                    ),
                    "count": unconstrained,
                }
            )

        asrep = summary.get("asreproastable", 0)
        if asrep > 0:
            findings.append(
                {
                    "type": "asrep_roastable_users",
                    "severity": "medium",
                    "title": f"AS-REP Roastable Users Detected ({asrep})",
                    "description": (
                        f"{asrep} user account(s) do not require Kerberos pre-authentication "
                        "and are vulnerable to AS-REP Roasting."
                    ),
                    "count": asrep,
                }
            )

        return findings
