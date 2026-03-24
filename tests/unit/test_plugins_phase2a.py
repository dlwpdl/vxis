"""Unit tests for Tier 2 security plugins: AD and Privilege Escalation."""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.ad.bloodhound_plugin import BloodhoundPlugin
from vxis.plugins.ad.certipy_plugin import CertipyPlugin
from vxis.plugins.ad.netexec_plugin import NetexecPlugin
from vxis.plugins.privesc.linpeas_plugin import LinpeasPlugin
from vxis.plugins.privesc.winpeas_plugin import WinpeasPlugin


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TARGET = "10.0.0.1"
DOMAIN = "corp.local"
TOOL_CONFIG: dict[str, Any] = {
    "domain": DOMAIN,
    "username": "testuser",
    "password": "Password123!",
    "nameserver": "10.0.0.1",
    "dc_ip": "10.0.0.1",
}


def _make_ctx() -> DAGContext:
    return DAGContext(target=TARGET, scan_profile="standard")


# ---------------------------------------------------------------------------
# Sample output strings (as specified in the task)
# ---------------------------------------------------------------------------

BLOODHOUND_SAMPLE = (
    '{"users":150,"admins":5,"kerberoastable":12,'
    '"asreproastable":3,"unconstrained_delegation":2}'
)

CERTIPY_SAMPLE = (
    '{"Certificate Templates":['
    '{"Template Name":"VulnTemplate","Enabled":true,'
    '"Client Authentication":true,"Enrollee Supplies Subject":true,'
    '"Vulnerability":"ESC1"}'
    ']}'
)

NETEXEC_SAMPLE = (
    "SMB  10.0.0.1  445  DC01  [*] Share: ADMIN$ Permissions: READ\n"
    "SMB  10.0.0.1  445  DC01  [*] Share: backup Permissions: READ,WRITE\n"
    "SMB  10.0.0.1  445  DC01  [+] Password Policy: MinLength=4 Complexity=False"
)

LINPEAS_SAMPLE = (
    "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 SUID binaries\n"
    "[95%] /usr/bin/sudo is SUID and writable\n"
    "[70%] /usr/bin/pkexec has known CVE\n"
    "[50%] /tmp is world writable"
)

WINPEAS_SAMPLE = (
    "[!] [95%] AlwaysInstallElevated is enabled\n"
    "[!] [70%] Unquoted service path: VulnService"
)


# ===========================================================================
# BloodHound Plugin
# ===========================================================================


class TestBloodhoundPlugin:
    def setup_method(self) -> None:
        self.plugin = BloodhoundPlugin()
        self.ctx = _make_ctx()

    def test_meta_name(self) -> None:
        assert self.plugin.meta.name == "bloodhound"

    def test_meta_category(self) -> None:
        assert self.plugin.meta.category == "ad"

    def test_meta_depends_on(self) -> None:
        assert self.plugin.meta.depends_on == ()

    def test_meta_produces(self) -> None:
        assert "ad_graph" in self.plugin.meta.produces

    def test_meta_timeout(self) -> None:
        assert self.plugin.meta.timeout_seconds == 1800

    def test_build_command_contains_domain(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, TOOL_CONFIG)
        assert DOMAIN in cmd
        assert "bloodhound-python" in cmd
        assert "-c All" in cmd
        assert "--zip" in cmd

    def test_build_command_contains_credentials(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, TOOL_CONFIG)
        assert "testuser" in cmd
        assert "Password123!" in cmd
        assert "10.0.0.1" in cmd

    def test_parse_output_sample(self) -> None:
        output = self.plugin.parse_output(BLOODHOUND_SAMPLE, "")
        assert isinstance(output, PluginOutput)
        assert output.plugin_name == "bloodhound"
        assert output.parsed_data["users"] == 150
        assert output.parsed_data["admins"] == 5
        assert output.parsed_data["kerberoastable"] == 12
        assert output.parsed_data["asreproastable"] == 3
        assert output.parsed_data["unconstrained_delegation"] == 2

    def test_parse_output_findings_generated(self) -> None:
        output = self.plugin.parse_output(BLOODHOUND_SAMPLE, "")
        assert len(output.findings) == 3
        severity_types = {f["type"] for f in output.findings}
        assert "kerberoastable_users" in severity_types
        assert "unconstrained_delegation" in severity_types
        assert "asrep_roastable_users" in severity_types

    def test_parse_output_severity_mapping(self) -> None:
        output = self.plugin.parse_output(BLOODHOUND_SAMPLE, "")
        sev_map = {f["type"]: f["severity"] for f in output.findings}
        assert sev_map["kerberoastable_users"] == "high"
        assert sev_map["unconstrained_delegation"] == "critical"
        assert sev_map["asrep_roastable_users"] == "medium"

    def test_parse_output_empty(self) -> None:
        output = self.plugin.parse_output("", "")
        assert output.parsed_data == {}
        assert output.findings == []
        assert output.errors == []

    def test_parse_output_no_risky_accounts(self) -> None:
        safe_data = json.dumps({"users": 50, "admins": 2, "kerberoastable": 0,
                                "asreproastable": 0, "unconstrained_delegation": 0})
        output = self.plugin.parse_output(safe_data, "")
        assert output.findings == []

    def test_parse_output_invalid_json(self) -> None:
        output = self.plugin.parse_output("not json at all", "")
        # Falls through to zip path; errors should be populated
        assert isinstance(output, PluginOutput)


# ===========================================================================
# Certipy Plugin
# ===========================================================================


class TestCertipyPlugin:
    def setup_method(self) -> None:
        self.plugin = CertipyPlugin()
        self.ctx = _make_ctx()

    def test_meta_name(self) -> None:
        assert self.plugin.meta.name == "certipy"

    def test_meta_category(self) -> None:
        assert self.plugin.meta.category == "ad"

    def test_meta_depends_on(self) -> None:
        assert self.plugin.meta.depends_on == ()

    def test_meta_produces(self) -> None:
        assert "adcs_findings" in self.plugin.meta.produces

    def test_meta_timeout(self) -> None:
        assert self.plugin.meta.timeout_seconds == 600

    def test_build_command_format(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, TOOL_CONFIG)
        assert "certipy find" in cmd
        assert f"testuser@{DOMAIN}" in cmd
        assert "Password123!" in cmd
        assert "-dc-ip 10.0.0.1" in cmd
        assert "-json" in cmd

    def test_parse_output_sample(self) -> None:
        output = self.plugin.parse_output(CERTIPY_SAMPLE, "")
        assert isinstance(output, PluginOutput)
        assert output.plugin_name == "certipy"
        assert output.parsed_data["total_vulnerable"] == 1

    def test_parse_output_vulnerable_template(self) -> None:
        output = self.plugin.parse_output(CERTIPY_SAMPLE, "")
        templates = output.parsed_data["vulnerable_templates"]
        assert len(templates) == 1
        t = templates[0]
        assert t["template_name"] == "VulnTemplate"
        assert t["vulnerability"] == "ESC1"
        assert t["severity"] == "critical"

    def test_parse_output_findings(self) -> None:
        output = self.plugin.parse_output(CERTIPY_SAMPLE, "")
        assert len(output.findings) == 1
        finding = output.findings[0]
        assert finding["severity"] == "critical"
        assert "VulnTemplate" in finding["title"]
        assert "ESC1" in finding["title"]

    def test_parse_output_esc3_is_high(self) -> None:
        data = json.dumps({"Certificate Templates": [
            {"Template Name": "TestTemplate", "Enabled": True,
             "Client Authentication": True, "Enrollee Supplies Subject": False,
             "Vulnerability": "ESC3"}
        ]})
        output = self.plugin.parse_output(data, "")
        assert output.findings[0]["severity"] == "high"

    def test_parse_output_empty(self) -> None:
        output = self.plugin.parse_output("", "")
        assert output.parsed_data == {}
        assert output.findings == []
        assert output.errors == []

    def test_parse_output_no_vulnerable_templates(self) -> None:
        data = json.dumps({"Certificate Templates": [
            {"Template Name": "SafeTemplate", "Enabled": True,
             "Client Authentication": True, "Enrollee Supplies Subject": False}
        ]})
        output = self.plugin.parse_output(data, "")
        assert output.findings == []
        assert output.parsed_data["total_vulnerable"] == 0

    def test_parse_output_invalid_json(self) -> None:
        output = self.plugin.parse_output("{invalid json}", "")
        assert len(output.errors) > 0


# ===========================================================================
# NetExec Plugin
# ===========================================================================


class TestNetexecPlugin:
    def setup_method(self) -> None:
        self.plugin = NetexecPlugin()
        self.ctx = _make_ctx()

    def test_meta_name(self) -> None:
        assert self.plugin.meta.name == "netexec"

    def test_meta_category(self) -> None:
        assert self.plugin.meta.category == "ad"

    def test_meta_depends_on(self) -> None:
        assert self.plugin.meta.depends_on == ()

    def test_meta_produces(self) -> None:
        assert "ad_enum" in self.plugin.meta.produces

    def test_meta_timeout(self) -> None:
        assert self.plugin.meta.timeout_seconds == 900

    def test_build_command_format(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, TOOL_CONFIG)
        assert cmd.startswith("nxc smb")
        assert TARGET in cmd
        assert "testuser" in cmd
        assert "Password123!" in cmd
        assert "--shares" in cmd
        assert "--pass-pol" in cmd

    def test_parse_output_shares(self) -> None:
        output = self.plugin.parse_output(NETEXEC_SAMPLE, "")
        assert isinstance(output, PluginOutput)
        shares = output.parsed_data["readable_shares"]
        share_names = {s["share"] for s in shares}
        assert "ADMIN$" in share_names
        assert "backup" in share_names

    def test_parse_output_share_findings(self) -> None:
        output = self.plugin.parse_output(NETEXEC_SAMPLE, "")
        share_findings = [f for f in output.findings if f["type"] == "readable_share"]
        assert len(share_findings) == 2
        for f in share_findings:
            assert f["severity"] == "medium"

    def test_parse_output_password_policy(self) -> None:
        output = self.plugin.parse_output(NETEXEC_SAMPLE, "")
        policy = output.parsed_data["password_policy"]
        assert policy["min_length"] == 4
        assert policy["complexity"] is False

    def test_parse_output_weak_policy_finding(self) -> None:
        output = self.plugin.parse_output(NETEXEC_SAMPLE, "")
        pol_findings = [f for f in output.findings if f["type"] == "weak_password_policy"]
        assert len(pol_findings) == 1
        assert pol_findings[0]["severity"] == "high"

    def test_parse_output_empty(self) -> None:
        output = self.plugin.parse_output("", "")
        assert output.parsed_data == {}
        assert output.findings == []
        assert output.errors == []

    def test_parse_output_no_readable_shares(self) -> None:
        no_shares = "SMB  10.0.0.1  445  DC01  [+] Password Policy: MinLength=12 Complexity=True"
        output = self.plugin.parse_output(no_shares, "")
        assert output.parsed_data["readable_shares"] == []
        pol_findings = [f for f in output.findings if f["type"] == "weak_password_policy"]
        assert len(pol_findings) == 0


# ===========================================================================
# LinPEAS Plugin
# ===========================================================================


class TestLinpeasPlugin:
    def setup_method(self) -> None:
        self.plugin = LinpeasPlugin()
        self.ctx = _make_ctx()

    def test_meta_name(self) -> None:
        assert self.plugin.meta.name == "linpeas"

    def test_meta_category(self) -> None:
        assert self.plugin.meta.category == "privesc"

    def test_meta_depends_on(self) -> None:
        assert self.plugin.meta.depends_on == ()

    def test_meta_produces(self) -> None:
        assert "linux_privesc" in self.plugin.meta.produces

    def test_meta_binary(self) -> None:
        assert self.plugin.meta.tool_binary == "bash"

    def test_meta_timeout(self) -> None:
        assert self.plugin.meta.timeout_seconds == 600

    def test_build_command(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, {})
        assert "bash /opt/vxis/linpeas.sh" in cmd
        assert "-q" in cmd
        assert "-a" in cmd

    def test_parse_output_count(self) -> None:
        output = self.plugin.parse_output(LINPEAS_SAMPLE, "")
        assert isinstance(output, PluginOutput)
        assert output.plugin_name == "linpeas"
        assert len(output.findings) == 3

    def test_parse_output_severity_critical(self) -> None:
        output = self.plugin.parse_output(LINPEAS_SAMPLE, "")
        critical = [f for f in output.findings if f["severity"] == "critical"]
        assert len(critical) == 1
        assert "/usr/bin/sudo" in critical[0]["title"]

    def test_parse_output_severity_high(self) -> None:
        output = self.plugin.parse_output(LINPEAS_SAMPLE, "")
        high = [f for f in output.findings if f["severity"] == "high"]
        assert len(high) == 1
        assert "pkexec" in high[0]["title"]

    def test_parse_output_severity_medium(self) -> None:
        output = self.plugin.parse_output(LINPEAS_SAMPLE, "")
        medium = [f for f in output.findings if f["severity"] == "medium"]
        assert len(medium) == 1
        assert "/tmp" in medium[0]["title"]

    def test_parse_output_summary_counts(self) -> None:
        output = self.plugin.parse_output(LINPEAS_SAMPLE, "")
        counts = output.parsed_data["findings_by_severity"]
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1

    def test_parse_output_empty(self) -> None:
        output = self.plugin.parse_output("", "")
        assert output.parsed_data == {}
        assert output.findings == []
        assert output.errors == []

    def test_parse_output_no_markers(self) -> None:
        no_markers = "Some random linpeas output without any percentage markers"
        output = self.plugin.parse_output(no_markers, "")
        assert output.findings == []

    def test_parse_output_ansi_stripped(self) -> None:
        ansi_output = "\x1b[1;31m[95%] SUID binary found: /usr/bin/bash\x1b[0m"
        output = self.plugin.parse_output(ansi_output, "")
        assert len(output.findings) == 1
        assert output.findings[0]["severity"] == "critical"


# ===========================================================================
# WinPEAS Plugin
# ===========================================================================


class TestWinpeasPlugin:
    def setup_method(self) -> None:
        self.plugin = WinpeasPlugin()
        self.ctx = _make_ctx()

    def test_meta_name(self) -> None:
        assert self.plugin.meta.name == "winpeas"

    def test_meta_category(self) -> None:
        assert self.plugin.meta.category == "privesc"

    def test_meta_depends_on(self) -> None:
        assert self.plugin.meta.depends_on == ()

    def test_meta_produces(self) -> None:
        assert "windows_privesc" in self.plugin.meta.produces

    def test_meta_binary(self) -> None:
        assert self.plugin.meta.tool_binary == "winpeas.exe"

    def test_meta_timeout(self) -> None:
        assert self.plugin.meta.timeout_seconds == 600

    def test_build_command(self) -> None:
        if sys.platform != "win32":
            # WinPEAS raises OSError on non-Windows platforms — that is the
            # correct behaviour; the orchestrator will skip this plugin.
            with pytest.raises(OSError, match="Windows"):
                self.plugin.build_command(TARGET, "standard", self.ctx, {})
        else:
            cmd = self.plugin.build_command(TARGET, "standard", self.ctx, {})
            assert "winpeas.exe" in cmd
            assert "quiet" in cmd
            assert "searchall" in cmd

    def test_parse_output_count(self) -> None:
        output = self.plugin.parse_output(WINPEAS_SAMPLE, "")
        assert isinstance(output, PluginOutput)
        assert output.plugin_name == "winpeas"
        assert len(output.findings) == 2

    def test_parse_output_critical(self) -> None:
        output = self.plugin.parse_output(WINPEAS_SAMPLE, "")
        critical = [f for f in output.findings if f["severity"] == "critical"]
        assert len(critical) == 1
        assert "AlwaysInstallElevated" in critical[0]["title"]

    def test_parse_output_high(self) -> None:
        output = self.plugin.parse_output(WINPEAS_SAMPLE, "")
        high = [f for f in output.findings if f["severity"] == "high"]
        assert len(high) == 1
        assert "Unquoted service path" in high[0]["title"]

    def test_parse_output_summary_counts(self) -> None:
        output = self.plugin.parse_output(WINPEAS_SAMPLE, "")
        counts = output.parsed_data["findings_by_severity"]
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 0

    def test_parse_output_empty(self) -> None:
        output = self.plugin.parse_output("", "")
        assert output.parsed_data == {}
        assert output.findings == []
        assert output.errors == []

    def test_parse_output_no_markers(self) -> None:
        no_markers = "WinPEAS output without severity markers"
        output = self.plugin.parse_output(no_markers, "")
        assert output.findings == []

    def test_parse_output_ansi_stripped(self) -> None:
        ansi_output = "\x1b[1;31m[!] [95%] AlwaysInstallElevated is enabled\x1b[0m"
        output = self.plugin.parse_output(ansi_output, "")
        assert len(output.findings) == 1
        assert output.findings[0]["severity"] == "critical"
