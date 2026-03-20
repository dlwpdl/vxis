"""Unit tests for all 8 VXIS security tool plugins."""

from __future__ import annotations

import textwrap
from typing import Any

import pytest

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.recon.subfinder import SubfinderPlugin
from vxis.plugins.recon.httpx_plugin import HttpxPlugin
from vxis.plugins.scan.nmap_plugin import NmapPlugin
from vxis.plugins.scan.wafw00f_plugin import Wafw00fPlugin
from vxis.plugins.vuln.nuclei_plugin import NucleiPlugin
from vxis.plugins.crypto.testssl_plugin import TestsslPlugin
from vxis.plugins.crypto.checkdmarc_plugin import CheckdmarcPlugin
from vxis.plugins.secrets.trufflehog_plugin import TrufflehogPlugin


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TARGET = "example.com"
TOOL_CONFIG: dict[str, Any] = {}


def _make_ctx(**plugin_data: Any) -> DAGContext:
    """Build a DAGContext pre-populated with plugin outputs."""
    ctx = DAGContext(target=TARGET, scan_profile="standard")
    for plugin_name, data in plugin_data.items():
        ctx.set(plugin_name, PluginOutput(plugin_name=plugin_name, parsed_data=data))
    return ctx


# ---------------------------------------------------------------------------
# Sample output strings
# ---------------------------------------------------------------------------

SUBFINDER_SAMPLE = (
    '{"host":"api.example.com","source":"crtsh"}\n'
    '{"host":"mail.example.com","source":"dnsdumpster"}'
)

HTTPX_SAMPLE = (
    '{"url":"https://api.example.com","status_code":200,"title":"API",'
    '"tech":["nginx"],"cdn":false,"cname":[],'
    '"asn":{"as_number":"AS1234"}}'
)

NMAP_SAMPLE = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="93.184.216.34" addrtype="ipv4"/>
        <hostnames>
          <hostname name="example.com" type="user"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open" reason="syn-ack"/>
            <service name="https" product="nginx" version="1.24.0"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""")

WAFW00F_SAMPLE = (
    '[{"url":"https://example.com","detected":true,'
    '"firewall":"Cloudflare","manufacturer":"Cloudflare Inc."}]'
)

NUCLEI_SAMPLE = (
    '{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE",'
    '"severity":"critical","tags":["cve","rce"]},'
    '"matched-at":"https://example.com/api","matcher-status":true}'
)

TESTSSL_SAMPLE = (
    '[{"id":"POODLE_SSL","severity":"HIGH","finding":"POODLE SSL",'
    '"cwe":"CWE-310","cve":"CVE-2014-3566"}]'
)

CHECKDMARC_SAMPLE = (
    '{"domain":"example.com",'
    '"spf":{"valid":true,"record":"v=spf1 ~all"},'
    '"dmarc":{"valid":true,"record":"v=DMARC1; p=none",'
    '"tags":{"p":{"value":"none"}}}}'
)

TRUFFLEHOG_SAMPLE = (
    '{"DetectorName":"AWS","Verified":false,"Raw":"AKIAIOSFODNN7EXAMPLE",'
    '"SourceMetadata":{"Data":{"Github":{"repository":'
    '"https://github.com/example/repo","file":"config.yml","line":42}}}}'
)


# ===========================================================================
# Plugin 1: subfinder
# ===========================================================================


class TestSubfinderPlugin:
    plugin = SubfinderPlugin()

    def test_meta_name(self):
        assert self.plugin.meta.name == "subfinder"

    def test_meta_depends_on(self):
        assert self.plugin.meta.depends_on == ()

    def test_build_command_contains_target(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        assert TARGET in cmd

    def test_build_command_stealth_threads(self):
        ctx = DAGContext(target=TARGET, scan_profile="stealth")
        cmd = self.plugin.build_command(TARGET, "stealth", ctx, TOOL_CONFIG)
        assert "-t 2" in cmd

    def test_build_command_aggressive_threads(self):
        ctx = DAGContext(target=TARGET, scan_profile="aggressive")
        cmd = self.plugin.build_command(TARGET, "aggressive", ctx, TOOL_CONFIG)
        assert "-t 30" in cmd

    def test_parse_output_extracts_hosts(self):
        result = self.plugin.parse_output(SUBFINDER_SAMPLE, "")
        assert "subdomains" in result.parsed_data
        subdomains = result.parsed_data["subdomains"]
        assert "api.example.com" in subdomains
        assert "mail.example.com" in subdomains

    def test_parse_output_deduplicates(self):
        duplicate = SUBFINDER_SAMPLE + '\n{"host":"api.example.com","source":"virustotal"}'
        result = self.plugin.parse_output(duplicate, "")
        subdomains = result.parsed_data["subdomains"]
        assert subdomains.count("api.example.com") == 1

    def test_parse_output_empty(self):
        result = self.plugin.parse_output("", "")
        assert result.parsed_data["subdomains"] == []

    def test_parse_output_invalid_json_skipped(self):
        bad_input = "not-json\n" + SUBFINDER_SAMPLE
        result = self.plugin.parse_output(bad_input, "")
        assert len(result.parsed_data["subdomains"]) == 2


# ===========================================================================
# Plugin 2: httpx
# ===========================================================================


class TestHttpxPlugin:
    plugin = HttpxPlugin()

    def test_meta_name(self):
        assert self.plugin.meta.name == "httpx"

    def test_meta_depends_on(self):
        assert "subfinder" in self.plugin.meta.depends_on

    def test_build_command_contains_target_fallback(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        # Command must reference a file; target is written to the file not the cmd.
        assert "httpx" in cmd

    def test_build_command_stealth_rate(self):
        ctx = _make_ctx(subfinder={"subdomains": ["api.example.com"]})
        cmd = self.plugin.build_command(TARGET, "stealth", ctx, TOOL_CONFIG)
        assert "-rate-limit 10" in cmd

    def test_build_command_aggressive_rate(self):
        ctx = _make_ctx(subfinder={"subdomains": ["api.example.com"]})
        cmd = self.plugin.build_command(TARGET, "aggressive", ctx, TOOL_CONFIG)
        assert "-rate-limit 300" in cmd

    def test_parse_output_extracts_url(self):
        result = self.plugin.parse_output(HTTPX_SAMPLE, "")
        assert "https://api.example.com" in result.parsed_data["live_urls"]

    def test_parse_output_extracts_live_hosts(self):
        result = self.plugin.parse_output(HTTPX_SAMPLE, "")
        hosts = result.parsed_data["live_hosts"]
        assert len(hosts) == 1
        assert hosts[0]["status_code"] == 200
        assert hosts[0]["cdn"] is False

    def test_parse_output_empty(self):
        result = self.plugin.parse_output("", "")
        assert result.parsed_data["live_hosts"] == []
        assert result.parsed_data["live_urls"] == []

    def test_parse_output_invalid_json_skipped(self):
        bad_input = "garbage\n" + HTTPX_SAMPLE
        result = self.plugin.parse_output(bad_input, "")
        assert len(result.parsed_data["live_hosts"]) == 1


# ===========================================================================
# Plugin 3: nmap
# ===========================================================================


class TestNmapPlugin:
    plugin = NmapPlugin()

    def test_meta_name(self):
        assert self.plugin.meta.name == "nmap"

    def test_meta_depends_on(self):
        assert "httpx" in self.plugin.meta.depends_on

    def test_build_command_contains_timing(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        assert "-T3" in cmd

    def test_build_command_stealth_timing(self):
        ctx = DAGContext(target=TARGET, scan_profile="stealth")
        cmd = self.plugin.build_command(TARGET, "stealth", ctx, TOOL_CONFIG)
        assert "-T2" in cmd

    def test_build_command_aggressive_timing(self):
        ctx = DAGContext(target=TARGET, scan_profile="aggressive")
        cmd = self.plugin.build_command(TARGET, "aggressive", ctx, TOOL_CONFIG)
        assert "-T4" in cmd

    def test_parse_output_extracts_host(self):
        result = self.plugin.parse_output(NMAP_SAMPLE, "")
        hosts = result.parsed_data["hosts"]
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "93.184.216.34"

    def test_parse_output_extracts_open_port(self):
        result = self.plugin.parse_output(NMAP_SAMPLE, "")
        ports = result.parsed_data["hosts"][0]["ports"]
        assert len(ports) == 1
        assert ports[0]["port"] == 443
        assert ports[0]["state"] == "open"

    def test_parse_output_extracts_service(self):
        result = self.plugin.parse_output(NMAP_SAMPLE, "")
        port = result.parsed_data["hosts"][0]["ports"][0]
        assert port["service"] == "https"
        assert "nginx" in port["product"]

    def test_parse_output_empty(self):
        result = self.plugin.parse_output("", "")
        assert result.parsed_data["hosts"] == []

    def test_parse_output_invalid_xml(self):
        result = self.plugin.parse_output("not xml", "")
        assert result.parsed_data["hosts"] == []
        assert len(result.errors) > 0


# ===========================================================================
# Plugin 4: wafw00f
# ===========================================================================


class TestWafw00fPlugin:
    plugin = Wafw00fPlugin()

    def test_meta_name(self):
        assert self.plugin.meta.name == "wafw00f"

    def test_meta_depends_on(self):
        assert "httpx" in self.plugin.meta.depends_on

    def test_build_command_contains_flags(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        assert "wafw00f" in cmd
        assert "-f json" in cmd

    def test_build_command_uses_live_urls(self):
        ctx = _make_ctx(httpx={"live_urls": ["https://api.example.com"]})
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        # Live URLs are written to a temp file; command should reference wafw00f -i
        assert "-i" in cmd

    def test_parse_output_extracts_waf(self):
        result = self.plugin.parse_output(WAFW00F_SAMPLE, "")
        waf_results = result.parsed_data["waf_results"]
        assert len(waf_results) == 1
        assert waf_results[0]["detected"] is True
        assert waf_results[0]["firewall"] == "Cloudflare"

    def test_parse_output_empty(self):
        result = self.plugin.parse_output("", "")
        assert result.parsed_data["waf_results"] == []

    def test_parse_output_invalid_json(self):
        result = self.plugin.parse_output("not json", "")
        assert result.parsed_data["waf_results"] == []
        assert len(result.errors) > 0


# ===========================================================================
# Plugin 5: nuclei
# ===========================================================================


class TestNucleiPlugin:
    plugin = NucleiPlugin()

    def test_meta_name(self):
        assert self.plugin.meta.name == "nuclei"

    def test_meta_depends_on(self):
        assert "httpx" in self.plugin.meta.depends_on

    def test_meta_optional_depends(self):
        assert "wafw00f" in self.plugin.meta.optional_depends

    def test_build_command_contains_target(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        assert "nuclei" in cmd

    def test_build_command_standard_rate(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        assert "-rate-limit 50" in cmd

    def test_build_command_waf_reduces_rate(self):
        ctx = _make_ctx(
            httpx={"live_urls": ["https://example.com"]},
            wafw00f={"waf_results": [{"detected": True, "firewall": "Cloudflare"}]},
        )
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        assert "-rate-limit 25" in cmd

    def test_build_command_aggressive_rate(self):
        ctx = DAGContext(target=TARGET, scan_profile="aggressive")
        cmd = self.plugin.build_command(TARGET, "aggressive", ctx, TOOL_CONFIG)
        assert "-rate-limit 150" in cmd

    def test_parse_output_extracts_finding(self):
        result = self.plugin.parse_output(NUCLEI_SAMPLE, "")
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding["template_id"] == "CVE-2021-44228"
        assert finding["severity"] == "critical"

    def test_parse_output_extracts_cve(self):
        result = self.plugin.parse_output(NUCLEI_SAMPLE, "")
        finding = result.findings[0]
        assert "CVE-2021-44228" in finding["cve_id"]

    def test_parse_output_empty(self):
        result = self.plugin.parse_output("", "")
        assert result.findings == []
        assert result.parsed_data["vulnerabilities"] == []

    def test_parse_output_invalid_json_skipped(self):
        bad_input = "garbage\n" + NUCLEI_SAMPLE
        result = self.plugin.parse_output(bad_input, "")
        assert len(result.findings) == 1


# ===========================================================================
# Plugin 6: testssl
# ===========================================================================


class TestTestsslPlugin:
    plugin = TestsslPlugin()

    def test_meta_name(self):
        assert self.plugin.meta.name == "testssl"

    def test_meta_depends_on(self):
        assert "nmap" in self.plugin.meta.depends_on

    def test_build_command_contains_port_443(self):
        nmap_hosts = [{
            "ip": "93.184.216.34",
            "hostname": "example.com",
            "ports": [{"port": 443, "state": "open", "service": "https", "scripts": []}],
        }]
        ctx = _make_ctx(nmap={"hosts": nmap_hosts})
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        assert ":443" in cmd

    def test_build_command_fallback_to_target(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        assert TARGET in cmd

    def test_parse_output_extracts_finding(self):
        result = self.plugin.parse_output(TESTSSL_SAMPLE, "")
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding["id"] == "POODLE_SSL"
        assert finding["severity"] == "HIGH"
        assert finding["cve"] == "CVE-2014-3566"

    def test_parse_output_filters_ok(self):
        ok_record = '[{"id":"cert_chain_of_trust","severity":"OK","finding":"OK","cwe":"","cve":""}]'
        result = self.plugin.parse_output(ok_record, "")
        assert result.findings == []

    def test_parse_output_filters_info(self):
        info_record = '[{"id":"service","severity":"INFO","finding":"HTTPS","cwe":"","cve":""}]'
        result = self.plugin.parse_output(info_record, "")
        assert result.findings == []

    def test_parse_output_empty(self):
        result = self.plugin.parse_output("", "")
        assert result.parsed_data["tls_findings"] == []

    def test_parse_output_invalid_json(self):
        result = self.plugin.parse_output("bad json", "")
        assert result.parsed_data["tls_findings"] == []
        assert len(result.errors) > 0


# ===========================================================================
# Plugin 7: checkdmarc
# ===========================================================================


class TestCheckdmarcPlugin:
    plugin = CheckdmarcPlugin()

    def test_meta_name(self):
        assert self.plugin.meta.name == "checkdmarc"

    def test_meta_depends_on(self):
        assert self.plugin.meta.depends_on == ()

    def test_build_command_contains_target(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        assert TARGET in cmd

    def test_build_command_json_format(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        assert "--output-format json" in cmd

    def test_parse_output_spf_softfail_finding(self):
        result = self.plugin.parse_output(CHECKDMARC_SAMPLE, "")
        finding_types = [f["type"] for f in result.findings]
        assert "spf_softfail" in finding_types

    def test_parse_output_dmarc_policy_none_finding(self):
        result = self.plugin.parse_output(CHECKDMARC_SAMPLE, "")
        finding_types = [f["type"] for f in result.findings]
        assert "dmarc_policy_none" in finding_types

    def test_parse_output_strict_spf_and_dmarc_no_critical(self):
        strict = (
            '{"domain":"example.com",'
            '"spf":{"valid":true,"record":"v=spf1 -all"},'
            '"dmarc":{"valid":true,"record":"v=DMARC1; p=reject",'
            '"tags":{"p":{"value":"reject"}}}}'
        )
        result = self.plugin.parse_output(strict, "")
        # No findings for properly configured SPF (-all) and DMARC (reject).
        assert result.findings == []

    def test_parse_output_invalid_spf_finding(self):
        invalid_spf = (
            '{"domain":"example.com",'
            '"spf":{"valid":false,"error":"No SPF record found"},'
            '"dmarc":{"valid":true,"record":"v=DMARC1; p=reject",'
            '"tags":{"p":{"value":"reject"}}}}'
        )
        result = self.plugin.parse_output(invalid_spf, "")
        types = [f["type"] for f in result.findings]
        assert "spf_invalid" in types

    def test_parse_output_plus_all_finding(self):
        plus_all = (
            '{"domain":"example.com",'
            '"spf":{"valid":true,"record":"v=spf1 +all"},'
            '"dmarc":{"valid":true,"record":"v=DMARC1; p=reject",'
            '"tags":{"p":{"value":"reject"}}}}'
        )
        result = self.plugin.parse_output(plus_all, "")
        types = [f["type"] for f in result.findings]
        assert "spf_too_permissive" in types

    def test_parse_output_empty(self):
        result = self.plugin.parse_output("", "")
        assert result.parsed_data["email_security"] == {}

    def test_parse_output_invalid_json(self):
        result = self.plugin.parse_output("not json", "")
        assert len(result.errors) > 0


# ===========================================================================
# Plugin 8: trufflehog
# ===========================================================================


class TestTrufflehogPlugin:
    plugin = TrufflehogPlugin()

    def test_meta_name(self):
        assert self.plugin.meta.name == "trufflehog"

    def test_meta_depends_on(self):
        assert self.plugin.meta.depends_on == ()

    def test_build_command_contains_target_org(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        # "example.com" → org "example"
        assert "--org=example" in cmd

    def test_build_command_uses_github_org_override(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(TARGET, "standard", ctx, {"github_org": "myorg"})
        assert "--org=myorg" in cmd

    def test_build_command_adds_token_when_provided(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(
            TARGET, "standard", ctx, {"github_token": "ghp_secret"}
        )
        assert "--token ghp_secret" in cmd

    def test_build_command_no_token_by_default(self):
        ctx = DAGContext(target=TARGET, scan_profile="standard")
        cmd = self.plugin.build_command(TARGET, "standard", ctx, TOOL_CONFIG)
        assert "--token" not in cmd

    def test_parse_output_extracts_finding(self):
        result = self.plugin.parse_output(TRUFFLEHOG_SAMPLE, "")
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding["detector_name"] == "AWS"
        assert finding["verified"] is False

    def test_parse_output_masks_secret(self):
        result = self.plugin.parse_output(TRUFFLEHOG_SAMPLE, "")
        finding = result.findings[0]
        # Raw value "AKIAIOSFODNN7EXAMPLE" (20 chars) must be masked.
        raw_masked: str = finding["raw_masked"]
        assert "AKIAIOSFODNN7EXAMPLE" not in raw_masked
        # First 4 and last 4 characters should be preserved.
        assert raw_masked.startswith("AKIA")
        assert raw_masked.endswith("MPLE")

    def test_parse_output_deduplicates(self):
        duplicate = TRUFFLEHOG_SAMPLE + "\n" + TRUFFLEHOG_SAMPLE
        result = self.plugin.parse_output(duplicate, "")
        assert len(result.findings) == 1

    def test_parse_output_empty(self):
        result = self.plugin.parse_output("", "")
        assert result.findings == []
        assert result.parsed_data["exposed_secrets"] == []

    def test_parse_output_invalid_json_skipped(self):
        bad_input = "not-json\n" + TRUFFLEHOG_SAMPLE
        result = self.plugin.parse_output(bad_input, "")
        assert len(result.findings) == 1
