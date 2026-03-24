"""Unit tests for the 6 Phase 1 security plugins."""

from __future__ import annotations

import os
from typing import Any

import pytest

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.cloud.prowler_plugin import ProwlerPlugin
from vxis.plugins.cloud.s3scanner_plugin import S3ScannerPlugin
from vxis.plugins.osint.gitleaks_plugin import GitleaksPlugin
from vxis.plugins.osint.shodan_plugin import ShodanPlugin
from vxis.plugins.supply_chain.trivy_plugin import TrivyPlugin
from vxis.plugins.brand.dnstwist_plugin import DnstwistPlugin


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TARGET = "example.com"
TOOL_CONFIG: dict[str, Any] = {}


def _make_ctx() -> DAGContext:
    return DAGContext(target=TARGET, scan_profile="standard")


# ---------------------------------------------------------------------------
# Sample output strings
# ---------------------------------------------------------------------------

PROWLER_SAMPLE = (
    '[{"CheckID":"iam_root_mfa","Status":"FAIL","Severity":"critical",'
    '"ServiceName":"IAM","Description":"Root MFA not enabled","Risk":"High",'
    '"Remediation":{"Recommendation":{"Text":"Enable MFA"}},'
    '"ResourceArn":"arn:aws:iam::root"}]'
)

PROWLER_PASS_SAMPLE = (
    '[{"CheckID":"iam_root_mfa","Status":"PASS","Severity":"critical",'
    '"ServiceName":"IAM","Description":"Root MFA enabled","Risk":"None",'
    '"Remediation":{},"ResourceArn":"arn:aws:iam::root"}]'
)

S3SCANNER_SAMPLE = (
    '{"bucket":"example-backup","exists":true,"public_read":true,"public_write":false}'
)

S3SCANNER_PRIVATE_SAMPLE = (
    '{"bucket":"example-private","exists":true,"public_read":false,"public_write":false}'
)

S3SCANNER_NOT_EXISTS_SAMPLE = (
    '{"bucket":"example-missing","exists":false,"public_read":false,"public_write":false}'
)

GITLEAKS_SAMPLE = (
    '[{"RuleID":"aws-access-key","Description":"AWS Access Key",'
    '"File":"config.yml","StartLine":10,"Commit":"abc123",'
    '"Secret":"AKIAIOSFODNN7EXAMPLE"}]'
)

SHODAN_SAMPLE = "93.184.216.34\t443\tEdgecast\tLinux\tnginx"

TRIVY_SAMPLE = (
    '{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2021-44228",'
    '"PkgName":"log4j","InstalledVersion":"2.14.0","FixedVersion":"2.17.0",'
    '"Severity":"CRITICAL","Title":"Log4Shell"}]}]}'
)

TRIVY_NO_VULNS_SAMPLE = '{"Results":[{"Vulnerabilities":null}]}'

DNSTWIST_SAMPLE = (
    '[{"fuzzer":"homoglyph","domain":"examp1e.com",'
    '"dns_a":["93.184.216.34"],"dns_mx":["mail.examp1e.com"]}]'
)

DNSTWIST_UNREGISTERED_SAMPLE = (
    '[{"fuzzer":"homoglyph","domain":"examp1e.com","dns_a":[],"dns_mx":[]}]'
)


# ===========================================================================
# ProwlerPlugin
# ===========================================================================

class TestProwlerPlugin:
    def setup_method(self) -> None:
        self.plugin = ProwlerPlugin()
        self.ctx = _make_ctx()

    def test_meta_name(self) -> None:
        assert self.plugin.meta.name == "prowler"

    def test_meta_depends_on(self) -> None:
        assert self.plugin.meta.depends_on == ()

    def test_build_command_default_provider(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, {})
        assert "prowler aws" in cmd
        # prowler v3+ uses -M for output mode (--output-formats was renamed)
        assert "-M json" in cmd
        assert "critical" in cmd and "high" in cmd and "medium" in cmd
        assert "-b" in cmd

    def test_build_command_custom_provider(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, {"provider": "gcp"})
        assert "prowler gcp" in cmd

    def test_parse_output_fail_finding(self) -> None:
        output = self.plugin.parse_output(PROWLER_SAMPLE, "")
        assert output.plugin_name == "prowler"
        assert len(output.findings) == 1
        finding = output.findings[0]
        assert finding["check_id"] == "iam_root_mfa"
        assert finding["status"] == "FAIL"
        assert finding["severity"] == "critical"
        assert finding["service_name"] == "IAM"
        assert finding["remediation"] == "Enable MFA"
        assert finding["resource_arn"] == "arn:aws:iam::root"

    def test_parse_output_pass_items_excluded(self) -> None:
        output = self.plugin.parse_output(PROWLER_PASS_SAMPLE, "")
        assert len(output.findings) == 0

    def test_parse_output_empty_input(self) -> None:
        output = self.plugin.parse_output("", "")
        assert output.findings == []
        assert output.errors == []

    def test_parse_output_invalid_json(self) -> None:
        output = self.plugin.parse_output("not json", "")
        assert len(output.errors) == 1
        assert "parse" in output.errors[0].lower()


# ===========================================================================
# S3ScannerPlugin
# ===========================================================================

class TestS3ScannerPlugin:
    def setup_method(self) -> None:
        self.plugin = S3ScannerPlugin()
        self.ctx = _make_ctx()

    def test_meta_name(self) -> None:
        assert self.plugin.meta.name == "s3scanner"

    def test_meta_depends_on(self) -> None:
        assert self.plugin.meta.depends_on == ()

    def test_build_command_contains_target_company(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, {})
        assert "s3scanner" in cmd
        assert "--json" in cmd
        assert "example" in cmd  # company name derived from example.com

    def test_build_command_returns_string(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, {})
        assert isinstance(cmd, str) and len(cmd) > 0

    def test_parse_output_public_bucket(self) -> None:
        output = self.plugin.parse_output(S3SCANNER_SAMPLE, "")
        assert output.plugin_name == "s3scanner"
        assert len(output.findings) == 1
        finding = output.findings[0]
        assert finding["bucket"] == "example-backup"
        assert finding["public_read"] is True

    def test_parse_output_private_bucket_excluded(self) -> None:
        output = self.plugin.parse_output(S3SCANNER_PRIVATE_SAMPLE, "")
        assert len(output.findings) == 0

    def test_parse_output_nonexistent_bucket_excluded(self) -> None:
        output = self.plugin.parse_output(S3SCANNER_NOT_EXISTS_SAMPLE, "")
        assert len(output.findings) == 0

    def test_parse_output_empty_input(self) -> None:
        output = self.plugin.parse_output("", "")
        assert output.findings == []


# ===========================================================================
# GitleaksPlugin
# ===========================================================================

class TestGitleaksPlugin:
    def setup_method(self) -> None:
        self.plugin = GitleaksPlugin()
        self.ctx = _make_ctx()

    def test_meta_name(self) -> None:
        assert self.plugin.meta.name == "gitleaks"

    def test_meta_depends_on(self) -> None:
        assert self.plugin.meta.depends_on == ()

    def test_build_command_contains_source(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, {"repo_url": "https://github.com/org/repo"})
        assert "gitleaks detect" in cmd
        assert "--source=https://github.com/org/repo" in cmd
        assert "--report-format json" in cmd
        # --no-git is intentionally absent: scanning the full git history is
        # more thorough than scanning only the working tree.  Callers that need
        # to scan a non-git directory should pass extra_flags="--no-git" via
        # tool_config.
        assert "--no-git" not in cmd
        assert "--exit-code 0" in cmd

    def test_build_command_defaults_to_target(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, {})
        assert f"--source={TARGET}" in cmd

    def test_parse_output_secret_masked(self) -> None:
        output = self.plugin.parse_output(GITLEAKS_SAMPLE, "")
        assert output.plugin_name == "gitleaks"
        assert len(output.findings) == 1
        finding = output.findings[0]
        assert finding["rule_id"] == "aws-access-key"
        assert finding["file"] == "config.yml"
        assert finding["start_line"] == 10
        assert finding["commit"] == "abc123"
        # Secret must be masked — raw value must not appear.
        assert "AKIAIOSFODNN7EXAMPLE" not in finding["secret"]
        assert "*" in finding["secret"]

    def test_parse_output_empty_input(self) -> None:
        output = self.plugin.parse_output("", "")
        assert output.findings == []

    def test_parse_output_invalid_json(self) -> None:
        output = self.plugin.parse_output("not json", "")
        assert len(output.errors) == 1


# ===========================================================================
# ShodanPlugin
# ===========================================================================

class TestShodanPlugin:
    def setup_method(self) -> None:
        self.plugin = ShodanPlugin()
        self.ctx = _make_ctx()

    def test_meta_name(self) -> None:
        assert self.plugin.meta.name == "shodan"

    def test_meta_depends_on(self) -> None:
        # shodan resolves the target IP via dig — no upstream plugin required.
        assert self.plugin.meta.depends_on == ()

    def test_build_command_contains_target(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, {})
        # shodan CLI uses 'shodan host <IP>'; target is passed via dig substitution.
        assert TARGET in cmd
        assert "shodan host" in cmd

    def test_parse_output_without_api_key_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        output = self.plugin.parse_output(SHODAN_SAMPLE, "")
        assert len(output.errors) == 1
        assert "SHODAN_API_KEY" in output.errors[0]
        assert output.findings == []

    def test_parse_output_with_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SHODAN_API_KEY", "test_key_12345")
        output = self.plugin.parse_output(SHODAN_SAMPLE, "")
        assert output.plugin_name == "shodan"
        assert len(output.findings) == 1
        finding = output.findings[0]
        assert finding["ip"] == "93.184.216.34"
        assert finding["port"] == 443
        assert finding["org"] == "Edgecast"
        assert finding["os"] == "Linux"
        assert finding["product"] == "nginx"

    def test_parse_output_empty_input(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SHODAN_API_KEY", "test_key_12345")
        output = self.plugin.parse_output("", "")
        assert output.findings == []


# ===========================================================================
# TrivyPlugin
# ===========================================================================

class TestTrivyPlugin:
    def setup_method(self) -> None:
        self.plugin = TrivyPlugin()
        self.ctx = _make_ctx()

    def test_meta_name(self) -> None:
        assert self.plugin.meta.name == "trivy"

    def test_meta_depends_on(self) -> None:
        assert self.plugin.meta.depends_on == ()

    def test_build_command_with_repo_url(self) -> None:
        cmd = self.plugin.build_command(
            TARGET, "standard", self.ctx, {"repo_url": "https://github.com/org/repo"}
        )
        assert "trivy repo" in cmd
        assert "--format json" in cmd
        assert "--severity CRITICAL,HIGH,MEDIUM" in cmd
        assert "https://github.com/org/repo" in cmd

    def test_build_command_without_repo_url_uses_fs(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, {})
        assert "trivy fs" in cmd
        assert "." in cmd

    def test_parse_output_vulnerability_extracted(self) -> None:
        output = self.plugin.parse_output(TRIVY_SAMPLE, "")
        assert output.plugin_name == "trivy"
        assert len(output.findings) == 1
        finding = output.findings[0]
        assert finding["vulnerability_id"] == "CVE-2021-44228"
        assert finding["pkg_name"] == "log4j"
        assert finding["installed_version"] == "2.14.0"
        assert finding["fixed_version"] == "2.17.0"
        assert finding["severity"] == "CRITICAL"
        assert finding["title"] == "Log4Shell"

    def test_parse_output_null_vulnerabilities_ignored(self) -> None:
        output = self.plugin.parse_output(TRIVY_NO_VULNS_SAMPLE, "")
        assert len(output.findings) == 0

    def test_parse_output_empty_input(self) -> None:
        output = self.plugin.parse_output("", "")
        assert output.findings == []

    def test_parse_output_invalid_json(self) -> None:
        output = self.plugin.parse_output("not json", "")
        assert len(output.errors) == 1


# ===========================================================================
# DnstwistPlugin
# ===========================================================================

class TestDnstwistPlugin:
    def setup_method(self) -> None:
        self.plugin = DnstwistPlugin()
        self.ctx = _make_ctx()

    def test_meta_name(self) -> None:
        assert self.plugin.meta.name == "dnstwist"

    def test_meta_depends_on(self) -> None:
        assert self.plugin.meta.depends_on == ()

    def test_build_command_contains_target(self) -> None:
        cmd = self.plugin.build_command(TARGET, "standard", self.ctx, {})
        assert "dnstwist" in cmd
        assert "--registered" in cmd
        assert "--format json" in cmd
        assert TARGET in cmd

    def test_parse_output_registered_domain_included(self) -> None:
        output = self.plugin.parse_output(DNSTWIST_SAMPLE, "")
        assert output.plugin_name == "dnstwist"
        assert len(output.findings) == 1
        finding = output.findings[0]
        assert finding["domain"] == "examp1e.com"
        assert finding["fuzzer"] == "homoglyph"
        assert "93.184.216.34" in finding["dns_a"]
        assert "mail.examp1e.com" in finding["dns_mx"]

    def test_parse_output_unregistered_domain_excluded(self) -> None:
        output = self.plugin.parse_output(DNSTWIST_UNREGISTERED_SAMPLE, "")
        assert len(output.findings) == 0

    def test_parse_output_empty_input(self) -> None:
        output = self.plugin.parse_output("", "")
        assert output.findings == []

    def test_parse_output_invalid_json(self) -> None:
        output = self.plugin.parse_output("not json", "")
        assert len(output.errors) == 1
