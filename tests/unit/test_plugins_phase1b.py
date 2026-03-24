"""Phase 1b plugin tests — swaks, crtsh, confused, sslyze + normalizer additions."""

from __future__ import annotations

import json

import pytest

from vxis.core.context import DAGContext
from vxis.core.normalizer import FindingFactory
from vxis.plugins.cert.crtsh_plugin import CrtshPlugin
from vxis.plugins.cert.sslyze_plugin import SSLyzePlugin
from vxis.plugins.email.swaks_plugin import SwaksPlugin
from vxis.plugins.supply_chain.confused_plugin import ConfusedPlugin


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ctx() -> DAGContext:
    return DAGContext(target="example.com", scan_profile="standard")


@pytest.fixture()
def swaks() -> SwaksPlugin:
    return SwaksPlugin()


@pytest.fixture()
def crtsh() -> CrtshPlugin:
    return CrtshPlugin()


@pytest.fixture()
def confused() -> ConfusedPlugin:
    return ConfusedPlugin()


@pytest.fixture()
def sslyze() -> SSLyzePlugin:
    return SSLyzePlugin()


# ===========================================================================
# Plugin 1: SwaksPlugin
# ===========================================================================


class TestSwaksPluginMeta:
    def test_meta_name(self, swaks: SwaksPlugin) -> None:
        assert swaks.meta.name == "swaks"

    def test_meta_binary(self, swaks: SwaksPlugin) -> None:
        assert swaks.meta.tool_binary == "swaks"

    def test_meta_category(self, swaks: SwaksPlugin) -> None:
        assert swaks.meta.category == "email"

    def test_meta_produces(self, swaks: SwaksPlugin) -> None:
        assert "email_relay_results" in swaks.meta.produces

    def test_meta_timeout(self, swaks: SwaksPlugin) -> None:
        assert swaks.meta.timeout_seconds == 120

    def test_meta_depends_on_empty(self, swaks: SwaksPlugin) -> None:
        assert swaks.meta.depends_on == ()


class TestSwaksBuildCommand:
    def test_build_command_uses_target(self, swaks: SwaksPlugin, ctx: DAGContext) -> None:
        cmd = swaks.build_command("example.com", "standard", ctx, {})
        assert "test@example.com" in cmd
        assert "--quit-after RCPT" in cmd
        assert "--timeout 10" in cmd

    def test_build_command_uses_mx_from_tool_config(
        self, swaks: SwaksPlugin, ctx: DAGContext
    ) -> None:
        cmd = swaks.build_command("example.com", "standard", ctx, {"mx_server": "mx1.example.com"})
        assert "--server mx1.example.com" in cmd

    def test_build_command_fallback_to_target_as_mx(
        self, swaks: SwaksPlugin, ctx: DAGContext
    ) -> None:
        cmd = swaks.build_command("example.com", "standard", ctx, {})
        # No MX configured → server defaults to target domain
        assert "--server example.com" in cmd


class TestSwaksParseOutput:
    def test_parse_not_vulnerable_550(self, swaks: SwaksPlugin) -> None:
        raw = (
            "=== Trying mx.example.com:25...\n"
            "-> RCPT TO:<test@example.com>\n"
            "<** 550 relay not permitted"
        )
        output = swaks.parse_output(raw, "")
        result = output.parsed_data["email_relay_results"]
        assert result["open_relay"] is False
        assert result["relay_denied"] is True
        assert output.findings == []

    def test_parse_open_relay_250(self, swaks: SwaksPlugin) -> None:
        raw = "<~~ 250 2.1.5 OK"
        output = swaks.parse_output(raw, "")
        result = output.parsed_data["email_relay_results"]
        assert result["open_relay"] is True
        assert len(output.findings) == 1
        assert output.findings[0]["severity"] == "high"

    def test_parse_empty_input(self, swaks: SwaksPlugin) -> None:
        output = swaks.parse_output("", "")
        result = output.parsed_data["email_relay_results"]
        assert result["open_relay"] is False
        assert output.findings == []

    def test_parse_connection_refused(self, swaks: SwaksPlugin) -> None:
        raw = "=== Trying mx.example.com:25...\nConnection refused"
        output = swaks.parse_output(raw, "")
        result = output.parsed_data["email_relay_results"]
        assert result["open_relay"] is False
        assert result["connection_failed"] is True


# ===========================================================================
# Plugin 2: CrtshPlugin
# ===========================================================================

_CRTSH_SAMPLE = json.dumps([
    {
        "issuer_ca_id": 1,
        "issuer_name": "Let's Encrypt",
        "common_name": "example.com",
        "name_value": "example.com",
        "not_before": "2025-01-01",
        "not_after": "2025-04-01",
    }
])

_CRTSH_FUTURE_SAMPLE = json.dumps([
    {
        "issuer_ca_id": 1,
        "issuer_name": "Let's Encrypt",
        "common_name": "example.com",
        "name_value": "example.com",
        "not_before": "2026-01-01",
        "not_after": "2026-12-31",
    }
])


class TestCrtshPluginMeta:
    def test_meta_name(self, crtsh: CrtshPlugin) -> None:
        assert crtsh.meta.name == "crtsh"

    def test_meta_binary(self, crtsh: CrtshPlugin) -> None:
        assert crtsh.meta.tool_binary == "curl"

    def test_meta_category(self, crtsh: CrtshPlugin) -> None:
        assert crtsh.meta.category == "cert"

    def test_meta_produces(self, crtsh: CrtshPlugin) -> None:
        assert "certificates" in crtsh.meta.produces

    def test_meta_timeout(self, crtsh: CrtshPlugin) -> None:
        assert crtsh.meta.timeout_seconds == 120


class TestCrtshBuildCommand:
    def test_build_command_format(self, crtsh: CrtshPlugin, ctx: DAGContext) -> None:
        cmd = crtsh.build_command("example.com", "standard", ctx, {})
        assert "crt.sh" in cmd
        assert "%.example.com" in cmd
        assert "output=json" in cmd
        assert cmd.startswith("curl")

    def test_build_command_subdomains_prefix(self, crtsh: CrtshPlugin, ctx: DAGContext) -> None:
        cmd = crtsh.build_command("target.io", "standard", ctx, {})
        assert "%.target.io" in cmd


class TestCrtshParseOutput:
    def test_parse_expired_cert_generates_finding(self, crtsh: CrtshPlugin) -> None:
        output = crtsh.parse_output(_CRTSH_SAMPLE, "")
        # The date 2025-04-01 is in the past relative to today (2026-03-20)
        expired_findings = [
            f for f in output.findings if f["type"] == "expired_certificate"
        ]
        assert len(expired_findings) == 1
        assert "example.com" in expired_findings[0]["title"]

    def test_parse_populates_certificates(self, crtsh: CrtshPlugin) -> None:
        output = crtsh.parse_output(_CRTSH_SAMPLE, "")
        certs = output.parsed_data["certificates"]
        assert len(certs) == 1
        assert certs[0]["common_name"] == "example.com"
        assert certs[0]["issuer_name"] == "Let's Encrypt"

    def test_parse_no_findings_for_valid_cert(self, crtsh: CrtshPlugin) -> None:
        """A future-expiry cert from a known CA should produce no high/medium findings."""
        output = crtsh.parse_output(_CRTSH_FUTURE_SAMPLE, "")
        non_info_findings = [
            f for f in output.findings
            if f.get("severity") in ("high", "medium", "critical")
        ]
        assert non_info_findings == []

    def test_parse_empty_input(self, crtsh: CrtshPlugin) -> None:
        output = crtsh.parse_output("", "")
        assert output.parsed_data["certificates"] == []
        assert output.findings == []

    def test_parse_wildcard_cert_finding(self, crtsh: CrtshPlugin) -> None:
        wildcard_data = json.dumps([{
            "issuer_ca_id": 1,
            "issuer_name": "Let's Encrypt",
            "common_name": "*.example.com",
            "name_value": "*.example.com",
            "not_before": "2026-01-01",
            "not_after": "2026-12-31",
        }])
        output = crtsh.parse_output(wildcard_data, "")
        wildcard_findings = [f for f in output.findings if f["type"] == "wildcard_certificate"]
        assert len(wildcard_findings) == 1

    def test_parse_unexpected_ca_finding(self, crtsh: CrtshPlugin) -> None:
        unknown_ca_data = json.dumps([{
            "issuer_ca_id": 99,
            "issuer_name": "SuperPrivateInternalCA",
            "common_name": "internal.example.com",
            "name_value": "internal.example.com",
            "not_before": "2026-01-01",
            "not_after": "2026-12-31",
        }])
        output = crtsh.parse_output(unknown_ca_data, "")
        ca_findings = [f for f in output.findings if f["type"] == "unexpected_ca"]
        assert len(ca_findings) == 1


# ===========================================================================
# Plugin 3: ConfusedPlugin
# ===========================================================================

_CONFUSED_FOUND = "FOUND on npm: internal-utils\nFOUND on npm: my-private-lib"
_CONFUSED_CLEAN = "No packages found"


class TestConfusedPluginMeta:
    def test_meta_name(self, confused: ConfusedPlugin) -> None:
        assert confused.meta.name == "confused"

    def test_meta_binary(self, confused: ConfusedPlugin) -> None:
        assert confused.meta.tool_binary == "confused"

    def test_meta_category(self, confused: ConfusedPlugin) -> None:
        assert confused.meta.category == "supply_chain"

    def test_meta_produces(self, confused: ConfusedPlugin) -> None:
        assert "dependency_confusion" in confused.meta.produces

    def test_meta_timeout(self, confused: ConfusedPlugin) -> None:
        assert confused.meta.timeout_seconds == 300


class TestConfusedBuildCommand:
    def test_build_command_default_package_file(
        self, confused: ConfusedPlugin, ctx: DAGContext
    ) -> None:
        cmd = confused.build_command("example.com", "standard", ctx, {})
        assert cmd.startswith("confused -l")
        assert "package.json" in cmd

    def test_build_command_custom_package_file(
        self, confused: ConfusedPlugin, ctx: DAGContext
    ) -> None:
        cmd = confused.build_command(
            "example.com", "standard", ctx, {"package_file": "requirements.txt"}
        )
        assert "requirements.txt" in cmd


class TestConfusedParseOutput:
    def test_parse_found_packages(self, confused: ConfusedPlugin) -> None:
        output = confused.parse_output(_CONFUSED_FOUND, "")
        data = output.parsed_data["dependency_confusion"]
        assert data["total_found"] == 2
        assert "internal-utils" in data["vulnerable_packages"]
        assert "my-private-lib" in data["vulnerable_packages"]

    def test_parse_found_generates_high_findings(self, confused: ConfusedPlugin) -> None:
        output = confused.parse_output(_CONFUSED_FOUND, "")
        assert len(output.findings) == 2
        for finding in output.findings:
            assert finding["severity"] == "high"
            assert finding["type"] == "dependency_confusion"

    def test_parse_no_packages_found(self, confused: ConfusedPlugin) -> None:
        output = confused.parse_output(_CONFUSED_CLEAN, "")
        data = output.parsed_data["dependency_confusion"]
        assert data["total_found"] == 0
        assert output.findings == []

    def test_parse_empty_input(self, confused: ConfusedPlugin) -> None:
        output = confused.parse_output("", "")
        data = output.parsed_data["dependency_confusion"]
        assert data["total_found"] == 0
        assert output.findings == []


# ===========================================================================
# Plugin 4: SSLyzePlugin
# ===========================================================================

_SSLYZE_SAMPLE = json.dumps({
    "server_scan_results": [{
        "server_location": {"hostname": "example.com", "port": 443},
        "scan_result": {
            "tls_1_0_cipher_suites": {
                "accepted_cipher_suites": [{"name": "TLS_RSA_WITH_AES_128_CBC_SHA"}]
            },
            "certificate_deployments": [{
                "received_certificate_chain": [{
                    "not_valid_after": "2025-12-31T00:00:00",
                    "subject": {"common_name": "example.com"},
                    "public_key": {"algorithm": "RSA", "key_size": 2048},
                }]
            }]
        },
    }]
})


class TestSSLyzePluginMeta:
    def test_meta_name(self, sslyze: SSLyzePlugin) -> None:
        assert sslyze.meta.name == "sslyze"

    def test_meta_binary(self, sslyze: SSLyzePlugin) -> None:
        assert sslyze.meta.tool_binary == "sslyze"

    def test_meta_category(self, sslyze: SSLyzePlugin) -> None:
        assert sslyze.meta.category == "cert"

    def test_meta_depends_on_httpx(self, sslyze: SSLyzePlugin) -> None:
        # sslyze enriches from httpx HTTPS host list but can run with fallback target.
        assert "httpx" in sslyze.meta.optional_depends

    def test_meta_produces(self, sslyze: SSLyzePlugin) -> None:
        assert "tls_detailed" in sslyze.meta.produces

    def test_meta_timeout(self, sslyze: SSLyzePlugin) -> None:
        assert sslyze.meta.timeout_seconds == 600


class TestSSLyzeBuildCommand:
    def test_build_command_fallback_to_target(
        self, sslyze: SSLyzePlugin, ctx: DAGContext
    ) -> None:
        # No httpx output → fall back to target:443
        cmd = sslyze.build_command("example.com", "standard", ctx, {})
        assert "sslyze" in cmd
        assert "--json_out=-" in cmd
        assert "example.com:443" in cmd

    def test_build_command_uses_live_hosts_from_ctx(
        self, sslyze: SSLyzePlugin, ctx: DAGContext
    ) -> None:
        from vxis.core.context import PluginOutput

        ctx.set(
            "httpx",
            PluginOutput(
                plugin_name="httpx",
                parsed_data={"live_hosts": ["https://sub.example.com"]},
            ),
        )
        cmd = sslyze.build_command("example.com", "standard", ctx, {})
        assert "sub.example.com:443" in cmd

    def test_build_command_https_only(self, sslyze: SSLyzePlugin, ctx: DAGContext) -> None:
        from vxis.core.context import PluginOutput

        ctx.set(
            "httpx",
            PluginOutput(
                plugin_name="httpx",
                # HTTP hosts should be excluded
                parsed_data={"live_hosts": ["http://plain.example.com", "https://secure.example.com"]},
            ),
        )
        cmd = sslyze.build_command("example.com", "standard", ctx, {})
        assert "secure.example.com" in cmd
        # plain HTTP host must not appear (no port 443 mapping for HTTP)
        assert "plain.example.com" not in cmd


class TestSSLyzeParseOutput:
    def test_parse_tls10_generates_finding(self, sslyze: SSLyzePlugin) -> None:
        output = sslyze.parse_output(_SSLYZE_SAMPLE, "")
        weak_proto_findings = [
            f for f in output.findings if f["type"] == "weak_tls_protocol"
        ]
        assert len(weak_proto_findings) >= 1
        labels = [f["protocol"] for f in weak_proto_findings]
        assert "TLS 1.0" in labels

    def test_parse_tls_detailed_populated(self, sslyze: SSLyzePlugin) -> None:
        output = sslyze.parse_output(_SSLYZE_SAMPLE, "")
        results = output.parsed_data["tls_detailed"]
        assert len(results) == 1
        assert results[0]["hostname"] == "example.com"
        assert "TLS 1.0" in results[0]["weak_protocols"]

    def test_parse_expired_cert_finding(self, sslyze: SSLyzePlugin) -> None:
        # Cert expired 2025-12-31, today is 2026-03-20
        output = sslyze.parse_output(_SSLYZE_SAMPLE, "")
        expired = [f for f in output.findings if f["type"] == "expired_certificate"]
        assert len(expired) == 1

    def test_parse_empty_input(self, sslyze: SSLyzePlugin) -> None:
        output = sslyze.parse_output("", "")
        assert output.parsed_data["tls_detailed"] == []
        assert output.findings == []

    def test_parse_invalid_json(self, sslyze: SSLyzePlugin) -> None:
        output = sslyze.parse_output("not valid json {{", "")
        assert output.parsed_data["tls_detailed"] == []
        assert "Failed to parse sslyze JSON output" in output.errors


# ===========================================================================
# Normalizer additions
# ===========================================================================


class TestNormalizerFromCrtsh:
    def test_from_crtsh_detects_expired_cert(self) -> None:
        parsed_data = {
            "certificates": [{
                "issuer_ca_id": 1,
                "issuer_name": "Let's Encrypt",
                "common_name": "example.com",
                "name_value": "example.com",
                "not_before": "2025-01-01",
                "not_after": "2025-04-01",  # Past date; today = 2026-03-20
            }]
        }
        findings = FindingFactory.from_crtsh(parsed_data, "scan-001", "example.com")
        expired = [f for f in findings if "Expired" in f.title]
        assert len(expired) == 1
        assert expired[0].severity.value == "high"
        assert expired[0].source_plugin == "crtsh"

    def test_from_crtsh_no_finding_for_valid_cert(self) -> None:
        parsed_data = {
            "certificates": [{
                "issuer_ca_id": 1,
                "issuer_name": "DigiCert",
                "common_name": "example.com",
                "name_value": "example.com",
                "not_before": "2026-01-01",
                "not_after": "2026-12-31",  # Valid future date
            }]
        }
        findings = FindingFactory.from_crtsh(parsed_data, "scan-001", "example.com")
        expired = [f for f in findings if "Expired" in f.title]
        assert expired == []

    def test_from_crtsh_empty_certificates(self) -> None:
        findings = FindingFactory.from_crtsh({"certificates": []}, "scan-001", "example.com")
        assert findings == []

    def test_from_crtsh_wildcard_finding(self) -> None:
        parsed_data = {
            "certificates": [{
                "issuer_ca_id": 1,
                "issuer_name": "Let's Encrypt",
                "common_name": "*.example.com",
                "name_value": "*.example.com",
                "not_before": "2026-01-01",
                "not_after": "2026-12-31",
            }]
        }
        findings = FindingFactory.from_crtsh(parsed_data, "scan-002", "example.com")
        wildcard = [f for f in findings if "Wildcard" in f.title]
        assert len(wildcard) == 1
        assert wildcard[0].severity.value == "informational"


class TestNormalizerFromSslyze:
    def test_from_sslyze_detects_tls10_finding(self) -> None:
        parsed_data = {
            "server_scan_results": [{
                "server_location": {"hostname": "example.com", "port": 443},
                "scan_result": {
                    "tls_1_0_cipher_suites": {
                        "accepted_cipher_suites": [{"name": "TLS_RSA_WITH_AES_128_CBC_SHA"}]
                    },
                    "certificate_deployments": [{
                        "received_certificate_chain": [{
                            "not_valid_after": "2025-12-31T00:00:00",
                            "subject": {"common_name": "example.com"},
                            "public_key": {"algorithm": "RSA", "key_size": 2048},
                        }]
                    }]
                },
            }]
        }
        findings = FindingFactory.from_sslyze(parsed_data, "scan-003")
        tls10_findings = [
            f for f in findings
            if "TLS 1.0" in f.title or "Deprecated Protocol" in f.title
        ]
        assert len(tls10_findings) >= 1
        assert tls10_findings[0].severity.value == "medium"
        assert tls10_findings[0].source_plugin == "sslyze"

    def test_from_sslyze_empty_parsed_data(self) -> None:
        findings = FindingFactory.from_sslyze({}, "scan-004")
        assert findings == []

    def test_from_sslyze_no_weak_protocols(self) -> None:
        parsed_data = {
            "server_scan_results": [{
                "server_location": {"hostname": "example.com", "port": 443},
                "scan_result": {
                    "tls_1_0_cipher_suites": {"accepted_cipher_suites": []},
                    "certificate_deployments": [],
                },
            }]
        }
        findings = FindingFactory.from_sslyze(parsed_data, "scan-005")
        weak_proto = [f for f in findings if "Deprecated" in f.title]
        assert weak_proto == []
