"""Unit tests for Phase 1 FindingFactory methods: from_prowler, from_gitleaks,
from_trivy, and from_dnstwist."""

from __future__ import annotations

from vxis.core.normalizer import FindingFactory
from vxis.models.finding import Severity


SCAN_ID = "scan-phase1-test"


# ---------------------------------------------------------------------------
# Sample parsed_data payloads (mirrors plugin parse_output output)
# ---------------------------------------------------------------------------

PROWLER_PARSED: dict = {
    "cloud_findings": [
        {
            "check_id": "iam_root_mfa",
            "status": "FAIL",
            "severity": "critical",
            "service_name": "IAM",
            "description": "Root MFA not enabled",
            "risk": "High",
            "remediation": "Enable MFA",
            "resource_arn": "arn:aws:iam::root",
        }
    ]
}

GITLEAKS_PARSED: dict = {
    "code_secrets": [
        {
            "rule_id": "aws-access-key",
            "description": "AWS Access Key",
            "file": "config.yml",
            "start_line": 10,
            "commit": "abc123",
            # Already masked by GitleaksPlugin; testing that FindingFactory
            # handles the masked form correctly.
            "secret": "AKIA**************PLE",
        }
    ]
}

GITLEAKS_UNMASKED_PARSED: dict = {
    "code_secrets": [
        {
            "rule_id": "aws-access-key",
            "description": "AWS Access Key",
            "file": "config.yml",
            "start_line": 10,
            "commit": "abc123",
            # Raw (un-masked) value — normalizer must mask it.
            "secret": "AKIAIOSFODNN7EXAMPLE",
        }
    ]
}

TRIVY_PARSED: dict = {
    "dependency_vulns": [
        {
            "vulnerability_id": "CVE-2021-44228",
            "pkg_name": "log4j",
            "installed_version": "2.14.0",
            "fixed_version": "2.17.0",
            "severity": "CRITICAL",
            "title": "Log4Shell",
            "description": "Remote code execution via JNDI lookup.",
        }
    ]
}

DNSTWIST_PARSED: dict = {
    "lookalike_domains": [
        {
            "fuzzer": "homoglyph",
            "domain": "examp1e.com",
            "dns_a": ["93.184.216.34"],
            "dns_mx": ["mail.examp1e.com"],
        }
    ]
}


# ===========================================================================
# from_prowler
# ===========================================================================

class TestFromProwler:
    def test_creates_finding_for_fail(self) -> None:
        findings = FindingFactory.from_prowler(PROWLER_PARSED, SCAN_ID)
        assert len(findings) == 1

    def test_critical_severity_for_root_mfa(self) -> None:
        findings = FindingFactory.from_prowler(PROWLER_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.critical

    def test_source_plugin_is_prowler(self) -> None:
        findings = FindingFactory.from_prowler(PROWLER_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "prowler"

    def test_finding_type_is_misconfiguration(self) -> None:
        findings = FindingFactory.from_prowler(PROWLER_PARSED, SCAN_ID)
        assert findings[0].finding_type == "misconfiguration"

    def test_remediation_is_populated(self) -> None:
        findings = FindingFactory.from_prowler(PROWLER_PARSED, SCAN_ID)
        assert findings[0].remediation == "Enable MFA"

    def test_scan_id_attached(self) -> None:
        findings = FindingFactory.from_prowler(PROWLER_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_empty_parsed_data_returns_empty(self) -> None:
        findings = FindingFactory.from_prowler({"cloud_findings": []}, SCAN_ID)
        assert findings == []

    def test_severity_mapping_high(self) -> None:
        data = {
            "cloud_findings": [
                {
                    "check_id": "s3_bucket_public_access",
                    "status": "FAIL",
                    "severity": "high",
                    "service_name": "S3",
                    "description": "S3 bucket public",
                    "risk": "Data exposure",
                    "remediation": "Block public access",
                    "resource_arn": "arn:aws:s3:::my-bucket",
                }
            ]
        }
        findings = FindingFactory.from_prowler(data, SCAN_ID)
        assert findings[0].severity == Severity.high


# ===========================================================================
# from_gitleaks
# ===========================================================================

class TestFromGitleaks:
    def test_creates_finding(self) -> None:
        findings = FindingFactory.from_gitleaks(GITLEAKS_PARSED, SCAN_ID)
        assert len(findings) == 1

    def test_aws_key_is_critical(self) -> None:
        findings = FindingFactory.from_gitleaks(GITLEAKS_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.critical

    def test_source_plugin_is_gitleaks(self) -> None:
        findings = FindingFactory.from_gitleaks(GITLEAKS_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "gitleaks"

    def test_finding_type_is_secret(self) -> None:
        findings = FindingFactory.from_gitleaks(GITLEAKS_PARSED, SCAN_ID)
        assert findings[0].finding_type == "secret"

    def test_masked_secret_in_description(self) -> None:
        # The unmasked payload should have its secret masked by the normalizer.
        findings = FindingFactory.from_gitleaks(GITLEAKS_UNMASKED_PARSED, SCAN_ID)
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].description
        assert "*" in findings[0].description

    def test_already_masked_secret_preserved(self) -> None:
        findings = FindingFactory.from_gitleaks(GITLEAKS_PARSED, SCAN_ID)
        # The pre-masked value has asterisks and should appear in description.
        assert "*" in findings[0].description

    def test_empty_parsed_data_returns_empty(self) -> None:
        findings = FindingFactory.from_gitleaks({"code_secrets": []}, SCAN_ID)
        assert findings == []

    def test_non_cloud_rule_is_high(self) -> None:
        data = {
            "code_secrets": [
                {
                    "rule_id": "generic-password",
                    "description": "Generic password",
                    "file": "app.py",
                    "start_line": 5,
                    "commit": "def456",
                    "secret": "my-secret-pass",
                }
            ]
        }
        findings = FindingFactory.from_gitleaks(data, SCAN_ID)
        assert findings[0].severity == Severity.high


# ===========================================================================
# from_trivy
# ===========================================================================

class TestFromTrivy:
    def test_creates_finding(self) -> None:
        findings = FindingFactory.from_trivy(TRIVY_PARSED, SCAN_ID)
        assert len(findings) == 1

    def test_cve_id_extracted(self) -> None:
        findings = FindingFactory.from_trivy(TRIVY_PARSED, SCAN_ID)
        assert "CVE-2021-44228" in findings[0].cve_ids

    def test_critical_severity_mapped(self) -> None:
        findings = FindingFactory.from_trivy(TRIVY_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.critical

    def test_source_plugin_is_trivy(self) -> None:
        findings = FindingFactory.from_trivy(TRIVY_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "trivy"

    def test_finding_type_is_vulnerability(self) -> None:
        findings = FindingFactory.from_trivy(TRIVY_PARSED, SCAN_ID)
        assert findings[0].finding_type == "vulnerability"

    def test_affected_component_includes_version(self) -> None:
        findings = FindingFactory.from_trivy(TRIVY_PARSED, SCAN_ID)
        assert "log4j" in findings[0].affected_component
        assert "2.14.0" in findings[0].affected_component

    def test_scan_id_attached(self) -> None:
        findings = FindingFactory.from_trivy(TRIVY_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_empty_parsed_data_returns_empty(self) -> None:
        findings = FindingFactory.from_trivy({"dependency_vulns": []}, SCAN_ID)
        assert findings == []

    def test_high_severity_mapped(self) -> None:
        data = {
            "dependency_vulns": [
                {
                    "vulnerability_id": "CVE-2022-12345",
                    "pkg_name": "requests",
                    "installed_version": "2.25.0",
                    "fixed_version": "2.27.0",
                    "severity": "HIGH",
                    "title": "SSRF in requests",
                    "description": "SSRF vulnerability.",
                }
            ]
        }
        findings = FindingFactory.from_trivy(data, SCAN_ID)
        assert findings[0].severity == Severity.high


# ===========================================================================
# from_dnstwist
# ===========================================================================

class TestFromDnstwist:
    def test_creates_finding(self) -> None:
        findings = FindingFactory.from_dnstwist(DNSTWIST_PARSED, SCAN_ID)
        assert len(findings) == 1

    def test_severity_is_medium(self) -> None:
        findings = FindingFactory.from_dnstwist(DNSTWIST_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.medium

    def test_source_plugin_is_dnstwist(self) -> None:
        findings = FindingFactory.from_dnstwist(DNSTWIST_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "dnstwist"

    def test_target_is_lookalike_domain(self) -> None:
        findings = FindingFactory.from_dnstwist(DNSTWIST_PARSED, SCAN_ID)
        assert findings[0].target == "examp1e.com"

    def test_finding_type_is_exposure(self) -> None:
        findings = FindingFactory.from_dnstwist(DNSTWIST_PARSED, SCAN_ID)
        assert findings[0].finding_type == "exposure"

    def test_title_contains_domain(self) -> None:
        findings = FindingFactory.from_dnstwist(DNSTWIST_PARSED, SCAN_ID)
        assert "examp1e.com" in findings[0].title

    def test_scan_id_attached(self) -> None:
        findings = FindingFactory.from_dnstwist(DNSTWIST_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_empty_parsed_data_returns_empty(self) -> None:
        findings = FindingFactory.from_dnstwist({"lookalike_domains": []}, SCAN_ID)
        assert findings == []

    def test_fuzzer_in_source_tool_ref(self) -> None:
        findings = FindingFactory.from_dnstwist(DNSTWIST_PARSED, SCAN_ID)
        assert findings[0].source_tool_ref == "homoglyph"
