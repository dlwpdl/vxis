"""Unit tests for Phase 3 FindingFactory methods:
from_subfinder, from_httpx, from_shodan, from_trivy_k8s, from_swaks,
from_actionlint, from_s3scanner, from_confused, from_winpeas.
Also tests the NORMALIZERS registry dict."""

from __future__ import annotations

import pytest

from vxis.core.normalizer import FindingFactory, NORMALIZERS
from vxis.models.finding import Severity


SCAN_ID = "scan-phase3-test"


# ---------------------------------------------------------------------------
# Sample parsed_data payloads (mirror plugin parse_output output)
# ---------------------------------------------------------------------------

SUBFINDER_PARSED: dict = {
    "subdomains": ["api.example.com", "mail.example.com", "dev.example.com"],
}

SUBFINDER_EMPTY: dict = {
    "subdomains": [],
}

HTTPX_PARSED: dict = {
    "live_hosts": [
        {
            "url": "https://api.example.com",
            "status_code": 200,
            "title": "API Gateway",
            "tech": ["nginx", "Express"],
            "cdn": True,
            "cname": [],
            "asn": {},
        }
    ],
    "live_urls": ["https://api.example.com"],
}

HTTPX_EMPTY: dict = {
    "live_hosts": [],
    "live_urls": [],
}

HTTPX_MINIMAL: dict = {
    "live_hosts": [
        {
            "url": "http://example.com",
            "status_code": 301,
            "title": "",
            "tech": [],
            "cdn": False,
            "cname": [],
            "asn": {},
        }
    ],
    "live_urls": ["http://example.com"],
}

SHODAN_PARSED: dict = {
    "shodan_results": [
        {
            "ip": "1.2.3.4",
            "port": 443,
            "org": "Example Inc",
            "os": "Linux",
            "product": "nginx",
        }
    ],
}

SHODAN_EMPTY: dict = {
    "shodan_results": [],
}

TRIVY_K8S_PARSED: dict = {
    "k8s_vulns": [
        {
            "cluster_name": "prod-cluster",
            "vulnerability_id": "CVE-2024-1234",
            "severity": "CRITICAL",
            "title": "Container escape vulnerability",
            "misconf_summary": {"successes": 10, "failures": 2},
        }
    ],
}

TRIVY_K8S_HIGH: dict = {
    "k8s_vulns": [
        {
            "cluster_name": "staging",
            "vulnerability_id": "CVE-2023-9999",
            "severity": "HIGH",
            "title": "Privilege escalation in kubelet",
            "misconf_summary": {},
        }
    ],
}

TRIVY_K8S_EMPTY: dict = {
    "k8s_vulns": [],
}

SWAKS_OPEN_RELAY: dict = {
    "email_relay_results": {
        "open_relay": True,
        "connection_failed": False,
        "relay_denied": False,
    }
}

SWAKS_NOT_VULNERABLE: dict = {
    "email_relay_results": {
        "open_relay": False,
        "connection_failed": False,
        "relay_denied": True,
    }
}

SWAKS_CONNECTION_FAILED: dict = {
    "email_relay_results": {
        "open_relay": False,
        "connection_failed": True,
        "relay_denied": False,
    }
}

ACTIONLINT_PARSED: dict = {
    "gha_lint": [
        {
            "filepath": ".github/workflows/ci.yml",
            "line": 15,
            "column": 10,
            "message": "expression injection via ${{ github.event.pull_request.title }}",
            "kind": "expression",
            "severity": "medium",
        }
    ],
}

ACTIONLINT_LOW: dict = {
    "gha_lint": [
        {
            "filepath": ".github/workflows/deploy.yml",
            "line": 5,
            "column": 3,
            "message": "unknown action 'foo/bar@v1'",
            "kind": "action",
            "severity": "low",
        }
    ],
}

ACTIONLINT_EMPTY: dict = {
    "gha_lint": [],
}

S3SCANNER_PARSED: dict = {
    "public_buckets": [
        {
            "bucket": "example-backup",
            "exists": True,
            "public_read": True,
            "public_write": False,
        }
    ],
}

S3SCANNER_WRITABLE: dict = {
    "public_buckets": [
        {
            "bucket": "example-uploads",
            "exists": True,
            "public_read": True,
            "public_write": True,
        }
    ],
}

S3SCANNER_EMPTY: dict = {
    "public_buckets": [],
}

CONFUSED_PARSED_FINDINGS: dict = {
    "findings": [
        {
            "type": "dependency_confusion",
            "severity": "high",
            "title": "Dependency Confusion: internal-utils",
            "description": (
                "The internal package 'internal-utils' was found on a public registry (npm). "
                "An attacker could upload a malicious package."
            ),
            "package_name": "internal-utils",
            "registry_info": "FOUND on npm",
            "raw_line": "FOUND on npm: internal-utils",
        }
    ],
}

CONFUSED_PARSED_PACKAGES: dict = {
    "dependency_confusion": {
        "vulnerable_packages": ["my-internal-lib", "company-core"],
        "total_found": 2,
    }
}

CONFUSED_EMPTY: dict = {
    "dependency_confusion": {
        "vulnerable_packages": [],
        "total_found": 0,
    }
}

WINPEAS_PARSED: dict = {
    "findings": [
        {
            "type": "windows_privesc_vector",
            "severity": "critical",
            "title": "Unquoted Service Path",
            "description": "WinPEAS identified a privilege escalation vector with 95% exploitability confidence: Unquoted Service Path",
            "confidence_pct": 95,
            "raw_line": "[95%] Unquoted Service Path",
        },
        {
            "type": "windows_privesc_vector",
            "severity": "high",
            "title": "Modifiable Service Binary",
            "description": "WinPEAS identified a privilege escalation vector with 70% exploitability confidence: Modifiable Service Binary",
            "confidence_pct": 70,
            "raw_line": "[70%] Modifiable Service Binary",
        },
    ]
}

WINPEAS_EMPTY: dict = {
    "findings": [],
}


# ===========================================================================
# NORMALIZERS registry
# ===========================================================================


class TestNormalizersRegistry:
    def test_registry_has_30_entries(self) -> None:
        assert len(NORMALIZERS) == 30

    def test_all_expected_plugins_present(self) -> None:
        expected = {
            "nuclei", "nmap", "testssl", "checkdmarc", "trufflehog",
            "wafw00f", "prowler", "gitleaks", "trivy", "dnstwist",
            "crtsh", "sslyze", "bloodhound", "certipy", "netexec",
            "linpeas", "semgrep", "bandit", "checkov", "kube-bench",
            "poutine", "subfinder", "httpx", "shodan", "trivy-k8s",
            "swaks", "actionlint", "s3scanner", "confused", "winpeas",
        }
        assert set(NORMALIZERS.keys()) == expected

    def test_all_values_are_callable(self) -> None:
        for name, func in NORMALIZERS.items():
            assert callable(func), f"NORMALIZERS['{name}'] is not callable"


# ===========================================================================
# from_subfinder
# ===========================================================================


class TestFromSubfinder:
    def test_returns_list(self) -> None:
        findings = FindingFactory.from_subfinder(SUBFINDER_PARSED, SCAN_ID, domain="example.com")
        assert isinstance(findings, list)
        assert len(findings) == 3

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_subfinder(SUBFINDER_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_severity_is_informational(self) -> None:
        findings = FindingFactory.from_subfinder(SUBFINDER_PARSED, SCAN_ID)
        for f in findings:
            assert f.severity == Severity.informational

    def test_finding_type_is_discovery(self) -> None:
        findings = FindingFactory.from_subfinder(SUBFINDER_PARSED, SCAN_ID)
        assert findings[0].finding_type == "discovery"

    def test_source_plugin_is_subfinder(self) -> None:
        findings = FindingFactory.from_subfinder(SUBFINDER_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "subfinder"

    def test_title_contains_subdomain(self) -> None:
        findings = FindingFactory.from_subfinder(SUBFINDER_PARSED, SCAN_ID)
        assert "api.example.com" in findings[0].title

    def test_affected_component_is_subdomain(self) -> None:
        findings = FindingFactory.from_subfinder(SUBFINDER_PARSED, SCAN_ID)
        assert findings[0].affected_component == "api.example.com"

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_subfinder(SUBFINDER_EMPTY, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_subfinder(SUBFINDER_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "recon"


# ===========================================================================
# from_httpx
# ===========================================================================


class TestFromHttpx:
    def test_returns_list(self) -> None:
        findings = FindingFactory.from_httpx(HTTPX_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_httpx(HTTPX_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_severity_is_informational(self) -> None:
        findings = FindingFactory.from_httpx(HTTPX_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.informational

    def test_finding_type_is_discovery(self) -> None:
        findings = FindingFactory.from_httpx(HTTPX_PARSED, SCAN_ID)
        assert findings[0].finding_type == "discovery"

    def test_source_plugin_is_httpx(self) -> None:
        findings = FindingFactory.from_httpx(HTTPX_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "httpx"

    def test_title_contains_url(self) -> None:
        findings = FindingFactory.from_httpx(HTTPX_PARSED, SCAN_ID)
        assert "https://api.example.com" in findings[0].title

    def test_description_contains_tech(self) -> None:
        findings = FindingFactory.from_httpx(HTTPX_PARSED, SCAN_ID)
        assert "nginx" in findings[0].description

    def test_description_contains_cdn(self) -> None:
        findings = FindingFactory.from_httpx(HTTPX_PARSED, SCAN_ID)
        assert "CDN" in findings[0].description

    def test_minimal_host_entry(self) -> None:
        findings = FindingFactory.from_httpx(HTTPX_MINIMAL, SCAN_ID)
        assert len(findings) == 1
        assert findings[0].target == "http://example.com"

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_httpx(HTTPX_EMPTY, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_httpx(HTTPX_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "recon"


# ===========================================================================
# from_shodan
# ===========================================================================


class TestFromShodan:
    def test_returns_list(self) -> None:
        findings = FindingFactory.from_shodan(SHODAN_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_shodan(SHODAN_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_severity_is_informational(self) -> None:
        findings = FindingFactory.from_shodan(SHODAN_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.informational

    def test_finding_type_is_discovery(self) -> None:
        findings = FindingFactory.from_shodan(SHODAN_PARSED, SCAN_ID)
        assert findings[0].finding_type == "discovery"

    def test_source_plugin_is_shodan(self) -> None:
        findings = FindingFactory.from_shodan(SHODAN_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "shodan"

    def test_title_contains_ip_and_port(self) -> None:
        findings = FindingFactory.from_shodan(SHODAN_PARSED, SCAN_ID)
        assert "1.2.3.4" in findings[0].title
        assert "443" in findings[0].title

    def test_port_is_set(self) -> None:
        findings = FindingFactory.from_shodan(SHODAN_PARSED, SCAN_ID)
        assert findings[0].port == 443

    def test_description_contains_product(self) -> None:
        findings = FindingFactory.from_shodan(SHODAN_PARSED, SCAN_ID)
        assert "nginx" in findings[0].description

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_shodan(SHODAN_EMPTY, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_shodan(SHODAN_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "osint"


# ===========================================================================
# from_trivy_k8s
# ===========================================================================


class TestFromTrivyK8s:
    def test_returns_list(self) -> None:
        findings = FindingFactory.from_trivy_k8s(TRIVY_K8S_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_trivy_k8s(TRIVY_K8S_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_critical_severity_mapping(self) -> None:
        findings = FindingFactory.from_trivy_k8s(TRIVY_K8S_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.critical

    def test_high_severity_mapping(self) -> None:
        findings = FindingFactory.from_trivy_k8s(TRIVY_K8S_HIGH, SCAN_ID)
        assert findings[0].severity == Severity.high

    def test_cve_extracted(self) -> None:
        findings = FindingFactory.from_trivy_k8s(TRIVY_K8S_PARSED, SCAN_ID)
        assert "CVE-2024-1234" in findings[0].cve_ids

    def test_target_is_cluster_name(self) -> None:
        findings = FindingFactory.from_trivy_k8s(TRIVY_K8S_PARSED, SCAN_ID)
        assert findings[0].target == "prod-cluster"

    def test_source_plugin_is_trivy_k8s(self) -> None:
        findings = FindingFactory.from_trivy_k8s(TRIVY_K8S_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "trivy-k8s"

    def test_finding_type_is_vulnerability(self) -> None:
        findings = FindingFactory.from_trivy_k8s(TRIVY_K8S_PARSED, SCAN_ID)
        assert findings[0].finding_type == "vulnerability"

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_trivy_k8s(TRIVY_K8S_EMPTY, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_trivy_k8s(TRIVY_K8S_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "k8s_scan"


# ===========================================================================
# from_swaks
# ===========================================================================


class TestFromSwaks:
    def test_open_relay_returns_high_severity(self) -> None:
        findings = FindingFactory.from_swaks(SWAKS_OPEN_RELAY, SCAN_ID, target="example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.high

    def test_open_relay_title(self) -> None:
        findings = FindingFactory.from_swaks(SWAKS_OPEN_RELAY, SCAN_ID, target="example.com")
        assert "Open Relay" in findings[0].title

    def test_not_vulnerable_returns_informational(self) -> None:
        findings = FindingFactory.from_swaks(SWAKS_NOT_VULNERABLE, SCAN_ID, target="example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.informational

    def test_connection_failed_returns_empty(self) -> None:
        findings = FindingFactory.from_swaks(SWAKS_CONNECTION_FAILED, SCAN_ID, target="example.com")
        assert len(findings) == 0

    def test_source_plugin_is_swaks(self) -> None:
        findings = FindingFactory.from_swaks(SWAKS_OPEN_RELAY, SCAN_ID, target="example.com")
        assert findings[0].source_plugin == "swaks"

    def test_finding_type_is_misconfiguration_for_open_relay(self) -> None:
        findings = FindingFactory.from_swaks(SWAKS_OPEN_RELAY, SCAN_ID, target="example.com")
        assert findings[0].finding_type == "misconfiguration"

    def test_port_is_25(self) -> None:
        findings = FindingFactory.from_swaks(SWAKS_OPEN_RELAY, SCAN_ID, target="example.com")
        assert findings[0].port == 25

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_swaks(SWAKS_OPEN_RELAY, SCAN_ID, target="example.com")
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "email_test"


# ===========================================================================
# from_actionlint
# ===========================================================================


class TestFromActionlint:
    def test_returns_list(self) -> None:
        findings = FindingFactory.from_actionlint(ACTIONLINT_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_actionlint(ACTIONLINT_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_security_relevant_kind_is_medium(self) -> None:
        findings = FindingFactory.from_actionlint(ACTIONLINT_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.medium

    def test_non_security_kind_is_low(self) -> None:
        findings = FindingFactory.from_actionlint(ACTIONLINT_LOW, SCAN_ID)
        assert findings[0].severity == Severity.low

    def test_title_contains_kind(self) -> None:
        findings = FindingFactory.from_actionlint(ACTIONLINT_PARSED, SCAN_ID)
        assert "expression" in findings[0].title

    def test_affected_component_contains_filepath_and_line(self) -> None:
        findings = FindingFactory.from_actionlint(ACTIONLINT_PARSED, SCAN_ID)
        assert ".github/workflows/ci.yml:15" == findings[0].affected_component

    def test_finding_type_is_misconfiguration(self) -> None:
        findings = FindingFactory.from_actionlint(ACTIONLINT_PARSED, SCAN_ID)
        assert findings[0].finding_type == "misconfiguration"

    def test_source_plugin_is_actionlint(self) -> None:
        findings = FindingFactory.from_actionlint(ACTIONLINT_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "actionlint"

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_actionlint(ACTIONLINT_EMPTY, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_actionlint(ACTIONLINT_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "cicd_lint"


# ===========================================================================
# from_s3scanner
# ===========================================================================


class TestFromS3Scanner:
    def test_returns_list(self) -> None:
        findings = FindingFactory.from_s3scanner(S3SCANNER_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_s3scanner(S3SCANNER_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_readable_bucket_is_high_severity(self) -> None:
        findings = FindingFactory.from_s3scanner(S3SCANNER_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.high

    def test_writable_bucket_is_critical_severity(self) -> None:
        findings = FindingFactory.from_s3scanner(S3SCANNER_WRITABLE, SCAN_ID)
        assert findings[0].severity == Severity.critical

    def test_title_contains_bucket_name(self) -> None:
        findings = FindingFactory.from_s3scanner(S3SCANNER_PARSED, SCAN_ID)
        assert "example-backup" in findings[0].title

    def test_finding_type_is_misconfiguration(self) -> None:
        findings = FindingFactory.from_s3scanner(S3SCANNER_PARSED, SCAN_ID)
        assert findings[0].finding_type == "misconfiguration"

    def test_source_plugin_is_s3scanner(self) -> None:
        findings = FindingFactory.from_s3scanner(S3SCANNER_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "s3scanner"

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_s3scanner(S3SCANNER_EMPTY, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_s3scanner(S3SCANNER_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "cloud_scan"

    def test_writable_title_says_writable(self) -> None:
        findings = FindingFactory.from_s3scanner(S3SCANNER_WRITABLE, SCAN_ID)
        assert "Writable" in findings[0].title


# ===========================================================================
# from_confused
# ===========================================================================


class TestFromConfused:
    def test_returns_list_from_findings_key(self) -> None:
        findings = FindingFactory.from_confused(CONFUSED_PARSED_FINDINGS, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_returns_list_from_packages_key(self) -> None:
        findings = FindingFactory.from_confused(CONFUSED_PARSED_PACKAGES, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 2

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_confused(CONFUSED_PARSED_FINDINGS, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_severity_is_high(self) -> None:
        findings = FindingFactory.from_confused(CONFUSED_PARSED_FINDINGS, SCAN_ID)
        assert findings[0].severity == Severity.high

    def test_title_contains_package_name(self) -> None:
        findings = FindingFactory.from_confused(CONFUSED_PARSED_FINDINGS, SCAN_ID)
        assert "internal-utils" in findings[0].title

    def test_finding_type_is_vulnerability(self) -> None:
        findings = FindingFactory.from_confused(CONFUSED_PARSED_FINDINGS, SCAN_ID)
        assert findings[0].finding_type == "vulnerability"

    def test_source_plugin_is_confused(self) -> None:
        findings = FindingFactory.from_confused(CONFUSED_PARSED_FINDINGS, SCAN_ID)
        assert findings[0].source_plugin == "confused"

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_confused(CONFUSED_EMPTY, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_confused(CONFUSED_PARSED_FINDINGS, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "supply_chain"

    def test_packages_fallback_creates_correct_targets(self) -> None:
        findings = FindingFactory.from_confused(CONFUSED_PARSED_PACKAGES, SCAN_ID)
        targets = {f.target for f in findings}
        assert "my-internal-lib" in targets
        assert "company-core" in targets


# ===========================================================================
# from_winpeas
# ===========================================================================


class TestFromWinpeas:
    def test_returns_list(self) -> None:
        findings = FindingFactory.from_winpeas(WINPEAS_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 2

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_winpeas(WINPEAS_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_95pct_maps_to_critical(self) -> None:
        findings = FindingFactory.from_winpeas(WINPEAS_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.critical

    def test_70pct_maps_to_high(self) -> None:
        findings = FindingFactory.from_winpeas(WINPEAS_PARSED, SCAN_ID)
        assert findings[1].severity == Severity.high

    def test_target_is_localhost(self) -> None:
        findings = FindingFactory.from_winpeas(WINPEAS_PARSED, SCAN_ID)
        assert findings[0].target == "localhost"

    def test_affected_component_is_windows_os(self) -> None:
        findings = FindingFactory.from_winpeas(WINPEAS_PARSED, SCAN_ID)
        assert findings[0].affected_component == "Windows OS"

    def test_finding_type_is_vulnerability(self) -> None:
        findings = FindingFactory.from_winpeas(WINPEAS_PARSED, SCAN_ID)
        assert findings[0].finding_type == "vulnerability"

    def test_source_plugin_is_winpeas(self) -> None:
        findings = FindingFactory.from_winpeas(WINPEAS_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "winpeas"

    def test_title_contains_finding_title(self) -> None:
        findings = FindingFactory.from_winpeas(WINPEAS_PARSED, SCAN_ID)
        assert "Unquoted Service Path" in findings[0].title

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_winpeas(WINPEAS_EMPTY, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_winpeas(WINPEAS_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "privesc_scan"
