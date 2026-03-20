"""Unit tests for the FindingFactory and FindingDeduplicator."""

from __future__ import annotations

import pytest

from vxis.core.normalizer import FindingDeduplicator, FindingFactory
from vxis.models.finding import Finding, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_finding(**overrides) -> Finding:
    defaults = dict(
        id="finding-001",
        scan_id="scan-001",
        title="Test Finding",
        description="A test finding.",
        severity=Severity.medium,
        target="192.168.1.1",
        finding_type="vulnerability",
        source_plugin="nuclei",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# FindingFactory — nuclei
# ---------------------------------------------------------------------------


class TestFromNuclei:
    def test_creates_finding_with_correct_severity(self):
        parsed = {
            "results": [
                {
                    "template-id": "cve-2021-44228",
                    "info": {
                        "name": "Log4Shell",
                        "description": "Remote code execution via Log4j.",
                        "severity": "critical",
                        "tags": ["cve", "rce"],
                    },
                    "host": "192.168.1.10",
                    "matched-at": "https://192.168.1.10:443/",
                }
            ]
        }
        findings = FindingFactory.from_nuclei(parsed, scan_id="scan-001")

        assert len(findings) == 1
        assert findings[0].severity == Severity.critical
        assert findings[0].source_plugin == "nuclei"
        assert findings[0].scan_id == "scan-001"

    def test_extracts_cve_id_from_classification(self):
        parsed = {
            "results": [
                {
                    "template-id": "cve-2021-44228",
                    "info": {
                        "name": "Log4Shell",
                        "description": "Remote code execution.",
                        "severity": "critical",
                        "classification": {
                            "cve-id": ["CVE-2021-44228"],
                        },
                    },
                    "host": "10.0.0.1",
                    "matched-at": "http://10.0.0.1/",
                }
            ]
        }
        findings = FindingFactory.from_nuclei(parsed, scan_id="scan-001")

        assert len(findings) == 1
        assert "CVE-2021-44228" in findings[0].cve_ids

    def test_extracts_cve_id_from_tags(self):
        parsed = {
            "results": [
                {
                    "template-id": "cve-2022-22965",
                    "info": {
                        "name": "Spring4Shell",
                        "description": "RCE in Spring Framework.",
                        "severity": "high",
                        "tags": ["CVE-2022-22965", "rce", "spring"],
                    },
                    "host": "10.0.0.2",
                    "matched-at": "http://10.0.0.2/",
                }
            ]
        }
        findings = FindingFactory.from_nuclei(parsed, scan_id="scan-001")

        assert "CVE-2022-22965" in findings[0].cve_ids

    def test_creates_evidence_from_request_response(self):
        parsed = {
            "results": [
                {
                    "template-id": "test-template",
                    "info": {"name": "Test", "description": "Test", "severity": "medium"},
                    "host": "10.0.0.1",
                    "matched-at": "http://10.0.0.1/",
                    "request": "GET / HTTP/1.1\nHost: 10.0.0.1",
                    "response": "HTTP/1.1 200 OK\nContent-Type: text/html",
                }
            ]
        }
        findings = FindingFactory.from_nuclei(parsed, scan_id="scan-001")

        evidence_types = [e.evidence_type for e in findings[0].evidence]
        assert "http_request" in evidence_types
        assert "http_response" in evidence_types

    def test_severity_mapping_all_levels(self):
        severities = [
            ("critical", Severity.critical),
            ("high", Severity.high),
            ("medium", Severity.medium),
            ("low", Severity.low),
            ("info", Severity.informational),
        ]
        for severity_str, expected in severities:
            parsed = {
                "results": [{
                    "template-id": "test",
                    "info": {"name": "T", "description": "D", "severity": severity_str},
                    "host": "1.2.3.4",
                    "matched-at": "http://1.2.3.4/",
                }]
            }
            findings = FindingFactory.from_nuclei(parsed, scan_id="s1")
            assert findings[0].severity == expected, f"Failed for {severity_str}"

    def test_handles_empty_results(self):
        findings = FindingFactory.from_nuclei({"results": []}, scan_id="scan-001")
        assert findings == []

    def test_target_is_host_field(self):
        parsed = {
            "results": [{
                "template-id": "t1",
                "info": {"name": "N", "description": "D", "severity": "low"},
                "host": "example.com",
                "matched-at": "https://example.com/",
            }]
        }
        findings = FindingFactory.from_nuclei(parsed, scan_id="s1")
        assert findings[0].target == "example.com"


# ---------------------------------------------------------------------------
# FindingFactory — nmap
# ---------------------------------------------------------------------------


class TestFromNmap:
    def test_creates_informational_findings_for_open_ports(self):
        parsed = {
            "hosts": [
                {
                    "address": "192.168.1.1",
                    "ports": [
                        {
                            "port": 80,
                            "state": "open",
                            "protocol": "tcp",
                            "service": {"name": "http"},
                        },
                        {
                            "port": 443,
                            "state": "open",
                            "protocol": "tcp",
                            "service": {"name": "https"},
                        },
                    ],
                }
            ]
        }
        findings = FindingFactory.from_nmap(parsed, scan_id="scan-001")

        assert len(findings) == 2
        for f in findings:
            assert f.severity == Severity.informational
            assert f.source_plugin == "nmap"
            assert f.finding_type == "exposure"

    def test_skips_closed_and_filtered_ports(self):
        parsed = {
            "hosts": [
                {
                    "address": "10.0.0.1",
                    "ports": [
                        {"port": 22, "state": "open", "protocol": "tcp", "service": {"name": "ssh"}},
                        {"port": 8080, "state": "closed", "protocol": "tcp", "service": {}},
                        {"port": 9090, "state": "filtered", "protocol": "tcp", "service": {}},
                    ],
                }
            ]
        }
        findings = FindingFactory.from_nmap(parsed, scan_id="s1")
        assert len(findings) == 1
        assert findings[0].port == 22

    def test_port_number_is_correct(self):
        parsed = {
            "hosts": [{
                "address": "10.0.0.1",
                "ports": [{"port": 3306, "state": "open", "protocol": "tcp", "service": {"name": "mysql"}}],
            }]
        }
        findings = FindingFactory.from_nmap(parsed, scan_id="s1")
        assert findings[0].port == 3306

    def test_uses_hostname_when_available(self):
        parsed = {
            "hosts": [{
                "address": "10.0.0.1",
                "hostname": "db.internal",
                "ports": [{"port": 5432, "state": "open", "protocol": "tcp", "service": {"name": "postgresql"}}],
            }]
        }
        findings = FindingFactory.from_nmap(parsed, scan_id="s1")
        assert findings[0].target == "db.internal"

    def test_evidence_includes_port_scan_type(self):
        parsed = {
            "hosts": [{
                "address": "1.2.3.4",
                "ports": [{"port": 22, "state": "open", "protocol": "tcp", "service": {"name": "ssh"}}],
            }]
        }
        findings = FindingFactory.from_nmap(parsed, scan_id="s1")
        assert len(findings[0].evidence) == 1
        assert findings[0].evidence[0].evidence_type == "port_scan"

    def test_handles_no_hosts(self):
        findings = FindingFactory.from_nmap({"hosts": []}, scan_id="s1")
        assert findings == []


# ---------------------------------------------------------------------------
# FindingFactory — checkdmarc
# ---------------------------------------------------------------------------


class TestFromCheckdmarc:
    def test_flags_missing_dmarc_as_critical(self):
        parsed = {
            "dmarc": {"valid": False, "record": ""},
            "spf": {"valid": True, "record": "v=spf1 -all"},
        }
        findings = FindingFactory.from_checkdmarc(parsed, scan_id="s1", domain="example.com")

        dmarc_findings = [f for f in findings if "DMARC" in f.title and "Missing" in f.title]
        assert len(dmarc_findings) >= 1
        assert dmarc_findings[0].severity == Severity.critical

    def test_flags_p_none_as_high(self):
        parsed = {
            "dmarc": {
                "valid": True,
                "record": "v=DMARC1; p=none;",
                "tags": {"p": {"value": "none"}},
            },
            "spf": {"valid": True, "record": "v=spf1 -all"},
        }
        findings = FindingFactory.from_checkdmarc(parsed, scan_id="s1", domain="example.com")

        p_none_findings = [f for f in findings if "none" in f.title.lower() and "DMARC" in f.affected_component]
        assert len(p_none_findings) >= 1
        assert p_none_findings[0].severity == Severity.high

    def test_flags_spf_softfail_as_medium(self):
        parsed = {
            "dmarc": {"valid": True, "record": "v=DMARC1; p=reject;", "tags": {"p": {"value": "reject"}}},
            "spf": {"valid": True, "record": "v=spf1 include:_spf.google.com ~all"},
        }
        findings = FindingFactory.from_checkdmarc(parsed, scan_id="s1", domain="example.com")

        spf_soft = [f for f in findings if "Softfail" in f.title or "~all" in f.description]
        assert len(spf_soft) >= 1
        assert spf_soft[0].severity == Severity.medium

    def test_flags_missing_spf_as_high(self):
        parsed = {
            "dmarc": {"valid": True, "record": "v=DMARC1; p=reject;", "tags": {"p": {"value": "reject"}}},
            "spf": {"valid": False, "record": ""},
        }
        findings = FindingFactory.from_checkdmarc(parsed, scan_id="s1", domain="example.com")

        missing_spf = [f for f in findings if "Missing SPF" in f.title]
        assert len(missing_spf) >= 1
        assert missing_spf[0].severity == Severity.high

    def test_flags_spf_passall_as_critical(self):
        parsed = {
            "dmarc": {"valid": True, "record": "v=DMARC1; p=reject;", "tags": {"p": {"value": "reject"}}},
            "spf": {"valid": True, "record": "v=spf1 +all"},
        }
        findings = FindingFactory.from_checkdmarc(parsed, scan_id="s1", domain="example.com")

        passall = [f for f in findings if "+all" in f.title or "+all" in f.description]
        assert len(passall) >= 1
        assert passall[0].severity == Severity.critical

    def test_no_findings_for_valid_config(self):
        parsed = {
            "dmarc": {
                "valid": True,
                "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
                "tags": {"p": {"value": "reject"}},
            },
            "spf": {
                "valid": True,
                "record": "v=spf1 include:_spf.google.com -all",
            },
        }
        findings = FindingFactory.from_checkdmarc(parsed, scan_id="s1", domain="example.com")
        assert len(findings) == 0

    def test_domain_appears_in_target(self):
        parsed = {
            "dmarc": {"valid": False, "record": ""},
            "spf": {"valid": True, "record": "v=spf1 -all"},
        }
        findings = FindingFactory.from_checkdmarc(parsed, scan_id="s1", domain="mycompany.com")
        assert all(f.target == "mycompany.com" for f in findings)


# ---------------------------------------------------------------------------
# FindingFactory — trufflehog
# ---------------------------------------------------------------------------


class TestFromTrufflehog:
    def _make_result(self, detector: str, verified: bool, raw: str, **extra) -> dict:
        result: dict = {
            "DetectorName": detector,
            "Verified": verified,
            "Raw": raw,
            "SourceMetadata": {"Data": {}},
        }
        result.update(extra)
        return result

    def test_masks_secret_in_evidence(self):
        raw_secret = "AKIAIOSFODNN7EXAMPLE"  # 20 chars
        parsed = {"results": [self._make_result("AWSKeyID", False, raw_secret)]}
        findings = FindingFactory.from_trufflehog(parsed, scan_id="s1")

        assert len(findings) == 1
        evidence_content = findings[0].evidence[0].content
        # Should NOT contain the full raw secret
        assert raw_secret not in evidence_content
        # Should contain masked version with asterisks
        assert "****" in evidence_content

    def test_masked_secret_not_in_description(self):
        raw_secret = "super_secret_api_key_value_1234"
        parsed = {"results": [self._make_result("GenericAPIKey", False, raw_secret)]}
        findings = FindingFactory.from_trufflehog(parsed, scan_id="s1")

        assert raw_secret not in findings[0].description

    def test_verified_secret_is_critical(self):
        parsed = {"results": [self._make_result("AWSKeyID", True, "AKIAIOSFODNN7EXAMPLE")]}
        findings = FindingFactory.from_trufflehog(parsed, scan_id="s1")

        assert findings[0].severity == Severity.critical

    def test_cloud_provider_key_unverified_is_high(self):
        for detector in ["AWSAccessKey", "GCPServiceAccount", "AzureStorageKey", "GitHubToken"]:
            parsed = {"results": [self._make_result(detector, False, "a" * 20)]}
            findings = FindingFactory.from_trufflehog(parsed, scan_id="s1")
            assert findings[0].severity == Severity.high, f"Expected high for {detector}"

    def test_generic_unverified_secret_is_medium(self):
        parsed = {"results": [self._make_result("GenericAPIKey", False, "x" * 20)]}
        findings = FindingFactory.from_trufflehog(parsed, scan_id="s1")
        assert findings[0].severity == Severity.medium

    def test_finding_type_is_secret(self):
        parsed = {"results": [self._make_result("PrivateKey", True, "a" * 20)]}
        findings = FindingFactory.from_trufflehog(parsed, scan_id="s1")
        assert findings[0].finding_type == "secret"

    def test_handles_empty_results(self):
        findings = FindingFactory.from_trufflehog({"results": []}, scan_id="s1")
        assert findings == []


# ---------------------------------------------------------------------------
# FindingDeduplicator
# ---------------------------------------------------------------------------


class TestFindingDeduplicator:
    def _make_finding(self, target: str, finding_type: str, port: int | None = None, **kwargs) -> Finding:
        return make_finding(
            target=target,
            finding_type=finding_type,
            port=port,
            affected_component=kwargs.pop("affected_component", ""),
            **kwargs,
        )

    def test_deduplicate_merges_findings_with_same_dedup_hash(self):
        """Two findings with identical hash fields should be merged into one."""
        f1 = self._make_finding(
            target="192.168.1.1",
            finding_type="sqli",
            port=80,
            protocol="tcp",
            affected_component="login",
            id="f1",
        )
        f2 = self._make_finding(
            target="192.168.1.1",
            finding_type="sqli",
            port=80,
            protocol="tcp",
            affected_component="login",
            id="f2",
            source_plugin="manual",
        )
        # Verify they share a dedup_hash
        assert f1.dedup_hash == f2.dedup_hash

        deduplicator = FindingDeduplicator()
        result = deduplicator.deduplicate([f1, f2])

        assert len(result) == 1

    def test_deduplicate_keeps_distinct_findings_separate(self):
        """Findings with different targets must not be merged."""
        f1 = self._make_finding(target="192.168.1.1", finding_type="sqli", port=80, protocol="tcp", id="f1")
        f2 = self._make_finding(target="192.168.1.2", finding_type="sqli", port=80, protocol="tcp", id="f2")

        assert f1.dedup_hash != f2.dedup_hash

        deduplicator = FindingDeduplicator()
        result = deduplicator.deduplicate([f1, f2])

        assert len(result) == 2

    def test_deduplicate_merges_evidence_from_both(self):
        """Merged finding should contain evidence from all merged findings."""
        from vxis.models.finding import Evidence

        f1 = self._make_finding(target="10.0.0.1", finding_type="xss", port=443, protocol="tcp", id="f1")
        f1.evidence = [Evidence(evidence_type="http_request", title="Req1", content="GET /")]

        f2 = self._make_finding(target="10.0.0.1", finding_type="xss", port=443, protocol="tcp", id="f2")
        f2.evidence = [Evidence(evidence_type="http_response", title="Resp1", content="200 OK")]

        deduplicator = FindingDeduplicator()
        result = deduplicator.deduplicate([f1, f2])

        assert len(result) == 1
        assert len(result[0].evidence) == 2

    def test_deduplicate_keeps_higher_severity(self):
        """After merging, the higher severity should be retained."""
        f1 = self._make_finding(
            target="10.0.0.1", finding_type="rce", port=80, protocol="tcp",
            id="f1", severity=Severity.medium,
        )
        f2 = self._make_finding(
            target="10.0.0.1", finding_type="rce", port=80, protocol="tcp",
            id="f2", severity=Severity.critical,
        )

        deduplicator = FindingDeduplicator()
        result = deduplicator.deduplicate([f1, f2])

        assert result[0].severity == Severity.critical

    def test_deduplicate_empty_list(self):
        deduplicator = FindingDeduplicator()
        assert deduplicator.deduplicate([]) == []

    def test_group_related_groups_by_fuzzy_hash(self):
        """Findings on same target+finding_type should cluster together."""
        f1 = self._make_finding(
            target="10.0.0.1", finding_type="sqli", port=80,
            protocol="tcp", affected_component="login", id="f1",
        )
        f2 = self._make_finding(
            target="10.0.0.1", finding_type="sqli", port=443,
            protocol="tcp", affected_component="search", id="f2",
        )
        f3 = self._make_finding(
            target="10.0.0.2", finding_type="xss", port=80,
            protocol="tcp", id="f3",
        )

        deduplicator = FindingDeduplicator()
        groups = deduplicator.group_related([f1, f2, f3])

        # f1 and f2 share fuzzy_hash (same target + finding_type + no CVE)
        assert f1.fuzzy_hash == f2.fuzzy_hash
        assert f1.fuzzy_hash in groups
        assert len(groups[f1.fuzzy_hash]) == 2

        # f3 should be in its own group
        assert f3.fuzzy_hash in groups
        assert len(groups[f3.fuzzy_hash]) == 1

    def test_group_related_empty_list(self):
        deduplicator = FindingDeduplicator()
        result = deduplicator.group_related([])
        assert result == {}
