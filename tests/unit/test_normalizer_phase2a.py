"""Unit tests for Phase 2a FindingFactory methods: from_bloodhound, from_certipy,
from_netexec, and from_linpeas."""

from __future__ import annotations

from vxis.core.normalizer import FindingFactory
from vxis.models.finding import Finding, Severity


SCAN_ID = "scan-phase2a-test"


# ---------------------------------------------------------------------------
# Sample parsed_data payloads (mirrors plugin parse_output output)
# ---------------------------------------------------------------------------

BLOODHOUND_PARSED: dict = {
    "users": 150,
    "admins": 5,
    "kerberoastable": 12,
    "asreproastable": 3,
    "unconstrained_delegation": 2,
}

BLOODHOUND_SAFE_PARSED: dict = {
    "users": 50,
    "admins": 2,
    "kerberoastable": 0,
    "asreproastable": 0,
    "unconstrained_delegation": 0,
}

CERTIPY_PARSED: dict = {
    "vulnerable_templates": [
        {
            "template_name": "VulnTemplate",
            "vulnerability": "ESC1",
            "severity": "critical",
            "enabled": True,
            "client_authentication": True,
            "enrollee_supplies_subject": True,
        }
    ],
    "total_vulnerable": 1,
}

CERTIPY_ESC3_PARSED: dict = {
    "vulnerable_templates": [
        {
            "template_name": "EnrollmentTemplate",
            "vulnerability": "ESC3",
            "severity": "high",
            "enabled": True,
            "client_authentication": False,
            "enrollee_supplies_subject": False,
        }
    ],
    "total_vulnerable": 1,
}

CERTIPY_MULTI_PARSED: dict = {
    "vulnerable_templates": [
        {
            "template_name": "CritTemplate",
            "vulnerability": "ESC2",
            "severity": "critical",
            "enabled": True,
            "client_authentication": True,
            "enrollee_supplies_subject": True,
        },
        {
            "template_name": "HighTemplate",
            "vulnerability": "ESC4",
            "severity": "high",
            "enabled": True,
            "client_authentication": False,
            "enrollee_supplies_subject": False,
        },
    ],
    "total_vulnerable": 2,
}

NETEXEC_PARSED: dict = {
    "readable_shares": [
        {"share": "ADMIN$", "permissions": "READ"},
        {"share": "backup", "permissions": "READ,WRITE"},
    ],
    "password_policy": {
        "raw": "MinLength=4 Complexity=False",
        "min_length": 4,
        "complexity": False,
    },
    "total_readable_shares": 2,
}

NETEXEC_STRONG_POLICY_PARSED: dict = {
    "readable_shares": [],
    "password_policy": {
        "raw": "MinLength=14 Complexity=True",
        "min_length": 14,
        "complexity": True,
    },
    "total_readable_shares": 0,
}

LINPEAS_PARSED: dict = {
    "findings_by_severity": {"critical": 1, "high": 1, "medium": 1},
    "total_findings": 3,
    "privesc_findings": [
        {
            "type": "linux_privesc_vector",
            "severity": "critical",
            "title": "/usr/bin/sudo is SUID and writable",
            "description": "LinPEAS identified a privilege escalation vector with 95% exploitability confidence",
            "confidence_pct": 95,
            "raw_line": "[95%] /usr/bin/sudo is SUID and writable",
        },
        {
            "type": "linux_privesc_vector",
            "severity": "high",
            "title": "/usr/bin/pkexec has known CVE",
            "description": "LinPEAS identified a privilege escalation vector with 70% exploitability confidence",
            "confidence_pct": 70,
            "raw_line": "[70%] /usr/bin/pkexec has known CVE",
        },
        {
            "type": "linux_privesc_vector",
            "severity": "medium",
            "title": "/tmp is world writable",
            "description": "LinPEAS identified a privilege escalation vector with 50% exploitability confidence",
            "confidence_pct": 50,
            "raw_line": "[50%] /tmp is world writable",
        },
    ],
}


# ===========================================================================
# from_bloodhound
# ===========================================================================


class TestFromBloodhound:
    def test_returns_list_of_findings(self) -> None:
        findings = FindingFactory.from_bloodhound(BLOODHOUND_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)

    def test_three_findings_for_full_sample(self) -> None:
        findings = FindingFactory.from_bloodhound(BLOODHOUND_PARSED, SCAN_ID)
        assert len(findings) == 3

    def test_kerberoastable_is_high(self) -> None:
        findings = FindingFactory.from_bloodhound(BLOODHOUND_PARSED, SCAN_ID)
        kerb = [f for f in findings if "Kerberoastable" in f.title]
        assert len(kerb) == 1
        assert kerb[0].severity == Severity.high

    def test_unconstrained_delegation_is_critical(self) -> None:
        findings = FindingFactory.from_bloodhound(BLOODHOUND_PARSED, SCAN_ID)
        unconstrained = [f for f in findings if "Unconstrained Delegation" in f.title]
        assert len(unconstrained) == 1
        assert unconstrained[0].severity == Severity.critical

    def test_asrep_roastable_is_medium(self) -> None:
        findings = FindingFactory.from_bloodhound(BLOODHOUND_PARSED, SCAN_ID)
        asrep = [f for f in findings if "AS-REP" in f.title]
        assert len(asrep) == 1
        assert asrep[0].severity == Severity.medium

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_bloodhound(BLOODHOUND_PARSED, SCAN_ID)
        assert all(f.scan_id == SCAN_ID for f in findings)

    def test_source_plugin_is_bloodhound(self) -> None:
        findings = FindingFactory.from_bloodhound(BLOODHOUND_PARSED, SCAN_ID)
        assert all(f.source_plugin == "bloodhound" for f in findings)

    def test_empty_input_returns_empty_list(self) -> None:
        findings = FindingFactory.from_bloodhound({}, SCAN_ID)
        assert findings == []

    def test_zero_counts_returns_empty_list(self) -> None:
        findings = FindingFactory.from_bloodhound(BLOODHOUND_SAFE_PARSED, SCAN_ID)
        assert findings == []

    def test_only_kerberoastable_generates_one_finding(self) -> None:
        data = {"users": 100, "admins": 0, "kerberoastable": 5,
                "asreproastable": 0, "unconstrained_delegation": 0}
        findings = FindingFactory.from_bloodhound(data, SCAN_ID)
        assert len(findings) == 1
        assert findings[0].severity == Severity.high

    def test_finding_has_evidence(self) -> None:
        findings = FindingFactory.from_bloodhound(BLOODHOUND_PARSED, SCAN_ID)
        for f in findings:
            assert len(f.evidence) >= 1

    def test_finding_ids_are_unique(self) -> None:
        findings = FindingFactory.from_bloodhound(BLOODHOUND_PARSED, SCAN_ID)
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids))


# ===========================================================================
# from_certipy
# ===========================================================================


class TestFromCertipy:
    def test_returns_list_of_findings(self) -> None:
        findings = FindingFactory.from_certipy(CERTIPY_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)

    def test_esc1_is_critical(self) -> None:
        findings = FindingFactory.from_certipy(CERTIPY_PARSED, SCAN_ID)
        assert len(findings) == 1
        assert findings[0].severity == Severity.critical

    def test_esc2_is_critical(self) -> None:
        data = {
            "vulnerable_templates": [{
                "template_name": "ESC2Template",
                "vulnerability": "ESC2",
                "severity": "critical",
                "enabled": True,
                "client_authentication": True,
                "enrollee_supplies_subject": True,
            }],
            "total_vulnerable": 1,
        }
        findings = FindingFactory.from_certipy(data, SCAN_ID)
        assert findings[0].severity == Severity.critical

    def test_esc3_is_high(self) -> None:
        findings = FindingFactory.from_certipy(CERTIPY_ESC3_PARSED, SCAN_ID)
        assert len(findings) == 1
        assert findings[0].severity == Severity.high

    def test_esc4_through_esc8_are_high(self) -> None:
        for esc in ["ESC4", "ESC5", "ESC6", "ESC7", "ESC8"]:
            data = {
                "vulnerable_templates": [{
                    "template_name": f"{esc}Template",
                    "vulnerability": esc,
                    "severity": "high",
                    "enabled": True,
                    "client_authentication": False,
                    "enrollee_supplies_subject": False,
                }],
                "total_vulnerable": 1,
            }
            findings = FindingFactory.from_certipy(data, SCAN_ID)
            assert findings[0].severity == Severity.high, f"{esc} should be high"

    def test_multi_template(self) -> None:
        findings = FindingFactory.from_certipy(CERTIPY_MULTI_PARSED, SCAN_ID)
        assert len(findings) == 2
        severities = {f.severity for f in findings}
        assert Severity.critical in severities
        assert Severity.high in severities

    def test_title_contains_template_name(self) -> None:
        findings = FindingFactory.from_certipy(CERTIPY_PARSED, SCAN_ID)
        assert "VulnTemplate" in findings[0].title

    def test_title_contains_esc_class(self) -> None:
        findings = FindingFactory.from_certipy(CERTIPY_PARSED, SCAN_ID)
        assert "ESC1" in findings[0].title

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_certipy(CERTIPY_PARSED, SCAN_ID)
        assert all(f.scan_id == SCAN_ID for f in findings)

    def test_source_plugin_is_certipy(self) -> None:
        findings = FindingFactory.from_certipy(CERTIPY_PARSED, SCAN_ID)
        assert all(f.source_plugin == "certipy" for f in findings)

    def test_empty_templates_returns_empty_list(self) -> None:
        findings = FindingFactory.from_certipy({"vulnerable_templates": []}, SCAN_ID)
        assert findings == []

    def test_empty_input_returns_empty_list(self) -> None:
        findings = FindingFactory.from_certipy({}, SCAN_ID)
        assert findings == []

    def test_finding_has_evidence(self) -> None:
        findings = FindingFactory.from_certipy(CERTIPY_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1

    def test_source_tool_ref_is_esc_class(self) -> None:
        findings = FindingFactory.from_certipy(CERTIPY_PARSED, SCAN_ID)
        assert findings[0].source_tool_ref == "ESC1"


# ===========================================================================
# from_netexec
# ===========================================================================


class TestFromNetexec:
    def test_returns_list_of_findings(self) -> None:
        findings = FindingFactory.from_netexec(NETEXEC_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)

    def test_readable_shares_are_medium(self) -> None:
        findings = FindingFactory.from_netexec(NETEXEC_PARSED, SCAN_ID)
        share_findings = [f for f in findings if "Share" in f.title]
        assert len(share_findings) == 2
        for f in share_findings:
            assert f.severity == Severity.medium

    def test_weak_password_policy_is_high(self) -> None:
        findings = FindingFactory.from_netexec(NETEXEC_PARSED, SCAN_ID)
        pol_findings = [f for f in findings if "Password Policy" in f.title]
        assert len(pol_findings) == 1
        assert pol_findings[0].severity == Severity.high

    def test_total_findings_count(self) -> None:
        findings = FindingFactory.from_netexec(NETEXEC_PARSED, SCAN_ID)
        # 2 shares + 1 weak password policy
        assert len(findings) == 3

    def test_strong_policy_no_policy_finding(self) -> None:
        findings = FindingFactory.from_netexec(NETEXEC_STRONG_POLICY_PARSED, SCAN_ID)
        pol_findings = [f for f in findings if "Password Policy" in f.title]
        assert len(pol_findings) == 0

    def test_no_shares_returns_only_policy(self) -> None:
        data = {
            "readable_shares": [],
            "password_policy": {
                "raw": "MinLength=4 Complexity=False",
                "min_length": 4,
                "complexity": False,
            },
        }
        findings = FindingFactory.from_netexec(data, SCAN_ID)
        assert len(findings) == 1
        assert findings[0].severity == Severity.high

    def test_share_title_contains_share_name(self) -> None:
        findings = FindingFactory.from_netexec(NETEXEC_PARSED, SCAN_ID)
        share_findings = [f for f in findings if "Share" in f.title]
        names = {f.title for f in share_findings}
        assert any("ADMIN$" in n for n in names)
        assert any("backup" in n for n in names)

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_netexec(NETEXEC_PARSED, SCAN_ID)
        assert all(f.scan_id == SCAN_ID for f in findings)

    def test_source_plugin_is_netexec(self) -> None:
        findings = FindingFactory.from_netexec(NETEXEC_PARSED, SCAN_ID)
        assert all(f.source_plugin == "netexec" for f in findings)

    def test_empty_input_returns_empty_list(self) -> None:
        findings = FindingFactory.from_netexec({}, SCAN_ID)
        assert findings == []

    def test_finding_has_evidence(self) -> None:
        findings = FindingFactory.from_netexec(NETEXEC_PARSED, SCAN_ID)
        for f in findings:
            assert len(f.evidence) >= 1

    def test_finding_ids_are_unique(self) -> None:
        findings = FindingFactory.from_netexec(NETEXEC_PARSED, SCAN_ID)
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids))


# ===========================================================================
# from_linpeas
# ===========================================================================


class TestFromLinpeas:
    def test_returns_list_of_findings(self) -> None:
        findings = FindingFactory.from_linpeas(LINPEAS_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)

    def test_three_findings_from_sample(self) -> None:
        findings = FindingFactory.from_linpeas(LINPEAS_PARSED, SCAN_ID)
        assert len(findings) == 3

    def test_95_percent_is_critical(self) -> None:
        findings = FindingFactory.from_linpeas(LINPEAS_PARSED, SCAN_ID)
        critical = [f for f in findings if f.severity == Severity.critical]
        assert len(critical) == 1
        assert "sudo" in critical[0].title

    def test_70_percent_is_high(self) -> None:
        findings = FindingFactory.from_linpeas(LINPEAS_PARSED, SCAN_ID)
        high = [f for f in findings if f.severity == Severity.high]
        assert len(high) == 1
        assert "pkexec" in high[0].title

    def test_50_percent_is_medium(self) -> None:
        findings = FindingFactory.from_linpeas(LINPEAS_PARSED, SCAN_ID)
        medium = [f for f in findings if f.severity == Severity.medium]
        assert len(medium) == 1
        assert "/tmp" in medium[0].title

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_linpeas(LINPEAS_PARSED, SCAN_ID)
        assert all(f.scan_id == SCAN_ID for f in findings)

    def test_source_plugin_is_linpeas(self) -> None:
        findings = FindingFactory.from_linpeas(LINPEAS_PARSED, SCAN_ID)
        assert all(f.source_plugin == "linpeas" for f in findings)

    def test_empty_input_returns_empty_list(self) -> None:
        findings = FindingFactory.from_linpeas({}, SCAN_ID)
        assert findings == []

    def test_empty_findings_list_returns_empty(self) -> None:
        findings = FindingFactory.from_linpeas({"privesc_findings": []}, SCAN_ID)
        assert findings == []

    def test_finding_has_evidence(self) -> None:
        findings = FindingFactory.from_linpeas(LINPEAS_PARSED, SCAN_ID)
        for f in findings:
            assert len(f.evidence) >= 1

    def test_finding_ids_are_unique(self) -> None:
        findings = FindingFactory.from_linpeas(LINPEAS_PARSED, SCAN_ID)
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids))

    def test_severity_from_name_string_fallback(self) -> None:
        """When confidence_pct is absent, severity should fall back to the string field."""
        data = {
            "privesc_findings": [
                {
                    "type": "linux_privesc_vector",
                    "severity": "high",
                    "title": "Some high finding",
                    "description": "desc",
                    "raw_line": "[70%] Some high finding",
                }
            ]
        }
        findings = FindingFactory.from_linpeas(data, SCAN_ID)
        assert findings[0].severity == Severity.high
