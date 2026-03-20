"""Unit tests for Phase 2b FindingFactory methods:
from_semgrep, from_bandit, from_checkov, from_kube_bench, from_poutine."""

from __future__ import annotations

import pytest

from vxis.core.normalizer import FindingFactory
from vxis.models.finding import Severity


SCAN_ID = "scan-phase2b-test"


# ---------------------------------------------------------------------------
# Sample parsed_data payloads (mirrors plugin parse_output output)
# ---------------------------------------------------------------------------

SEMGREP_PARSED: dict = {
    "sast_findings": [
        {
            "check_id": "python.lang.security.audit.exec-detected",
            "message": "exec() detected",
            "severity": "ERROR",
            "path": "app.py",
            "line": 42,
            "cwe_ids": ["CWE-78"],
            "affected_component": "app.py:42",
        }
    ]
}

SEMGREP_WARNING_PARSED: dict = {
    "sast_findings": [
        {
            "check_id": "python.lang.security.audit.subprocess-shell",
            "message": "subprocess with shell=True",
            "severity": "WARNING",
            "path": "run.py",
            "line": 10,
            "cwe_ids": [],
            "affected_component": "run.py:10",
        }
    ]
}

BANDIT_PARSED: dict = {
    "python_sast": [
        {
            "test_id": "B101",
            "issue_text": "Use of assert",
            "issue_severity": "MEDIUM",
            "filename": "test.py",
            "line_number": 10,
            "cwe_id": 703,
        }
    ]
}

BANDIT_HIGH_PARSED: dict = {
    "python_sast": [
        {
            "test_id": "B602",
            "issue_text": "subprocess call with shell=True",
            "issue_severity": "HIGH",
            "filename": "run.py",
            "line_number": 5,
            "cwe_id": 78,
        }
    ]
}

CHECKOV_PARSED: dict = {
    "iac_findings": [
        {
            "check_id": "CKV_AWS_18",
            "name": "Ensure S3 bucket has logging",
            "guideline": "https://docs.checkov.io",
            "file_path": "/main.tf",
            "file_line_range": [1, 5],
            "severity": "HIGH",
        }
    ]
}

CHECKOV_MEDIUM_PARSED: dict = {
    "iac_findings": [
        {
            "check_id": "CKV_AWS_20",
            "name": "Ensure S3 bucket has access control",
            "guideline": "https://docs.checkov.io/ckv20",
            "file_path": "/s3.tf",
            "file_line_range": [10, 15],
            "severity": "MEDIUM",
        }
    ]
}

KUBE_BENCH_PARSED: dict = {
    "k8s_cis": [
        {
            "test_number": "1.1.1",
            "test_desc": "Ensure API server --anonymous-auth is false",
            "remediation": "Set --anonymous-auth=false",
            "status": "FAIL",
            "scored": True,
        }
    ]
}

KUBE_BENCH_UNSCORED_PARSED: dict = {
    "k8s_cis": [
        {
            "test_number": "4.2.1",
            "test_desc": "Some unscored check",
            "remediation": "Manual review required",
            "status": "FAIL",
            "scored": False,
        }
    ]
}

POUTINE_PARSED: dict = {
    "cicd_findings": [
        {
            "id": "untrusted-checkout",
            "title": "Untrusted checkout in PR trigger",
            "severity": "high",
            "details": "pull_request_target with checkout",
        }
    ]
}

POUTINE_CRITICAL_PARSED: dict = {
    "cicd_findings": [
        {
            "id": "script-injection",
            "title": "Script injection via environment variables",
            "severity": "critical",
            "details": "Untrusted data interpolated into run step",
        }
    ]
}


# ===========================================================================
# from_semgrep
# ===========================================================================


class TestFromSemgrep:
    def test_returns_list(self) -> None:
        findings = FindingFactory.from_semgrep(SEMGREP_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_semgrep(SEMGREP_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_error_severity_maps_to_high(self) -> None:
        findings = FindingFactory.from_semgrep(SEMGREP_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.high

    def test_warning_severity_maps_to_medium(self) -> None:
        findings = FindingFactory.from_semgrep(SEMGREP_WARNING_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.medium

    def test_title_contains_check_id(self) -> None:
        findings = FindingFactory.from_semgrep(SEMGREP_PARSED, SCAN_ID)
        assert "python.lang.security.audit.exec-detected" in findings[0].title

    def test_affected_component_contains_path_and_line(self) -> None:
        findings = FindingFactory.from_semgrep(SEMGREP_PARSED, SCAN_ID)
        assert findings[0].affected_component == "app.py:42"

    def test_source_plugin_is_semgrep(self) -> None:
        findings = FindingFactory.from_semgrep(SEMGREP_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "semgrep"

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_semgrep({"sast_findings": []}, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_semgrep(SEMGREP_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "sast_result"


# ===========================================================================
# from_bandit
# ===========================================================================


class TestFromBandit:
    def test_returns_list(self) -> None:
        findings = FindingFactory.from_bandit(BANDIT_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_bandit(BANDIT_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_medium_severity_mapping(self) -> None:
        findings = FindingFactory.from_bandit(BANDIT_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.medium

    def test_high_severity_mapping(self) -> None:
        findings = FindingFactory.from_bandit(BANDIT_HIGH_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.high

    def test_title_contains_test_id(self) -> None:
        findings = FindingFactory.from_bandit(BANDIT_PARSED, SCAN_ID)
        assert "B101" in findings[0].title

    def test_affected_component_contains_file_and_line(self) -> None:
        findings = FindingFactory.from_bandit(BANDIT_PARSED, SCAN_ID)
        assert findings[0].affected_component == "test.py:10"

    def test_source_plugin_is_bandit(self) -> None:
        findings = FindingFactory.from_bandit(BANDIT_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "bandit"

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_bandit({"python_sast": []}, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_bandit(BANDIT_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "sast_result"


# ===========================================================================
# from_checkov
# ===========================================================================


class TestFromCheckov:
    def test_returns_list(self) -> None:
        findings = FindingFactory.from_checkov(CHECKOV_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_checkov(CHECKOV_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_high_severity_mapping(self) -> None:
        findings = FindingFactory.from_checkov(CHECKOV_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.high

    def test_medium_severity_mapping(self) -> None:
        findings = FindingFactory.from_checkov(CHECKOV_MEDIUM_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.medium

    def test_title_contains_check_id(self) -> None:
        findings = FindingFactory.from_checkov(CHECKOV_PARSED, SCAN_ID)
        assert "CKV_AWS_18" in findings[0].title

    def test_affected_component_contains_file_and_lines(self) -> None:
        findings = FindingFactory.from_checkov(CHECKOV_PARSED, SCAN_ID)
        assert "/main.tf" in findings[0].affected_component
        assert "1" in findings[0].affected_component
        assert "5" in findings[0].affected_component

    def test_finding_type_is_misconfiguration(self) -> None:
        findings = FindingFactory.from_checkov(CHECKOV_PARSED, SCAN_ID)
        assert findings[0].finding_type == "misconfiguration"

    def test_source_plugin_is_checkov(self) -> None:
        findings = FindingFactory.from_checkov(CHECKOV_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "checkov"

    def test_guideline_in_remediation(self) -> None:
        findings = FindingFactory.from_checkov(CHECKOV_PARSED, SCAN_ID)
        assert findings[0].remediation == "https://docs.checkov.io"

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_checkov({"iac_findings": []}, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_checkov(CHECKOV_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "iac_scan"


# ===========================================================================
# from_kube_bench
# ===========================================================================


class TestFromKubeBench:
    def test_returns_list(self) -> None:
        findings = FindingFactory.from_kube_bench(KUBE_BENCH_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_kube_bench(KUBE_BENCH_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_scored_check_is_medium(self) -> None:
        findings = FindingFactory.from_kube_bench(KUBE_BENCH_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.medium

    def test_unscored_check_is_low(self) -> None:
        findings = FindingFactory.from_kube_bench(KUBE_BENCH_UNSCORED_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.low

    def test_title_contains_test_number(self) -> None:
        findings = FindingFactory.from_kube_bench(KUBE_BENCH_PARSED, SCAN_ID)
        assert "1.1.1" in findings[0].title

    def test_finding_type_is_misconfiguration(self) -> None:
        findings = FindingFactory.from_kube_bench(KUBE_BENCH_PARSED, SCAN_ID)
        assert findings[0].finding_type == "misconfiguration"

    def test_source_plugin_is_kube_bench(self) -> None:
        findings = FindingFactory.from_kube_bench(KUBE_BENCH_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "kube-bench"

    def test_remediation_populated(self) -> None:
        findings = FindingFactory.from_kube_bench(KUBE_BENCH_PARSED, SCAN_ID)
        assert findings[0].remediation == "Set --anonymous-auth=false"

    def test_target_is_kubernetes(self) -> None:
        findings = FindingFactory.from_kube_bench(KUBE_BENCH_PARSED, SCAN_ID)
        assert findings[0].target == "kubernetes"

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_kube_bench({"k8s_cis": []}, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_kube_bench(KUBE_BENCH_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "cis_benchmark"


# ===========================================================================
# from_poutine
# ===========================================================================


class TestFromPoutine:
    def test_returns_list(self) -> None:
        findings = FindingFactory.from_poutine(POUTINE_PARSED, SCAN_ID)
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_scan_id_propagated(self) -> None:
        findings = FindingFactory.from_poutine(POUTINE_PARSED, SCAN_ID)
        assert findings[0].scan_id == SCAN_ID

    def test_high_severity_mapping(self) -> None:
        findings = FindingFactory.from_poutine(POUTINE_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.high

    def test_critical_severity_mapping(self) -> None:
        findings = FindingFactory.from_poutine(POUTINE_CRITICAL_PARSED, SCAN_ID)
        assert findings[0].severity == Severity.critical

    def test_title_contains_rule_title(self) -> None:
        findings = FindingFactory.from_poutine(POUTINE_PARSED, SCAN_ID)
        assert "Untrusted checkout in PR trigger" in findings[0].title

    def test_finding_type_is_misconfiguration(self) -> None:
        findings = FindingFactory.from_poutine(POUTINE_PARSED, SCAN_ID)
        assert findings[0].finding_type == "misconfiguration"

    def test_source_plugin_is_poutine(self) -> None:
        findings = FindingFactory.from_poutine(POUTINE_PARSED, SCAN_ID)
        assert findings[0].source_plugin == "poutine"

    def test_affected_component_is_rule_id(self) -> None:
        findings = FindingFactory.from_poutine(POUTINE_PARSED, SCAN_ID)
        assert findings[0].affected_component == "untrusted-checkout"

    def test_description_contains_details(self) -> None:
        findings = FindingFactory.from_poutine(POUTINE_PARSED, SCAN_ID)
        assert "pull_request_target with checkout" in findings[0].description

    def test_empty_returns_empty_list(self) -> None:
        findings = FindingFactory.from_poutine({"cicd_findings": []}, SCAN_ID)
        assert findings == []

    def test_evidence_attached(self) -> None:
        findings = FindingFactory.from_poutine(POUTINE_PARSED, SCAN_ID)
        assert len(findings[0].evidence) >= 1
        assert findings[0].evidence[0].evidence_type == "cicd_scan"
