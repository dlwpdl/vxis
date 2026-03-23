"""Tests for the scan comparison (diff) module."""

from __future__ import annotations

import pytest

from vxis.core.scan_diff import ScanDiffResult, compare_finding_lists, ChangedFinding
from vxis.models.finding import Finding, Severity


def _make_finding(
    *,
    title: str = "Test Finding",
    target: str = "10.0.0.1",
    finding_type: str = "sqli",
    severity: Severity = Severity.medium,
    port: int | None = None,
    cve_ids: list[str] | None = None,
    affected_component: str = "",
) -> Finding:
    """Helper to build a minimal Finding for testing."""
    return Finding(
        id="test-id",
        scan_id="scan-1",
        title=title,
        description="Test description",
        severity=severity,
        target=target,
        finding_type=finding_type,
        source_plugin="test-plugin",
        port=port,
        cve_ids=cve_ids or [],
        affected_component=affected_component,
    )


class TestCompareFindingLists:
    """Tests for compare_finding_lists()."""

    def test_empty_scans(self) -> None:
        """Comparing two empty scans returns an empty diff."""
        result = compare_finding_lists([], [])
        assert result.new_findings == []
        assert result.resolved_findings == []
        assert result.unchanged_findings == []
        assert result.changed_findings == []
        assert result.total_a == 0
        assert result.total_b == 0

    def test_identical_scans(self) -> None:
        """Identical finding lists produce only unchanged findings."""
        f1 = _make_finding(title="SQLi in login", finding_type="sqli", target="10.0.0.1")
        f2 = _make_finding(title="XSS in search", finding_type="xss", target="10.0.0.1")

        # Both scans have the same findings (same dedup_hash)
        result = compare_finding_lists([f1, f2], [f1, f2])

        assert len(result.unchanged_findings) == 2
        assert result.new_findings == []
        assert result.resolved_findings == []
        assert result.changed_findings == []

    def test_new_findings(self) -> None:
        """Findings in B but not in A are classified as new."""
        f_common = _make_finding(title="Common", finding_type="sqli", target="10.0.0.1")
        f_new = _make_finding(title="New vuln", finding_type="xss", target="10.0.0.2")

        result = compare_finding_lists([f_common], [f_common, f_new])

        assert len(result.new_findings) == 1
        assert result.new_findings[0].title == "New vuln"
        assert len(result.unchanged_findings) == 1

    def test_resolved_findings(self) -> None:
        """Findings in A but not in B are classified as resolved."""
        f_common = _make_finding(title="Common", finding_type="sqli", target="10.0.0.1")
        f_resolved = _make_finding(title="Old vuln", finding_type="rce", target="10.0.0.3")

        result = compare_finding_lists([f_common, f_resolved], [f_common])

        assert len(result.resolved_findings) == 1
        assert result.resolved_findings[0].title == "Old vuln"
        assert len(result.unchanged_findings) == 1

    def test_changed_severity(self) -> None:
        """Findings with matching hash but different severity are classified as changed."""
        f_a = _make_finding(
            title="Vuln",
            finding_type="sqli",
            target="10.0.0.1",
            severity=Severity.medium,
        )
        f_b = _make_finding(
            title="Vuln",
            finding_type="sqli",
            target="10.0.0.1",
            severity=Severity.critical,
        )

        # Same dedup_hash (same target, finding_type, port, etc.) but different severity
        assert f_a.dedup_hash == f_b.dedup_hash

        result = compare_finding_lists([f_a], [f_b])

        assert result.unchanged_findings == []
        assert len(result.changed_findings) == 1
        assert result.changed_findings[0].old_severity == "medium"
        assert result.changed_findings[0].new_severity == "critical"
        assert result.new_findings == []
        assert result.resolved_findings == []

    def test_mixed_diff(self) -> None:
        """A realistic mixed diff with new, resolved, unchanged, and changed findings."""
        # Common finding (unchanged)
        f_unchanged = _make_finding(
            title="Unchanged",
            finding_type="misconfig",
            target="10.0.0.1",
        )
        # Finding resolved in B
        f_resolved = _make_finding(
            title="Resolved",
            finding_type="xss",
            target="10.0.0.1",
        )
        # Finding new in B
        f_new = _make_finding(
            title="New",
            finding_type="rce",
            target="10.0.0.2",
        )
        # Changed severity
        f_changed_a = _make_finding(
            title="Changed",
            finding_type="sqli",
            target="10.0.0.3",
            severity=Severity.low,
        )
        f_changed_b = _make_finding(
            title="Changed",
            finding_type="sqli",
            target="10.0.0.3",
            severity=Severity.high,
        )

        findings_a = [f_unchanged, f_resolved, f_changed_a]
        findings_b = [f_unchanged, f_new, f_changed_b]

        result = compare_finding_lists(findings_a, findings_b)

        assert len(result.new_findings) == 1
        assert len(result.resolved_findings) == 1
        assert len(result.unchanged_findings) == 1
        assert len(result.changed_findings) == 1

    def test_all_new(self) -> None:
        """Baseline scan is empty — all findings in B are new."""
        f1 = _make_finding(title="A", finding_type="sqli", target="10.0.0.1")
        f2 = _make_finding(title="B", finding_type="xss", target="10.0.0.2")

        result = compare_finding_lists([], [f1, f2])

        assert len(result.new_findings) == 2
        assert result.resolved_findings == []
        assert result.total_a == 0
        assert result.total_b == 2

    def test_all_resolved(self) -> None:
        """Comparison scan is empty — all findings from A are resolved."""
        f1 = _make_finding(title="A", finding_type="sqli", target="10.0.0.1")

        result = compare_finding_lists([f1], [])

        assert len(result.resolved_findings) == 1
        assert result.new_findings == []
        assert result.total_a == 1
        assert result.total_b == 0

    def test_summary_counts(self) -> None:
        """The summary property returns correct counts."""
        f_a = _make_finding(title="A", finding_type="sqli", target="10.0.0.1")
        f_b = _make_finding(title="B", finding_type="xss", target="10.0.0.2")

        result = compare_finding_lists([f_a], [f_a, f_b])

        summary = result.summary
        assert summary["new"] == 1
        assert summary["resolved"] == 0
        assert summary["unchanged"] == 1
        assert summary["changed"] == 0
        assert summary["total_a"] == 1
        assert summary["total_b"] == 2


class TestScanDiffResult:
    """Tests for the ScanDiffResult dataclass."""

    def test_default_empty(self) -> None:
        """Default ScanDiffResult has empty lists."""
        result = ScanDiffResult()
        assert result.total_a == 0
        assert result.total_b == 0
        assert result.summary == {
            "new": 0,
            "resolved": 0,
            "unchanged": 0,
            "changed": 0,
            "total_a": 0,
            "total_b": 0,
        }
