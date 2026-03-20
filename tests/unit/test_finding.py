"""Unit tests for the Finding model and related types."""

from __future__ import annotations

import pytest

from vxis.models.finding import (
    CVSSVector,
    Evidence,
    Finding,
    FindingStatus,
    MitreAttack,
    Reference,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_finding(**overrides) -> Finding:
    """Return a minimal valid Finding with sensible defaults."""
    defaults = dict(
        id="finding-001",
        scan_id="scan-001",
        title="SQL Injection",
        description="Unsanitized user input passed to SQL query.",
        severity=Severity.high,
        target="192.168.1.10",
        affected_component="login_service",
        port=443,
        protocol="tcp",
        finding_type="sqli",
        source_plugin="plugin_sqlmap",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_weight_critical(self):
        assert Severity.critical.weight == 4

    def test_weight_high(self):
        assert Severity.high.weight == 3

    def test_weight_medium(self):
        assert Severity.medium.weight == 2

    def test_weight_low(self):
        assert Severity.low.weight == 1

    def test_weight_informational(self):
        assert Severity.informational.weight == 0

    def test_ordering_critical_gt_high(self):
        assert Severity.critical > Severity.high

    def test_ordering_high_gt_medium(self):
        assert Severity.high > Severity.medium

    def test_ordering_medium_gt_low(self):
        assert Severity.medium > Severity.low

    def test_ordering_low_gt_informational(self):
        assert Severity.low > Severity.informational

    def test_ordering_equal(self):
        assert Severity.medium <= Severity.medium
        assert Severity.medium >= Severity.medium

    def test_ordering_less_than(self):
        assert Severity.low < Severity.high


# ---------------------------------------------------------------------------
# CVSSVector
# ---------------------------------------------------------------------------


class TestCVSSVector:
    def test_score_zero_is_informational(self):
        v = CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", base_score=0.0)
        assert v.severity_from_score == Severity.informational

    def test_score_below_4_is_low(self):
        v = CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", base_score=3.9)
        assert v.severity_from_score == Severity.low

    def test_score_4_is_medium(self):
        v = CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", base_score=4.0)
        assert v.severity_from_score == Severity.medium

    def test_score_6_9_is_medium(self):
        v = CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", base_score=6.9)
        assert v.severity_from_score == Severity.medium

    def test_score_7_is_high(self):
        v = CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", base_score=7.0)
        assert v.severity_from_score == Severity.high

    def test_score_8_9_is_high(self):
        v = CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", base_score=8.9)
        assert v.severity_from_score == Severity.high

    def test_score_9_is_critical(self):
        v = CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", base_score=9.0)
        assert v.severity_from_score == Severity.critical

    def test_score_10_is_critical(self):
        v = CVSSVector(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", base_score=10.0)
        assert v.severity_from_score == Severity.critical

    def test_score_out_of_range_raises(self):
        with pytest.raises(Exception):
            CVSSVector(vector_string="CVSS:3.1/AV:N", base_score=10.1)

    def test_negative_score_raises(self):
        with pytest.raises(Exception):
            CVSSVector(vector_string="CVSS:3.1/AV:N", base_score=-0.1)


# ---------------------------------------------------------------------------
# Finding.effective_severity
# ---------------------------------------------------------------------------


class TestEffectiveSeverity:
    def test_without_analyst_override_uses_scanner_severity(self):
        f = make_finding(severity=Severity.medium, analyst_severity=None)
        assert f.effective_severity == Severity.medium

    def test_with_analyst_override_uses_analyst_severity(self):
        f = make_finding(severity=Severity.medium, analyst_severity=Severity.critical)
        assert f.effective_severity == Severity.critical

    def test_analyst_downgrade(self):
        f = make_finding(severity=Severity.high, analyst_severity=Severity.low)
        assert f.effective_severity == Severity.low

    def test_analyst_severity_same_as_scanner(self):
        f = make_finding(severity=Severity.high, analyst_severity=Severity.high)
        assert f.effective_severity == Severity.high


# ---------------------------------------------------------------------------
# Finding.dedup_hash
# ---------------------------------------------------------------------------


class TestDedupHash:
    def test_identical_findings_have_same_dedup_hash(self):
        f1 = make_finding()
        f2 = make_finding()
        assert f1.dedup_hash == f2.dedup_hash

    def test_different_ports_produce_different_hashes(self):
        f1 = make_finding(port=443)
        f2 = make_finding(port=8080)
        assert f1.dedup_hash != f2.dedup_hash

    def test_different_affected_component_produces_different_hash(self):
        f1 = make_finding(affected_component="login_service")
        f2 = make_finding(affected_component="payment_service")
        assert f1.dedup_hash != f2.dedup_hash

    def test_different_finding_type_produces_different_hash(self):
        f1 = make_finding(finding_type="sqli")
        f2 = make_finding(finding_type="xss")
        assert f1.dedup_hash != f2.dedup_hash

    def test_different_target_produces_different_hash(self):
        f1 = make_finding(target="192.168.1.10")
        f2 = make_finding(target="10.0.0.1")
        assert f1.dedup_hash != f2.dedup_hash

    def test_different_cve_produces_different_hash(self):
        f1 = make_finding(cve_ids=["CVE-2023-0001"])
        f2 = make_finding(cve_ids=["CVE-2023-9999"])
        assert f1.dedup_hash != f2.dedup_hash

    def test_dedup_hash_is_16_chars(self):
        f = make_finding()
        assert len(f.dedup_hash) == 16

    def test_none_port_and_protocol_handled(self):
        f1 = make_finding(port=None, protocol=None)
        f2 = make_finding(port=None, protocol=None)
        assert f1.dedup_hash == f2.dedup_hash


# ---------------------------------------------------------------------------
# Finding.fuzzy_hash
# ---------------------------------------------------------------------------


class TestFuzzyHash:
    def test_different_affected_component_same_fuzzy_hash(self):
        """fuzzy_hash must be equal even when affected_component differs."""
        f1 = make_finding(affected_component="component_a")
        f2 = make_finding(affected_component="component_b")
        assert f1.fuzzy_hash == f2.fuzzy_hash

    def test_different_port_same_fuzzy_hash(self):
        """fuzzy_hash must be equal even when port differs."""
        f1 = make_finding(port=80)
        f2 = make_finding(port=443)
        assert f1.fuzzy_hash == f2.fuzzy_hash

    def test_different_target_different_fuzzy_hash(self):
        f1 = make_finding(target="192.168.1.1")
        f2 = make_finding(target="10.0.0.1")
        assert f1.fuzzy_hash != f2.fuzzy_hash

    def test_different_finding_type_different_fuzzy_hash(self):
        f1 = make_finding(finding_type="sqli")
        f2 = make_finding(finding_type="xss")
        assert f1.fuzzy_hash != f2.fuzzy_hash

    def test_fuzzy_hash_is_16_chars(self):
        f = make_finding()
        assert len(f.fuzzy_hash) == 16

    def test_fuzzy_hash_differs_from_dedup_hash(self):
        """fuzzy_hash and dedup_hash are computed from different field sets and
        therefore must never be equal, even when optional dedup fields are empty.

        dedup_hash: target|port|protocol|finding_type|cve|affected_component  (6 segments)
        fuzzy_hash: target|finding_type|cve                                     (3 segments)

        The different number of pipe-separated segments guarantees distinct hashes.
        """
        f = make_finding(port=None, protocol=None, affected_component="")
        assert f.fuzzy_hash != f.dedup_hash


# ---------------------------------------------------------------------------
# Finding.merge_with
# ---------------------------------------------------------------------------


class TestMergeWith:
    def _make_evidence(self, title: str) -> Evidence:
        return Evidence(
            evidence_type="log",
            title=title,
            content="sample log line",
        )

    def test_merge_combines_evidence(self):
        f1 = make_finding(id="f1", evidence=[self._make_evidence("ev-1")])
        f2 = make_finding(id="f2", evidence=[self._make_evidence("ev-2")])

        f1.merge_with(f2)

        titles = [e.title for e in f1.evidence]
        assert "ev-1" in titles
        assert "ev-2" in titles
        assert len(f1.evidence) == 2

    def test_merge_keeps_highest_severity_when_other_is_higher(self):
        f1 = make_finding(severity=Severity.medium)
        f2 = make_finding(severity=Severity.critical)

        f1.merge_with(f2)

        assert f1.severity == Severity.critical

    def test_merge_keeps_original_severity_when_other_is_lower(self):
        f1 = make_finding(severity=Severity.high)
        f2 = make_finding(severity=Severity.low)

        f1.merge_with(f2)

        assert f1.severity == Severity.high

    def test_merge_keeps_severity_when_equal(self):
        f1 = make_finding(severity=Severity.medium)
        f2 = make_finding(severity=Severity.medium)

        f1.merge_with(f2)

        assert f1.severity == Severity.medium

    def test_merge_unions_source_plugins(self):
        f1 = make_finding(source_plugin="plugin_a", source_plugins=["plugin_b"])
        f2 = make_finding(source_plugin="plugin_c", source_plugins=["plugin_d"])

        f1.merge_with(f2)

        assert "plugin_a" in f1.source_plugins
        assert "plugin_c" in f1.source_plugins
        assert "plugin_d" in f1.source_plugins

    def test_merge_no_duplicate_plugins(self):
        f1 = make_finding(source_plugin="plugin_shared", source_plugins=[])
        f2 = make_finding(source_plugin="plugin_shared", source_plugins=[])

        f1.merge_with(f2)

        assert f1.source_plugins.count("plugin_shared") == 1

    def test_merge_unions_cve_ids(self):
        f1 = make_finding(cve_ids=["CVE-2023-0001"])
        f2 = make_finding(cve_ids=["CVE-2023-0002"])

        f1.merge_with(f2)

        assert "CVE-2023-0001" in f1.cve_ids
        assert "CVE-2023-0002" in f1.cve_ids

    def test_merge_no_duplicate_cve_ids(self):
        f1 = make_finding(cve_ids=["CVE-2023-0001"])
        f2 = make_finding(cve_ids=["CVE-2023-0001", "CVE-2023-0002"])

        f1.merge_with(f2)

        assert f1.cve_ids.count("CVE-2023-0001") == 1
        assert "CVE-2023-0002" in f1.cve_ids

    def test_merge_accumulates_multiple_evidence_from_empty(self):
        ev1 = self._make_evidence("first")
        ev2 = self._make_evidence("second")
        f1 = make_finding(evidence=[])
        f2 = make_finding(evidence=[ev1, ev2])

        f1.merge_with(f2)

        assert len(f1.evidence) == 2


# ---------------------------------------------------------------------------
# raw_data excluded from serialization
# ---------------------------------------------------------------------------


class TestFindingSerializationExclusion:
    def test_raw_data_excluded_from_model_dump(self):
        f = make_finding(raw_data={"tool_output": "very verbose data"})
        dumped = f.model_dump()
        assert "raw_data" not in dumped

    def test_raw_data_still_accessible_on_instance(self):
        f = make_finding(raw_data={"tool_output": "secret"})
        assert f.raw_data == {"tool_output": "secret"}
