"""Unit tests for the vxis.knowledge module (VulnKB and enricher integration)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vxis.knowledge.kb import RemediationInfo, VulnKB, get_vuln_kb
from vxis.core.enricher import FindingEnricher
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
        severity=Severity.high,
        target="192.168.1.1",
        finding_type="vulnerability",
        source_plugin="nuclei",
    )
    defaults.update(overrides)
    return Finding(**defaults)


MINIMAL_KB_DATA = [
    {
        "vuln_type": "test_vuln",
        "title": "Test Vulnerability",
        "description": "A test vulnerability for unit tests.",
        "remediation_steps": ["Step 1.", "Step 2."],
        "references": ["https://example.com/ref1"],
        "cwe_id": "CWE-999",
        "owasp_category": "A99:2021 – Test Category",
    },
    {
        "vuln_type": "another_vuln",
        "title": "Another Vulnerability",
        "description": "Second entry for search tests.",
        "remediation_steps": ["Fix it."],
        "references": ["https://example.com/ref2"],
        "cwe_id": "CWE-111",
        "owasp_category": "A01:2021 – Broken Access Control",
    },
]


@pytest.fixture()
def tmp_kb(tmp_path: Path) -> VulnKB:
    """Create a VulnKB backed by a temporary JSON file with minimal data."""
    kb_file = tmp_path / "vuln_kb.json"
    kb_file.write_text(json.dumps(MINIMAL_KB_DATA), encoding="utf-8")
    return VulnKB(path=kb_file)


# ---------------------------------------------------------------------------
# VulnKB – loading and basic properties
# ---------------------------------------------------------------------------


class TestVulnKBLoading:
    def test_loads_bundled_data(self):
        """The default bundled KB loads without errors and has entries."""
        kb = VulnKB()
        assert len(kb) >= 20

    def test_loads_custom_path(self, tmp_kb: VulnKB):
        assert len(tmp_kb) == 2

    def test_all_types_sorted(self, tmp_kb: VulnKB):
        assert tmp_kb.all_types == ["another_vuln", "test_vuln"]

    def test_contains(self, tmp_kb: VulnKB):
        assert "test_vuln" in tmp_kb
        assert "nonexistent" not in tmp_kb

    def test_invalid_path_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            VulnKB(path=tmp_path / "does_not_exist.json")


# ---------------------------------------------------------------------------
# VulnKB.get_remediation
# ---------------------------------------------------------------------------


class TestGetRemediation:
    def test_exact_match(self, tmp_kb: VulnKB):
        info = tmp_kb.get_remediation("test_vuln")
        assert info is not None
        assert info.vuln_type == "test_vuln"
        assert info.cwe_id == "CWE-999"

    def test_case_insensitive(self, tmp_kb: VulnKB):
        info = tmp_kb.get_remediation("Test_Vuln")
        assert info is not None
        assert info.vuln_type == "test_vuln"

    def test_hyphen_normalisation(self, tmp_kb: VulnKB):
        info = tmp_kb.get_remediation("test-vuln")
        assert info is not None

    def test_space_normalisation(self, tmp_kb: VulnKB):
        info = tmp_kb.get_remediation("test vuln")
        assert info is not None

    def test_missing_returns_none(self, tmp_kb: VulnKB):
        assert tmp_kb.get_remediation("does_not_exist") is None

    def test_remediation_steps_populated(self, tmp_kb: VulnKB):
        info = tmp_kb.get_remediation("test_vuln")
        assert info is not None
        assert len(info.remediation_steps) == 2

    def test_references_populated(self, tmp_kb: VulnKB):
        info = tmp_kb.get_remediation("test_vuln")
        assert info is not None
        assert "https://example.com/ref1" in info.references


# ---------------------------------------------------------------------------
# VulnKB.search
# ---------------------------------------------------------------------------


class TestSearch:
    def test_search_by_vuln_type(self, tmp_kb: VulnKB):
        results = tmp_kb.search("test_vuln")
        assert len(results) == 1
        assert results[0].vuln_type == "test_vuln"

    def test_search_by_title(self, tmp_kb: VulnKB):
        results = tmp_kb.search("Another Vulnerability")
        assert len(results) == 1

    def test_search_by_cwe(self, tmp_kb: VulnKB):
        results = tmp_kb.search("CWE-999")
        assert len(results) == 1
        assert results[0].cwe_id == "CWE-999"

    def test_search_by_owasp(self, tmp_kb: VulnKB):
        results = tmp_kb.search("Broken Access Control")
        assert len(results) == 1

    def test_search_by_description_fragment(self, tmp_kb: VulnKB):
        results = tmp_kb.search("unit tests")
        assert len(results) == 1

    def test_search_case_insensitive(self, tmp_kb: VulnKB):
        results = tmp_kb.search("TEST_VULN")
        assert len(results) == 1

    def test_search_broad_keyword(self, tmp_kb: VulnKB):
        results = tmp_kb.search("vulnerability")
        # Both entries contain "vulnerability" in title or description
        assert len(results) == 2

    def test_search_no_results(self, tmp_kb: VulnKB):
        results = tmp_kb.search("zzzzz_nonexistent_zzzzz")
        assert results == []


# ---------------------------------------------------------------------------
# RemediationInfo model
# ---------------------------------------------------------------------------


class TestRemediationInfoModel:
    def test_serialization_roundtrip(self):
        info = RemediationInfo(
            vuln_type="test",
            title="Test",
            description="Desc",
            remediation_steps=["A", "B"],
            references=["https://example.com"],
            cwe_id="CWE-1",
            owasp_category="A01:2021 – Test",
        )
        data = info.model_dump()
        restored = RemediationInfo(**data)
        assert restored == info

    def test_json_roundtrip(self):
        info = RemediationInfo(
            vuln_type="test",
            title="Test",
            description="Desc",
            remediation_steps=["A"],
            references=[],
            cwe_id="CWE-1",
            owasp_category="A01:2021 – Test",
        )
        json_str = info.model_dump_json()
        restored = RemediationInfo.model_validate_json(json_str)
        assert restored == info


# ---------------------------------------------------------------------------
# Bundled KB data quality checks
# ---------------------------------------------------------------------------


class TestBundledKBData:
    """Validate the shipped vuln_kb.json file."""

    @pytest.fixture(autouse=True)
    def _load_bundled(self):
        self.kb = VulnKB()

    def test_minimum_entry_count(self):
        assert len(self.kb) >= 20

    def test_all_entries_have_cwe(self):
        for vtype in self.kb.all_types:
            info = self.kb.get_remediation(vtype)
            assert info is not None
            assert info.cwe_id.startswith("CWE-"), f"{vtype} has invalid CWE: {info.cwe_id}"

    def test_all_entries_have_owasp(self):
        for vtype in self.kb.all_types:
            info = self.kb.get_remediation(vtype)
            assert info is not None
            assert info.owasp_category, f"{vtype} missing OWASP category"

    def test_all_entries_have_remediation_steps(self):
        for vtype in self.kb.all_types:
            info = self.kb.get_remediation(vtype)
            assert info is not None
            assert len(info.remediation_steps) >= 1, f"{vtype} has no remediation steps"

    def test_all_entries_have_references(self):
        for vtype in self.kb.all_types:
            info = self.kb.get_remediation(vtype)
            assert info is not None
            assert len(info.references) >= 1, f"{vtype} has no references"

    def test_common_vulns_present(self):
        expected = [
            "sql_injection",
            "xss",
            "ssrf",
            "weak_tls",
            "missing_dmarc",
            "missing_spf",
            "secret",
            "exposure",
            "misconfiguration",
            "injection",
            "rce",
        ]
        for vtype in expected:
            assert vtype in self.kb, f"Expected vuln type '{vtype}' not in bundled KB"


# ---------------------------------------------------------------------------
# get_vuln_kb singleton
# ---------------------------------------------------------------------------


class TestGetVulnKB:
    def test_returns_same_instance(self):
        # Clear the lru_cache first to ensure a clean test
        get_vuln_kb.cache_clear()
        kb1 = get_vuln_kb()
        kb2 = get_vuln_kb()
        assert kb1 is kb2

    def test_returns_valid_kb(self):
        get_vuln_kb.cache_clear()
        kb = get_vuln_kb()
        assert len(kb) >= 20


# ---------------------------------------------------------------------------
# Enricher integration
# ---------------------------------------------------------------------------


class TestEnricherKBIntegration:
    """Verify that FindingEnricher uses VulnKB to enrich findings."""

    def test_enricher_adds_cwe_from_kb(self):
        finding = make_finding(finding_type="xss")
        enricher = FindingEnricher()
        enricher.enrich([finding])
        assert "CWE-79" in finding.cwe_ids

    def test_enricher_adds_references_from_kb(self):
        finding = make_finding(finding_type="sql_injection")
        # finding_type "sql_injection" won't match REMEDIATION_TEMPLATES (which uses "sqli"),
        # but it will match the KB directly.
        enricher = FindingEnricher()
        enricher.enrich([finding])
        ref_urls = {ref.url for ref in finding.references}
        assert any("owasp.org" in url or "cwe.mitre.org" in url for url in ref_urls)

    def test_enricher_does_not_duplicate_cwe(self):
        finding = make_finding(finding_type="xss", cwe_ids=["CWE-79"])
        enricher = FindingEnricher()
        enricher.enrich([finding])
        assert finding.cwe_ids.count("CWE-79") == 1

    def test_enricher_replaces_generic_remediation_with_kb(self):
        finding = make_finding(finding_type="ssrf")
        enricher = FindingEnricher()
        enricher.enrich([finding])
        # KB remediation uses numbered steps format
        assert finding.remediation is not None
        assert "(1)" in finding.remediation

    def test_enricher_preserves_custom_remediation(self):
        custom = "My custom remediation guidance."
        finding = make_finding(finding_type="xss", remediation=custom)
        enricher = FindingEnricher()
        enricher.enrich([finding])
        assert finding.remediation == custom

    def test_enricher_with_custom_kb(self, tmp_path: Path):
        """FindingEnricher can accept a custom VulnKB instance."""
        kb_data = [
            {
                "vuln_type": "custom_type",
                "title": "Custom",
                "description": "Custom vuln.",
                "remediation_steps": ["Do the thing."],
                "references": ["https://custom.example.com"],
                "cwe_id": "CWE-42",
                "owasp_category": "A99:2021 – Custom",
            }
        ]
        kb_file = tmp_path / "custom_kb.json"
        kb_file.write_text(json.dumps(kb_data), encoding="utf-8")
        kb = VulnKB(path=kb_file)

        finding = make_finding(finding_type="custom_type")
        enricher = FindingEnricher(vuln_kb=kb)
        enricher.enrich([finding])
        assert "CWE-42" in finding.cwe_ids
