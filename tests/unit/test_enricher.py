"""Unit tests for the FindingEnricher."""

from __future__ import annotations

import pytest

from vxis.core.enricher import (
    COMPLIANCE_MAPPING,
    MITRE_MAPPING,
    REMEDIATION_TEMPLATES,
    FindingEnricher,
)
from vxis.models.finding import CVSSVector, Finding, MitreAttack, Severity


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


# ---------------------------------------------------------------------------
# CVSS enrichment
# ---------------------------------------------------------------------------


class TestEnrichCvss:
    def test_sets_score_based_on_critical_severity(self):
        enricher = FindingEnricher()
        f = make_finding(severity=Severity.critical, cve_ids=["CVE-2021-44228"])
        enricher._enrich_cvss(f)

        assert f.cvss is not None
        assert f.cvss.base_score == pytest.approx(9.5)

    def test_sets_score_based_on_high_severity(self):
        enricher = FindingEnricher()
        f = make_finding(severity=Severity.high, cve_ids=["CVE-2022-1234"])
        enricher._enrich_cvss(f)

        assert f.cvss is not None
        assert f.cvss.base_score == pytest.approx(8.0)

    def test_sets_score_based_on_medium_severity(self):
        enricher = FindingEnricher()
        f = make_finding(severity=Severity.medium, cve_ids=["CVE-2022-5678"])
        enricher._enrich_cvss(f)

        assert f.cvss is not None
        assert f.cvss.base_score == pytest.approx(5.5)

    def test_sets_score_based_on_low_severity(self):
        enricher = FindingEnricher()
        f = make_finding(severity=Severity.low, cve_ids=["CVE-2022-9999"])
        enricher._enrich_cvss(f)

        assert f.cvss is not None
        assert f.cvss.base_score == pytest.approx(2.5)

    def test_does_not_set_cvss_without_cve(self):
        """CVSS enrichment should not apply without CVE IDs."""
        enricher = FindingEnricher()
        f = make_finding(severity=Severity.high, cve_ids=[])
        enricher._enrich_cvss(f)

        assert f.cvss is None

    def test_does_not_overwrite_existing_cvss(self):
        enricher = FindingEnricher()
        existing_cvss = CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            base_score=5.9,
        )
        f = make_finding(
            severity=Severity.critical,
            cve_ids=["CVE-2021-44228"],
            cvss=existing_cvss,
        )
        enricher._enrich_cvss(f)

        # Should not be overwritten
        assert f.cvss.base_score == pytest.approx(5.9)
        assert f.cvss.vector_string == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"


# ---------------------------------------------------------------------------
# MITRE ATT&CK enrichment
# ---------------------------------------------------------------------------


class TestEnrichMitre:
    def test_maps_vulnerability_to_t1190(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="vulnerability")
        enricher._enrich_mitre(f)

        assert f.mitre_attack is not None
        assert f.mitre_attack.technique_id == "T1190"

    def test_maps_secret_to_t1552_001(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="secret")
        enricher._enrich_mitre(f)

        assert f.mitre_attack is not None
        assert f.mitre_attack.technique_id == "T1552"
        assert f.mitre_attack.subtechnique_id == "T1552.001"

    def test_maps_exposure_to_t1530(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="exposure")
        enricher._enrich_mitre(f)

        assert f.mitre_attack is not None
        assert f.mitre_attack.technique_id == "T1530"

    def test_maps_misconfiguration_to_t1574(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="misconfiguration")
        enricher._enrich_mitre(f)

        assert f.mitre_attack is not None
        assert f.mitre_attack.technique_id == "T1574"

    def test_does_not_overwrite_existing_mitre(self):
        enricher = FindingEnricher()
        existing_mitre = MitreAttack(
            tactic_id="TA0099",
            tactic_name="Custom Tactic",
            technique_id="T9999",
            technique_name="Custom Technique",
        )
        f = make_finding(finding_type="vulnerability", mitre_attack=existing_mitre)
        enricher._enrich_mitre(f)

        assert f.mitre_attack.technique_id == "T9999"

    def test_unknown_finding_type_leaves_mitre_null(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="some_unknown_type_xyz")
        enricher._enrich_mitre(f)

        assert f.mitre_attack is None

    def test_all_mitre_mapping_entries_have_required_fields(self):
        for finding_type, mapping in MITRE_MAPPING.items():
            tactic_id, tactic_name, technique_id, technique_name, subtechnique_id = mapping
            assert tactic_id.startswith("TA")
            assert technique_id.startswith("T")
            assert tactic_name
            assert technique_name


# ---------------------------------------------------------------------------
# Compliance enrichment
# ---------------------------------------------------------------------------


class TestEnrichCompliance:
    def test_maps_vulnerability_to_iso27001_controls(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="vulnerability")
        enricher._enrich_compliance(f)

        assert f.analyst_notes is not None
        assert "ISO 27001" in f.analyst_notes or "iso27001" in f.analyst_notes.lower()
        # Verify actual control numbers appear
        expected_controls = COMPLIANCE_MAPPING["vulnerability"]["iso27001"]
        for control in expected_controls:
            assert control in f.analyst_notes

    def test_maps_vulnerability_to_soc2_controls(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="vulnerability")
        enricher._enrich_compliance(f)

        expected_controls = COMPLIANCE_MAPPING["vulnerability"]["soc2"]
        for control in expected_controls:
            assert control in f.analyst_notes

    def test_maps_secret_to_correct_controls(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="secret")
        enricher._enrich_compliance(f)

        assert f.analyst_notes is not None
        for control in COMPLIANCE_MAPPING["secret"]["iso27001"]:
            assert control in f.analyst_notes

    def test_does_not_overwrite_existing_compliance_notes(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="vulnerability", analyst_notes="[compliance] Already set.")
        enricher._enrich_compliance(f)

        # Should not duplicate compliance notes
        assert f.analyst_notes.count("[compliance]") == 1

    def test_preserves_existing_analyst_notes(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="sqli", analyst_notes="Analyst note here.")
        enricher._enrich_compliance(f)

        assert "Analyst note here." in f.analyst_notes
        # Compliance note should be appended
        assert "[compliance]" in f.analyst_notes


# ---------------------------------------------------------------------------
# Remediation enrichment
# ---------------------------------------------------------------------------


class TestEnrichRemediation:
    def test_adds_template_when_missing(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="vulnerability", remediation=None)
        enricher._enrich_remediation(f)

        assert f.remediation is not None
        assert len(f.remediation) > 0

    def test_uses_type_specific_template(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="sqli", remediation=None)
        enricher._enrich_remediation(f)

        expected_template = REMEDIATION_TEMPLATES["sqli"]
        assert f.remediation == expected_template

    def test_does_not_overwrite_existing_remediation(self):
        enricher = FindingEnricher()
        existing = "Custom remediation already set by analyst."
        f = make_finding(finding_type="xss", remediation=existing)
        enricher._enrich_remediation(f)

        assert f.remediation == existing

    def test_unknown_finding_type_gets_generic_remediation(self):
        enricher = FindingEnricher()
        f = make_finding(finding_type="unknown_type_xyz", remediation=None)
        enricher._enrich_remediation(f)

        assert f.remediation is not None
        assert len(f.remediation) > 10  # Not empty

    def test_all_templates_are_non_empty_strings(self):
        for finding_type, template in REMEDIATION_TEMPLATES.items():
            assert isinstance(template, str)
            assert len(template) > 20, f"Template for {finding_type} is too short"


# ---------------------------------------------------------------------------
# Full enrich() integration
# ---------------------------------------------------------------------------


class TestEnrich:
    def test_enrich_runs_all_steps(self):
        enricher = FindingEnricher()
        f = make_finding(
            finding_type="vulnerability",
            severity=Severity.critical,
            cve_ids=["CVE-2021-44228"],
            remediation=None,
        )
        result = enricher.enrich([f])

        assert len(result) == 1
        enriched = result[0]

        # CVSS should be set
        assert enriched.cvss is not None
        assert enriched.cvss.base_score == pytest.approx(9.5)

        # MITRE should be set
        assert enriched.mitre_attack is not None
        assert enriched.mitre_attack.technique_id == "T1190"

        # Compliance should be in notes
        assert enriched.analyst_notes is not None
        assert "[compliance]" in enriched.analyst_notes

        # Remediation should be set
        assert enriched.remediation is not None

    def test_enrich_does_not_overwrite_existing_values(self):
        """All enrichment steps should be non-destructive."""
        enricher = FindingEnricher()

        existing_cvss = CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            base_score=5.9,
        )
        existing_mitre = MitreAttack(
            tactic_id="TA0099",
            tactic_name="Custom",
            technique_id="T9999",
            technique_name="Custom Technique",
        )
        existing_remediation = "Do not touch this."

        f = make_finding(
            finding_type="vulnerability",
            severity=Severity.critical,
            cve_ids=["CVE-2021-44228"],
            cvss=existing_cvss,
            mitre_attack=existing_mitre,
            remediation=existing_remediation,
        )
        result = enricher.enrich([f])
        enriched = result[0]

        assert enriched.cvss.base_score == pytest.approx(5.9)
        assert enriched.mitre_attack.technique_id == "T9999"
        assert enriched.remediation == "Do not touch this."

    def test_enrich_returns_same_list_size(self):
        enricher = FindingEnricher()
        findings = [
            make_finding(id=f"f{i}", finding_type="sqli", cve_ids=["CVE-2022-1234"])
            for i in range(5)
        ]
        result = enricher.enrich(findings)
        assert len(result) == 5

    def test_enrich_empty_list(self):
        enricher = FindingEnricher()
        result = enricher.enrich([])
        assert result == []
