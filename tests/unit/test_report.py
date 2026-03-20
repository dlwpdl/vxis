"""Unit tests for the VXIS report engine.

Tests cover ReportData property logic, ReportGenerator HTML rendering,
SVG chart generation, HTML file output, PDF stub, AI summary fallback,
and template coverage for evidence and attestation.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

from vxis.models.finding import (
    Evidence,
    Finding,
    FindingStatus,
    MitreAttack,
    Reference,
    Severity,
)
from vxis.report.ai_summary import generate_executive_summary
from vxis.report.charts import severity_bar_svg, severity_donut_svg
from vxis.report.generator import ReportData, ReportGenerator


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def make_finding(
    id: str = "f-001",
    title: str = "SQL Injection",
    severity: Severity = Severity.high,
    finding_type: str = "sqli",
    description: str = "Unsanitised input passed to SQL query.",
    **overrides,
) -> Finding:
    """Return a minimal valid Finding with sensible defaults."""
    defaults: dict = dict(
        id=id,
        scan_id="scan-001",
        title=title,
        description=description,
        severity=severity,
        target="192.168.1.10",
        finding_type=finding_type,
        source_plugin="plugin_test",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def make_report_data(findings: list[Finding] | None = None, **overrides) -> ReportData:
    """Return a populated ReportData with sensible defaults."""
    defaults: dict = dict(
        scan_id="scan-001",
        client_name="Acme Corp",
        target="192.168.1.0/24",
        scan_date="2026-03-20",
        findings=findings if findings is not None else [],
        author="Jane Smith",
    )
    defaults.update(overrides)
    return ReportData(**defaults)


def make_generator() -> ReportGenerator:
    """Return a ReportGenerator pointed at the real templates directory."""
    template_dir = (
        Path(__file__).parent.parent.parent
        / "src" / "vxis" / "report" / "templates"
    )
    return ReportGenerator(template_dir=template_dir)


# ---------------------------------------------------------------------------
# ReportData — severity_counts
# ---------------------------------------------------------------------------


class TestReportDataSeverityCounts:
    def test_empty_findings_all_zero(self):
        rd = make_report_data(findings=[])
        counts = rd.severity_counts
        assert counts == {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }

    def test_single_high_finding(self):
        rd = make_report_data(findings=[make_finding(severity=Severity.high)])
        assert rd.severity_counts["high"] == 1
        assert rd.severity_counts["critical"] == 0

    def test_multiple_severities_counted_correctly(self):
        findings = [
            make_finding(id="f1", severity=Severity.critical),
            make_finding(id="f2", severity=Severity.critical),
            make_finding(id="f3", severity=Severity.high),
            make_finding(id="f4", severity=Severity.medium),
            make_finding(id="f5", severity=Severity.low),
            make_finding(id="f6", severity=Severity.informational),
        ]
        counts = make_report_data(findings=findings).severity_counts
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 1
        assert counts["informational"] == 1

    def test_analyst_override_affects_count(self):
        # scanner says high, analyst downgrades to low
        f = make_finding(severity=Severity.high, analyst_severity=Severity.low)
        counts = make_report_data(findings=[f]).severity_counts
        assert counts["low"] == 1
        assert counts["high"] == 0

    def test_all_severity_keys_always_present(self):
        rd = make_report_data(findings=[make_finding(severity=Severity.critical)])
        counts = rd.severity_counts
        for key in ("critical", "high", "medium", "low", "informational"):
            assert key in counts


# ---------------------------------------------------------------------------
# ReportData — findings_by_severity
# ---------------------------------------------------------------------------


class TestReportDataFindingsBySeverity:
    def test_grouping_is_correct(self):
        f_crit = make_finding(id="f1", severity=Severity.critical)
        f_high = make_finding(id="f2", severity=Severity.high)
        f_med = make_finding(id="f3", severity=Severity.medium)
        rd = make_report_data(findings=[f_crit, f_high, f_med])
        grouped = rd.findings_by_severity

        assert f_crit in grouped["critical"]
        assert f_high in grouped["high"]
        assert f_med in grouped["medium"]
        assert grouped["low"] == []
        assert grouped["informational"] == []

    def test_all_severity_keys_present_even_when_empty(self):
        rd = make_report_data(findings=[])
        grouped = rd.findings_by_severity
        for key in ("critical", "high", "medium", "low", "informational"):
            assert key in grouped
            assert grouped[key] == []

    def test_findings_within_group_sorted_by_title(self):
        findings = [
            make_finding(id="f1", title="Zebra Finding", severity=Severity.high),
            make_finding(id="f2", title="Alpha Finding", severity=Severity.high),
        ]
        grouped = make_report_data(findings=findings).findings_by_severity
        titles = [f.title for f in grouped["high"]]
        assert titles == sorted(titles)

    def test_analyst_override_routes_to_correct_group(self):
        f = make_finding(severity=Severity.critical, analyst_severity=Severity.medium)
        grouped = make_report_data(findings=[f]).findings_by_severity
        assert f in grouped["medium"]
        assert grouped["critical"] == []


# ---------------------------------------------------------------------------
# ReportData — risk_score
# ---------------------------------------------------------------------------


class TestReportDataRiskScore:
    def test_empty_findings_returns_zero(self):
        assert make_report_data(findings=[]).risk_score == 0.0

    def test_all_critical_returns_ten(self):
        findings = [make_finding(id=f"f{i}", severity=Severity.critical) for i in range(3)]
        score = make_report_data(findings=findings).risk_score
        assert score == pytest.approx(10.0, abs=0.01)

    def test_all_informational_is_low(self):
        findings = [
            make_finding(id=f"f{i}", severity=Severity.informational) for i in range(5)
        ]
        score = make_report_data(findings=findings).risk_score
        # informational weight 0.1 / critical weight 10.0 * 10 = 0.1
        assert score < 1.0

    def test_score_is_bounded_between_zero_and_ten(self):
        findings = [make_finding(id=f"f{i}", severity=Severity.critical) for i in range(100)]
        score = make_report_data(findings=findings).risk_score
        assert 0.0 <= score <= 10.0

    def test_mixed_severity_score_is_between_extremes(self):
        findings = [
            make_finding(id="f1", severity=Severity.critical),
            make_finding(id="f2", severity=Severity.low),
        ]
        score = make_report_data(findings=findings).risk_score
        # Should be > all-informational but < all-critical (= 10)
        assert 0.0 < score < 10.0

    def test_risk_score_is_float(self):
        score = make_report_data(findings=[make_finding()]).risk_score
        assert isinstance(score, float)


# ---------------------------------------------------------------------------
# ReportGenerator — render_html
# ---------------------------------------------------------------------------


class TestReportGeneratorRenderHtml:
    def test_contains_client_name(self):
        rd = make_report_data(client_name="TestClient Ltd")
        html = make_generator().render_html(rd)
        assert "TestClient Ltd" in html

    def test_contains_finding_title(self):
        rd = make_report_data(findings=[make_finding(title="Remote Code Execution")])
        html = make_generator().render_html(rd)
        assert "Remote Code Execution" in html

    def test_contains_severity_label(self):
        rd = make_report_data(findings=[make_finding(severity=Severity.critical)])
        html = make_generator().render_html(rd)
        # Badge text is rendered in uppercase
        assert "CRITICAL" in html

    def test_empty_findings_produces_valid_html(self):
        rd = make_report_data(findings=[])
        html = make_generator().render_html(rd)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html

    def test_all_severity_sections_present_when_findings_exist(self):
        findings = [
            make_finding(id="f1", severity=Severity.critical),
            make_finding(id="f2", severity=Severity.high),
            make_finding(id="f3", severity=Severity.medium),
            make_finding(id="f4", severity=Severity.low),
            make_finding(id="f5", severity=Severity.informational),
        ]
        html = make_generator().render_html(make_report_data(findings=findings))
        for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            assert label in html

    def test_executive_summary_text_included(self):
        rd = make_report_data(executive_summary="Unique summary text XYZ123.")
        html = make_generator().render_html(rd)
        assert "Unique summary text XYZ123." in html

    def test_html_document_structure(self):
        html = make_generator().render_html(make_report_data())
        assert "<head>" in html
        assert "<body>" in html
        assert "</body>" in html

    def test_scan_id_included(self):
        rd = make_report_data(scan_id="scan-UNIQUE-99")
        html = make_generator().render_html(rd)
        assert "scan-UNIQUE-99" in html

    def test_stylesheet_link_present(self):
        html = make_generator().render_html(make_report_data())
        assert "main.css" in html


# ---------------------------------------------------------------------------
# ReportGenerator — generate_html_file
# ---------------------------------------------------------------------------


class TestReportGeneratorHtmlFile:
    def test_creates_file_on_disk(self, tmp_path: Path):
        output = tmp_path / "report.html"
        make_generator().generate_html_file(make_report_data(), output)
        assert output.exists()

    def test_file_contains_html(self, tmp_path: Path):
        output = tmp_path / "report.html"
        make_generator().generate_html_file(make_report_data(), output)
        content = output.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_creates_parent_directories(self, tmp_path: Path):
        output = tmp_path / "deep" / "nested" / "report.html"
        make_generator().generate_html_file(make_report_data(), output)
        assert output.exists()

    def test_returns_resolved_path(self, tmp_path: Path):
        output = tmp_path / "report.html"
        returned = make_generator().generate_html_file(make_report_data(), output)
        assert returned == output.resolve()

    def test_file_is_utf8(self, tmp_path: Path):
        rd = make_report_data(client_name="Société Générale")
        output = tmp_path / "report.html"
        make_generator().generate_html_file(rd, output)
        content = output.read_text(encoding="utf-8")
        assert "Société Générale" in content


# ---------------------------------------------------------------------------
# ReportGenerator — generate_pdf (stubbed)
# ---------------------------------------------------------------------------


class TestReportGeneratorPdf:
    def test_generate_pdf_raises_not_implemented(self, tmp_path: Path):
        with pytest.raises(NotImplementedError):
            make_generator().generate_pdf(make_report_data(), tmp_path / "report.pdf")

    def test_not_implemented_message_mentions_weasyprint(self, tmp_path: Path):
        with pytest.raises(NotImplementedError, match="WeasyPrint"):
            make_generator().generate_pdf(make_report_data(), tmp_path / "report.pdf")


# ---------------------------------------------------------------------------
# SVG charts — severity_donut_svg
# ---------------------------------------------------------------------------


class TestSeverityDonutSvg:
    def test_returns_string(self):
        result = severity_donut_svg({"critical": 2, "high": 3})
        assert isinstance(result, str)

    def test_is_valid_svg(self):
        result = severity_donut_svg({"critical": 1})
        assert result.strip().startswith("<svg")
        assert "</svg>" in result

    def test_contains_critical_colour(self):
        result = severity_donut_svg({"critical": 5})
        assert "#7B2C34" in result

    def test_contains_high_colour(self):
        result = severity_donut_svg({"high": 3})
        assert "#C0392B" in result

    def test_contains_medium_colour(self):
        result = severity_donut_svg({"medium": 2})
        assert "#E67E22" in result

    def test_contains_low_colour(self):
        result = severity_donut_svg({"low": 1})
        assert "#2ECC71" in result

    def test_contains_informational_colour(self):
        result = severity_donut_svg({"informational": 4})
        assert "#3498DB" in result

    def test_centre_shows_total_count(self):
        result = severity_donut_svg({"critical": 2, "high": 3})
        assert ">5<" in result

    def test_empty_counts_produces_svg(self):
        result = severity_donut_svg({})
        assert "<svg" in result
        assert "</svg>" in result

    def test_custom_size_reflected_in_svg(self):
        result = severity_donut_svg({"high": 1}, size=300)
        assert 'width="300"' in result
        assert 'height="300"' in result

    def test_all_severity_colours_present_when_all_counts_nonzero(self):
        counts = {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 1,
            "informational": 1,
        }
        result = severity_donut_svg(counts)
        for colour in ("#7B2C34", "#C0392B", "#E67E22", "#2ECC71", "#3498DB"):
            assert colour in result


# ---------------------------------------------------------------------------
# SVG charts — severity_bar_svg
# ---------------------------------------------------------------------------


class TestSeverityBarSvg:
    def test_returns_string(self):
        result = severity_bar_svg({"high": 3})
        assert isinstance(result, str)

    def test_is_valid_svg(self):
        result = severity_bar_svg({"critical": 2})
        assert result.strip().startswith("<svg")
        assert "</svg>" in result

    def test_contains_severity_labels(self):
        result = severity_bar_svg({"critical": 1, "high": 2})
        assert "Critical" in result
        assert "High" in result

    def test_contains_count_values(self):
        result = severity_bar_svg({"critical": 7, "low": 3})
        assert ">7<" in result
        assert ">3<" in result

    def test_custom_width_reflected(self):
        result = severity_bar_svg({"high": 1}, width=500)
        assert 'width="500"' in result

    def test_empty_counts_produces_valid_svg(self):
        result = severity_bar_svg({})
        assert "<svg" in result

    def test_all_severities_have_labels(self):
        result = severity_bar_svg({"critical": 1})
        for label in ("Critical", "High", "Medium", "Low", "Informational"):
            assert label in result


# ---------------------------------------------------------------------------
# AI summary — template fallback
# ---------------------------------------------------------------------------


class TestGenerateExecutiveSummary:
    def test_fallback_returns_string(self):
        summary = asyncio.run(
            generate_executive_summary([], "TestCorp", api_key=None)
        )
        assert isinstance(summary, str)

    def test_fallback_mentions_client_name(self):
        summary = asyncio.run(
            generate_executive_summary([], "Acme Industries", api_key=None)
        )
        assert "Acme Industries" in summary

    def test_fallback_with_no_findings_mentions_no_findings(self):
        summary = asyncio.run(
            generate_executive_summary([], "Acme Corp", api_key=None)
        )
        # Should mention zero findings or no findings
        assert re.search(r"0|[Nn]o.*finding", summary)

    def test_fallback_with_findings_mentions_total_count(self):
        findings = [
            make_finding(id="f1", severity=Severity.critical),
            make_finding(id="f2", severity=Severity.high),
            make_finding(id="f3", severity=Severity.medium),
        ]
        summary = asyncio.run(
            generate_executive_summary(findings, "BetaCorp", api_key=None)
        )
        assert "3" in summary

    def test_fallback_mentions_critical_finding_in_prose(self):
        findings = [make_finding(id="f1", title="Remote Code Execution", severity=Severity.critical)]
        summary = asyncio.run(
            generate_executive_summary(findings, "GammaCorp", api_key=None)
        )
        assert "Remote Code Execution" in summary

    def test_fallback_recommends_remediation_of_critical_high(self):
        findings = [
            make_finding(id="f1", severity=Severity.critical),
            make_finding(id="f2", severity=Severity.high),
        ]
        summary = asyncio.run(
            generate_executive_summary(findings, "DeltaCorp", api_key=None)
        )
        # Should mention remediation priority language
        assert re.search(r"[Cc]ritical|[Hh]igh|remediat|prioriti", summary)

    def test_fallback_is_non_empty(self):
        summary = asyncio.run(
            generate_executive_summary([], "Corp", api_key=None)
        )
        assert len(summary.strip()) > 100


# ---------------------------------------------------------------------------
# Template: finding card shows evidence content
# ---------------------------------------------------------------------------


class TestFindingCardEvidence:
    def test_evidence_content_appears_in_html(self):
        evidence = Evidence(
            evidence_type="screenshot",
            title="Login form bypass",
            content="Payload: ' OR '1'='1 triggered a 200 response without credentials.",
        )
        finding = make_finding(
            id="f-ev-001",
            title="Authentication Bypass",
            severity=Severity.critical,
            evidence=[evidence],
        )
        rd = make_report_data(findings=[finding])
        html = make_generator().render_html(rd)
        assert "Login form bypass" in html
        assert "' OR '1'='1" in html

    def test_multiple_evidence_items_all_rendered(self):
        evidences = [
            Evidence(
                evidence_type="log",
                title=f"Evidence item {i}",
                content=f"Unique content alpha-{i}",
            )
            for i in range(3)
        ]
        finding = make_finding(id="f-multi-ev", evidence=evidences)
        html = make_generator().render_html(make_report_data(findings=[finding]))
        for i in range(3):
            assert f"Unique content alpha-{i}" in html

    def test_evidence_type_badge_rendered(self):
        evidence = Evidence(
            evidence_type="packet_capture",
            title="Network trace",
            content="TCP SYN-ACK from target.",
        )
        finding = make_finding(id="f-badge", evidence=[evidence])
        html = make_generator().render_html(make_report_data(findings=[finding]))
        # Badge should show the type in uppercase
        assert "PACKET_CAPTURE" in html

    def test_finding_without_evidence_renders_cleanly(self):
        finding = make_finding(id="f-no-ev", evidence=[])
        html = make_generator().render_html(make_report_data(findings=[finding]))
        assert "<!DOCTYPE html>" in html


# ---------------------------------------------------------------------------
# Template: attestation has severity counts
# ---------------------------------------------------------------------------


class TestAttestationTemplate:
    def _render(self, findings: list[Finding]) -> str:
        rd = make_report_data(findings=findings, author="Alice Tester")
        return make_generator().render_html(rd)

    def test_attestation_section_present(self):
        html = self._render([])
        assert "Attestation" in html

    def test_attestation_shows_client_name(self):
        html = self._render([])
        assert "Acme Corp" in html

    def test_attestation_severity_table_shows_critical_count(self):
        findings = [
            make_finding(id="f1", severity=Severity.critical),
            make_finding(id="f2", severity=Severity.critical),
        ]
        html = self._render(findings)
        # The attestation section repeats the counts; "2" should appear for critical
        assert "2" in html

    def test_attestation_shows_author(self):
        html = self._render([])
        assert "Alice Tester" in html

    def test_attestation_shows_confidential_marker(self):
        html = self._render([])
        assert "Confidential" in html

    def test_attestation_to_whom_it_may_concern(self):
        html = self._render([])
        assert "To Whom It May Concern" in html


# ---------------------------------------------------------------------------
# Template: MITRE ATT&CK mapping rendered
# ---------------------------------------------------------------------------


class TestMitreAttackRendering:
    def test_mitre_attack_fields_appear_in_html(self):
        mitre = MitreAttack(
            tactic_id="TA0001",
            tactic_name="Initial Access",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
        )
        finding = make_finding(id="f-mitre", mitre_attack=mitre)
        html = make_generator().render_html(make_report_data(findings=[finding]))
        assert "TA0001" in html
        assert "Initial Access" in html
        assert "T1190" in html

    def test_no_mitre_section_when_not_set(self):
        finding = make_finding(id="f-no-mitre", mitre_attack=None)
        html = make_generator().render_html(make_report_data(findings=[finding]))
        # Should not raise and should not contain the MITRE section heading
        # (it may contain "MITRE" in comments or CSS class names)
        assert "TA0" not in html


# ---------------------------------------------------------------------------
# Template: references rendered
# ---------------------------------------------------------------------------


class TestReferencesRendering:
    def test_references_appear_in_html(self):
        ref = Reference(
            title="CVE-2023-12345 Advisory",
            url="https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
        )
        finding = make_finding(id="f-ref", references=[ref])
        html = make_generator().render_html(make_report_data(findings=[finding]))
        assert "CVE-2023-12345 Advisory" in html
        assert "https://nvd.nist.gov" in html
