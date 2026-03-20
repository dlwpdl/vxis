"""Unit tests for the FPPipeline false positive elimination stages."""

from __future__ import annotations

import pytest

from vxis.core.fp_pipeline import TOOL_BASE_CONFIDENCE, FPPipeline
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
        confidence=1.0,
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Stage 0 — Context Prefilter
# ---------------------------------------------------------------------------


class TestContextPrefilter:
    def test_removes_incompatible_findings(self):
        """Nginx stack should drop IIS-related findings."""
        pipeline = FPPipeline(tech_stack=["nginx"])

        iis_finding = make_finding(title="IIS Remote Code Execution", finding_type="vulnerability")
        safe_finding = make_finding(title="Open Redirect", finding_type="vulnerability")

        result = pipeline._context_prefilter([iis_finding, safe_finding])

        titles = [f.title for f in result]
        assert "IIS Remote Code Execution" not in titles
        assert "Open Redirect" in titles

    def test_no_tech_stack_passes_all(self):
        pipeline = FPPipeline(tech_stack=None)
        findings = [
            make_finding(title="IIS Remote Code Execution"),
            make_finding(title="Apache misconfiguration"),
        ]
        result = pipeline._context_prefilter(findings)
        assert len(result) == 2

    def test_case_insensitive_pattern_matching(self):
        pipeline = FPPipeline(tech_stack=["nginx"])
        finding = make_finding(title="Internet Information Services Path Traversal")
        result = pipeline._context_prefilter([finding])
        assert len(result) == 0

    def test_unrelated_tech_stack_passes_all(self):
        pipeline = FPPipeline(tech_stack=["postgresql"])
        findings = [
            make_finding(title="XSS in search form", finding_type="xss"),
            make_finding(title="Open redirect", finding_type="vulnerability"),
        ]
        result = pipeline._context_prefilter(findings)
        assert len(result) == 2

    def test_linux_stack_drops_ms17_010(self):
        pipeline = FPPipeline(tech_stack=["linux"])
        finding = make_finding(title="MS17-010 EternalBlue", finding_type="vulnerability")
        result = pipeline._context_prefilter([finding])
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Stage 1 — Tool Validation
# ---------------------------------------------------------------------------


class TestToolValidation:
    def test_removes_findings_without_target(self):
        pipeline = FPPipeline()
        f1 = make_finding(target="")
        f2 = make_finding(target="  ")
        f3 = make_finding(target="192.168.1.1")

        result = pipeline._tool_validation([f1, f2, f3])

        assert len(result) == 1
        assert result[0].target == "192.168.1.1"

    def test_removes_findings_without_finding_type(self):
        pipeline = FPPipeline()
        f1 = make_finding(finding_type="")
        f2 = make_finding(finding_type="   ")
        f3 = make_finding(finding_type="vulnerability")

        result = pipeline._tool_validation([f1, f2, f3])

        assert len(result) == 1
        assert result[0].finding_type == "vulnerability"

    def test_keeps_valid_findings(self):
        pipeline = FPPipeline()
        findings = [
            make_finding(id="f1", target="10.0.0.1", finding_type="sqli"),
            make_finding(id="f2", target="10.0.0.2", finding_type="xss"),
        ]
        result = pipeline._tool_validation(findings)
        assert len(result) == 2

    def test_empty_input(self):
        pipeline = FPPipeline()
        assert pipeline._tool_validation([]) == []


# ---------------------------------------------------------------------------
# Stage 2 — Cross-Tool Correlation
# ---------------------------------------------------------------------------


class TestCrossToolCorrelation:
    def test_boosts_confidence_for_multi_source_findings(self):
        """Same target+port from two tools should boost confidence."""
        pipeline = FPPipeline()

        f1 = make_finding(
            id="f1", target="10.0.0.1", port=80, source_plugin="nuclei", confidence=0.60,
        )
        f2 = make_finding(
            id="f2", target="10.0.0.1", port=80, source_plugin="nmap", confidence=0.75,
        )

        result = pipeline._cross_tool_correlation([f1, f2])

        # Both should have been boosted by 0.15 (one extra source)
        for f in result:
            assert f.confidence > 0.60 if f.source_plugin == "nuclei" else f.confidence > 0.75

    def test_no_boost_for_single_source(self):
        """Single source should not be boosted."""
        pipeline = FPPipeline()
        f1 = make_finding(id="f1", target="10.0.0.1", port=80, source_plugin="nuclei", confidence=0.60)

        result = pipeline._cross_tool_correlation([f1])

        assert result[0].confidence == pytest.approx(0.60)

    def test_different_ports_dont_cross_correlate(self):
        """Different ports should not correlate even on same target."""
        pipeline = FPPipeline()
        f1 = make_finding(id="f1", target="10.0.0.1", port=80, source_plugin="nuclei", confidence=0.60)
        f2 = make_finding(id="f2", target="10.0.0.1", port=443, source_plugin="nmap", confidence=0.75)

        result = pipeline._cross_tool_correlation([f1, f2])

        # No correlation — different ports
        nuclei_f = next(f for f in result if f.source_plugin == "nuclei")
        nmap_f = next(f for f in result if f.source_plugin == "nmap")
        assert nuclei_f.confidence == pytest.approx(0.60)
        assert nmap_f.confidence == pytest.approx(0.75)

    def test_three_tools_boost_more(self):
        """Three sources should produce greater boost than two."""
        pipeline = FPPipeline()
        findings = [
            make_finding(id="f1", target="10.0.0.1", port=80, source_plugin="nuclei", confidence=0.60),
            make_finding(id="f2", target="10.0.0.1", port=80, source_plugin="nmap", confidence=0.60),
            make_finding(id="f3", target="10.0.0.1", port=80, source_plugin="testssl", confidence=0.60),
        ]
        result = pipeline._cross_tool_correlation(findings)

        # With 3 sources, boost = 2 * 0.15 = 0.30
        for f in result:
            assert f.confidence == pytest.approx(min(1.0, 0.60 + 0.30))

    def test_confidence_capped_at_1(self):
        pipeline = FPPipeline()
        findings = [
            make_finding(id=f"f{i}", target="10.0.0.1", port=80, source_plugin=f"tool{i}", confidence=0.95)
            for i in range(5)
        ]
        result = pipeline._cross_tool_correlation(findings)
        for f in result:
            assert f.confidence <= 1.0


# ---------------------------------------------------------------------------
# Stage 3 — Revalidation
# ---------------------------------------------------------------------------


class TestRevalidation:
    def test_flags_high_severity_low_confidence(self):
        pipeline = FPPipeline()
        f = make_finding(severity=Severity.high, confidence=0.55)
        result = pipeline._revalidation([f])

        assert result[0].analyst_notes is not None
        assert "needs_revalidation" in result[0].analyst_notes

    def test_flags_critical_severity_low_confidence(self):
        pipeline = FPPipeline()
        f = make_finding(severity=Severity.critical, confidence=0.40)
        result = pipeline._revalidation([f])

        assert "needs_revalidation" in result[0].analyst_notes

    def test_does_not_flag_high_severity_sufficient_confidence(self):
        pipeline = FPPipeline()
        f = make_finding(severity=Severity.high, confidence=0.80)
        result = pipeline._revalidation([f])

        assert result[0].analyst_notes is None

    def test_does_not_flag_medium_severity_low_confidence(self):
        """Only HIGH and CRITICAL trigger revalidation."""
        pipeline = FPPipeline()
        f = make_finding(severity=Severity.medium, confidence=0.40)
        result = pipeline._revalidation([f])

        assert result[0].analyst_notes is None

    def test_preserves_existing_analyst_notes(self):
        pipeline = FPPipeline()
        f = make_finding(severity=Severity.high, confidence=0.50, analyst_notes="Previous note.")
        result = pipeline._revalidation([f])

        assert "Previous note." in result[0].analyst_notes
        assert "needs_revalidation" in result[0].analyst_notes


# ---------------------------------------------------------------------------
# Stage 4 — Confidence Scoring
# ---------------------------------------------------------------------------


class TestConfidenceScoring:
    def test_applies_tool_base_confidence(self):
        """Findings with default 1.0 confidence should get tool base confidence."""
        pipeline = FPPipeline()
        f = make_finding(source_plugin="nuclei", confidence=1.0)
        result = pipeline._confidence_scoring([f])

        assert len(result) == 1
        assert result[0].confidence == pytest.approx(TOOL_BASE_CONFIDENCE["nuclei"])

    def test_filters_out_low_confidence_findings(self):
        """Findings below MIN_CONFIDENCE (0.3) must be discarded."""
        pipeline = FPPipeline()
        f = make_finding(source_plugin="nuclei", confidence=0.20)
        result = pipeline._confidence_scoring([f])

        assert len(result) == 0

    def test_keeps_findings_above_min_confidence(self):
        pipeline = FPPipeline()
        f = make_finding(source_plugin="testssl", confidence=0.90)
        result = pipeline._confidence_scoring([f])

        assert len(result) == 1

    def test_checkdmarc_has_highest_base_confidence(self):
        assert TOOL_BASE_CONFIDENCE["checkdmarc"] > TOOL_BASE_CONFIDENCE["nuclei"]
        assert TOOL_BASE_CONFIDENCE["checkdmarc"] > TOOL_BASE_CONFIDENCE["trufflehog"]

    def test_unknown_tool_gets_default_confidence(self):
        pipeline = FPPipeline()
        f = make_finding(source_plugin="unknown_tool_xyz", confidence=1.0)
        result = pipeline._confidence_scoring([f])
        # Should not raise, and confidence should be set to default 0.5
        if result:
            assert result[0].confidence == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Full pipeline integration
# ---------------------------------------------------------------------------


class TestFullPipeline:
    @pytest.mark.asyncio
    async def test_full_pipeline_processes_findings_end_to_end(self):
        """Integration test: valid findings survive the full pipeline."""
        pipeline = FPPipeline(tech_stack=["nginx"])

        good_finding = make_finding(
            id="good-1",
            title="SQL Injection in login form",
            target="https://example.com",
            finding_type="sqli",
            source_plugin="nuclei",
            confidence=1.0,
            severity=Severity.high,
        )
        iis_finding = make_finding(
            id="bad-1",
            title="IIS Directory Traversal",
            target="https://example.com",
            finding_type="vulnerability",
            source_plugin="nuclei",
            confidence=1.0,
        )
        empty_target = make_finding(
            id="bad-2",
            title="No Target Finding",
            target="",
            finding_type="vulnerability",
            source_plugin="nmap",
            confidence=0.50,
        )

        result = await pipeline.process([good_finding, iis_finding, empty_target])

        # IIS finding should be filtered by context prefilter
        result_ids = [f.id for f in result]
        assert "bad-1" not in result_ids

        # Empty target finding should be filtered by tool validation
        assert "bad-2" not in result_ids

        # Good finding should survive
        assert "good-1" in result_ids

    @pytest.mark.asyncio
    async def test_pipeline_returns_empty_list_for_empty_input(self):
        pipeline = FPPipeline()
        result = await pipeline.process([])
        assert result == []

    @pytest.mark.asyncio
    async def test_pipeline_applies_confidence_scores(self):
        pipeline = FPPipeline()
        f = make_finding(
            id="f1",
            target="10.0.0.1",
            finding_type="vulnerability",
            source_plugin="testssl",
            confidence=1.0,
        )
        result = await pipeline.process([f])
        assert len(result) == 1
        assert result[0].confidence == pytest.approx(TOOL_BASE_CONFIDENCE["testssl"])
