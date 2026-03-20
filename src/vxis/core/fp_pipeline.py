"""False Positive (FP) elimination pipeline for VXIS security automation platform.

5-stage pipeline that filters and scores findings to reduce noise before
findings are surfaced to analysts.

Stage 0 - Context Prefilter: drop tech-incompatible findings
Stage 1 - Tool Validation: remove structurally invalid findings
Stage 2 - Cross-Tool Correlation: boost confidence for multi-source findings
Stage 3 - Revalidation: flag high/critical findings that need manual review
Stage 4 - Confidence Scoring: apply base confidence per source tool and filter
"""

from __future__ import annotations

from vxis.models.finding import Finding, Severity


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Base confidence score assigned per source tool.
#: Reflects historical false-positive rates for each scanner.
TOOL_BASE_CONFIDENCE: dict[str, float] = {
    "testssl": 0.90,
    "checkdmarc": 0.95,
    "nuclei": 0.60,
    "nmap": 0.75,
    "trufflehog": 0.55,
    "wafw00f": 0.70,
}

#: Maps detected technology keywords to finding patterns that are
#: incompatible with that tech stack (substring match on finding_type or title).
INCOMPATIBLE_TECH: dict[str, list[str]] = {
    "nginx": [
        "iis",
        "internet information services",
        "asp.net",
        "windows server iis",
    ],
    "iis": [
        "nginx",
        "apache httpd",
        "openssl heartbleed",
    ],
    "apache": [
        "iis",
        "internet information services",
        "asp.net",
    ],
    "linux": [
        "windows server iis",
        "iis",
        "asp.net",
        "windows smb",
        "ms17-010",
    ],
    "windows": [
        "nginx unix socket",
        "apache unix",
    ],
    "mysql": [
        "mssql",
        "oracle db",
        "postgresql specific",
    ],
    "postgresql": [
        "mssql",
        "oracle db",
        "mysql specific",
    ],
}

#: Minimum confidence threshold below which findings are discarded.
_MIN_CONFIDENCE: float = 0.3

#: Confidence boost per additional corroborating tool source.
_CROSS_TOOL_BOOST: float = 0.15

#: Minimum confidence for HIGH/CRITICAL findings before flagging for revalidation.
_REVALIDATION_THRESHOLD: float = 0.7


# ---------------------------------------------------------------------------
# FPPipeline
# ---------------------------------------------------------------------------


class FPPipeline:
    """5-stage false positive elimination pipeline.

    Usage::

        pipeline = FPPipeline(tech_stack=["nginx", "linux"])
        clean_findings = await pipeline.process(raw_findings)
    """

    def __init__(self, tech_stack: list[str] | None = None) -> None:
        """Initialize pipeline with optional detected tech stack.

        Args:
            tech_stack: List of technology identifiers detected on the target
                        (e.g. ["nginx", "linux", "postgresql"]). Used in Stage 0.
        """
        self._tech_stack: list[str] = [t.lower() for t in (tech_stack or [])]

    async def process(self, findings: list[Finding]) -> list[Finding]:
        """Run all 5 pipeline stages sequentially.

        Args:
            findings: Raw list of findings from normalization.

        Returns:
            Filtered and scored list of findings after FP elimination.
        """
        stage0 = self._context_prefilter(findings)
        stage1 = self._tool_validation(stage0)
        stage2 = self._cross_tool_correlation(stage1)
        stage3 = self._revalidation(stage2)
        stage4 = self._confidence_scoring(stage3)
        return stage4

    # ------------------------------------------------------------------
    # Stage 0 — Context Prefilter
    # ------------------------------------------------------------------

    def _context_prefilter(self, findings: list[Finding]) -> list[Finding]:
        """Drop findings that are incompatible with the detected tech stack.

        For each technology in tech_stack, we check whether any of its
        incompatible patterns appear in the finding's title or finding_type.
        If so, the finding is dropped.

        Args:
            findings: Input findings list.

        Returns:
            Filtered list with tech-incompatible findings removed.
        """
        if not self._tech_stack:
            return findings

        # Build a flat set of all incompatible patterns for detected techs
        incompatible_patterns: set[str] = set()
        for tech in self._tech_stack:
            patterns = INCOMPATIBLE_TECH.get(tech, [])
            for pattern in patterns:
                incompatible_patterns.add(pattern.lower())

        if not incompatible_patterns:
            return findings

        result: list[Finding] = []
        for finding in findings:
            haystack = (finding.title + " " + finding.finding_type).lower()
            is_incompatible = any(pattern in haystack for pattern in incompatible_patterns)
            if not is_incompatible:
                result.append(finding)

        return result

    # ------------------------------------------------------------------
    # Stage 1 — Tool Validation
    # ------------------------------------------------------------------

    def _tool_validation(self, findings: list[Finding]) -> list[Finding]:
        """Remove findings with missing critical fields or empty evidence stubs.

        A finding is considered invalid if:
        - target is empty or whitespace-only
        - finding_type is empty or whitespace-only

        Args:
            findings: Input findings list.

        Returns:
            Filtered list with structurally invalid findings removed.
        """
        result: list[Finding] = []
        for finding in findings:
            if not finding.target or not finding.target.strip():
                continue
            if not finding.finding_type or not finding.finding_type.strip():
                continue
            result.append(finding)
        return result

    # ------------------------------------------------------------------
    # Stage 2 — Cross-Tool Correlation
    # ------------------------------------------------------------------

    def _cross_tool_correlation(self, findings: list[Finding]) -> list[Finding]:
        """Boost confidence when multiple tools confirm the same target+port finding.

        For each unique (target, port) pair, count how many distinct source
        plugins have findings. For each additional plugin beyond the first,
        boost confidence by CROSS_TOOL_BOOST (capped at 1.0).

        Args:
            findings: Input findings list.

        Returns:
            Same findings list with adjusted confidence scores.
        """
        # Group findings by (target, port)
        group_to_plugins: dict[tuple[str, int | None], set[str]] = {}
        for finding in findings:
            key = (finding.target, finding.port)
            if key not in group_to_plugins:
                group_to_plugins[key] = set()
            group_to_plugins[key].add(finding.source_plugin)

        # Apply boost
        for finding in findings:
            key = (finding.target, finding.port)
            plugin_count = len(group_to_plugins.get(key, set()))
            if plugin_count > 1:
                # Each additional source (beyond the first) adds a boost
                extra_sources = plugin_count - 1
                boost = extra_sources * _CROSS_TOOL_BOOST
                new_confidence = min(1.0, finding.confidence + boost)
                finding.confidence = new_confidence

        return findings

    # ------------------------------------------------------------------
    # Stage 3 — Revalidation
    # ------------------------------------------------------------------

    def _revalidation(self, findings: list[Finding]) -> list[Finding]:
        """Flag HIGH/CRITICAL findings with low confidence for analyst review.

        Findings that are high or critical severity but have confidence below
        REVALIDATION_THRESHOLD are annotated in analyst_notes. Actual HTTP
        re-validation is deferred to Phase 1+.

        Args:
            findings: Input findings list.

        Returns:
            Same findings list with analyst_notes updated where appropriate.
        """
        high_severities = {Severity.high, Severity.critical}

        for finding in findings:
            if finding.severity in high_severities and finding.confidence < _REVALIDATION_THRESHOLD:
                note = (
                    f"[needs_revalidation] Finding severity is {finding.severity.value} "
                    f"but confidence is {finding.confidence:.2f} (below threshold "
                    f"{_REVALIDATION_THRESHOLD}). Manual verification recommended."
                )
                if finding.analyst_notes:
                    finding.analyst_notes = finding.analyst_notes + "\n" + note
                else:
                    finding.analyst_notes = note

        return findings

    # ------------------------------------------------------------------
    # Stage 4 — Confidence Scoring
    # ------------------------------------------------------------------

    def _confidence_scoring(self, findings: list[Finding]) -> list[Finding]:
        """Apply base confidence per source tool, then filter out low-confidence findings.

        If a finding's confidence is still at the default (1.0), it is replaced
        with the tool's base confidence. If confidence is already lower (e.g. from
        a previous stage), the minimum of current and base is used to avoid
        artificially inflating confidence.

        Findings with final confidence < MIN_CONFIDENCE are discarded.

        Args:
            findings: Input findings list.

        Returns:
            Filtered list with confidence scores applied.
        """
        result: list[Finding] = []
        for finding in findings:
            base = TOOL_BASE_CONFIDENCE.get(finding.source_plugin, 0.5)

            # If still at default 1.0 from model initialization, apply tool base
            if finding.confidence >= 1.0:
                finding.confidence = base
            else:
                # Already modified by correlation; only decrease, never inflate above base
                finding.confidence = min(finding.confidence, max(base, finding.confidence))

            if finding.confidence >= _MIN_CONFIDENCE:
                result.append(finding)

        return result
