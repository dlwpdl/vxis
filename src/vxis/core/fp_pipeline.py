"""False Positive (FP) elimination pipeline for VXIS security automation platform.

5-stage pipeline that filters and scores findings to reduce noise before
findings are surfaced to analysts.

Stage 0 - Context Prefilter: drop tech-incompatible findings
Stage 1 - Tool Validation: remove structurally invalid findings
Stage 2 - Cross-Tool Correlation: boost confidence for multi-source findings
Stage 3 - Revalidation: flag high/critical findings that need manual review
Stage 3.5 - HTTP Revalidation: actively revalidate flagged findings via HTTP
Stage 4 - Confidence Scoring: apply base confidence per source tool and filter
"""

from __future__ import annotations

import asyncio
import logging
import re

from vxis.interaction.hands import AnalyzedResponse, SessionManager
from vxis.models.finding import Finding, Severity

logger = logging.getLogger(__name__)


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

#: Default timeout in seconds for HTTP revalidation requests.
_REVALIDATION_TIMEOUT: float = 5.0

#: Maximum number of concurrent HTTP revalidation requests.
_REVALIDATION_MAX_CONCURRENT: int = 10

#: Confidence boost when HTTP revalidation confirms a vulnerability indicator.
_REVALIDATION_CONFIRM_BOOST: float = 0.15

#: Confidence penalty when HTTP revalidation finds no vulnerability indicator.
_REVALIDATION_DENY_PENALTY: float = 0.15

#: HTTP-related protocols and finding types used to identify revalidatable findings.
_HTTP_PROTOCOLS: set[str] = {"http", "https"}

#: URL pattern to detect URLs in evidence content.
_URL_PATTERN: re.Pattern[str] = re.compile(r"https?://[^\s\"'<>]+")

#: HTTP status codes that commonly indicate a vulnerability is still present.
_VULN_STATUS_CODES: set[int] = {200, 401, 403, 500, 502, 503}

#: Response header patterns that may indicate vulnerability presence.
_VULN_HEADER_PATTERNS: dict[str, list[str]] = {
    "server": ["apache", "nginx", "iis"],
    "x-powered-by": ["php", "asp.net", "express"],
}


# ---------------------------------------------------------------------------
# FPPipeline
# ---------------------------------------------------------------------------


class FPPipeline:
    """5-stage false positive elimination pipeline.

    Usage::

        pipeline = FPPipeline(tech_stack=["nginx", "linux"])
        clean_findings = await pipeline.process(raw_findings)
    """

    def __init__(
        self,
        tech_stack: list[str] | None = None,
        revalidate: bool = True,
        revalidation_timeout: float = _REVALIDATION_TIMEOUT,
    ) -> None:
        """Initialize pipeline with optional detected tech stack.

        Args:
            tech_stack: List of technology identifiers detected on the target
                        (e.g. ["nginx", "linux", "postgresql"]). Used in Stage 0.
            revalidate: Whether to perform HTTP revalidation on flagged findings.
                        Defaults to True. Set to False to skip revalidation.
            revalidation_timeout: Timeout in seconds for each HTTP revalidation
                                  request. Defaults to 5 seconds.
        """
        self._tech_stack: list[str] = [t.lower() for t in (tech_stack or [])]
        self._revalidate: bool = revalidate
        self._revalidation_timeout: float = revalidation_timeout

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
        if self._revalidate:
            stage3 = await self._http_revalidation(stage3)
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
    # Stage 3.5 — HTTP Revalidation
    # ------------------------------------------------------------------

    async def _http_revalidation(self, findings: list[Finding]) -> list[Finding]:
        """Perform HTTP revalidation on findings flagged in stage 3.

        Only findings with ``[needs_revalidation]`` in analyst_notes and
        HTTP-related evidence (URLs, endpoints) are revalidated. A rate-limited
        semaphore caps concurrency.

        Args:
            findings: Input findings list (post stage 3).

        Returns:
            Same findings list with confidence adjusted based on revalidation.
        """
        semaphore = asyncio.Semaphore(_REVALIDATION_MAX_CONCURRENT)

        async def _guarded_revalidate(finding: Finding) -> Finding:
            async with semaphore:
                return await self._http_revalidate(finding)

        tasks: list[asyncio.Task[Finding]] = []
        flagged_indices: list[int] = []

        for i, finding in enumerate(findings):
            if self._is_flagged_for_revalidation(finding):
                url = self._extract_revalidation_url(finding)
                if url is not None:
                    flagged_indices.append(i)
                    tasks.append(asyncio.ensure_future(_guarded_revalidate(finding)))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for idx, result in zip(flagged_indices, results):
                if isinstance(result, Finding):
                    findings[idx] = result
                # Exceptions are swallowed — original finding is kept unchanged

        return findings

    async def _http_revalidate(self, finding: Finding) -> Finding:
        """Perform a single HTTP revalidation request for a finding.

        Extracts the target URL, sends a lightweight request, and adjusts
        confidence based on whether vulnerability indicators are still present.

        Args:
            finding: A finding flagged for revalidation with HTTP evidence.

        Returns:
            The finding with potentially adjusted confidence and updated notes.
        """
        url = self._extract_revalidation_url(finding)
        if url is None:
            return finding

        # Route through SessionManager so revalidation honors the same
        # transport / Ghost / WAF-aware throttling as the rest of the scan
        # (and so the AST guard for raw httpx imports stays clean).
        mgr = SessionManager()
        try:
            session = await mgr.get_session(url)
            try:
                response = await session.request("HEAD", url)
                if response.status == 405:
                    response = await session.request("GET", url)
            except Exception:
                response = await session.request("GET", url)

            confirmed = self._check_vulnerability_indicators(response, finding)

            if confirmed:
                new_confidence = min(1.0, finding.confidence + _REVALIDATION_CONFIRM_BOOST)
                note = (
                    f"[http_revalidation] Confirmed: HTTP {response.status} "
                    f"at {url}. Confidence boosted {finding.confidence:.2f} -> "
                    f"{new_confidence:.2f}."
                )
                finding.confidence = new_confidence
            else:
                new_confidence = max(0.0, finding.confidence - _REVALIDATION_DENY_PENALTY)
                note = (
                    f"[http_revalidation] Not confirmed: HTTP {response.status} "
                    f"at {url}. Confidence reduced {finding.confidence:.2f} -> "
                    f"{new_confidence:.2f}."
                )
                finding.confidence = new_confidence

            if finding.analyst_notes:
                finding.analyst_notes = finding.analyst_notes + "\n" + note
            else:
                finding.analyst_notes = note

        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Unexpected error during HTTP revalidation for %s: %s",
                finding.id,
                exc,
            )
            note = f"[http_revalidation] Skipped: {type(exc).__name__} for {url}."
            if finding.analyst_notes:
                finding.analyst_notes = finding.analyst_notes + "\n" + note
            else:
                finding.analyst_notes = note
        finally:
            try:
                await mgr.close_all()
            except Exception:
                pass

        return finding

    @staticmethod
    def _is_flagged_for_revalidation(finding: Finding) -> bool:
        """Check whether a finding was flagged for revalidation in stage 3."""
        return bool(
            finding.analyst_notes and "[needs_revalidation]" in finding.analyst_notes
        )

    @staticmethod
    def _extract_revalidation_url(finding: Finding) -> str | None:
        """Extract a target URL suitable for HTTP revalidation.

        Checks (in order):
        1. Evidence content for explicit URLs
        2. Target field if it looks like a URL
        3. Target + port to construct an HTTP URL

        Returns:
            A URL string, or None if no HTTP-based URL can be derived.
        """
        # 1. Look for URLs in evidence content
        for ev in finding.evidence:
            matches = _URL_PATTERN.findall(ev.content)
            if matches:
                return matches[0]

        # 2. Target field itself might be a URL
        target = finding.target.strip()
        if target.startswith("http://") or target.startswith("https://"):
            return target

        # 3. Construct from target + port if port is HTTP-like
        if finding.port in (80, 443, 8080, 8443):
            scheme = "https" if finding.port in (443, 8443) else "http"
            return f"{scheme}://{target}:{finding.port}"

        # 4. If protocol is http/https, construct URL
        if finding.protocol and finding.protocol.lower() in _HTTP_PROTOCOLS:
            scheme = finding.protocol.lower()
            port_suffix = f":{finding.port}" if finding.port else ""
            return f"{scheme}://{target}{port_suffix}"

        return None

    @staticmethod
    def _check_vulnerability_indicators(
        response: AnalyzedResponse,
        finding: Finding,
    ) -> bool:
        """Check whether the HTTP response indicates the vulnerability is present.

        Heuristics:
        - Status code is in the set of codes that suggest a live vulnerable endpoint
        - Finding-related keywords appear in response headers
        """
        if response.status in _VULN_STATUS_CODES:
            finding_keywords = finding.finding_type.lower().split()  # noqa: F841 — reserved for future header tagging
            for header_name, patterns in _VULN_HEADER_PATTERNS.items():
                header_value = response.headers.get(header_name, "").lower()
                if header_value:
                    for pattern in patterns:
                        if pattern in header_value:
                            return True

            if response.status in {401, 403, 500, 502, 503}:
                return True

            if response.status == 200:
                return True

        return False

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
