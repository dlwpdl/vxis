"""Unit tests for HTTP revalidation stage (stage 3.5) in the FP pipeline.

phase-B.4 — revalidation now flows through SessionManager (vxis.interaction.hands)
instead of raw httpx.AsyncClient. Mocks below patch the SessionManager.get_session
seam and return AnalyzedResponse-shaped objects (`.status: int`, `.headers: dict`).
"""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from vxis.core.fp_pipeline import (
    FPPipeline,
    _REVALIDATION_CONFIRM_BOOST,
    _REVALIDATION_DENY_PENALTY,
)
from vxis.models.finding import Evidence, Finding, Severity


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
        port=443,
        finding_type="vulnerability",
        source_plugin="nuclei",
        confidence=0.55,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def make_flagged_finding(**overrides) -> Finding:
    """Create a finding that has already been flagged by stage 3."""
    f = make_finding(**overrides)
    f.analyst_notes = (
        "[needs_revalidation] Finding severity is high "
        "but confidence is 0.55 (below threshold 0.7). "
        "Manual verification recommended."
    )
    return f


def make_mock_response(
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> MagicMock:
    """Create a mock AnalyzedResponse with `.status` (int) and `.headers` (dict).

    phase-B.4 — `_check_vulnerability_indicators` and `_http_revalidate` now
    consume AnalyzedResponse from SessionManager (not raw httpx.Response).
    """
    resp = MagicMock()
    resp.status = status_code
    resp.headers = headers or {}
    return resp


@contextmanager
def patch_session_manager(
    head_response: MagicMock | None = None,
    get_response: MagicMock | None = None,
    head_exc: Exception | None = None,
    get_exc: Exception | None = None,
):
    """Patch SessionManager so `get_session().request("HEAD"/"GET")` returns the given mocks.

    Yields the mock session so tests can inspect call history.
    """
    session = AsyncMock()

    async def _request(method: str, url: str, **_kw):
        m = method.upper()
        if m == "HEAD":
            if head_exc is not None:
                raise head_exc
            return head_response
        if m == "GET":
            if get_exc is not None:
                raise get_exc
            return get_response
        raise AssertionError(f"unexpected method {method}")

    session.request = AsyncMock(side_effect=_request)
    mgr_instance = MagicMock()
    mgr_instance.get_session = AsyncMock(return_value=session)
    mgr_instance.close_all = AsyncMock(return_value=None)
    with patch("vxis.core.fp_pipeline.SessionManager", return_value=mgr_instance):
        yield session


# ---------------------------------------------------------------------------
# _extract_revalidation_url
# ---------------------------------------------------------------------------


class TestExtractRevalidationUrl:
    def test_extracts_url_from_evidence(self):
        f = make_flagged_finding(
            evidence=[
                Evidence(
                    evidence_type="http_response",
                    title="Response",
                    content="Vulnerable endpoint found at https://example.com/admin",
                ),
            ],
        )
        url = FPPipeline._extract_revalidation_url(f)
        assert url == "https://example.com/admin"

    def test_extracts_url_from_target_field(self):
        f = make_flagged_finding(target="https://example.com/login", port=None)
        url = FPPipeline._extract_revalidation_url(f)
        assert url == "https://example.com/login"

    def test_constructs_url_from_target_and_port_443(self):
        f = make_flagged_finding(target="example.com", port=443)
        url = FPPipeline._extract_revalidation_url(f)
        assert url == "https://example.com:443"

    def test_constructs_url_from_target_and_port_80(self):
        f = make_flagged_finding(target="example.com", port=80)
        url = FPPipeline._extract_revalidation_url(f)
        assert url == "http://example.com:80"

    def test_constructs_url_from_protocol_field(self):
        f = make_flagged_finding(target="example.com", port=8080, protocol="http")
        # port 8080 is in the HTTP-like set
        url = FPPipeline._extract_revalidation_url(f)
        assert url == "http://example.com:8080"

    def test_returns_none_for_non_http_finding(self):
        f = make_flagged_finding(target="192.168.1.1", port=22, protocol="tcp")
        url = FPPipeline._extract_revalidation_url(f)
        assert url is None

    def test_returns_none_for_no_port_no_protocol_no_url(self):
        f = make_flagged_finding(target="192.168.1.1", port=None, protocol=None)
        url = FPPipeline._extract_revalidation_url(f)
        assert url is None


# ---------------------------------------------------------------------------
# _is_flagged_for_revalidation
# ---------------------------------------------------------------------------


class TestIsFlaggedForRevalidation:
    def test_flagged_finding_detected(self):
        f = make_flagged_finding()
        assert FPPipeline._is_flagged_for_revalidation(f) is True

    def test_unflagged_finding_not_detected(self):
        f = make_finding(analyst_notes=None)
        assert FPPipeline._is_flagged_for_revalidation(f) is False

    def test_other_notes_not_detected(self):
        f = make_finding(analyst_notes="Some other note")
        assert FPPipeline._is_flagged_for_revalidation(f) is False


# ---------------------------------------------------------------------------
# _check_vulnerability_indicators
# ---------------------------------------------------------------------------


class TestCheckVulnerabilityIndicators:
    def test_status_200_confirms(self):
        resp = make_mock_response(status_code=200)
        f = make_flagged_finding()
        assert FPPipeline._check_vulnerability_indicators(resp, f) is True

    def test_status_403_confirms(self):
        resp = make_mock_response(status_code=403)
        f = make_flagged_finding()
        assert FPPipeline._check_vulnerability_indicators(resp, f) is True

    def test_status_404_does_not_confirm(self):
        resp = make_mock_response(status_code=404)
        f = make_flagged_finding()
        assert FPPipeline._check_vulnerability_indicators(resp, f) is False

    def test_status_301_does_not_confirm(self):
        resp = make_mock_response(status_code=301)
        f = make_flagged_finding()
        assert FPPipeline._check_vulnerability_indicators(resp, f) is False


# ---------------------------------------------------------------------------
# _http_revalidate — mocked HTTP
# ---------------------------------------------------------------------------


class TestHttpRevalidate:
    @pytest.mark.asyncio
    async def test_confirmed_revalidation_boosts_confidence(self):
        """HTTP 200 response should boost confidence."""
        pipeline = FPPipeline()
        f = make_flagged_finding(
            target="https://example.com/vuln",
            port=None,
            confidence=0.55,
        )

        mock_response = make_mock_response(status_code=200)

        with patch_session_manager(head_response=mock_response, get_response=mock_response):
            result = await pipeline._http_revalidate(f)

        assert result.confidence == pytest.approx(0.55 + _REVALIDATION_CONFIRM_BOOST)
        assert "[http_revalidation] Confirmed" in result.analyst_notes

    @pytest.mark.asyncio
    async def test_not_confirmed_reduces_confidence(self):
        """HTTP 404 response should reduce confidence."""
        pipeline = FPPipeline()
        f = make_flagged_finding(
            target="https://example.com/vuln",
            port=None,
            confidence=0.55,
        )

        mock_response = make_mock_response(status_code=404)

        with patch_session_manager(head_response=mock_response, get_response=mock_response):
            result = await pipeline._http_revalidate(f)

        assert result.confidence == pytest.approx(0.55 - _REVALIDATION_DENY_PENALTY)
        assert "[http_revalidation] Not confirmed" in result.analyst_notes

    @pytest.mark.asyncio
    async def test_head_405_falls_back_to_get(self):
        """If HEAD returns 405, should fall back to GET."""
        pipeline = FPPipeline()
        f = make_flagged_finding(
            target="https://example.com/vuln",
            port=None,
            confidence=0.55,
        )

        head_response = make_mock_response(status_code=405)
        get_response = make_mock_response(status_code=200)

        with patch_session_manager(
            head_response=head_response, get_response=get_response
        ) as session:
            result = await pipeline._http_revalidate(f)

        # The 405 HEAD must trigger a follow-up GET — assert at least one
        # call with method == "GET".
        get_calls = [c for c in session.request.call_args_list if c.args[0].upper() == "GET"]
        assert get_calls, "expected GET follow-up after HEAD 405"
        assert "[http_revalidation] Confirmed" in result.analyst_notes

    @pytest.mark.asyncio
    async def test_timeout_does_not_change_confidence(self):
        """Timeout should not change confidence score."""
        pipeline = FPPipeline()
        original_confidence = 0.55
        f = make_flagged_finding(
            target="https://example.com/vuln",
            port=None,
            confidence=original_confidence,
        )

        with patch_session_manager(
            head_exc=httpx.TimeoutException("timed out"),
            get_exc=httpx.TimeoutException("timed out"),
        ):
            result = await pipeline._http_revalidate(f)

        assert result.confidence == pytest.approx(original_confidence)
        assert "[http_revalidation] Skipped" in result.analyst_notes

    @pytest.mark.asyncio
    async def test_connect_error_does_not_change_confidence(self):
        """Connection error should not change confidence score."""
        pipeline = FPPipeline()
        original_confidence = 0.55
        f = make_flagged_finding(
            target="https://example.com/vuln",
            port=None,
            confidence=original_confidence,
        )

        with patch_session_manager(
            head_exc=httpx.ConnectError("connection refused"),
            get_exc=httpx.ConnectError("connection refused"),
        ):
            result = await pipeline._http_revalidate(f)

        assert result.confidence == pytest.approx(original_confidence)
        assert "[http_revalidation] Skipped" in result.analyst_notes

    @pytest.mark.asyncio
    async def test_no_url_skips_revalidation(self):
        """Finding without HTTP evidence should be returned unchanged."""
        pipeline = FPPipeline()
        f = make_flagged_finding(
            target="192.168.1.1",
            port=22,
            protocol="tcp",
            confidence=0.55,
        )
        original_notes = f.analyst_notes

        result = await pipeline._http_revalidate(f)

        assert result.confidence == pytest.approx(0.55)
        assert result.analyst_notes == original_notes


# ---------------------------------------------------------------------------
# _http_revalidation (batch orchestrator)
# ---------------------------------------------------------------------------


class TestHttpRevalidationBatch:
    @pytest.mark.asyncio
    async def test_only_revalidates_flagged_findings(self):
        """Non-flagged findings should not be revalidated."""
        pipeline = FPPipeline()

        flagged = make_flagged_finding(
            id="flagged-1",
            target="https://example.com/vuln",
            port=None,
            confidence=0.55,
        )
        unflagged = make_finding(
            id="unflagged-1",
            target="https://example.com/safe",
            port=None,
            confidence=0.80,
            analyst_notes=None,
        )

        mock_response = make_mock_response(status_code=200)

        with patch_session_manager(head_response=mock_response, get_response=mock_response):
            results = await pipeline._http_revalidation([flagged, unflagged])

        # Flagged should have been revalidated (confidence changed)
        assert results[0].confidence != 0.55
        # Unflagged should be unchanged
        assert results[1].confidence == pytest.approx(0.80)

    @pytest.mark.asyncio
    async def test_skips_non_http_flagged_findings(self):
        """Flagged findings without HTTP evidence should not be revalidated."""
        pipeline = FPPipeline()

        f = make_flagged_finding(
            target="192.168.1.1",
            port=22,
            protocol="tcp",
            confidence=0.55,
        )
        original_confidence = f.confidence

        results = await pipeline._http_revalidation([f])

        assert results[0].confidence == pytest.approx(original_confidence)


# ---------------------------------------------------------------------------
# Full pipeline integration — revalidation toggle
# ---------------------------------------------------------------------------


class TestRevalidationToggle:
    @pytest.mark.asyncio
    async def test_revalidation_enabled_by_default(self):
        """Pipeline with revalidate=True (default) should run HTTP revalidation."""
        pipeline = FPPipeline()
        assert pipeline._revalidate is True

    @pytest.mark.asyncio
    async def test_revalidation_disabled_skips_http_stage(self):
        """Pipeline with revalidate=False should skip HTTP revalidation entirely."""
        pipeline = FPPipeline(revalidate=False)

        f = make_finding(
            target="https://example.com/vuln",
            port=None,
            severity=Severity.high,
            confidence=0.55,
            source_plugin="nuclei",
        )

        # With revalidation disabled, no HTTP calls should be made
        with patch.object(pipeline, "_http_revalidation", new_callable=AsyncMock) as mock_reval:
            result = await pipeline.process([f])
            mock_reval.assert_not_called()

    @pytest.mark.asyncio
    async def test_revalidation_enabled_calls_http_stage(self):
        """Pipeline with revalidate=True should call HTTP revalidation."""
        pipeline = FPPipeline(revalidate=True)

        f = make_finding(
            target="https://example.com/vuln",
            port=None,
            severity=Severity.high,
            confidence=0.55,
            source_plugin="nuclei",
        )

        with patch.object(
            pipeline,
            "_http_revalidation",
            new_callable=AsyncMock,
            return_value=[f],
        ) as mock_reval:
            await pipeline.process([f])
            mock_reval.assert_called_once()

    @pytest.mark.asyncio
    async def test_full_pipeline_with_revalidation_disabled(self):
        """Full pipeline run with revalidation disabled still processes findings."""
        pipeline = FPPipeline(revalidate=False)

        f = make_finding(
            id="f1",
            target="https://example.com",
            finding_type="sqli",
            severity=Severity.high,
            confidence=0.55,
            source_plugin="nuclei",
        )

        result = await pipeline.process([f])

        # Finding should survive pipeline (confidence 0.55 > 0.3 threshold)
        assert len(result) == 1
        assert result[0].id == "f1"
        # Should have been flagged by stage 3
        assert "[needs_revalidation]" in result[0].analyst_notes
