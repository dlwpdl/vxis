"""Task 1.5a — Pre-baseline instrumentation fixes.

Tests for:
  Fix #1: ScanContext.peak_context_bytes counter
  Fix #3: ScanPipeline honors report_output_path (--output CLI flag)
  Fix #4: brain.get_llm_call_count() authoritative LLM counter
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


# ── Fix #1: peak_context_bytes ────────────────────────────────────

def test_scan_context_peak_context_bytes_grows_with_state() -> None:
    from vxis.pipeline.context import ScanContext

    ctx = ScanContext(target="http://example.test", scan_id="unit-test")
    assert ctx.peak_context_bytes == 0

    ctx.update_peak_size()
    first = ctx.peak_context_bytes
    assert first > 0, "peak should be non-zero after first sample"

    # Grow state
    ctx.api_endpoints.extend([{"url": f"/api/{i}", "method": "GET"} for i in range(50)])
    ctx.hypotheses.extend([{"id": i, "description": "x" * 200} for i in range(20)])
    ctx.update_peak_size()
    assert ctx.peak_context_bytes > first, "peak should grow with added state"

    # Shrinking state must NOT reduce peak (it's a high-water mark)
    grown_peak = ctx.peak_context_bytes
    ctx.api_endpoints.clear()
    ctx.hypotheses.clear()
    ctx.update_peak_size()
    assert ctx.peak_context_bytes == grown_peak, "peak is a high-water mark"


# ── Fix #3: --output flag honored by ScanPipeline ────────────────

def test_scan_pipeline_accepts_report_output_path(tmp_path: Path) -> None:
    from vxis.pipeline.pipeline import ScanPipeline

    custom = tmp_path / "sub" / "custom_report.html"
    pipeline = ScanPipeline(brain=object(), report_output_path=custom)
    assert pipeline._report_output_path == custom


def test_scan_pipeline_default_report_output_is_none() -> None:
    from vxis.pipeline.pipeline import ScanPipeline

    pipeline = ScanPipeline(brain=object())
    assert pipeline._report_output_path is None


@pytest.mark.asyncio
async def test_phase6_report_writes_to_custom_path(tmp_path: Path) -> None:
    """When report_output_path is set, _phase6_report writes there instead of default."""
    from vxis.pipeline.context import ScanContext
    from vxis.pipeline.pipeline import ScanPipeline

    custom = tmp_path / "nested" / "my_report.html"
    pipeline = ScanPipeline(brain=object(), report_output_path=custom)

    ctx = ScanContext(target="http://example.test", scan_id="unit-out")

    # Stub ai_summary to avoid network + ReportGenerator.generate_html_file
    with patch("vxis.report.ai_summary.generate_executive_summary", return_value=None), \
         patch("vxis.report.generator.ReportGenerator.generate_html_file") as mock_gen:
        await pipeline._phase6_report(ctx)
        assert mock_gen.called
        out_arg = mock_gen.call_args[0][1]
        assert Path(out_arg) == custom


# ── Fix #4: LLM invocation counter ───────────────────────────────

def test_llm_call_count_increments_on_direct_call() -> None:
    from vxis.agent import brain as brain_mod

    brain_mod.reset_llm_call_count()
    assert brain_mod.get_llm_call_count() == 0

    b = brain_mod.AgentBrain()
    # Force provider to a bogus one so _call_llm_direct returns None quickly
    # without making a real network call — but the counter must still fire.
    b._provider = "nonexistent_provider"
    b._model = "none"

    b._call_llm_direct("sys", "user", provider="nonexistent_provider", model="none")
    assert brain_mod.get_llm_call_count() == 1

    b._call_llm_direct("sys", "user", provider="nonexistent_provider", model="none")
    b._call_llm_direct("sys", "user", provider="nonexistent_provider", model="none")
    assert brain_mod.get_llm_call_count() == 3


def test_get_llm_call_count_is_module_level() -> None:
    from vxis.agent.brain import get_llm_call_count, reset_llm_call_count

    reset_llm_call_count()
    assert get_llm_call_count() == 0
