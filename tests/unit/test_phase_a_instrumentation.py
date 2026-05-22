"""Task 1.5a — Pre-baseline instrumentation fixes.

Tests for:
  Fix #1: ScanContext.peak_context_bytes counter
  Fix #3: ScanPipeline honors report_output_path (--output CLI flag)
  Fix #4: brain.get_llm_call_count() authoritative LLM counter
"""

from __future__ import annotations

from pathlib import Path


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
# Phase A Task 12: legacy `vxis.pipeline.pipeline` deleted. These tests now target
# the v2 shim `ScanPipelineV2` exposed via `vxis.pipeline.ScanPipeline`. The
# _phase6_report test was dropped because the legacy private method no longer
# exists — v2's report generation is covered by tests/pipeline/test_scan_pipeline_v2.py.

def test_scan_pipeline_accepts_report_output_path(tmp_path: Path) -> None:
    from vxis.pipeline import ScanPipeline

    custom = tmp_path / "sub" / "custom_report.html"
    pipeline = ScanPipeline(brain=object(), report_output_path=custom)
    assert pipeline._report_output_path == custom


def test_scan_pipeline_default_report_output_is_none() -> None:
    from vxis.pipeline import ScanPipeline

    pipeline = ScanPipeline(brain=object())
    assert pipeline._report_output_path is None


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


# ── Task 1.5b: Unified brain_decision_count across all backends ──


def test_brain_decision_count_increments_on_agent_brain_think() -> None:
    from vxis.agent import brain as brain_mod
    from vxis.agent.brain import AgentBrain, AgentObservation

    brain_mod.reset_brain_decision_count()
    assert brain_mod.get_brain_decision_count() == 0

    b = AgentBrain(max_steps=10)
    # Force LLM fallback to return None so think() exits after counter increment
    # without making any network call. Also bypass compiled-pattern shortcut.
    b._try_compiled_patterns = lambda obs: []  # type: ignore[assignment]
    b._call_llm_with_fallback = lambda system, user: None  # type: ignore[assignment]

    obs = AgentObservation(target="http://example.test")
    b.think(obs)
    assert brain_mod.get_brain_decision_count() == 1

    # think() set is_done=True after None fallback; reset to call again
    b.is_done = False
    b.think(obs)
    b.is_done = False
    b.think(obs)
    assert brain_mod.get_brain_decision_count() == 3


def test_brain_decision_count_increments_on_interactive_brain_think() -> None:
    import io
    from vxis.agent import brain as brain_mod
    from vxis.agent.brain import AgentObservation
    from vxis.agent.brain_interactive import InteractiveBrain

    brain_mod.reset_brain_decision_count()

    stdin = io.StringIO('{"actions": [{"tool": "DONE", "reasoning": "done"}]}\n')
    stdout = io.StringIO()
    b = InteractiveBrain(max_steps=10, input_stream=stdin, output_stream=stdout)

    obs = AgentObservation(target="http://example.test")
    b.think(obs)
    assert brain_mod.get_brain_decision_count() == 1


def test_brain_decision_count_increments_on_file_based_brain_think(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from vxis.agent import brain as brain_mod
    from vxis.agent.brain import AgentObservation
    from vxis.agent.brain_filebased import FileBasedBrain

    brain_mod.reset_brain_decision_count()

    b = FileBasedBrain(brain_dir=str(tmp_path))
    # Stub out file I/O + decision wait so think() returns quickly
    b._wait_for_decision = lambda: {"vector_id": "v1", "attempt": False, "actions": []}  # type: ignore[assignment]
    b._parse_decision = lambda d: []  # type: ignore[assignment]

    obs = AgentObservation(target="http://example.test")
    b.think(obs)
    assert brain_mod.get_brain_decision_count() == 1


def test_brain_decision_count_does_not_increment_on_early_return() -> None:
    from vxis.agent import brain as brain_mod
    from vxis.agent.brain import AgentBrain, AgentObservation

    brain_mod.reset_brain_decision_count()

    b = AgentBrain(max_steps=10)
    b.is_done = True

    obs = AgentObservation(target="http://example.test")
    result = b.think(obs)
    assert result == []
    assert brain_mod.get_brain_decision_count() == 0


def test_brain_decision_count_and_llm_count_are_independent() -> None:
    from vxis.agent import brain as brain_mod

    brain_mod.reset_brain_decision_count()
    brain_mod.reset_llm_call_count()

    brain_mod._increment_brain_decision_count()
    brain_mod._increment_brain_decision_count()
    brain_mod._increment_llm_call_count()

    assert brain_mod.get_brain_decision_count() == 2
    assert brain_mod.get_llm_call_count() == 1

    brain_mod.reset_llm_call_count()
    assert brain_mod.get_brain_decision_count() == 2
    assert brain_mod.get_llm_call_count() == 0

    brain_mod.reset_brain_decision_count()
    brain_mod._increment_llm_call_count()
    brain_mod._increment_llm_call_count()
    assert brain_mod.get_brain_decision_count() == 0
    assert brain_mod.get_llm_call_count() == 2
