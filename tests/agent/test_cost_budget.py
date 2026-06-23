"""Mid-scan cost/token budget — resolution + the exceeded check."""

from __future__ import annotations

from vxis.agent.cost_budget import budget_exceeded, resolve_cost_budget

# claude-opus-4-8 is priced (15.0 / 75.0 USD per 1M in/out) in llm_cost.MODEL_PRICES,
# so 1M input tokens = exactly $15.00.
_OPUS_1M_IN = [{"model": "claude-opus-4-8", "role": "director", "input_tokens": 1_000_000, "output_tokens": 0}]


def test_resolve_reads_env(monkeypatch):
    monkeypatch.setenv("VXIS_SCAN_MAX_USD", "2.50")
    monkeypatch.setenv("VXIS_SCAN_MAX_TOKENS", "500000")
    assert resolve_cost_budget() == (2.50, 500000)


def test_resolve_none_when_unset(monkeypatch):
    monkeypatch.delenv("VXIS_SCAN_MAX_USD", raising=False)
    monkeypatch.delenv("VXIS_SCAN_MAX_TOKENS", raising=False)
    assert resolve_cost_budget() == (None, None)


def test_resolve_rejects_nonpositive(monkeypatch):
    monkeypatch.setenv("VXIS_SCAN_MAX_USD", "0")
    monkeypatch.setenv("VXIS_SCAN_MAX_TOKENS", "-5")
    assert resolve_cost_budget() == (None, None)


def test_no_cap_never_exceeds():
    assert budget_exceeded(_OPUS_1M_IN, None, None) is False
    assert budget_exceeded([], None, None) is False


def test_usd_cap():
    assert budget_exceeded(_OPUS_1M_IN, 10.0, None) is True   # $15 >= $10
    assert budget_exceeded(_OPUS_1M_IN, 20.0, None) is False  # $15 < $20


def test_token_cap():
    rows = [{"model": "x", "role": "r", "input_tokens": 600_000, "output_tokens": 0}]
    assert budget_exceeded(rows, None, 500_000) is True
    assert budget_exceeded(rows, None, 700_000) is False


def test_either_cap_trips():
    # USD under but tokens over → still exceeded.
    rows = [{"model": "x", "role": "r", "input_tokens": 600_000, "output_tokens": 0}]  # unknown model -> $0
    assert budget_exceeded(rows, 100.0, 500_000) is True


# --- loop wiring: the budget methods on a real ScanAgentLoop ---

def _loop(**kwargs):
    from vxis.agent.scan_loop import ScanAgentLoop
    from vxis.agent.tools import build_default_registry

    return ScanAgentLoop(target="http://localhost:3000", registry=build_default_registry(), **kwargs)


def test_loop_detects_and_finalizes_on_budget(monkeypatch):
    import vxis.agent.brain_metrics as bm

    monkeypatch.setattr(bm, "get_llm_usage_stats", lambda: {"rows": _OPUS_1M_IN})  # ~$15 spent
    loop = _loop(cost_budget_usd=0.01)
    assert loop._cost_budget_exceeded() is True
    loop._finalize_cost_exhausted_scan()
    assert loop.state.completed is True  # graceful stop -> pipeline reports findings


def test_loop_without_budget_never_trips(monkeypatch):
    import vxis.agent.brain_metrics as bm

    monkeypatch.setattr(bm, "get_llm_usage_stats", lambda: {"rows": _OPUS_1M_IN})
    loop = _loop()  # no cap set
    assert loop._cost_budget_exceeded() is False


def test_loop_under_budget_does_not_trip(monkeypatch):
    import vxis.agent.brain_metrics as bm

    monkeypatch.setattr(bm, "get_llm_usage_stats", lambda: {"rows": _OPUS_1M_IN})  # ~$15
    loop = _loop(cost_budget_usd=100.0)  # generous cap
    assert loop._cost_budget_exceeded() is False
