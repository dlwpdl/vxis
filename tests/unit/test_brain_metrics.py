"""Brain health gate — a scan whose LLM calls ALL failed must not masquerade as
a clean run. The brain swallows provider errors (e.g. a 429 quota / non-callable
model) and the loop ends in seconds; without this gate the pipeline printed
"completed, 0 findings" as if the target were clean.

Also covers per-call usage rows — the data behind the per-model cost panel."""
from vxis.agent.brain_metrics import (
    _record_llm_usage,
    get_llm_usage_stats,
    llm_health_warning,
    reset_llm_usage_stats,
)


def test_warns_when_calls_attempted_but_none_succeeded():
    # 9 calls entered the choke point, 0 produced usage → dead brain.
    msg = llm_health_warning(9, {"calls": 0, "total_tokens": 0})
    assert msg is not None
    assert "9" in msg
    assert "not valid" in msg.lower()


def test_no_warning_when_some_call_succeeded():
    assert llm_health_warning(9, {"calls": 3, "total_tokens": 1200}) is None


def test_no_warning_when_no_calls_attempted():
    # claude-code interactive brain path, or a scan that never reached the LLM.
    assert llm_health_warning(0, {"calls": 0, "total_tokens": 0}) is None


def test_record_usage_accumulates_per_call_rows_with_model_and_role():
    reset_llm_usage_stats()
    _record_llm_usage(
        "gemini", "gemini-2.5-flash", "sys", "usr", "resp",
        {"promptTokenCount": 100, "candidatesTokenCount": 50}, role="director",
    )
    _record_llm_usage(
        "gemini", "gemini-2.5-flash", "s", "u", "r",
        {"promptTokenCount": 10, "candidatesTokenCount": 5},
    )
    rows = get_llm_usage_stats().get("rows")
    assert rows is not None and len(rows) == 2
    assert rows[0]["model"] == "gemini-2.5-flash"
    assert rows[0]["role"] == "director"
    assert rows[1]["role"] == "?"  # default until call sites thread the role
    assert rows[0]["input_tokens"] == 100 and rows[0]["output_tokens"] == 50
    reset_llm_usage_stats()
    assert get_llm_usage_stats().get("rows") == []


def test_get_usage_stats_returns_a_rows_copy_not_the_live_list():
    reset_llm_usage_stats()
    _record_llm_usage("gemini", "gemini-2.5-flash", "s", "u", "r", {})
    snapshot = get_llm_usage_stats().get("rows")
    snapshot.append({"model": "x"})  # mutating the snapshot must not leak back
    assert len(get_llm_usage_stats().get("rows")) == 1
    reset_llm_usage_stats()
