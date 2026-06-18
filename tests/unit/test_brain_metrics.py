"""Brain health gate — a scan whose LLM calls ALL failed must not masquerade as
a clean run. The brain swallows provider errors (e.g. a 429 quota / non-callable
model) and the loop ends in seconds; without this gate the pipeline printed
"completed, 0 findings" as if the target were clean."""
from vxis.agent.brain_metrics import llm_health_warning


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
