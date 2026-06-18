"""LLM call and usage telemetry for AgentBrain."""

from __future__ import annotations

import json
import threading
from typing import Any

# ── Benchmark instrumentation: unified brain decision counter ──
# Incremented once per `think()` entry (after early-return checks) across ALL
# Brain backends (AgentBrain API path + InteractiveBrain + FileBasedBrain).
# Apples-to-apples metric for Task 14 comparison independent of backend.
# Process-global, not per-scan.
_BRAIN_DECISION_COUNT: int = 0
_BRAIN_DECISION_LOCK = threading.Lock()


def get_brain_decision_count() -> int:
    """Return total number of Brain think() decisions since process start."""
    return _BRAIN_DECISION_COUNT


def reset_brain_decision_count() -> None:
    """Reset counter to zero (test hook)."""
    global _BRAIN_DECISION_COUNT
    with _BRAIN_DECISION_LOCK:
        _BRAIN_DECISION_COUNT = 0


def _increment_brain_decision_count() -> None:
    global _BRAIN_DECISION_COUNT
    with _BRAIN_DECISION_LOCK:
        _BRAIN_DECISION_COUNT += 1


# ── Benchmark instrumentation: authoritative LLM invocation counter ──
# Incremented once per `_call_llm_direct` entry (the single choke point for
# all provider paths in AgentBrain). Used by Task 1 baseline + Task 14
# post-migration comparison. Does NOT affect dispatch — claude-first routing
# stays untouched.
_LLM_CALL_COUNT: int = 0
_LLM_CALL_COUNT_LOCK = threading.Lock()


def get_llm_call_count() -> int:
    """Return total number of LLM provider invocations since process start."""
    return _LLM_CALL_COUNT


def reset_llm_call_count() -> None:
    """Reset counter to zero (test hook)."""
    global _LLM_CALL_COUNT
    with _LLM_CALL_COUNT_LOCK:
        _LLM_CALL_COUNT = 0


def _increment_llm_call_count() -> None:
    global _LLM_CALL_COUNT
    with _LLM_CALL_COUNT_LOCK:
        _LLM_CALL_COUNT += 1


# ── Live LLM usage telemetry ───────────────────────────────────
# TUI/operator visibility needs more than call counts: it should expose
# provider/model plus token/cost usage while the scan is still running.
# Costs are estimates unless the upstream provider returns exact usage.
_LLM_USAGE_LOCK = threading.Lock()
_LLM_USAGE_STATS: dict[str, Any] = {
    "provider": "",
    "model": "",
    "calls": 0,
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
    "cost_usd": 0.0,
    "tokens_estimated": False,
    "cost_estimated": False,
    # Per-call rows {model, role, input_tokens, output_tokens} — the data behind
    # the per-model×role cost panel (the single-bucket fields above only keep the
    # last provider/model, which is useless when a hybrid scan mixes models).
    "rows": [],
}


def get_llm_usage_stats() -> dict[str, Any]:
    """Return cumulative LLM usage telemetry for the current process.

    ``rows`` is returned as a fresh copy so a reader can iterate it without
    racing the recording thread that appends to the live list.
    """
    with _LLM_USAGE_LOCK:
        snapshot = dict(_LLM_USAGE_STATS)
        snapshot["rows"] = list(_LLM_USAGE_STATS.get("rows", []))
        return snapshot


def reset_llm_usage_stats() -> None:
    """Reset live LLM usage telemetry (test + per-scan hook)."""
    with _LLM_USAGE_LOCK:
        _LLM_USAGE_STATS.update({
            "provider": "",
            "model": "",
            "calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "cost_usd": 0.0,
            "tokens_estimated": False,
            "cost_estimated": False,
            "rows": [],
        })


def llm_health_warning(call_count: int, usage_stats: dict[str, Any]) -> str | None:
    """Return a loud, actionable warning when LLM calls were attempted but NONE
    succeeded — otherwise None.

    `_record_llm_usage` only fires on a successful response, so `call_count > 0`
    (calls entered the choke point) with `usage_stats["calls"] == 0` (none
    recorded) means every provider call failed and the Brain never produced a
    decision. The scan's "0 findings" then reflects a dead Brain, not a clean
    target, and must be surfaced instead of reported as a completed scan."""
    if call_count > 0 and int(usage_stats.get("calls", 0)) == 0:
        return (
            f"Brain produced NO output: all {call_count} LLM call(s) failed "
            f"(0 succeeded, 0 tokens). The scan result is NOT valid — '0 findings' "
            f"reflects a dead Brain, not a clean target. Likely cause: provider "
            f"auth / model / quota (e.g. gemini-2.5-pro needs a paid plan — use "
            f"gemini-2.5-flash on the free tier). See logs/scan_*.log for the "
            f"per-call error."
        )
    return None


def _estimate_token_count(value: Any) -> int:
    """Cheap text-length proxy when providers do not return token usage."""
    if value is None:
        return 0
    if isinstance(value, (dict, list, tuple)):
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            text = str(value)
    else:
        text = str(value)
    if not text:
        return 0
    return max(1, len(text) // 4)


def _estimate_usage_cost(provider: str, total_tokens: int) -> tuple[float, bool]:
    """Return an estimated cost using coarse provider-level defaults.

    We intentionally label these as estimates in the UI; exact per-model
    billing is not yet wired into the scan runtime.
    """
    if total_tokens <= 0:
        return 0.0, False
    if provider in {"ollama", "llamacpp", "claude-cli", "gemini-cli", "codex-cli"}:
        return 0.0, False
    per_million = {
        "openai": 0.15,
        "together": 0.50,
        "anthropic": 3.00,
        "gemini": 0.0,
    }.get(provider)
    if per_million is None:
        return 0.0, False
    return round(per_million * total_tokens / 1_000_000, 4), True


def _record_llm_usage(
    provider: str,
    model: str,
    system_prompt: Any,
    user_prompt: Any,
    response_text: Any,
    usage: dict[str, Any] | None = None,
    role: str = "?",
) -> None:
    """Accumulate live usage telemetry from a single LLM call.

    ``role`` (director/worker/verifier/summarizer) groups the cost panel by
    model×role; it defaults to "?" until the brain call sites thread it through.
    """
    usage = usage or {}
    input_tokens = int(
        usage.get("prompt_tokens")
        or usage.get("input_tokens")
        or usage.get("promptTokenCount")
        or 0
    )
    output_tokens = int(
        usage.get("completion_tokens")
        or usage.get("output_tokens")
        or usage.get("candidatesTokenCount")
        or usage.get("outputTokenCount")
        or 0
    )
    tokens_estimated = False
    if input_tokens <= 0:
        input_tokens = _estimate_token_count(system_prompt) + _estimate_token_count(user_prompt)
        tokens_estimated = True
    if output_tokens <= 0:
        output_tokens = _estimate_token_count(response_text)
        tokens_estimated = True
    total_tokens = input_tokens + output_tokens
    cost_usd, cost_estimated = _estimate_usage_cost(provider, total_tokens)

    with _LLM_USAGE_LOCK:
        _LLM_USAGE_STATS["provider"] = provider
        _LLM_USAGE_STATS["model"] = model
        _LLM_USAGE_STATS["calls"] = int(_LLM_USAGE_STATS.get("calls", 0)) + 1
        _LLM_USAGE_STATS["input_tokens"] = int(_LLM_USAGE_STATS.get("input_tokens", 0)) + input_tokens
        _LLM_USAGE_STATS["output_tokens"] = int(_LLM_USAGE_STATS.get("output_tokens", 0)) + output_tokens
        _LLM_USAGE_STATS["total_tokens"] = int(_LLM_USAGE_STATS.get("total_tokens", 0)) + total_tokens
        _LLM_USAGE_STATS["cost_usd"] = round(float(_LLM_USAGE_STATS.get("cost_usd", 0.0)) + cost_usd, 4)
        _LLM_USAGE_STATS["tokens_estimated"] = bool(_LLM_USAGE_STATS.get("tokens_estimated", False) or tokens_estimated)
        _LLM_USAGE_STATS["cost_estimated"] = bool(_LLM_USAGE_STATS.get("cost_estimated", False) or cost_estimated)
        _LLM_USAGE_STATS.setdefault("rows", []).append({
            "model": model,
            "role": role,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        })
