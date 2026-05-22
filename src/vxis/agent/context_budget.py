"""Context budget helpers for director and worker prompts.

The model context window is not the budget. VXIS keeps role-specific ceilings
so frontier directors, local directors, worker agents, verifiers, and
summarizers do not silently grow into expensive or unreadable prompts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable


_LOCAL_PROVIDERS = {"llamacpp", "ollama"}
_ROLE_ALIASES = {
    "director": "director",
    "root": "director",
    "worker": "worker",
    "subagent": "worker",
    "sub_agent": "worker",
    "recon_worker": "worker",
    "exploit_worker": "worker",
    "post_exploit_worker": "worker",
    "review_worker": "worker",
    "verifier": "verifier",
    "judge": "verifier",
    "summarizer": "summarizer",
    "summary": "summarizer",
}
_FRONTIER_ROLE_CEILINGS = {
    "director": 300_000,
    "worker": 32_000,
    "verifier": 24_000,
    "summarizer": 12_000,
}
_LOCAL_ROLE_CEILINGS = {
    "director": 6_000,
    "worker": 3_500,
    "verifier": 4_000,
    "summarizer": 2_200,
}
_ROLE_CONTEXT_FRACTIONS = {
    "director": 0.68,
    "worker": 0.32,
    "verifier": 0.38,
    "summarizer": 0.25,
}
_ROLE_HISTORY_FRACTIONS = {
    "director": 0.38,
    "worker": 0.24,
    "verifier": 0.22,
    "summarizer": 0.18,
}


@dataclass(frozen=True)
class RoleContextBudget:
    role: str
    provider: str
    model: str
    context_window: int
    max_prompt_tokens: int
    history_tokens: int
    max_skill_chars: int
    max_message_chars: int
    max_execution_chars: int
    max_agent_messages: int
    max_agent_executions: int
    local_profile: bool = False


def normalize_context_role(role: Any) -> str:
    text = str(getattr(role, "value", role) or "director").strip().lower()
    return _ROLE_ALIASES.get(text, text if text in _FRONTIER_ROLE_CEILINGS else "director")


def estimate_context_tokens(value: Any) -> int:
    """Deterministic rough token estimate used by prompt guards and audits."""
    if value is None:
        return 0
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)
        except Exception:
            text = str(value)
    if not text:
        return 0
    encoded_len = len(text.encode("utf-8", errors="ignore"))
    return max(1, len(text) // 4, encoded_len // 3)


def resolve_context_budget(
    role: Any,
    *,
    provider: str = "",
    model: str = "",
    context_window: int | None = None,
) -> RoleContextBudget:
    role_name = normalize_context_role(role)
    provider_name = str(provider or "").strip().lower()
    model_name = str(model or "").strip()
    resolved_window = _resolve_context_window(
        provider=provider_name,
        model=model_name,
        context_window=context_window,
    )
    local_profile = provider_name in _LOCAL_PROVIDERS or resolved_window <= 16_384
    ceilings = _LOCAL_ROLE_CEILINGS if local_profile else _FRONTIER_ROLE_CEILINGS
    role_ceiling = ceilings[role_name]
    window_fraction = _ROLE_CONTEXT_FRACTIONS[role_name]
    max_prompt = min(role_ceiling, max(512, int(resolved_window * window_fraction)))
    if resolved_window > 0:
        output_reserve = max(384, min(8_000, int(resolved_window * (0.20 if local_profile else 0.12))))
        max_prompt = min(max_prompt, max(512, resolved_window - output_reserve))
    history_tokens = max(128, int(max_prompt * _ROLE_HISTORY_FRACTIONS[role_name]))
    return RoleContextBudget(
        role=role_name,
        provider=provider_name,
        model=model_name,
        context_window=resolved_window,
        max_prompt_tokens=max_prompt,
        history_tokens=history_tokens,
        max_skill_chars=_skill_char_budget(role_name, local_profile=local_profile),
        max_message_chars=_message_char_budget(role_name, local_profile=local_profile),
        max_execution_chars=_execution_char_budget(role_name, local_profile=local_profile),
        max_agent_messages=3 if role_name == "worker" or local_profile else 6,
        max_agent_executions=3 if role_name == "worker" or local_profile else 5,
        local_profile=local_profile,
    )


def trim_text_to_token_budget(text: Any, max_tokens: int, *, marker: str = "...truncated...") -> str:
    clean = str(text or "")
    max_tokens = int(max_tokens or 0)
    if max_tokens <= 0 or estimate_context_tokens(clean) <= max_tokens:
        return clean
    max_chars = max(0, max_tokens * 3)
    suffix = "\n" + marker if marker else ""
    trimmed = clean[: max(0, max_chars - len(suffix))].rstrip() + suffix
    while trimmed and estimate_context_tokens(trimmed) > max_tokens:
        trimmed = trimmed[: max(0, int(len(trimmed) * 0.9))].rstrip() + suffix
    return trimmed


def fit_lines_to_token_budget(
    lines: Iterable[str],
    max_tokens: int,
    *,
    prefer_recent: bool = True,
    marker: str = "PROMPT-BUDGET COMPACTION",
) -> list[str]:
    items = [str(line or "") for line in lines]
    max_tokens = max(1, int(max_tokens or 1))
    if sum(estimate_context_tokens(line) for line in items) <= max_tokens:
        return items
    source = list(reversed(items)) if prefer_recent else list(items)
    kept: list[str] = []
    used = 0
    for line in source:
        tokens = estimate_context_tokens(line)
        if not kept and tokens > max_tokens:
            line = trim_text_to_token_budget(line, max_tokens, marker="...line truncated...")
            tokens = estimate_context_tokens(line)
        if kept and used + tokens > max_tokens:
            break
        kept.append(line)
        used += tokens
    if prefer_recent:
        kept = list(reversed(kept))
    omitted = len(items) - len(kept)
    if omitted > 0:
        kept.insert(0, f"[system] {marker}: {omitted} older line(s) omitted")
    return kept


def trim_text_chars(text: Any, max_chars: int, *, marker: str = "...truncated...") -> str:
    clean = str(text or "")
    max_chars = int(max_chars or 0)
    if max_chars <= 0 or len(clean) <= max_chars:
        return clean
    suffix = "\n" + marker if marker else ""
    return clean[: max(0, max_chars - len(suffix))].rstrip() + suffix


def compact_context_value(value: Any, *, max_chars: int = 1_200, max_depth: int = 3) -> Any:
    """Recursively compact tool-result payloads before they enter prompts."""
    if max_depth <= 0:
        return trim_text_chars(value, max_chars=max_chars)
    if isinstance(value, str):
        return trim_text_chars(value, max_chars=max_chars)
    if isinstance(value, list):
        return [
            compact_context_value(item, max_chars=max_chars, max_depth=max_depth - 1)
            for item in value[:20]
        ]
    if isinstance(value, tuple):
        return [
            compact_context_value(item, max_chars=max_chars, max_depth=max_depth - 1)
            for item in value[:20]
        ]
    if isinstance(value, dict):
        compacted: dict[str, Any] = {}
        for idx, (key, item) in enumerate(value.items()):
            if idx >= 40:
                compacted["..."] = f"{len(value) - idx} key(s) omitted"
                break
            compacted[str(key)] = compact_context_value(
                item,
                max_chars=max_chars,
                max_depth=max_depth - 1,
            )
        return compacted
    return value


def _resolve_context_window(*, provider: str, model: str, context_window: int | None) -> int:
    if context_window is not None and int(context_window) > 0:
        return int(context_window)
    try:
        from vxis.llm.model_registry import get_compression_policy

        policy = get_compression_policy(provider, model)
        if int(policy.context_window or 0) > 0:
            return int(policy.context_window)
    except Exception:
        pass
    return 8_192 if provider in _LOCAL_PROVIDERS else 300_000


def _skill_char_budget(role: str, *, local_profile: bool) -> int:
    if local_profile:
        return 700 if role == "worker" else 900
    return {
        "director": 2_200,
        "worker": 1_400,
        "verifier": 1_200,
        "summarizer": 700,
    }[role]


def _message_char_budget(role: str, *, local_profile: bool) -> int:
    if local_profile:
        return 700 if role == "worker" else 1_000
    return {
        "director": 2_000,
        "worker": 900,
        "verifier": 1_200,
        "summarizer": 700,
    }[role]


def _execution_char_budget(role: str, *, local_profile: bool) -> int:
    if local_profile:
        return 900 if role == "worker" else 1_400
    return {
        "director": 4_000,
        "worker": 1_200,
        "verifier": 1_800,
        "summarizer": 900,
    }[role]


__all__ = [
    "RoleContextBudget",
    "compact_context_value",
    "estimate_context_tokens",
    "fit_lines_to_token_budget",
    "normalize_context_role",
    "resolve_context_budget",
    "trim_text_chars",
    "trim_text_to_token_budget",
]
