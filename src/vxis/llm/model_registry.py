"""Model registry — canonical source for model IDs, context windows, and vision support.

All other modules should look up model capabilities here instead of hardcoding
values. Keep this file in sync with provider documentation whenever a model is
added, deprecated, or upgraded.

Sources:
    OpenAI:    https://developers.openai.com/api/docs/guides/latest-model
    Anthropic: https://docs.anthropic.com/en/docs/about-claude/models
    Google:    https://ai.google.dev/gemini-api/docs/models
    Together:  https://docs.together.ai/docs/serverless-models
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ModelInfo:
    """Canonical metadata for a single LLM model."""

    model_id: str
    provider: str                   # "openai" | "anthropic" | "gemini" | "together" | "ollama"
    context_window: int             # max total tokens (input + output)
    max_output_tokens: int          # max completion tokens
    supports_vision: bool = False
    supports_json_mode: bool = False
    reasoning_model: bool = False   # consumes reasoning tokens (max_completion_tokens required)
    family: str = ""                # e.g. "gpt-5.4", "claude-4.6", "gemini-3.1"
    aliases: tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""


# ---------------------------------------------------------------------------
# Registry — verified 2026-04-07 against provider docs
# ---------------------------------------------------------------------------

_MODELS: tuple[ModelInfo, ...] = (
    # ── OpenAI ────────────────────────────────────────────────
    ModelInfo(
        model_id="gpt-5.4",
        provider="openai",
        context_window=1_050_000,     # 1.05M (xhigh tier)
        max_output_tokens=64_000,
        supports_vision=True,
        supports_json_mode=True,
        reasoning_model=True,
        family="gpt-5.4",
        aliases=("gpt-5.4-xhigh",),
        notes="OpenAI flagship reasoning model, 1.05M context in xhigh tier",
    ),
    ModelInfo(
        model_id="gpt-5.4-mini",
        provider="openai",
        context_window=400_000,
        max_output_tokens=32_000,
        supports_vision=True,
        supports_json_mode=True,
        reasoning_model=True,
        family="gpt-5.4",
        aliases=("gpt-5.4-mini-xhigh", "gpt-5.4-mini-2026-03-17"),
        notes="Cost-efficient reasoning model, 400k context",
    ),
    ModelInfo(
        model_id="gpt-4o",
        provider="openai",
        context_window=128_000,
        max_output_tokens=16_000,
        supports_vision=True,
        supports_json_mode=True,
        reasoning_model=False,
        family="gpt-4o",
    ),
    ModelInfo(
        model_id="gpt-4o-mini",
        provider="openai",
        context_window=128_000,
        max_output_tokens=16_000,
        supports_vision=True,
        supports_json_mode=True,
        reasoning_model=False,
        family="gpt-4o",
    ),
    # ── Anthropic ─────────────────────────────────────────────
    ModelInfo(
        model_id="claude-opus-4-6",
        provider="anthropic",
        context_window=1_000_000,     # 1M max tier
        max_output_tokens=64_000,
        supports_vision=True,
        supports_json_mode=False,     # Anthropic uses tool_use for structured output
        reasoning_model=False,
        family="claude-4.6",
        aliases=("claude-opus-4-6[1m]",),
        notes="Anthropic flagship — 1M context in max tier",
    ),
    ModelInfo(
        model_id="claude-sonnet-4-6",
        provider="anthropic",
        context_window=1_000_000,     # 1M max tier
        max_output_tokens=64_000,
        supports_vision=True,
        supports_json_mode=False,
        reasoning_model=False,
        family="claude-4.6",
    ),
    ModelInfo(
        model_id="claude-haiku-4-5-20251001",
        provider="anthropic",
        context_window=200_000,
        max_output_tokens=8_000,
        supports_vision=True,
        supports_json_mode=False,
        reasoning_model=False,
        family="claude-4.5",
    ),
    # ── Google Gemini ─────────────────────────────────────────
    ModelInfo(
        model_id="gemini-3.1-pro-preview",
        provider="gemini",
        context_window=1_000_000,
        max_output_tokens=64_000,
        supports_vision=True,
        supports_json_mode=True,
        reasoning_model=False,
        family="gemini-3.1",
        aliases=("gemini-3.1-pro",),
        notes="1M context preview — limited availability on free tier",
    ),
    ModelInfo(
        model_id="gemini-2.5-pro",
        provider="gemini",
        context_window=2_000_000,
        max_output_tokens=64_000,
        supports_vision=True,
        supports_json_mode=True,
        reasoning_model=False,
        family="gemini-2.5",
    ),
    ModelInfo(
        model_id="gemini-2.5-flash",
        provider="gemini",
        context_window=1_000_000,
        max_output_tokens=64_000,
        supports_vision=True,
        supports_json_mode=True,
        reasoning_model=False,
        family="gemini-2.5",
    ),
    # ── Together.ai ───────────────────────────────────────────
    ModelInfo(
        model_id="zai-org/GLM-5",
        provider="together",
        context_window=200_000,
        max_output_tokens=16_000,
        supports_vision=False,
        supports_json_mode=True,
        reasoning_model=True,
        family="glm-5",
        aliases=("glm-5",),
        notes="Strong safety guardrails — often refuses offensive security prompts",
    ),
    ModelInfo(
        model_id="moonshotai/Kimi-K2.5",
        provider="together",
        context_window=256_000,
        max_output_tokens=32_000,
        supports_vision=False,
        supports_json_mode=True,
        reasoning_model=True,
        family="kimi-2.5",
        aliases=("kimi-k2.5",),
        notes="1T-param reasoning model, prone to truncated JSON under short max_tokens",
    ),
    ModelInfo(
        model_id="deepseek-ai/DeepSeek-V3.1",
        provider="together",
        context_window=128_000,
        max_output_tokens=16_000,
        supports_vision=False,
        supports_json_mode=True,
        reasoning_model=False,
        family="deepseek-v3",
    ),
    ModelInfo(
        model_id="deepseek-ai/DeepSeek-R1-0528",
        provider="together",
        context_window=128_000,
        max_output_tokens=16_000,
        supports_vision=False,
        supports_json_mode=True,
        reasoning_model=True,
        family="deepseek-r1",
    ),
    ModelInfo(
        model_id="Qwen/Qwen3-Coder-480B-A35B-Instruct-FP8",
        provider="together",
        context_window=256_000,
        max_output_tokens=16_000,
        supports_vision=False,
        supports_json_mode=True,
        reasoning_model=False,
        family="qwen3-coder",
    ),
    # ── Ollama (local uncensored) ─────────────────────────────
    ModelInfo(
        model_id="whiterabbitneo:13b",
        provider="ollama",
        context_window=32_000,
        max_output_tokens=8_000,
        supports_vision=False,
        supports_json_mode=False,
        reasoning_model=False,
        family="whiterabbitneo",
        notes="Uncensored, specifically tuned for offensive security research",
    ),
    ModelInfo(
        model_id="dolphin-mixtral:8x7b",
        provider="ollama",
        context_window=32_000,
        max_output_tokens=8_000,
        supports_vision=False,
        supports_json_mode=False,
        reasoning_model=False,
        family="dolphin",
        notes="Uncensored general-purpose",
    ),
)


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

_BY_ID: dict[str, ModelInfo] = {}
for _m in _MODELS:
    _BY_ID[_m.model_id.lower()] = _m
    for _alias in _m.aliases:
        _BY_ID[_alias.lower()] = _m


def get_model_info(model_id: str) -> ModelInfo | None:
    """Look up a model by id or alias (case-insensitive).

    Returns None if unknown. Callers should fall back to a sane default rather
    than crashing — unknown models may be user-configured via environment.
    """
    if not model_id:
        return None
    return _BY_ID.get(model_id.lower())


def get_context_window(model_id: str, default: int = 128_000) -> int:
    """Return the context window (total tokens) for a model id."""
    info = get_model_info(model_id)
    return info.context_window if info else default


def get_max_output_tokens(model_id: str, default: int = 4_000) -> int:
    """Return the max output (completion) tokens for a model id."""
    info = get_model_info(model_id)
    return info.max_output_tokens if info else default


def supports_vision(model_id: str) -> bool:
    """True if the model can accept image inputs."""
    info = get_model_info(model_id)
    return bool(info and info.supports_vision)


def is_reasoning_model(model_id: str) -> bool:
    """True if the model consumes reasoning tokens (max_completion_tokens required)."""
    info = get_model_info(model_id)
    return bool(info and info.reasoning_model)


def supports_json_mode(model_id: str) -> bool:
    """True if the model supports native JSON mode / structured output."""
    info = get_model_info(model_id)
    return bool(info and info.supports_json_mode)


def list_models(provider: str | None = None) -> list[ModelInfo]:
    """List all registered models, optionally filtered by provider."""
    if provider:
        return [m for m in _MODELS if m.provider == provider]
    return list(_MODELS)


__all__ = [
    "ModelInfo",
    "get_model_info",
    "get_context_window",
    "get_max_output_tokens",
    "supports_vision",
    "is_reasoning_model",
    "supports_json_mode",
    "list_models",
]
