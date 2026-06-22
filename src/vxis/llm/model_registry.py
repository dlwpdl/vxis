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
import os


@dataclass(frozen=True)
class ModelInfo:
    """Canonical metadata for a single LLM model."""

    model_id: str
    provider: str                   # "openai" | "anthropic" | "gemini" | "together" | "ollama" | "llamacpp"
    context_window: int             # max total tokens (input + output)
    max_output_tokens: int          # max completion tokens
    supports_vision: bool = False
    supports_json_mode: bool = False
    reasoning_model: bool = False   # consumes reasoning tokens (max_completion_tokens required)
    family: str = ""                # e.g. "gpt-5.4", "claude-4.6", "gemini-3.1"
    aliases: tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""
    release_date: str = ""          # ISO date (from live catalog); "" for curated/unknown


@dataclass(frozen=True)
class CompressionPolicy:
    """Prompt history compression policy for a runtime/model pair."""

    context_window: int
    compress_threshold_tokens: int
    preserve_recent_messages: int
    chunk_size: int
    summary_max_words: int = 300
    recent_full_iterations: int = 3
    output_token_cap: int = 8_000
    allow_long_context: bool = False
    profile: str = "balanced"


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
        model_id="claude-opus-4-8",
        provider="anthropic",
        context_window=1_000_000,     # 1M max tier
        max_output_tokens=64_000,
        supports_vision=True,
        supports_json_mode=False,     # Anthropic uses tool_use for structured output
        reasoning_model=False,
        family="claude-4.8",
        aliases=("claude-opus-4-8[1m]",),
        notes="Anthropic flagship — 1M context in max tier (recommended default)",
    ),
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
        notes="Prior flagship — kept for compatibility; live catalog supplies newer ids",
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
    # ── llama.cpp (local OpenAI-compatible server) ────────────
    ModelInfo(
        model_id="huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m",
        provider="llamacpp",
        context_window=8_192,
        max_output_tokens=4_096,
        supports_vision=False,
        supports_json_mode=False,
        reasoning_model=False,
        family="huihui-qwen3.6",
        aliases=("huihui-qwen3.6-35b-a3b",),
        notes="Run via local llama-server; on 64GB Macs start at 2048 context even though the model can be configured higher.",
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


# Recommended default ("flagship") model per provider — the single source other
# modules (brain failover chain, hybrid config) reference instead of hardcoding,
# so a model upgrade is a one-line edit here. Each value MUST be a registered id.
_FLAGSHIP: dict[str, str] = {
    "anthropic": "claude-opus-4-8",
    "openai": "gpt-5.4",
    # GA model, not the -preview (preview/limited models aren't callable with a
    # standard key → silent 0-finding scans). Live catalog still surfaces newer GA ids.
    "gemini": "gemini-2.5-pro",
    "together": "moonshotai/Kimi-K2.5",
    "deepseek": "deepseek-ai/DeepSeek-R1-0528",
}


def flagship(provider: str) -> str | None:
    """Recommended default model id for *provider* (case-insensitive); None if
    the provider has no curated flagship."""
    return _FLAGSHIP.get((provider or "").strip().lower())


def _runtime_context_window(provider: str, model_id: str) -> int:
    """Resolve the effective runtime context window for compression decisions."""
    provider = (provider or "").lower()

    if provider == "llamacpp":
        override = os.environ.get("VXIS_LLAMACPP_CONTEXT", "").strip()
        if override.isdigit():
            return max(512, int(override))
        return min(get_context_window(model_id, default=8_192), 8_192)

    if provider == "ollama":
        override = os.environ.get("VXIS_OLLAMA_CONTEXT", "").strip()
        if override.isdigit():
            return max(512, int(override))
        return get_context_window(model_id, default=32_000)

    return get_context_window(model_id, default=128_000)


def get_compression_policy(provider: str, model_id: str) -> CompressionPolicy:
    """Return model-aware history compression settings."""
    provider = (provider or "").lower()
    if provider == "google":
        provider = "gemini"

    context_window = _runtime_context_window(provider, model_id)

    if provider == "llamacpp":
        threshold = max(900, min(context_window - 768, int(context_window * 0.45)))
        return CompressionPolicy(
            context_window=context_window,
            compress_threshold_tokens=threshold,
            preserve_recent_messages=5,
            chunk_size=5,
            summary_max_words=180,
            recent_full_iterations=1,
            output_token_cap=max(512, min(2_048, int(context_window * 0.18))),
            allow_long_context=False,
            profile="local-small",
        )

    if provider == "ollama":
        threshold = max(2_000, min(context_window - 1_024, int(context_window * 0.65)))
        return CompressionPolicy(
            context_window=context_window,
            compress_threshold_tokens=threshold,
            preserve_recent_messages=8,
            chunk_size=8,
            summary_max_words=220,
            recent_full_iterations=2,
            output_token_cap=max(1_024, min(4_096, int(context_window * 0.18))),
            allow_long_context=False,
            profile="local-medium",
        )

    if provider in {"openai", "anthropic", "gemini", "together", "deepseek"}:
        segment_cap = _context_segment_cap()
        threshold = max(12_000, min(segment_cap, int(context_window * 0.85)))
        return CompressionPolicy(
            context_window=context_window,
            compress_threshold_tokens=threshold,
            preserve_recent_messages=12,
            chunk_size=10,
            summary_max_words=220,
            recent_full_iterations=4,
            output_token_cap=8_000,
            allow_long_context=True,
            profile="cloud-segmented",
        )

    return CompressionPolicy(
        context_window=context_window,
        compress_threshold_tokens=max(8_000, int(context_window * 0.75)),
        preserve_recent_messages=12,
        chunk_size=8,
        recent_full_iterations=3,
        output_token_cap=4_000,
        allow_long_context=False,
        profile="balanced",
    )


def _context_segment_cap() -> int:
    raw = os.environ.get("VXIS_CONTEXT_SEGMENT_TOKENS", "").strip()
    if raw:
        try:
            value = int(raw)
        except ValueError:
            value = 200_000
    else:
        value = 200_000
    return max(32_000, min(300_000, value))


__all__ = [
    "CompressionPolicy",
    "ModelInfo",
    "get_compression_policy",
    "get_model_info",
    "get_context_window",
    "get_max_output_tokens",
    "supports_vision",
    "is_reasoning_model",
    "supports_json_mode",
    "list_models",
    "flagship",
]
