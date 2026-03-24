"""
Upstream Watch — LLM provider abstraction.

Together.ai as the unified gateway (Kimi-K2.5, GLM-5, Llama, Qwen, DeepSeek, etc.)
plus direct access to Claude, Gemini, and OpenAI.

Zero external dependencies — uses urllib from stdlib only.

Configuration via environment variables:
    UPSTREAM_LLM_PROVIDER   — Provider name (default: "together")
    UPSTREAM_LLM_MODEL      — Model name or shortcut (optional, see TOGETHER_MODELS)
    UPSTREAM_LLM_API_KEY    — API key (falls back to provider-specific env vars)

Supported providers & default models:
    together   → Together.ai   — moonshotai/Kimi-K2.5 (default)
                                  Also: zai-org/GLM-5, DeepSeek-R1, Llama-3.3, Qwen-72B, ...
    anthropic  → Claude        — claude-sonnet-4-20250514
    google     → Gemini        — gemini-2.5-flash
    openai     → OpenAI        — gpt-4o-mini
    deepseek   → DeepSeek      — deepseek-chat (direct API)
    kimi       → Moonshot      — kimi-k2.5 (direct API)
    glm        → Zhipu / Z.AI  — glm-5 (direct API)

Together.ai model shortcuts (use as UPSTREAM_LLM_MODEL value):
    kimi-k2.5, glm-5, qwen-72b, llama-70b, deepseek-r1, deepseek-v3, gemma-27b
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
import urllib.error
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ── Provider Configs ────────────────────────────────────────────

_PROVIDERS: dict[str, dict[str, str]] = {
    # ── Together.ai: unified gateway for 200+ models ──
    # Default model: Kimi-K2.5 via Together (best value for code/reasoning)
    "together": {
        "base_url": "https://api.together.xyz/v1",
        "default_model": "moonshotai/Kimi-K2.5",
        "env_key": "TOGETHER_API_KEY",
        "format": "openai",
    },
    # ── Direct provider APIs ──
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "default_model": "claude-sonnet-4-20250514",
        "env_key": "ANTHROPIC_API_KEY",
        "format": "anthropic",
    },
    "google": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "default_model": "gemini-2.5-flash",
        "env_key": "GOOGLE_API_KEY",
        "format": "gemini",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini",
        "env_key": "OPENAI_API_KEY",
        "format": "openai",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "env_key": "DEEPSEEK_API_KEY",
        "format": "openai",
    },
    # Kimi direct API (platform.moonshot.ai)
    "kimi": {
        "base_url": "https://api.moonshot.cn/v1",
        "default_model": "kimi-k2.5",
        "env_key": "MOONSHOT_API_KEY",
        "format": "openai",
    },
    # GLM direct API — international: api.z.ai, China: open.bigmodel.cn
    "glm": {
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "default_model": "glm-5",
        "env_key": "ZHIPU_API_KEY",
        "format": "openai",
    },
}

# Together.ai model shortcuts — use with UPSTREAM_LLM_MODEL env var
# Full list: https://docs.together.ai/docs/serverless-models
TOGETHER_MODELS = {
    # ── Flagship models (via Together) ──
    "kimi-k2.5": "moonshotai/Kimi-K2.5",       # 1T params, 32B active, MoE
    "glm-5": "zai-org/GLM-5",                   # 744B params, 40B active, MoE
    # ── Other strong models ──
    "qwen-72b": "Qwen/Qwen2.5-72B-Instruct-Turbo",
    "qwen-7b": "Qwen/Qwen2.5-7B-Instruct-Turbo",
    "llama-70b": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "llama-8b": "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
    "deepseek-r1": "deepseek-ai/DeepSeek-R1",
    "deepseek-v3": "deepseek-ai/DeepSeek-V3",
    "gemma-27b": "google/gemma-2-27b-it",
}


@dataclass
class LLMResponse:
    """Unified response from any LLM provider."""
    text: str
    model: str
    provider: str


def _get_provider() -> str:
    return os.environ.get("UPSTREAM_LLM_PROVIDER", "together").lower()


def _get_api_key() -> str:
    """Resolve API key: UPSTREAM_LLM_API_KEY → provider-specific → fallbacks."""
    key = os.environ.get("UPSTREAM_LLM_API_KEY", "")
    if key:
        return key

    provider = _get_provider()
    cfg = _PROVIDERS.get(provider, {})
    env_key = cfg.get("env_key", "")
    if env_key:
        key = os.environ.get(env_key, "")
        if key:
            return key

    # Fallback chain: TOGETHER → ANTHROPIC → OPENAI
    for fallback in ("TOGETHER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        key = os.environ.get(fallback, "")
        if key:
            return key

    return ""


def _get_model() -> str:
    override = os.environ.get("UPSTREAM_LLM_MODEL", "")
    if override:
        # Check shortcuts for together.ai
        if _get_provider() == "together" and override in TOGETHER_MODELS:
            return TOGETHER_MODELS[override]
        return override
    provider = _get_provider()
    return _PROVIDERS.get(provider, {}).get(
        "default_model", "Qwen/Qwen2.5-72B-Instruct-Turbo"
    )


def is_available() -> bool:
    """Return True if an LLM API key is configured."""
    return bool(_get_api_key())


def _try_provider(
    provider: str,
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
) -> LLMResponse | None:
    """Attempt a single provider call."""
    cfg = _PROVIDERS.get(provider, _PROVIDERS["together"])
    fmt = cfg.get("format", "openai")

    if fmt == "anthropic":
        return _call_anthropic(api_key, model, system_prompt, user_prompt, max_tokens)
    elif fmt == "gemini":
        return _call_gemini(api_key, model, system_prompt, user_prompt, max_tokens)
    else:
        return _call_openai_compat(
            api_key, model, provider,
            cfg["base_url"], system_prompt, user_prompt, max_tokens,
        )


def chat(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 2000,
) -> LLMResponse | None:
    """
    Send a chat completion request to the configured LLM provider.
    If the primary provider fails, automatically falls back to other
    providers that have API keys configured.

    Returns None if no API key is set or all providers fail.
    """
    primary_provider = _get_provider()
    primary_key = _get_api_key()
    if not primary_key:
        return None

    model = _get_model()

    # Try primary provider first
    try:
        result = _try_provider(primary_provider, primary_key, model, system_prompt, user_prompt, max_tokens)
        if result is not None:
            return result
    except Exception as exc:
        logger.warning("Primary LLM failed (%s/%s): %s", primary_provider, model, exc)

    # Fallback chain: try other providers that have keys
    _FALLBACK_ORDER = [
        ("google", "GOOGLE_API_KEY"),
        ("anthropic", "ANTHROPIC_API_KEY"),
        ("openai", "OPENAI_API_KEY"),
        ("deepseek", "DEEPSEEK_API_KEY"),
        ("together", "TOGETHER_API_KEY"),
    ]

    for fb_provider, fb_env in _FALLBACK_ORDER:
        if fb_provider == primary_provider:
            continue
        fb_key = os.environ.get(fb_env, "")
        if not fb_key:
            continue

        fb_cfg = _PROVIDERS[fb_provider]
        fb_model = fb_cfg["default_model"]
        logger.info("Falling back to %s/%s", fb_provider, fb_model)

        try:
            result = _try_provider(fb_provider, fb_key, fb_model, system_prompt, user_prompt, max_tokens)
            if result is not None:
                return result
        except Exception as exc:
            logger.warning("Fallback LLM failed (%s/%s): %s", fb_provider, fb_model, exc)
            continue

    logger.warning("All LLM providers failed")
    return None


# ── OpenAI-compatible (Together, OpenAI, DeepSeek, Kimi, GLM) ──

def _call_openai_compat(
    api_key: str,
    model: str,
    provider: str,
    base_url: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
) -> LLMResponse | None:
    url = f"{base_url}/chat/completions"
    payload = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "VXIS-Upstream-Watch/1.0",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        logger.warning("LLM HTTP %d from %s: %s", e.code, provider, body)
        return None

    choices = data.get("choices", [])
    if not choices:
        return None

    text = choices[0].get("message", {}).get("content", "")
    return LLMResponse(text=text, model=model, provider=provider)


# ── Anthropic Claude ────────────────────────────────────────────

def _call_anthropic(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
) -> LLMResponse | None:
    url = "https://api.anthropic.com/v1/messages"
    payload = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "User-Agent": "VXIS-Upstream-Watch/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        logger.warning("Anthropic HTTP %d: %s", e.code, body)
        return None

    content = data.get("content", [])
    if not content:
        return None

    text = content[0].get("text", "")
    return LLMResponse(text=text, model=model, provider="anthropic")


# ── Google Gemini ───────────────────────────────────────────────

def _call_gemini(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
) -> LLMResponse | None:
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/"
        f"models/{model}:generateContent?key={api_key}"
    )
    payload = json.dumps({
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"parts": [{"text": user_prompt}]}],
        "generationConfig": {"maxOutputTokens": max_tokens},
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "VXIS-Upstream-Watch/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        logger.warning("Gemini HTTP %d: %s", e.code, body)
        return None

    candidates = data.get("candidates", [])
    if not candidates:
        return None

    parts = candidates[0].get("content", {}).get("parts", [])
    if not parts:
        return None

    text = parts[0].get("text", "")
    return LLMResponse(text=text, model=model, provider="google")
