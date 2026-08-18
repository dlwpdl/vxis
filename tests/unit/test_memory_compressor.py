from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

from vxis.agent.memory_compressor import compress_history
from vxis.agent.memory_compressor import _effective_policy_for_runtime
from vxis.agent.memory_compressor import get_memory_compression_stats
from vxis.agent.memory_compressor import reset_memory_compression_stats
from vxis.llm.model_registry import get_compression_policy
from vxis.llm.model_registry import detect_llamacpp_context


class _Response:
    def __init__(self, payload: dict) -> None:
        self._body = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return self._body


class _StubBrain:
    def __init__(self, provider: str, model: str) -> None:
        self._provider = provider
        self._model = model

    def _call_llm_with_fallback(self, system_prompt: str, user_prompt: str) -> str:
        return "compressed summary"


def test_llamacpp_compression_policy_is_aggressive() -> None:
    policy = get_compression_policy(
        "llamacpp",
        "huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m",
    )

    assert policy.compress_threshold_tokens <= 3_700
    assert policy.preserve_recent_messages == 5
    assert policy.chunk_size == 5
    assert policy.summary_max_words <= 180
    assert policy.recent_full_iterations == 1
    assert policy.output_token_cap <= 2048
    assert policy.allow_long_context is False
    assert policy.profile == "local-small"


def test_llamacpp_policy_detects_large_runtime_context(monkeypatch) -> None:
    monkeypatch.delenv("VXIS_LLAMACPP_CONTEXT", raising=False)
    monkeypatch.setenv("VXIS_LLAMACPP_BASE_URL", "http://localhost:8080")
    detect_llamacpp_context.cache_clear()
    models = {
        "data": [{
            "id": "local-model",
            "status": {"args": ["llama-server", "--ctx-size", "262144"]},
        }],
    }

    router_props = {"default_generation_settings": {"n_ctx": 0}}
    with patch(
        "vxis.llm.model_registry.urlopen",
        side_effect=[_Response(router_props), _Response(models)],
    ):
        policy = get_compression_policy("llamacpp", "local-model")

    assert policy.context_window == 262_144
    assert policy.compress_threshold_tokens > 100_000
    assert policy.allow_long_context is True
    assert policy.profile == "local-large"
    detect_llamacpp_context.cache_clear()


def test_cloud_compression_policy_is_segmented() -> None:
    policy = get_compression_policy("openai", "gpt-4o")

    assert policy.compress_threshold_tokens >= 100_000
    assert policy.compress_threshold_tokens <= 200_000
    assert policy.preserve_recent_messages == 12
    assert policy.recent_full_iterations >= 4
    assert policy.output_token_cap == 8000
    assert policy.allow_long_context is True
    assert policy.profile == "cloud-segmented"


def test_large_cloud_models_do_not_wait_for_full_context() -> None:
    policy = get_compression_policy("openai", "gpt-5.4")

    assert policy.context_window > 200_000
    assert policy.compress_threshold_tokens == 200_000


def test_compress_history_uses_model_policy_for_llamacpp() -> None:
    reset_memory_compression_stats()
    brain = _StubBrain(
        "llamacpp",
        "huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m",
    )
    messages = [
        {"role": "user", "content": "A" * 2000, "iter": i}
        for i in range(10)
    ]

    compressed = asyncio.run(compress_history(messages, brain))

    assert len(compressed) < len(messages)
    assert any(
        str(m.get("content", "")).startswith("[COMPRESSED HISTORY")
        for m in compressed
    )
    stats = get_memory_compression_stats()
    assert stats["checks"] >= 1
    assert stats["triggered"] >= 1
    assert stats["compressed_runs"] >= 1
    assert stats["llm_summary_runs"] >= 1
    assert stats["total_tokens_saved"] > 0
    assert stats["last_iter"] == 9


def test_local_runtime_policy_is_more_aggressive_than_registry_defaults() -> None:
    brain = _StubBrain(
        "llamacpp",
        "huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m",
    )
    base = get_compression_policy(brain._provider, brain._model)
    threshold, preserve_recent, chunk_size, summary_words = _effective_policy_for_runtime(base, brain)
    assert threshold < base.compress_threshold_tokens
    assert preserve_recent < base.preserve_recent_messages
    assert chunk_size < base.chunk_size
    assert summary_words < base.summary_max_words


def test_large_local_runtime_keeps_context_scaled_policy(monkeypatch) -> None:
    monkeypatch.setenv("VXIS_LLAMACPP_CONTEXT", "64000")
    brain = _StubBrain("llamacpp", "local-model")
    base = get_compression_policy(brain._provider, brain._model)

    assert _effective_policy_for_runtime(base, brain) == (
        base.compress_threshold_tokens,
        base.preserve_recent_messages,
        base.chunk_size,
        base.summary_max_words,
    )


def test_cloud_runtime_policy_keeps_registry_defaults() -> None:
    brain = _StubBrain("openai", "gpt-5.5")
    base = get_compression_policy(brain._provider, brain._model)
    threshold, preserve_recent, chunk_size, summary_words = _effective_policy_for_runtime(base, brain)
    assert threshold == base.compress_threshold_tokens
    assert preserve_recent == base.preserve_recent_messages
    assert chunk_size == base.chunk_size
    assert summary_words == base.summary_max_words


def test_compress_history_records_non_triggered_check_state() -> None:
    reset_memory_compression_stats()
    brain = _StubBrain("llamacpp", "local-qwen")
    messages = [{"role": "user", "content": "tiny", "iter": 1}]

    result = asyncio.run(compress_history(messages, brain))

    assert result == messages
    stats = get_memory_compression_stats()
    assert stats["checks"] == 1
    assert stats["triggered"] == 0
    assert stats["last_tokens_after"] == stats["last_tokens_before"]
    assert stats["last_messages_after"] == stats["last_messages_before"]
