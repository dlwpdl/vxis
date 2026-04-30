from __future__ import annotations

import asyncio

from vxis.agent.memory_compressor import compress_history
from vxis.llm.model_registry import get_compression_policy


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


def test_cloud_compression_policy_is_late() -> None:
    policy = get_compression_policy("openai", "gpt-4o")

    assert policy.compress_threshold_tokens >= 100_000
    assert policy.preserve_recent_messages == 15


def test_compress_history_uses_model_policy_for_llamacpp() -> None:
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
