"""LLM-based memory compression for scan loop — Strix pattern.

When the message history grows beyond a token threshold, older messages
are chunked and summarized by the LLM. Recent messages (last 15) are
always preserved verbatim. Summaries preserve:
- Discovered vulnerabilities and attack vectors
- Credentials, tokens, auth details
- Failed attempts (to avoid duplication)
- Endpoint map and architecture insights

This lets the scan run 2000+ iterations without losing critical context.
"""
from __future__ import annotations

import asyncio
import json
import logging
from copy import deepcopy
from typing import Any

from vxis.llm.model_registry import get_compression_policy

logger = logging.getLogger(__name__)

# Rough token estimate: 1 token ≈ 4 chars for English text
_CHARS_PER_TOKEN = 4
_MEMORY_COMPRESSION_STATS: dict[str, Any] = {
    "checks": 0,
    "triggered": 0,
    "compressed_runs": 0,
    "llm_summary_runs": 0,
    "total_messages_before": 0,
    "total_messages_after": 0,
    "total_tokens_before": 0,
    "total_tokens_after": 0,
    "total_tokens_saved": 0,
    "total_messages_saved": 0,
    "total_chunks": 0,
    "total_chunks_summarized": 0,
    "total_chunks_passthrough": 0,
    "last_iter": 0,
    "last_threshold": 0,
    "last_tokens_before": 0,
    "last_tokens_after": 0,
    "last_tokens_saved": 0,
    "last_messages_before": 0,
    "last_messages_after": 0,
    "last_messages_saved": 0,
}


def reset_memory_compression_stats() -> None:
    for key in list(_MEMORY_COMPRESSION_STATS):
        _MEMORY_COMPRESSION_STATS[key] = 0


def get_memory_compression_stats() -> dict[str, Any]:
    return deepcopy(_MEMORY_COMPRESSION_STATS)


def _last_iter(messages: list[dict[str, Any]]) -> int:
    for message in reversed(messages):
        try:
            return int(message.get("iter") or 0)
        except Exception:
            continue
    return 0


def _record_compression_check(*, total_tokens: int, threshold: int, messages: list[dict[str, Any]]) -> None:
    _MEMORY_COMPRESSION_STATS["checks"] += 1
    _MEMORY_COMPRESSION_STATS["last_iter"] = _last_iter(messages)
    _MEMORY_COMPRESSION_STATS["last_threshold"] = int(threshold)
    _MEMORY_COMPRESSION_STATS["last_tokens_before"] = int(total_tokens)
    _MEMORY_COMPRESSION_STATS["last_tokens_after"] = int(total_tokens)
    _MEMORY_COMPRESSION_STATS["last_tokens_saved"] = 0
    _MEMORY_COMPRESSION_STATS["last_messages_before"] = int(len(messages))
    _MEMORY_COMPRESSION_STATS["last_messages_after"] = int(len(messages))
    _MEMORY_COMPRESSION_STATS["last_messages_saved"] = 0


def _record_compression_result(
    *,
    total_tokens_before: int,
    total_tokens_after: int,
    messages_before: int,
    messages_after: int,
    chunks_total: int,
    chunks_summarized: int,
    chunks_passthrough: int,
) -> None:
    tokens_saved = max(0, int(total_tokens_before) - int(total_tokens_after))
    messages_saved = max(0, int(messages_before) - int(messages_after))
    _MEMORY_COMPRESSION_STATS["triggered"] += 1
    if tokens_saved > 0 or messages_saved > 0:
        _MEMORY_COMPRESSION_STATS["compressed_runs"] += 1
    if chunks_summarized > 0:
        _MEMORY_COMPRESSION_STATS["llm_summary_runs"] += 1
    _MEMORY_COMPRESSION_STATS["total_messages_before"] += int(messages_before)
    _MEMORY_COMPRESSION_STATS["total_messages_after"] += int(messages_after)
    _MEMORY_COMPRESSION_STATS["total_tokens_before"] += int(total_tokens_before)
    _MEMORY_COMPRESSION_STATS["total_tokens_after"] += int(total_tokens_after)
    _MEMORY_COMPRESSION_STATS["total_tokens_saved"] += tokens_saved
    _MEMORY_COMPRESSION_STATS["total_messages_saved"] += messages_saved
    _MEMORY_COMPRESSION_STATS["total_chunks"] += int(chunks_total)
    _MEMORY_COMPRESSION_STATS["total_chunks_summarized"] += int(chunks_summarized)
    _MEMORY_COMPRESSION_STATS["total_chunks_passthrough"] += int(chunks_passthrough)
    _MEMORY_COMPRESSION_STATS["last_tokens_after"] = int(total_tokens_after)
    _MEMORY_COMPRESSION_STATS["last_tokens_saved"] = tokens_saved
    _MEMORY_COMPRESSION_STATS["last_messages_after"] = int(messages_after)
    _MEMORY_COMPRESSION_STATS["last_messages_saved"] = messages_saved

def _build_summarize_prompt(max_words: int) -> str:
    return f"""\
You are summarizing a chunk of penetration testing conversation history.
Preserve ALL of the following in your summary:
- Discovered vulnerabilities, endpoints, and attack vectors
- Credentials, tokens, API keys, session cookies found
- Tools used and their key results (what worked, what didn't)
- Failed attempts (so the agent doesn't repeat them)
- Architecture insights (tech stack, framework, routing patterns)

Be concise but NEVER drop security-relevant details. Output a single
paragraph summary, max {max_words} words."""


def _resolve_policy(brain: Any) -> Any:
    provider = getattr(brain, "_provider", "") if brain is not None else ""
    model = getattr(brain, "_model", "") if brain is not None else ""
    return get_compression_policy(provider, model)


def _is_local_strict(brain: Any) -> bool:
    provider = str(getattr(brain, "_provider", "") or "").lower()
    return provider in {"llamacpp", "ollama"}


def _effective_policy_for_runtime(policy: Any, brain: Any) -> tuple[int, int, int, int]:
    """Return runtime-tuned compression knobs.

    Local 8k-ish models need more aggressive history compaction than the
    generic registry defaults: compress sooner, preserve fewer raw messages,
    summarize smaller chunks, and emit shorter summaries.
    """
    threshold = int(policy.compress_threshold_tokens)
    preserve_recent = int(policy.preserve_recent_messages)
    chunk_size = int(policy.chunk_size)
    summary_words = int(policy.summary_max_words)
    if _is_local_strict(brain):
        threshold = min(threshold, 2200)
        preserve_recent = min(preserve_recent, 3)
        chunk_size = min(chunk_size, 3)
        summary_words = min(summary_words, 90)
    return threshold, preserve_recent, chunk_size, summary_words


def _estimate_tokens(messages: list[dict[str, Any]]) -> int:
    """Rough token count from message content."""
    total_chars = 0
    for m in messages:
        content = m.get("content", "")
        if isinstance(content, dict):
            total_chars += len(json.dumps(content, default=str))
        else:
            total_chars += len(str(content))
    return total_chars // _CHARS_PER_TOKEN


async def compress_history(
    messages: list[dict[str, Any]],
    brain: Any,
) -> list[dict[str, Any]]:
    """Compress old messages if total tokens exceed threshold.

    Returns the (possibly compressed) message list. If compression is
    not needed, returns the original list unchanged.

    Args:
        messages: Full message history from ScanLoopState.
        brain: AgentBrain instance (used for LLM summarization calls).
    """
    total_tokens = _estimate_tokens(messages)
    policy = _resolve_policy(brain)
    threshold, preserve_recent, chunk_size, summary_words = _effective_policy_for_runtime(policy, brain)
    _record_compression_check(total_tokens=total_tokens, threshold=threshold, messages=messages)
    if total_tokens < threshold:
        return messages

    logger.info(
        "memory_compressor: provider=%s model=%s tokens=%d threshold=%d recent=%d chunk=%d",
        getattr(brain, "_provider", "?") if brain is not None else "?",
        getattr(brain, "_model", "?") if brain is not None else "?",
        total_tokens,
        threshold,
        preserve_recent,
        chunk_size,
    )

    # Split: old messages to compress, recent to preserve
    if len(messages) <= preserve_recent:
        return messages

    old = messages[:-preserve_recent]
    recent = messages[-preserve_recent:]

    # Chunk old messages and summarize each chunk
    compressed: list[dict[str, Any]] = []
    chunks_total = 0
    chunks_summarized = 0
    chunks_passthrough = 0
    for i in range(0, len(old), chunk_size):
        chunk = old[i:i + chunk_size]
        chunks_total += 1

        # Build a text representation of the chunk
        chunk_text_parts: list[str] = []
        for m in chunk:
            role = m.get("role", "?")
            content = m.get("content", "")
            if isinstance(content, dict):
                name = content.get("name", "?")
                result = content.get("result", {})
                summary = result.get("summary", "") if isinstance(result, dict) else str(result)[:200]
                chunk_text_parts.append(f"[{role}:{name}] {summary}")
            else:
                chunk_text_parts.append(f"[{role}] {str(content)[:300]}")
        chunk_text = "\n".join(chunk_text_parts)

        # If chunk is tiny, keep as-is
        if len(chunk_text) < 500:
            compressed.extend(chunk)
            chunks_passthrough += 1
            continue

        # Summarize via LLM
        if brain is not None and hasattr(brain, "_call_llm_with_fallback"):
            try:
                summary = await asyncio.to_thread(
                    brain._call_llm_with_fallback,
                    _build_summarize_prompt(summary_words),
                    f"Conversation chunk (iterations {chunk[0].get('iter', '?')}-{chunk[-1].get('iter', '?')}):\n\n{chunk_text}",
                )
                if summary:
                    compressed.append({
                        "role": "system",
                        "content": f"[COMPRESSED HISTORY iters {chunk[0].get('iter','?')}-{chunk[-1].get('iter','?')}] {summary.strip()[:1000]}",
                        "iter": chunk[-1].get("iter", 0),
                    })
                    chunks_summarized += 1
                    logger.info(
                        "memory_compressor: compressed %d messages → 1 summary (%d chars)",
                        len(chunk), len(summary),
                    )
                    continue
            except Exception:
                logger.exception("memory_compressor: LLM summarization failed, keeping raw")

        # Fallback: keep raw but truncated
        compressed.extend(chunk)
        chunks_passthrough += 1

    result = compressed + recent
    new_tokens = _estimate_tokens(result)
    _record_compression_result(
        total_tokens_before=total_tokens,
        total_tokens_after=new_tokens,
        messages_before=len(messages),
        messages_after=len(result),
        chunks_total=chunks_total,
        chunks_summarized=chunks_summarized,
        chunks_passthrough=chunks_passthrough,
    )
    logger.info(
        "memory_compressor: %d → %d messages, %d → %d tokens",
        len(messages), len(result), total_tokens, new_tokens,
    )
    return result
