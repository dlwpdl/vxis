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
from typing import Any

from vxis.llm.model_registry import get_compression_policy

logger = logging.getLogger(__name__)

# Rough token estimate: 1 token ≈ 4 chars for English text
_CHARS_PER_TOKEN = 4

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
    if total_tokens < policy.compress_threshold_tokens:
        return messages

    logger.info(
        "memory_compressor: provider=%s model=%s tokens=%d threshold=%d recent=%d chunk=%d",
        getattr(brain, "_provider", "?") if brain is not None else "?",
        getattr(brain, "_model", "?") if brain is not None else "?",
        total_tokens,
        policy.compress_threshold_tokens,
        policy.preserve_recent_messages,
        policy.chunk_size,
    )

    # Split: old messages to compress, recent to preserve
    if len(messages) <= policy.preserve_recent_messages:
        return messages

    old = messages[:-policy.preserve_recent_messages]
    recent = messages[-policy.preserve_recent_messages:]

    # Chunk old messages and summarize each chunk
    compressed: list[dict[str, Any]] = []
    for i in range(0, len(old), policy.chunk_size):
        chunk = old[i:i + policy.chunk_size]

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
            continue

        # Summarize via LLM
        if brain is not None and hasattr(brain, "_call_llm_with_fallback"):
            try:
                summary = await asyncio.to_thread(
                    brain._call_llm_with_fallback,
                    _build_summarize_prompt(policy.summary_max_words),
                    f"Conversation chunk (iterations {chunk[0].get('iter', '?')}-{chunk[-1].get('iter', '?')}):\n\n{chunk_text}",
                )
                if summary:
                    compressed.append({
                        "role": "system",
                        "content": f"[COMPRESSED HISTORY iters {chunk[0].get('iter','?')}-{chunk[-1].get('iter','?')}] {summary.strip()[:1000]}",
                        "iter": chunk[-1].get("iter", 0),
                    })
                    logger.info(
                        "memory_compressor: compressed %d messages → 1 summary (%d chars)",
                        len(chunk), len(summary),
                    )
                    continue
            except Exception:
                logger.exception("memory_compressor: LLM summarization failed, keeping raw")

        # Fallback: keep raw but truncated
        compressed.extend(chunk)

    result = compressed + recent
    new_tokens = _estimate_tokens(result)
    logger.info(
        "memory_compressor: %d → %d messages, %d → %d tokens",
        len(messages), len(result), total_tokens, new_tokens,
    )
    return result
