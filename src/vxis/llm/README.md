# `src/vxis/llm/` — LLM Client + Fallback Router

> Low-level LLM provider client and token-aware routing. Used by `AgentBrain._call_llm_with_fallback` for the provider cascade (OpenAI / Anthropic / Together / Gemini / DeepSeek).

## Files

| File | Role |
|---|---|
| `client.py` | Unified LLM client wrapper with provider-specific call methods |
| `router.py` | Token-budget-aware provider routing + cost tracking |
| `model_registry.py` | Registry of known models (context window, cost per 1M tokens, vision support) |

## Provider fallback chain (built by `AgentBrain._build_standard_chain`)

```
Anthropic (Opus 4.6 → Sonnet 4.6 → Haiku 4.5)
  → Together.ai (Kimi-K2.5 → GLM-5-FP4 → DeepSeek-V3.1 → DeepSeek-R1-0528 → Qwen3.5-397B → Qwen3-235B → gpt-oss-120b → gpt-oss-20b)
  → OpenAI direct (gpt-5.4-mini → gpt-5.4 → gpt-4o → gpt-4o-mini)
  → Google Gemini (gemini-2.5-pro → gemini-2.5-flash)
```

Each tier only engages if the corresponding `API_KEY` env var is set.

## Instrumentation hook (Phase A)

`AgentBrain._call_llm_direct` — the single choke point for every provider call — increments `_LLM_CALL_COUNT` via `_increment_llm_call_count()`. This is how Phase A's `llm_call_count` metric is populated.

## Do NOT add LLM clients elsewhere

All LLM calls must go through `AgentBrain._call_llm` → `_call_llm_direct` to be counted. The legacy `_call_claude_subprocess` exists in brain.py but is dead code (see `project_code_changes_2026_03` memory).
