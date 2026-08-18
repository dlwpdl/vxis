# `src/vxis/llm/` — LLM Client + Fallback Router

> Low-level LLM provider client and token-aware routing. Used by `AgentBrain._call_llm_with_fallback` for the provider cascade (OpenAI / Anthropic / Together / Gemini / DeepSeek).

## Files

| File | Role |
|---|---|
| `client.py` | Unified LLM client wrapper with provider-specific call methods |
| `hybrid_config.py` | Role-based hybrid model selection for director/worker/verifier/summarizer |
| `router.py` | Token-budget-aware provider routing + cost tracking |
| `model_registry.py` | Registry of known models (context window, cost per 1M tokens, vision support) |

## Hybrid Role Policy

VXIS uses a hybrid model split instead of treating every agent call as the
same model class:

- `director`: frontier/cloud model for root planning, branch choice, and hard
  judgment. Configure with `VXIS_DIRECTOR_LLM`, or split
  `VXIS_DIRECTOR_LLM_PROVIDER` + `VXIS_DIRECTOR_LLM_MODEL`.
- `worker`: local-first model for bounded task execution. Configure with
  `VXIS_WORKER_LLM` or split provider/model vars. Defaults to `llamacpp` using
  `VXIS_LLAMACPP_MODEL`.
- `verifier`: strong model for adversarial finding review. Defaults to the
  director unless `VXIS_VERIFIER_LLM` is set.
- `summarizer`: cheap/local model for compression and summarization. Defaults
  to the worker unless `VXIS_SUMMARIZER_LLM` is set.

Strix uses one LiteLLM-style `provider/model` setting for the main runtime.
VXIS keeps the same readable format for each role, but separates director cost
from worker throughput so local 30B-class models can absorb bounded tasks
without being trusted as the root orchestrator.

## Context Policy

`model_registry.get_compression_policy(provider, model)` is the canonical
source for provider-specific context behavior.

- `llamacpp`: explicit `VXIS_LLAMACPP_CONTEXT` wins; otherwise VXIS detects the
  selected server model's active context from `/props` or `/v1/models`, with an
  `8192` fallback. Runtimes up to 16K use aggressive local compaction; larger
  runtimes scale prompt/compression budgets and may honor `VXIS_LONG_CONTEXT`.
- `ollama`: medium local profile. Uses `VXIS_OLLAMA_CONTEXT`, keeps two recent
  full iterations, and compresses earlier than cloud models.
- Cloud providers: large profile. Keeps more recent full history, delays
  compression, and may honor `VXIS_LONG_CONTEXT`.

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
