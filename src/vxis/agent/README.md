# `src/vxis/agent/` — Brain + Single Loop + Tool Registry

> The heart of Phase A. This module contains everything that makes VXIS a Brain-First agent: the ReAct loop, the LLM brain with provider fallback, the tool registry, and the 11 BrainTool implementations.

## Key files (Phase A live)

| File | Role |
|---|---|
| **`brain.py`** (1800+ lines) | `AgentBrain` class. Contains `think()` (legacy) and **`think_in_loop()`** (Phase A sibling). Owns `AGENT_SYSTEM_PROMPT`, `LOOP_PROMPT_ADAPTER`, `TOOL_DESCRIPTIONS`, the provider fallback chain (`_call_llm_with_fallback`), `_parse_response` JSON parser, and the three unified counters (`brain_decision_count`, `llm_call_count`). |
| **`scan_loop.py`** (~90 lines) | `ScanAgentLoop` class. Strix-equivalent single `while` loop. Owns `ScanLoopState.messages[]` across iterations. Delegates decision-making to `brain.think_in_loop(messages, catalog)` and dispatches returned actions through the `ToolRegistry`. |
| **`tool_registry.py`** (~45 lines) | `BrainTool` runtime-checkable Protocol, `ToolResult` dataclass, and `ToolRegistry` async dispatcher. The registry's `describe_all()` output is what the Brain sees as its "available tools" catalog. |
| **`tools/`** | Subpackage with 11 BrainTool implementations. See [`tools/README.md`](tools/README.md). |

## Brain backends (three, only AgentBrain is live in Phase A)

| File | Backend | Status |
|---|---|---|
| `brain.py` → `AgentBrain` | LLM API (OpenAI / Anthropic / Gemini / DeepSeek fallback chain) | **LIVE** — Phase A default |
| `brain_interactive.py` → `InteractiveBrain` | stdin/stdout NDJSON — external Claude Code process | Legacy (`vxis scan --interactive`) |
| `brain_filebased.py` → `FileBasedBrain` | File-based protocol | Rarely used |

All three implement `think()` which increments the unified `_BRAIN_DECISION_COUNT` counter via `_increment_brain_decision_count()`. This gives Phase A a single apples-to-apples "Brain is deciding" metric regardless of backend.

`brain_protocol.py` defines the shared Protocol that all three implement.

## The ReAct loop (Phase A happy path)

```python
# ScanAgentLoop.run() — scan_loop.py
while not completed and iteration < max_iters:
    iteration += 1
    actions = await brain.think_in_loop(state.messages, registry.describe_all())
    for (tool_name, args) in actions:
        result = await registry.dispatch(tool_name, args)
        state.add_message("tool", {"name": tool_name, "args": args, "result": result})
        if tool_name == "finish_scan" and result.ok:
            completed = True
            break
```

## `think_in_loop` — how the prompt is assembled

1. `AGENT_SYSTEM_PROMPT.format(available_tools=tools_text)` — uses the dynamic catalog from `registry.describe_all()`. The template uses `{{…}}` for literal JSON braces and `{available_tools}` as the only real placeholder.
2. `LOOP_PROMPT_ADAPTER + "\n" + formatted_body` — **concatenate after format**, never before (the adapter uses single braces and cannot go through `.format()`). This is guarded by `test_think_in_loop_adapter_concatenation_no_brace_explosion`.
3. User prompt: last 20 messages' digest + JSON output schema reminder.
4. `_call_llm_with_fallback(system, user)` through `asyncio.to_thread`.
5. `_parse_response(text)` returns `list[AgentAction]`, mapped to `list[(tool_name, args_dict)]`.

## Legacy / supporting files (still present, some used by old pipeline)

| File | Role |
|---|---|
| `agents/` | Sub-package with legacy 63-agent fleet from old pipeline |
| `base.py` | Base `AgentObservation`, `AgentAction`, `AgentStep` dataclasses |
| `business_logic.py` | Legacy business-logic attack agent |
| `context.py` | `AgentContext` (legacy, separate from `ScanContext`) |
| `director.py` | Legacy `DirectorAgent` for phase dispatch |
| `evidence.py` | Evidence aggregation (legacy) |
| `executor.py` | Legacy action executor (pre-ScanAgentLoop) |
| `memory.py` | Memory store (legacy knowledge base per scan) |
| `registry.py` | Legacy agent registry |
| `report_writer.py` | Report drafting helpers |
| `runner.py` | Legacy `AgentRunner` with 63-agent orchestration |
| `sandbox.py` | Legacy sandbox (pre-Docker) |
| `threat_modeling.py` | Threat model synthesis |
| `waf_bypass.py` | WAF bypass technique catalog |

These will be pruned in Phase B cleanup once ScanAgentLoop is fully established and nothing else imports them.

## Phase A brain-related instrumentation

Three module-level counters in `brain.py`, all thread-safe:

```python
get_llm_call_count()         # Incremented at entry of _call_llm_direct
get_brain_decision_count()   # Incremented at entry of every think() / think_in_loop()
# (peak_context_bytes lives on ScanContext, not brain.py)

reset_llm_call_count()
reset_brain_decision_count()
```

`ScanPipelineV2` resets both before each scan and prints them in the `VXIS_BENCHMARK` line at the end.

## Critical rules for future edits

- **Do NOT modify `AgentBrain.think()`** — it is legacy but still referenced. Add siblings instead.
- **Do NOT modify `AGENT_SYSTEM_PROMPT` body** — use `LOOP_PROMPT_ADAPTER` for overrides.
- **Never pass `LOOP_PROMPT_ADAPTER` through `.format()`** — brace escape bug (see regression test).
- Counter increments must happen AFTER the `is_done` / `max_steps` early-return (don't count skipped steps).
