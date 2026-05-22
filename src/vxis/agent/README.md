# `src/vxis/agent/` — Brain + Single Loop + AI Review Hierarchy

> The heart of VXIS. This module contains the Brain-first worker loop, the AI reviewer layers, the tool registry, the verifier, branch persistence, memory compression, and the auto-orchestration safety net.

## Key files

| File | Role |
|---|---|
| **`brain.py`** | `AgentBrain` class. Contains `think()` (legacy), **`think_in_loop()`** (live), context fitting, provider routing, and provider calls. Prompt/data contracts live in `brain_prompts.py`; usage counters live in `brain_metrics.py`. |
| **`scan_loop.py`** | `ScanAgentLoop` assembly class and constructor. Runtime behavior is split into focused mixins so worker/local LLM context can stay compact. |
| **`scan_loop_run.py`** | Main ReAct loop: iteration control, dispatch guards, finish gates, and final result assembly. |
| **`scan_loop_run_skills.py`** | Scheduled `run_skill` execution and skill-result-to-finding promotion. |
| **`scan_loop_run_auto.py`** | Auto-orchestration safety net: browser login probing, ffuf, nuclei, and sqlmap fallback execution. |
| **`scan_loop_run_followups.py`** | Chain nudges, untried-skill sweep, and director follow-up execution. |
| **`scan_loop_actions.py`** | Action preprocessing, evidence enrichment, verifier dispatch, branch/candidate bookkeeping, and Brain tool catalog. |
| **`scan_loop_decision_policy.py`** | Finish-blocking policy, branch scoring, forced replan actions, focus discipline, and target-memory pressure. |
| **`scan_loop_agent_graph.py`** | Director/worker agent graph state synchronization, child execution crediting, and crown-chain follow-up branch creation. |
| **`scan_loop_dashboard.py`** | Compact per-iteration scan dashboard rendered into Brain context and TUI state. |
| **`scan_loop_policy.py`** | Static director prompt and skill-family policy tables. |
| **`scan_loop_state.py`** | Durable scan state: messages, verdict counts, vector candidates, branch state, review queue, callback/retrieval observations, and branch role/phase helpers. |
| **`tool_registry.py`** | `BrainTool` runtime-checkable Protocol, `ToolResult` dataclass, and `ToolRegistry` async dispatcher. `describe_all()` output is the Brain's tool catalog. |
| **`memory_compressor.py`** | LLM-based memory compression — Strix pattern. At 90K tokens, older messages are chunked and summarized. 15 most recent messages always preserved verbatim. |
| **`egress.py`** | Enterprise egress filter. When `VXIS_EGRESS_STRICT=1`, builds an allowlist from the target URL and blocks sandbox outbound to non-target hosts. |
| **`tools/`** | Subpackage with 23 BrainTool implementations. See [`tools/README.md`](tools/README.md). |

## Brain backends (three, only AgentBrain is live)

| File | Backend | Status |
|---|---|---|
| `brain.py` → `AgentBrain` | LLM API (OpenAI / Anthropic / Gemini / DeepSeek fallback chain) | **LIVE** |
| `brain_interactive.py` → `InteractiveBrain` | stdin/stdout NDJSON — external Claude Code process | Legacy (`vxis scan --interactive`) |
| `brain_filebased.py` → `FileBasedBrain` | File-based protocol | Rarely used |

All three implement `think()` which increments the unified `_BRAIN_DECISION_COUNT` counter. `brain_protocol.py` defines the shared Protocol.

## Runtime roles

Although VXIS currently runs inside one process and one loop, the module already divides responsibilities into runtime roles:

| Role | Main code | Responsibility |
|---|---|---|
| Worker | `brain.py` + `scan_loop.py` | Select actions, run tools, persist exploit branches |
| Verifier | `tools/verifier_tools.py` | Refute weak findings and demand PoC/control evidence |
| Judge | `scan_loop.py` + `tools/control_tools.py` | Reject premature `finish_scan`, shape final report sections |
| Human | External | Only for escalated exceptions or risky approvals |

This is deliberate: VXIS aims for unattended execution with AI review, not continuous human steering.

## The ReAct loop (live happy path)

```python
# ScanAgentLoop.run() — scan_loop.py (simplified)
while not completed and iteration < max_iters:  # max_iters=300
    iteration += 1
    messages = await compress_history(messages, brain)  # at 90K tokens
    dashboard = _build_scan_dashboard()  # compact progress summary
    actions = await brain.think_in_loop(messages + [dashboard], registry.describe_all())
    actions = actions[:1]  # Strix pattern: 1 tool per message
    for (tool_name, args) in actions:
        result = await registry.dispatch(tool_name, args)
        state.add_message("tool", {"name": tool_name, "args": args, "result": result})
        # findings may be auto-promoted and auto-verified here
        if tool_name == "finish_scan" and result.ok:
            completed = True; break
    # Focus-branch discipline, auto-orchestration safety net, and completion gate fire here
```

## Branch persistence

`ScanLoopState` persists more than messages:

- `vector_candidates`: durable attack hypotheses
- `attempt_outcomes`: concrete tries against those hypotheses
- `scan_todos`: operator-visible work queue
- `branches`: active exploit paths, including pivots from findings

This is the real search state. Tool names are just verbs over that state.

The practical effect is:

- the loop can keep digging on one lead instead of forgetting it,
- off-branch actions can be warned or blocked,
- `finish_scan` can be rejected while high-value branches remain open.

## Smart 3-tier history (`_build_smart_history`)

Instead of a flat window of the last N messages, `AgentBrain` builds a compacted view:

| Tier | Content | Detail |
|---|---|---|
| T1 — FULL | Last 3 iterations | Complete tool calls, args, results |
| T2 — COMPACT | Older iterations | `tool:name` + summary only |
| T3 — PINNED | High-value messages (any age) | Dashboard, critic, findings, verify, system hints |

Pinned tools: `report_finding`, `verify_finding`, `fingerprint_target`.
Pinned keywords: `SCAN DASHBOARD`, `CRITIC REVIEW`, `SYSTEM HINT`, `AUTO-RECON`, `BELIEF STATE`, `STICKY HINT`.

## AI review hierarchy

The module no longer assumes that "finding creation" equals "finding acceptance".

1. Worker loop proposes a result.
2. Structured PoC contract gates serious findings.
3. `verify_finding` tries to refute them.
4. The completion gate blocks termination if the run is still strategically incomplete.

This is the key autonomy mechanism that replaces phase-by-phase human review.

## Auto-orchestration safety net

Triggers in `scan_loop.py` that fire when Brain hasn't reached for critical tools:

| Trigger | Fires at | What |
|---|---|---|
| auto-login | iter 5+ (password form detected) | SQLi bypass creds on login forms |
| auto-ffuf | iter 10 | Directory bruteforce with common wordlist |
| auto-nuclei | iter 12 | nuclei with web templates |
| auto-sqlmap | iter 18+ | Test endpoints that returned 500 errors |

## `think_in_loop` — prompt assembly

1. `AGENT_SYSTEM_PROMPT.format(available_tools=tools_text)` — dynamic catalog from `registry.describe_all()`. Template uses `{{…}}` for literal JSON braces.
2. `LOOP_PROMPT_ADAPTER + "\n" + formatted_body` — **concatenate after format**, never before (adapter uses single braces). Guarded by regression test.
3. User prompt: smart 3-tier history digest + scan dashboard + JSON output schema.
4. `_call_llm_with_fallback(system, user)` through `asyncio.to_thread`.
5. `_parse_response(text)` returns `list[AgentAction]` → `list[(tool_name, args_dict)]`.

## LLM memory compression

`memory_compressor.py`: when history exceeds 90K tokens (~360K chars), messages are chunked in groups of 10 and summarized by the LLM. Summaries preserve vulnerabilities, credentials, failed attempts, and architecture insights. 15 most recent messages are always verbatim. Compression is best-effort (failure falls through silently).

## Legacy / supporting files (still present)

| File | Role |
|---|---|
| `agents/` | Sub-package with legacy 63-agent fleet from old pipeline |
| `base.py` | Base `AgentObservation`, `AgentAction`, `AgentStep` dataclasses |
| `context.py` | `AgentContext` (legacy, separate from `ScanContext`) |
| `director.py` | Legacy `DirectorAgent` for phase dispatch |
| `executor.py` | Legacy action executor (pre-ScanAgentLoop) |
| `memory.py` | Memory store (legacy knowledge base per scan) |
| `runner.py` | Legacy `AgentRunner` with 63-agent orchestration |

## Instrumentation

Three module-level counters in `brain.py`, all thread-safe:

```python
get_llm_call_count()         # Incremented at entry of _call_llm_direct
get_brain_decision_count()   # Incremented at entry of every think() / think_in_loop()
reset_llm_call_count()
reset_brain_decision_count()
```

`ScanLoopState` also tracks: `peak_context_bytes`, `verdict_counts` (CONFIRMED/UNCONFIRMED/REFUTED), `refuted_findings`, `confirmed_findings`.

## Critical rules for future edits

- **Do NOT modify `AgentBrain.think()`** — it is legacy but still referenced. Add siblings instead.
- **Do NOT modify `AGENT_SYSTEM_PROMPT` body** — use `LOOP_PROMPT_ADAPTER` for overrides.
- **Never pass `LOOP_PROMPT_ADAPTER` through `.format()`** — brace escape bug (see regression test).
- **1 tool per message** — `actions[:1]` in scan_loop.py. Do not remove this.
- **Do NOT weaken PoC / verifier / finish gates just to raise finding count**.
- Counter increments must happen AFTER the `is_done` / `max_steps` early-return (don't count skipped steps).
