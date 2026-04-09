# Chapter 01 — Phase A: Architecture Migration

**Date:** 2026-04-08
**Commits:** 2ae3f9f ... 9329d9f ... e98dbb8 (17 total)
**Outcome:** 14-phase pipeline killed. Single persistent ReAct loop owns every scan. `brain_decision_count: 0 → 20`

## Context

Before Phase A, VXIS had a 5234-line `ScanPipeline` (`src/vxis/pipeline/pipeline.py`)
that ran 14 hardcoded phases (P0 Foundation → P1 Director → P4 CPR → ... → P6 Report
→ P18 Collective). Each phase called specific Brain helper methods, not the full
ReAct loop.

CLAUDE.md declared "Brain-First" as the absolute architectural principle. Reality
did not match.

## Problem

Task 1 of Phase A measured `brain_decision_count = 0` on a full baseline scan with
`llm_call_count = 10+`. Proof: the Brain was being called as a helper 10 times,
but never as a decision-making loop entry. The smoking gun at `pipeline.py:1927-1929`:

```python
if not isinstance(self.brain, FileBasedBrain):
    return None   # ← AgentBrain never uses think()
```

So `AgentBrain.think()` was completely bypassed. The Brain-First principle was
violated at the code level.

## Decision

Strix-parity migration: replace the 14-phase pipeline with a **single persistent
ReAct loop** that owns `messages[]` across the entire scan, just like Strix's
`base_agent.agent_loop`.

Key design choices:
- `ScanAgentLoop` (new, ~90 lines) is the top-level entrypoint.
- `AgentBrain.think_in_loop()` is a **sibling** method to the legacy `think()` —
  shares the verified helpers (`_call_llm_with_fallback`, `_parse_response`) but
  takes `messages[]` + dynamic `tool_catalog` as inputs.
- `LOOP_PROMPT_ADAPTER` is prepended to `AGENT_SYSTEM_PROMPT` to override
  scanner-tool naming (Hands/Eyes/X-Ray → http_request/browser_render/intercept_proxy).
- `ScanPipelineV2` (new, ~360 lines) is a thin shim over ScanAgentLoop; CLI keeps
  working via a single import swap.
- Legacy `pipeline.py` (5234 lines) and `phases/` directory deleted in Task 12.

Rejected alternatives:
- **In-place gutting of pipeline.py**: too risky, 5234 lines of interleaved state
- **Keep phases as tools**: the Brain would still be boxed into phase abstractions
- **Strix clone**: VXIS has existing modules (Hands/Eyes/X-Ray) worth preserving

## Execution

15 tasks, all with TDD:
- Task 1: Baseline + instrumentation (4 counters)
- Task 2-3: `BrainTool` protocol + `ToolRegistry` + `ScanAgentLoop` skeleton
- Task 4: `think_in_loop` wired into ScanAgentLoop
- Task 5: Control tools (finish_scan, think, wait)
- Task 6: Hands/Eyes/X-Ray wrappers (http_request, browser_render, intercept_proxy)
- Task 7-8: `shell_exec` + `python_exec` + vxis-sandbox Docker image
- Task 9: Finding CRUD (report_finding, query_findings, link_chain)
- Task 10: ScanPipelineV2 shim (5234 → 360 lines)
- Task 11: Benchmark gate (0 findings but `brain_decision_count = 20`)
- Task 12: Delete 14960 lines of legacy dead code

## Result

**Primary gate met**: `brain_decision_count = 0 → 20` on Juice Shop. The Brain
actually drives every decision now.

**Known gap**: `findings_count = 0` in the first end-to-end run because Brain
got stuck calling browser_render 20 times in a row. Prompt tuning deferred to
Phase B.

Code delta: **+2500 lines new, −14960 lines legacy**.

## Lessons learned

1. **`brain_decision_count` is the single most important metric**. If it's 0,
   the Brain-First principle is violated no matter what else looks right.
2. **Do not attempt to extract phase methods from legacy pipeline.** Parallel
   new file + switch import is safer than in-place gutting.
3. **`think()` was left untouched as legacy** — additive sibling methods are
   safer than modifying 1700-line verified code.
4. **TOOL_DESCRIPTIONS and AGENT_SYSTEM_PROMPT are pre-Strix-migration artifacts**
   and conflict with dynamic tool catalogs. The `LOOP_PROMPT_ADAPTER` override
   pattern solves this without touching the prompt body.

## Next

Phase B: the architecture is right but quality is zero. The Brain has a real
ReAct loop but doesn't yet know HOW to pentest effectively. Next chapter
tackles prompt engineering + tool interpretation.
