# Phase A — Strix-Parity Single-Loop Migration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Kill the 14-Phase pipeline orchestrator and make a single persistent Brain ReAct loop (via new `AgentBrain.think_in_loop()` sibling method) the owner of an entire scan end-to-end, with existing Phase logic demoted to high-level tools the Brain can call. **Success is defined by `brain_decision_count` growing from baseline 0 to a meaningful number** — see Task 1 discovery below.

**Architecture:** VXIS already has a ReAct-style brain method `AgentBrain.think()`, hypothesis queue (`graph/hypothesis.py`), and attack graph (`graph/attack_graph.py`). What it lacks is (a) a single persistent outer loop that owns `messages[]` for the whole scan and (b) a Brain entrypoint that actually gets called by that loop. We build `ScanAgentLoop` as the new top-level entrypoint (Strix `base_agent.agent_loop` equivalent) AND add `AgentBrain.think_in_loop()` as a sibling method to `think()` that accepts `messages[]` + dynamic `tool_catalog` directly. `pipeline.py` becomes a thin shim that constructs `ScanAgentLoop` and runs it. Each of the 14 phases is classified: valuable domain logic → wrapped as a `BrainTool`, thin glue → deleted. Hands/Eyes/X-Ray/Finding stay as low-level tools. No context dict passing between "stages" — one `messages[]` array for the whole scan.

**Tech Stack:** Python 3.12, existing VXIS modules (`agent/brain.py`, `agent/runner.py`, `agent/executor.py`, `graph/hypothesis.py`, `evidence/engine.py`, Hands/X-Ray), pytest, no new dependencies.

**Non-goals for Phase A (deferred to Phase B/C/D):** Episodic memory DB, critic loop, typed blackboard, 1M context mode, domain runtimes (Game/Mobile/HW). Phase A is *parity*, not differentiation.

## 🚨 CRITICAL DISCOVERY — Task 1 baseline revealed the true architectural rot (2026-04-08)

Task 1 ran against Juice Shop + WebGoat with the new instrumentation and measured:

| Metric | Juice Shop | WebGoat |
|---|---:|---:|
| `peak_context_bytes` | 10,391 | 9,743 |
| `llm_call_count` | 10 | 12 |
| **`brain_decision_count`** | **0** | **0** |
| VXIS Score | 758.8 | 760.4 |

`llm_call_count > 0` + `brain_decision_count = 0` is the **smoking gun** for `CLAUDE.md`'s "Brain-First 원칙 위반" line. The current `pipeline.py:1927-1929` explicitly early-returns for `AgentBrain`:

```python
def _consult_brain_for_vector(self, ctx, vector_id, vector_name, phase_name):
    from vxis.agent.brain_filebased import FileBasedBrain
    if not isinstance(self.brain, FileBasedBrain):
        return None   # ← AgentBrain path skips think() entirely
```

The pipeline then calls `brain._call_llm_with_fallback(...)`, `brain.interpret_probe_result(...)`, `brain.generate_chain_attacks(...)` directly as helper functions. **Brain is a bag of LLM helpers, not a decision-making loop.** This is a direct violation of `CLAUDE.md` ("Brain을 가끔 호출하는 헬퍼로 취급 금지").

**Implication for this plan:** A thin `think_in_loop()` wrapper over `think()` is not viable — see Task 4 for the revised β-strategy. `think()` is functional (verified: `AGENT_SYSTEM_PROMPT` at `brain.py:182` is 200+ lines of real pentest methodology, `_call_llm_with_fallback` + `_parse_response` work) but is hardwired to `TOOL_DESCRIPTIONS` (scanner tools) and `AgentObservation` snapshots, incompatible with `ScanAgentLoop`'s persistent-messages model. Task 4 now adds `think_in_loop()` as a **sibling** method that shares the verified helpers but takes `messages[]` + dynamic `tool_catalog`.

**Success criteria (hard gate before Phase B):**
1. A scan against Juice Shop + WebGoat finishes in one continuous Brain loop, with `messages[]` never truncated between "phases".
2. **`brain_decision_count` grows from baseline 0 to ≥ 1 per `max_iters` upper bound** on both targets — this is the PRIMARY Brain-First gate.
3. Findings count ≥ current `pipeline.py` instrumented baseline (Juice Shop: 3, WebGoat: 3) on both targets. **Note**: baseline numbers are lower than the pre-instrumented original Task 1 run because `--allow-inject` was omitted; Task 14 must also run without `--allow-inject` for apples-to-apples.
4. Chain depth (max `attack_chain` length) ≥ current baseline (≥ 2 on both targets).
5. **Per-target attempt counts must differ** — current baseline shows exactly 78 attempts + 11 consultations on BOTH targets (profile-hardcoded). Phase A should make attempt count Brain-driven, therefore target-dependent.
6. `peak_context_bytes` should grow with loop iterations but remain manageable (soft target: < 200 KB at max_iters = 300; document actual).
7. `pipeline.py` reduced below 1000 lines (from 5234).
8. All existing tests still pass; new tests added for `ScanAgentLoop` + `think_in_loop`.

**Task 1 status: DONE** (commit `2ae3f9f`). Baseline doc: `docs/superpowers/benchmarks/2026-04-08-phase-a-baseline.md`. Instrumentation commits: `e5dc304`, `09379c2`, `aa69014`, `f9d8da3`.

## ⚠️ Worktree execution hazard — READ BEFORE ANY `poetry run vxis` COMMAND

The poetry venv at `/Users/eliot/Desktop/유/vxis/.venv` has an editable install pointing to the **main repo's `src/` directory**, NOT this worktree's `src/`. Running `poetry run vxis ...` from inside the worktree without override **loads main-repo code**, not worktree code. All four instrumentation commits (e5dc304, 09379c2, aa69014, f9d8da3) are INVISIBLE to `poetry run vxis` unless you force the worktree source path.

**Always prefix with `PYTHONPATH`:**

```bash
export PYTHONPATH=/Users/eliot/Desktop/유/vxis/.worktrees/phase-a/src
poetry run vxis scan http://localhost:3000 ...
```

Verification command (run before any scan):

```bash
poetry run python -c "import vxis.cli.main as m; import inspect; print(inspect.getfile(m))"
# Expected: /Users/eliot/Desktop/유/vxis/.worktrees/phase-a/src/vxis/cli/main.py
```

This hazard is also documented in `WORKTREE_README.md` at the worktree root. Every subagent dispatch MUST include this instruction.

---

## File Structure (what gets created / changed / deleted)

**Create:**
- `src/vxis/agent/scan_loop.py` — new `ScanAgentLoop` class. Persistent ReAct loop, owns `messages[]`, `hypothesis_queue`, `attack_graph`, `evidence_engine` for the whole scan. ~400 lines target.
- `src/vxis/agent/tool_registry.py` — new `BrainTool` protocol + `ToolRegistry` singleton. Brain queries available tools, dispatches calls, returns structured observations. ~200 lines.
- `src/vxis/agent/tools/` — new package housing wrapped Phase logic as tools:
  - `recon_tools.py` — wraps P4 CPR, P15 Digital Twin, P13 Biometrics
  - `intel_tools.py` — wraps P2 Agents, P3 Hypothesis
  - `exploit_tools.py` — wraps P5 Special, P7 Hardware
  - `chain_tools.py` — wraps P8 Synthesis, P11 Mutation
  - `hands_tools.py` — exposes Hands/X-Ray/Eyes as primitive tools
  - `finding_tools.py` — `report_finding`, `query_findings`, `link_chain`
  - `control_tools.py` — `finish_scan`, `think`, `wait` (Strix-style)
- `tests/agent/test_scan_loop.py` — unit + integration tests for the loop

**Modify:**
- `src/vxis/pipeline/pipeline.py` — gut to <1000 lines. Keep only: target normalization, scan context bootstrap, `ScanAgentLoop` instantiation, deferred-action gate, report generation call. Delete all `_run_phase`, stage dispatching, parallel phase execution.
- `src/vxis/agent/brain.py:675 think()` — accept structured tool results from `ScanAgentLoop` instead of being called directly with an `AgentObservation` per phase. Minimal change: add a new method `think_in_loop(messages)` that preserves full message history instead of resetting.
- `src/vxis/agent/runner.py` — delete or make into a thin re-export of `ScanAgentLoop`.

**Delete (after migration verified):**
- `src/vxis/phases/p0_foundation.py`, `p1_director.py`, `p8_synthesis.py` — pure orchestration glue, no domain logic → Brain does these natively.
- 14-phase `Stage` classification in `pipeline.py` docstring.

**Keep untouched (Phase A scope protection):**
- `src/vxis/evidence/`, `src/vxis/graph/`, `src/vxis/report/`, `src/vxis/mission/`, `src/vxis/knowledge/`, `src/vxis/primitives/` (Hands/X-Ray).

---

## Task Breakdown

### Task 1: Snapshot the baseline

**Files:**
- Read: `src/vxis/pipeline/pipeline.py`, `.github/workflows/growth-loop.yml`
- Create: `docs/superpowers/benchmarks/2026-04-08-phase-a-baseline.md`

- [ ] **Step 1:** Run the current `pipeline.py`-based scan against DVWA, Juice Shop, WebGoat (whatever `growth-loop.yml` uses). Capture: total wall time, finding count by severity, max chain depth, total LLM calls, peak messages/context-dict size.
- [ ] **Step 2:** Record baseline numbers in `docs/superpowers/benchmarks/2026-04-08-phase-a-baseline.md`. Include git SHA.
- [ ] **Step 3:** Commit.

```bash
git add docs/superpowers/benchmarks/2026-04-08-phase-a-baseline.md
git commit -m "bench: capture Phase A baseline (pre-migration numbers)"
```

**Why first:** Without this, Task 14 (success gate) can't be evaluated. Do not skip.

---

### Task 2: `BrainTool` protocol + registry

**Files:**
- Create: `src/vxis/agent/tool_registry.py`
- Test: `tests/agent/test_tool_registry.py`

- [ ] **Step 1: Write failing test**

```python
# tests/agent/test_tool_registry.py
import pytest
from vxis.agent.tool_registry import BrainTool, ToolRegistry, ToolResult

class DummyTool:
    name = "dummy"
    description = "returns echo"
    input_schema = {"type": "object", "properties": {"msg": {"type": "string"}}}

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, data={"echo": kwargs["msg"]}, summary=f"echoed {kwargs['msg']}")

@pytest.mark.asyncio
async def test_registry_registers_and_dispatches():
    reg = ToolRegistry()
    reg.register(DummyTool())
    assert "dummy" in reg.list_tools()
    result = await reg.dispatch("dummy", {"msg": "hi"})
    assert result.ok is True
    assert result.data == {"echo": "hi"}

@pytest.mark.asyncio
async def test_registry_unknown_tool_returns_error_result():
    reg = ToolRegistry()
    result = await reg.dispatch("ghost", {})
    assert result.ok is False
    assert "unknown tool" in result.summary.lower()
```

- [ ] **Step 2: Run — expect import failure**

```bash
pytest tests/agent/test_tool_registry.py -v
# Expected: ModuleNotFoundError: vxis.agent.tool_registry
```

- [ ] **Step 3: Implement `tool_registry.py`**

```python
# src/vxis/agent/tool_registry.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

@dataclass
class ToolResult:
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    error: str | None = None

@runtime_checkable
class BrainTool(Protocol):
    name: str
    description: str
    input_schema: dict[str, Any]
    async def run(self, **kwargs: Any) -> ToolResult: ...

class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, BrainTool] = {}

    def register(self, tool: BrainTool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool {tool.name} already registered")
        self._tools[tool.name] = tool

    def list_tools(self) -> list[str]:
        return sorted(self._tools.keys())

    def describe_all(self) -> list[dict[str, Any]]:
        return [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            for t in self._tools.values()
        ]

    async def dispatch(self, name: str, args: dict[str, Any]) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(ok=False, summary=f"unknown tool: {name}", error="unknown_tool")
        try:
            return await tool.run(**args)
        except Exception as e:
            return ToolResult(ok=False, summary=f"tool {name} raised {type(e).__name__}: {e}", error=str(e))
```

- [ ] **Step 4: Run tests — expect pass**

```bash
pytest tests/agent/test_tool_registry.py -v
# Expected: 2 passed
```

- [ ] **Step 5: Commit**

```bash
git add src/vxis/agent/tool_registry.py tests/agent/test_tool_registry.py
git commit -m "feat(agent): add BrainTool protocol and ToolRegistry dispatcher"
```

---

### Task 3: `ScanAgentLoop` skeleton (empty loop, no tools yet)

**Files:**
- Create: `src/vxis/agent/scan_loop.py`
- Test: `tests/agent/test_scan_loop.py`

- [ ] **Step 1: Failing test for skeleton**

```python
# tests/agent/test_scan_loop.py
import pytest
from vxis.agent.scan_loop import ScanAgentLoop, ScanLoopState
from vxis.agent.tool_registry import ToolRegistry, ToolResult

class FinishTool:
    name = "finish_scan"
    description = "end scan"
    input_schema = {"type": "object"}
    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, summary="finished", data={"final": True})

@pytest.mark.asyncio
async def test_scan_loop_runs_to_finish(monkeypatch):
    reg = ToolRegistry()
    reg.register(FinishTool())

    call_count = {"n": 0}
    async def fake_decide(state):
        call_count["n"] += 1
        return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost", registry=reg, max_iters=10)
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()
    assert result["completed"] is True
    assert call_count["n"] == 1
    assert len(loop.state.messages) >= 2  # system + user + tool result

@pytest.mark.asyncio
async def test_scan_loop_respects_max_iters():
    reg = ToolRegistry()
    loop = ScanAgentLoop(target="http://localhost", registry=reg, max_iters=3)
    async def never_finish(state):
        return [("nonexistent_tool", {})]
    loop._decide = never_finish  # type: ignore
    result = await loop.run()
    assert result["completed"] is False
    assert loop.state.iteration == 3
```

- [ ] **Step 2: Run — expect fail**

```bash
pytest tests/agent/test_scan_loop.py -v
```

- [ ] **Step 3: Implement skeleton**

```python
# src/vxis/agent/scan_loop.py
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from vxis.agent.tool_registry import ToolRegistry, ToolResult

logger = logging.getLogger(__name__)

@dataclass
class ScanLoopState:
    target: str
    messages: list[dict[str, Any]] = field(default_factory=list)
    iteration: int = 0
    max_iters: int = 300
    completed: bool = False
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[dict[str, Any]] = field(default_factory=list)

    def add_message(self, role: str, content: Any) -> None:
        self.messages.append({"role": role, "content": content, "iter": self.iteration})

class ScanAgentLoop:
    def __init__(self, target: str, registry: ToolRegistry, max_iters: int = 300) -> None:
        self.state = ScanLoopState(target=target, max_iters=max_iters)
        self.registry = registry

    async def _decide(self, state: ScanLoopState) -> list[tuple[str, dict[str, Any]]]:
        """Returns list of (tool_name, args). Overridden by Brain integration in Task 4."""
        return [("finish_scan", {})]

    async def run(self) -> dict[str, Any]:
        self.state.add_message("system", f"Scan started on {self.state.target}")
        self.state.add_message("user", f"Target: {self.state.target}. Find all vulnerabilities.")
        while not self.state.completed and self.state.iteration < self.state.max_iters:
            self.state.iteration += 1
            actions = await self._decide(self.state)
            if not actions:
                logger.warning("iter %d: no actions returned, stopping", self.state.iteration)
                break
            for name, args in actions:
                result = await self.registry.dispatch(name, args)
                self.state.add_message("tool", {"name": name, "args": args, "result": {
                    "ok": result.ok, "summary": result.summary, "data": result.data,
                }})
                if name == "finish_scan" and result.ok:
                    self.state.completed = True
                    break
        return {
            "target": self.state.target,
            "completed": self.state.completed,
            "iterations": self.state.iteration,
            "findings": self.state.findings,
            "messages": len(self.state.messages),
        }
```

- [ ] **Step 4: Run tests — expect pass**

```bash
pytest tests/agent/test_scan_loop.py -v
# Expected: 2 passed
```

- [ ] **Step 5: Commit**

```bash
git add src/vxis/agent/scan_loop.py tests/agent/test_scan_loop.py
git commit -m "feat(agent): add ScanAgentLoop skeleton with persistent messages"
```

---

### Task 4: Wire `AgentBrain` into `ScanAgentLoop._decide` — **REVISED 2026-04-08 post-Task-1**

> **Why revised:** Task 1 baseline revealed `brain_decision_count=0` across both targets — the current `pipeline.py` *bypasses* `AgentBrain.think()` entirely (see `pipeline.py:1927-1929`) and treats Brain as a bag of helpers (`_call_llm_with_fallback`, `interpret_probe_result`, `generate_chain_attacks`). The existing `think()` method IS functional (verified: `AGENT_SYSTEM_PROMPT` at brain.py:182 is 200+ lines of real pentest methodology, `TOOL_DESCRIPTIONS` at :506 holds 30+ scanner entries, `_parse_response` at :1626 parses `{"actions": [{"tool":..., "args":..., "reasoning":..., "priority":...}]}`) — **but** it:
> - Hardcodes the scanner-tool catalog `TOOL_DESCRIPTIONS` (nmap/nuclei/sqlmap/...), not our new high-level Phase-as-tool catalog (`cpr_recon`/`intel_agents`/...)
> - Expects an `AgentObservation` snapshot, not a persistent `messages[]` history
>
> So a thin-wrapper approach is impossible. Strategy α (wrap `think()`) is dropped. **Adopted strategy: β — add `think_in_loop()` as a SIBLING method that shares `think()`'s verified helpers (`_call_llm_with_fallback`, `_parse_response`, `AGENT_SYSTEM_PROMPT` template) but takes `messages[]` + dynamic `tool_catalog` as inputs.** `think()` stays untouched as legacy. `_try_compiled_patterns` / `_reflect` are deferred from v1 of `think_in_loop` — add them back in Task 4b if Task 14 benchmarks show they matter.

**Files:**
- Modify: `src/vxis/agent/scan_loop.py` (add `brain` param to `ScanAgentLoop.__init__`, replace stub `_decide`)
- Modify: `src/vxis/agent/brain.py` (add `think_in_loop()` sibling method, do NOT touch `think()`)
- Test: `tests/agent/test_scan_loop_brain.py`

- [ ] **Step 1: Verify think()'s shared helpers**

Before coding, confirm these exist and behave as documented (they do as of commit `f9d8da3` — this step is a trust-but-verify):
- `brain.py:182` `AGENT_SYSTEM_PROMPT` — 200+ line pentest methodology prompt
- `brain.py:1088-1200` `_call_llm_with_fallback(system, user)` — provider fallback chain, returns `str | None`
- `brain.py:1626` `_parse_response(text)` — parses JSON `{"actions":[{"tool","args","reasoning","priority"}]}` → `list[AgentAction]`
- `brain.py:60-95` `_increment_brain_decision_count()` — the counter we added in Task 1.5b

```bash
grep -n "^AGENT_SYSTEM_PROMPT\|def _call_llm_with_fallback\|def _parse_response\|def _increment_brain_decision_count" src/vxis/agent/brain.py
```

Expected: one match per item, all with line numbers > 0.

- [ ] **Step 2: Failing test** (`tests/agent/test_scan_loop_brain.py`)

```python
import pytest
from unittest.mock import MagicMock, AsyncMock
from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult

class EchoTool:
    name = "echo"; description = "echo back"; input_schema = {"type": "object"}
    async def run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, summary="echoed", data=kw)

class FinishTool:
    name = "finish_scan"; description = "end scan"; input_schema = {"type": "object"}
    async def run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, summary="done")

@pytest.mark.asyncio
async def test_brain_drives_loop_via_think_in_loop():
    reg = ToolRegistry()
    reg.register(EchoTool())
    reg.register(FinishTool())

    fake_brain = MagicMock()
    fake_brain.think_in_loop = AsyncMock(side_effect=[
        [("echo", {"msg": "hello"})],
        [("finish_scan", {})],
    ])

    loop = ScanAgentLoop(target="http://x", registry=reg, max_iters=5, brain=fake_brain)
    result = await loop.run()

    assert result["completed"] is True
    assert fake_brain.think_in_loop.await_count == 2
    call_args = fake_brain.think_in_loop.await_args_list[0]
    messages_arg, tools_arg = call_args.args[0], call_args.args[1]
    assert isinstance(messages_arg, list) and len(messages_arg) > 0
    assert any(t["name"] == "echo" for t in tools_arg)

@pytest.mark.asyncio
async def test_think_in_loop_returns_parsed_actions_from_real_brain(monkeypatch):
    """Integration test: real AgentBrain.think_in_loop with stubbed _call_llm_with_fallback."""
    from vxis.agent.brain import AgentBrain, get_brain_decision_count, reset_brain_decision_count
    reset_brain_decision_count()

    brain = AgentBrain()
    fake_llm_response = (
        '```json\n'
        '{"actions": [{"tool": "cpr_recon", "args": {"depth": 2}, '
        '"reasoning": "map attack surface", "priority": "high"}]}\n'
        '```'
    )
    monkeypatch.setattr(brain, "_call_llm_with_fallback", lambda s, u: fake_llm_response)

    messages = [
        {"role": "system", "content": "Scan started"},
        {"role": "user", "content": "Target: http://example.com"},
    ]
    tool_catalog = [
        {"name": "cpr_recon", "description": "map endpoints + subdomains", "input_schema": {"type": "object"}},
        {"name": "finish_scan", "description": "end scan", "input_schema": {"type": "object"}},
    ]

    actions = await brain.think_in_loop(messages, tool_catalog)

    assert len(actions) == 1
    assert actions[0] == ("cpr_recon", {"depth": 2})
    assert get_brain_decision_count() == 1
```

- [ ] **Step 3: Run — expect fail**

```bash
PYTHONPATH=$PWD/src poetry run pytest tests/agent/test_scan_loop_brain.py -v
# Expected: 2 failed (AttributeError: 'AgentBrain' has no 'think_in_loop')
```

- [ ] **Step 4: Add `LOOP_PROMPT_ADAPTER` constant + `think_in_loop()` sibling method on `AgentBrain`** — incorporates Task 3.5 audit findings

> **Task 3.5 audit summary** (see audit report from subagent dispatch on 2026-04-08):
> - 0 BREAKING issues for `_parse_response` (it only reads `data["actions"]`, ignores `module_checklist` / `owasp_checklist` / `chains_in_progress`)
> - 0 hardcoded scanner names (nmap/nuclei/sqlmap) in `AGENT_SYSTEM_PROMPT` body
> - **The real risk**: 7 references to `Controller` / `Hands` / `Eyes` / `X-Ray` module names in mandatory checklists (L201-210, L302, L420, L430). LLM will try to emit these as tool names if not redirected.
> - **Strategy β3 chosen**: prepend a ~15-line `LOOP_PROMPT_ADAPTER` constant that maps the legacy module names to Phase A tool names. Preserves the 200+ lines of OWASP/kill-chain/anti-bias guidance while overriding the tool naming.
> - **CRITICAL gotcha**: do NOT pass the adapter through `.format()` — the original prompt uses `{{...}}` for literal JSON braces and `{available_tools}` is the only placeholder. Concatenate AFTER formatting.

Insert all of the following AFTER `think()` (around line 800 in brain.py, before `record_result`). Do NOT modify `think()`.

**4a. Add the adapter constant** at module level (near `AGENT_SYSTEM_PROMPT` around line 182):

```python
# brain.py — NEW MODULE-LEVEL CONSTANT (place after AGENT_SYSTEM_PROMPT)
LOOP_PROMPT_ADAPTER = """\
[ADAPTER INSTRUCTIONS — these take precedence over anything in the prompt below]

You are operating in ScanAgentLoop mode (Phase A Strix-parity).

TOOL CATALOG RULES:
1. The tools listed under "## Available Tools" below are your ONLY tools.
   You MUST emit `"tool": "<exact name from that list>"` — nothing else.
2. The body of the prompt mentions VXIS module names like "Controller",
   "Hands", "Eyes", "X-Ray", "InteractionController", "SessionManager",
   "BrowserEngine", "FlowAnalyzer", "MitmProxy". These are NOT tool names
   in this mode. Map them to the closest tool in the catalog:
     - "Controller" / "fingerprint via Controller"  -> use cpr_recon or http_request
     - "Hands" / HTTP session work                  -> use http_request
     - "Eyes" / DOM/JS / screenshot                 -> use browser_render
     - "X-Ray" / passive traffic / token detection  -> use intercept_proxy
     - "Knowledge Store" / "Finding Model"          -> use report_finding / query_findings
     - chain reasoning                              -> use chain_synthesis / link_chain
     - finishing the scan                           -> emit finish_scan
3. The DONE-state JSON schema in the body (with module_checklist keys)
   is ADVISORY only. The required output schema for every step is:
     {{"reasoning": "...", "actions": [{{"tool": "...", "args": {{}}, "reasoning": "...", "priority": "high|medium|low"}}]}}
   module_checklist and owasp_checklist keys are optional and ignored.
4. If you cannot find a tool that matches your intent, choose the closest
   alternative from the catalog and explain the substitution in `reasoning`.
   NEVER emit a tool name that is not in the catalog.

[ORIGINAL PROMPT BELOW]
"""
```

**Note**: the JSON schema example inside the adapter uses `{{` `}}` because the adapter is a regular Python string literal — NO `.format()` is called on the adapter itself, so the doubled braces will appear as literal `{` `}` to the LLM. The doubled braces are needed only because the constant is defined with the same convention as `AGENT_SYSTEM_PROMPT` for consistency. **Verify by printing it** before committing: `print(LOOP_PROMPT_ADAPTER)` — you should see single braces `{` `}` in the output (Python-level string interpolation does not process `{{` outside of f-strings or `.format()`). Actually since this is a regular triple-quoted string (not an f-string), Python will NOT process the braces — `{{` will print as literal `{{`. **Use single braces in the adapter**, since it's never `.format()`'d. **Correct version**:

```python
# Corrected adapter — use SINGLE braces since this string is never .format()'d
LOOP_PROMPT_ADAPTER = """\
[ADAPTER INSTRUCTIONS — these take precedence over anything in the prompt below]

You are operating in ScanAgentLoop mode (Phase A Strix-parity).

TOOL CATALOG RULES:
1. The tools listed under "## Available Tools" below are your ONLY tools.
   You MUST emit `"tool": "<exact name from that list>"` — nothing else.
2. The body of the prompt mentions VXIS module names like "Controller",
   "Hands", "Eyes", "X-Ray", "InteractionController", "SessionManager",
   "BrowserEngine", "FlowAnalyzer", "MitmProxy". These are NOT tool names
   in this mode. Map them to the closest tool in the catalog:
     - "Controller" / "fingerprint via Controller"  -> use cpr_recon or http_request
     - "Hands" / HTTP session work                  -> use http_request
     - "Eyes" / DOM/JS / screenshot                 -> use browser_render
     - "X-Ray" / passive traffic / token detection  -> use intercept_proxy
     - "Knowledge Store" / "Finding Model"          -> use report_finding / query_findings
     - chain reasoning                              -> use chain_synthesis / link_chain
     - finishing the scan                           -> emit finish_scan
3. The DONE-state JSON schema in the body (with module_checklist keys)
   is ADVISORY only. The required output schema for every step is:
     {"reasoning": "...", "actions": [{"tool": "...", "args": {}, "reasoning": "...", "priority": "high|medium|low"}]}
   module_checklist and owasp_checklist keys are optional and ignored.
4. If you cannot find a tool that matches your intent, choose the closest
   alternative from the catalog and explain the substitution in `reasoning`.
   NEVER emit a tool name that is not in the catalog.

[ORIGINAL PROMPT BELOW]
"""
```

**4b. Add `think_in_loop()` method**:

```python
# brain.py — NEW METHOD on AgentBrain, sibling to think(). Insert before record_result().
async def think_in_loop(
    self,
    messages: list[dict[str, Any]],
    tool_catalog: list[dict[str, Any]],
) -> list[tuple[str, dict[str, Any]]]:
    """ScanAgentLoop entrypoint — takes persistent message history + dynamic tool catalog.

    Differs from think() in three ways:
    1. Consumes messages[] directly (no AgentObservation snapshot)
    2. Uses a dynamic tool_catalog passed in (not static TOOL_DESCRIPTIONS)
    3. Prepends LOOP_PROMPT_ADAPTER to override scanner-tool naming in AGENT_SYSTEM_PROMPT

    Shares with think():
    - AGENT_SYSTEM_PROMPT base template (formatted with dynamic catalog)
    - _call_llm_with_fallback provider fallback chain
    - _parse_response JSON parser
    - _increment_brain_decision_count for apples-to-apples counting
    - is_done / _step_count termination guards

    Omitted from v1 (re-add in Task 4b if Task 14 benchmarks show they matter):
    - _try_compiled_patterns (pattern cache)
    - _reflect (strategy pivot)
    - _get_chain_driven_actions (chain reasoner)
    - _record_step (step recording for legacy execution log)

    Returns: list of (tool_name, args_dict) tuples. Empty list = agent requests finish or LLM failed.
    """
    import asyncio

    # Termination guards (same as think())
    with self._state_lock:
        if self.is_done or self._step_count >= self.max_steps:
            self.is_done = True
            return []
        self._step_count += 1
    _increment_brain_decision_count()

    # Build dynamic tool block from the catalog passed in
    tools_text = "\n".join(
        f"  - {t['name']}: {t.get('description', '')}"
        for t in tool_catalog
    )

    # CRITICAL: format the body FIRST, then concatenate the adapter.
    # AGENT_SYSTEM_PROMPT contains {{...}} for literal JSON braces that .format() handles.
    # LOOP_PROMPT_ADAPTER contains literal { } and is NOT .format()'d.
    body_prompt = AGENT_SYSTEM_PROMPT.format(available_tools=tools_text)
    system_prompt = LOOP_PROMPT_ADAPTER + "\n" + body_prompt

    # Build user prompt from messages history — recent tool results + latest user msg
    history_lines: list[str] = []
    for m in messages[-20:]:  # last 20 msgs as tactical context; earlier deferred to Phase B memory store
        role = m.get("role", "?")
        content = m.get("content", "")
        if isinstance(content, dict):
            # tool message shape: {"name": ..., "args": ..., "result": {...}}
            name = content.get("name", "?")
            result = content.get("result", {})
            summary = result.get("summary", "") if isinstance(result, dict) else str(result)
            history_lines.append(f"[tool:{name}] {summary}")
        else:
            history_lines.append(f"[{role}] {str(content)[:500]}")

    user_prompt = (
        "## Conversation history (most recent last)\n"
        + "\n".join(history_lines)
        + "\n\n## Your task\n"
        + "Based on the history above, decide the next tool call(s). "
        + "Output EXACTLY this JSON shape (inside a ```json fence):\n"
        + '{"reasoning": "<why>", "actions": [{"tool": "<exact name from catalog>", "args": {...}, "reasoning": "<why>", "priority": "high|medium|low"}]}\n'
        + "To end the scan, emit a single action with tool='finish_scan'.\n"
        + "REMEMBER: only emit tool names that appear in '## Available Tools' above."
    )

    # Call LLM via the same fallback chain think() uses (sync method, run in thread)
    response = await asyncio.to_thread(
        self._call_llm_with_fallback, system_prompt, user_prompt
    )
    if response is None:
        logger.warning("think_in_loop: all LLM calls failed at step %d", self._step_count)
        return []

    # Parse using the same parser as think()
    actions = self._parse_response(response)
    return [(a.tool, a.args) for a in actions]
```

**Pre-commit verification** (add to Step 6 test list):

```python
# tests/agent/test_scan_loop_brain.py — additional verification test
@pytest.mark.asyncio
async def test_think_in_loop_adapter_concatenation_no_brace_explosion():
    """Regression guard: adapter prepend must not break .format() of AGENT_SYSTEM_PROMPT."""
    from vxis.agent.brain import AgentBrain, LOOP_PROMPT_ADAPTER, AGENT_SYSTEM_PROMPT
    # The adapter must be concatenated AFTER format, never before
    body = AGENT_SYSTEM_PROMPT.format(available_tools="  - test: test")
    full = LOOP_PROMPT_ADAPTER + "\n" + body
    # Sanity: contains both the adapter header and the body's first line
    assert "ADAPTER INSTRUCTIONS" in full
    assert "100% COVERAGE" in full  # body marker
    # Sanity: no doubled braces leaked through (the body resolves {{...}} → {...})
    assert "{{" not in full
    assert "}}" not in full
```

- [ ] **Step 5: Wire `brain` param into `ScanAgentLoop`**

```python
# scan_loop.py — modify __init__ and _decide
def __init__(
    self,
    target: str,
    registry: ToolRegistry,
    max_iters: int = 300,
    brain: Any | None = None,
) -> None:
    self.state = ScanLoopState(target=target, max_iters=max_iters)
    self.registry = registry
    self.brain = brain

async def _decide(self, state: ScanLoopState) -> list[tuple[str, dict[str, Any]]]:
    if self.brain is None:
        return [("finish_scan", {})]
    return await self.brain.think_in_loop(state.messages, self.registry.describe_all())
```

- [ ] **Step 6: Run tests — expect pass**

```bash
PYTHONPATH=$PWD/src poetry run pytest tests/agent/test_scan_loop_brain.py tests/agent/test_scan_loop.py tests/unit/test_phase_a_instrumentation.py -v
# Expected: all green. brain_decision_count increments verified.
```

- [ ] **Step 7: Smoke test against a real target (abbreviated)**

Run a 3-iter capped scan against Juice Shop to verify the end-to-end wire-up works (not a full benchmark — just proof-of-life):

```bash
export PYTHONPATH=$PWD/src
poetry run python -c "
import asyncio
from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry
from vxis.agent.brain import AgentBrain
from vxis.agent.tools.control_tools import FinishScanTool  # from Task 5

reg = ToolRegistry()
reg.register(FinishScanTool())
brain = AgentBrain()
loop = ScanAgentLoop(target='http://localhost:3000', registry=reg, max_iters=3, brain=brain)
result = asyncio.run(loop.run())
print('completed:', result['completed'], 'iters:', result['iterations'])
"
```

Expected: completes in ≤3 iters (Brain will likely finish_scan immediately because no real tools are registered yet). `brain_decision_count ≥ 1` after the run.

- [ ] **Step 8: Commit**

```bash
git add -u
git commit -m "feat(agent): wire AgentBrain.think_in_loop into ScanAgentLoop"
```

**Critical note:** Do NOT modify `AgentBrain.think()` itself. Add `think_in_loop` alongside. Touching the 1732-line legacy brain risks regressions; we isolate the migration to additive change only.

---

### Task 5: Wrap `finish_scan`, `think`, `wait` control tools

**Files:**
- Create: `src/vxis/agent/tools/__init__.py`
- Create: `src/vxis/agent/tools/control_tools.py`
- Test: `tests/agent/tools/test_control_tools.py`

- [ ] **Step 1: Failing test** — assert `FinishScanTool`, `ThinkTool`, `WaitTool` each conform to `BrainTool` protocol and return `ToolResult(ok=True)`.
- [ ] **Step 2: Implement** — minimal wrappers. `FinishScanTool.run()` returns `ToolResult(ok=True, data={"final": True})`. `ThinkTool.run(thought=...)` just logs and returns ok. `WaitTool.run(seconds=...)` does `await asyncio.sleep(min(seconds, 5))` and returns.
- [ ] **Step 3:** Register them in a helper `build_default_registry()` in `tools/__init__.py`.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit:** `feat(agent/tools): add control tools (finish, think, wait)`

---

### Task 6: Expose Hands/X-Ray primitives as tools

**Files:**
- Create: `src/vxis/agent/tools/hands_tools.py`
- Test: `tests/agent/tools/test_hands_tools.py`

Scope: wrap existing primitives (`src/vxis/primitives/` or equivalent — verify location first) as BrainTools without reimplementing logic.

- [ ] **Step 1:** `grep -rn "class.*Hands\|class.*XRay\|def send_request" src/vxis/primitives/ src/vxis/agent/executor.py` — locate the real primitive interfaces first. Document in a scratchpad.
- [ ] **Step 2: Failing test** — a `http_request` tool and a `browser_render` tool each return `ToolResult` with status code and body length for a stubbed httpx response (use `respx` for mocking).
- [ ] **Step 3: Implement** `HttpRequestTool`, `BrowserRenderTool`, `InterceptProxyTool` as thin adapters. Each `run()` calls the existing primitive and maps the return to `ToolResult`.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit:** `feat(agent/tools): wrap Hands/Eyes/X-Ray primitives as BrainTools`

---

## 🚨 PIVOT 2026-04-09 — Tasks 7-11 REPLACED with Strix-power tools

**Discovery:** On starting Task 7, verified that `src/vxis/phases/guides/*.py` files are `PhaseGuide` metadata objects (playbooks), NOT execution code. All phase execution logic lives inside `ScanPipeline._phaseN_*` methods in `pipeline.py`, tightly coupled to `self` and `ScanContext`. Extracting them is exactly Task 13's job — Tasks 7-11 as originally planned would have been duplicated work.

**Decision:** Replace Tasks 7-11 (5 Phase wrappers) with 2 Strix-power tools. This makes VXIS architecturally equivalent to Strix: low-level primitives + unrestricted shell + Python subprocess + Docker sandbox isolation. Brain drives scanner selection dynamically per target instead of being boxed into hardcoded phases.

**Trade-off accepted:** Phase A benchmark (Task 14 revised) may show lower finding count than baseline temporarily — because gpt-5.4-mini running ad-hoc shell commands is less tuned than the current hand-coded phase pipeline. The win is that `brain_decision_count` is meaningful (each decision is a strategic scanner choice, not a micro-payload step) AND Phase B can trivially scale quality by adding better scanners or better models without touching the architecture.

**Enterprise gate note:** `shell_exec` bypasses the existing Hands-layer deferred mutation queue (sqlmap/nuclei do their own HTTP clients). For Phase A this is intentional — targets are local Docker (Juice Shop / WebGoat) and full destructive power is the goal ("real hacker simulation"). Phase C will add a second-layer egress filter on the sandbox for enterprise scans against customer production.

### Revised task list (15 → 12)

```
✅ Task 1-6 complete (baseline, registry, loop, think_in_loop, control, Hands/Eyes/Xray)
🎯 Task 7  (NEW)       shell_exec tool + vxis-sandbox Docker image (Strix terminal equivalent)
   Task 8  (NEW)       python_exec tool (Strix python equivalent, same sandbox)
   Task 9  (was 12)    Finding CRUD tools
   Task 10 (was 13)    🔥 pipeline.py gutting — DELETE _phaseN_* methods (no extraction)
   Task 11 (was 14)    🚦 Benchmark gate (brain_decision_count >> 0)
   Task 12 (was 15)    Cleanup obsolete phase guide files
```

---

### Task 7 (NEW): `shell_exec` tool + Docker sandbox

**Files:**
- Create: `docker/sandbox/Dockerfile` — `debian:trixie-slim` base + `sqlmap ffuf nuclei nikto gobuster wapiti dalfox jwt_tool httpx arjun curl python3 python3-pip` installed
- Create: `src/vxis/agent/tools/shell_tools.py` — `ShellExecTool` class, lifecycle manager for `vxis-sandbox` container
- Modify: `src/vxis/agent/tools/__init__.py` — register `ShellExecTool` in `build_default_registry()`
- Test: `tests/agent/tools/test_shell_tools.py`

**`ShellExecTool` behavior:**
- `name = "shell_exec"`
- `input_schema = {"type": "object", "properties": {"command": {"type": "string"}, "timeout": {"type": "number", "default": 120}}, "required": ["command"]}`
- `run(command, timeout=120)`:
  1. Lazy-init: if `vxis-sandbox` container not running, start it via `docker run -d --name vxis-sandbox --network host -v /tmp/vxis-workspace:/workspace vxis/sandbox:latest sleep infinity`. If image not built, return `ToolResult(ok=False, summary="vxis-sandbox image not built — run: docker build -t vxis/sandbox:latest docker/sandbox/")`.
  2. Dispatch: `asyncio.create_subprocess_exec("docker", "exec", "vxis-sandbox", "sh", "-c", command)` with the timeout
  3. Capture stdout/stderr, return:
     ```python
     ToolResult(
         ok=(exit_code == 0),
         data={"stdout": stdout[:5000], "stderr": stderr[:2000], "exit_code": exit_code, "command": command[:200]},
         summary=f"shell_exec: exit={exit_code}, {len(stdout)} bytes stdout",
     )
     ```
- **Unrestricted**: no command whitelist, no arg filtering. Brain emits any shell command and it runs inside the sandbox.
- **Module-level container lifecycle**: a helper `_ensure_sandbox_running()` that's idempotent and caches state.
- **Cleanup**: add `_reset_for_tests()` following the Task 6 pattern. Production code does NOT auto-stop the container; it stays warm across scans.

**Dockerfile sketch:**
```dockerfile
FROM debian:trixie-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    sqlmap ffuf nikto gobuster wapiti dirb curl wget jq \
    python3 python3-pip python3-venv python3-httpx python3-aiohttp \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Nuclei (Go-based, install binary)
RUN curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.4/nuclei_3.3.4_linux_$(dpkg --print-architecture).zip" -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

# httpx, arjun, dalfox via pip where available
RUN pip3 install --break-system-packages httpx dalfox-py jwt-tool arjun 2>/dev/null || true

WORKDIR /workspace
CMD ["sleep", "infinity"]
```

(The subagent may adjust package names for availability — record actual packages installed in the Dockerfile.)

**Tests (unit, mocked docker):**
- `test_shell_exec_tool_conforms_to_brain_tool` — isinstance check
- `test_shell_exec_tool_runs_command_via_docker_exec` — mock `asyncio.create_subprocess_exec`, verify called with `["docker", "exec", "vxis-sandbox", "sh", "-c", command]`
- `test_shell_exec_tool_captures_exit_code_and_stdout` — mock returns exit=0, stdout="hello"
- `test_shell_exec_tool_timeout_handling` — mock raises `asyncio.TimeoutError`, verify graceful fail
- `test_shell_exec_tool_image_not_built` — mock `_check_image_exists` returns False, verify error ToolResult
- `test_build_default_registry_now_has_seven_tools` — registry count assertion (control 3 + Hands/Eyes/Xray 3 + shell_exec 1 = 7)

**Manual integration (not in CI):**
- Controller builds the Docker image manually: `docker build -t vxis/sandbox:latest docker/sandbox/`
- Smoke test: `shell_exec("nuclei -u http://localhost:3000 -severity high")` — verify real nuclei runs

**Commit:** `feat(agent/tools): add shell_exec tool + vxis-sandbox Docker image`

---

### Task 8 (NEW): `python_exec` tool

**Files:**
- Create: `src/vxis/agent/tools/python_tools.py` — `PythonExecTool`
- Modify: `src/vxis/agent/tools/__init__.py` — register
- Test: `tests/agent/tools/test_python_tools.py`

**`PythonExecTool` behavior:**
- `name = "python_exec"`
- `input_schema = {"type": "object", "properties": {"code": {"type": "string"}, "timeout": {"type": "number", "default": 120}}, "required": ["code"]}`
- `run(code, timeout=120)`:
  1. Ensure sandbox running (reuse `shell_tools._ensure_sandbox_running`)
  2. Write code to `/tmp/vxis-workspace/_python_exec_<uuid>.py` on the host (mounted into sandbox at `/workspace/`)
  3. Dispatch: `docker exec vxis-sandbox python3 /workspace/_python_exec_<uuid>.py`
  4. Capture stdout/stderr, cleanup the temp file
  5. Return ToolResult with stdout/stderr/exit_code

**Why a separate tool (not just `shell_exec python3 -c '...'`):**
- Multi-line Python with quotes is painful to escape in a single command string
- File-based dispatch lets Brain write larger scripts cleanly
- Shared `/workspace` volume means Brain can persist state (CSVs of discovered endpoints, found credentials, etc.) between tool calls

**Tests:**
- `test_python_exec_tool_conforms_to_brain_tool`
- `test_python_exec_tool_writes_code_to_tempfile_and_dispatches`
- `test_python_exec_tool_captures_output`
- `test_python_exec_tool_timeout`
- `test_python_exec_tool_cleanup_on_error`
- `test_build_default_registry_now_has_eight_tools`

**Commit:** `feat(agent/tools): add python_exec tool (Strix python equivalent)`

---

### ~~Task 7: Classify and wrap Phase 4 CPR as `cpr_recon` tool~~ (DELETED — see pivot above)

### ~~Task 8-11: Phase wrappers~~ (DELETED — see pivot above)

### OLD Task 7 content (kept below for reference, DO NOT IMPLEMENT):

**Files:**
- Read: `src/vxis/phases/p4_cpr.py` (entire file)
- Create: `src/vxis/agent/tools/recon_tools.py`
- Test: `tests/agent/tools/test_recon_tools.py`

- [ ] **Step 1:** Read `p4_cpr.py`. Identify the *pure logic* function (the part that does recon) vs the *orchestration glue* (the part that reads/writes `ScanContext`). The pure logic becomes the tool body; the glue is discarded.
- [ ] **Step 2: Failing test** — `cpr_recon` tool on a mocked target returns `ToolResult` with a `data={"endpoints": [...], "subdomains": [...]}` shape.
- [ ] **Step 3: Implement** `CprReconTool` that imports the pure logic from `p4_cpr` and wraps it.
- [ ] **Step 4: Tests pass.**
- [ ] **Step 5: Commit:** `feat(agent/tools): wrap P4 CPR as cpr_recon BrainTool`

**Apply the same pattern to Tasks 8-11:**

---

### Task 8: Wrap P15 Digital Twin + P13 Biometrics as recon tools

Same pattern as Task 7. Extends `recon_tools.py`. One test each. One commit.

### Task 9: Wrap P2 Agents + P3 Hypothesis as `intel_tools.py`

Same pattern. Note: P3 Hypothesis should hook into the existing `graph/hypothesis.py` `HypothesisQueue`. The tool adds hypotheses to the queue, Brain reads them back via `list_hypotheses` tool.

### Task 10: Wrap P5 Special + P7 Hardware as `exploit_tools.py`

Same pattern. Note: P5 Special contains the injection logic — it MUST route through the existing enterprise deferred-action gate (keep this invariant).

### Task 11: Wrap P8 Synthesis + P11 Mutation as `chain_tools.py`

Same pattern. P8 Synthesis is a candidate for deletion instead of wrapping — check: if its only role is to merge findings across phases, Brain does this natively via `messages[]` and we delete it. Decide per-file.

### Task 12: Finding CRUD tools

**Files:** `src/vxis/agent/tools/finding_tools.py`

Tools: `report_finding(finding_dict)`, `query_findings(filter)`, `link_chain([finding_ids])`. Backed by `state.findings` list initially (Phase B will replace with DB). One test each. One commit.

---

### Task 13: Gut `pipeline.py` to the shim

**Files:**
- Modify: `src/vxis/pipeline/pipeline.py` (5234 → target <1000 lines)
- Modify: `src/vxis/pipeline/__init__.py`
- Test: `tests/pipeline/test_pipeline_shim.py`

- [ ] **Step 1:** Read `pipeline.py:707-1300` (`ScanPipeline` class and `run()` method) to identify the parts that MUST survive: (a) target normalization, (b) `ScanContext` bootstrap, (c) deferred-action gate invocation, (d) report generation call.
- [ ] **Step 2: Failing integration test**

```python
# tests/pipeline/test_pipeline_shim.py
import pytest
from vxis.pipeline.pipeline import ScanPipeline

@pytest.mark.asyncio
async def test_pipeline_delegates_to_scan_loop(monkeypatch):
    called = {}
    from vxis.agent.scan_loop import ScanAgentLoop
    original_run = ScanAgentLoop.run
    async def spy_run(self):
        called["ran"] = True
        called["target"] = self.state.target
        return {"target": self.state.target, "completed": True, "findings": [], "iterations": 1, "messages": 2}
    monkeypatch.setattr(ScanAgentLoop, "run", spy_run)

    pipe = ScanPipeline()
    result = await pipe.run("http://example.com")
    assert called["ran"] is True
    assert called["target"] == "http://example.com"
```

- [ ] **Step 3: Rewrite `ScanPipeline.run`** to:
  1. Normalize target
  2. Build `ScanContext`
  3. Build `ToolRegistry` via `tools.build_default_registry(ctx)`
  4. Instantiate `AgentBrain` + `ScanAgentLoop(target, registry, brain=brain)`
  5. `await loop.run()`
  6. Run deferred-action gate
  7. Generate report
  8. Return structured result

- [ ] **Step 4: Delete** all `_run_phase`, `Stage` dispatch, parallel phase coros, phase registry lookups. Keep only the 8 steps above.
- [ ] **Step 5: Run full test suite**

```bash
pytest tests/ -x --ignore=tests/slow
wc -l src/vxis/pipeline/pipeline.py
# Expected: pytest pass, wc < 1000
```

- [ ] **Step 6: Commit:** `refactor(pipeline): gut ScanPipeline to thin shim over ScanAgentLoop`

**Rollback safety:** Keep a git branch `legacy/phase-pipeline-pre-migration` pointing to the commit before Task 13 so we can A/B compare for weeks after.

---

### Task 14: Run Phase A acceptance benchmark

**Files:** `docs/superpowers/benchmarks/2026-04-08-phase-a-result.md`

- [ ] **Step 1:** Run the same 3-target benchmark from Task 1 against the new loop. Capture the same metrics.
- [ ] **Step 2:** Compare against Task 1 baseline. Success criteria from the header:
  1. Scan finishes in one continuous loop ✓
  2. Findings ≥ baseline
  3. Chain depth ≥ baseline
  4. `pipeline.py` < 1000 lines
  5. All tests pass
- [ ] **Step 3:** If any criterion fails, **do not proceed to Phase B**. Open debugging with `superpowers:systematic-debugging`.
- [ ] **Step 4:** If all pass, write result doc, commit, tag `phase-a-complete`.

```bash
git tag phase-a-complete
git commit -m "bench: Phase A acceptance — ScanAgentLoop at parity with legacy pipeline"
```

---

### Task 15: Delete obsolete phase files (cleanup)

**Files:** `src/vxis/phases/p0_foundation.py`, `p1_director.py`, `p8_synthesis.py` (confirm each is truly glue-only before deletion in Tasks 9/11).

- [ ] **Step 1:** For each candidate file, grep for remaining imports: `grep -rn "from vxis.phases.p0_foundation\|from vxis.phases.p1_director\|from vxis.phases.p8_synthesis" src/ tests/`
- [ ] **Step 2:** If no importers remain, delete the file + its entry in `phases/registry.py` + any test file.
- [ ] **Step 3:** Run full test suite.
- [ ] **Step 4: Commit:** `chore(phases): remove obsolete glue phases after migration`

---

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| `AgentBrain.think()` signature assumes `AgentObservation` per-call context; loop integration breaks it | Task 4 adds `think_in_loop` additively. Do NOT modify `think()`. |
| Some "phase glue" hides real domain logic we'd lose on deletion | Task 15 is last and requires grep verification. Deletion gated on Task 14 success. |
| `pipeline.py` gutting breaks unrelated callers (CLI, MCP server, dashboard) | Task 13 integration test + full test suite. Keep `ScanPipeline.run()` signature stable. |
| Benchmark regression hides in chain-depth metric (fewer phases → fewer synthetic "chains" even if real chains are better) | Task 14 uses *real* findings chain depth from the report, not phase count. |
| 5234-line gutting is error-prone | Do it in Task 13 as ONE commit after Tasks 2-12 provide a working alternative. Keep `legacy/phase-pipeline-pre-migration` branch for 4 weeks post-merge. |
| LLM cost explodes because single loop = longer context | Monitor token count in Task 14. If >30% regression, add `MemoryCompressor` equivalent BEFORE Phase B. |

---

## Self-Review

**1. Spec coverage:**
- Kill 14-phase orchestrator → Task 13 ✓
- Single persistent `messages[]` → Task 3 + 4 ✓
- Phases demoted to tools → Tasks 7-12 ✓
- Hands/X-Ray/Finding as tools → Tasks 6, 12 ✓
- `pipeline.py` < 1000 lines → Task 13 success criterion ✓
- Parity benchmark → Tasks 1, 14 ✓
- No regression in existing tests → every task runs pytest ✓

**2. Placeholder scan:** Tasks 7-11 use "same pattern as Task 7" — acceptable because Task 7 is fully spelled out and the pattern is mechanical. Tasks 5, 6, 8-12 have acceptance criteria but less verbose code — acceptable because they're wrappers over existing well-understood modules.

**3. Type consistency:** `ToolResult`, `BrainTool`, `ToolRegistry`, `ScanLoopState`, `ScanAgentLoop`, `think_in_loop` — all names used consistently across tasks. ✓

---

## Execution Handoff

Phase A is a high-risk migration (gutting 5234 lines) but the task decomposition keeps the risk isolated to Task 13, which is preceded by 12 additive tasks that establish a working parallel loop. Recommend **Subagent-Driven execution** with two-stage review between Tasks 4, 12, 13, and 14 — these are the high-blast-radius checkpoints.
