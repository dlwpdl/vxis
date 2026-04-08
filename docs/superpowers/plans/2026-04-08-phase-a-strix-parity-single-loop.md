# Phase A — Strix-Parity Single-Loop Migration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Kill the 14-Phase pipeline orchestrator and make a single persistent `AgentBrain.think()` ReAct loop the owner of an entire scan end-to-end, with existing Phase logic demoted to high-level tools the Brain can call.

**Architecture:** VXIS already has a ReAct-style brain (`AgentBrain.think`), hypothesis queue (`graph/hypothesis.py`), and attack graph (`graph/attack_graph.py`). What it lacks is a single persistent outer loop that owns `messages[]` for the whole scan. We build `ScanAgentLoop` as the new top-level entrypoint (Strix `base_agent.agent_loop` equivalent). `pipeline.py` becomes a thin shim that constructs `ScanAgentLoop` and runs it. Each of the 14 phases is classified: valuable domain logic → wrapped as a `BrainTool`, thin glue → deleted. Hands/Eyes/X-Ray/Finding stay as low-level tools. No context dict passing between "stages" — one `messages[]` array for the whole scan.

**Tech Stack:** Python 3.12, existing VXIS modules (`agent/brain.py`, `agent/runner.py`, `agent/executor.py`, `graph/hypothesis.py`, `evidence/engine.py`, Hands/X-Ray), pytest, no new dependencies.

**Non-goals for Phase A (deferred to Phase B/C/D):** Episodic memory DB, critic loop, typed blackboard, 1M context mode, domain runtimes (Game/Mobile/HW). Phase A is *parity*, not differentiation.

**Success criteria (hard gate before Phase B):**
1. A scan against `juice-shop` local docker finishes in one continuous Brain loop, with `messages[]` never truncated between "phases".
2. Findings count ≥ current `pipeline.py` baseline on DVWA/Juice Shop/WebGoat (same 3 targets as `growth-loop.yml`).
3. Chain depth (max `attack_chain` length in report) ≥ current baseline.
4. `pipeline.py` reduced below 1000 lines (from 5234).
5. All existing tests still pass; new tests added for `ScanAgentLoop`.

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

### Task 4: Wire `AgentBrain` into `ScanAgentLoop._decide`

**Files:**
- Modify: `src/vxis/agent/scan_loop.py`
- Modify: `src/vxis/agent/brain.py` (add `think_in_loop(messages)` thin wrapper around existing `think()`; do not rewrite `think()` itself)
- Test: `tests/agent/test_scan_loop_brain.py`

- [ ] **Step 1:** Read `brain.py:502-741` to understand `think()` signature (takes `AgentObservation`, returns `list[AgentAction]`). Document the exact shape in a docstring comment.
- [ ] **Step 2: Failing test**

```python
# tests/agent/test_scan_loop_brain.py
import pytest
from unittest.mock import MagicMock, AsyncMock
from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult

class EchoTool:
    name = "echo"; description = "echo"; input_schema = {"type": "object"}
    async def run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, summary="echoed", data=kw)

@pytest.mark.asyncio
async def test_brain_drives_loop(monkeypatch):
    reg = ToolRegistry(); reg.register(EchoTool())
    fake_brain = MagicMock()
    fake_brain.think_in_loop = AsyncMock(side_effect=[
        [("echo", {"msg": "hello"})],
        [("finish_scan", {})],
    ])
    class FinishTool:
        name = "finish_scan"; description = ""; input_schema = {"type": "object"}
        async def run(self, **kw): return ToolResult(ok=True, summary="done")
    reg.register(FinishTool())

    loop = ScanAgentLoop(target="http://x", registry=reg, max_iters=5, brain=fake_brain)
    result = await loop.run()
    assert result["completed"] is True
    assert fake_brain.think_in_loop.await_count == 2
```

- [ ] **Step 3: Add `brain` param + `think_in_loop` call**

```python
# scan_loop.py — modify __init__ and _decide
def __init__(self, target, registry, max_iters=300, brain=None):
    self.state = ScanLoopState(target=target, max_iters=max_iters)
    self.registry = registry
    self.brain = brain

async def _decide(self, state):
    if self.brain is None:
        return [("finish_scan", {})]
    return await self.brain.think_in_loop(state.messages, self.registry.describe_all())
```

- [ ] **Step 4: Add `think_in_loop` to `AgentBrain`**

```python
# brain.py — ADD NEW METHOD, do not touch existing think()
async def think_in_loop(
    self, messages: list[dict], tools: list[dict]
) -> list[tuple[str, dict]]:
    """Loop-driven entrypoint: receives full message history + tool catalog,
    returns list of (tool_name, args) to execute. Preserves messages across iterations
    (unlike legacy think() which rebuilt AgentObservation per phase).
    """
    # Build a synthetic AgentObservation from the latest messages (compatibility shim)
    last_tool_msgs = [m for m in messages[-10:] if m.get("role") == "tool"]
    observation_text = "\n".join(
        f"{m.get('content', {}).get('name', '?')}: {m.get('content', {}).get('result', {}).get('summary', '')}"
        for m in last_tool_msgs
    ) or "Scan started. No prior observations."
    # Delegate to existing sync think() via executor
    import asyncio
    from vxis.agent.brain import AgentObservation
    obs = AgentObservation(target=self._target_for_loop, raw_text=observation_text, history=messages)
    actions = await asyncio.to_thread(self.think, obs)
    return [(a.tool, a.params) for a in actions]
```

- [ ] **Step 5: Run tests**

```bash
pytest tests/agent/test_scan_loop_brain.py tests/agent/test_scan_loop.py -v
```

- [ ] **Step 6: Commit**

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

### Task 7: Classify and wrap Phase 4 CPR as `cpr_recon` tool

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
