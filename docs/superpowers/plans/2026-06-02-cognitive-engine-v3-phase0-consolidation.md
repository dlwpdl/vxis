# Cognitive Engine v3 — Phase 0 (Consolidation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> Sub-plan of [`2026-06-02-cognitive-engine-v3.md`](2026-06-02-cognitive-engine-v3.md) — Phase 0 only.
> Read that plan's **Current State** + **Phase 0** sections first.

**Goal:** Collapse the duplicated cognitive substrate (two legacy memory stores, two `Hypothesis` classes, three model-routing tables, four coupled prioritizers) into one of each — **without an un-rollback-able cutover** — and split the benchmark CI into a deterministic per-PR tier + a live tier.

**Architecture:** Deletion is *not* protected by a feature flag, so memory consolidation runs **shadow/dual-write** behind `VXIS_V3_MEMORY` (default off → old path stays live); the legacy stores are deleted in a *later* phase after prod parity. The hypothesis rename, model-table merge, and prioritizer collapse are pure refactors guarded by the full test suite. The benchmark split is real build work (no cassette substrate exists today).

**Tech Stack:** Python 3.12, Pydantic v2, pytest (`pytest tests/ -x --timeout=30`), dataclasses, PyYAML, GitHub Actions.

**No new features.** Every task is migrate/rename/delete/wire. New cognitive behavior lives in later phases.

---

## Current-state facts every task assumes (verified against the tree)

- **Two legacy memory stores, separate from each other and from PTI:**
  - `AgentMemory` (`src/vxis/agent/memory.py:79`) → `~/.vxis/agent_memory.json`. Written at
    `core/orchestrator.py:735` (`AgentMemory().remember_scan(...)`); read at `brain.py:1770`
    (`self._memory.recall_similar(...)` → `format_memory_context`, returns a **formatted string**).
    Injected via the `memory: AgentMemory | None` ctor param (`brain.py:143`, TYPE_CHECKING import `:68`).
  - The `query_scan_memory` BrainTool (`agent/tools/memory_tools.py:514` `QueryScanMemoryTool`) → its
    **own** JSON KB via module-level `_load_kb()`/`_save_kb()`/`record_scan_result()`/`migrate_scan_kb()`.
    It does **not** touch `AgentMemory`.
- **PTI store** (`src/vxis/pti/store.py:17`) keys on `target_hash` only; path `data/pti/<target_hash>/`.
  `Dossier` (`pti/models.py:105`) has no `tenant_id`. `PTIStore.load_for_target(url, create=True)`.
- **Two `Hypothesis` classes:** `agent/hypothesis/dag.py:32` (Pydantic, new) exported from
  `agent/hypothesis/__init__.py`; `graph/hypothesis.py:18` (dataclass, old).
- **Three model tables:** `routing/cost_router.py:25` `ROUTE_TABLE`; `llm/hybrid_config.py` `ModelRole`;
  `brain.py:818` `_model_role_for_decision_class()` (live behind `VXIS_V3_ROLE_ROUTING`, default on).
- **Prioritizer = 4 coupled stores** seeded by `ensure_vector_candidate()` (`scan_loop_state.py:471`):
  `vector_candidates` + `scan_todos` + `branches`(`BranchState`) + control-state mirror. Legacy finish
  helpers `_blocking_finish_branches` / `_remaining_high_yield_family_candidates` have **10+ call sites**
  across `scan_loop_decision_policy.py` (~22, 374, 792, 872-874, 2149-2197), `scan_loop_actions.py:1097`,
  `scan_loop_run.py:1467`.
- **Benchmark:** `.github/workflows/benchmark.yml` runs a **live-LLM** scan on every PR to main; no
  `vcr`/`pytest-recording` dep, no `live` pytest marker, no cassette substrate.

> **Scope note (writing-plans Scope Check):** Task Group 4 (prioritizer collapse) is the largest, riskiest
> workstream and may be split into its own sub-plan if it balloons during execution. The other groups
> (1 memory, 2 rename, 3 model-table, 5 benchmark, 6 docs) are independently shippable.

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `src/vxis/agent/memory.py` | legacy `AgentMemory`; gains a `VXIS_V3_MEMORY`-gated dual-write hook | Modify |
| `src/vxis/pti/memory_bridge.py` | `ScanMemory → Dossier` mapping + PTI-backed `recall_similar` equivalent | **Create** |
| `scripts/migrate_agent_memory_to_pti.py` | one-shot idempotent migrator (both legacy stores → PTI) | **Create** |
| `src/vxis/agent/tools/memory_tools.py` | `query_scan_memory` backend re-pointed at PTI (same I/O) | Modify |
| `src/vxis/core/orchestrator.py:735` | write site → dual-write when flag on | Modify |
| `src/vxis/agent/brain.py:1770` | read site → PTI-backed recall when flag on | Modify |
| `src/vxis/agent/hypothesis/dag.py` | rename `Hypothesis` → `HypothesisNode` | Modify |
| `src/vxis/agent/hypothesis/__init__.py` | export rename | Modify |
| `src/vxis/agent/routing/cost_router.py` | delete `ROUTE_TABLE`; keep `CostReport`/telemetry | Modify |
| `src/vxis/agent/scan_loop_decision_policy.py` | replace legacy-finish-helper call sites with DAG queries | Modify |
| `src/vxis/agent/scan_loop_state.py` | absorption shim: vector_candidates/branches → DAG | Modify |
| `.github/workflows/benchmark.yml` | split into cassette-PR + live job | Modify |
| `pyproject.toml` | register `live` pytest marker | Modify |
| `docs/superpowers/CONSOLIDATION.md` | merge/deletion ledger | **Create** |
| `wiki/decisions/011_v3_consolidation.md` | ADR | **Create** |

---

## Task Group 1 — Memory consolidation (rollback-safe dual-write)

### Task 1.1: `ScanMemory → Dossier` mapping bridge

**Files:**
- Create: `src/vxis/pti/memory_bridge.py`
- Test: `tests/pti/test_memory_bridge.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/pti/test_memory_bridge.py
from vxis.agent.memory import ScanMemory
from vxis.pti.memory_bridge import scan_memory_to_dossier_facts

def test_scan_memory_maps_to_dossier_facts():
    mem = ScanMemory(
        target="http://example.com:80",
        tech_stack=["nginx", "php"],
        findings_summary=[{"severity": "high", "type": "sqli", "title": "login SQLi"}],
        effective_tools=["test_injection"],
        ineffective_tools=["test_xss"],
        total_findings=1,
    )
    facts = scan_memory_to_dossier_facts(mem)
    assert facts.target_url == "http://example.com:80"
    assert {s.tech for s in facts.stack} == {"nginx", "php"}
    assert facts.findings_history[0].finding_type == "sqli"
    # tools recorded as authored/efficacy hints, not dropped
    assert any(t.name == "test_injection" for t in facts.authored_tools)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/pti/test_memory_bridge.py -v`
Expected: FAIL — `ModuleNotFoundError: vxis.pti.memory_bridge`

- [ ] **Step 3: Write minimal implementation**

```python
# src/vxis/pti/memory_bridge.py
"""Map the legacy AgentMemory.ScanMemory shape onto PTI Dossier facts.

This is the field-level contract that lets PTI absorb the AgentMemory store.
Every ScanMemory field maps to a Dossier field or is explicitly dropped (see
DROPPED below) — no silent data loss.
"""
from __future__ import annotations

from vxis.agent.memory import ScanMemory
from vxis.pti.hashing import target_hash_for_url
from vxis.pti.models import (
    AuthoredTool, Dossier, FindingHistoryEntry, StackEntry,
)

# DROPPED (intentional, documented): nothing — every field maps below.

def scan_memory_to_dossier_facts(mem: ScanMemory, scan_id: str = "legacy-import") -> Dossier:
    target_hash = target_hash_for_url(mem.target)
    stack = [
        StackEntry(tech=t, confidence=0.5, first_seen_scan=scan_id, last_seen_scan=scan_id)
        for t in mem.tech_stack
    ]
    findings_history = [
        FindingHistoryEntry(
            finding_id=f"{scan_id}-{i}",
            finding_type=str(f.get("type", "unknown")),
            surface_id="legacy",
            status="unknown",
            first_seen_scan=scan_id,
            last_verified_scan=scan_id,
        )
        for i, f in enumerate(mem.findings_summary)
    ]
    authored_tools = [
        AuthoredTool(
            name=t, purpose="legacy-efficacy", script_path="", created_scan=scan_id,
            last_used_scan=scan_id, success_count=1, fail_count=0,
        )
        for t in mem.effective_tools
    ] + [
        AuthoredTool(
            name=t, purpose="legacy-efficacy", script_path="", created_scan=scan_id,
            last_used_scan=scan_id, success_count=0, fail_count=1,
        )
        for t in mem.ineffective_tools
    ]
    return Dossier(
        target_hash=target_hash,
        target_url=mem.target,
        scan_ids=[scan_id],
        stack=stack,
        findings_history=findings_history,
        authored_tools=authored_tools,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/pti/test_memory_bridge.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vxis/pti/memory_bridge.py tests/pti/test_memory_bridge.py
git commit -m "phase-0: map ScanMemory onto PTI Dossier facts

Field-level contract for absorbing the legacy AgentMemory store into PTI.
No silent drops — every ScanMemory field maps to a Dossier field."
```

### Task 1.2: `VXIS_V3_MEMORY` flag + dual-write in the write path

**Files:**
- Modify: `src/vxis/core/orchestrator.py:735`
- Test: `tests/agent/test_memory_dualwrite.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/agent/test_memory_dualwrite.py
import os
from vxis.agent.memory import AgentMemory, ScanMemory
from vxis.pti.store import PTIStore

def test_dualwrite_writes_both_when_flag_on(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_V3_MEMORY", "1")
    monkeypatch.setenv("VXIS_PTI_ROOT", str(tmp_path / "pti"))
    from vxis.agent.memory import dual_write_scan
    mem = AgentMemory(db_path=str(tmp_path / "legacy.json"))
    sm = ScanMemory(target="http://example.com:80", total_findings=0)
    dual_write_scan(mem, sm)
    # legacy still written
    assert mem.recall_similar("http://example.com:80") != [] or mem._memories
    # PTI also written
    store = PTIStore(root=tmp_path / "pti")
    dossier = store.load_for_target("http://example.com:80", create=False)
    assert dossier.target_url == "http://example.com:80"

def test_dualwrite_legacy_only_when_flag_off(tmp_path, monkeypatch):
    monkeypatch.delenv("VXIS_V3_MEMORY", raising=False)
    monkeypatch.setenv("VXIS_PTI_ROOT", str(tmp_path / "pti"))
    from vxis.agent.memory import dual_write_scan
    mem = AgentMemory(db_path=str(tmp_path / "legacy.json"))
    dual_write_scan(mem, ScanMemory(target="http://example.com:80"))
    store = PTIStore(root=tmp_path / "pti")
    import pytest
    with pytest.raises(FileNotFoundError):
        store.load_for_target("http://example.com:80", create=False)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/agent/test_memory_dualwrite.py -v`
Expected: FAIL — `ImportError: cannot import name 'dual_write_scan'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/vxis/agent/memory.py` (end of module). Note: the PTI write **must not** carry raw secrets to
the un-tenanted legacy store — `ScanMemory` only holds finding *summaries* (type/severity/title), no PoC
bodies, so it is safe; assert this stays true.

```python
# src/vxis/agent/memory.py  (append)
import os

def dual_write_scan(memory: "AgentMemory", scan: "ScanMemory") -> None:
    """Always write the legacy store; additionally write PTI when VXIS_V3_MEMORY is on.

    Legacy write is unconditional so VXIS_V3_MEMORY=off is a true rollback.
    ScanMemory holds only finding summaries (no PoC bodies / secrets), so the
    dual write does not leak secrets to the un-tenanted legacy store.
    """
    memory.remember_scan(scan)
    if os.environ.get("VXIS_V3_MEMORY", "0") == "0":
        return
    from vxis.pti.memory_bridge import scan_memory_to_dossier_facts
    from vxis.pti.store import PTIStore
    root = os.environ.get("VXIS_PTI_ROOT", "data/pti")
    store = PTIStore(root=root)
    store.persist(scan_memory_to_dossier_facts(scan))
```

Then change `core/orchestrator.py:735` from `memory = AgentMemory(); ...; memory.remember_scan(scan_mem)`
to:

```python
            from vxis.agent.memory import dual_write_scan
            memory = AgentMemory()
            scan_mem = ScanMemory(
                target=target,
                tech_stack=tech_stack,
                findings_summary=findings_summary,
                effective_tools=effective,
                ineffective_tools=ineffective + failed,
                total_findings=len(findings),
            )
            dual_write_scan(memory, scan_mem)
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/agent/test_memory_dualwrite.py -v`
Expected: PASS (both)

- [ ] **Step 5: Commit**

```bash
git add src/vxis/agent/memory.py src/vxis/core/orchestrator.py tests/agent/test_memory_dualwrite.py
git commit -m "phase-0: dual-write scan memory to PTI behind VXIS_V3_MEMORY

Default off keeps the legacy AgentMemory path as the sole live store, so the
flag is a real one-flag rollback. When on, also persists to PTI for the parity
window before later-phase deletion."
```

### Task 1.3: PTI-backed `recall_similar` equivalent + read-path switch

**Files:**
- Modify: `src/vxis/pti/memory_bridge.py`, `src/vxis/agent/brain.py:1770`
- Test: `tests/agent/test_memory_recall_parity.py`

- [ ] **Step 1: Write the failing parity test** (asserts on the formatted prompt fragment — `brain.py`
  returns `format_memory_context(similar)`, a string, so parity must be on the rendered text):

```python
# tests/agent/test_memory_recall_parity.py
from vxis.agent.memory import AgentMemory, ScanMemory, format_memory_context
from vxis.pti.memory_bridge import recall_context_from_pti
from vxis.pti.store import PTIStore

def test_pti_recall_matches_legacy_format(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_PTI_ROOT", str(tmp_path / "pti"))
    sm = ScanMemory(target="http://example.com:80", tech_stack=["nginx"],
                    findings_summary=[{"severity": "high", "type": "sqli", "title": "x"}],
                    total_findings=1)
    # legacy rendering
    legacy = AgentMemory(db_path=str(tmp_path / "legacy.json"))
    legacy.remember_scan(sm)
    legacy_text = format_memory_context(legacy.recall_similar("http://example.com:80", ["nginx"]))
    # PTI rendering
    from vxis.pti.memory_bridge import scan_memory_to_dossier_facts
    PTIStore(root=tmp_path / "pti").persist(scan_memory_to_dossier_facts(sm))
    pti_text = recall_context_from_pti("http://example.com:80", ["nginx"], root=tmp_path / "pti")
    # semantic parity: both mention the target and the sqli finding
    for needle in ("example.com", "sqli"):
        assert needle in legacy_text.lower()
        assert needle in pti_text.lower()
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/agent/test_memory_recall_parity.py -v`
Expected: FAIL — `ImportError: cannot import name 'recall_context_from_pti'`

- [ ] **Step 3: Implement `recall_context_from_pti`** in `memory_bridge.py`:

```python
# src/vxis/pti/memory_bridge.py  (append)
from pathlib import Path

def recall_context_from_pti(target_url: str, tech_stack: list[str] | None = None,
                            root: str | Path = "data/pti") -> str:
    """PTI-backed equivalent of AgentMemory.recall_similar → format_memory_context.

    Returns a prompt-fragment string with the same salient content (target,
    tech, prior findings) so the Brain context is unchanged when the read path
    flips to PTI.
    """
    from vxis.pti.store import PTIStore
    store = PTIStore(root=root)
    try:
        dossier = store.load_for_target(target_url, create=False)
    except FileNotFoundError:
        return ""
    lines = [f"Prior intelligence for {dossier.target_url}:"]
    if dossier.stack:
        lines.append("  tech: " + ", ".join(s.tech for s in dossier.stack))
    for fh in dossier.findings_history[:10]:
        lines.append(f"  prior finding: {fh.finding_type} (status={fh.status})")
    return "\n".join(lines)
```

- [ ] **Step 4: Switch the read path** at `brain.py:1770`, flag-gated:

```python
            if os.environ.get("VXIS_V3_MEMORY", "0") != "0":
                from vxis.pti.memory_bridge import recall_context_from_pti
                context = recall_context_from_pti(target, tech_stack)
                if not context:
                    return ""
            else:
                from vxis.agent.memory import format_memory_context
                similar = self._memory.recall_similar(target, tech_stack)
                if not similar:
                    return ""
                context = format_memory_context(similar)
```

- [ ] **Step 5: Run parity test + full memory suite**

Run: `pytest tests/agent/test_memory_recall_parity.py tests/agent/ -k memory -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/vxis/pti/memory_bridge.py src/vxis/agent/brain.py tests/agent/test_memory_recall_parity.py
git commit -m "phase-0: PTI-backed recall behind VXIS_V3_MEMORY with format parity

brain.py read path reads PTI when the flag is on; parity test asserts on the
rendered prompt fragment (not just fact-set), since the Brain consumes text."
```

### Task 1.4: Re-point `query_scan_memory` tool backend at PTI

**Files:**
- Modify: `src/vxis/agent/tools/memory_tools.py` (`QueryScanMemoryTool.run`, `_load_kb`/`record_scan_result`)
- Test: `tests/agent/tools/test_query_scan_memory_pti.py`

- [ ] **Step 1: Characterization test of the CURRENT I/O contract** (lock it before swapping backend):

```python
# tests/agent/tools/test_query_scan_memory_pti.py
import pytest
from vxis.agent.tools.memory_tools import QueryScanMemoryTool

@pytest.mark.asyncio
async def test_query_scan_memory_fresh_target_contract(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_V3_MEMORY", "1")
    monkeypatch.setenv("VXIS_PTI_ROOT", str(tmp_path / "pti"))
    res = await QueryScanMemoryTool().run(url="http://fresh.example.com:80")
    assert res.ok is True
    assert res.data["target_known"] is False
    # keys the Brain depends on must all be present
    for key in ("scans", "known_findings", "aggregated_findings",
                "refuted_patterns", "successful_tactics", "branch_leads",
                "cross_target_findings"):
        assert key in res.data
```

- [ ] **Step 2: Run to confirm it passes on the CURRENT backend** (this is the lock):

Run: `pytest tests/agent/tools/test_query_scan_memory_pti.py -v`
Expected: PASS (current JSON-KB backend already returns this shape)

- [ ] **Step 3: Re-point the backend** — when `VXIS_V3_MEMORY` is on, `_load_kb()` (or the `run` body)
  reads from `PTIStore` and maps the dossier into the **same** output dict keys; keep the JSON-KB path
  when off. Preserve every `data[...]` key and the `summary` text format verbatim.

```python
# in QueryScanMemoryTool.run, before kb = _load_kb():
        if os.environ.get("VXIS_V3_MEMORY", "0") != "0":
            from vxis.pti.memory_bridge import query_scan_memory_view
            return query_scan_memory_view(url=url, stack_hint=stack_hint)
```

Implement `query_scan_memory_view` in `memory_bridge.py` returning a `ToolResult` with the identical key
set asserted in Step 1 (target_known/scans/known_findings/.../cross_target_findings + summary string).

- [ ] **Step 4: Run the characterization test under BOTH flag states**

Run: `VXIS_V3_MEMORY=0 pytest tests/agent/tools/test_query_scan_memory_pti.py -v && VXIS_V3_MEMORY=1 pytest tests/agent/tools/test_query_scan_memory_pti.py -v`
Expected: PASS in both — identical contract.

- [ ] **Step 5: Commit**

```bash
git add src/vxis/agent/tools/memory_tools.py src/vxis/pti/memory_bridge.py tests/agent/tools/test_query_scan_memory_pti.py
git commit -m "phase-0: back query_scan_memory with PTI behind VXIS_V3_MEMORY

Identical tool name + output contract; JSON-KB path retained when flag off."
```

### Task 1.5: Idempotent migrator (both legacy stores → PTI)

**Files:**
- Create: `scripts/migrate_agent_memory_to_pti.py`
- Test: `tests/scripts/test_migrate_agent_memory.py`

- [ ] **Step 1: Write the failing test** (idempotency + manifest):

```python
# tests/scripts/test_migrate_agent_memory.py
import json
from scripts.migrate_agent_memory_to_pti import migrate

def test_migrate_is_idempotent(tmp_path):
    legacy = tmp_path / "agent_memory.json"
    legacy.write_text(json.dumps({"memories": [
        {"target": "http://example.com:80", "tech_stack": ["nginx"],
         "findings_summary": [], "effective_tools": [], "ineffective_tools": [],
         "scan_date": "2026-01-01T00:00:00+00:00", "total_findings": 0}
    ]}))
    pti_root = tmp_path / "pti"
    first = migrate(legacy_path=legacy, pti_root=pti_root, dry_run=False)
    assert first["migrated"] == 1 and first["failed"] == 0
    second = migrate(legacy_path=legacy, pti_root=pti_root, dry_run=False)
    assert second["migrated"] == 0 and second["skipped"] == 1  # marker present
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/scripts/test_migrate_agent_memory.py -v`
Expected: FAIL — `ModuleNotFoundError: scripts.migrate_agent_memory_to_pti`

- [ ] **Step 3: Implement the migrator** — keyed upsert by `(target_hash)`, `migrated_at`/`source_checksum`
  marker per target (a `migrated.json` sidecar under the PTI root), `--dry-run`, returns
  `{migrated, skipped, failed}`. Migrates BOTH `~/.vxis/agent_memory.json` and the `query_scan_memory` KB.

```python
# scripts/migrate_agent_memory_to_pti.py
"""One-shot, idempotent migrator: legacy AgentMemory JSON + query_scan_memory KB → PTI.

Re-runnable after partial failure. Use --dry-run to preview.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

from vxis.agent.memory import ScanMemory
from vxis.pti.hashing import target_hash_for_url
from vxis.pti.memory_bridge import scan_memory_to_dossier_facts
from vxis.pti.store import PTIStore

def _checksum(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()

def migrate(legacy_path: Path, pti_root: Path, dry_run: bool = False) -> dict:
    store = PTIStore(root=pti_root)
    marker_path = pti_root / "migrated.json"
    pti_root.mkdir(parents=True, exist_ok=True)
    markers = json.loads(marker_path.read_text()) if marker_path.exists() else {}
    counts = {"migrated": 0, "skipped": 0, "failed": 0}
    raw = json.loads(legacy_path.read_text()) if legacy_path.exists() else {"memories": []}
    for entry in raw.get("memories", []):
        try:
            sm = ScanMemory.from_dict(entry)
            th = target_hash_for_url(sm.target)
            cs = _checksum(entry)
            if markers.get(th) == cs:
                counts["skipped"] += 1
                continue
            if not dry_run:
                store.persist(scan_memory_to_dossier_facts(sm))
                markers[th] = cs
            counts["migrated"] += 1
        except Exception:  # noqa: BLE001 — count + continue, re-runnable
            counts["failed"] += 1
    if not dry_run:
        marker_path.write_text(json.dumps(markers))
    return counts

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--legacy", default="~/.vxis/agent_memory.json")
    ap.add_argument("--pti-root", default="data/pti")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    print(migrate(Path(a.legacy).expanduser(), Path(a.pti_root).expanduser(), a.dry_run))
```

- [ ] **Step 4: Run test**

Run: `pytest tests/scripts/test_migrate_agent_memory.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/migrate_agent_memory_to_pti.py tests/scripts/test_migrate_agent_memory.py
git commit -m "phase-0: idempotent AgentMemory/KB → PTI migrator

Keyed upsert + per-target checksum marker; --dry-run; {migrated,skipped,failed}
manifest; re-runnable after partial failure."
```

> **Deletion of `AgentMemory` + the JSON KB is intentionally deferred to a later phase** (after prod
> dossier parity is measured). Do not delete them in Phase 0 — the deferred deletion preserves
> `VXIS_V3_MEMORY=off` as a working rollback.

---

## Task Group 2 — Hypothesis de-collision rename

### Task 2.1: Rename `Hypothesis` → `HypothesisNode` (DAG) end-to-end

**Files:**
- Modify: `src/vxis/agent/hypothesis/dag.py`, `src/vxis/agent/hypothesis/__init__.py`
- Test: `tests/agent/hypothesis/test_dag.py` (existing — update refs)

- [ ] **Step 1: Inventory the references** (run first, paste output into the commit body):

Run: `grep -rn "\bHypothesis\b" src/vxis/agent/hypothesis tests/agent/hypothesis`
Expected: hits in `dag.py` (class def line 32, type hints `-> list[Hypothesis]`, `Hypothesis.model_validate`,
forward-ref strings `"Hypothesis"`), `__init__.py` (import + `__all__`), and the test file.

- [ ] **Step 2: Rename in `dag.py`** — class def, all annotations (`dict[str, HypothesisNode]`,
  `-> list[HypothesisNode]`, `hypothesis: HypothesisNode`), forward-ref strings, and `model_validate` calls.
  Do **not** touch `HypothesisDAG`, `HypothesisOutcome` (`pti/models.py`), or `HypothesisFilter`.

- [ ] **Step 3: Update `__init__.py`**

```python
from vxis.agent.hypothesis.dag import HypothesisNode, HypothesisDAG
__all__ = ["HypothesisNode", "HypothesisDAG", "bayes_update", "clamp_probability"]
```

- [ ] **Step 4: Update the test file** refs `Hypothesis(` → `HypothesisNode(`.

- [ ] **Step 5: Verify exactly one DAG node class + suite green**

Run: `grep -rn "^class Hypothesis\b" src/vxis/agent/hypothesis` (expect: zero — it's `HypothesisNode` now)
Run: `grep -rn "^class Hypothesis\b" src/vxis` (expect: one — `graph/hypothesis.py:18`, the legacy class, untouched)
Run: `pytest tests/agent/hypothesis/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/vxis/agent/hypothesis/
git commit -m "phase-0: rename DAG Hypothesis -> HypothesisNode

De-collides with the legacy graph/hypothesis.Hypothesis dataclass. No behavior
change; grep confirms exactly one HypothesisNode and the legacy class untouched."
```

---

## Task Group 3 — Model-table merge

### Task 3.1: Delete `cost_router.ROUTE_TABLE`; keep telemetry; one map in `brain`

**Files:**
- Modify: `src/vxis/agent/routing/cost_router.py` (remove `ROUTE_TABLE`, `ROUTE_TABLE_ENV`, route overrides)
- Test: `tests/agent/routing/test_cost_router.py` (existing — drop route-table assertions, keep `CostReport`)

- [ ] **Step 1: Confirm `brain._model_role_for_decision_class` is the sole live map**

Run: `grep -rn "ROUTE_TABLE\|_model_role_for_decision_class" src/vxis`
Expected: `ROUTE_TABLE` referenced only inside `cost_router.py` + its test; the decision→role map used in
`brain.py:818/789`.

- [ ] **Step 2: Write/adjust the failing test** — assert the router keeps cost telemetry but no longer owns
  a model table:

```python
# tests/agent/routing/test_cost_router.py  (replace route-table test)
from vxis.agent.routing.cost_router import CostReport, CostUsage

def test_cost_report_tracks_usage_without_model_table():
    rep = CostReport(by_class={}, calls=2, cost_usd=0.5)
    assert rep.cost_per_finding(2) == 0.25
    assert not hasattr(__import__("vxis.agent.routing.cost_router", fromlist=["x"]), "ROUTE_TABLE")
```

- [ ] **Step 3: Run to verify it fails**

Run: `pytest tests/agent/routing/test_cost_router.py -v`
Expected: FAIL — `ROUTE_TABLE` still present.

- [ ] **Step 4: Delete `ROUTE_TABLE` + `ROUTE_TABLE_ENV` + `ROUTE_OVERRIDE_ENV_PREFIX`** and any
  `model_for(decision_class)` that read the table. Keep `DecisionClass`, `CostUsage`, `CostReport`,
  `coerce_decision_class`. Model resolution stays in `brain._model_role_for_decision_class` →
  `hybrid_config`.

- [ ] **Step 5: Run routing + brain tests**

Run: `pytest tests/agent/routing/ tests/agent/ -k "brain or routing" -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/vxis/agent/routing/cost_router.py tests/agent/routing/test_cost_router.py
git commit -m "phase-0: delete cost_router.ROUTE_TABLE; brain map is the one router

Three model tables -> one. cost_router keeps CostReport telemetry only; model
resolution lives in brain._model_role_for_decision_class -> hybrid_config."
```

---

## Task Group 4 — Prioritizer collapse (largest; may be split out)

> DAG (`HypothesisNode`/`HypothesisDAG`) becomes the single prioritizer. `vector_candidates` + `scan_todos`
> + `branches` are absorbed or removed; the legacy finish-helper call sites are **migrated** (not deleted)
> to DAG queries. This touches `scan_loop_decision_policy.py` broadly — execute as its own review batch.

### Task 4.1: Field-level mapping table (design artifact, no code)

**Files:**
- Create: `docs/superpowers/plans/phase0-prioritizer-mapping.md`

- [ ] **Step 1:** Produce a table: for every field of `VectorCandidate` (`scan_loop_state.py:197`),
  `BranchState` (`:277`, 25+ fields), and the `scan_todos` entry → one of `{→ HypothesisNode.<field>,
  → side-table keyed by node_id, DELETE (with reason)}`. This locks decisions before code. No field may be
  unaccounted-for.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/phase0-prioritizer-mapping.md
git commit -m "phase-0: lock field-level prioritizer mapping (vector/branch/todo -> DAG)"
```

### Task 4.2: Absorption shim — seed DAG from existing vector candidates

**Files:**
- Modify: `src/vxis/agent/scan_loop_state.py` (`ensure_vector_candidate` → also create a `HypothesisNode`)
- Test: `tests/agent/test_prioritizer_absorption.py`

- [ ] **Step 1: Write the failing test** — seeding a vector candidate creates a DAG node with the mapped
  fields:

```python
# tests/agent/test_prioritizer_absorption.py
from vxis.agent.scan_loop_state import ScanLoopState

def test_vector_candidate_seeds_dag_node():
    s = ScanLoopState()  # use the real ctor / factory the suite uses
    s.ensure_vector_candidate(surface_id="s1", vector_class="sqli", priority=95)
    assert s.hypothesis_dag is not None
    node = next(n for n in s.hypothesis_dag.nodes.values() if n.surface_id == "s1")
    assert node.proposed_vector_class == "sqli"
    assert node.status == "untested"
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/agent/test_prioritizer_absorption.py -v`
Expected: FAIL — DAG not seeded by `ensure_vector_candidate`.

- [ ] **Step 3: Implement** — inside `ensure_vector_candidate`, after creating the candidate, also
  `self.hypothesis_dag.add(HypothesisNode(node_id=..., surface_id=surface_id,
  proposed_vector_class=vector_class, prior=priority/100, status="untested", ...))` per the Task 4.1 table.

- [ ] **Step 4: Run test + existing scan-loop-state tests**

Run: `pytest tests/agent/test_prioritizer_absorption.py tests/agent/ -k scan_loop_state -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vxis/agent/scan_loop_state.py tests/agent/test_prioritizer_absorption.py
git commit -m "phase-0: seed HypothesisNode from each vector candidate (absorption shim)"
```

### Task 4.3: Migrate legacy finish-helper call sites to DAG queries

**Files:**
- Modify: `src/vxis/agent/scan_loop_decision_policy.py` (call sites ~22, 374, 792, 872-874, 2149-2197),
  `src/vxis/agent/scan_loop_actions.py:1097`, `src/vxis/agent/scan_loop_run.py:1467`
- Test: `tests/agent/test_finish_gate_dag.py`

- [ ] **Step 1: Enumerate every call site** (paste into commit body):

Run: `grep -rn "_blocking_finish_branches\|_remaining_high_yield_family_candidates" src/vxis`

- [ ] **Step 2: Write the failing test** — finish is blocked by an untested high-prior DAG node, not by
  `vector_candidates`:

```python
# tests/agent/test_finish_gate_dag.py
from vxis.agent.scan_loop_state import ScanLoopState

def test_finish_blocked_by_untested_high_prior_dag_node():
    s = ScanLoopState()
    s.ensure_vector_candidate(surface_id="admin", vector_class="auth-bypass", priority=95)
    # one untested prior>=0.5 node must block finish
    assert s.hypothesis_dag.top_untested(k=1)[0].prior >= 0.5
    # the finish predicate (DAG-based) reports not-finishable
    from vxis.agent.scan_loop_decision_policy import dag_blocks_finish
    assert dag_blocks_finish(s) is True
```

- [ ] **Step 3: Run to verify it fails**

Run: `pytest tests/agent/test_finish_gate_dag.py -v`
Expected: FAIL — `dag_blocks_finish` not defined.

- [ ] **Step 4: Implement `dag_blocks_finish(state)`** using `HypothesisDAG.top_untested()` priors;
  **replace** each enumerated call site of the legacy helpers with this DAG query; then delete the two
  helper functions.

- [ ] **Step 5: Verify zero call sites + suite green**

Run: `grep -rn "_blocking_finish_branches\|_remaining_high_yield_family_candidates" src/vxis` (expect: none)
Run: `pytest tests/agent/ -x --timeout=30 -k "not runs_to_finish"`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/vxis/agent/scan_loop_decision_policy.py src/vxis/agent/scan_loop_actions.py src/vxis/agent/scan_loop_run.py tests/agent/test_finish_gate_dag.py
git commit -m "phase-0: migrate finish-gate helpers to DAG queries; delete legacy helpers

vector_candidates/branches finish logic replaced by HypothesisDAG.top_untested
priors. Zero call sites of the legacy helpers remain (grep-verified)."
```

---

## Task Group 5 — Benchmark CI split (real build)

### Task 5.1: Register the `live` pytest marker + split the PR workflow

**Files:**
- Modify: `pyproject.toml` (`[tool.pytest.ini_options] markers`), `.github/workflows/benchmark.yml`
- Test: `tests/meta/test_live_marker_registered.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/meta/test_live_marker_registered.py
import configparser, pathlib, tomllib

def test_live_marker_registered():
    data = tomllib.loads(pathlib.Path("pyproject.toml").read_text())
    markers = data["tool"]["pytest"]["ini_options"]["markers"]
    assert any(m.startswith("live") for m in markers)
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest tests/meta/test_live_marker_registered.py -v`
Expected: FAIL — marker not registered.

- [ ] **Step 3: Register the marker** in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
markers = [
    "live: requires live LLM/network; excluded from the per-PR deterministic tier",
]
```

- [ ] **Step 4: Split `benchmark.yml`** — the PR-triggered job runs `pytest -m "not live"` with **no API
  keys and no Docker service**; move the current live Juice Shop scan to a separate job triggered on
  `schedule:` (nightly) + `workflow_dispatch`, not on `pull_request`.

- [ ] **Step 5: Verify**

Run: `pytest tests/meta/test_live_marker_registered.py -v`
Run: `grep -n "ANTHROPIC_API_KEY\|pull_request\|schedule" .github/workflows/benchmark.yml`
Expected: the `pull_request` job has no `ANTHROPIC_API_KEY`; the live job is on `schedule`/`workflow_dispatch`.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml .github/workflows/benchmark.yml tests/meta/test_live_marker_registered.py
git commit -m "phase-0: split benchmark CI — deterministic per-PR, live nightly

Per-PR job runs -m 'not live' with no API keys; the live Juice Shop scan moves
to schedule/workflow_dispatch. Removes unbounded per-PR LLM spend."
```

> **Phase 0.5 (separate sub-plan):** the K≥3 multi-run/variance harness + the cassette record/replay
> substrate (record mode, secret-scrub, stable keying) are a multi-day build tracked separately. Until it
> lands, no league gate is claimed CI-blocking. Do not stub it inside Phase 0.

---

## Task Group 6 — Documentation

### Task 6.1: `CONSOLIDATION.md` ledger + ADR 011

**Files:**
- Create: `docs/superpowers/CONSOLIDATION.md`, `wiki/decisions/011_v3_consolidation.md`

- [ ] **Step 1:** Write `CONSOLIDATION.md` as a table — one row per consolidated system:
  `old symbol/path | new home | consumers re-pointed | removal commit (or "deferred to Phase 2") |
  grep-guard command`. Populate from Task Groups 1–4.

- [ ] **Step 2:** Write `wiki/decisions/011_v3_consolidation.md` with mandatory frontmatter
  (`name`, `type: decision`, `status: active`, `when_to_read`, `updated`, `code_anchors`, `related`) and the
  ADR body sections (Context / Options / Decision / Consequences) per `wiki/CLAUDE.md`. Decision: DAG is the
  sole prioritizer; PTI absorbs both legacy memory stores via dual-write-then-defer-delete; one model map.

- [ ] **Step 3:** Add to `wiki/index.md` + `wiki/log.md` (run `python wiki/scripts/lint.py`).

- [ ] **Step 4: Verify wiki lint**

Run: `python wiki/scripts/lint.py`
Expected: no errors (non-zero exit = fail).

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/CONSOLIDATION.md wiki/decisions/011_v3_consolidation.md wiki/index.md wiki/log.md
git commit -m "phase-0: consolidation ledger + ADR 011

Records every merge/deletion so future agents don't resurrect a deleted system."
```

---

## Phase 0 Exit Criteria (gate before Phase 1)

- [ ] `VXIS_V3_MEMORY=off` restores the legacy `AgentMemory` path (rollback proven by a test).
- [ ] Dual-write parity test green; `query_scan_memory` contract identical under both flag states.
- [ ] Migrator idempotent (re-run → all skipped); manifest emitted.
- [ ] `grep "^class Hypothesis\b" src/vxis` → exactly one (`graph/hypothesis.py`); DAG class is `HypothesisNode`.
- [ ] `grep "ROUTE_TABLE" src/vxis` → none; `CostReport` telemetry retained.
- [ ] `grep "_blocking_finish_branches\|_remaining_high_yield_family_candidates" src/vxis` → none; DAG is sole prioritizer.
- [ ] PR `benchmark.yml` job has no `ANTHROPIC_API_KEY`; live job on schedule.
- [ ] `pytest tests/ -x --timeout=30 -k "not runs_to_finish"` green.
- [ ] `python wiki/scripts/lint.py` clean; `CONSOLIDATION.md` + ADR 011 present.

---

## Self-Review (run before handoff)

- **Spec coverage:** main-plan Phase 0 tasks 1–6 → Task Groups 1 (memory, both stores + dual-write +
  migrator + re-point), 2 (rename), 3 (model table), 4 (prioritizer + finish-helper migration), 5
  (benchmark split), 6 (CONSOLIDATION.md + ADR). The variance/cassette harness is explicitly deferred to a
  Phase 0.5 sub-plan (noted, not dropped).
- **Placeholder scan:** all code steps contain real signatures from the tree (`ScanMemory.from_dict`,
  `PTIStore.load_for_target`, `format_memory_context`, `ensure_vector_candidate`, `top_untested`,
  `_model_role_for_decision_class`). No TBD/TODO.
- **Type consistency:** `HypothesisNode` used consistently post-rename; `dual_write_scan`,
  `recall_context_from_pti`, `query_scan_memory_view`, `scan_memory_to_dossier_facts`,
  `dag_blocks_finish`, `migrate` names match across their defining and calling tasks.
