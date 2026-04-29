# Phase Status — Migration Roadmap

> Where VXIS is in its multi-phase evolution from hardcoded-phase pipeline to Strix-parity Brain-First architecture. Updated 2026-04-10.

## Overall progress: ~90% of total roadmap

| Phase | Weight | Progress | Contribution |
|---|---:|---:|---:|
| **A — Strix-parity single loop** | 20% | ✅ 100% | 20% |
| **B — Tuning + Playbook + Memory** | 25% | ✅ 100% | 25% |
| **C — Verifier + Belief + Egress** | 25% | ✅ 100% | 25% |
| **D — Dashboard + Smart History + Exploit Depth** | 20% | 🔥 ~90% | ~18% |
| **E — Strix patterns (1tool/msg, compression, hybrid brain)** | 10% | 🔧 In progress | ~2% |
| **Total** | 100% | | **~90%** |

**Fast context recovery**: read [`docs/chapters/`](docs/chapters/README.md)
in order. Each chapter is one decision or milestone with context → problem →
decision → execution → result → lessons learned → next.

Current state in one line:
> 23 tools, Strix-pattern single loop (1 tool/message, LLM compression at 90K tokens, 3-tier smart history), vector exhaustion toward crown jewels, adversarial verifier, MITRE ATT&CK mapping (16 techniques), enterprise egress filter, auto-orchestration safety net, NCC-style HTML report with verification summary + MITRE table.

## Latest benchmark — Juice Shop (2026-04-10)

```
CRITICAL: SQLi auth bypass (admin JWT + password hash)
brain_decisions: 50, llm_calls: 55
MITRE: 8 techniques / 6 tactics
```

## Phase A — Strix-Parity Single-Loop Migration (COMPLETE ✅)

**Goal:** Kill the 14-Phase `ScanPipeline` orchestrator. Make a single persistent Brain ReAct loop the owner of an entire scan end-to-end.

**Result:** `brain_decision_count: 0 → 20`. Single `ScanAgentLoop` replaced 5234-line pipeline with a ~360-line v2 shim. All architectural criteria met. Finding quality deferred to Phase B.

**Key artifacts:**
- `src/vxis/agent/scan_loop.py` — ScanAgentLoop (now ~1127 lines with Phase B-E additions)
- `src/vxis/pipeline/scan_pipeline_v2.py` — ~505 line shim
- `src/vxis/agent/brain.py` — AgentBrain with `think_in_loop()` (~2186 lines)
- `src/vxis/agent/tool_registry.py` — BrainTool protocol + ToolRegistry

## Phase B — Tuning + Playbook + Memory (COMPLETE ✅)

**Goal:** Get the loop to actually find vulnerabilities. Prompt engineering, scanner integration, playbook system, fingerprinting, cross-scan memory.

**Result:** 0 → 8+ findings on Juice Shop. Key additions:
- `LOOP_PROMPT_ADAPTER` rewrite with Strix-style explicit tool guidance
- `fingerprint_target` tool — auto-detect stack → load matching playbook
- `list_playbooks` / `load_playbook` tools — 11 playbook files (injection, auth, xss, etc.)
- `query_scan_memory` tool — cross-scan episodic memory KB
- Auto-hint system: Brain gets nudged when probe output contains likely findings
- Dual-brain critic: stronger model reviews weaker model's work every N iterations

## Phase C — Verifier + Belief + Egress (COMPLETE ✅)

**Goal:** Reduce false positives, add enterprise safety, structured belief tracking.

**Result:** Zero false positives on benchmark targets. Key additions:
- **Adversarial verifier** (`verify_finding` tool) — stronger model attempts to refute each finding before confirming. Verdicts: CONFIRMED / UNCONFIRMED / REFUTED
- **Belief state tracking** — `ScanLoopState.verdict_counts` + `refuted_findings` / `confirmed_findings`
- **Enterprise egress filter** (`src/vxis/agent/egress.py`) — strict allowlist mode (`VXIS_EGRESS_STRICT=1`) blocks sandbox outbound traffic to non-target hosts
- **MITRE ATT&CK mapping** (`src/vxis/agent/tools/mitre_data.py`) — 16 techniques across web attack surface, auto-inferred from finding_type
- **NCC report enrichment** — Verification Summary section + MITRE ATT&CK Coverage table in HTML report

## Phase D — Dashboard + Smart History + Exploit Depth (90% 🔥)

**Goal:** Prevent Brain amnesia at high iteration counts, deepen exploit chains, improve scan dashboard.

**Key additions:**
- **Scan dashboard** — compact progress summary injected every iteration, compensates for history window limits
- **Smart 3-tier history** (`AgentBrain._build_smart_history()`):
  - Tier 1 (FULL): last 3 iterations — full detail
  - Tier 2 (COMPACT): older iterations — tool:name + summary only
  - Tier 3 (PINNED): high-value messages regardless of age (dashboard, critic, findings, verify)
- **Browser tools** (7 new tools): `browser_navigate`, `browser_analyze_dom`, `browser_click`, `browser_fill_form`, `browser_screenshot`, `browser_eval_js`, `browser_get_cookies`
- **Auto-orchestration safety net**: auto-login (SQLi creds), auto-ffuf (dir bruteforce at iter 10), auto-nuclei (at iter 12), auto-sqlmap (at iter 18+ on 500-error endpoints)
- **Vector exhaustion pins**: `finish_scan` is rejected with 0 findings, 2+ findings require at least one chain, and `max_iters` timeout is scored as incomplete.
- **First-class vector state**: `ScanLoopState.vector_candidates` and `attempt_outcomes` preserve candidate priority, attempts, status, tool, and summary; high-priority unattempted candidates can block `finish_scan`.
- **5D score fidelity**: benchmark/growth-loop now compares the same pipeline-emitted score, including attempted vector IDs and auto sandbox invocations.

**Remaining:** Target-specific candidate generation from discovered evidence, final tuning on exploit chain depth, dashboard format refinement.

## Phase E — Strix Patterns (In Progress 🔧)

**Goal:** Full Strix-equivalent patterns for maximum scan quality.

**Implemented so far:**
- **1 tool per message** — `actions = actions[:1]`, Brain must see result before next decision
- **LLM memory compression** — at 90K tokens, older messages are chunked and summarized by LLM (preserves security-relevant details). 15 most recent messages always kept verbatim.
- **Think-first pattern** — system prompt enforces `think` tool usage when uncertain

**Remaining:**
- Hybrid brain (cheap executor + expensive strategist)
- Further compression tuning

## Phase D (original) — Domain Expansion (Future)

1. **Game runtime** — Unity memory hooking, emulator control (16-phase original spec)
2. **Mobile runtime** — Frida / Objection for APK dynamic analysis (19-phase original spec)
3. **Firmware / Hardware** — CAN bus, RF, smart meter bench rigs
4. **Cloud console** — AWS / Azure / GCP session automation beyond API-only

## Historical baseline

Pre-migration benchmark for reference:

| Metric | Juice Shop (pre-migration) | Current (Phase D) |
|---|---:|---:|
| Wall time | 311.8 s | — |
| Findings | 10 | CRITICAL SQLi + auth bypass |
| `brain_decision_count` | 0 | 50 |
| `llm_call_count` | 10+ | 55 |
| MITRE techniques | 0 | 8 techniques / 6 tactics |
