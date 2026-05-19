# VXIS Architecture — Brain-First Single-Loop with AI Review Hierarchy

> How VXIS reasons, decides, verifies, and escalates. Read this after `README.md`. Updated 2026-05-04.

## The one-line design statement

**A single persistent ReAct loop owns scanning and exploitation, while layered AI reviewers gate findings and scan completion before anything lands in the final report.**

Extended beyond Strix with:
- Adversarial verifier (stronger model refutes findings before confirmation)
- Selective escalation: cheap worker, stronger verifier, final judge/report gate
- MITRE ATT&CK mapping (16 techniques, auto-inferred)
- 3-tier smart history + LLM memory compression at 90K tokens
- Auto-orchestration safety net (auto-login, auto-ffuf, auto-nuclei, auto-sqlmap)
- Enterprise egress filter for customer-production scans
- Bilingual NCC-style HTML reports with verification summary + MITRE coverage table
- Multi-domain runtimes (planned — Game / Mobile / Hardware)
- Persistent Collective KB across scans

## Why Brain-First?

The preceding VXIS architecture (14-Phase `ScanPipeline` in `pipeline.py`, 5234 lines) treated the Brain as a **bag of LLM helpers** — each phase dispatched hardcoded scanner logic and only called the Brain to interpret individual probe results. `brain_decision_count = 0` across a full benchmark scan, despite `llm_call_count = 10+` — proof that the "Brain-First" principle was violated at the code level.

Phase A rebuilt VXIS so the Brain **owns the top of the stack**. Every tool call flows through `AgentBrain.think_in_loop()`, which is a true ReAct decision. Current state: `brain_decisions=50, llm_calls=55` on Juice Shop.

## Operating model: autonomous by default

VXIS is optimized for the workflow:

1. Launch a scan.
2. Leave it running unattended.
3. Return to a completed run with verified findings, chains, and a rendered report.

That means the architecture favors `AI-in-the-loop` over `human-in-the-loop`.
Humans should only see:

- dangerous real-world mutation approvals,
- ambiguous verdict queues,
- final delivery spot-checks.

Everything else should be handled by the runtime itself.

## Runtime roles

VXIS is still implemented as a single loop, but architecturally it already behaves like a role-separated system:

| Role | Current implementation | Responsibility |
|---|---|---|
| **Worker** | `AgentBrain` + `ScanAgentLoop` | Recon, probing, exploitation attempts, branch persistence |
| **Verifier** | `verify_finding` + PoC/control gates | Refute weak findings, block non-PoC high/criticals |
| **Judge** | `finish_scan` gate + final report extraction | Decide whether evidence is sufficient to end the run |
| **Human** | Optional exception handler | Review only escalated ambiguity or risky actions |

The design target is **fully autonomous with selective escalation**, not phase-by-phase human steering.

## Vector exhaustion and crown-jewel semantics

VXIS is not a tool picker. Tool names are only verbs. The real search state is the set of plausible attack vectors, hypotheses, pivots, and chain candidates that remain open for the current target.

The loop should behave like:

1. Discover surfaces and evidence.
2. Generate plausible vector candidates.
3. Prioritize by evidence, impact, and path-to-crown potential.
4. Pick the tool that best proves or refutes the highest-value candidate.
5. If blocked, classify the block and retry with a different route or variant.
6. Mark a candidate dead only after diverse probes or a clear policy/scope block.
7. Promote successful findings into chain candidates.
8. Keep expanding chains toward crown jewels: admin takeover, DB dump, RCE, credential/key theft, or data exfiltration.
9. Reject `finish_scan` while findings are unchained, likely vectors remain untested, or the loop ended by `max_iters` rather than completion.

Current hard pins:

- 0 findings cannot finish.
- 2+ findings require at least one chain.
- `max_iters` timeout is scored as incomplete.
- Direct and auto sandbox commands count toward vector coverage.
- Benchmark/growth-loop compares the same 5D score printed by the pipeline.
- First-class `vector_candidates` and `attempt_outcomes` live on `ScanLoopState`; attempted, found, clean, blocked, failed, retryable, and dead-end states survive beyond prompt text and are surfaced into scoring.

Next structural step: expand candidate generation from seeded web/desktop hypotheses to target-specific evidence mining so the queue grows from discovered routes, parameters, forms, technologies, and prior failures.

## Layered view

```
┌──────────────────────────────────────────────────────────────┐
│                          CLI                                 │
│            vxis scan <target> [--profile ...]                │
│                src/vxis/cli/main.py                          │
└─────────────────────────┬────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│                   ScanPipeline (v2)                          │
│    src/vxis/pipeline/scan_pipeline_v2.py  (~505 lines)       │
│                                                              │
│  • Build ScanContext                                         │
│  • Ghost activation                                          │
│  • Reset per-scan counters (finding store, brain decision)   │
│  • Run ScanAgentLoop                                         │
│  • Copy findings/chains → ctx                                │
│  • Extract final report sections from accepted finish_scan    │
│  • Deferred approval gate (enterprise)                       │
│  • Generate HTML report (NCC style + verification + MITRE)   │
│  • Compute VXIS score                                        │
└─────────────────────────┬────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│                   ScanAgentLoop                              │
│          src/vxis/agent/scan_loop.py                         │
│                                                              │
│  while not completed and iteration < max_iters (300):        │
│      compress_history(messages, brain)  # at 90K tokens      │
│      dashboard = _build_scan_dashboard()                     │
│      actions = brain.think_in_loop(messages + dashboard)     │
│      actions = actions[:1]  # Strix: 1 tool per message      │
│      result = registry.dispatch(name, args)                  │
│      enforce focus branch / vector discipline                │
│      auto-promote PoC-backed findings                        │
│      auto-verify high-value findings                         │
│      auto-orchestration safety net (login/ffuf/nuclei/sqlmap)│
│      if finish_scan: break                                   │
│                                                              │
│  Auto-orchestration triggers:                                │
│    • iter 5+  → auto-login (SQLi creds on forms)             │
│    • iter 10  → auto-ffuf (directory bruteforce)             │
│    • iter 12  → auto-nuclei (if Brain hasn't run it)         │
│    • iter 18+ → auto-sqlmap (on 500-error endpoints)         │
└─────────────────────────┬────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│                     AgentBrain                               │
│            src/vxis/agent/brain.py  (~2186 lines)            │
│                                                              │
│  • think_in_loop(messages, tool_catalog)                     │
│      - _build_smart_history: 3-tier compacted view           │
│        T1 FULL (last 3 iters), T2 COMPACT (older),          │
│        T3 PINNED (dashboard/critic/findings/verify)          │
│      - LOOP_PROMPT_ADAPTER + AGENT_SYSTEM_PROMPT             │
│      - _call_llm_with_fallback (provider chain)              │
│      - _parse_response → list[(tool, args)]                  │
│  • max_steps=300                                             │
│  • think_first pattern enforced in system prompt             │
└─────────────────────────┬────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│                  ToolRegistry — 23 BrainTools                │
│          src/vxis/agent/tool_registry.py                     │
│          src/vxis/agent/tools/                               │
│                                                              │
│  Control (3):  finish_scan  think  wait                      │
│  Recon (1):    fingerprint_target                            │
│  Browser (7):  browser_navigate  browser_analyze_dom         │
│                browser_click  browser_fill_form              │
│                browser_screenshot  browser_eval_js            │
│                browser_get_cookies                            │
│  Strix-pw (2): shell_exec  python_exec  (→ vxis-sandbox)    │
│  Playbook (2): list_playbooks  load_playbook                 │
│  Finding (3):  report_finding  query_findings  link_chain    │
│  Verify (1):   verify_finding  (adversarial, stronger model) │
│  Memory (1):   query_scan_memory                             │
│  HTTP (1):     http_request                                  │
│  Proxy (1):    intercept_proxy                               │
│  Legacy (1):   browser_render (thin wrapper, Phase A compat) │
└──────────┬────────────────────────────┬──────────────────────┘
           ↓                            ↓
┌──────────────────────────┐   ┌────────────────────────────────┐
│   VXIS Primitives        │   │   vxis/sandbox Docker image    │
│  src/vxis/interaction/   │   │   docker/sandbox/              │
│                          │   │                                │
│  • hands.py   (HTTP)     │   │  debian:trixie-slim +          │
│  • eyes.py    (Browser)  │   │   sqlmap ffuf nuclei gobuster  │
│  • xray.py    (MitM)     │   │   nikto dirb python3 httpx     │
│  • controller.py         │   │                                │
└──────────────────────────┘   └────────────────────────────────┘
```

## LLM memory compression — Strix pattern

`src/vxis/agent/memory_compressor.py`: when message history exceeds 90K tokens (estimated at 4 chars/token), older messages are chunked (groups of 10) and summarized by the LLM. The 15 most recent messages are always preserved verbatim. Summaries retain:
- Discovered vulnerabilities, endpoints, attack vectors
- Credentials, tokens, API keys, session cookies
- Failed attempts (dedup prevention)
- Architecture insights (tech stack, routing)

This lets scans run 300+ iterations without losing critical context.

## Smart 3-tier history — Phase D

`AgentBrain._build_smart_history()` builds a compacted view of conversation history:

| Tier | What | Detail level |
|---|---|---|
| T1 — FULL | Last 3 iterations | Complete tool calls, args, results |
| T2 — COMPACT | Older iterations | `tool:name` + summary only |
| T3 — PINNED | High-value messages (any age) | Dashboard, critic reviews, finding reports, verify results, system hints |

This replaces the naive flat window that caused Brain amnesia at high iteration counts.

## AI review hierarchy

VXIS does not treat review as a manual phase. It treats review as a chain of increasingly strict machine gates:

1. **Worker loop**
   - Generates hypotheses
   - Executes tools
   - Keeps branches alive until proven, exhausted, or blocked

2. **Structured PoC gate**
   - `report_finding` requires stronger fields for serious findings:
     `impact`, `technical_analysis`, `poc_description`, `poc_script_code`, `remediation_steps`
   - High/critical findings without real exploit transcript or observed result are blocked before report rendering

3. **Adversarial verifier**
   - `verify_finding` attempts to refute the claim
   - Control-pair evidence is required for auth / IDOR / injection-style findings

4. **Judge / completion gate**
   - `finish_scan` is rejected if high-value branches remain open, chain expectations are unmet, or the run looks incomplete

This is the main autonomy pattern: **cheap worker, stricter verifier, strictest completion gate, optional human only on exceptions**.

## Adversarial verifier — Phase C

`verify_finding` tool (`src/vxis/agent/tools/verifier_tools.py`): when Brain reports a finding via `report_finding`, the scan loop auto-intercepts and calls `verify_finding` with a stronger model that attempts to refute the claim. Verdicts:

- **CONFIRMED** — evidence supports the finding, included in report
- **UNCONFIRMED** — insufficient evidence, flagged for review
- **REFUTED** — false positive, excluded from report

Verdict counts tracked in `ScanLoopState.verdict_counts`. Report includes a Verification Summary section.

## Branch-first execution

The primary unit of work is no longer "phase" or "tool". It is the **branch**:

- `vector_candidates` represent durable attack hypotheses
- `branches` represent active exploit paths derived from those hypotheses or findings
- off-branch actions are warned, then blocked
- `finish_scan` is blocked while important branches remain alive

This is how VXIS approximates multi-agent persistence without requiring separate processes for every idea. The current architecture is a **logical multi-agent system inside one scan loop**.

Future evolution can split top branches into real parallel workers, but the required ownership model already exists in `ScanLoopState`.

## MITRE ATT&CK mapping

`src/vxis/agent/tools/mitre_data.py`: 16 web-focused techniques mapped to finding_types. `infer_techniques(finding_type, title, affected_component)` auto-maps findings. Coverage summary (techniques/tactics/percentage) included in the HTML report.

## Enterprise egress filter — Phase C

`src/vxis/agent/egress.py`: when `VXIS_EGRESS_STRICT=1`, an allowlist is built from the target URL. `shell_exec` commands that would reach non-target hosts are blocked. This prevents the sandbox from making unintended outbound connections during customer-production scans.

## Auto-orchestration safety net

The scan loop includes safety-net triggers that fire if Brain hasn't executed certain critical actions by specific iteration thresholds:

| Trigger | Fires at | What it does |
|---|---|---|
| auto-login | iter 5+ (form with password field detected) | Try SQLi bypass creds on login forms |
| auto-ffuf | iter 10 | Directory bruteforce with common wordlist |
| auto-nuclei | iter 12 | Run nuclei with web templates if Brain hasn't |
| auto-sqlmap | iter 18+ | Test endpoints that returned 500 errors |

These compensate for weaker models that may not autonomously reach for the right scanner at the right time.

## Current limits

The architecture is strongest today on `web/API` targets.

- `web/API`: most mature, with branch persistence, verifier gates, report shaping, and direct PoC rendering
- `desktop`: partial parity via dedicated desktop skills and verifier rubric
- `mobile / infra / k8s / hardware`: architecturally possible, but still missing launcher/runtime maturity

The long-term model is not "one universal sandbox". It is:

- platform-specific execution adapters (`docker`, VM, emulator, cluster, local binary runtime)
- one shared pentest core (`ScanAgentLoop`, verifier, reporting, chain analysis)

## Three Brain backends (only AgentBrain is live)

1. **`AgentBrain`** (`agent/brain.py`) — **LIVE** path, uses LLM API (OpenAI/Anthropic/Gemini/DeepSeek via fallback chain)
2. `InteractiveBrain` (`agent/brain_interactive.py`) — stdin/stdout NDJSON; Claude Code via `vxis scan --interactive` (legacy)
3. `FileBasedBrain` (`agent/brain_filebased.py`) — file protocol, rarely used

All three increment the **unified `brain_decision_count`** counter.

## Counters and instrumentation

| Metric | Source | Meaning |
|---|---|---|
| `peak_context_bytes` | `ScanLoopState.sample_peak_size()` per iteration | Peak in-memory state size |
| `llm_call_count` | `_call_llm_direct` entry hook | API call count |
| `brain_decision_count` | Entry of every `think()` / `think_in_loop()` | **PRIMARY** "Brain is deciding" metric |
| `findings_count` | `len(ctx.findings)` after scan | Discovered vulnerabilities |

Printed at scan end: `VXIS_BENCHMARK peak_context_bytes=<N> llm_call_count=<N> brain_decision_count=<N> findings_count=<N>`

## Docker sandbox

`docker/sandbox/Dockerfile` — `vxis-sandbox` container with: sqlmap, ffuf, nuclei, gobuster, nikto, dirb, python3, httpx, curl, nmap. Lazy-started on first `shell_exec` call, reused warm across scans. Workspace bind-mount: `/tmp/vxis-workspace` (host) ↔ `/workspace` (container).

## Phase roadmap

- **Phase A** ✅ — single loop migration
- **Phase B** ✅ — prompt tuning, playbooks, fingerprinting, memory
- **Phase C** ✅ — adversarial verifier, belief state, egress filter, MITRE mapping
- **Phase D** 🔥 90% — scan dashboard, smart history, browser tools, auto-orchestration
- **Phase E** 🔧 — Strix patterns (1 tool/msg, compression, hybrid brain)
- **Future** — domain expansion (Game/Mobile/Hardware/Cloud)
