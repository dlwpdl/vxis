# VXIS Architecture — Brain-First Single-Loop

> How VXIS reasons, decides, and acts. Read this after `README.md`.

## The one-line design statement

**A single persistent ReAct loop, driven by an LLM Brain, owns the entire scan — from recon to exploitation to reporting — via a dynamic tool catalog and a Docker sandbox.**

This is architecturally equivalent to Strix (the open-source Kali-in-a-box autonomous pentest tool) but extended with:
- Multi-domain runtimes (planned Phase D — Game / Mobile / Hardware)
- Persistent Collective KB across scans (planned Phase B)
- Enterprise deferred-mutation approval gate (already in place)
- Bilingual NCC-style HTML reports (already in place)

## Why Brain-First?

The preceding VXIS architecture (14-Phase `ScanPipeline` in `pipeline.py`, 5234 lines) treated the Brain as a **bag of LLM helpers** — each phase dispatched hardcoded scanner logic and only called the Brain to interpret individual probe results. Task 1 of the Phase A migration captured this directly as a measurement: `brain_decision_count = 0` across a full benchmark scan, despite `llm_call_count = 10+` — proof that the "Brain-First" principle in `CLAUDE.md` was violated at the code level.

Phase A rebuilt VXIS so the Brain **owns the top of the stack**. Every tool call flows through `AgentBrain.think_in_loop()`, which is a true ReAct decision. Baseline 0 → Phase A result 20.

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
│    src/vxis/pipeline/scan_pipeline_v2.py  (~360 lines)       │
│                                                              │
│  • Build ScanContext                                         │
│  • Ghost activation                                          │
│  • Reset per-scan counters (finding store, brain decision)   │
│  • Run ScanAgentLoop                                         │
│  • Copy findings/chains → ctx                                │
│  • Deferred approval gate (enterprise)                       │
│  • Generate HTML report (NCC style)                          │
│  • Compute VXIS score                                        │
└─────────────────────────┬────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│                   ScanAgentLoop                              │
│          src/vxis/agent/scan_loop.py                         │
│                                                              │
│  while not completed and iteration < max_iters:              │
│      actions = await brain.think_in_loop(messages, catalog)  │
│      for (name, args) in actions:                            │
│          result = await registry.dispatch(name, args)        │
│          messages.append({tool: name, args, result})         │
│      if finish_scan: break                                   │
└─────────────────────────┬────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│                     AgentBrain                               │
│            src/vxis/agent/brain.py                           │
│                                                              │
│  • think_in_loop(messages, tool_catalog)                     │
│      - increment brain_decision_count                        │
│      - build system = LOOP_PROMPT_ADAPTER + AGENT_SYSTEM_    │
│        PROMPT.format(available_tools=…)                      │
│      - build user = recent messages digest                   │
│      - _call_llm_with_fallback (API fallback chain)          │
│      - _parse_response → list[(tool, args)]                  │
│  • think() — LEGACY, untouched                               │
└─────────────────────────┬────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────┐
│                   ToolRegistry + BrainTools                  │
│          src/vxis/agent/tool_registry.py                     │
│          src/vxis/agent/tools/                               │
│                                                              │
│  Control:   finish_scan  think  wait                         │
│  Primitive: http_request  browser_render  intercept_proxy    │
│  Strix-pw:  shell_exec  python_exec    (→ vxis-sandbox)      │
│  Finding:   report_finding  query_findings  link_chain       │
└──────────────┬────────────────────────────┬──────────────────┘
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

## Three Brain backends (only one is live)

1. **`AgentBrain`** (`agent/brain.py`) — **LIVE** path, uses LLM API (OpenAI/Anthropic/Gemini/DeepSeek via fallback chain)
2. `InteractiveBrain` (`agent/brain_interactive.py`) — stdin/stdout NDJSON; Claude Code via `vxis scan --interactive` (legacy)
3. `FileBasedBrain` (`agent/brain_filebased.py`) — file protocol, rarely used

All three increment the **unified `brain_decision_count`** counter on every `think()` / `think_in_loop()` entry, giving Phase A a single apples-to-apples metric.

## LOOP_PROMPT_ADAPTER — the surgical fix

The 200-line `AGENT_SYSTEM_PROMPT` was written for legacy scanner-tool names (Controller / Hands / Eyes / X-Ray in mandatory checklists). When reused verbatim in `think_in_loop`, the LLM would emit those legacy names — which are not in the new tool catalog. The audit (Task 3.5) identified this risk with zero BREAKING issues but 7 CONFUSING references.

**Fix β3**: prepend a ~25-line `LOOP_PROMPT_ADAPTER` constant that explicitly maps legacy names to Phase A tool names:

```
Controller → cpr_recon or http_request
Hands      → http_request
Eyes       → browser_render
X-Ray      → intercept_proxy
Knowledge  → report_finding / query_findings
Chain      → chain_synthesis / link_chain
finishing  → finish_scan
```

**Critical gotcha preserved in code**: `AGENT_SYSTEM_PROMPT.format(available_tools=…)` must run FIRST (body template uses `{{…}}` for literal JSON braces), THEN concatenate the adapter. Never pass the adapter through `.format()`. A regression test (`test_think_in_loop_adapter_concatenation_no_brace_explosion`) guards this.

## Strix-power sandbox (Task 7–8)

The Brain's real power comes from **unrestricted shell + python inside a Docker sandbox**:

- `shell_exec(command)`: arbitrary shell inside `vxis-sandbox` container. Brain can run `sqlmap -u http://juice:3000/rest/products?q=1 --risk=3 --batch` or any other scanner.
- `python_exec(code)`: writes code to `/workspace/_python_exec_<uuid>.py` on the host-mounted volume, runs `docker exec vxis-sandbox python3 …`. For asyncio payload sprays, custom PoC scripts, post-exploitation automation.

**Sandbox lifecycle**: lazy-init via `_ensure_sandbox_running()` in `shell_tools.py`. Container is started on first call and reused warm across scans (Strix convention). Workspace is a bind mount at `/tmp/vxis-workspace` ↔ `/workspace` so `shell_exec` output files are available to `python_exec` and vice versa.

**Enterprise gate caveat**: `shell_exec` bypasses the Hands-layer deferred mutation queue because sqlmap/nuclei make their own HTTP requests. For Phase A this is intentional (local Docker targets, "real hacker simulation"). Phase C will add a second-layer egress filter for customer-production scans.

## Counters and instrumentation

The post-Task-1 instrumentation commits added four metrics so every change can be evaluated:

| Metric | Source | Meaning |
|---|---|---|
| `peak_context_bytes` | `ScanContext.update_peak_size()` per phase boundary | Peak in-memory state size — watches for context explosion |
| `llm_call_count` | `_call_llm_direct` entry hook | Authoritative API call count on the AgentBrain path |
| `brain_decision_count` | Entry of every `think()` / `think_in_loop()` on all 3 brain backends | **PRIMARY** apples-to-apples "Brain is actually deciding" metric |
| `findings_count` | `len(ctx.findings)` after the scan | Simple count of discovered vulnerabilities |

All four are printed to stdout at scan end as a single grep-parseable line:

```
VXIS_BENCHMARK peak_context_bytes=<N> llm_call_count=<N> brain_decision_count=<N> findings_count=<N>
```

## Phase roadmap and trade-offs

- **Phase A** (in progress — almost complete): replace phase pipeline with single loop. Accept temporary finding-count regression while tuning. See [`PHASE_STATUS.md`](PHASE_STATUS.md).
- **Phase B** (next): prompt tuning for `shell_exec` usage, scanner integration depth, episodic memory across scans.
- **Phase C**: adversarial validation agent, structured belief state, 1M context mode, enterprise egress filter.
- **Phase D**: domain-specific runtimes (Game memory hacking, Mobile APK Frida, Firmware/Hardware benches).

## Design references

- Strix: single `while` loop, ~100K token compression, per-agent subprocess spawn (`agents/base_agent.py`)
- PentestGPT / Reflexion: strategic guidance, explicit self-critique (future Phase B)
- XBOW (commercial): large RAG corpus + ensemble validation (future Phase C)
