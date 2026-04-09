# VXIS Features — What the Platform Does

> User-facing feature catalog. Read `README.md` for the elevator pitch, `ARCHITECTURE.md` for how it's built, `PHASE_STATUS.md` for roadmap progress.

## Core — Autonomous Brain-First Scanning

### 🧠 Single persistent ReAct loop
One LLM Brain (via `AgentBrain.think_in_loop`) owns the entire scan end-to-end. No hardcoded phases. The Brain decides what to do per iteration based on what it just observed. This is architecturally equivalent to Strix.

**CLI:** `vxis scan http://target.com --profile standard`

**Profiles:** `stealth` / `standard` / `aggressive` — controls how much noise / how fast / how aggressive the Brain's default strategy is.

### 🛠 11 BrainTools available to the Brain

| Layer | Tools | What they do |
|---|---|---|
| **Control** | `finish_scan`, `think`, `wait` | Loop management + scratchpad reasoning |
| **Primitive** | `http_request`, `browser_render`, `intercept_proxy` | HTTP client with persistent auth state, headless browser for SPAs, MitM proxy for passive capture |
| **Strix-power** | `shell_exec`, `python_exec` | **Unrestricted shell + Python** inside an isolated Docker sandbox. Runs sqlmap / nuclei / ffuf / gobuster / custom asyncio scripts. The Brain's real weapon. |
| **Finding CRUD** | `report_finding`, `query_findings`, `link_chain` | Submit discovered vulnerabilities, search what's already found, assert causal attack chains |

### 🐳 Docker sandbox — real-hacker simulation
`vxis/sandbox:latest` Debian image (~980 MB) with pre-installed scanners: **sqlmap 1.9.6, ffuf 2.1.0, nuclei 3.3.4, gobuster 3.6, dirb, nikto, httpx, aiohttp, Python 3**. The Brain runs these via `shell_exec` with zero command whitelisting — just like a real pentest engineer.

### 🌏 Bilingual NCC-style HTML reports
Every finding, summary, and remediation is written in both English and Korean using the `"EN|||KO"` convention. Reports are rendered in the NCC Group penetration-test style via `ReportGenerator` → single-file HTML.

## Enterprise

### 🔐 Deferred-mutation approval gate
Data-mutating HTTP verbs (POST / PUT / PATCH / DELETE) routed through the `Hands` layer are queued to a **deferred action queue**. At the end of the scan the operator reviews and approves each one before it's actually replayed against the target. This is the legal-safety layer for production scans.

**Current status:** Phase A's Strix-power `shell_exec` bypasses this gate (sqlmap / nuclei make their own HTTP requests). Phase C will add a second-layer egress filter on the sandbox for customer-production scans.

### 💉 Injection approval gate
Before exploitation-phase vectors (SQLi / XSS / RCE / SSRF / XXE / auth brute) fire, the operator gets an interactive `y/N` prompt. CLI flag `--allow-inject` bypasses (benchmark mode only).

### 📋 Client / mission management
`vxis client add`, `vxis client list`, `vxis client scan` — track engagements by client, scope constraints, mission type.

## Stealth

### 👻 Ghost mode
Proxy rotation, User-Agent spoofing, TLS fingerprint masking (via curl-cffi), timing jitter, metadata scrubbing. Activated via `--ghost` flag or `ghost://` URL prefix.

## Observability

### 📺 Live Rich TUI
Real-time Rich Live display showing:
- Phase panel (which phase the Brain is in)
- Brain Thinking panel (current reasoning)
- Live Attacks counter
- Recent Hits (confirmed findings)
- Findings severity breakdown
- Attack Chains tracker
- VXIS Score

### 📊 Instrumentation metrics
Every scan prints a grep-parseable benchmark line:
```
VXIS_BENCHMARK peak_context_bytes=<N> llm_call_count=<N> brain_decision_count=<N> findings_count=<N>
```
- `peak_context_bytes` — peak messages[] size across iterations
- `llm_call_count` — API call count (fallback chain counted as separate calls)
- **`brain_decision_count`** — **primary Brain-First metric** (how many times the Brain actually ran `think_in_loop`)
- `findings_count` — final finding count after dedup

### 🌐 Web dashboard
FastAPI backend at `src/vxis/dashboard/`. Browse past scans, findings, attack chains, scores across engagements.

## Continuous / Autonomous

### 📅 Scheduled monitoring
`src/vxis/scheduler/` — cron-like scheduler that runs `vxis scan` against a fleet of registered targets on schedule. Integrates with `src/vxis/integrations/` for Slack / GitHub Issues / email notifications on critical findings.

### 🏭 Industry-wide scanning
`src/vxis/industry/` — bulk enumerator for "all companies in vertical X" with automated target discovery and scheduled scans. Operator-level feature for security researchers.

### 👁 24/7 threat watchers
Background daemons monitoring external signals:
- **CVE Watch** — NVD + GitHub Security Advisories, every 6h
- **Upstream Watch** — dependency updates + supply chain, weekly
- **Domain Intel** — forecast + industry signals, weekly
- **Signal Ingest** — unifies all signal sources
- **Signal Analyze** — decides what to do with signals (open issues, propose code changes)

See [`GITHUB_ACTIONS.md`](GITHUB_ACTIONS.md) for the full automation pipeline.

## Self-Improvement (Growth Layer)

### 🌱 Growth Loop — VXIS improves itself weekly
The `growth-loop.yml` GitHub Action runs VXIS against fixed benchmark targets (Juice Shop / WebGoat) every Sunday, scores the results, compares against the previous week, and optionally auto-applies improvements via Claude Code.

**The cycle:**
1. Run `vxis scan` against benchmarks → get current score
2. Compare vs last week's score
3. If regressed → open a GitHub issue with the score delta
4. If an open issue is labeled `claude-implement` → `auto-implement.yml` invokes Claude Code to propose a fix
5. PR opened → `benchmark.yml` + `test.yml` gate it
6. Merged → `growth-loop.yml` re-runs to validate improvement
7. Weekly summary via `growth-digest.yml`

**Current state:** Phase A rebuilt the core architecture. Phase B will re-enable the auto-improve feedback loop.

### 🧬 Evolution layer (legacy Phase 12)
Auto-generates new agent capabilities when the Brain identifies a gap during a scan ("we don't have a handler for gRPC — synthesize one"). Not wired into Phase A but the concept survives for Phase C.

## Developer Surfaces

### 🔌 MCP Server
`src/vxis/mcp_server.py` exposes VXIS as an MCP (Model Context Protocol) server. Claude Code or any MCP client can invoke `vxis.scan` as a tool. Useful for embedding VXIS into AI-driven security workflows.

**Usage (Claude Code):** `claude mcp add vxis python -m vxis.mcp_server`

### 🐍 Python API
```python
from vxis.pipeline import ScanPipeline
from vxis.agent.brain import AgentBrain

pipeline = ScanPipeline(brain=AgentBrain())
ctx = await pipeline.run(target="http://example.com")
print(f"Found {len(ctx.findings)} vulns, score {ctx.vxis_score.total}")
```

### 🧩 Plugin system
`src/vxis/plugins/` — external scanner integrations (nuclei template packs, custom semgrep rules, gitleaks configs). Discovered at startup via `vxis.registry`.

### 📦 Brain backend choice
Three backends, all implement the same `BrainProtocol`:
- **`AgentBrain`** (API) — default, OpenAI / Anthropic / Gemini / DeepSeek fallback chain
- **`InteractiveBrain`** — `claude -p` subprocess via `vxis scan --interactive`
- **`FileBasedBrain`** — file-based protocol for external orchestrators

## Domain Support

### 🌐 Web targets
Full coverage: HTTP(S), SPAs (React/Vue/Angular), REST APIs, GraphQL, WebSocket, SSE. Phase A focus.

### 🎮 Game targets — **Phase D planned**
Unity memory hooking, emulator automation, client-side secret extraction. Legacy `GamePipeline` was deleted in Phase A Task 12 and will be rebuilt on ScanAgentLoop in Phase D.

### 📱 Mobile targets — **Phase D planned**
Frida / Objection runtime hooking, APK static analysis, iOS simulator. Legacy `MobilePipeline` was deleted in Phase A Task 12 and will be rebuilt in Phase D.

### 🔩 Hardware / firmware — **Phase D planned**
CAN bus, RF, smart meter bench rigs, firmware dumping. New territory — no legacy to migrate.

## Quick feature matrix by Phase

| Feature | Phase A (current) | Phase B (next) | Phase C | Phase D |
|---|:---:|:---:|:---:|:---:|
| Brain-First single loop | ✅ | — | — | — |
| `brain_decision_count` > 0 | ✅ 20 | ≥ baseline | — | — |
| Docker sandbox with scanners | ✅ 5/7 | 7/7 | — | — |
| Bilingual NCC reports | ✅ | — | — | — |
| Deferred mutation gate (Hands) | ✅ | — | — | — |
| Prompt tuning for shell_exec preference | ⚠ WIP | ✅ | — | — |
| Episodic memory DB | — | ✅ | — | — |
| Dual Brain (cheap loop + expensive critic) | — | ✅ | — | — |
| Adversarial verifier agent | — | — | ✅ | — |
| 1M context mode | — | — | ✅ | — |
| Enterprise sandbox egress filter | — | — | ✅ | — |
| Typed blackboard (Postgres) | — | — | ✅ | — |
| Game / Mobile / Hardware runtimes | — | — | — | ✅ |

## What VXIS is NOT

- **Not a one-shot CVE scanner.** VXIS is designed for multi-hour engagements where chaining matters.
- **Not a SaaS (yet).** Current state is a local CLI + optional dashboard. SaaS is deferred.
- **Not a replacement for human red teams.** VXIS is a force multiplier — it does the repetitive probing faster than a human, but critical-finding confirmation + exploit weaponization still benefit from human review.
- **Not legal to run against targets you don't own without authorization.** See the enterprise gates above — they exist for a reason.
