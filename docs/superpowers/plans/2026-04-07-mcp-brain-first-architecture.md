# VXIS MCP Brain-First Architecture Plan

> **Status:** Planned — implementation pending  
> **Goal:** Transform VXIS into a true AI-native penetration testing platform where Claude Code (Opus) acts as the external Brain, driving full phase execution through MCP primitives without wasteful double-brain LLM calls.

## Executive Summary

VXIS has two execution paths that must share the same Phase structure but differ in Brain placement:

- **Path A (MCP)**: Claude Code is the Brain. Uses MCP primitives + Task tool for parallel sub-agent dispatch. No internal LLM calls.
- **Path B (CLI)**: Internal AgentBrain is the Brain. Calls LLM API. Already implemented with parallel phase DAG.

Both paths:
- Execute the same 14-Phase + Growth Loop structure (SSOT Phase Registry)
- Activate Ghost Layer mandatorily in Phase 0
- Pursue Crown Jewel with Dead End semantics (try everything until saturated)
- Respect Scope enforcement + PII auto-redaction + Approval gates
- Support 5 profiles: aggressive / standard / stealth_1 / stealth_2 / stealth_3

## Core Principles

### 1. Single Brain Rule
- Path A: Claude Code (Opus) is the only Brain. MCP primitives contain NO LLM calls.
- Path B: Internal AgentBrain is the only Brain. Calls LLM API internally.
- Never call internal LLM when external LLM is already driving (no double-brain waste).

### 2. Full Process Always
- No "tier 1 / quick scan" modes. Every scan pursues Crown Jewel.
- Phase order is enforced. Skipping phases is not allowed.
- Each Phase runs to Dead End — the condition where nothing new can be discovered or attempted within that phase.

### 3. Phase Structure is Enforced, Internals are Autonomous
- Phase order: strictly enforced by server-side state machine
- Dead End criteria: enforced by server-side validation (objective + heuristic)
- Within each phase: Brain has full creative autonomy
- Brain chooses which primitives to call, in what order, with what payloads

### 4. Crown Jewel Policy
When Crown Jewel (L4 finding) is reached:
- Mark `crown_reached=True` in scan state
- Log `[CROWN REACHED]` event
- **Continue all remaining phases** — goal is to discover ALL alternative paths
- Final report includes primary crown path + all alternative paths
- Rationale: Customer must fix root cause, not just one entry point

### 5. Ghost Layer is Mandatory
- Every profile (including `aggressive`) activates Ghost Layer in Phase 0
- Ghost activation + verification is a blocking dead_end_criterion for Phase 0
- If `exit_ip == origin_ip`, scan aborts immediately
- Subsequent phases refuse to start if Ghost is not verified
- Profile controls Ghost configuration (proxy rotation, timing jitter, Tor requirement)

## Architecture

### Two-Path Overview

```
┌────────────────────────────────────────────────────────────┐
│                     VXIS Platform                           │
│                                                              │
│ ┌─────────────────────┐          ┌─────────────────────┐   │
│ │  Path A: MCP         │          │  Path B: CLI         │   │
│ │                      │          │                      │   │
│ │  Claude Code (Opus)  │          │  vxis scan target    │   │
│ │  as external Brain   │          │  Internal AgentBrain │   │
│ │                      │          │  (LLM API)           │   │
│ │  Serial: P0, P1,     │          │                      │   │
│ │          P8, P11,    │          │  Uses ScanPipeline   │   │
│ │          P6, Growth  │          │  with parallel DAG   │   │
│ │                      │          │  (already built)     │   │
│ │  Parallel via Task:  │          │                      │   │
│ │  P4+P15+P13          │          │  AgentBrain calls    │   │
│ │  P2+P3               │          │  primitives directly │   │
│ │  P5+P7               │          │                      │   │
│ │  P12+P18             │          │                      │   │
│ └──────────┬──────────┘          └──────────┬──────────┘   │
│            │                                  │              │
│            └──────────────┬───────────────────┘              │
│                           │                                  │
│                           ▼                                  │
│  ┌──────────────────────────────────────────────────┐      │
│  │         SHARED PHASE REGISTRY (SSOT)               │      │
│  │                                                     │      │
│  │  14 Phases + Growth Loop                           │      │
│  │  - PhaseGuide dataclass (bilingual)                │      │
│  │  - Execution order + dependencies                  │      │
│  │  - Parallel groups                                  │      │
│  │  - Dead End criteria (static + dynamic lambdas)    │      │
│  │  - Recommended primitives                           │      │
│  │  - Strategic advice + Crown hints                   │      │
│  └──────────────────────────────────────────────────┘      │
│                           │                                  │
│                           ▼                                  │
│  ┌──────────────────────────────────────────────────┐      │
│  │         SCOPE ENFORCEMENT LAYER                    │      │
│  │                                                     │      │
│  │  - URL / path / method rules                        │      │
│  │  - PII auto-detection + redaction                  │      │
│  │  - Approval gates (destructive actions)             │      │
│  │  - Rate limits / time windows                       │      │
│  │  - Audit log                                         │      │
│  └──────────────────────────────────────────────────┘      │
│                           │                                  │
│                           ▼                                  │
│  ┌──────────────────────────────────────────────────┐      │
│  │         PRIMITIVES (No LLM calls)                  │      │
│  │                                                     │      │
│  │  Hands (HTTP) / Eyes (browser) / X-Ray (proxy)    │      │
│  │  Pattern matchers / KB / Session / Finding store   │      │
│  │  Report generator / Scoring / Growth loop          │      │
│  └──────────────────────────────────────────────────┘      │
└────────────────────────────────────────────────────────────┘
```

### Parallel Execution (Both Paths)

```
Phase Dependency Graph:

P0 Foundation (serial — Ghost activation)
  ↓
P1 Director (serial)
  ↓
┌── Parallel Group 1 ──┐
│  P4 CPR               │
│  P15 Digital Twin     │
│  P13 OSINT            │
└───────────────────────┘
  ↓
┌── Parallel Group 2 ──┐
│  P2 Agents            │
│  P3 Hypothesis        │
└───────────────────────┘
  ↓
┌── Parallel Group 3 ──┐
│  P5 Special (IoT)     │
│  P7 Hardware          │
└───────────────────────┘
  ↓
P8 Synthesis (serial — chain construction)
  ↓
P11 Mutation (serial — chain variants)
  ↓
P6 Report (serial)
  ↓
┌── Parallel Group 4 ──┐
│  P12 Evolution        │
│  P18 Collective       │
└───────────────────────┘
  ↓
Growth Loop (serial — final)
```

- **Path A (MCP)**: Main Claude Code orchestrates, dispatches sub-agents via Task tool for parallel groups
- **Path B (CLI)**: Internal AgentBrain uses existing `asyncio.gather` via `parallel_group` field in `PhaseInfo`

## Profile × Parallel × Stealth Matrix

| Profile | Parallel | Delay | Ghost | Max Concurrent | Use Case |
|---------|----------|-------|-------|----------------|----------|
| `aggressive` | ON | 0ms | Mandatory | 10 | Bug bounty speed runs, internal benchmarks |
| `standard` | ON | 100ms | Mandatory | 5 | Default for most scans |
| `stealth_1` | ON | 500ms | Mandatory | 3 | Slightly cautious, WAF-sensitive targets |
| `stealth_2` | ON | 1500ms | Mandatory | 2 | More cautious, IDS/SIEM evasion |
| `stealth_3` | **OFF** (serial) | 3-5s | **Mandatory + Tor required** | 1 | Maximum stealth, forensic-grade |

**Ghost is mandatory in all profiles.** Configuration varies:

```python
GHOST_CONFIG = {
    "aggressive": {
        "proxy_rotation": True,
        "ua_rotation": True,
        "tls_fingerprint": True,
        "timing_jitter": "minimal",
    },
    "standard": {
        "proxy_rotation": True,
        "ua_rotation": True,
        "tls_fingerprint": True,
        "timing_jitter": "normal",
    },
    "stealth_1": {
        "proxy_rotation": True,
        "ua_rotation": True,
        "tls_fingerprint": True,
        "timing_jitter": "high",
    },
    "stealth_2": {
        "proxy_rotation": True,
        "ua_rotation": True,
        "tls_fingerprint": True,
        "timing_jitter": "maximum",
        "request_order_randomize": True,
    },
    "stealth_3": {
        "proxy_rotation": True,
        "ua_rotation": True,
        "tls_fingerprint": True,
        "timing_jitter": "maximum",
        "request_order_randomize": True,
        "tor_required": True,
        "residential_proxy_only": True,
    },
}
```

## Phase Registry Structure

### File Layout

```
src/vxis/phases/
├── __init__.py
├── base.py              # PhaseGuide dataclass, DeadEndCriterion
├── registry.py          # SSOT — 14 phases in execution order
└── guides/              # One file per phase
    ├── p0_foundation.py
    ├── p1_director.py
    ├── p4_cpr.py
    ├── p15_digital_twin.py
    ├── p13_biometrics.py
    ├── p2_agents.py
    ├── p3_hypothesis.py
    ├── p5_special.py
    ├── p7_hardware.py
    ├── p8_synthesis.py
    ├── p11_mutation.py
    ├── p6_report.py
    ├── p12_evolution.py
    ├── p18_collective.py
    └── growth_loop.py
```

### PhaseGuide Dataclass

```python
@dataclass(frozen=True)
class DeadEndCriterion:
    id: str
    description_en: str
    description_ko: str
    check: Callable[[ScanContext], bool]  # dynamic lambda

@dataclass(frozen=True)
class PhaseGuide:
    id: str
    name_en: str
    name_ko: str
    stage: str                          # init/recon/intelligence/exploitation/chain/report/learning
    parallel_group: int                 # same group = parallel execution
    depends_on: tuple[str, ...]         # phase IDs that must complete first
    
    objective_en: str
    objective_ko: str
    
    entry_conditions: list[str]
    
    recommended_primitives: list[str]   # hints for Brain
    mandatory_primitives: list[str]     # server-enforced (e.g. Ghost in P0)
    
    dead_end_criteria: list[DeadEndCriterion]
    success_criteria: list[str]
    blocking_errors: list[str]
    
    strategic_advice_en: str
    strategic_advice_ko: str
    
    crown_hint_en: str
    crown_hint_ko: str
    
    max_duration_minutes: int
    next_phase_hint: tuple[str, ...]
```

### Serialization to MCP

Static fields serialize via `dataclasses.asdict()`. Dynamic `check` lambdas stay server-side and are invoked by `vxis_phase_check_dead_end()`.

## MCP Server Tools

### Layer 1: Mission Control

```
vxis_mission_brief()
  → Returns: full mission statement (bilingual)
     - Goal: Crown Jewel
     - Phase structure enforcement
     - Dead End semantics
     - Scope respect
     - No giving up until exhaustion

vxis_phase_list()
  → Returns: all 14 phases + Growth Loop with execution order

vxis_phase_start(phase_id)
  → Validates: depends_on satisfied, prerequisites met
  → Returns: PhaseGuide JSON
  → Side effect: sets current phase state

vxis_phase_status()
  → Returns: current phase, completed phases, failed phases, progress

vxis_phase_check_dead_end(phase_id)
  → Runs all dead_end_criteria lambdas against current ctx
  → Returns: {is_dead_end: bool, reason: str, unmet: [...]}

vxis_phase_complete(phase_id, summary)
  → Validates: dead_end reached
  → Returns: next_phase_id, transition_ok
```

### Layer 2: Sensing Primitives

```
# Recon
vxis_crawl(target, depth, stealth_level)
vxis_fingerprint(target)
vxis_subdomain_enum(domain, wordlist)
vxis_parse_forms(html)
vxis_extract_secrets(text)
vxis_parse_openapi(target)

# HTTP
vxis_http(session_id, method, url, headers, body, params, stealth_level)
vxis_probe_parallel(session_id, requests[], stealth_level)

# Browser / Traffic
vxis_screenshot(url, viewport)
vxis_render(url, wait_for_selector)
vxis_xray_start(target)
vxis_xray_flows(session_id, filter)
vxis_xray_export_har(session_id)
vxis_xray_export_pcap(session_id)

# Session
vxis_session_create(target, auth_type, credentials)
vxis_session_get(target)

# Ghost
vxis_ghost_activate(profile)
vxis_ghost_verify()
```

### Layer 3: Analysis (Rule-Based, No LLM)

```
vxis_detect_signatures(response, vector_types)
  → Pattern matching for SQLi errors, XSS reflection, path traversal, etc.

vxis_detect_waf(response)
  → Fingerprint Cloudflare / Imperva / Akamai / ModSecurity / Sucuri / F5

vxis_extract_pii(text)
  → Regex scan for email, SSN, credit card, phone, JWT, API keys

vxis_classify_response(response)
  → Return type: json / html / xml / binary / error

vxis_waf_bypass_variants(payload, waf_type)
  → Algorithmic mutation from pre-built bypass DB (NOT LLM)
```

### Layer 4: Knowledge

```
vxis_kb_query(tech_stack, vuln_type)
vxis_list_vectors(category, phase)
vxis_vector_payloads(vector_id, variant)
vxis_cve_lookup(product, version)
```

### Layer 5: Finding & Chain

```
vxis_finding_add(scan_id, finding_data)
vxis_finding_list(scan_id, filter)
vxis_finding_escalate(finding_id, new_level)
vxis_chain_graph(finding_ids)           # NetworkX-based path finding
vxis_chain_link(from_id, to_id, reasoning)
```

### Layer 6: Output & Growth

```
vxis_report_generate(scan_id)
vxis_score_compute(scan_id)
vxis_kb_record(pattern, effectiveness)
vxis_growth_loop_update(scan_id)
vxis_baseline_compare(scan_id)
```

### Layer 7: Guardrails

```
vxis_scope_load(scope_file_path | target)
vxis_scope_check_url(url)
vxis_scope_check_action(method, url, body, headers)
vxis_scope_check_data(response_body, content_type)
vxis_scope_violation_log(action, reason, risk)
vxis_scope_audit_report()

vxis_request_approval(action_desc, risk_level, impact_desc)
vxis_stealth_check(action, stealth_level)
```

## Scope Enforcement

### Scope File Format

```json
{
  "scan_id": "...",
  "target": "target.com",
  "scope": {
    "in_scope_domains": ["target.com", "*.target.com"],
    "out_of_scope": [
      "payment.target.com",
      "status.target.com",
      "mail.target.com"
    ],
    "path_rules": {
      "allow": ["/api/*", "/app/*", "/public/*"],
      "deny": [
        "/api/payment/*",
        "/api/admin/delete_*",
        "/api/users/bulk/*",
        "/webhooks/*"
      ]
    },
    "http_methods": {
      "allow": ["GET", "POST", "PUT", "PATCH"],
      "deny": ["DELETE", "CONNECT", "TRACE"]
    },
    "data_sensitivity": {
      "pii_read": "detect_and_redact",
      "pii_exfil": "forbidden",
      "financial_data": "forbidden",
      "credentials": "detect_only",
      "phi": "forbidden",
      "max_records_per_query": 10
    },
    "account_rules": {
      "create_test_accounts": "approval_required",
      "use_real_user_credentials": "forbidden",
      "credential_stuffing": "forbidden",
      "password_reset_trigger": "forbidden",
      "email_verification_trigger": "forbidden"
    },
    "destructive_actions": {
      "database_writes": "approval_required",
      "file_uploads": "approval_required",
      "file_deletions": "forbidden",
      "sql_commands": "approval_required",
      "email_sending": "forbidden",
      "sms_sending": "forbidden",
      "payment_transactions": "forbidden"
    },
    "time_window": {
      "allowed_hours": "02:00-06:00",
      "timezone": "Asia/Seoul",
      "max_duration_hours": 4
    },
    "rate_limits": {
      "max_rps": 10,
      "max_total_requests": 100000,
      "max_concurrent": 5
    },
    "audit": {
      "log_all_requests": true,
      "require_reason_for_destructive": true
    }
  }
}
```

### Scope File Lookup Priority

1. `--scope /path/to/file.json` (CLI flag) — explicit override
2. `./vxis-scope.json` (project local) — team-shared config
3. `~/.vxis/scopes/<target_hostname>.json` (user config) — personal reuse
4. `~/.vxis/scopes/default.json` — safe default fallback
5. No file found → interactive wizard asks user to create one

### PII Auto-Detection Patterns

```python
PII_PATTERNS = {
    "email":       r"[\w._+-]+@[\w.-]+\.[A-Za-z]{2,}",
    "ssn_kr":      r"\d{6}-\d{7}",
    "ssn_us":      r"\d{3}-\d{2}-\d{4}",
    "phone_kr":    r"01[016789][- ]?\d{3,4}[- ]?\d{4}",
    "phone_us":    r"\+?1?[- ]?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}",
    "credit_card": r"\b(?:\d{4}[- ]?){3}\d{4}\b",
    "account_kr":  r"\d{3,6}-\d{2,6}-\d{4,10}",
    "jwt":         r"eyJ[A-Za-z0-9_=\-]{10,}\.eyJ[A-Za-z0-9_=\-]{10,}\.[A-Za-z0-9_=\-]{10,}",
    "api_key":     r"(?:api[_-]?key|apikey|sk_|pk_)[\"'\s:=]*[A-Za-z0-9_\-]{20,}",
    "aws_key":     r"AKIA[0-9A-Z]{16}",
    "password":    r"(?:password|passwd|pwd)[\"'\s:=]+[\"']?[^\s\"']{6,}",
    "private_key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "medical":     r"(?:diagnosis|prescription|patient[_ ]id)",
}
```

When `vxis_http` gets a response, the server automatically:
1. Scans body for PII patterns
2. If matches found and `pii_exfil == "forbidden"`: returns redacted body to Brain
3. Brain never sees raw PII unless scope explicitly allows
4. All events logged to audit trail

## Parallel Sub-Agent Dispatch (Path A)

### Main Orchestrator Prompt

```
YOU ARE THE VXIS ORCHESTRATOR (Main Claude Code Brain).

MISSION: Reach Crown Jewel on {target} using full phase pipeline.

PHASE STRUCTURE:
- Serial phases (you execute directly via MCP):
    P0 Foundation (includes Ghost activation) → P1 Director
    → [Parallel Group 1]
    → P2/P3 group
    → [Parallel Group 3: P5/P7]
    → P8 Synthesis → P11 Mutation → P6 Report
    → [Parallel Group 4: P12/P18]
    → Growth Loop

PARALLEL GROUPS via Task tool:
When entering a parallel group, dispatch sub-agents simultaneously:

    Task.dispatch_parallel([
        Task(prompt=P4_PROMPT, scan_id=..., stealth_level=...),
        Task(prompt=P15_PROMPT, scan_id=..., stealth_level=...),
        Task(prompt=P13_PROMPT, scan_id=..., stealth_level=...),
    ])

Wait for all sub-agents to return before proceeding to next group.

SERIAL-ONLY PHASES (you do them directly):
These need holistic context across all findings:
- P8 Synthesis: needs all findings to build chains
- P11 Mutation: needs P8 chains
- P6 Report: needs everything

RULES:
1. Never skip a phase
2. Never proceed to next group until current group fully complete
3. Pass scan_id to every sub-agent
4. Merge sub-agent results (automatic via MCP shared state)
5. Log each phase start/complete
6. Respect scope enforcement (server-enforced anyway)
7. For destructive actions, call vxis_request_approval()

ON CROWN JEWEL DETECTED:
- Mark `crown_reached=True` via vxis_finding_escalate(level=4)
- Log `[CROWN REACHED]` event
- Continue ALL remaining phases (don't stop — find alternative paths too)

OUTPUT (final):
- Full NCC-style HTML report
- 5-dimension score
- Growth Loop baseline update
- Audit trail of scope-related events
```

### Sub-Agent Prompt Template

```
YOU ARE A VXIS PHASE EXECUTOR — {phase_name}.

MISSION:
- scan_id: {scan_id}
- target: {target}
- stealth_level: {stealth}
- scope: loaded server-side

YOUR JOB:
Execute {phase_id} to DEAD END. Do not stop until:
{dead_end_criteria_ko}

TOOLS: All VXIS MCP primitives.

PROCESS:
1. Call vxis_phase_start("{phase_id}") to get PhaseGuide
2. Read PhaseGuide objectives + recommended primitives
3. Execute primitives iteratively using your own reasoning
4. Periodically call vxis_phase_check_dead_end("{phase_id}")
5. When dead_end confirmed: vxis_phase_complete("{phase_id}", summary)
6. Return JSON summary

CONSTRAINTS:
- Respect stealth_level in every primitive call
- Respect scope (vxis_scope_check_url before any probe — automatic)
- Request approval for destructive actions via vxis_request_approval
- NO wrapping of tools in LLM calls — you ARE the only Brain

PERSISTENCE:
Do not give up. If one path dead-ends, try others. If JS analysis fails,
try different extractors. This phase must complete.

OUTPUT (JSON):
{
  "phase_id": "...",
  "status": "completed" | "failed",
  "dead_end": true,
  "duration_seconds": N,
  "findings_added": N,
  "primitives_called": N,
  "summary": {...}
}
```

## Implementation Roadmap

### Day-by-Day Breakdown

| Day | Work | Files |
|-----|------|-------|
| 1 | Phase Registry foundation | `src/vxis/phases/base.py`, `src/vxis/phases/registry.py`, 14 guide files |
| 2 | Scope enforcement layer | `src/vxis/scope/loader.py`, `scope/enforcer.py`, `scope/pii_detector.py`, `scope/audit.py` |
| 3 | Primitives modularization | `src/vxis/primitives/` — extract LLM-free functions |
| 4 | MCP Server rewrite (layers 1-2: Mission + Sensing) | `src/vxis/mcp_server.py` (full rewrite) |
| 5 | MCP Server (layers 3-6: Analysis + Knowledge + Finding + Output) | continued |
| 6 | MCP Server (layer 7: Guardrails) + Orchestrator + Sub-agent prompts | `src/vxis/mcp_prompts/` |
| 7 | CLI path refactor — use same Phase Registry | `src/vxis/pipeline/pipeline.py`, `src/vxis/scoring/benchmark.py` |
| 8 | Profile × Stealth mapping implementation | `src/vxis/profile.py`, Hands layer delays |
| 9 | Growth Loop integration + Baseline compare as primitives | `src/vxis/scheduler/`, existing growth_loop integration |
| 10 | CI drift check + Scope validator + Smoke tests | `.github/workflows/`, `tests/` |

### Acceptance Criteria

After implementation, the following must work:

1. **Path A (MCP)**:
   - `claude mcp add vxis python -m vxis.mcp_server` succeeds
   - Claude Code calls `vxis_mission_brief()` and receives full mission
   - Claude Code calls `vxis_phase_list()` and receives 14 phases
   - Main Claude Code orchestrates full pentest on test target
   - Sub-agents run P4/P15/P13 in parallel via Task tool
   - All 14 phases complete, Growth Loop runs
   - Final report generated

2. **Path B (CLI)**:
   - `vxis scan target --profile stealth_2` works
   - Internal AgentBrain drives pipeline via LLM API
   - Uses same Phase Registry (SSOT)
   - Parallel phase DAG still works (already tested)
   - Stealth profile affects delays + concurrency

3. **Scope Enforcement**:
   - Out-of-scope URL → `vxis_http` returns scope violation error
   - PII in response body → auto-redacted before Brain sees it
   - Destructive action → requires approval via stdin/MCP sampling
   - All events logged to audit trail

4. **Ghost Mandatory**:
   - Every profile activates Ghost in Phase 0
   - If Ghost verification fails → scan aborts
   - `exit_ip == origin_ip` → scan aborts
   - Other phases refuse to start if Ghost not verified

5. **Crown Jewel Policy**:
   - L4 finding detected → `crown_reached=True` flag set
   - Pipeline continues all remaining phases
   - Report shows primary + alternative paths

6. **CI Drift Check**:
   - Test asserts Phase Registry is consistent between CLI and MCP
   - Test asserts all `recommended_primitives` exist as MCP tools
   - Test asserts scope schema validates

## Open Questions (Resolved)

| # | Question | Decision |
|---|----------|----------|
| 1 | MCP Server: refactor or rewrite? | **Full rewrite** — existing 969 lines are based on old ScanOrchestrator |
| 2 | WAF Bypass / Business Logic / Threat Modeling modules? | **Keep for CLI path only** (internal Brain uses them). MCP path: Claude Code does this natively. Phase Guides mention as hints. |
| 3 | Parallel by default? | Yes for all profiles except `stealth_3` (serial). |
| 4 | Scope file location? | Hybrid: `--scope` flag → `./vxis-scope.json` → `~/.vxis/scopes/<target>.json` → `default.json` |
| 5 | Phase Guide format? | Python dataclass (type-safe, dynamic lambdas, JSON-serializable) |
| 6 | Phase Guide language? | Bilingual (ko + en) |
| 7 | Stealth × Parallel? | aggressive/standard/s1/s2 = parallel, s3 = serial. All use Ghost. |
| 8 | Crown Jewel found → stop? | **No** — continue all phases to find alternative paths |
| 9 | Ghost activation? | **Mandatory in all profiles**, enforced in Phase 0 |
| 10 | Double Brain waste? | Eliminated — Path A never calls internal LLM, Path B never calls external |

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Sub-agent cost explosion (parallel Claude Code calls) | `stealth_3` falls back to serial. Profile controls parallel count. |
| Race conditions in shared scan state | Already solved in Batch 5 (threading.Lock, _chain_builder_lock, atomic checkpoint writes) |
| Scope file misconfig → accidental damage | Safe default (all destructive = forbidden). Interactive wizard on first run. |
| Ghost verification false positive | Explicit `exit_ip != origin_ip` check + Tor/proxy validator |
| Phase dead_end never reached | Timeout fallback: `max_duration_minutes` per phase, server forces transition with warning |
| MCP rewrite breaks existing tests | Keep old mcp_server.py as `mcp_server_legacy.py` during transition. CI runs both. |
| Claude Code Task tool limits | Max N parallel sub-agents per profile. `stealth_3` uses 1. |

## Self-Growth Intelligence Layer (Addition)

### Motivation

VXIS already has data collection (CVE Watch, Upstream Watch, Domain Intel) and
validation (Growth Loop), but these workflows operate in isolation. Each produces
Telegram alerts or digest markdown — humans must manually translate insights into
code upgrades. This section describes the missing feedback loop that closes the
circle: **every new piece of threat intelligence autonomously upgrades VXIS code,
phase guides, knowledge store, and attack vectors, with benchmark validation and
automatic rollback on regression**.

### Design Principle

"Whatever a human security expert does when reading a new CVE or threat report
— extract insights, map them to the right system component, apply improvements —
VXIS Brain does the same thing, continuously, 24/7, with rollback safety."

### 7-Step Self-Growth Loop

```
1. INGEST     — All sources → signals/inbox/*.jsonl
2. EXTRACT    — LLM Brain parses each signal into structured intelligence
3. CLASSIFY   — Route each intelligence to the correct VXIS component
4. VALIDATE   — Sanity checks (syntax, duplicates, trust score, blast radius)
5. APPLY      — Low-risk: auto-apply. High-risk: queue as GitHub Issue for approval.
6. BENCHMARK  — Run Growth Loop. IMPROVED → commit. REGRESSED → auto-rollback.
7. REPORT     — Weekly digest (Telegram + Dashboard + GitHub Discussion)
```

### Integration with Existing GitHub Actions

Existing workflows are NOT rewritten. They are extended to feed the new pipeline:

| Existing Workflow | Change |
|-------------------|--------|
| `cve-watch.yml` | Already produces Telegram alerts. Add step: write structured result to `.vxis/signals/inbox/cve-<timestamp>.jsonl` |
| `upstream-watch.yml` | Add step: write to `.vxis/signals/inbox/upstream-<timestamp>.jsonl` |
| `domain-intel.yml` | Add step: write to `.vxis/signals/inbox/domain-<timestamp>.jsonl` |
| `growth-loop.yml` | Add `repository_dispatch` trigger type (`growth-loop-validate`) + rollback logic for `signal-driven` changes |
| `action-bridge.yml` | Repurpose as orchestrator between signal pipeline workflows |

Three new workflows complete the loop:

#### `signal-ingest.yml` (hourly)
```yaml
name: Signal Ingest
on:
  schedule:
    - cron: "15 * * * *"
  workflow_run:
    workflows: ["CVE Watch", "Upstream Watch", "Domain Intelligence"]
    types: [completed]

jobs:
  ingest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - run: pip install -e .
      - run: python -m vxis.growth.ingest
        # - Read latest cve-watch output
        # - Read latest upstream-watch output
        # - Read latest domain-intel output
        # - Run ThreatNewsWatcher (RSS feeds)
        # - Unify all signals into .vxis/signals/inbox/
      - name: Commit signals
        run: |
          git config user.name "vxis-growth[bot]"
          git add .vxis/signals/inbox/
          git diff --staged --quiet || git commit -m "chore(signals): ingest hourly batch"
          git push || true
```

#### `signal-analyze.yml` (every 2 hours)
```yaml
name: Signal Analyze
on:
  schedule:
    - cron: "0 */2 * * *"
  workflow_dispatch:
    inputs:
      signal_file:
        description: "Process specific signal file only"
        required: false
  repository_dispatch:
    types: [manual-analyze]

permissions:
  contents: write
  issues: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - run: pip install -e .

      - name: LLM Analysis — extract structured intelligence
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          TOGETHER_API_KEY: ${{ secrets.TOGETHER_API_KEY }}
        run: python -m vxis.growth.analyze
        # Brain (LLM) processes each signal:
        # - Extract CVEs, TTPs, threat actors, techniques
        # - Map to VXIS components (vectors, phase guides, KB)
        # - Generate upgrade proposals
        # - Assign trust score based on source
        # Output: .vxis/signals/proposals/<timestamp>-<topic>.json

      - name: Apply low-risk changes
        id: apply
        run: python -m vxis.growth.apply --low-risk
        # Auto-apply if:
        #   - trust_score >= 0.7
        #   - change_type in [vector_add, guide_advice_append, kb_pattern_add, wordlist_expand]
        #   - blast_radius < 5% (diff size limit)
        # Writes to:
        #   - src/vxis/scoring/vectors.py
        #   - src/vxis/phases/guides/*.py
        #   - ~/.vxis/knowledge_store.json
        #   - src/vxis/primitives/wordlists/

      - name: Queue high-risk changes as GitHub Issues
        run: python -m vxis.growth.queue_high_risk
        # high-risk = phase order change, scope rule change, new phase, approval gate mod
        # Creates GitHub Issue with label: ["needs-approval", "growth-proposal"]

      - name: Commit applied changes
        if: steps.apply.outputs.changes_applied == 'true'
        run: |
          git config user.name "vxis-growth[bot]"
          git add src/ .vxis/signals/applied/
          git commit -m "feat(growth): auto-apply ${{ steps.apply.outputs.change_count }} upgrades from signals"
          git push

      - name: Trigger Growth Loop benchmark
        if: steps.apply.outputs.changes_applied == 'true'
        uses: peter-evans/repository-dispatch@v3
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          event-type: growth-loop-validate
          client-payload: |
            {
              "source": "signal-analyze",
              "apply_commit": "${{ steps.apply.outputs.commit_sha }}",
              "change_summary": "${{ steps.apply.outputs.change_summary }}"
            }
```

#### `growth-digest.yml` (Sunday 18:00 UTC)
```yaml
name: Growth Weekly Digest
on:
  schedule:
    - cron: "0 18 * * 0"
  workflow_dispatch:

jobs:
  digest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install -e .

      - run: python -m vxis.growth.digest --week
        # Aggregate:
        # - signals processed (by source)
        # - auto-applied changes (by type)
        # - rolled-back changes (with reasons)
        # - pending approvals count
        # - score delta this week
        # - top 10 insights
        # Writes: docs/growth-digests/YYYY-MM-DD.md

      - name: Notify
        env:
          TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}
          TELEGRAM_CHAT_ID: ${{ secrets.TELEGRAM_CHAT_ID }}
        run: python -m vxis.growth.notify --digest docs/growth-digests/$(date +%Y-%m-%d).md

      - name: Create GitHub Discussion
        uses: abirismyname/create-discussion@v1
        with:
          title: "VXIS Weekly Growth Digest — $(date +%Y-%m-%d)"
          body-filepath: docs/growth-digests/$(date +%Y-%m-%d).md
          category-id: ${{ secrets.GROWTH_DISCUSSION_CATEGORY_ID }}
```

### New Python Module: `src/vxis/growth/`

```
src/vxis/growth/
├── __init__.py
├── ingest.py          # Unify signals from all sources → inbox/
├── analyze.py         # LLM-powered extraction + classification
├── apply.py           # Low-risk auto-apply to code + KB
├── queue_high_risk.py # Create GitHub Issues for approval
├── rollback.py        # Undo applied changes
├── digest.py          # Weekly summary generation
├── notify.py          # Telegram + GitHub Discussion
├── trust.py           # Source trust scoring (per-domain reputation)
├── classifier.py      # Risk level assessment (low vs high)
├── changelog.py       # .vxis/growth_log.jsonl management
└── schemas.py         # NewsIntelligence, Proposal, UpgradeChange dataclasses
```

### Extraction Schema

```python
@dataclass
class NewsIntelligence:
    """Structured intelligence extracted from a signal."""
    signal_id: str
    source: str           # "cve_watch" | "upstream_watch" | "domain_intel" | "threat_news"
    article_url: str
    article_title: str
    pub_date: str
    trust_score: float    # 0.0-1.0

    # Factual (regex)
    cves: list[str]
    iocs: dict[str, list[str]]  # {"ip": [...], "domain": [...], "hash": [...]}

    # LLM-extracted
    threat_actors: list[str]
    malware_families: list[str]
    ttps: list[dict]  # [{"mitre_id": "T1566.001", "description": "..."}]
    attack_chain: list[str]
    target_industries: list[str]
    target_technologies: list[str]

    # VXIS upgrade proposals
    proposed_vectors: list[dict]          # new AttackVector entries
    proposed_phase_updates: list[dict]    # [{"phase_id": "P4_cpr", "field": "strategic_advice_ko", "append": "..."}]
    proposed_kb_patterns: list[dict]
    proposed_waf_variants: list[dict]
    proposed_actor_updates: list[dict]
```

### Phase-by-Phase Upgrade Mapping

| Phase | News-driven upgrades |
|-------|---------------------|
| **P0 Foundation** | New Ghost/anonymization techniques → `primitives/ghost_layer.py` |
| **P1 Director** | Chain reasoning patterns from real breach reports |
| **P4 CPR (Recon)** | **Major**. New fingerprints, new JS analysis, new exposed-file patterns (e.g., .lnk) → `recommended_primitives` + wordlists |
| **P15 Digital Twin** | New sandbox evasion techniques to test in simulation |
| **P13 OSINT** | **Major**. New threat actor TTPs, new GitHub/LinkedIn/Shodan queries → `threat_actors.json` |
| **P2 Agents** | **Major**. New attack vectors → `vectors.py` via existing `cve_to_vector.py` |
| **P3 Hypothesis** | **Major**. "if tech == X then likely Y" patterns → Knowledge Store |
| **P5 Special (IoT/Web3)** | New IoT CVEs, smart contract attacks, LotL techniques |
| **P7 Hardware** | Side-channel / DMA papers → research vectors |
| **P8 Synthesis** | **Major**. Breach report chain patterns ("credential dump → lateral → DA") |
| **P11 Mutation** | **Major**. New WAF bypass payloads → `waf_bypass_db.json` auto-expand |
| **P6 Report** | New compliance requirements → report template updates |
| **P12 Evolution** | **Already self-growth phase** — directly consumes news intelligence |
| **P18 Collective** | **Already KB update phase** — directly stores news-derived patterns |
| **Growth Loop** | **Already validation phase** — validates signal-driven changes |

### Safety Mechanisms

| Safeguard | Description |
|-----------|-------------|
| **Trust scoring** | Per-source reputation. securityaffairs=0.9, unknown blog=0.3. Low trust forces human review |
| **Change budget** | Max N auto-applied changes per 24h. Excess queues for manual batch review |
| **Dry-run mode** | First month: generate proposals only, no code changes. Human reviews everything |
| **Rollback history** | Every change recorded in `.vxis/growth_log.jsonl` with reverse diff |
| **Blast radius limits** | Reject if single change exceeds 5% of target file's lines |
| **Human approval gates** | Phase order changes, scope rule changes, new phases, approval gate modifications |
| **Regression guard** | Growth Loop benchmarks all changes. Score drop > 5 points → auto-rollback |
| **Duplicate detection** | Same CVE/TTP already in VXIS → skip |
| **Source allowlist** | Only accept signals from pre-approved sources (in `trust_scores.json`) |
| **Rate limiting** | Max 20 proposals per source per day → prevent flooding |

### Signal Storage Layout

```
.vxis/
├── signals/
│   ├── inbox/                    # Raw ingested (JSONL, append-only)
│   │   ├── cve-2026-04-07-14.jsonl
│   │   ├── news-2026-04-07-14.jsonl
│   │   ├── upstream-2026-04-07-02.jsonl
│   │   └── domain-2026-04-07-00.jsonl
│   ├── proposals/                # LLM analysis output
│   │   ├── 2026-04-07T14-dprk-lnk-github-c2.json
│   │   └── 2026-04-07T15-cloudflare-http3-bypass.json
│   ├── applied/                  # Auto-applied changes log
│   │   └── 2026-04-07/
│   │       ├── vectors-added.json
│   │       ├── guides-updated.json
│   │       ├── kb-patterns.json
│   │       └── summary.json
│   ├── rejected/                 # Rejected or rolled-back
│   │   └── 2026-04-07-regression.json
│   └── pending/                  # High-risk awaiting approval
│       └── 2026-04-07-new-phase-proposal.json
├── growth_log.jsonl              # Full growth history (append-only)
├── trust_scores.json             # Per-source reputation
└── upgrade_history.json          # Applied changes with reverse diffs
```

### Dashboard Extension

Add new route to FastAPI dashboard (already planned in Batch 1F):

- `/growth` — Main growth dashboard
  - Daily/weekly signals processed (by source)
  - Auto-applied changes list (with diff links)
  - Pending approvals count + details
  - Score trend graph (signal-driven vs manual)
  - Top 10 insights this week
  - Rollback history

### Case Study: DPRK LNK + GitHub C2 Article

Real example of what the loop would autonomously do when given the Security
Affairs article on DPRK phishing:

**Input**: ThreatNewsWatcher pulls the article from Security Affairs RSS.

**Extract** (LLM output):
```json
{
  "cves": [],
  "threat_actors": ["dprk", "kimsuky"],
  "malware_families": ["xenorat"],
  "ttps": [
    {"mitre_id": "T1566.001", "description": "Spear-phishing with LNK attachment"},
    {"mitre_id": "T1059.001", "description": "PowerShell execution from LNK"},
    {"mitre_id": "T1053.005", "description": "Scheduled Task persistence"},
    {"mitre_id": "T1102", "description": "GitHub as C2 channel"}
  ],
  "attack_chain": ["phishing_email", "lnk_obfuscation", "powershell_lotl", "scheduled_task", "github_c2"],
  "target_industries": ["south_korean_enterprises"],
  "iocs": {
    "github_accounts": ["motoralis", "God0808RAMA", "Pigresy80", "entire73", "pandora0009"]
  },
  "trust_score": 0.9
}
```

**Classify**:
```json
{
  "proposed_vectors": [
    {
      "id": "WEB-PHISH-001",
      "name_en": "Exposed LNK file discovery in public directories",
      "name_ko": "공개 디렉토리 .lnk 파일 노출 탐지",
      "phase": "P4_cpr",
      "risk": "low"
    },
    {
      "id": "WEB-C2-001",
      "name_en": "GitHub API anomalous traffic pattern (C2 indicator)",
      "name_ko": "GitHub API 이상 트래픽 패턴 (C2 의심)",
      "phase": "P13_biometrics",
      "risk": "low"
    }
  ],
  "proposed_phase_updates": [
    {
      "phase_id": "P4_cpr",
      "field": "strategic_advice_ko",
      "append": "최근 DPRK 캠페인은 /downloads, /files, /public 경로의 노출된 .lnk 파일을 악용한다. 크롤링 시 .lnk 확장자 체크 필수."
    },
    {
      "phase_id": "P13_biometrics",
      "field": "strategic_advice_ko",
      "append": "DPRK 행위자는 GitHub 비공개 레포를 C2 인프라로 사용한다. 한국 타겟 스캔 시 JS 번들/네트워크 플로우에서 비정상 GitHub API 트래픽 패턴 확인."
    }
  ],
  "proposed_kb_patterns": [
    {"if": "industry == 'south_korean_enterprise'", "then": "priority_actors += ['dprk_kimsuky']"},
    {"if": "exposed .lnk file found", "then": "priority_vector = 'WEB-PHISH-001'"},
    {"if": "github_api_anomaly", "then": "check_vector = 'WEB-C2-001'"}
  ],
  "proposed_actor_updates": [
    {
      "actor_id": "dprk_kimsuky",
      "aliases_add": ["APT43", "Black Banshee", "Thallium"],
      "ttps_add": ["T1566.001", "T1059.001", "T1053.005", "T1102"],
      "campaigns_append": {
        "year": 2026,
        "source": "securityaffairs/190413",
        "summary": "LNK + PowerShell LotL + GitHub C2",
        "iocs": {"github_accounts": ["motoralis", "..."]}
      }
    }
  ]
}
```

**Validate**: All new (no duplicates), syntax OK, trust 0.9 > 0.7 threshold, within blast radius limits.

**Apply** (automatic):
- `src/vxis/scoring/vectors.py` ← append WEB-PHISH-001, WEB-C2-001
- `src/vxis/phases/guides/p4_cpr.py` ← append strategic_advice
- `src/vxis/phases/guides/p13_biometrics.py` ← append strategic_advice
- `src/vxis/data/threat_actors.json` ← update DPRK profile
- `~/.vxis/knowledge_store.json` ← 3 new patterns

**Benchmark**: Growth Loop runs on Mutillidae + DVWA + Juice Shop → score delta +3 points → KEEP → commit.

**Report (weekly digest)**:
```
VXIS Growth Digest — 2026-04-08
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Articles processed: 142
New vectors added: 7
Phase guides updated: 4
KB patterns added: 23
Threat actor profiles updated: 5
Score delta: +12 points (831 → 843)

Top insights this week:
1. DPRK LNK + GitHub C2 (Security Affairs) → +2 vectors, P4/P13 updated
2. Cloudflare HTTP/3 bypass (BleepingComputer) → +8 WAF variants
3. Laravel Livewire CVE-2026-XXXXX → +1 critical vector
...

Rollbacks: 1 (pattern conflict)
Pending approvals: 2 (Phase order change suggestions)
```

### Implementation Addition to Roadmap

Add to the 10-day roadmap:

| Day | Work |
|-----|------|
| 11 | `src/vxis/growth/` module foundation (ingest, schemas, changelog) |
| 12 | `src/vxis/growth/analyze.py` — LLM extraction + classification logic |
| 13 | `src/vxis/growth/apply.py` + `rollback.py` — code modification + reverse diff |
| 14 | 3 new GitHub Actions workflows (signal-ingest, signal-analyze, growth-digest) |
| 15 | Existing workflow extensions (cve-watch, upstream-watch, domain-intel, growth-loop) |
| 16 | Trust scoring + classifier + high-risk queue (GitHub Issues integration) |
| 17 | Dashboard `/growth` route + digest notification + Discussion auto-post |
| 18 | Case study dry-run on DPRK article + 10 more real articles |

**Revised total: 18 days** (original 10 days MCP architecture + 8 days self-growth layer).

### Follow-up Work (Post-MVP)

- **Resource URIs**: `vxis://scans/<id>/findings`, `vxis://reports/<id>` for large data
- **Streaming progress**: MCP `notifications/progress` for real-time phase updates
- **Multi-target orchestration**: Single Claude Code session scans multiple targets
- **Report auto-publish**: Integration with existing hooks (Slack, Jira, Linear)
- **Retest workflow**: `vxis retest <scan_id>` reuses scope + compares results
- **Phase Guide hot-reload**: Edit guide → MCP picks up without restart
- **Custom vector injection**: `vxis_inject_vector()` for user-defined attacks
- **Growth ML model**: Train classifier on approved/rejected proposals for better auto-apply
- **Cross-source correlation**: "Same CVE mentioned in 3 sources → high confidence"
- **Proactive research**: When trending topic detected, auto-query NVD/GitHub for related

## Summary

This plan transforms VXIS into a true AI-native pentesting platform. The key innovations:

1. **Phase structure is a SSOT** shared by both paths (MCP and CLI)
2. **Claude Code is the only Brain in Path A** — no double LLM waste
3. **Internal AgentBrain is the only Brain in Path B** — unchanged from current
4. **Ghost is mandatory in all profiles** — no accidental origin IP leaks
5. **Full Dead End execution** — every phase runs exhaustively
6. **Crown Jewel pursuit continues after first hit** — maps all alternative paths
7. **Parallel via Task tool (Path A) or asyncio.gather (Path B)** — same speedup
8. **Scope + PII protection is server-enforced** — Brain can't bypass
9. **Approval gates for destructive actions** — user stays in control
10. **Profile system unifies stealth + parallelism** — 5 levels from aggressive to stealth_3
11. **Self-Growth Intelligence Layer** — CVE Watch / Upstream Watch / Domain Intel / Threat News RSS → auto-upgrade code + KB + phase guides, with benchmark validation and auto-rollback
12. **Existing GitHub Actions become the growth nervous system** — no rewrite, extended to feed signal pipeline

Total implementation effort: **18 days** for production-ready state (10 days MCP architecture + 8 days self-growth).

---

**Next step**: Start Day 1 — Phase Registry foundation (`src/vxis/phases/base.py` + 14 guide files).
