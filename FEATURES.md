# VXIS Features - Current Public Surface

> User-facing feature catalog. Read `README.md` for the product direction,
> `ARCHITECTURE.md` for how it is built, and `PHASE_STATUS.md` for roadmap
> status. This file lists production-wired behavior first; planned/incubator
> work is explicitly labeled.

## Core - Narrow, Deep Autonomous Web Testing

### Single persistent ReAct loop

One LLM Brain owns the scan end to end through `AgentBrain.think_in_loop()` and
`ScanAgentLoop`. VXIS uses Strix-style lessons such as one tool per turn,
sandbox execution, compact run state, and developer-friendly CLI output, but the
VXIS product center is stricter: verified findings, exploit chains, policy
gates, bilingual reporting, and reproducible benchmarks.

**CLI:** `vxis scan http://target.example --profile crown`

### Public profiles

| Profile | Use |
|---|---|
| `crown` | Deep validated chain hunting toward crown-jewel impact |
| `bugbounty` | Researcher-oriented mode with aggressive recon and concise PoC artifacts |
| `passive` | No direct target contact; third-party intel only |
| `stealth` / `standard` / `aggressive` | Legacy noise/speed presets still supported |

Aliases for `bugbounty`: `bug-bounty`, `bug_bounty`, `bb`.

### Brain tools

| Layer | Tools | What they do |
|---|---|---|
| Control | `finish_scan`, `think`, `wait` | Loop management and scratchpad reasoning |
| Primitive | `http_request`, `browser_render`, `intercept_proxy` | HTTP, browser, and proxy-backed evidence collection |
| Sandbox | `shell_exec`, `python_exec` | Isolated command execution for sqlmap, nuclei, ffuf, custom Python, and replay scripts |
| Finding CRUD | `report_finding`, `query_findings`, `link_chain` | Submit verified vulnerabilities, query state, and assert exploit chains |

### Evidence contract

High and critical findings are rejected unless they include:

- request or payload
- observed response or effect
- control comparison
- replay command or raw HTTP request
- repeated reproduction signal
- negative/refutation signal
- concrete impact statement

The bug bounty export only emits accepted, replayable findings.

### Bug bounty export

```bash
vxis scan http://localhost:3000 --profile bugbounty --output reports/juice-bb.html
vxis export <scan_id> --format bugbounty --output reports/juice-bugbounty.json
```

The export is a lightweight JSON artifact centered on `finding.json`-style
submission data: title, severity, impact, replay command, PoC transcript,
control comparison, evidence, remediation, and references.

### Bilingual NCC-style HTML reports

VXIS keeps the professional report path: single-file HTML rendered by
`ReportGenerator`, including verification context, chain evidence, MITRE
coverage where available, and Korean/English-ready finding text.

## Safety And Policy

### Scope and policy gates

Runtime policy is resolved per profile. `bugbounty` allows deeper sandbox-backed
recon and lateral validation inside strict authorized scope, while still
deferring risky mutation outside target policy.

### Mutation and injection controls

The Hands layer queues mutating HTTP verbs for review, and exploitation-class
vectors require explicit authorization unless the target is a known local
benchmark or the operator enables the appropriate bypass.

### Fail-closed public surface

Production Brain scans are black-box web scans. Unsupported or future surfaces
must fail closed instead of registering placeholder tools.

## Observability

### CLI/TUI

VXIS exposes a Textual/Rich scan surface for live Brain activity, tool actions,
findings, chains, score, and blockers. Headless output remains available for CI
and scripted benchmark runs.

### Benchmark line

Every scan prints a grep-parseable benchmark line:

```text
VXIS_BENCHMARK peak_context_bytes=<N> llm_call_count=<N> brain_decision_count=<N> findings_count=<N>
```

The current Strix-vs-VXIS comparison contract adds confirmed findings,
critical/high count, false positives, chain depth, time, tokens, and repro
completeness.

### Dashboard and MCP

The dashboard can create scans and review existing scan records. The MCP server
exposes working VXIS scan/primitive tools for external AI workflows; it should
not expose incubator-only surfaces.

## Developer Surfaces

### Python API

```python
from vxis.agent.brain import AgentBrain
from vxis.pipeline import ScanPipeline

pipeline = ScanPipeline(brain=AgentBrain())
ctx = await pipeline.run(target="http://example.com")
print(f"Found {len(ctx.findings)} vulns, score {ctx.vxis_score.total}")
```

### Plugin and registry system

`src/vxis/plugins/` and `vxis.registry` support scanner integrations and local
tooling, but public registration must mean the code is present, packaged,
policy-gated, and covered by runtime tests.

## Planned Or Incubator

These areas are not public production promises until promoted with runtime
tools, scope gates, report evidence, benchmark targets, and regression tests:

- Source-aware white/grey-box scanning
- CI/CD `vxis scan --ci --fail-on high`
- Mobile runtime analysis
- Game runtime analysis
- Hardware/firmware runtimes
- Cloud-console session automation
- Multi-agent swarm orchestration

## What VXIS Is Not

- Not a broad Strix clone.
- Not a one-shot CVE scanner.
- Not a promise to test every domain surface today.
- Not legal to run against targets you do not own or have authorization to test.
