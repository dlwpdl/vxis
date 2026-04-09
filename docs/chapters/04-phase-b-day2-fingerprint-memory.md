# Chapter 04 — Phase B Day 2: Fingerprint + Memory + Stabilization

**Date:** 2026-04-09 (evening)
**Commits:** b92987e
**Outcome:** 15 tools total, 11 playbooks, automatic stack detection, cross-scan memory KB. Phase B ≈ 80% complete.

## Context

End of Chapter 03: playbook architecture is working but Brain still has to:
1. Manually run `curl -sk -D -` and parse headers in its reasoning field
2. Look at signals and guess which playbooks to load
3. Start every scan from scratch with no knowledge of prior results

These are all things VXIS could automate.

## Problem

- **Stack detection is error-prone.** Brain sometimes loads the wrong
  playbook. Juice Shop = Node/SPA but Brain occasionally reached for PHP
  playbook because of a weak signal.
- **Cross-scan learning missing.** Scanning the same target 10 times
  repeats the same baseline work 10 times. No memory of prior findings.
- **Stack coverage limited.** Day 1 had 7 playbooks covering
  Node/PHP/Django/Spring/generic. Ruby, Python-micro, Go, and .NET were
  missing — important production stacks.

## Decision

Three parallel additions:

**`fingerprint_target` BrainTool.** Fetches root + a fake path, runs a
header/cookie/body signal library against 8 stacks, returns a ranked
`recommended_playbooks` list. Brain makes ONE call and gets a clear
next-step instead of hand-parsing headers.

**`query_scan_memory` BrainTool + `data/scan_kb.json` persistence.**
Simple append-only JSON store keyed by `scheme://host`. At scan end,
`ScanPipelineV2._run_deferred_gate` auto-records findings. At scan start,
Brain calls `query_scan_memory` to see prior findings and use them as
context ("verify these still exist, then hunt for new ones"). First step
toward Phase C's full vector-backed episodic memory.

**4 new playbooks** (markdown, no Python code):
- `rails.md` — Ruby on Rails (credentials/master.key, Sidekiq, Devise)
- `flask_fastapi.md` — Python Flask/FastAPI (debug console, /docs)
- `go_web.md` — Go Gin/Echo/Fiber (pprof, expvar, metrics)
- `aspnet.md` — ASP.NET / .NET Core / IIS (web.config, elmah, swagger)

**Adapter workflow v5** updated: STEP 1 is now `query_scan_memory`, STEP 2
is `fingerprint_target`, STEPs 3-7 unchanged.

## Execution

User's guidance mid-session: "stop creating new tools, strengthen what
you have." Stopped adding new things. Wired up the created tools to the
adapter, fixed fingerprint signal gaps, tested.

Key fingerprint signal fix: the initial body sample was 4000 chars, but
Angular `<app-root>` and Juice Shop's `mat-app-background` appear late
in large HTML bodies. Changed to **8k head + 4k tail sampling** so late
signals are caught. Added Angular Material signals (`mat-app-background`,
`mat-typography`) and Juice Shop's `X-Recruiting` header.

Verified fingerprint detection:
- Juice Shop → `['express_node_spa', 'generic_rest_api', 'generic_sensitive_files', 'injection_vectors']`
- WebGoat → `['spring_boot', 'django_python', 'generic_sensitive_files', 'injection_vectors']`
  - The `django_python` match is a soft false positive from `sessionid=` cookie
    sharing. `spring_boot` is the top match so it doesn't hurt.

## Result

**15 tools total registered** (13 Phase A + 2 new Phase B):
```
finish_scan, think, wait                          [control]
http_request, browser_render, intercept_proxy     [primitives]
shell_exec, python_exec                           [Strix-power]
report_finding, query_findings, link_chain        [finding CRUD]
list_playbooks, load_playbook                     [playbook library]
fingerprint_target                                [new — auto stack detect]
query_scan_memory                                 [new — cross-scan learning]
```

**11 playbooks total** (7 Day 1 + 4 today).

**Benchmark (gpt-5.4-mini, Juice Shop):**
- 44.7s, brain_decision_count=17, findings=2
- Workflow 100% compliant:
  `query_scan_memory → fingerprint_target → load_playbook ×4 →
   python_exec ×5 → think ×3 → HINT → STICKY → report ×2 →
   query_findings → link_chain ×2 → finish_scan`

Finding count dropped vs Day 1 peak (8 → 2) because the new workflow is
more conservative about what to report. This is tunable in Phase B's
remaining turns.

## Lessons learned

1. **"Stop creating new things, strengthen existing"** — the user's
   mid-session guidance was correct. I was adding surface without
   integrating. After pausing to wire up what existed, test pass.
2. **Fingerprint sampling must cover head AND tail of HTML** — SPA
   framework markers often live at the end.
3. **Cross-scan memory is trivial to add (simple JSON)** but expensive
   to consume well (Brain needs prompting to actually use the prior
   findings). Phase C work.
4. **Cross-stack accuracy trade-off**: soft matches like
   `sessionid=` trigger multiple playbook recommendations. Tolerable
   because the top match is usually right, but can be refined.

## Phase B state after this chapter

Roughly **80% of Phase B scope complete**:

| Task | Status |
|---|---|
| Strix-style adapter | ✅ |
| Auto-hint + dedup + sticky | ✅ |
| Parser recovery | ✅ |
| Stack-based playbook architecture | ✅ |
| `fingerprint_target` auto-detection | ✅ |
| `query_scan_memory` cross-scan KB | ✅ (MVP) |
| 11 playbooks | ✅ |
| Dual Brain (cheap loop + expensive critic) | ❌ |
| Full episodic memory (vector-backed) | ❌ |
| Real sqlmap integration verification | ❌ |

Phase B remaining ≈ 20%: dual brain orchestration, vector memory, real
scanner integration tests.

## Next

Chapter 05 (when it's written): Dual Brain orchestration. Haiku/mini for
cheap ReAct loop dispatch, Sonnet/Opus critic every N iterations. Or:
Phase C kickoff with structured belief state + adversarial verifier.
