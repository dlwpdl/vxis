# Phase A Strix-Parity — Pre-Migration Baseline

**Purpose:** Capture the current `ScanPipeline` (14-phase orchestrator) behavior on the two
local benchmark targets, so Task 14 of the Phase A migration plan can compare the new
single-loop `ScanAgentLoop` numbers against this snapshot and decide go/no-go.

This document is **observation-only**. No source files were modified to capture these numbers.

---

## Environment

| Field | Value |
|---|---|
| Date | 2026-04-08 |
| Git SHA (HEAD at capture) | `fa32049` (`fa3204936b9756d070b7837e44a67ae44100cd0a`) |
| Branch | `phase-a/strix-parity` |
| Worktree | `/Users/eliot/Desktop/유/vxis/.worktrees/phase-a` |
| Python | 3.14.3 |
| Runner | Poetry-managed venv (`poetry run vxis ...`) |
| Brain backend | `api:openai/gpt-5.4-mini` (auto-selected by preflight; `claude -p` not active in this env) |
| Profile | `standard` |
| `--allow-inject` | yes (local benchmark, owner-operated) |
| `GITHUB_TOKEN` | unset (Phase 13 OSINT was therefore degraded — same condition the migration must reproduce) |
| Targets running | Juice Shop on `:3000`, WebGoat on `:8080/WebGoat/` (DVWA intentionally excluded) |

**Note on `--output`:** the CLI flag is accepted but the pipeline always writes the report
to `reports/VXIS_Pipeline_<host>.html` regardless of `--output`. Both copies are recorded
under `artifacts/2026-04-08/` for reproducibility.

---

## Exact scan commands (copy-pasteable)

```bash
# from worktree root
poetry run vxis scan http://localhost:3000 \
  --profile standard --allow-inject \
  --output reports/baseline_juiceshop.html

poetry run vxis scan http://localhost:8080/WebGoat/login \
  --profile standard --allow-inject \
  --output reports/baseline_webgoat.html
```

---

## Per-target results

| Metric | Juice Shop | WebGoat |
|---|---:|---:|
| Wall time (CLI-reported) | 311.8 s | 163.2 s |
| Wall time (`/usr/bin/time -p real`) | 315.66 s | 166.59 s |
| Phases executed | 14 / 14 | 14 / 14 |
| Phases failed | 0 (exit 0) | 0 (exit 0) |
| Findings — total (`len(ctx.findings)`) | **10** | **5** |
| Findings — critical | 1 | 0 |
| Findings — high | 2 | 3 |
| Findings — medium | 1 | 1 |
| Findings — low | 5 | 0 |
| Findings — informational | 1 | 1 |
| Attack chains discovered | 9 | 4 |
| Live Attacks (cumulative requests) | 78 | 78 |
| Brain consultations (`[BRAIN] Consulting Brain ...` log lines) | 11 | 11 |
| LLM per-vector attempts (`[LLM] ATTEMPT ...` log lines) | 78 | 78 |
| Finding-enrichment Brain calls | 10 | 4 |
| **Estimated total LLM invocations** (consult + per-vector + enrich) | **~99** | **~93** |
| VXIS Score | 824.3 / 1000 (A) | 812.0 / 1000 (A) |
| Report HTML size | 173 KB | 99 KB |
| Peak messages / context-dict size | **not measured** (see Notes) | **not measured** (see Notes) |

### Severity counts — sources reconciled

- The Live TUI side panel shows a **cumulative** counter that double-counts findings emitted
  by multiple phases before dedup (e.g. JuiceShop side panel shows 2/4/2/10/2 = 20 while
  the final dedup'd `ctx.findings` table has 10). The numbers in the table above are the
  **post-dedup** counts taken from the printed `Findings — VXIS-...` table at the end of
  the scan, which match `len(ctx.findings)`. **Task 14 must compare against the post-dedup
  counts**, not the live panel counter.

### Severity breakdown — Juice Shop (post-dedup, from final table)

```
CRITICAL  1   VXIS-006 SQL Injection (Error-Based) /rest/products/search
HIGH      2   VXIS-001 Missing Security Headers (5/7)
              VXIS-010 Mass Assignment /api/users/
MEDIUM    1   VXIS-005 CORS Misconfiguration /
LOW       5   VXIS-002/004/007/008/009 Information Disclosure via Error
INFO      1   VXIS-003 Missing Security Headers /
```

### Severity breakdown — WebGoat (post-dedup, from final table)

```
HIGH   3   VXIS-001 Missing Security Headers (7/7)
           VXIS-002 JWT Vulnerability /
           VXIS-004 IDOR / Access Control Bypass /WebGoat/start.mvc
MEDIUM 1   VXIS-005 Missing CSRF Token /
INFO   1   VXIS-003 Missing Security Headers /
```

### Maximum chain depth

The current pipeline reports **chain count** in the live UI but not chain length. The
HTML report contains the chain expansion. For Task 14 the comparison value is **chain
count** (Juice Shop = 9, WebGoat = 4) plus, if extracted from the HTML, the longest
chain's edge count. Both reports are committed under `artifacts/2026-04-08/` so the
Task 14 sub-agent can re-derive max depth from them with the same parser.

---

## Raw output paths

| File | Path |
|---|---|
| Juice Shop report (live) | `reports/VXIS_Pipeline_localhost:3000.html` |
| Juice Shop report (archived) | `docs/superpowers/benchmarks/artifacts/2026-04-08/report_juiceshop.html` |
| Juice Shop scan log | `docs/superpowers/benchmarks/artifacts/2026-04-08/scan_juiceshop.log` |
| Juice Shop CLI stdout | `docs/superpowers/benchmarks/artifacts/2026-04-08/juiceshop.stdout` |
| Juice Shop `time -p` | `docs/superpowers/benchmarks/artifacts/2026-04-08/juiceshop.time` |
| WebGoat report (live) | `reports/VXIS_Pipeline_localhost:8080.html` |
| WebGoat report (archived) | `docs/superpowers/benchmarks/artifacts/2026-04-08/report_webgoat.html` |
| WebGoat scan log | `docs/superpowers/benchmarks/artifacts/2026-04-08/scan_webgoat.log` |
| WebGoat CLI stdout | `docs/superpowers/benchmarks/artifacts/2026-04-08/webgoat.stdout` |
| WebGoat `time -p` | `docs/superpowers/benchmarks/artifacts/2026-04-08/webgoat.time` |

---

## Notes / quirks / partial data

1. **Peak messages/context-dict size — NOT MEASURED.** The current pipeline emits no
   counter for the brain message list length, and `ScanContext` is not serialized at
   peak. Capturing this would require code changes (instrumentation hook in
   `pipeline.py` and/or `agent/brain.py`) which Task 1 explicitly forbids ("observation
   only — if it would require non-trivial code changes, record `not measured`").
   **Action item for Task 14:** the new `ScanAgentLoop` should expose this counter
   natively (the migration plan already calls for a single message list, so it is
   trivial to instrument). The Task 14 comparison should treat the new loop's number
   as the baseline-of-record and only flag a regression if the new loop's peak is
   *larger than expected for a single ReAct loop* (rule of thumb: <50 MB resident or
   <2000 messages — calibrate during Task 14).

2. **LLM invocation count is a lower bound.** `[LLM] ATTEMPT` lines count per-vector
   Brain attempts emitted by `pipeline.py`, and `[BRAIN] Consulting Brain` count
   per-phase batched consultations. There may be additional internal LLM calls inside
   helpers (e.g. report executive-summary generation, finding enrichment confirmation
   sub-calls) that do not produce a unique log marker. The two scans landed at
   identical `78 + 11 = 89` non-enrichment LLM markers, which suggests the per-vector
   pump count is **profile-driven** (`standard`) rather than target-driven.
   Task 14 should re-grep using the same patterns:
   `\[LLM\] ATTEMPT` and `\[BRAIN\] Consulting Brain` and `enriched`.

3. **Both scans exited 0 (success).** Neither hit the 30-minute abort. WebGoat ran
   considerably faster (~half) than Juice Shop, mostly because Juice Shop has more
   discoverable endpoints (78 attack steps vs 78 — same vector budget — but more
   findings to enrich).

4. **`reports/baseline_*.html` was never created** — see "Note on `--output`" above.
   This is a pre-existing CLI bug, NOT something the migration should preserve. If
   the new `ScanAgentLoop` honors `--output`, that's an improvement, not a regression.

5. **Brain backend was OpenAI, not Claude.** Per repo policy `claude -p` should be
   first, but in this environment the preflight selected `api:openai/gpt-5.4-mini`.
   This is the same condition the new loop will run under unless the env changes,
   so the comparison is apples-to-apples. If Task 14 runs under a different Brain
   backend, results are NOT comparable and the baseline must be re-captured first.

---

## Task 14 comparison hook

When Task 14 runs the new `ScanAgentLoop` against the same two targets, the following
metrics MUST be compared. **Pass criteria:** new loop must be no worse than baseline on
findings count and chain count, and no more than 1.5x baseline on wall time and LLM
invocations.

| Metric | Juice Shop baseline | WebGoat baseline | Pass criterion |
|---|---:|---:|---|
| Wall time (s) | 311.8 | 163.2 | new ≤ 1.5 × baseline |
| Findings — total (post-dedup) | 10 | 5 | new ≥ baseline |
| Findings — critical | 1 | 0 | new ≥ baseline |
| Findings — high | 2 | 3 | new ≥ baseline |
| Findings — medium | 1 | 1 | new ≥ baseline (or +/- 1) |
| Attack chains | 9 | 4 | new ≥ baseline |
| Total LLM invocations (markers) | ~99 | ~93 | new ≤ 1.5 × baseline |
| Phases executed (or equivalent ReAct iterations) | 14 / 14 | 14 / 14 | n/a — structural change |
| VXIS Score | 824.3 | 812.0 | new ≥ baseline − 25 |
| Peak messages / context size | not measured | not measured | new loop must measure & report |

**Replication command for Task 14:**

```bash
# Same flags, same env vars, same targets, same branch tip (post-migration HEAD).
# Run from worktree root with both Juice Shop (:3000) and WebGoat (:8080/WebGoat/)
# already up in Docker.
poetry run vxis scan http://localhost:3000 --profile standard --allow-inject -o /tmp/j.html
poetry run vxis scan http://localhost:8080/WebGoat/login --profile standard --allow-inject -o /tmp/w.html
```

Then re-grep the produced log under `logs/scan_*.log` with:

```
grep -c '^.*\[LLM\] ATTEMPT' logs/scan_*.log
grep -c '^.*\[BRAIN\] Consulting Brain' logs/scan_*.log
grep -c '^.*enriched' logs/scan_*.log    # or whatever marker the new loop emits
```

If the new loop changes log markers, Task 14 is responsible for emitting an
equivalent count and documenting the marker swap in the comparison report.
