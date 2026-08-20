# GitHub Actions — VXIS Automation

> How VXIS uses 14 GitHub Actions workflows. Generated code is never trusted
> merely because it came from the growth system; merge and execution require
> separate review and normal CI.

## TL;DR — The Growth Cycle in One Picture

```
    ┌──────────────── threat intelligence feeders ────────────────┐
    │                                                              │
    │   cve-watch      upstream-watch      domain-intel           │
    │   (every 6h)     (weekly Mon)        (weekly Mon)           │
    │       │                │                   │               │
    │       └────────────────┴───────────────────┘               │
    │                         ↓                                   │
    │                  signal-ingest                              │
    │          (every 6h + after any feeder)                     │
    │           unifies all raw signals → DB                     │
    │                         ↓                                   │
    │                  signal-analyze                             │
    │             (00:00 + 12:00 UTC daily)                      │
    │          decides: open issue? propose code fix?            │
    │                         ↓                                   │
    └─── opens GitHub Issue with "claude-implement" label ────────┘
                              ↓
    ┌──────────────── self-coding loop ───────────────────────────┐
    │                                                              │
    │              auto-implement                                  │
    │     (on issues:labeled[claude-implement])                   │
    │     invokes Claude Code → writes patch → opens PR           │
    │                         ↓                                   │
    │                      PR created                             │
    │                         ↓                                   │
    │        ┌────────────┬───────────┬──────────┐               │
    │        │            │           │          │               │
    │      lint        test      benchmark    review             │
    │    (lint.yml)  (test.yml) (bench.yml)                      │
    │        └────────────┴───────────┴──────────┘               │
    │                         ↓                                   │
    │                    PR merged                                │
    │                         ↓                                   │
    └──────────────── validation loop ────────────────────────────┘
                              ↓
    ┌──────────────── measurement loop ───────────────────────────┐
    │                                                              │
    │              growth-loop                                     │
    │     (manual confirmation in an isolated evaluation only)   │
    │     runs benchmark scans → stores review-only proposals    │
    │     generated proposals are not applied or executed        │
    │                         ↓                                   │
    │              growth-digest                                   │
    │          (weekly Sun 18:00 UTC)                             │
    │     summarizes the week's improvements into a report       │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

## The 14 workflows — by category

### A. Threat Intelligence Feeders (produce raw signals)

| Workflow | Schedule | What it does |
|---|---|---|
| **`cve-watch.yml`** | Every 6h | Polls NVD + GitHub Security Advisories for new CVEs relevant to VXIS's target stack. Writes to `data/signals/cve/*.json`. |
| **`upstream-watch.yml`** | Weekly | Scans VXIS's own dependencies (pyproject.toml + nuclei templates + other upstreams) for updates and security advisories. |
| **`domain-intel.yml`** | Weekly (Mon 01:00 UTC) | Runs forecast + industry intelligence for registered domains (`src/vxis/forecast/` + `src/vxis/industry/`). |

**Bootstrap mode note**: The cron schedules are currently on **reduced frequency** (every 6h instead of hourly, weekly instead of daily) to save free-tier GitHub Actions minutes. When VXIS revenue arrives, schedules upgrade to the full vision cadence.

### B. Signal Pipeline (unifies + decides)

| Workflow | Schedule | What it does |
|---|---|---|
| **`signal-ingest.yml`** | Every 6h + after any feeder completes | Collects all raw signal files from the feeders above, unifies into a single signal DB. Uses `workflow_run` trigger so it fires automatically after `cve-watch`/`upstream-watch`/`domain-intel`. |
| **`signal-analyze.yml`** | 00:00 + 12:00 UTC daily + manual | Reads the signal DB, decides what's actionable. Opens GitHub Issues for signals that need code changes. Can optionally auto-apply safe changes (e.g. bump nuclei template version) with `force_apply=true`. |
| **`action-bridge.yml`** | 00:30 UTC daily (after domain-intel) | Bridges domain-intel insights into actionable GitHub events — e.g. "new subdomain discovered for tracked client → open issue to scan it". |

**Signal → code flow:**
```
cve-watch finds CVE-2026-XXXX in sqlmap
    → signal-ingest unifies it into the signal DB
        → signal-analyze decides "this affects our sandbox image"
            → opens issue: "Update sqlmap in vxis-sandbox Dockerfile"
                → (manual or automated) add label claude-implement
                    → auto-implement picks it up
```

### C. Self-Coding Loop (writes its own patches)

| Workflow | Trigger | What it does |
|---|---|---|
| **`auto-implement.yml`** | Issue labeled `claude-implement` + manual | Spawns a Claude Code session that reads the issue, writes the fix, and opens a PR. Growth-loop suggestions must first be reviewed and converted into an explicitly approved issue. |

**Safety:** PR is NEVER auto-merged. It must pass lint + test + benchmark gates AND be reviewed by a human (or a code-reviewer agent) before merging.

### D. PR Quality Gates (block bad merges)

| Workflow | Trigger | What it does |
|---|---|---|
| **`lint.yml`** | PR to main | Runs ruff / mypy / other linters. Fast fail. |
| **`test.yml`** | PR to main + push to main | Runs the pytest suite (`tests/unit`, `tests/agent`, `tests/pipeline`). ~1400 tests. Phase A added ~30 new tests. |
| **`benchmark.yml`** | PR to main touching `src/vxis/**` | Runs `vxis scan` against local benchmark targets (Juice Shop / WebGoat) INSIDE the GitHub Action runner. Captures the `VXIS_BENCHMARK` line and compares against the baseline committed to `docs/superpowers/benchmarks/`. Fails the PR if `brain_decision_count` regresses or findings count drops significantly. |

**Gate ordering:** lint → test → benchmark. A PR must pass all three before merge is allowed.

### E. Growth Measurement Loop (measures the improvement)

| Workflow | Schedule | What it does |
|---|---|---|
| **`growth-loop.yml`** | Manual only; operator must confirm an isolated evaluation | Measures fixed training targets plus a holdout, emits bounded review-only suggestions, uploads two JSON artifacts, and opens a summary issue. It never applies, executes, commits, or pushes generated code. |
| **`growth-digest.yml`** | Weekly (Sun 18:00 UTC) | Summarizes the week's growth-loop runs, signal-ingest output, auto-implement merges, and score deltas into a single digest. Posted to the repo (and optionally to Slack / email via `integrations/`). |

## The end-to-end feedback loop, explained

VXIS automates signal collection and measurement, but code changes remain
human-gated. The growth evaluator does not execute generated patches.

### Cycle 1: Threat-driven improvement
1. **Signal**: cve-watch discovers CVE-2026-XXXX affecting Juice Shop, which means VXIS's sqlmap scan should now detect a new variant.
2. **Ingest**: signal-ingest adds the CVE to the unified DB.
3. **Analyze**: signal-analyze decides "we need a new nuclei template OR a new sqlmap tamper script to detect this". Opens an issue.
4. **Label**: Maintainer (or auto-labeler) adds `claude-implement`.
5. **Code**: auto-implement spawns Claude Code → writes the new detection rule → opens PR.
6. **Gate**: lint + test + benchmark all pass → merged.
7. **Measure**: an operator runs growth-loop in an isolated environment → reviews the score and suggestions.
8. **Digest**: Sunday digest reports "+X% detection this week thanks to the CVE-2026-XXXX rule".

### Cycle 2: Performance-driven improvement
1. **Signal**: a manually approved growth-loop run shows a weak scoring dimension.
2. **Analyze**: Delta analysis identifies the specific findings that are missing.
3. **Issue**: Auto-opens an issue "Juice Shop XSS detection regressed — investigate reflected param handling".
4. **Label**: `claude-implement` added.
5. **Code**: auto-implement writes a fix to the relevant BrainTool or prompt adapter.
6. **PR → gate → merge → re-measure** (same as Cycle 1).

### Cycle 3: Dependency-driven improvement
1. **Signal**: upstream-watch finds that nuclei released v3.4.0 with 50 new templates.
2. **Analyze**: "Update vxis-sandbox Dockerfile NUCLEI_VERSION".
3. **Issue + code + gate + merge**.
4. **Rebuild**: next scan uses the new image automatically.

## What's currently wired vs what's aspirational

| Capability | Status | Notes |
|---|---|---|
| Threat intelligence feeders (CVE/Upstream/Domain) | ✅ Live | On reduced bootstrap schedule |
| Signal ingest/analyze | ✅ Live | Feeds the issue opener |
| `auto-implement.yml` | ⚠ Scaffolded | Needs a `claude-implement` label to fire; manual approval required before merge |
| `growth-loop.yml` | ✅ Review-only | Manual confirmation, immutable target images, read-only contents permission, no generated-code execution, bounded proposal artifact. |
| `growth-digest.yml` | ⚠ Stub | Emits a weekly summary but no downstream notifications wired yet |
| PR gates (lint/test/benchmark) | ✅ Live | Active on every PR to main |

## The recurring "chore(signals): ingest batch YYYY-MM-DDTHH:MM" commits

If you look at `git log --oneline` you'll see dozens of these:
```
74b6293 chore(signals): ingest batch 2026-04-09T02:53
f9df6c8 chore(signals): ingest batch 2026-04-09T01:04
c07f6a5 chore(signals): ingest batch 2026-04-08T19:27
```

These are **automated commits from `signal-ingest.yml`** — every time the signal-ingest workflow runs, it writes the unified signal batch into `data/signals/` and commits the result directly to main. They're part of the VXIS memory — the signal history is the "what did we know when" record that growth-loop + signal-analyze consult.

**Don't squash or rebase these away.** They are the audit trail for the self-growth system.

## How the Growth Layer makes VXIS better, concretely

1. **More coverage over time**: New CVEs → reviewed detection rules → more findings on the same target. Measurable with manually approved growth evaluations.
2. **Fewer false positives over time**: weak dimensions and review-only proposals inform separately reviewed code changes.
3. **Fresh scanner versions**: upstream-watch keeps Dockerfile dependencies current → new sqlmap / nuclei versions automatically propagated via the self-coding loop.
4. **Adaptive prompts**: growth-digest summaries reveal which prompt strategies worked → signal-analyze opens PRs to strengthen successful patterns.
5. **Target-specific knowledge**: When VXIS scans a new target type repeatedly, the knowledge store (`src/vxis/knowledge/`) accumulates patterns. Phase B's episodic memory will feed this back into the Brain via RAG at scan start.

## Do NOT use these workflows to

- Run offensive scans against real targets without authorization. GitHub Actions runners are shared infrastructure and abuse triggers account bans.
- Store secrets in workflow files. Use GitHub repo secrets (Settings → Secrets → Actions).
- Bypass PR gates with `[skip ci]` or admin override. Phase A's `brain_decision_count` regression guard depends on `benchmark.yml` actually running.

## File locations

All workflow definitions: `.github/workflows/*.yml`

Related config:
- `pyproject.toml` — Python deps the actions use
- `uv.lock` — pinned versions
- `tools/benchmark/` — growth-loop score history and per-run proposal log
- `data/signals/` — unified signal DB (committed by signal-ingest)
