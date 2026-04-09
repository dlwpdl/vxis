# Chapter 06 — Phase C: Verifier, Belief State, Egress Filter

**Date:** 2026-04-10
**Branch:** main
**Commits:** `4069e35` (verifier first brick) → `a4461fe` (ABCD stabilization) → `ccbecaa` (rubric rebalance + belief state) → this chapter + egress

## Why Phase C exists

Phase B proved the single ReAct loop could actually find things. It also
exposed the next ceiling: the Brain was *claiming* findings that didn't
hold up. A probe would return 200 OK on `/.git/config`, Brain would
shout "critical info disclosure", and the response body would turn out
to be the 8968-byte SPA shell being echoed back.

Phase C's job: stop lying to ourselves. Concretely:

1. **Verifier** — an independent, stronger LLM whose only job is to
   refute claimed findings. Asymmetric model allocation: cheap model to
   find, expensive model to validate.
2. **Belief state** — the scan loop has to remember what it verified,
   not just what it reported. A finding is now `(claim, verdict,
   confidence, reasoning)`.
3. **Egress filter** — enterprise guardrail. If the Brain pivots to a
   host it wasn't authorized for, block the command.

## Architecture deltas from Phase B

```
Phase B loop:                        Phase C loop:
Brain → tool dispatch → finding      Brain → tool dispatch
                                              ├─ (if report_finding HIGH/CRIT)
                                              │    → auto-verify (stronger LLM)
                                              │       ├─ CONFIRMED → append
                                              │       ├─ UNCONFIRMED → append w/ note
                                              │       └─ REFUTED → BLOCK + inject refutation
                                              ├─ (if shell/python/http + strict mode)
                                              │    → egress check → block off-allowlist
                                              └─ dispatch
```

## First brick: verifier (commit `4069e35`)

`src/vxis/agent/tools/verifier_tools.py` exposes a single tool
`verify_finding`. It reuses the Brain's LLM fallback chain but swaps
the model to `gpt-5.4` (the full, not mini) for the refutation call.

The prompt was deliberately adversarial: "default stance — this is a
false positive until proven real". This turned out to be *too*
adversarial in the first benchmark: 9/9 verifications returned
UNCONFIRMED. Nothing ever confirmed, nothing ever refuted. Belief state
was flat.

## Rebalance: rubric-driven verdicts (commit `ccbecaa`)

The new prompt uses an ordered decision rubric — REFUTED first
(clearest signal), then CONFIRMED (concrete evidence), UNCONFIRMED last
(genuine ambiguity only). Explicit CONFIRMED triggers: real
credentials, stack traces with internal paths, IDOR response bodies,
SQL errors.

Unit smoke test (mocked brain) now passes all three verdict paths:

```
T1: CONFIRMED - high   (AWS keys in /.env body)
T2: REFUTED   - high   (size 8968 == SPA baseline)
T3: UNCONFIRMED - med  (HTTP 500 with empty body)
```

## Auto-verify enforcement in scan_loop

The Brain was told via prompt adapter that verification was MANDATORY
for HIGH/CRITICAL findings. It ignored the instruction. Fix: intercept
`report_finding` at the scan_loop dispatch boundary. If severity is
high/critical and `verify_finding` is in the registry, run it first.
If verdict is REFUTED, block the original report_finding and feed the
refutation reasoning back to the Brain.

This is **code enforcement beats prompt enforcement** — a Phase C
recurring theme.

## Belief state (commit `ccbecaa`)

`ScanLoopState` now carries:

- `verdict_counts: dict[str, int]` — CONFIRMED/UNCONFIRMED/REFUTED tallies
- `confirmed_findings: list[dict]` — verdict + reasoning metadata
- `refuted_findings: list[dict]` — same, for post-scan analysis

`ScanPipelineV2` surfaces these on `ctx.verdict_counts`,
`ctx.confirmed_findings`, `ctx.refuted_findings` and prints a
`VXIS_BELIEF` benchmark line for operators.

Downstream work will reason over `ctx.confirmed_findings` — e.g. a
report severity escalator that upgrades to "Verified Critical" only
when the confirmed set contains the finding.

## Egress filter (this chapter)

`src/vxis/agent/egress.py` exposes three functions:

- `build_allowlist(target_url)` — target host + `VXIS_EGRESS_ALLOWLIST` env
- `extract_hosts(blob)` — pull hostnames from shell/python command text
- `check_violations(blob, allowlist)` — returns off-allowlist hosts

Enabled only when `VXIS_EGRESS_STRICT=1`. Private/loopback hosts (RFC1918,
127/8, 169.254/16) always pass — lab runs never trip. The scan_loop
checks `shell_exec`, `python_exec`, and any `http_*` tool before
dispatch; violations are blocked with an `EGRESS BLOCKED` message fed
back to the Brain.

Smoke test:

```
allowlist = {target.local}
curl http://evil.com/x → violation: [evil.com]
curl http://target.local:3000/api → ok
curl http://127.0.0.1/x → ok (loopback)
nmap 192.168.1.1 → ok (rfc1918)
```

## Benchmark results (pending live run)

The last live benchmark (pre-rebalance) showed:

```
brain_decision_count=15, findings=4
verify_finding calls: 9, verdicts: 9 UNCONFIRMED / 0 CONFIRMED / 0 REFUTED
MITRE: 7 tech / 5 tactic / 43.8%
```

After the rubric rebalance we expect the split to diversify —
CONFIRMED on real shell exposures and REFUTED on the 4 `/api` 500
false-positives. A proper re-run is deferred until the Phase C2 work
(enterprise belief-backed reporting) lands.

## What Phase C still owes

- **Vector memory** — JSON KB works but won't scale. Next brick is an
  embedding index over `confirmed_findings` per target stack.
- **Report integration** — the NCC HTML report doesn't yet surface the
  CONFIRMED/REFUTED split. Findings should be segregated in the
  executive summary.
- **Structured belief prompt** — the loop adapter should remind the
  Brain which of its prior claims were refuted so it doesn't re-assert
  them. Currently the refutation is visible only in tool history.

## Files touched this chapter

- `src/vxis/agent/tools/verifier_tools.py` — rebalanced rubric
- `src/vxis/agent/scan_loop.py` — auto-verify interception, belief
  tracking, egress filter gate
- `src/vxis/agent/egress.py` — new, enterprise egress guardrail
- `src/vxis/agent/tools/mitre_data.py` — new, 16 curated techniques
- `src/vxis/agent/tools/fingerprint_tools.py` — weighted signals + stack expansion
- `src/vxis/agent/brain.py` — 1M context flag, MANDATORY verify adapter
- `src/vxis/pipeline/scan_pipeline_v2.py` — VXIS_BELIEF, MITRE_COVERAGE
  benchmark lines, belief state on ctx
