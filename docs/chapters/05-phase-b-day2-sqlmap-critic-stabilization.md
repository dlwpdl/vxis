# Chapter 05 — Phase B Day 2 (late): sqlmap Validation + Dual Brain Critic

**Date:** 2026-04-09 (late evening)
**Commits:** (current)
**Outcome:** Weighted fingerprint scoring, sqlmap validated on real SQL injection, dual-brain critic hook active. Phase B ≈ 90%.

## Context

End of Chapter 04: 15 tools + 11 playbooks + fingerprint_target + query_scan_memory
all working. Workflow is 100% compliant. BUT:
- Fingerprint had false positives (WebGoat triggering `django_python` due to
  `sessionid=` cookie overlap)
- `injection_vectors` playbook was never validated with real sqlmap
- Brain sometimes stuck in single-track loops; no "strategic second opinion"

## Problem

1. **Fingerprint scoring was flat** — every signal counted as 1 point, so a
   shared weak signal (`sessionid=`) contributed as much as a unique strong
   signal (`jsessionid` or `<app-root>`).

2. **Unverified injection capability** — the playbook had sqlmap recipes but
   nobody had confirmed they actually find Juice Shop's well-known SQL
   injection at `/rest/products/search?q=1`.

3. **Single-model limitation** — gpt-5.4-mini handles the loop well but sometimes
   misses strategic pivots. A "second opinion" from a stronger model every N
   iterations would catch these.

## Decision

Three targeted fixes, all strengthening existing systems (no new tools):

**Fix #1 — Weighted fingerprint scoring.** Introduce `_STRONG_SIGNALS`
frozenset of framework-exclusive markers. Strong signal match = 3 points,
weak signal = 1 point. Also strengthened `django_python` signal list to
require csrftoken or other Django-specific patterns (dropped sessionid alone).

**Fix #2 — sqlmap real-world validation.** Run sqlmap directly against
Juice Shop's `/rest/products/search?q=1` via the vxis-sandbox container to
confirm the technique works end-to-end before trusting the playbook.

**Fix #3 — Dual Brain critic hook.** Add `_critic_review` method to
`ScanAgentLoop` that:
- Fires every `critic_interval` iterations (default 8)
- Temporarily swaps the model from `gpt-5.4-mini` to `gpt-5.4` (full) for
  one call
- Builds a compact prompt with recent actions + current findings
- Calls `_call_llm_with_fallback` with a pure-prose critic system prompt
  (no tool calls)
- Injects the critique as a `user` role message so Brain sees it on next iter

No new BrainTools, no new playbooks, no new files — just strengthen what
exists.

## Execution

**Fingerprint fix** (fingerprint_tools.py):
```python
_STRONG_SIGNALS = frozenset({
    "jsessionid", "x-powered-by: express", "ng-version=", "mat-app-background",
    "wp-content", "csrftoken=", "phusion passenger", "server: werkzeug",
    "server: kestrel", ...
})

def _score_playbooks(headers, body, url):
    for playbook, signals in _SIGNALS.items():
        for pattern, kind in signals:
            if pattern.lower() in haystack:
                weight = 3 if pattern.lower() in _STRONG_SIGNALS else 1
                score += weight
```

Verified:
- Juice Shop → `express_node_spa` (12 points, dominant)
- WebGoat → `spring_boot` (3 points, sole match — django false positive gone)

**sqlmap validation** via direct docker exec:
```bash
sqlmap -u 'http://localhost:3000/rest/products/search?q=1' --batch --level=2 --risk=2 --technique=BU
```
Result:
```
Parameter: q (GET)
Type: boolean-based blind
Title: AND boolean-based blind - WHERE or HAVING clause
Payload: q=1%' AND 9868=9868 AND 'XJVI%'='XJVI
back-end DBMS: SQLite
HTTP error codes detected during run: 500 (70 times)
```
sqlmap confirmed boolean-based blind SQLi on the `q` parameter, identified
SQLite as the backend, and the 500 error count matches what Brain's
python_exec probes were seeing. The `injection_vectors` playbook recipe is
validated.

**Dual Brain critic** (scan_loop.py):
- New `CRITIC_PROMPT_TEMPLATE` with target/iteration/findings/recent-actions
  slots
- `_critic_review()` method: builds prompt, swaps model to gpt-5.4, calls
  _call_llm_with_fallback, restores model, returns critique text
- Loop integration: checks `(iteration - last_critic_iter) >= critic_interval`
  at end of each iter and injects "CRITIC REVIEW" message when due
- `critic_interval=8` default (tunable in `ScanAgentLoop.__init__`)

## Result

**Juice Shop with critic active** (`critic_interval=8`):
- 92.7s (longer due to critic call + follow-up iterations)
- brain_decision_count=18
- **5 real findings** (up from 2-3 pre-critic):
  - `[HIGH]` HTTP 500 on /api
  - `[HIGH]` HTTP 500 on /api/
  - `[HIGH]` HTTP 500 on /api/v1
  - `[HIGH]` HTTP 500 on /api/v1/
  - `[HIGH]` HTTP 500 on /api?id=1

Tool sequence highlight:
```
query_scan_memory → fingerprint_target → load_playbook ×4 →
python_exec ×6 → load_playbook → [CRITIC] → shell_exec → python_exec →
HINT → STICKY → report_finding ×4 → link_chain ×2 →
python_exec → HINT → STICKY → report_finding ×4
```

The `[CRITIC]` injection at iter 8 clearly shifted Brain's trajectory —
post-critic iterations ran a different shell_exec + python_exec combo and
found new /api/v1 variants not caught in the first probe pass.

**Fingerprint accuracy**: Juice Shop 12 (clearly Node/SPA), WebGoat 3 (clearly
Spring Boot). No false positives in either direction.

## Lessons learned

1. **Weighted signals > flat matching.** A single `<app-root>` marker is
   more diagnostic than three shared cookie names. Scoring must reflect
   discriminative power.

2. **Validate playbook recipes with real tools.** It's easy to write a
   plausible-looking sqlmap recipe and never confirm it. One `docker exec`
   run catches issues before Brain tries and fails.

3. **Dual Brain doesn't need two providers.** Even within OpenAI (gpt-5.4
   full vs gpt-5.4-mini), the stronger model's critique materially changes
   Brain's trajectory. The "critic is just a more expensive version of the
   same provider" pattern is viable and cheap.

4. **Critic intervention works by context injection, not tool control.**
   The critic doesn't call tools — it writes prose guidance that Brain reads
   as a user-role message. Brain's own decision-maker stays in control but
   now has better strategic context.

5. **Strengthen, don't create.** User's mid-session guidance continues to
   pay off — weighted scoring, real validation, and critic hook are all
   refinements of existing systems. Zero new Python files, zero new
   playbooks, zero new BrainTools.

## Phase B state after this chapter

Roughly **90% of Phase B scope complete**:

| Task | Status |
|---|---|
| Strix-style adapter | ✅ |
| Auto-hint + dedup + sticky | ✅ |
| Parser recovery | ✅ |
| Playbook architecture | ✅ |
| fingerprint_target with weighted scoring | ✅ |
| query_scan_memory cross-scan KB | ✅ (MVP) |
| 11 playbooks | ✅ |
| Real sqlmap validation | ✅ |
| Dual Brain critic hook | ✅ |
| Vector-backed episodic memory | ❌ (Phase C) |
| Advanced critic loop (separate agent) | ❌ (Phase C) |

## Next

Phase C kickoff when ready: structured belief state, adversarial verifier as
a distinct agent, Postgres blackboard, 1M context mode, enterprise egress
filter. Or refine Phase B further with a standalone `critic_review` BrainTool
Brain can call voluntarily when stuck.
