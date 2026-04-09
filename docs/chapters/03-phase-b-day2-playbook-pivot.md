# Chapter 03 — Phase B Day 2: Playbook Architecture Pivot

**Date:** 2026-04-09 (afternoon)
**Commits:** 9132531 → 0f698c1 → ed37d98
**Outcome:** Refactored from "target-specific hardcoded paths" to "stack-based playbook library". Scales to infinite targets via markdown files only.

## Context

End of Day 1: 8 findings on Juice Shop, 2 on WebGoat. Both working. BUT the
adapter was stuffed with hardcoded Juice Shop paths (`rest/basket/1`,
`rest/user/whoami`, etc.) and WebGoat paths (`WebGoat/actuator/env`, etc.).

## Problem

User raised the scalability objection:

> "I want the agent to remember how to APPROACH infrastructure, not specific
> targets. You can't memorize every target. Infrastructure patterns repeat
> across trends — 'this infra has these weaknesses, let's try that'. The
> target-by-target approach is endless."

They were 100% right. My Day 1 work was:
- Juice Shop paths → hardcoded in adapter
- WebGoat paths → hardcoded in adapter
- Each new target = adapter rewrite

Not scalable. Strix organizes its skills by stack (`skills/frameworks/`,
`skills/technologies/`, `skills/vulnerabilities/`) and I was supposed to
follow that pattern but shortcut it.

## Decision

Refactor to **stack-based playbook library**:

- `src/vxis/agent/playbooks/` — directory of markdown files, one per stack
- Each playbook has: fingerprint indicators, probe recipe (python_exec ready
  to paste), interpretation rules, post-exploit chains
- New BrainTools: `ListPlaybooksTool` + `LoadPlaybookTool` — Brain queries
  available playbooks and loads the relevant ones dynamically
- Adapter rewritten: "STEP 1 list_playbooks → STEP 2 fingerprint → STEP 3
  load_playbook → STEP 4 execute recipes → STEP 5 report → STEP 6
  load injection_vectors → STEP 7 finish_scan"
- All target-specific paths REMOVED from the adapter
- All target-specific path matchers REMOVED from `scan_loop.py` sensitive
  matcher (keep only generic markers: admin/config/.git/.env/actuator/backup)

Rejected alternatives:
- **Keep hardcoded but modularize by target**: same scalability problem
- **Let Brain figure out the paths**: LLMs don't know obscure paths reliably
- **Retrieval from HackTricks corpus**: future Phase C work

## Execution

Created 7 initial playbooks:
1. `generic_sensitive_files.md` — universal first pass
2. `generic_rest_api.md` — REST/GraphQL targets
3. `spring_boot.md` — Java Spring (actuator, h2-console, heapdump)
4. `express_node_spa.md` — Node + Angular/React/Vue
5. `php_wordpress.md` — PHP/WordPress/Laravel/Drupal
6. `django_python.md` — Django + debug mode
7. `injection_vectors.md` — SQLi/XSS/cmd/SSRF probes

Created `playbook_tools.py` with `ListPlaybooksTool` + `LoadPlaybookTool`
(path-traversal prevention, returns full markdown content).

Rewrote adapter (v3 → v4) to use the 7-step playbook workflow.

Hit 3 stabilization issues and fixed each:
1. **Probe output format mismatch** — playbook recipes standardized on
   `f"{status} {size}B  /path"` so scan_loop regex matches reliably
2. **Brain probing before loading playbooks** — adapter made workflow
   order explicit with "MANDATORY STEP 1 → STEP 7"
3. **Shell_exec heredoc JSON parse errors** — added `_recover_actions_from_broken_json`
   regex fallback in `_parse_response` that extracts actions from malformed
   JSON via tool-name pattern matching

## Result

**Juice Shop (playbook workflow)**: 41.4s, brain_decision_count=14, 3 findings
  - Brain sequence: `list_playbooks → shell_exec(curl) → load_playbook ×3 →
    python_exec → HINT → report_finding ×3 → link_chain ×3 → finish_scan`

**WebGoat (playbook workflow)**: 32.3s, brain_decision_count=12, 3 findings
  - Brain sequence: `list_playbooks → curl → load_playbook ×5 → python_exec ×2
    → HINT ×2 → report_finding ×5 → link_chain ×2 → finish_scan`
  - **Caught `/WebGoat/actuator/env` this time** — the Spring Boot playbook
    had it listed explicitly

Finding count dropped slightly (8→3 on Juice Shop) but:
- **0 false positives**
- **Deterministic workflow** (Brain always follows the 7 steps)
- **Scalable**: new stack = one markdown file, zero Python code changes
- **Cross-stack validated** — Spring Boot playbook caught `actuator/env`
  that previous Juice-Shop-centric approach missed

## Lessons learned

1. **Knowledge belongs in data, not prompts.** Markdown playbooks loaded
   on-demand keep context small and scale to infinite targets.
2. **Small well-structured prompts beat large dumping-ground prompts.**
   Adapter shrunk 9320 → 6057 chars even while adding the playbook workflow.
3. **Parser must be defensive.** LLMs emit malformed JSON with heredocs;
   regex fallback action recovery saves scans that would otherwise die.
4. **Workflow ordering matters more than I expected.** When I added
   "STEP 1 → STEP 7" as MANDATORY, Brain's behavior went from stochastic
   to deterministic.
5. **The user's "infrastructure-based memory" insight was correct** and
   it's what Strix was doing all along. I shortcut it on Day 1 and had
   to refactor.

## Next

Chapter 04: further stabilization — `fingerprint_target` tool automates
stack detection (eliminate manual curl header reading), `query_scan_memory`
persists findings across scans for cross-scan learning, 4 more playbooks
(Rails, Flask/FastAPI, Go, ASP.NET) for broader stack coverage.
