# VXIS Process Hardening Report

Date: 2026-05-29

## Summary

This report explains how the recent hardening work affects the VXIS scan process end to end. The main direction is not adding many features. The goal is to make every deep-scan step explicit, recoverable, observable, and bounded so the director can keep pushing toward verified crown-jewel impact without hidden execution gaps.

## Current End-to-End Flow

1. CLI starts `ScanPipelineV2`.
2. `ScanPipelineV2` activates Ghost when the mission asks for `ghost://`, stealth, or proxy-backed anonymous mode.
3. The pipeline enters `ScanAgentLoop`.
4. The director receives the tool catalog from `ToolRegistry.describe_all()`.
5. Each tool catalog entry now includes `target_egress`, so the director sees whether a tool is `ghost_transport`, `browser_proxy_or_ua`, `env_proxy`, `direct_raw_socket`, `delegated`, `offline`, or `llm_api`.
6. The director creates/updates branches and delegates bounded work through `agent_graph`.
7. Worker turns execute through deterministic guardrails and local-worker planning where configured.
8. Findings must carry evidence, can be verifier-checked, and can be chained through `link_chain`.
9. Control-plane/TUI receives runtime state for Ghost, egress, agents, SDK runtime, proxy, todos, branches, and chain candidates.

## What Changed In Practice

### Ghost Routing

Ghost is now a runtime path, not only a trigger flag.

- `TargetSession`/`SessionManager`: in-process HTTP uses `GhostTransport` when Ghost is active.
- `http_request`: uses the shared `SessionManager` path and reports `_egress`/Ghost metadata.
- `fingerprint_target`: also routes through `SessionManager`, so it inherits `GhostTransport`.
- `browser_navigate`: uses Ghost proxy and user-agent when available.
- `browser_render`: legacy browser path now also receives Ghost proxy and user-agent.
- `shell_exec`: injects `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and lower-case equivalents into sandbox commands.
- `python_exec`: injects the same proxy env into one-shot scripts and persistent Python REPL sessions.
- `nmap_scan`: explicitly reports `direct_raw_socket` because HTTP/SOCKS env proxy does not anonymize raw TCP/UDP scanning.

### Egress Contract

Every default tool now has a target-facing egress contract in `vxis.agent.egress_contract`.

Important classifications:

- `http_request`, `fingerprint_target`: `ghost_transport`, covered.
- `browser_navigate`, browser interaction tools, `browser_render`: `browser_proxy_or_ua`, covered.
- `shell_exec`, `python_exec`: `env_proxy`, partial. Child code can still open raw sockets.
- `nmap_scan`: `direct_raw_socket`, not covered.
- `run_skill`, `agent_graph`: delegated. They must inherit or enforce coverage internally.
- finding/query/control/playbook/memory tools: offline.
- `verify_finding`: `llm_api`, not target-facing.

This contract is included in the director tool catalog and control-plane snapshot. Tests fail if a default tool is registered without a contract.

### run_skill Hardening

`run_skill` was the biggest delegated gap. It now has a static audit harness.

The audit rejects raw egress patterns in skill code:

- `httpx`
- `requests`
- `urllib.request.urlopen`
- `socket` DNS/socket calls
- `asyncio.create_subprocess_exec`
- non-desktop `subprocess` calls

Allowed paths:

- Web skills should use `SessionManager` / `TargetSession`.
- Desktop skills may use local `subprocess.run` for local binary/static inspection only.

`test_infra` previously used raw `socket.gethostbyname` for subdomain DNS checks. That was changed to HTTP probing through `SessionManager`, so it inherits Ghost/SessionManager behavior instead of bypassing the egress layer.

`run_skill` now blocks execution if its registered skill fails the static egress audit. Successful skill results include `_egress` metadata.

### Agent Graph And Chaining

Recent work moved VXIS closer to the Strix-style director/worker loop:

- Agent graph runtime persists worker nodes, messages, and executions.
- Restored agents are surfaced in the control plane after process restart.
- SDK child runtime state is attached to worker drilldown where available.
- Worker execution is bounded by role, envelope, allowed tools, and action validation.
- Director can observe child results and continue chaining based on returned evidence.

This is still not identical to Strix independent child sessions, but it is no longer "one person pretending to be many" in the weak sense. VXIS now has durable worker state, explicit message history, bounded child turns, and director-visible results.

### TUI / Control Plane

The TUI now exposes more of the real runtime state:

- restored agents
- SDK runtime events
- Ghost state and coverage
- egress risk counts
- direct/partial/delegated warnings
- proxy state and recent requests
- branch/todo/chain state

This matters because deep scans fail when the operator cannot see which worker is stuck, which tool is direct-egress, or whether Ghost is only partially applied.

## Quality Gates Now In Place

The current gates protect these boundaries:

- default registry tools must have egress contracts
- tool catalog includes egress metadata for director/worker prompts
- Ghost routing metadata is visible in tool results and control-plane state
- `run_skill` registered skills must pass static egress audit
- raw `httpx` remains globally confined by the existing AST guard
- repeated/stalled execution has monitor pressure
- agent graph runtime state persists
- restored agents are shown in control-plane/TUI

Latest local verification for this report:

- `uv run ruff check src tests`
- `uv run pytest -q` -> `2095 passed, 4 skipped`

## Remaining Gaps

1. Sandbox egress is not OS-enforced yet.

   `shell_exec` and `python_exec` receive proxy env, but a command can still use raw sockets or tools that ignore proxy env. This is why their contract is `partial`.

2. `nmap_scan` is intentionally direct.

   This is accurate and transparent, but not anonymous. If Ghost anonymity is mandatory, director policy should avoid nmap or require explicit operator opt-in.

3. Browser Ghost depends on proxy availability.

   If Ghost is active but no exit proxy exists, browser tools can use capture proxy + Ghost user-agent, but that is not a true anonymity exit.

4. `agent_graph` is still delegated, not a full per-agent persistent SDK session for every worker.

   VXIS has durable worker state and SDK child runtime support, but the next quality jump is making every serious worker a resumable session with inbox/tool/result journal.

5. Context compaction still needs stronger enforcement for all prompts.

   Worker prompts have bounds, but the whole director/worker/report path needs consistent context-budget assertions.

## Recommended Next Steps

1. Add sandbox-side egress enforcement.

   Use container network policy or wrapper-level restrictions so `shell_exec`/`python_exec` cannot silently bypass proxy policy when Ghost is required.

2. Add director policy for direct-egress tools.

   If Ghost is active, `nmap_scan` should require explicit rationale or be blocked unless the mission allows direct raw socket scanning.

3. Promote serious workers to durable child sessions.

   Keep the current `agent_graph` interface, but back long-running workers with per-agent event journals and resumable sessions.

4. Add context-budget report to control plane.

   Show director prompt size, worker prompt size, memory compression count, and truncation reasons in one place.

5. Add a golden end-to-end scan fixture.

   The test should assert: director sees egress contracts, creates worker, worker uses covered tool, evidence returns, director links chain, report includes verified finding.
