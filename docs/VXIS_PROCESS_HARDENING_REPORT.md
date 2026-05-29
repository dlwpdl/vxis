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
10. Positive claims are challenged before they can settle work: the system now asks for control, repeat reproduction, negative/refutation, source-output reuse, and crown-jewel evidence.

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
- `nmap_scan`: explicitly reports `direct_raw_socket` because HTTP/SOCKS env proxy does not anonymize raw TCP/UDP scanning. When Ghost is active, this path is blocked unless `VXIS_ALLOW_DIRECT_EGRESS=1` is set.

### Ghost Egress Enforcement

Visibility now has an execution guard behind it:

- `nmap_scan` is blocked during Ghost mode by default.
- `shell_exec` blocks known raw egress tools during Ghost mode, including `nmap`, `masscan`, `hping`, `nping`, `nc`/`ncat`, `socat`, `dig`, `nslookup`, `ping`, `traceroute`, and `telnet`.
- `python_exec` blocks Python code that imports or calls raw socket/subprocess paths during Ghost mode.
- Explicit opt-in is available with `VXIS_ALLOW_DIRECT_EGRESS=1`.

Proxy-aware HTTP tools remain allowed because they can use `GhostTransport`, browser proxy/UA routing, or injected proxy env.

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
- Worker EvidenceArtifacts now preserve `repeat_count`, `negative_control`, `source_output`, `source_output_used_in_pivot`, and `crown_jewel_evidence` so the director can challenge the proof instead of trusting a positive summary.
- If a worker says it found something but those challenge fields are absent, VXIS queues a `CHALLENGE-WORKER` branch and forces the pentest loop back through control, repeat, refutation, pivot proof, crown impact, and report.

This is still not identical to Strix independent child sessions, but it is no longer "one person pretending to be many" in the weak sense. VXIS now has durable worker state, explicit message history, bounded child turns, and director-visible results.

### Recursive Evidence Challenge Loop

VXIS now treats weak positive claims as new work, not as finished work:

- weak high/critical PoCs create `CHALLENGE-POC` branches
- weak chain proofs create `CHALLENGE-CHAIN` branches
- `verify_finding=UNCONFIRMED` creates `CHALLENGE-VERIFY` branches
- positive worker results with missing challenge fields create `CHALLENGE-WORKER` branches

The branch objective restarts the same core loop: hypothesis -> execute -> evidence -> refute -> reproduce -> pivot/chain -> crown impact -> report. This is the guard that prevents "looks found" from becoming a report or a settled branch without the follow-up work.

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
- Ghost active mode blocks direct/raw egress unless `VXIS_ALLOW_DIRECT_EGRESS=1`
- `run_skill` registered skills must pass static egress audit
- high/critical `report_finding` calls require a replayable PoC transcript with an exploit attempt, observed result, control/baseline, `repeat_count>=2`, and negative/refutation evidence
- escaped LLM transcript newlines are normalized before PoC evaluation, without accepting request-only evidence
- high-value `link_chain` calls require `VerifiedChainArtifact` evidence: source output, pivot action, observed result, control result, `repeat_count>=2`, negative/refutation result, source-output reuse, and crown-jewel evidence
- narrative-only chains can be stored, but they no longer settle branches as proven
- auto-linking must pass the same chain artifact gate before closing parent/child branches, and only marks source-output reuse when source evidence is actually present in the pivot/target context
- multi-hop chains require hop evidence for every adjacent finding pair
- recursive gap branches are generated for weak PoC, weak chain proof, unconfirmed verifier output, and under-challenged worker positives
- raw `httpx` remains globally confined by the existing AST guard
- repeated/stalled execution has monitor pressure
- agent graph runtime state persists
- restored agents are shown in control-plane/TUI

Latest local verification for this report:

- `uv run ruff check src tests`
- `uv run pytest -q` -> `2109 passed, 4 skipped`

## Remaining Gaps

1. Sandbox egress is not OS-enforced yet.

   `shell_exec` and `python_exec` now block common raw egress patterns during Ghost mode, but this is still process-level policy, not container network enforcement.

2. `nmap_scan` is intentionally direct.

   It is blocked during Ghost mode unless direct egress is explicitly allowed. In normal pentest mode, it remains useful for service discovery.

3. Browser Ghost depends on proxy availability.

   If Ghost is active but no exit proxy exists, browser tools can use capture proxy + Ghost user-agent, but that is not a true anonymity exit.

4. `agent_graph` is still delegated, not a full per-agent persistent SDK session for every worker.

   VXIS has durable worker state and SDK child runtime support, but the next quality jump is making every serious worker a resumable session with inbox/tool/result journal.

5. Context compaction still needs stronger enforcement for all prompts.

   Worker prompts have bounds, but the whole director/worker/report path needs consistent context-budget assertions.

## Recommended Next Steps

1. Promote serious workers to durable child sessions.

   Keep the current `agent_graph` interface, but back long-running workers with per-agent event journals and resumable sessions.

2. Add context-budget report to control plane.

   Show director prompt size, worker prompt size, memory compression count, and truncation reasons in one place.

3. Add richer chain replay executors.

   `VerifiedChainArtifact` now blocks weak chain narratives, but the next step is having workers actively replay each hop rather than deriving chain proof from already reported PoC transcripts.

4. Shift the next workstream to pentest depth.

   Prioritize better attack-surface expansion, PoC verification, false-positive controls, and crown-jewel chain progression over more anonymity features.
