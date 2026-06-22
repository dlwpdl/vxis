# VXIS Core Flow And Context Review - 2026-06-19

This document describes what VXIS does today when an operator picks a target,
runs an AI-guided lab/aggressive scan, and watches it through the TUI. It also
marks what should remain in the core product and what should be removed or
collapsed because it adds context load without improving attack quality.

## 1. Current Operator Flow

Command shape:

```bash
vxis scan <target> --profile aggressive --allow-inject --box black
```

For a lab target, `aggressive` is the current closest profile. It maps to:

- exploitation ceiling: `full`
- scope strictness: `lab-allowlist`
- tenant isolation: off
- secret handling: `plaintext-lab`
- evasion: allowed
- deferred mutation approval: off

The single-target CLI path currently does this:

1. Normalize the profile name.
2. Load optional operator instructions from `--instruction` or `--instruction-file`.
3. Set per-run env values such as `VXIS_SCAN_PROFILE`, `VXIS_SCAN_INSTRUCTIONS`,
   and `VXIS_CLIENT_ID`.
4. Run preflight:
   - target reachability
   - Brain backend availability
   - Docker availability
   - GitHub token state
   - Ghost proxy pool if Ghost is enabled
5. Create the display object.
6. Activate a fail-closed runtime scope for the target.
7. Decide display mode:
   - Textual TUI if `--tui`, stdout is a TTY, Textual is installed, and the
     scan is not `--interactive`
   - otherwise classic Rich Live display
8. Build `ScanPipeline`.
9. Run `ScanPipeline.run()`.
10. Print final findings, aggregate target memory, score, benchmark counters,
    LLM usage, and report path.

## 2. Current Pipeline Flow

`ScanPipelineV2.run()` is now the active scan path. Its practical flow:

1. `prepare_target_runtime(target, kind, hints)` resolves the target runtime.
2. `ensure_active_scope(runtime.resolved_target)` installs scope enforcement.
3. Build `ScanContext` with target, kind, scan id, and app context.
4. Resolve scan policy from profile and publish it as ambient runtime policy.
5. Resolve the one-shot injection decision:
   - known local benchmarks or `--allow-inject`: `full`
   - classic Rich display: prompt user for `full`, `readonly`, or `deny`
   - Textual TUI: fail-safe to `readonly` because blocking console prompts do
     not work inside the TUI app
6. Activate Ghost if requested and allowed by policy.
7. Reset per-scan state:
   - finding store
   - finding event callback
   - Brain counters
   - LLM usage stats
   - playbook dedup cache
8. Patch the target kind into Brain.
9. Resolve box mode:
   - `black`: no source-aware tools
   - `white`: source-aware allowed where applicable
   - `grey`: mixed dynamic/source-aware behavior
   - `auto`: derive from target kind
10. Build the default Brain tool registry.
11. Emit the compatibility `scan_loop` display event.
12. Create `ScanAgentLoop`.
13. Seed the loop from target memory and local retrospectives.
14. Run the loop.
15. Cleanup tool registry, browser, proxy runtime, Ghost, and callbacks.
16. Copy loop state back to `ScanContext`:
   - findings
   - verdict counts
   - confirmed/refuted findings
   - vector candidates
   - attempt outcomes
   - todos
   - branches
   - shared notes
   - sandbox invocations
   - peak context bytes
   - final report sections
17. Generate report if enabled.
18. Emit benchmark counters.

## 3. Current Attack/Test Loop

The live core is `ScanAgentLoop.run()`. It is a ReAct loop with one action per
Brain response.

Per iteration:

1. Sample current message/context size.
2. Compress stored history if the provider-specific threshold is exceeded.
3. Build a compact scan dashboard from durable state.
4. Build a tool catalog from `ToolRegistry.describe_all()`.
5. Ask `AgentBrain.think_in_loop()` for the next action.
6. Enforce one action only.
7. Validate the tool args.
8. Pass the action through gates:
   - P1 engagement gate
   - scope gate
   - exploitation ceiling
   - injection approval
   - Ghost/direct-egress policy
9. Execute the tool.
10. Record result into message history.
11. Update vector candidates, branches, todos, attempts, agent graph, and review queue.
12. Promote strong skill results into findings when evidence is sufficient.
13. Verify findings where needed.
14. Emit display/control-plane events.
15. Run finish gates if Brain attempted `finish_scan`.
16. Continue until finish succeeds, max iterations are exhausted, or hard budget is hit.

The important product shape is not "20 phases". The important product shape is:

```text
target -> scope/policy -> director decision -> one tool -> evidence -> verifier
       -> branch/todo update -> compact dashboard -> next decision -> report
```

That is the core app.

## 4. What The Tools Actually Do

Core tool families that matter:

- browser tools: navigate, snapshot, click/fill/submit, cookies/session state
- sandbox tools: `shell_exec`, `python_exec`, nmap, target-facing command work
- skill tools: bounded templates for recurring attack patterns
- finding tools: report/query findings and link chains
- verifier tools: challenge weak findings
- memory tools: load target memory and write scan memory
- agent graph: delegated worker turns with bounded context
- control tools: `finish_scan`, wait/think/self-critique style controls

For lab/aggressive mode, the sandbox becomes central. `shell_exec` starts or
reuses a per-scan sandbox runtime, executes commands with timeouts, truncates
stdout/stderr before putting results back into context, and includes Ghost
metadata. This is correct directionally: raw terminal output must never be
dumped unbounded into the Brain.

## 5. Current Safety Gates

The registry is the choke point for Brain actions. Before a tool runs, it checks:

- schema/arg validity
- P1 engagement scope
- ambient target scope
- exploitation ceiling
- one-shot injection decision

Then tool-level policies may also apply, such as Ghost egress checks for shell
and Python execution.

This is the right architecture. The weak point is not the idea of gates; it is
that too many code paths, legacy tools, and duplicate displays increase the
chance that a path bypasses the clean choke point.

## 6. TUI Behavior Today

There are three display concepts in the codebase:

1. `cli/scan_display.py`
   - The classic Rich Live display used by normal non-Textual scans.
   - Shows target, profile, Brain, Ghost, current loop state, attack feed,
     hit feed, findings count, branches, todos, agents, SDK runtime, proxy,
     Ghost, egress contract, telemetry, and errors.

2. `cli/scan_tui.py`
   - Textual interactive TUI.
   - Shows a navigable tree:
     - root scan
     - Director iterations
     - delegated agents
   - Selecting an iteration shows raw event detail.
   - Status bar shows cost, box, injection mode, Ghost, context budget,
     Brain decisions, and findings.
   - It owns the terminal, so injection approval is forced to read-only instead
     of prompting mid-scan.

3. Legacy snapshot Rich display
   - Older plugin/snapshot state still exists for non-agent compatibility.
   - It is now rendered by `cli/scan_display.py::SnapshotLiveDisplay`; the
     separate `cli/live_display.py` module was removed on 2026-06-19.

Core-app direction: keep one display model and one rendering path. The model
should be event-sourced and compact:

- left: iteration/branch/agent tree
- center/right: selected item detail
- bottom: scope, policy, injection mode, context usage, LLM cost, findings
- top: target, profile, elapsed, current objective

Do not maintain two live displays that interpret events differently.

## 7. Context Handling Today

There are several context controls:

- `memory_compressor.py` compresses old stored messages once message history
  crosses the model policy threshold.
- `AgentBrain.think_in_loop()` builds smart 3-tier history:
  - recent iterations: fuller detail
  - older iterations: compact summaries
  - pinned high-value messages: findings, verifier output, dashboard, system hints
- `context_budget.py` sets role budgets:
  - frontier director ceiling: 300k tokens
  - frontier worker ceiling: 32k
  - verifier ceiling: 24k
  - summarizer ceiling: 12k
  - local profiles are much smaller
- tool results are compacted/truncated before entering prompts in many paths.

Cloud compression now uses a 200k-token operating segment by default
(`VXIS_CONTEXT_SEGMENT_TOKENS`) instead of waiting until a 1M-token model is
nearly full. The user-facing goal is not "fill 1M". The goal is "keep the
active director prompt small, stable, and unambiguous".

Recommended context policy:

- Treat 200k tokens as a hard operating segment, not a target to fill.
- Director prompt target: 60k-120k for normal work, emergency cap at 200k.
- Worker prompt target: 8k-32k.
- Verifier prompt target: 8k-24k.
- Summarizer prompt target: 4k-12k.
- Compress every segment boundary into terse bullets, not free prose.
- Keep raw evidence outside LLM context as artifacts with ids.
- Put only evidence summaries, hashes, paths, and replay commands into prompt.
- Show context budget in the TUI status bar every iteration.

The remaining issue is not the default cloud threshold; that is now segmented.
The remaining issue is that director, worker, verifier, report, and TUI should
share one explicit context contract instead of separately enforcing related
limits across several modules.

## 8. Strix Comparison

What VXIS copied or moved toward:

- single-loop Brain-first scanning instead of fixed helper-style phases
- one tool/action per Brain message
- director/worker split
- persistent worker/agent graph state
- bounded worker turns
- evidence challenge branches for weak positive claims
- memory compression pattern
- TUI/control-plane visibility for agents, branches, Ghost, egress, and runtime

Where VXIS still differs or is weaker:

- Strix-style child workers should be durable sessions with their own journals;
  VXIS still has a partially delegated agent graph and optional SDK child runtime.
- VXIS still carries legacy 63-agent code and old phase-era concepts.
- VXIS has duplicate display models, although `scan_tui.py` is now the
  canonical clickable tree TUI for normal terminal scans.
- Finding/chains state and `run_skill` cache are now scoped to the active scan
  or tool instance, not process-global state.
- VXIS has very large mixed-responsibility scan-loop classes.
- VXIS context compaction exists, but is not enforced as one simple product
  contract across director, worker, verifier, report, and TUI.

The right direction is not "more agents" or "more phases". It is fewer public
concepts with stronger state, evidence, and context discipline.

## 9. Slop To Remove Or Collapse

High priority:

1. Remove or quarantine legacy 63-agent fleet from the production mental model.
   Keep it only if tests and entrypoints prove active value.

2. Collapse display paths:
   - `scan_display.py`
   - `scan_tui.py`
   - resolved 2026-06-19: `live_display.py` removed; snapshot compatibility
     renderer lives in `scan_display.py`.

3. Split `scan_loop_*` god mixins by product state:
   - decision
   - execution
   - evidence
   - branches
   - dashboard
   - finish gates

4. Replace "phase" language in the live product with loop/branch language.
   Historical docs can stay historical, but product UI should not pretend the
   current system is phase-based.

5. Treat all generated `.vxis` runtime logs/caches as runtime artifacts unless
   explicitly promoted to curated fixtures.

6. Stop exposing scaffold profiles/modules as production capabilities until they
   execute end-to-end and have real execution tests.

## 10. Proposed Core App

The core app should have these public concepts only:

1. Target
   - URL/domain/app/package/repo
   - kind: web/desktop/mobile/game/code
   - scope
   - credentials/instructions

2. Policy
   - profile
   - box mode
   - injection mode
   - destructive approval
   - egress/Ghost mode

3. Brain Runtime
   - director model
   - worker model
   - verifier model
   - summarizer model
   - context budget contract

4. State
   - branches
   - todos
   - attempts
   - findings
   - evidence artifacts
   - verifier verdicts
   - chains

5. Tools
   - browser
   - sandbox
   - skills
   - verifier
   - memory
   - report

6. TUI
   - one event model
   - one tree/detail UI
   - one context/cost/scope status bar

7. Report
   - accepted findings only
   - evidence artifact references
   - replay commands
   - verifier verdicts
   - chain proof

## 11. Ideal Lab Scan Step-By-Step

1. Operator enters target and chooses `lab/aggressive`.
2. VXIS normalizes the target and shows exact scope.
3. VXIS checks target reachability, Brain backend, Docker/sandbox, proxy/Ghost,
   and required optional dependencies.
4. VXIS shows the effective policy:
   - full exploitation allowed
   - lab allowlist scope
   - raw secrets allowed only because lab
   - no deferred mutation approval
5. VXIS starts the TUI.
6. VXIS creates a scan id and per-scan stores.
7. VXIS creates the sandbox and browser/session managers lazily.
8. Director receives only:
   - target
   - scope/policy
   - compact dashboard
   - active branches/todos
   - available tools
   - last few results
   - pinned findings/verifier outputs
9. Director selects one tool.
10. Registry gates the tool.
11. Tool executes and emits a compact result plus artifact ids.
12. Evidence processor decides whether the result is:
   - noise
   - lead
   - finding candidate
   - confirmed finding
   - chain pivot
13. Verifier challenges high-impact claims.
14. Branch manager updates next objective.
15. TUI updates the selected branch/iteration tree.
16. Context manager compacts after budget threshold and stores a structured
   state summary.
17. Finish gate rejects completion while high-value untested branches remain.
18. On successful finish, report writer emits only verified/accepted findings and
   references to evidence artifacts.

## 12. Non-Negotiable Build Rule

Do not wire placeholders into CLI, MCP, dashboard, registry, or report paths.
Features become public only after:

1. implementation exists,
2. execution path works,
3. there is at least one test that calls the feature, not just lists it,
4. TUI/report behavior is defined or intentionally hidden.
