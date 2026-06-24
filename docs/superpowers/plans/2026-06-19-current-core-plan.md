# VXIS Current Core Plan - 2026-06-23

## Goal

Keep VXIS as a lean autonomous validation helper: authorized system in,
Brain-controlled web black-box runtime loop, accepted evidence out. Prioritize
researcher assistance, verifier-backed findings, related-impact depth, and
professional bilingual reporting over broad Strix clone behavior.

## Live Architecture

- Runtime entrypoint: `ScanPipelineV2`
- Loop owner: `ScanAgentLoop`
- Brain path: `AgentBrain.think_in_loop()`
- Tools: `ToolRegistry` BrainTools only
- Findings: per-scan `FindingStore`, `report_finding`, `verify_finding`,
  `link_chain`
- Profiles: `crown` for deep related-impact validation, `bugbounty` for concise
  replayable PoC artifacts
- Reports: NCC-style HTML plus `--format bugbounty` accepted-finding JSON
- Cost: Anthropic director calls mark the stable system prompt cacheable
- MCP: working primitive and scan tools only; no deleted phase wrappers
- Development boundary: incomplete feature work lives under top-level
  `incubator/` until it is complete, tested, and intentionally moved into
  `src/vxis`.

## Strix Comparison

- Borrow: sandbox-first execution, compact artifacts, resumable state, skill
  loading, source-aware scan UX, and CI-friendly output.
- VXIS difference: stricter policy/scope gates, verifier-backed acceptance,
  replayable high/critical evidence contract, related-evidence scoring pressure,
  bilingual NCC-style reporting.
- Avoid: broad public parity, specialist-agent fleets, source/mobile/game
  placeholders, and docs that imply runtime support before tools are promoted.

## Immediate Priorities

1. Keep prompt caching working before adding parallel runtime complexity.
2. Implement the deterministic replay gate spec:
   `docs/superpowers/specs/2026-06-24-deterministic-replay-gate.md`.
3. Capture one trigger benchmark where cached single-loop plateaus before
   promoting any SDK worker substrate.
4. Keep `incubator/sdk_runtime` worker-only; never move the director onto SDK.
5. Generate vector candidates from discovered routes, forms, params, and tech.
6. Refuse `finish_scan` when high-value candidates are unattempted or related
   evidence is missing for multi-finding scans.
7. Keep source-aware work in `incubator/` until tools, gates, reports,
   benchmark targets, and regression tests are complete.

## Non-Goals

- No broad Strix clone rewrite.
- No OpenAI Agents SDK migration for its own sake.
- No public white/grey-box claim until source-aware Brain tools are production
  wired and exercised through the live scan loop.
- No mobile/game/hardware runtime commands until execution tests pass.
- No placeholder MCP/CLI/dashboard links.
- No empty/import-only tests or tests that preserve placeholder stubs as product
  behavior.

## Success Gates

- `uv run ruff check src/vxis tests`
- `uv run pytest -q`
- high/critical findings without replayable evidence are rejected
- bug bounty export includes accepted findings only
- public registries expose no incubator/source/mobile/game runtime placeholders
- docs point to this plan plus `docs/superpowers/DECISIONS.md` as the current
  source of truth
