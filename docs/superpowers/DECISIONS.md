# VXIS Decisions

## 2026-06-23 - Narrow/deep validation helper before Strix parity

Decision: VXIS v1 prioritizes authorized web black-box validation that helps a
researcher produce accepted finding evidence, related-impact context, and a
bilingual report or bug bounty export. Strix remains a benchmark for sandbox UX,
compact artifacts, source-aware scanning, and CI polish, but broad Strix parity
is lower priority than verifier-backed helpfulness and evidence quality.

Reason: VXIS's durable advantage is the support layer around policy, scope,
evidence contracts, verifier status, related-evidence scoring, and report
discipline. A broad product surface without runtime proof would recreate the
placeholder drift that recent cleanup removed.

Obsolete when: benchmark evidence shows that a broader source-aware or
multi-agent production surface improves confirmed findings, related-evidence
depth, and repro completeness without increasing false positives, context load,
or public surface drift.

## 2026-06-19 - Production wiring only

Decision: public surfaces such as CLI, MCP, dashboard routes, registries, reports,
and package data may reference only working code that is present, packaged, and
covered by an execution test.

Reason: dead registrations and placeholder routes make production fail late and
pollute AI context with features that do not actually exist.

Obsolete when: VXIS has a formal feature-flag/incubator promotion system with
automated checks proving that disabled experiments cannot be imported from
production paths.

## 2026-06-19 - Incubator before `src/`

Decision: incomplete features are developed outside `src/` in a clearly marked
incubator/labs area with local status notes and tests. They move into
`src/vxis/...` only after they are complete enough to import, package, wire, and
exercise through a real runtime entrypoint.

Reason: future agents and humans can identify WIP without auditing every import
edge, and production code stays small enough for reliable AI reasoning.

Obsolete when: the repository has an equivalent enforced convention that
separates experiments from production-importable modules.

## 2026-06-19 - Current plan only

Decision: keep a single current actionable plan in
`docs/superpowers/plans/2026-06-19-current-core-plan.md`. Old implementation
plans and speculative specs are removed from the working tree once they stop
describing the live architecture.

Reason: stale plans were preserving deleted phase-era concepts such as
`DirectorAgent`, `BaseAgent`, old attack graphs, and placeholder phase wrappers.

Obsolete when: a new dated current plan replaces the 2026-06-19 plan and this
file records why the plan changed.

## 2026-06-19 - Black-box only until source tools are real

Decision: production Brain scans resolve all `--box` values to black-box until
source-aware CODE tools are implemented, registered, and tested through the live
loop. Existing CODE helpers remain library/test assets, not public white-box
runtime behavior.

Reason: exposing white/grey modes before source-aware Brain tools exist creates
a misleading public surface and another context branch for future agents to
misread.

Obsolete when: CODE/white-box Brain tools are promoted from the incubator with
tests proving black-box scans still register zero source-aware tools.

## 2026-06-19 - Tests verify real contracts

Decision: tests must assert a concrete behavior contract. Empty import-only
tests, placeholder-stub preservation tests, and public tests for unwired future
features are removed or rewritten. Future unsupported surfaces should fail
closed with explicit tests, not construct no-op stubs.

Reason: green test output is misleading if it only proves placeholders exist.
The suite should protect the lean production runtime and keep AI context focused
on code that actually works.

Obsolete when: an equivalent enforced test-quality policy exists in CI and this
decision is duplicated there.

## 2026-06-19 - Strix-style small loop over phase sprawl

Decision: VXIS direction is a compact Strix-style loop: one Brain, one action at
a time, durable branch/finding state, aggressive context compression, strict
scope/policy gates, and verifier-backed findings.

Reason: large phase graphs and broad specialist-agent fleets inflated context
without improving real scan execution. The product needs accurate, fast
iteration more than more named modules.

Obsolete when: benchmark evidence shows a different architecture improves
confirmed findings per time/cost without increasing false positives or context
load.
