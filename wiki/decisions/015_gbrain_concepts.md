# ADR-015 — Adopt GBrain *concepts* (not the product) into the VXIS knowledge layer

Status: Accepted (2026-06-17) — concept adoption; implementation deferred to roadmap.

## Context

Evaluated **GBrain** (github.com/garrytan/gbrain, MIT) — Garry Tan's personal/
company knowledge brain. It is a TypeScript/Bun + PGLite(pgvector) retrieval +
synthesis + self-wiring knowledge-graph system with a 24/7 "dream cycle" daemon,
shipped as an MCP server / OpenClaw plugin, with ~60 domain skills (meeting/voice/
article ingest, person/company enrichment, briefings).

## Decision

**Do NOT bolt GBrain on as a component.** Reasons:
- **Domain mismatch** — GBrain models people/companies/deals/meetings (exec/CRM
  memory); VXIS models targets/services/findings/CVEs/attack-chains. Its skills
  are irrelevant to pentesting.
- **Stack mismatch** — TS/Bun + PGLite vs VXIS Python. A second MCP service
  contradicts the "100% 자체 구현" principle (CLAUDE.md). MIT licensing permits a
  fork, but the principle is concept-reuse, not adoption.
- **Redundant** — VXIS already has KnowledgeStore, cross-scan target memory,
  P18 Collective KB, and the growth loop.

**DO borrow three concepts** (self-implemented in Python, into the existing
knowledge/growth layer). Each maps onto a current roadmap LATER item:

1. **Self-wiring typed-edge knowledge graph, zero LLM calls.** GBrain extracts
   entity refs on every write → typed edges (`attended`/`works_at`/…) and
   benchmarks **+31.4 P@5 over its graph-disabled variant**. VXIS analogue: on
   every finding/recon write, extract host/service/endpoint/CVE/finding entities
   → typed edges (`runs_service`, `vulnerable_to`, `chains_to`, `same_origin`,
   `auth_boundary`). Enables "what did we find on this org across scans?" and
   attack-chain graph traversal vector search can't reach. → feeds the LATER
   "findings_by_type → connected KnowledgeStore" item.
2. **Synthesis with explicit GAP ANALYSIS** ("what the brain doesn't know yet").
   VXIS analogue = **coverage-gap synthesis**: "which attack vectors / endpoints /
   phases were NOT exercised, and why." Directly strengthens the "100% 공격 벡터
   커버리지" principle and becomes a report panel (sibling to the verification-rate
   panel).
3. **Consolidation / "dream cycle" daemon** (overnight ingest → enrich →
   consolidate → fix-citations). VXIS analogue: a scheduled job that dedups
   findings across scans, enriches with CVE/threat-intel, prunes stale beliefs,
   and updates the Collective KB. → converges the LATER self-improvement item
   (growth loop / P12 Evolution).

## Non-goals
- No GBrain code, MCP server, PGLite, or its skills.
- No people/company/CRM modeling.

## Consequences
- Three roadmap LATER items gain a concrete, evidence-backed shape (the graph
  benchmark is the strongest signal — prioritize concept #1).
- Concept #2 (coverage-gap panel) is the cheapest near-term win and pairs with
  the existing report verification-rate panel.
