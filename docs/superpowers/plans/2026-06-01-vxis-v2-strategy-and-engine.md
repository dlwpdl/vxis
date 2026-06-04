# 2026-06-01 — VXIS v2 Strategy & Engine Plan

> Supersedes `2026-06-01-vc-b2b-profile-plan.md`. Same date intentionally — this is the result
> of a strategy review of that plan after surveying competitor tooling (Strix, PentAGI,
> Metatron, PentestAgent) and re-scoping the next 6 weeks of engine work.

## Goal

Lock in VXIS's product category as **Continuous Autonomous Pentest (CAPT)**, prove the
`crown` engine on a hardened benchmark league, build the four engine capabilities that
unlock recurring-revenue ICPs, and ship a SaaS deployment with a Korean-market wedge —
without diluting Brain-First identity or competing with VXIS's own depth story.

## Product Principle

VXIS default mode stays `crown`: deep, agentic, Brain-First pentest. Every ICP package
is a thin wrapper over the same engine — never a separate weaker engine. Compliance is
treated as a **mapping output**, not a product line; VXIS does not become a compliance
consulting tool.

## Competitive Positioning

| Tool | Wedge | What VXIS does differently |
|---|---|---|
| **Strix** | Open-source CLI + GitHub Actions + dev-first SaaS | Depth + adversarial verifier (zero-FP) + safe-for-prod (deferred mutation gate + egress filter) + bilingual reports |
| **PentAGI** | Self-hosted multi-agent infra (Graphiti KG, 20+ tools) | Single Brain ReAct loop (lower ops cost) + vector-exhaustion semantics + MITRE-mapped findings out of the box |
| **Metatron** | Local/offline Parrot OS hobbyist tool | Multi-tenant SaaS + recurring/delta scan + portfolio-level rollup |
| **PentestAgent** | Generic LiteLLM agent | Production-grade verifier hierarchy + crown-jewel chain semantics |

VXIS's defensible moat: **adversarial verifier → vector exhaustion → chain to crown jewel
→ MITRE-mapped → bilingual NCC-style evidence report**. No competitor stacks all five.

## ICP Packages (3 core + 1 add-on)

All four wrap the same `crown` engine.

| Profile | ICP | Pricing | Wedge vs competitors |
|---|---|---|---|
| `continuous-devsec` | SaaS AppSec teams | per-target / month | Compete with Strix on depth + zero-FP, not on CI/CD ergonomics |
| `vc-portfolio-monitor` | VC funds (KR-first) | per-portco / month, VC-issued discount codes | Deep validated pentest, not external surface scoring (BitSight/SecurityScorecard) |
| `pre-investment-dd` | VC / PE | one-off premium per target | High-margin diligence runs with verified PoC |
| `compliance-mapping` (add-on) | Buyers above | flat add-on fee | MITRE → SOC-2 / ISO 27001 / ISMS-P **mapping only**, no consulting |

Profile scaffolds in the codebase (initial state — empty wrappers, decisions deferred to
implementation plans):

- `crown` — default Brain-First mode
- `continuous-devsec`
- `vc-portfolio-monitor`
- `pre-investment-dd`
- `remediation-verification`
- `compliance-mapping` (add-on, layered on any profile output)

## Korean-Market Wedge

Position VXIS as a **SaaS tool that customers run themselves**, not as an outsourced
pentest service. This avoids Korean regulatory cert requirements entirely:

| Segment | Reality | VXIS path |
|---|---|---|
| Startups / SaaS / e-commerce / games | Free market, no cert needed | **1차 타겟 — 진입** |
| Korean VC portcos | Free market | **1차 타겟 — VC channel** |
| 금융권 모의해킹 | 정보보호 전문 서비스 기업 지정 필요 (12–24mo) | 보류 |
| 공공기관 / 주요정보통신기반시설 | 동일 + ISMS-P 인증심사원 | 보류 |
| 금융보안원 발주 사업 | 별도 등록 | 보류 |

Differentiators that matter in the KR free-market segment:

- **Korean-language NCC-style report** — Strix/PentAGI ship English-only output
- **Korean VC channel** (HashedVC, Altos, SoftBank KR style funds) → portco distribution
- **SaaS pricing 1/10 of a consulting engagement** — replaces low-end consulting spend

Regulated segments (금융/공공) are deferred until product-market fit in the free market,
then opened with a 12-month cert-acquisition track.

## SaaS Deployment Shape

- **Multi-tenant SaaS only.** No self-hosted SKU at launch (PentAGI is in that lane;
  we are not.).
- **Self-serve onboarding.** Drop a domain, get a sample report under 30 minutes.
- **Per-target / month** primary pricing; **one-off DD** secondary.
- **VC channel.** VC fund gets a free read-only dashboard view; portcos pay; VC issues
  discount codes. No revenue split with the VC.
- **Tenant isolation.** Each tenant gets its own Brain sandbox volume; findings DB is
  row-level isolated.

Operationally this means we will add: tenant identity, target ownership records, scope
binding, scan credential storage, scheduling, delta diffing, and dashboards. The
existing `src/vxis/dashboard/`, `src/vxis/scheduler/`, and `src/vxis/integrations/`
modules are starting points but need multi-tenant hardening.

## Customer Flow (per ICP)

**Continuous DevSec**
1. Customer adds target(s), uploads credentials, sets schedule.
2. VXIS runs `crown` engine per target on schedule.
3. Delta scan compares vs last run; only **new / changed / regressed** findings notify.
4. Customer receives technical report with PoC + remediation; optional Slack/GitHub
   integration via existing `src/vxis/integrations/`.

**VC Portfolio Monitoring**
1. VC registers portcos; each portco confirms scope (assets + rules).
2. VXIS runs `vc-portfolio-monitor` profile on schedule.
3. Asset discovery surfaces new domains/subdomains/cloud assets per portco; out-of-scope
   assets are listed separately as discovered references, never tested.
4. VC sees executive view: per-portco score, trend, severity mix, critical themes,
   portfolio ranking. **No raw scanner branding.**
5. Each portco receives a technical remediation report.

**Pre-Investment DD**
1. VC submits target with one-off scope authorization.
2. VXIS runs `pre-investment-dd` profile (single deep `crown` pass, full chain
   exhaustion, verified findings only).
3. Premium PDF + HTML report with executive findings, attack chains, and remediation
   priority; delivered as a one-time artifact.

**Remediation Verification**
1. Customer marks findings as remediated.
2. VXIS replays the same vectors against the same surface.
3. Report shows fixed / not-fixed / regressed per finding.

## Default Completion Gate — Benchmark League v2

Do not ship any business-facing profile until `crown` clears the league.

**League targets:**

- **Known vulnerable**: Juice Shop, WebGoat, DVWA, Mutillidae, crAPI, VAmPI, DVGA
- **Clean controls**: 2–3 intentionally low-risk targets, used to measure false-positive
  rate. Crown must produce zero CONFIRMED criticals on these.
- **Randomized arena**: generated variants of vulnerable targets — randomized routes,
  parameters, payload sieves — to detect Juice Shop overfitting.
- **Secret holdout**: 1 target the team never trains on, scored quarterly only. Never
  used for prompt tuning, never reviewed during development.

**Quality dimensions** (each scored on every league run):

- Recall (true vulns found / known vulns)
- Precision (CONFIRMED findings / all reported)
- Evidence quality (Has PoC? Has reproduction steps? Has MITRE tag?)
- Scope safety (Did the scan touch anything out-of-scope?)
- Chain depth (Average + max chain length toward crown jewel)
- Stability (Variance across 3 repeated runs)
- Cost / runtime (LLM cost, wall-clock, peak context)

No single benchmark target counts as proof that `crown` is shippable. The holdout score
gates `continuous-devsec` and `vc-portfolio-monitor` launch.

## 6-Week Engine Build — Priority Order

Five engine capabilities. Each becomes its own implementation plan in a follow-up file.
The five are ordered so earlier work unblocks later work.

### 1. Benchmark League v2

**Why first**: Without a hardened league, we can't trust quality gates on anything else
we build. Also gives us a stable artifact pipeline for the recurring product (delta
scan reuses it).

**Deliverables**:
- League target manifest in `infra/benchmarks/` (Docker Compose for each target)
- Randomized arena generator (route shuffling, parameter renaming, payload-sieve
  injection)
- Secret holdout protocol (in `docs/superpowers/benchmarks/`)
- Multi-dimensional scoring report (recall / precision / evidence / scope / chain / stability / cost)
- CI workflow that runs the league per PR

**Status gate**: All league dims tracked, holdout score recorded.

### 2. Delta / Diff Scan Engine

**Why second**: This is the killer feature of every recurring profile (`continuous-devsec`,
`vc-portfolio-monitor`). Without it, recurring scans are noise.

**Deliverables**:
- Per-target scan history store with content-addressable evidence
- Delta resolver: maps findings across runs by `(finding_type, route, parameter,
  payload_class, severity)`
- Status transitions: `NEW / RECURRING / FIXED / REGRESSED / CHANGED-EVIDENCE`
- Delta report section in the NCC HTML output
- Slack / GitHub Issue notification rules driven by transitions only

**Status gate**: Two scheduled runs against Juice Shop produce a delta report with
zero spurious NEWs on the second run.

### 3. Asset Discovery Pipeline

**Why third**: Prerequisite for `vc-portfolio-monitor` — VCs hand us a domain and
expect us to find what to scan.

**Deliverables**:
- Subdomain enumeration (passive: crt.sh, RDAP, CT logs; active: dictionary, permutation)
- HTTP probe + tech fingerprint for each discovered host
- Cloud asset hints (S3 bucket guessing, GCS, public Azure, only when domain matches)
- API surface heuristics (`/api`, `/v1`, `/graphql`, OpenAPI spec discovery)
- Discovered-but-out-of-scope list in the report (never tested, only listed)

**Status gate**: Given a single seed domain for one of our internal demo targets,
the pipeline lists assets correctly classified as in-scope vs discovered-only.

### 4. Authenticated Scan Credential Vault

**Why fourth**: Recurring authenticated scans need persistent, rotatable credentials.
Without this, customers can't onboard recurring scans safely.

**Deliverables**:
- Per-tenant encrypted credential store
- Credential injection into Brain context per scan, scoped to a single target+scan id
- Credential rotation API and audit trail
- Login orchestration handoff: existing `auto-login` path in `scan_loop.py` reads
  from vault instead of CLI flags

**Status gate**: A scheduled scan can use stored credentials, log evidence of
authenticated requests, and rotate credentials without re-onboarding.

### 5. Compliance Mapping (Lightweight Add-On)

**Why last**: It's an output formatter, not an engine change. Cheap to ship after the
above is done, and unlocks the `compliance-mapping` add-on SKU.

**Deliverables**:
- MITRE technique → SOC-2 Common Criteria mapping table
- MITRE technique → ISO 27001 Annex A control mapping table
- MITRE technique → ISMS-P 통제항목 mapping table (KR market)
- Report section: per finding, list mapped controls
- Portfolio rollup: control coverage matrix across all findings

**Status gate**: A Juice Shop scan report includes a Compliance Mapping section
referencing SOC-2 / ISO / ISMS-P controls, validated against the source standards by
manual spot-check.

## Implementation Slices (sequencing inside the 6 weeks)

1. Week 1: Benchmark league v2 manifest + scoring scaffolding (1)
2. Week 2: Randomized arena + holdout protocol; start delta engine schema (1 → 2)
3. Week 3: Delta engine ships against Juice Shop + WebGoat (2)
4. Week 4: Asset discovery pipeline + scope classifier (3)
5. Week 5: Credential vault + authenticated scan integration (4)
6. Week 6: Compliance mapping output + profile scaffolds in CLI (5 + glue)

Each numbered item gets its own implementation plan with task-level decomposition,
file paths, code blocks, and commit messages per `docs/superpowers/plans/README.md`
plan-authoring rules.

## Revenue Model

| Stream | Notes |
|---|---|
| Per-target / month (`continuous-devsec`) | Core recurring revenue |
| Per-portco / month (`vc-portfolio-monitor`) | VC-issued discount codes drive adoption; portco pays |
| One-off premium (`pre-investment-dd`) | High margin, low recurring; supports cash flow |
| Retest credits (`remediation-verification`) | Sold as packs |
| Compliance mapping add-on | Flat add-on per scan or per tenant |

VC funds receive a **free read-only dashboard view** to encourage portfolio onboarding.
No revenue share with the VC.

## Success Criteria

- `crown` clears the benchmark league with stable recall/precision across 3 repeat runs
  and a known holdout score
- Delta scan produces zero spurious NEW findings on a repeated unchanged target
- Asset discovery correctly separates in-scope from discovered-only assets
- Credential vault supports scheduled authenticated scans with rotation
- Compliance mapping appears in every report with SOC-2 / ISO / ISMS-P references
- At least one VC and one DevSec customer are onboarded onto SaaS before profile work
  goes beyond scaffolds
- Korean-language report path validated by at least one Korean-market user

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Juice Shop overfitting masks real quality | Randomized arena + holdout target; multi-dim scoring, not single metric |
| Recurring scans create alert fatigue | Notifications gated on delta transitions, not raw findings |
| VC channel never converts portcos | Direct DevSec sales runs in parallel; VC is a channel, not the only ICP |
| Korean regulatory segments block expansion | Position as SaaS tool (customer-run), not outsourced service; defer 금융/공공 to year-2 cert track |
| Compliance scope creep into consulting | Hard line: mapping output only; no advisory deliverables, no auditor handholding |
| Strix ships the same delta/asset features first | VXIS leads on depth + zero-FP + KR-language report; delta is table stakes, not the moat |
| Tenant isolation bugs leak findings across tenants | Multi-tenant tests in CI; row-level isolation enforced at DB layer; pre-launch security review |
| Asset discovery scans assets the customer doesn't own | Strict scope binding before any active probe; discovered assets are listed, never tested, unless explicit opt-in |

## Out of Scope (for this plan)

- Compliance consulting deliverables
- Self-hosted SKU
- Public benchmark leaderboard / Strix head-to-head publication
- 금융 / 공공 / 주요정보통신기반시설 segment entry
- Mobile / game / hardware runtime expansion (separate roadmap)

## Relationship to Prior Plans

- Supersedes [`2026-06-01-vc-b2b-profile-plan.md`](2026-06-01-vc-b2b-profile-plan.md) —
  same date, but this plan re-frames VC monitoring as one of three core ICPs rather than
  the headline, and adds the engine build sequence.
- Continues the Phase D / Phase E direction in [`PHASE_STATUS.md`](../../../PHASE_STATUS.md):
  benchmark league v2 absorbs the remaining Phase D tuning work, delta engine extends
  Phase D's vector-state tracking across runs.
- Does **not** touch Brain-First architecture from
  [`2026-04-08-phase-a-strix-parity-single-loop.md`](2026-04-08-phase-a-strix-parity-single-loop.md);
  all engine work is layered on the existing `ScanAgentLoop` + `AgentBrain`.

## Next Step

Write the five implementation plans (one per engine capability above) before starting
any code. Each gets `superpowers:writing-plans` treatment with task decomposition,
file paths, code blocks, and commit messages.
