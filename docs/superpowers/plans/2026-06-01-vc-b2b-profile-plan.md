# 2026-06-01 - VC/B2B Profile Plan

> **Status: Superseded by [`2026-06-01-vxis-v2-strategy-and-engine.md`](2026-06-01-vxis-v2-strategy-and-engine.md)** (same date).
> The successor plan re-frames VC monitoring as one of three core ICPs (Continuous DevSec, VC Portfolio Monitoring, Pre-Investment DD)
> rather than the headline, drops fund-retainer pricing in favor of per-target/per-portco SaaS, adds a Korean-market wedge
> with regulatory-cert reality check, and sequences a 6-week engine build (benchmark league v2 → delta scan → asset discovery →
> credential vault → compliance mapping). Kept here for revision history.

## Goal

Add a business-facing profile layer on top of the VXIS crown engine without changing
the core product identity: deep, agentic, open-ended pentesting remains the default.

## Product Principle

VXIS default mode is the crown profile. It is optimized for depth, persistence,
evidence quality, and finding real risk.

B2B and VC profiles should not become a separate weaker engine. They should wrap
the same engine with stricter scope handling, clearer reporting, recurring
assessment cadence, and business-readable risk summaries.

## Profile Shape

Initial profile scaffolds:

- `crown`: default VXIS mode, deep agentic pentest posture.
- `b2b-standard`: baseline business assessment profile.
- `vc-baseline`: recurring portfolio risk monitoring profile.
- `pre-investment-dd`: pre-investment due diligence profile.
- `remediation-verification`: retest profile for fixed findings.

The public report should use VXIS-owned language such as "VXIS Standard Baseline"
and "VXIS Portfolio Cyber Risk Index". Do not expose underlying scanner/tool names
as the product story.

## Customer Flow

1. VC registers portfolio companies or a prospective investment target.
2. Each company submits approved assets: domains, apps, APIs, cloud accounts, and
   explicit scope rules.
3. VXIS runs the selected profile on a schedule or as a one-off diligence run.
4. If linked URLs or adjacent assets are discovered, VXIS lists them separately as
   discovered references unless they are explicitly in scope.
5. VC receives an executive risk view: score, trend, severity mix, critical themes,
   and company ranking.
6. Portfolio company receives the technical remediation report with evidence,
   reproduction steps, and retest guidance.

## Revenue Model

- Fund retainer: monthly or quarterly subscription per VC fund.
- Portfolio monitoring: recurring per-company fee.
- Pre-investment diligence: one-off premium assessment per target.
- Retest credits: paid verification runs after remediation.
- Board/investor reporting: paid recurring cyber-risk summary pack.

The strongest recurring revenue path is fund retainer plus per-company monitoring.

## Default Completion Gate

Before building full VC workflows, improve and measure the `crown` profile with a
benchmark league:

- vulnerable targets: Juice Shop, WebGoat, DVWA/Mutillidae, crAPI, VAmPI, DVGA.
- clean controls: intentionally low-risk targets to measure false positives.
- randomized arena targets: generated variants to prevent Juice Shop overfitting.

Release quality should be judged across recall, precision, evidence quality, scope
safety, depth, stability, and cost/runtime. No single benchmark target should be
treated as proof that default is complete.

## Implementation Slices

1. Stabilize benchmark runner and CI workflow.
2. Keep `crown` as the default profile and benchmark it against the target league.
3. Keep business profiles as scaffolds until the default profile reaches acceptable
   benchmark quality.
4. Add report templates for VC summary, portfolio company technical report, and
   remediation verification.
5. Add recurring schedule orchestration and trend comparison.
6. Add portfolio-level dashboard and exportable investor report.

## Success Criteria

- Default profile can run repeatable benchmarks without CI flakes.
- Reports separate in-scope findings from discovered linked assets.
- VC receives a portfolio-level risk view without raw scanner branding.
- Portfolio company receives actionable technical remediation detail.
- Retest flow can prove whether fixes reduced risk.

## Risks And Mitigations

| Risk | Mitigation |
| --- | --- |
| Overfitting to Juice Shop | Use multiple targets, clean controls, and randomized arena cases. |
| B2B profile weakens VXIS identity | Keep `crown` as default and make B2B profiles wrappers, not a separate engine. |
| Scope confusion from linked URLs | Report discovered linked assets separately and do not actively test them unless allowed. |
| Report reads like a tool bundle | Use VXIS-owned standard names and business-level scoring language. |
| Recurring scans create noise | Add trend tracking, deduplication, retest status, and severity movement. |
