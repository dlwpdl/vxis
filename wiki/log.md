# VXIS LLM Wiki — Log

> Append-only. 형식: `## [YYYY-MM-DD] <type> | <subject>` + 1~3줄 본문.
> Types: `init` | `ingest` | `refactor` | `decay` | `lint-fix` | `decision`

## [2026-04-16] init | wiki scaffolding
- wiki/ 디렉토리 트리 생성 (sources/concepts/entities/decisions/scripts).
- schema (CLAUDE.md), index.md, log.md 초기화.
- Phase 2 concept 페이지 8개 시드 예정 (ai_context_hygiene 추가 — Eliot 의 4 원칙).

## [2026-04-16] ingest | Phase 6 tooling: lint.py + log_ingest.py delivered
- wiki/scripts/ 세 파일 생성 완료

## [2026-04-16] ingest | Phase 2 concept pages (8) seeded
- brain_first / chain_intelligence / payload_rotation / severity_oracle / scoring_model / plan_review_workflow / vxis_architecture / ai_context_hygiene

## [2026-04-16] ingest | Phase 3 skill entity pages (15) seeded
- SKILL_REGISTRY 15개 각 1 페이지. rotation 지원 (test_injection, test_xss) 은 Payload Rounds 섹션 포함. 나머지 13은 Params/Known Limitations/Source Files 만.

## [2026-04-16] ingest | Phase 4 modules (7) + pipelines (14) seeded
- scan_loop / skill_runner / brain / hands / eyes / xray / report_generator + P0~P18 (14 active pipelines). 각 페이지 code_anchors 로 소스 추적 가능.

## [2026-04-16] ingest | Phase 5 incidents (3) + ADRs (6+draft_007) seeded
- ADR-001~006 + 2026-04-16 3 postmortems + draft_007 (payloads yaml refactor plan). code_freeze 원칙 ADR-006 으로 격상.

## [2026-04-17] decision | ADR-008 Finding Precision Bayesian smoothing — 5벡터 noise 90% 축소, user rule 실행 가능해짐

## [2026-04-17] decision | ADR-007 Phase 2 — XSS payloads → xss.json (behavior-preserving, pytest parity 3 rounds)

## [2026-04-17] ingest | ADR-007 Phase 3-9 — 12 non-rotation skills migrated to datasets (load_skill_dataset)

## [2026-04-17] ingest | ADR-007 Phase 10 — growth apply.py / rollback.py rewired to JSON data files (pydantic-validated)

## [2026-04-17] ingest | ADR-007 Phase 11 activated — legacy PAYLOADS*/XSS_PAYLOADS* removed, docs resynced

## [2026-04-20] ingest | 2026-04-20 browser_fill_form Angular+PIVOT fix (phase-1/2/3); eyes.md + scan_loop.md code_anchors stale
