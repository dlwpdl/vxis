---
name: VXIS Scoring Model — 5 Dimensions
type: concept
status: active
when_to_read: 5차원 가중치 / 벡터 ID 매핑 / 새 skill 추가 시 scoring 연결 / 등급 기준 / FP Bayesian smoothing
updated: 2026-04-17
sources:
  - ../../src/vxis/pipeline/scan_pipeline_v2.py
  - ../../src/vxis/scoring/engine.py
  - ../../docs/SCORING.md
related:
  - ../entities/pipelines/scan_pipeline_v2.md
  - ./chain_intelligence.md
  - ./severity_oracle.md
  - ../entities/modules/scoring_engine.md
  - ../decisions/008_finding_precision_smoothing.md
---
# VXIS Scoring Model — 5 Dimensions

## 핵심 사실
| 차원 | 약어 | 가중치 | 무엇 측정 |
|---|---|---|---|
| Vector Coverage | VC | 25% (250pt) | 시도한 벡터 수 / 전체 벡터 수 |
| Exploitation Reach | ER | 30% (300pt) | 발견당 Level 0~4 점수 합 / 이상적 합 |
| Chain Intelligence | CI | 15% (150pt) | 최대 체인 깊이 (0/1-2/3-4/5+ → 0/50/100/150) |
| Finding Precision | FP | 20% (200pt) | Bayesian (n<3) + TP/(TP+FP) (n≥3) + 증거·GT 보너스 (ADR-008) |
| Completeness | CO | 10% (100pt) | 완료 Phase / (완료+실패+에러) |
| 등급 기준 | — | — | S 900+, A 750+, B 600+, C 400+, D 그 외 |

## TL;DR
총 1000점 = VC 25 + ER 30 + CI 15 + FP 20 + CO 10. `_compute_vxis_score()`가 ScoreTracker를 채우고 ScoringEngine이 계산. 새 skill 추가 시 `_skill_to_vectors` dict에 벡터 ID 매핑 필수 — 누락하면 VC 0, ER 저평가.

## What
VXIS Scoring은 단일 스캔을 1000점 5차원으로 측정해 (1) NCC Group 시니어 펜테스터 수준(900+)과 비교, (2) Growth Loop baseline과 diff, (3) CI에서 회귀 탐지한다. `scan_pipeline_v2.py:_compute_vxis_score()`가 진입점.

## Why
단일 지표(발견 개수, 심각도 합)는 깊이·체인·정확도를 반영하지 못한다. 5차원 분리는 "넓게 찍고 FP 덤핑"(VC 높지만 FP 낮음)과 "한 벡터를 Crown Jewel까지"(VC 낮지만 ER·CI 높음)를 구분한다. 이 구분이 있어야 Growth Loop가 어떤 차원을 개선할지 결정할 수 있다.

## How
- **진입점**: `scan_pipeline_v2.py:131` `_compute_vxis_score(ctx)` — ScoreTracker 생성 → ScoringEngine 실행.
- **Vector 매핑**: `_skill_to_vectors` dict(line 177) — 각 skill을 `WEB-XXX-NNN` 벡터 ID 리스트로 매핑. `_completed_skills`에 있는 skill만 `record_vector_attempt()` 호출.
- **Finding → Vector**: `_type_to_vector` dict(line 144) — finding_type(예: `sql_injection`)을 `WEB-SQLI-001`로.
- **Severity → Level**: `_sev_to_level` — critical=3, high=2, medium=1, low/info=0.
- **Verifier verdicts**: `confirmed_findings` → TP, `refuted_findings` → FP로 FP 차원 계산.
- **FP Bayesian smoothing (ADR-008)**: `total_judged=0` → 100pt (중립), `1≤n<3` → `(tp+3)/(n+6) × 200`, `n≥3` → `tp/n × 200` (기존). `details.measurement_valid=True` 만 commit 판정에 사용.
- **새 skill 추가**: `_skill_to_vectors`에 매핑 추가 필수. 누락 시 VC가 attempted 집합에서 빠진다.

## Related
- [chain_intelligence](./chain_intelligence.md) — CI 차원(15%) 실제 계산 근거
- [severity_oracle](./severity_oracle.md) — FP 차원 감점 회피용 body-aware 조정
- [scan_loop](../entities/modules/scan_loop.md) — `_completed_skills` 출처
