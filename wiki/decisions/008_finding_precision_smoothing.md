---
name: ADR-008 — Finding Precision Bayesian smoothing + neutral fallback
type: decision
status: active
when_to_read: 스코어 비교 시 FP 차원 해석 / 판정 수 부족 / baseline vs after 노이즈 / 측정 인프라 수정 정당화
updated: 2026-04-17
sources:
  - ../../../.claude/projects/-Users-eliot-Desktop---vxis/memory/feedback_test_score_sync_process.md
  - historical Juice Shop score snapshots generated under benchmarks/juice_shop/
related:
  - ./006_code_freeze_data_only_updates.md
  - ./007_payloads_as_data_files.md
  - ../concepts/scoring_model.md
code_anchors:
  - src/vxis/scoring/engine.py:_calc_finding_precision
  - src/vxis/scoring/engine.py:_MIN_JUDGMENTS_FOR_CONFIDENCE
  - src/vxis/scoring/engine.py:_PRECISION_PRIOR
---
# ADR-008 — Finding Precision Bayesian Smoothing

## 핵심 사실
| 항목 | 값 |
|---|---|
| Status | Accepted |
| Date | 2026-04-17 |
| 대상 | `ScoringEngine._calc_finding_precision` (차원 4, max 200pts) |
| 임계값 | `_MIN_JUDGMENTS_FOR_CONFIDENCE = 3` |
| Prior | `_PRECISION_PRIOR = 3.0` (α=β, 중립 0.5 방향) |
| 수식 (n<3) | `base = (tp + α) / (n + 2α) × 200` |
| 수식 (n=0) | `base = 200 × 0.5 = 100pts` (neutral — 기존 140pts 폐기) |
| 수식 (n≥3) | `base = tp / n × 200` (기존 로직 유지) |
| 새 플래그 | `details.measurement_valid` / `details.min_judgments_required` |

## TL;DR
기존 FP 로직은 `analyst_judged=0 → 140pts` (판정 안 하면 고득점 perverse) + `judged=1 & FP=1 → 0pts` (n=1 로 전체 precision 0 판정) 결함. Bayesian smoothing α=3 으로 n<3 구간을 중립(0.5) 방향으로 shrink. baseline(j=0) vs after(j=1,FP=1) noise delta 140→14pt (90% 축소). n≥3 부터는 기존 그대로.

## Context

2026-04-17 Juice Shop 벤치마크에서:
- baseline: `total_judged=0` → precision=1.0 → 140pts
- after-phase1 (ADR-007 refactor, byte-identical payload): `total_judged=1, FP=1` → precision=0.0 → 0pts
- Total 472.33 → 332.33 (D). **4/5 차원은 byte-identical**, FP만 -140.

ADR-007 refactor 는 `pytest` 로 byte-identical 증명 (8/8 parity pass) — 공격 행동 불변. 스코어 -140 은 LLM Brain 의 비결정적 `analyst_verdict` 호출 한 건에 의한 noise. 즉 **측정 체계가 noise 에 민감해서 user rule ("5벡터 개선만 반영") 을 실행할 수 없음**.

결함 두 층:
1. **Perverse incentive**: 판정 0건이면 기본 140pts → "Brain 이 judge 안 할수록 점수 ↑".
2. **Statistical invalidity**: n=1 로 전체 precision 을 결정. Sample size 문제.

## Options

**A. 현상 유지** (기각) — user rule 실행 불가. ADR-007 같은 behavior-preserving refactor 모두 false regression.

**B. 판정 수 부족 시 dim 비활성 (max_score 에서 차감)** (기각) — 총점 max 가 동적으로 바뀜 → 스코어간 비교 불가.

**C. Bayesian smoothing (α=β=3) + 판정 0건 중립 100pts** (선택) — 수식 단일, 총점 max 고정, 단일 판정의 극단 영향 제거. n≥3 기존 로직 보존.

**D. Wilson score interval lower bound** (보류) — 수식 복잡도 ↑, 효과는 C 와 유사.

## Decision

**C 채택.** 모듈 상수 `_MIN_JUDGMENTS_FOR_CONFIDENCE=3`, `_PRECISION_PRIOR=3.0` 추가. 로직 분기:
- `findings=0` → 0pts (대상 없음)
- `total_judged=0` → 100pts (중립)
- `1 ≤ total_judged < 3` → `(tp+3)/(n+6) × 200` (smoothing)
- `total_judged ≥ 3` → `tp/n × 200` (기존)

`details.measurement_valid` 플래그로 n≥3 여부 노출 → `ScoreComparison` 이 해석.

## Consequences

**긍정:**
- Noise delta 90% 축소 (140 → 14pt at j=0↔j=1). user rule 유의미 실행 가능.
- n≥3 구간 기존 semantics 보존 — 과거 벤치마크와 회귀 아님.
- `measurement_valid` flag 로 비교 해석 가능 (analyst judgment coverage 부족을 명시).
- ADR-006 code freeze 원칙 준수: 측정 인프라 수정은 정당화 사유 명시 + 별도 ADR.

**부정:**
- FP 절대값 (0, 140, 200 등) 이 shift — 과거 스코어 JSON 과 FP 비교 시 α=3 smoothing 감안 필요.
- α=3 선택은 heuristic — 실측 noise 수집되면 재조정 가능 (별도 ADR).

**Enforcement:**
- `_MIN_JUDGMENTS_FOR_CONFIDENCE` / `_PRECISION_PRIOR` 변경 시 이 ADR 수정 + 기존 벤치마크 재계산.
- `details.measurement_valid=False` 인 스코어는 "측정 부족" 으로 표기, commit 정당화 근거로 단독 사용 금지.

## Out of Scope

- Vector Coverage / Exploitation Reach / Chain Intelligence / Completeness 의 유사 결함 — 별도 ADR.
- Wilson score interval / Jeffreys prior 전환 — 현재 α=3 균일 prior 로 충분.
- `analyst_verdict` 호출 결정론화 — Brain 비결정성 자체 축소는 별도 문제 (prompt 엔지니어링).
