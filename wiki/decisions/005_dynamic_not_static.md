---
name: ADR-005 — Dynamic Attack Only (No Static grep Scoring)
type: decision
status: active
when_to_read: 코드 grep 커버리지 측정 금지 이유 / 동적 스캔 필수 근거 / 벤치마크·스코어링 원칙
updated: 2026-04-16
sources:
  - /Users/eliot/.claude/projects/-Users-eliot-Desktop---vxis/memory/feedback_dynamic_not_static.md
related:
  - ../concepts/brain_first.md
  - ../concepts/severity_oracle.md
  - ../concepts/scoring_model.md
---
# ADR-005 — Dynamic Attack Only — No Static grep Scoring

## 핵심 사실
| 항목 | 값 |
|---|---|
| Status | Accepted |
| Date | 2026-04-16 |
| 금지 | 소스코드 grep 커버리지 / 패턴 매칭 스코어링 / 정적 분석 기반 벤치마크 |
| 필수 | 실제 타겟 동적 스캔 → 결과 → 점수 → 약한 부분 인식 → 코드 개선 → 재공격 |
| 벤치마크 | Docker 로 DVWA / Juice Shop / WebGoat 기동 후 실공격 |
| CI | 동일 동적 스캔을 Docker 컨테이너 위에서 |

## TL;DR
VXIS 는 자동 펜테스터, 코드 분석기 아님. grep 으로 "이 공격 벡터 커버하는 함수 있나" 세서 점수 매기면 AI 가 코드만 많이 쓰는 방향으로 학습 — 실제 공격 능력과 괴리. 모든 스코어링·벤치마크·self-improvement 루프는 **실제 타겟 동적 공격 결과** 기반.

## Context
자동 개선 루프에서 "커버리지" 측정 방식 선택. 정적 grep (skill 코드에 "SQLi" 키워드 카운트 등) 은 구현·측정 쉽지만 실공격 성공과 무관. 동적 (실 타겟 finding·severity·chain 깊이) 은 reproducibility 낮고 인프라 필요. VXIS 의 핵심은 실공격 루프 — 정적은 방향 불일치.

## Options
1. **정적 grep** — 빠름, AI 가 "코드만 늘리는" 방향 학습.
2. **동적 실공격** — Docker 취약앱 필요, 측정 신뢰도 높음.
3. **하이브리드** — 정적 점수가 동적 신호 희석 가능.

## Decision
옵션 2 채택. 벤치마크·스코어링·자가 개선 루프 모두 실 타겟 동적 스캔 기반. 정적 grep 금지. 5 차원 VXIS 스코어 (Finding Precision / Vector Coverage / Exploitation Rigor / Chain Intelligence / Operational Efficiency) 는 전부 스캔 run 결과에서 계산. Growth loop 는 DVWA/Juice Shop/WebGoat 컨테이너 기동 → 실스캔 → 약한 차원 감지 → 튜닝 → 재실행.

## Consequences
- **Pro**: AI 가 공격 능력 향상 방향 학습 — 발견 수·severity·chain 깊이 증가.
- **Pro**: Severity oracle 같은 content-aware 판정이 자연스러운 선택이 됨 (→ [severity_oracle](../concepts/severity_oracle.md)).
- **Pro**: 벤치마크 재현성 = Docker 이미지 해시.
- **Con**: CI 비용 증가 — Docker + 5~10 분 스캔.
- **Con**: 타겟 편향 주의 (WebGoat 만 돌리면 Juice 차원 미측정).
- **Enforcement**: 새 지표 "실 스캔에서 나오나?" 확인, grep 제안 reject.
