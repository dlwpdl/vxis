---
name: Chain Intelligence
type: concept
status: active
when_to_read: chain nudge 재주입 주기 / _desired 계산식 / finish_scan 거부 조건 (0-finding/chains 부족) / 체인 부족 시 동작
updated: 2026-04-23
sources:
  - ../../src/vxis/agent/scan_loop.py
related:
  - ./brain_first.md
  - ./scoring_model.md
  - ../entities/modules/scan_loop.md
  - ../entities/skills/link_chain.md
---
# Chain Intelligence

## 핵심 사실
| 항목 | 값 |
|---|---|
| 목표 체인 수 (`_desired`) | `max(3, len(findings) // 3)` — findings 3개당 체인 1개 |
| Nudge 재주입 주기 | 6 iter gap (`_last_chain_nudge_iter` 기록) |
| Nudge 시작 조건 | findings ≥ 3 AND chains < `_desired` AND iter ≥ 18 |
| finish_scan 거부 조건 | (1) iter < `min_iters` (2) **0 findings** (Q11, 2026-04-23) (3) findings ≥ 3 이면서 chains < `_desired` |
| 거부 응답 | (체인 부족) top-4 severity 피어링 쌍 + ready-to-call `link_chain()` 템플릿 / (0 findings) 등록 tool 목록 + run_skill·shell_exec·report_finding 옵션 |
| 대시보드 | ≥ 2 findings 부터 5 카테고리 × 7 candidate 템플릿 상시 노출 |

## TL;DR
Brain이 체인을 빌드할 때까지 scan_loop가 압박을 유지한다. 한 번만 주입되는 `_done` 플래그 대신 6-iter gap 주기로 nudge 재주입, findings 3개당 chain 1개 목표로 `_desired` 재계산, finish_scan 호출 시 부족하면 거부하고 구체 ID 쌍 제시.

## What
Chain Intelligence는 단일 취약점을 multi-step 공격 체인으로 엮어 Crown Jewel까지 연결하는 Brain의 추론 능력이다. `scan_loop.py`는 이 추론을 강제하는 3개 feedback 메커니즘을 운영한다: CHAIN INTELLIGENCE 대시보드(상시), chain nudge 재주입(주기적), finish_scan 거부 gate(종료 시).

## Why
Brain이 chain을 "안 만들면" 원인은 거의 항상 프롬프트 품질이 아니라 배관 문제다. 압박이 한 번만 발사되고 사라지거나(one-shot `_done` flag), Brain 출력이 다음 iter로 흐르지 않는다. 2026-04-16에 7개 disconnection 수정 중 3개가 체인 경로였다 — Brain-First가 명목상 돌아가도 구조적으로 끊겨 있었다.

## How
- **대시보드** (`scan_loop.py:221` 근처): findings ≥ 2이면 매 iter 시스템 메시지에 `Chains recorded: N / _desired+ target` 노출. `_desired = max(3, len(reported) // 3)`.
- **Nudge 재주입** (`scan_loop.py:1892` 근처): `_last_chain_nudge_iter` gap 체크. 6 iter마다 `link_chain(finding_ids=["ID-001","ID-002"], ...)` 템플릿을 실제 finding ID로 채워 재주입.
- **finish_scan gate** (`scan_loop.py:1095-1230` 근처): 3 단 ladder. 첫째 `iter < min_iters` reject. 둘째 (Q11, commit `507f21a`) `_get_findings()` 비어 있으면 reject — Q10 smoke 에서 Calculator.app 이 21 findings (Q9) → 0 findings (Q10) 회귀했던 원인이 0-finding finish_scan 이 acceptance 로 슬쩍 넘어가던 배관 버그였다. 셋째 `findings ≥ 3 AND chains < _desired` 면 reject + top-4 severity 쌍 제안.

## Related
- [brain_first](./brain_first.md) — Brain이 chain의 주체인 이유
- [scoring_model](./scoring_model.md) — Chain Intelligence 차원(15%, 150점) 계산
- [scan_loop](../entities/modules/scan_loop.md) — nudge/gate 구현 위치
