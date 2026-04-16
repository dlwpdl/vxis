---
name: 2026-04-16 Seven Disconnections in scan_loop
type: incident
status: active
when_to_read: scan_loop 동작 이상 / chain 연쇄 안 됨 / skill cache 꼬임 / severity 정적 고정 / IDOR 자동 큐잉 누락
updated: 2026-04-16
sources:
  - /Users/eliot/.claude/projects/-Users-eliot-Desktop---vxis/memory/project_scan_loop_fixes_2026_04.md
  - ../../../src/vxis/agent/scan_loop.py
  - ../../../src/vxis/agent/tools/skill_runner.py
  - ../../../src/vxis/agent/skills/test_sensitive_files.py
related:
  - ../../concepts/chain_intelligence.md
  - ../../concepts/severity_oracle.md
  - ../../concepts/payload_rotation.md
  - ../../entities/modules/scan_loop.md
---
# 2026-04-16 — Seven Disconnections in scan_loop

## 핵심 사실
| 항목 | 값 |
|---|---|
| Scope | `scan_loop.py` / `skill_runner.py` / `test_sensitive_files.py` plumbing |
| 발견 bugs | 7 (chain·cache·severity·auto-login·IDOR·dashboard·finish_scan gate) |
| 벤치마크 증상 | WebGoat 409.3 vs Juice Shop 522.3 (벡터 커버리지·체인 차원 급락) |
| 공통 패턴 | one-shot `_done` 플래그 / Brain 출력 → 다음 iter 미전달 |
| 수정 커밋 | d13d6d9 (feat(scan): payload rotation R2/R3 + skill sweep + auto-login pivot + cache hardening) |
| 영향 | Brain-First 루프가 명목상 동작하나 구조적으로 절단 |

## TL;DR
scan_loop 에 chain 재주입 / skill 캐시 / severity oracle / IDOR auto-queue 등 7개 배관이 빠져 Brain 이 첫 표면 스캔 후 정지했다. 각자 Brain 프롬프트 문제처럼 보였으나 모두 "압박이 1회 발사 후 사라지거나 Brain 출력이 다음 iter 로 흐르지 않음" 공통 원인.

## Symptom
- Findings 10+ 인데 chain 은 0~1 에서 멈춤.
- 동일 skill 같은 args 반복 호출, 결과 동일.
- `/actuator/env` 가 masked 인데도 critical.
- 숫자 ID path 있어도 `test_idor` 큐잉 없음.
- `finish_scan` 이 findings 3 개에도 성공 처리.

## Root Cause
Brain 의 X 출력이 다음 iter 로 도달할 채널 부재:
1. Chain nudge = `_chain_nudge_done` one-shot.
2. Skill runner 캐시 부재 → 중복 호출 silent repeat.
3. Severity 경로별 declared 그대로 (body 무시).
4. Auto-login 실패 시 Brain 에 pivot 신호 없음.
5. `test_idor` enumerate 결과에서 자동 큐잉 로직 부재.
6. CHAIN 대시보드가 edge 케이스에만 노출.
7. `finish_scan` gate 가 `_desired` 재계산 안 함.

## Fix
- **Chain nudge 재주입**: `_last_chain_nudge_iter` gap 체크 (6 iter).
- **CHAIN INTELLIGENCE 대시보드**: findings ≥ 2 상시 노출, 5×7 템플릿.
- **skill_runner 캐시 escalation**: hit#1 soft → #2 strong+untried → #3+ BLOCK. `_skill_override` alias 로 다른 args 재실행.
- **`_adjust_severity()`**: masked > 60% → low, raw `jdbc:|mongodb://` → critical.
- **Auto-login adaptive**: form 파싱 + creds 확대 + Enter fallback + PIVOT 메시지.
- **test_idor auto-queue**: regex `^(/[^?]*?/)\d+(/|$)` → url_pattern 큐잉.
- **finish_scan gate**: `_fin_desired = max(3, findings // 3)` 재계산, 부족 시 top-4 pairwise `link_chain()` 템플릿.

## Lessons
- Brain 이 "X 안 한다" 싶으면 프롬프트가 아니라 **X 출력이 다음 iter 로 흐르는 경로** 부터 확인.
- `_done` one-shot 플래그는 거의 항상 버그 — iter-gap cycling 으로 대체.
- 같은 skill 재실행은 캐시 + nudge + `_skill_override` alias 조합.
- Severity 는 declared 고정 금지 — body-aware oracle 필수.
- 자동 동작은 성공·실패 모두 Brain 메시지로 — silent fail 금지.
