---
name: scan_loop
type: module
status: active
when_to_read: Brain ReAct 루프 구조 / skill 스케줄·sweep / auto-login / chain nudge / finish_scan gate 조건
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/scan_loop.py
related:
  - ./skill_runner.md
  - ./brain.md
  - ../../concepts/brain_first.md
code_anchors:
  - src/vxis/agent/scan_loop.py:ScanAgentLoop
  - src/vxis/agent/scan_loop.py:ScanLoopState
  - src/vxis/agent/scan_loop.py:DIRECTOR_PROMPT_TEMPLATE
---
# scan_loop

## 핵심 사실
| 항목 | 값 |
|---|---|
| Role | Brain 이 phase 루프 돌리는 단일 ReAct 엔진 |
| Loop | 분석 → 결정 → 실행 → 해석 → 다음 행동 |
| State | `ScanLoopState` (messages, iteration, findings, verdict_counts) |
| Max iters | 기본 300 |
| Auto-login | 비밀번호 필드 감지 시 `browser_fill_form` 자동 주입 (1회) |
| Skill sweep | iter ≥ 25 에서 누락 skill 일괄 실행 (blind spot 방지) |
| finish_scan | `_desired` (iters, findings, chains) 미달 시 REJECTED |
| Context 추적 | `peak_context_bytes` 로 messages 최대 크기 샘플링 |

## TL;DR
Brain LLM 호출 → ToolRegistry 에서 tool 실행 → 결과 해석 → 다음 결정 반복. chain nudge 로 연쇄 공격 유도, sweep 으로 skill 커버리지 강제, finish_scan 은 gate 로 조기 종료 방지.

## Key Surfaces
- `ScanAgentLoop.run()` — 메인 async 루프. iteration 마다 Brain 호출 → tool dispatch → messages 갱신.
- `ScanLoopState.update_peak_size()` — messages JSON 바이트 샘플링, Task 14 벤치마크용.
- `DIRECTOR_PROMPT_TEMPLATE` — stuck 감지 시 상위 모델에 "다음 tool 정하라" 프롬프트.
- Auto-login 블록 (~L1381-L1440) — DOM 에서 password 필드 감지 → 1회 `_auto_login_done` flag.
- Skill sweep 블록 — iter ≥ 25 시 `SKILL_REGISTRY - _skills_ever_called` 자동 주입.
- Chain nudge 블록 (~L1931) — findings ≥ 3 & chains = 0 시 "CHAIN ANALYSIS PHASE" 메시지 주입.
- finish_scan 검증 (~L965-L1062) — min iters / findings / chains 미달 시 reject 메시지.

## Invariants
- Brain 호출 전 context 는 state 요약만 (raw tool output 재주입 금지 → [ai_context_hygiene](../../concepts/ai_context_hygiene.md)).
- 한 iteration 당 최대 1 tool 호출. 중복 호출 5회 시 강제 전환.
- `finish_scan` 은 `_desired` 충족 시에만 완료, 아니면 reject 메시지 주입 후 루프 지속.
- `_auto_login_done` 은 scan 당 1회만 True — 재로그인 루프 방지.
- `peak_context_bytes` 는 monotonically increasing — decay 없음.

## Related
- [skill_runner](./skill_runner.md) — skill 실행·캐시 escalation
- [brain](./brain.md) — LLM 호출 choke point
- [brain_first](../../concepts/brain_first.md) — 이 루프가 구현하는 절대 원칙
