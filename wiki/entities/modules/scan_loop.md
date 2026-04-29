---
name: scan_loop
type: module
status: active
when_to_read: Brain ReAct 루프 구조 / skill 스케줄·sweep / auto-login / chain nudge / finish_scan gate 조건 / 0-finding 거부 / desktop VC 크레딧 경로 / TUI live sync contract
updated: 2026-04-29
sources:
  - ../../../src/vxis/agent/scan_loop.py
related:
  - ./skill_runner.md
  - ./brain.md
  - ../../concepts/brain_first.md
  - ../../concepts/chain_intelligence.md
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
| State | `ScanLoopState` (messages, iteration, findings, verdict_counts, scan_todos, branches, waiting_reason) |
| Max iters | 기본 300 |
| Auto-login | 비밀번호 필드 감지 시 `browser_fill_form` 자동 주입 (1회) |
| Skill sweep | iter ≥ 25 에서 누락 skill 일괄 실행 (blind spot 방지) |
| finish_scan gate | min_iters 미달 / **0 findings** (Q11) / chains < `_desired` 3 단 reject |
| Skill 크레딧 (Q10) | `_real_skills_completed` (실명) 와 `_skills_completed` (alias 포함) 분리 — 리턴 dict 는 real names 만 |
| Context 추적 | `peak_context_bytes` 로 messages 최대 크기 샘플링 |
| TUI contract | `brain_thinking` / `attack` / `hit` / `chain_*` 는 scan 중 실시간 방출되어야 함. 조용하면 UX 버그 |
| Control-plane contract | `control_plane` 이벤트로 todo / branch / current block / shared notes / token usage 를 scan 중 계속 동기화해야 함 |
| Planning vs execution | "로드/계획/대기" 와 실제 tool dispatch/evidence/finding 은 분리해 보여야 함. plan-only chatter 는 실행으로 치지 않음 |
| Root continuity | `report_finding` 뒤에는 follow-up branch dossier 가 자동 생성되어 다음 pivot 을 루트가 계속 추적해야 함 |

## TL;DR
Brain LLM 호출 → ToolRegistry 에서 tool 실행 → 결과 해석 → 다음 결정 반복. chain nudge 로 연쇄 공격 유도, sweep 으로 skill 커버리지 강제, finish_scan 은 gate 로 조기 종료 방지.

## Key Surfaces
- `ScanAgentLoop.run()` — 메인 async 루프. iteration 마다 Brain 호출 → tool dispatch → messages 갱신.
- `ScanLoopState.update_peak_size()` — messages JSON 바이트 샘플링, Task 14 벤치마크용.
- `DIRECTOR_PROMPT_TEMPLATE` — stuck 감지 시 상위 모델에 "다음 tool 정하라" 프롬프트.
- Auto-login 블록 (~L1381-L1440) — DOM 에서 password 필드 감지 → 1회 `_auto_login_done` flag.
- Brain 프롬프트 `browser_fill_form` 예시 (~L93-99) — 2026-04-20 부터 DOM-first 2-step (analyze_dom → fill_form). SQLi·field-name 하드코딩 제거.
- Skill sweep 블록 — iter ≥ 25 시 `SKILL_REGISTRY - _skills_ever_called` 자동 주입.
- Chain nudge 블록 (~L1931) — findings ≥ 3 & chains = 0 시 "CHAIN ANALYSIS PHASE" 메시지 주입.
- Follow-up branch spawn — auth / access control / SQLi / disclosure / XSS finding 이 보고되면 후속 pivot branch (`post-auth-enum`, `admin-access-control`, `write-idor`, `db-impact` 등) 자동 생성, 이후 dashboard 와 TUI 에 계속 주입.
- finish_scan 검증 (~L1095-L1230) — 3 단 ladder: (1) `iter < min_iters` reject, (2) **`_get_findings()` 비어 있음 → reject** (Q11, L1136), (3) `findings ≥ 3 AND chains < _desired` → reject. 0-finding 분기는 등록 tool 목록을 nudge 에 포함시켜 Brain 에 다음 수단 제시 (`run_skill` / `shell_exec` / `report_finding`).
- 실명 vs alias 트래킹 (~L597-L602, L880-L894, L1278) — `_skills_completed` 는 sweep alias (`test_dylib_hijack__sweep25`) 포함, `_real_skills_completed` 는 dedupe 한 real names. Brain-direct `run_skill` 도 양쪽 set 에 add. run() 리턴 dict 의 `skills_completed` 는 `_real_skills_completed` 만 노출 → pipeline `_DESKTOP_SKILL_TO_VECTORS` lookup 적중 (Q10).

## Invariants
- Brain 호출 전 context 는 state 요약만 (raw tool output 재주입 금지 → [ai_context_hygiene](../../concepts/ai_context_hygiene.md)).
- 한 iteration 당 최대 1 tool 호출. 중복 호출 5회 시 강제 전환.
- `finish_scan` 은 `_desired` 충족 시에만 완료, 아니면 reject 메시지 주입 후 루프 지속.
- `_auto_login_done` 은 scan 당 1회만 True — 재로그인 루프 방지.
- `peak_context_bytes` 는 monotonically increasing — decay 없음.
- TUI 는 최종 요약만이 아니라 **현재 루프 상태**를 보여야 한다. `recent hit=?`, chain 공란, todo/branch 미동기화, token usage 공란, 무진행처럼 보이는 정적 phase 패널은 회귀로 본다.
- TUI 의 planning 문구는 tool 실행/feed 와 분리되어야 한다. operator 가 "말만 하는 중"과 "실제로 때리는 중"을 헷갈리면 안 된다.
- branch dossier 는 context compression 이후에도 다음 iteration 에 다시 주입되어야 한다. 긴 런에서도 root 가 branch objective / next step / blocker 를 잃으면 회귀다.

## Related
- [skill_runner](./skill_runner.md) — skill 실행·캐시 escalation
- [brain](./brain.md) — LLM 호출 choke point
- [brain_first](../../concepts/brain_first.md) — 이 루프가 구현하는 절대 원칙
