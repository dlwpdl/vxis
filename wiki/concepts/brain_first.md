---
name: Brain-First Architecture
type: concept
status: active
when_to_read: VXIS 절대 원칙 / 하드코딩 금지 이유 / Brain이 공격 주체여야 하는 근거 / claude -p 우선 조건
updated: 2026-04-16
sources:
  - ../../CLAUDE.md
related:
  - ./vxis_architecture.md
  - ./chain_intelligence.md
  - ./payload_rotation.md
  - ../entities/modules/scan_loop.md
  - ../entities/modules/brain.md
---
# Brain-First Architecture

## 핵심 사실
| 항목 | 값 |
|---|---|
| 원칙 | Brain(AI)이 모든 Phase의 주인공. Hands/Eyes/X-Ray는 실행만 |
| 금지 | 하드코딩 엔드포인트·페이로드, 정적 grep 스코어링, 1회성 batch Brain 호출 |
| Phase 구조 | 분석 → 결정 → 실행 → 해석 → 다음 행동 (루프) |
| 종착점 | Crown Jewel (admin takeover / DB dump / RCE / data exfil) |
| LLM 우선순위 | Claude Code 세션 또는 Claude 모델 명시 시 `claude -p` 우선, 실패 시만 API 폴백 |
| 적용 범위 예외 | 다른 모델(gpt/gemini/deepseek) 명시적 사용 시는 해당 API 직접 호출 |

## TL;DR
Brain은 시니어 펜테스터의 두뇌 — 타겟을 보고 동적으로 엔드포인트·페이로드를 생성하고 응답을 해석해 체이닝한다. 하드코딩 로직은 알려진 패턴만 잡지만 Brain-First는 새 공격 벡터를 창의적으로 발견·연결한다. Claude Code 환경에선 `claude -p` 서브프로세스가 1순위.

## What
Brain-First는 VXIS의 최상위 아키텍처 원칙이다. 모든 파이프라인(Web/Game/Mobile)의 모든 Phase는 `Brain.plan → Hands 실행 → Brain.interpret → Brain.chain` 루프를 강제한다. Brain은 "가끔 호출되는 헬퍼"가 아니라 매 의사결정의 주체다.

## Why
일반 스캐너는 하드코딩된 룰 매칭으로 알려진 패턴만 잡는다. Brain-First는 응답을 해석해 다음 공격을 생성하므로 다단계 체인(SQLi → creds 덤프 → admin 로그인 → IDOR)을 자동으로 구성할 수 있다. 이게 VXIS가 scanner가 아닌 pentester를 지향하는 이유다. 1회성 batch 패턴(`_consult_agent_brain_batch` 류)으로 회귀하면 체이닝 지능이 증발한다.

## How
- 파이프라인 코드는 Brain.ask/analyze가 핵심 결정을 내리도록 작성. Hands/Eyes/X-Ray는 "시키는 걸 실행"만.
- 페이로드는 round 기반 로테이션으로 Brain이 다시 시도(→ [payload_rotation](./payload_rotation.md)).
- 결과는 state-not-result 원칙으로 요약해 다음 iter에 재주입(→ [ai_context_hygiene](./ai_context_hygiene.md)).
- 체인은 `link_chain` 호출로 박제되고, 부족 시 scan_loop이 nudge 재주입(→ [chain_intelligence](./chain_intelligence.md)).
- LLM 호출: `brain.py`의 `_call_claude_subprocess()` 우선 경로. 다른 모델 벤치마크는 예외.

## Related
- [vxis_architecture](./vxis_architecture.md) — Brain/Hands/Eyes/X-Ray 역할 분담
- [chain_intelligence](./chain_intelligence.md) — Brain이 findings를 체이닝하는 메커니즘
- [scan_loop](../entities/modules/scan_loop.md) — Brain 루프 구현체
