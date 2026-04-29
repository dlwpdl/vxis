---
name: ADR-002 — Brain LLM claude -p First
type: decision
status: active
when_to_read: Brain LLM 호출 우선순위 / claude -p 서브프로세스 vs API / 다른 모델 벤치마크 예외 / 적용 범위
updated: 2026-04-16
sources:
  - /Users/eliot/.claude/projects/-Users-eliot-Desktop---vxis/memory/feedback_brain_claude_first.md
related:
  - ../concepts/brain_first.md
---
# ADR-002 — Brain LLM: claude -p Subprocess First

## 핵심 사실
| 항목 | 값 |
|---|---|
| Status | Accepted |
| Date | 2026-04-16 (Eliot 2026-04-08 명시) |
| 1순위 경로 | `_call_claude_subprocess()` — `claude -p` 서브프로세스 |
| Fallback | Anthropic API (subprocess 실패 시만) |
| 적용 조건 | Claude Code 세션 내 VXIS 실행 OR Claude 모델 명시 |
| 적용 제외 | gpt / gemini / deepseek 명시 OR 벤치마크 목적 모델 고정 |

## TL;DR
Claude Code 세션 안이거나 Claude 모델을 명시한 경우 Brain 은 `claude -p` 서브프로세스 1 순위. 실패 시에만 Anthropic API fallback. 다른 모델 (gpt/gemini/deepseek) 명시 사용 시는 해당 API 직접 호출 — claude 로 강제 변환 금지.

## Context
Brain (`agent/brain.py`) 이 LLM choke point. Claude Code 세션 안에서 `claude -p` 서브프로세스로 LLM 접근 가능 — (a) API 키 관리 불필요 (b) Claude Code 컨텍스트·도구 공유 (c) usage 가 세션 귀속. 반면 API 는 별도 키·billing·rate. VXIS 는 모델 agnostic 도 목표 — 벤치마크 시 다른 모델 필요.

## Options
1. **항상 API 우선** — Claude Code 혜택 포기.
2. **환경별 분기** — Claude Code 에선 `claude -p` 우선, 그 외엔 API.
3. **모든 호출 `claude -p` 강제** — 다른 모델 사용 불가.

## Decision
옵션 2 채택. 적용 조건:
- Claude Code 세션 내 VXIS 실행 → `_call_claude_subprocess()` 1 순위, 실패 시 API fallback.
- Claude 모델 명시 시 동일 규칙.
- gpt / gemini / deepseek 등 명시 → 해당 API 직접. claude 강요 금지.
- Phase A 같은 마이그레이션 검증은 baseline / post-migration **같은 모델** 이면 충분.

## Consequences
- **Pro**: Claude Code 세션 사용 시 키·billing 관리 제로.
- **Pro**: 모델 벤치마크 시 gpt/gemini/deepseek 자유 사용.
- **Con**: `brain.py` 에 환경 감지 + 2 경로 라우팅 복잡도. `_call_claude_subprocess()` 현재 dead code — Phase B 이후 연결 예정 (기술 부채 추적).
- **Con**: 동일 모델이라도 `claude -p` 경로와 API 경로 응답이 미묘하게 다를 수 있어 reproducibility 주의.
