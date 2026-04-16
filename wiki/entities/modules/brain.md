---
name: brain
type: module
status: active
when_to_read: Brain LLM 호출 choke point / claude -p 우선 조건 / fallback chain / think() 엔트리 / token 카운터
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/brain.py
  - ../../../src/vxis/agent/brain_interactive.py
  - ../../../src/vxis/agent/brain_filebased.py
related:
  - ./scan_loop.md
  - ../../concepts/brain_first.md
code_anchors:
  - src/vxis/agent/brain.py:AgentBrain
  - src/vxis/agent/brain.py:_call_llm_direct
  - src/vxis/agent/brain.py:_call_llm_with_fallback
  - src/vxis/agent/brain.py:AgentBrain.think
---
# brain

## 핵심 사실
| 항목 | 값 |
|---|---|
| Role | VXIS 의사결정 엔진 — PERCEIVE→RECALL→REASON→CHAIN→REFLECT→ACT→LEARN |
| 진입점 | `AgentBrain.think(observation)` |
| Choke point | `_call_llm_direct` (모든 provider 경로 단일 진입) |
| 우선 경로 | `claude -p` 서브프로세스 (Claude Code 세션 또는 Claude 모델 명시 시) |
| Fallback chain | claude -p → Anthropic API → Uncensored (Ollama/Together) → Standard (OpenAI/Gemini) |
| 변종 | `InteractiveBrain`, `FileBasedBrain` — 프로토콜 구현 |
| Counter | `_LLM_CALL_COUNT`, `_BRAIN_DECISION_COUNT` (thread-safe, Task 14 메트릭) |

## TL;DR
모든 Brain 호출은 `think()` 한 곳으로 수렴, 프로바이더 호출은 `_call_llm_direct` 단일 choke point 통과. Claude Code 세션에선 `claude -p` 서브프로세스 우선, 실패하면 Anthropic API → OSS/third-party 순서로 fallback.

## Key Surfaces
- `AgentBrain.think(observation) -> list[AgentAction]` — 동기 진입점. `_BRAIN_DECISION_COUNT` 증가 후 LLM 호출.
- `AgentBrain.think_in_loop(...)` — async 루프 버전 (scan_loop 에서 사용).
- `_call_llm_direct(...)` — 최하위 LLM 호출 choke point. `_LLM_CALL_COUNT` 증가.
- `_call_llm_with_fallback(system, user)` — fallback chain 오케스트레이션.
- `_build_fallback_chain()` — provider 리스트 순서 결정. uncensored 모드 시 Ollama/DeepSeek 우선.
- `get_llm_call_count()`, `get_brain_decision_count()` — 벤치마크 counter getter.
- `_call_claude_subprocess(...)` — `claude -p` 서브프로세스 실행, ANSI 코드 sanitize.

## Invariants
- Claude 모델 명시 또는 Claude Code 세션 감지 시 `claude -p` 우선 — 다른 provider 로 우회 금지.
- 다른 모델(gpt/gemini/deepseek) 명시적 지정 시에만 해당 API 직접 호출.
- `_LLM_CALL_COUNT` 는 프로세스 글로벌 — scan 경계 없이 누적.
- Fallback 은 예외 시에만 — 성공 응답이면 즉시 반환.
- Ghost 모드(uncensored) 는 Ollama 로컬 → Together DeepSeek → 표준 체인 순서 강제.
- Batch 호출 패턴(`_consult_agent_brain_batch`) 으로 회귀 금지 — iteration 당 think() 1회.

## Related
- [scan_loop](./scan_loop.md) — Brain.think() 를 iteration 마다 호출
- [brain_first](../../concepts/brain_first.md) — 이 모듈이 구현하는 아키텍처 원칙
