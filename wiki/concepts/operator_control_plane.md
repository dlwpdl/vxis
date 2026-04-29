---
name: Operator Control Plane
type: concept
status: active
when_to_read: TUI 가 조용해 보이는 이유 / planning 과 execution 분리 / todo·branch·waiting 상태를 왜 1급 상태로 다뤄야 하는지 / Strix 비교 근거
updated: 2026-04-29
sources:
  - ../../../src/vxis/agent/scan_loop.py
  - ../../../src/vxis/cli/scan_display.py
  - ../../../../strix/strix/agents/StrixAgent/system_prompt.jinja
  - ../../../../strix/strix/agents/base_agent.py
  - ../../../../strix/strix/tools/todo/todo_actions.py
  - ../../../../strix/strix/tools/notes/notes_actions.py
  - ../../../../strix/strix/interface/tui.py
related:
  - ./brain_first.md
  - ../entities/modules/scan_loop.md
code_anchors:
  - src/vxis/agent/scan_loop.py:ScanAgentLoop
  - src/vxis/cli/scan_display.py:ScanLiveDisplay
---
# Operator Control Plane

## 핵심 사실
| 항목 | 값 |
|---|---|
| 문제 정의 | "에이전트가 생각 중인지, 대기 중인지, 실제 실행 중인지"가 분리되지 않으면 운영자는 정지로 오해함 |
| Strix 강점 | tool-only 루프, waiting 상태, todo, notes, agent graph, operator-to-agent 메시지 |
| VXIS 현상 | single-loop 가 실제 일은 해도 branch/todo/wait reason 이 없어 조용해 보임 |
| 핵심 분리 | planning / executing / evidence / validated 를 별도 상태로 보여야 함 |
| 1급 상태 | todo list, branch owner, waiting reason, shared notes, validation state, token/cost telemetry |
| 금지 패턴 | plan-only chatter 를 실행처럼 보이게 하는 UI |

## TL;DR
좋은 보안 에이전트 TUI 는 "예쁘게 보여주는 화면"이 아니라 실행 제어면이다. Strix 는 todo·waiting·subagent graph 를 1급 상태로 올렸고, 그래서 운영자가 현재 진행을 오해하지 않는다. VXIS도 같은 문제를 풀어야 하지만, AGPL 구조를 베끼지 말고 VXIS의 vector/verifier/scoring 중심 구조에 맞는 control plane 을 만들어야 한다.

## What
Strix 를 보면 차이는 모델 지능 자체보다 운영 제어면이 더 크다. system prompt 가 "tool call 없는 계획 문구는 실행 정지"라고 강하게 규정하고, root agent 는 todo 와 subagent graph 를 관리하며, idle 상태는 `wait_for_message` 로 명시한다. notes 는 run memory 로 남고, TUI 는 running/waiting/completed 와 agent graph, token/cost, Caido 연결 상태까지 보여준다.

VXIS 는 아직 `ScanAgentLoop` 단일 루프에 planning, execution, auto-rescue, reporting 힌트가 섞여 있다. 그래서 실제 실행이 있어도 operator 는 "지금 뭐 하는지"를 읽기 어렵다.

## Why
보안 테스트는 긴 대기와 병렬 분기가 많다. 대기 이유, 현재 집중 벡터, 남은 검증, validation owner 가 없으면 운영자는 정지로 오해하고, 에이전트는 같은 생각을 반복한다. 반대로 control plane 이 있으면 coverage 관리, branch handoff, PoC 검증, 최종 보고까지 흐름이 끊기지 않는다.

## How
VXIS 는 Strix 를 그대로 복제하지 말고 다음 1급 상태를 도입해야 한다.

- `scan_todos`: attack surface / validation / reporting 작업 큐
- `branches`: 각 가설의 owner, 상태, 최근 증거, 다음 액션
- `waiting_reason`: 네트워크/브라우저/서브태스크/사용자승인 대기 이유
- `shared_notes`: JS route, auth flow, failed payload, high-value endpoint 요약
- `evidence_feed`: 실제 실행 결과와 planning chatter 분리
- `llm_usage`: provider/model, llm_calls, brain_decisions, token usage, estimated cost
- `follow_up_pivots`: finding 이 나오면 후속 branch dossier 를 자동 생성해 root 가 다음 depth 를 잃지 않게 유지

TUI 는 최소한 아래 4열을 유지해야 한다.
- Planning
- Executing
- Evidence
- Validated

그리고 operator 는 root loop 에서 끝까지 추적하다가 필요 시 branch 상세로 내려가야 한다. Strix 의 agent drill-down 경험에서 배울 점은 여기에 있다. VXIS 는 subagent graph 가 없더라도, 최소한 branch/todo/current block 을 root TUI 에서 항상 보고 branch 상세를 열 수 있어야 한다.

## Related
- [brain_first](./brain_first.md) — Brain 이 주도하지만 상태는 외부화되어야 함
- [scan_loop](../entities/modules/scan_loop.md) — 현재 single-loop 의 책임과 TUI contract
