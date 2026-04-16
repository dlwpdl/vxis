---
name: P3 Hypothesis
type: pipeline
status: active
when_to_read: 가설 우선순위 큐 / probability·impact 스코어링 / 테스트 상태 FSM
updated: 2026-04-16
sources:
  - ../../../src/vxis/graph/hypothesis.py
related:
  - ./P2_agents.md
  - ./P5_special.md
  - ./P8_synthesis.md
code_anchors:
  - src/vxis/graph/hypothesis.py:Hypothesis
  - src/vxis/graph/hypothesis.py:HypothesisQueue
  - src/vxis/graph/hypothesis.py:HypothesisGenerator
---
# P3 — Hypothesis

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 3 Intelligence |
| 앞 단계 | P2 Agents |
| 뒤 단계 | P5 Special (exploitation) |
| 역할 | 가설 우선순위 큐 — "이 공격 해볼 만한가?" |
| 스코어 | `probability * impact` (heapq 우선순위) |
| 상태 | PENDING → TESTING → CONFIRMED / REJECTED |
| 제안 | `suggested_agent` + `suggested_tool` |

## TL;DR
에이전트들이 생성한 가설을 우선순위 큐로 관리. `probability * impact` 로 정렬, 상위부터 exploitation 에 투입. 테스트 결과에 따라 상태 전이, REJECTED 는 학습 데이터로 KnowledgeStore 에 누적.

## Stage
Intelligence — P2 다음. 가설 스코어 기반 exploitation 대상 선정.

## Inputs-Outputs
- Input: `Hypothesis` (title, rationale, probability, impact, suggested_agent/tool).
- Output: 우선순위 정렬된 가설 리스트 → P5 Special 에 dispatch.

## Triggers
- P2 에이전트의 `queue.push(hypothesis)` 호출.
- Director 가 다음 iteration 준비 시 `queue.pop()`.

## Related Pipelines
- [P2 Agents](./P2_agents.md) — 앞 단계 (가설 생성)
- [P5 Special](./P5_special.md) — 뒤 단계 (가설 실행)
- [P8 Synthesis](./P8_synthesis.md) — 확정된 가설을 체인으로 합성
