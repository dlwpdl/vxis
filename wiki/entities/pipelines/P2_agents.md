---
name: P2 Agents
type: pipeline
status: active
when_to_read: 60+ 전문 에이전트 레지스트리 / 에이전트 동적 스폰 / 도메인별 공격 특화
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/agents/
  - ../../../src/vxis/agent/registry.py
related:
  - ./P1_director.md
  - ./P3_hypothesis.md
  - ../modules/brain.md
code_anchors:
  - src/vxis/agent/registry.py:spawn
  - src/vxis/agent/agents/__init__.py
---
# P2 — Agents

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 3 Intelligence |
| 앞 단계 | P1 Director |
| 뒤 단계 | P3 Hypothesis |
| 역할 | 도메인별 공격 전문 에이전트 |
| 레지스트리 | `agent/agents/` 60+ 에이전트 (web, api, cloud, game, mobile, identity, ...) |
| 스폰 | `registry.spawn(agent_name)` — 동적 생성 |
| 추천 | KnowledgeStore 기반 tool 추천/스킵 |

## TL;DR
Director 가 미션·기술 스택에 맞는 에이전트를 선택·스폰. 각 에이전트는 `AgentContext` 로 상태 공유하며 가설을 HypothesisQueue 에 push. web/api/cloud/game/mobile/identity/IoT/database 등 도메인 특화.

## Stage
Intelligence — Director 가 선택한 에이전트가 병렬로 가설 생성.

## Inputs-Outputs
- Input: `MissionConfig`, 초기 recon (tech stack, endpoints).
- Output: `Hypothesis` 리스트 → HypothesisQueue push.

## Triggers
- `DirectorAgent.select_initial_agents(mission)` 호출.
- 체인 확장 시 `AgentSelector.select()` 재호출.

## Related Pipelines
- [P1 Director](./P1_director.md) — 앞 단계 (에이전트 선택)
- [P3 Hypothesis](./P3_hypothesis.md) — 뒤 단계 (에이전트가 가설 push)
