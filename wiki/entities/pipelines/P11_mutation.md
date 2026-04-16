---
name: P11 Mutation
type: pipeline
status: active
when_to_read: 체인 변이 / 대안 경로 증명 / "부분 패치 허상" 검증 / NetworkX 그래프 탐색
updated: 2026-04-16
sources:
  - ../../../src/vxis/mutation/chain_mutator.py
related:
  - ./P8_synthesis.md
  - ./P6_ncc_style.md
code_anchors:
  - src/vxis/mutation/chain_mutator.py
---
# P11 — Mutation

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 5 Chain Analysis |
| 앞 단계 | P8 Synthesis |
| 뒤 단계 | P6 NCC Style (report) |
| 역할 | 체인 변이 — 같은 목적지로 가는 대안 경로 증명 |
| Phase 1 | NetworkX BFS/DFS 동등 경로 탐색 (Tier 0) |
| Phase 2 | LLM 단계 대체 변이 생성 (Tier 3) |
| 목적 | "SQLi 막았다고? 3개 더 있다" — 부분 패치 허상 증명 |

## TL;DR
P8 이 만든 체인에서 "이 단계 패치해도 다른 경로로 같은 목표 달성 가능" 여부를 수학적으로 증명. NetworkX 그래프에서 동등 경로를 찾고, LLM 이 단계 대체 변이 생성.

## Stage
Chain Analysis — Synthesis 이후 내성 검증. 방어 공학에 전달.

## Inputs-Outputs
- Input: `SynthesizedChain` + 공격 그래프.
- Output: 대안 경로 리스트 + mutation 통계 (coverage, resilience).

## Triggers
- P8 가 체인 완성 후 `ChainMutator.mutate(chain)` 호출.
- 리포트 생성 전 방어 추천 계산 시.

## Related Pipelines
- [P8 Synthesis](./P8_synthesis.md) — 앞 단계 (원본 체인)
- [P6 NCC Style](./P6_ncc_style.md) — 뒤 단계 (변이 결과를 리포트에)
