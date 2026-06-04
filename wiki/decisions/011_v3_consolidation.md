---
name: ADR-011 — Cognitive Engine v3 Consolidation (DAG 단일 prioritizer · PTI 메모리 통합)
type: decision
status: active
when_to_read: v3 가 왜 build 아니라 integrate 인지 / 중복 시스템(메모리·hypothesis·model table·prioritizer) 통합 결정 / 삭제를 왜 미루나 / dual-write 롤백
updated: 2026-06-02
sources:
  - ../../docs/superpowers/plans/2026-06-02-cognitive-engine-v3.md
  - ../../docs/superpowers/plans/2026-06-02-cognitive-engine-v3-phase0-consolidation.md
related:
  - ./012_verifier_spine.md
  - ./013_profile_scan_policy.md
  - ./001_agpl_forbidden.md
code_anchors:
  - src/vxis/agent/memory.py:AgentMemory
  - src/vxis/agent/hypothesis/dag.py:HypothesisDAG
  - src/vxis/agent/routing/cost_router.py:ROUTE_TABLE
  - src/vxis/agent/scan_loop_state.py:ensure_vector_candidate
---
# ADR-011 — Cognitive Engine v3 Consolidation

## 핵심 사실
| 항목 | 값 |
|---|---|
| Status | Accepted |
| Date | 2026-06-02 |
| 발견 | v3 컴포넌트 라이브러리 ~80% 가 `VXIS_V3` 플래그 뒤 이미 구현됨 (57 테스트 통과) |
| 중복 메모리 | `AgentMemory`(orchestrator/brain 소비) + `query_scan_memory` JSON KB — 2개 별개 |
| 중복 hypothesis | `agent/hypothesis/dag.py` + `graph/hypothesis.py` — `Hypothesis` 충돌 |
| 중복 model table | `cost_router.ROUTE_TABLE` + `hybrid_config` + `brain._model_role_for_decision_class` — 3개 |
| 중복 prioritizer | `vector_candidates` + `scan_todos` + `branches` + control-state — 4개 결합 |
| 롤백 안전 | 삭제는 Phase 0 아님 — dual-write(`VXIS_V3_MEMORY` default off) 후 later-phase 삭제 |

## TL;DR
v3 는 신규 빌드가 아니라 **통합**이다. 메모리 2개·hypothesis 2개·model table 3개·prioritizer 4개 중복을 각각 하나로 합친다. 핵심 원칙: DAG(`HypothesisNode`/`HypothesisDAG`)가 유일한 prioritizer, PTI 가 두 레거시 메모리를 흡수, model 해석은 `brain._model_role_for_decision_class` 하나. 삭제는 플래그로 보호 안 되므로 dual-write 패리티 윈도우 후로 미룬다.

## Context
원래 v3 plan 은 "Create `src/vxis/pti/`…" 처럼 신규 빌드로 쓰였으나, 8-에이전트 plan-review 가 코드와 대조한 결과 라이브러리 대부분이 이미 존재하고 4종의 중복 시스템이 미해결임을 발견. 특히 `AgentMemory` 삭제를 그냥 하면 `VXIS_V3=off` 로 복구 불가능한 cutover 가 된다.

## Options
1. **신규 빌드로 진행** — 이미 있는 파일 재생성·중복 영구화. 기각.
2. **integrate + consolidate, 삭제는 dual-write 후 연기** — 채택.
3. **중복 그대로 공존** — 진실원천 N개, bookkeeping 낭비. 기각.

## Decision
옵션 2. Phase 0 가 선행: (a) `VXIS_V3_MEMORY` 뒤 dual-write 로 PTI 흡수, 레거시 삭제는 prod 패리티 후 Phase 2; (b) DAG 클래스 `HypothesisNode` 로 개명; (c) `cost_router.ROUTE_TABLE` 삭제, `brain` map 단일화; (d) prioritizer 필드 매핑표 후 DAG 로 흡수, 레거시 finish 헬퍼 call-site 마이그레이션.

## Consequences
- **Pro**: 진실원천 1개씩. 다음 agent 가 어떤 시스템이 살아있는지 명확.
- **Pro**: dual-write 로 `VXIS_V3_MEMORY=off` 가 진짜 1-플래그 롤백.
- **Con**: 패리티 윈도우 동안 두 저장소 동시 유지 — 시크릿이 un-tenanted 레거시로 새지 않게 ScanMemory(요약만)로 제한.
- **Enforcement**: Phase 0 exit grep — `^class Hypothesis\b`·`ROUTE_TABLE`·legacy finish 헬퍼 = 0. `CONSOLIDATION.md` 가 삭제/이전 원장.
