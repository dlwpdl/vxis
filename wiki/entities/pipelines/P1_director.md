---
name: P1 Director
type: pipeline
status: active
when_to_read: 스캔 오케스트레이션 시작점 / 에이전트 선택 / 가설 큐 관리 / 미션 기반 전략
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/director.py
  - ../../../src/vxis/pipeline/scan_pipeline_v2.py
related:
  - ./P0_config.md
  - ./P2_agents.md
  - ./P4_cpr.md
  - ../modules/scan_loop.md
  - ../modules/brain.md
code_anchors:
  - src/vxis/agent/director.py:DirectorAgent
  - src/vxis/pipeline/scan_pipeline_v2.py:ScanPipelineV2
---
# P1 — Director

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 1 Foundation |
| 앞 단계 | P0 Config |
| 뒤 단계 | P2 Agents / P4 CPR (recon) |
| 역할 | 전략 지휘 — 에이전트 선택·가설 큐·체인 추론 |
| 핵심 | `DirectorAgent` + `ScanPipelineV2` (Strix-parity shim) |
| Phase 3 모듈 | ChainReasoner, KnowledgeStore, TokenRouter (lazy init) |

## TL;DR
P0 config 를 받아 미션 기반으로 초기 에이전트 선택, HypothesisQueue 초기화, ScanAgentLoop 구동. findings 를 ChainReasoner 로 연결하고 KnowledgeStore 에 학습 누적. `ScanPipelineV2` 는 기존 5234-line 파이프라인을 대체하는 thin shim.

## Stage
Foundation — Phase 3 전략적 오케스트레이터. ReAct 루프 주도.

## Inputs-Outputs
- Input: `VXISConfig`, `MissionConfig`, target.
- Output: `ScanContext` (findings, attack_chains, vxis_score, peak_context_bytes).

## Triggers
- `ScanPipelineV2().run_scan(target, mode)` 호출.
- `python -m vxis.cli scan --target ... --mode enterprise`.

## Related Pipelines
- [P0 Config](./P0_config.md) — 앞 단계
- [P2 Agents](./P2_agents.md) — 동적 스폰 대상
- [P4 CPR](./P4_cpr.md) — 초기 recon 호출
