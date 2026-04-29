---
name: P8 Synthesis
type: pipeline
status: active
when_to_read: 공격 체인 합성 / 크로스레이어 연결 / 공격 트리 탐색 / 방어 시뮬레이션
updated: 2026-04-16
sources:
  - ../../../src/vxis/synthesis/chain_builder.py
  - ../../../src/vxis/synthesis/cross_protocol.py
  - ../../../src/vxis/synthesis/defense_simulator.py
  - ../../../src/vxis/synthesis/poc_generator.py
related:
  - ./P5_special.md
  - ./P11_mutation.md
  - ./P6_ncc_style.md
code_anchors:
  - src/vxis/synthesis/chain_builder.py
  - src/vxis/synthesis/cross_protocol.py:SynthesizedChain
  - src/vxis/synthesis/poc_generator.py
---
# P8 — Synthesis

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 5 Chain Analysis |
| 앞 단계 | P5 Special / P7 Hardware |
| 뒤 단계 | P11 Mutation |
| 역할 | 개별 finding 들을 공격 체인으로 합성 |
| 엔진 | LLM 분기 추론 + 공격 트리 BFS |
| 출력 | `SynthesizedChain` (step 리스트 + PoC) |
| 부산물 | defense_simulator, poc_generator, red_vs_blue |

## TL;DR
여러 레이어의 findings 를 "이걸로 뭘 더 할 수 있나?" 반복 질의로 체인 구성. depth>2 & 레이어≥2 시 크로스레이어 체인 등록. PoC 자동 생성, 방어 시뮬레이션 병행.

## Stage
Chain Analysis — exploitation(P5/P7) 결과를 크라운 주얼(admin/DB/RCE)까지 연결.

## Inputs-Outputs
- Input: `Finding` 리스트 (여러 레이어).
- Output: `SynthesizedChain` 리스트 + PoC 스크립트 + defense plan.

## Triggers
- Director 가 findings ≥ 3 시 `ChainBuilder.build()` 호출.
- scan_loop chain nudge 가 link_chain tool 호출.

## Related Pipelines
- [P5 Special](./P5_special.md) — 앞 단계 (findings 공급)
- [P11 Mutation](./P11_mutation.md) — 뒤 단계 (체인 변이로 대안 경로 증명)
- [P6 NCC Style](./P6_ncc_style.md) — 체인을 리포트에 포함
