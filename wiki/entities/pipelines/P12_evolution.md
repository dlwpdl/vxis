---
name: P12 Evolution
type: pipeline
status: active
when_to_read: 자기 진화 에이전트 합성 / 부족 능력 자동 생성 / 안전 검증 / 다음 미션 피드백
updated: 2026-04-16
sources:
  - ../../../src/vxis/evolution/agent_synthesizer.py
related:
  - ./P18_collective_kb.md
  - ./P6_ncc_style.md
code_anchors:
  - src/vxis/evolution/agent_synthesizer.py
---
# P12 — Evolution

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 8 Learning |
| 앞 단계 | P6 NCC Style (post-report) |
| 뒤 단계 | P18 Collective KB |
| 역할 | 부족 능력 식별 → LLM 으로 새 에이전트 코드 자동 생성 |
| 안전 | ast.parse 구문 검증 + 위험 패턴(exec/eval/__import__) 차단 |
| 격리 | `.generated_agents/` 디렉토리, 자동 실행 금지 |
| 승인 | 파일 저장 후 수동 승인 필수 |

## TL;DR
미션 후 "X 에이전트가 없어서 놓친 취약점" 을 LLM 이 새 Python 에이전트 코드로 생성. 구문·정적 검증 후 격리 디렉토리에 저장, 승인 후 다음 미션에 포함.

## Stage
Learning — 리포트 완료 후 자기 개선 루프. Growth Loop 의 핵심.

## Inputs-Outputs
- Input: 미션 결과 (findings, 누락 영역, coverage gap).
- Output: 생성된 에이전트 파일 (`.generated_agents/<name>.py`) — 승인 대기.

## Triggers
- `scripts/growth_loop.py --weekly` 에서 주간 호출.
- 대규모 miss 감지 시 자동 트리거.

## Related Pipelines
- [P6 NCC Style](./P6_ncc_style.md) — 앞 단계 (리포트에서 gap 추출)
- [P18 Collective KB](./P18_collective_kb.md) — 뒤 단계 (학습 누적)
