---
name: P15 Digital Twin
type: pipeline
status: active
when_to_read: 사전 공격 리허설 / Docker 기술 스택 재현 / 공격 성공 확률 사전 평가 / 실타겟 소음 최소화
updated: 2026-04-16
sources:
  - ../../../src/vxis/twin/simulator.py
related:
  - ./P4_cpr.md
  - ./P13_biometrics.md
  - ./P5_special.md
code_anchors:
  - src/vxis/twin/simulator.py:TwinSimulator
  - src/vxis/twin/simulator.py:DigitalTwinBuilder
---
# P15 — Digital Twin

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 2 Recon |
| 앞 단계 | P4 CPR |
| 뒤 단계 | P13 Biometrics |
| 역할 | 실타겟 접촉 전 가상 환경에서 공격 리허설 |
| 원리 | tech stack → Docker Compose → 격리 네트워크 |
| 출력 | "이 공격이 실제로 먹힐 확률" 사전 평가 |
| 안전 | `network: none` 또는 isolated bridge, 외부 인터넷 차단, 사후 정리 |

## TL;DR
P4 recon 이 찾은 tech stack 을 Docker Compose 로 재현한 격리 twin 에서 공격 리허설. 검증된 공격만 실타겟에 집행 → 소음·감지 최소화. 실제 스캔 전 승인 필수.

## Stage
Recon — CPR(P4) 이 식별한 스택을 로컬 재현. Active scan 전 pre-flight.

## Inputs-Outputs
- Input: tech stack (nginx 1.18, MySQL 5.7, Django 3.2 등).
- Output: `DockerConfig` + `SimResult` (공격 성공/실패 + 페이로드 목록).

## Triggers
- P4 CPR 완료 후 Director 가 `TwinSimulator.run(stack)` 호출.
- Enterprise 스캔의 "injection 마지막, 승인 후" 단계에 사용.

## Related Pipelines
- [P4 CPR](./P4_cpr.md) — 앞 단계 (tech stack 공급)
- [P13 Biometrics](./P13_biometrics.md) — 뒤 단계 (휴먼 OSINT)
- [P5 Special](./P5_special.md) — twin 에서 검증된 공격만 실행
