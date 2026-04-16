---
name: P13 Biometrics
type: pipeline
status: active
when_to_read: 행동 생체인식 OSINT / 직원 행동 패턴 분석 / GitHub·LinkedIn 공개 정보 / 피싱 타이밍
updated: 2026-04-16
sources:
  - ../../../src/vxis/biometrics/analyzer.py
related:
  - ./P4_cpr.md
  - ./P15_digital_twin.md
  - ./P5_special.md
code_anchors:
  - src/vxis/biometrics/analyzer.py
---
# P13 — Biometrics

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 2 Recon |
| 앞 단계 | P15 Digital Twin |
| 뒤 단계 | P2 Agents (identity/phishing) |
| 역할 | 행동 패턴 OSINT — 직원 GitHub·LinkedIn 공개 정보 분석 |
| 데이터 원칙 | 공개 정보만, 인증 정보 금지, PII 최소 |
| 소스 | GitHub REST API v3, gh CLI, 공개 DNS |
| 출력 | 타겟 인물별 행동 패턴 (push 시간, 역할, 관심사) |

## TL;DR
"직원 A가 매일 9시에 GitHub push → 9시 피싱이 효과적" — 공개 OSINT 로 인간 행동 표면을 맵핑. SW 취약점을 넘어 휴먼 벡터까지 커버. 공개 정보만 수집, PII 최소 원칙.

## Stage
Recon — P4 CPR 과 병렬. OSINT 기반 인간 공격 표면 스캔.

## Inputs-Outputs
- Input: 조직 도메인, 알려진 직원 이름/ID.
- Output: 행동 패턴 dict (시간대별 활동, 기술 스택, 공개 프로젝트, 관심 토픽).

## Triggers
- MissionConfig 에 social engineering scope 포함 시.
- Director 가 identity agent 스폰 전 사전 조사.

## Related Pipelines
- [P15 Digital Twin](./P15_digital_twin.md) — 앞 단계 (기술 recon)
- [P4 CPR](./P4_cpr.md) — 병렬 recon (기술 계층)
- [P5 Special](./P5_special.md) — 이 데이터로 phishing/social agent 가 공격
