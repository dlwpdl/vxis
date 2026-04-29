---
name: P5 Special
type: pipeline
status: active
when_to_read: 특화 공격 스킬 실행 / SKILL_REGISTRY 호출점 / exploitation 본체 / skill_runner 와의 관계
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/skills/
  - ../../../src/vxis/agent/tools/skill_runner.py
related:
  - ./P3_hypothesis.md
  - ./P7_hardware.md
  - ./P8_synthesis.md
  - ../modules/skill_runner.md
code_anchors:
  - src/vxis/agent/skills/__init__.py:SKILL_REGISTRY
  - src/vxis/agent/tools/skill_runner.py:RunSkillTool
---
# P5 — Special

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 4 Exploitation |
| 앞 단계 | P3 Hypothesis |
| 뒤 단계 | P7 Hardware / P8 Synthesis |
| 역할 | 특화 공격 스킬 실행 (web/api/auth/crypto/business/infra) |
| Registry | `SKILL_REGISTRY` — 15 skills |
| Runner | `RunSkillTool` (Brain 어댑터) |
| Escalation | skill_runner 캐시 정책 (hit#1 nudge → #3 BLOCK) |

## TL;DR
가설을 실제 공격으로 변환하는 단계. SKILL_REGISTRY 의 15개 스킬(test_injection, test_idor, test_xss, test_auth_deep, test_ssrf 등) 이 Brain 의 `run_skill` 호출로 실행. 1 skill = 수십 payload 병렬 테스트.

## Stage
Exploitation — 핵심 공격 단계. Brain 이 가장 많이 호출하는 루프.

## Inputs-Outputs
- Input: 가설(target endpoint, param, vuln hypothesis) + 인증 세션.
- Output: `Finding` 리스트 (severity, evidence, PoC).

## Triggers
- Brain 이 `run_skill(skill, target_url, params)` 호출.
- scan_loop sweep (iter ≥ 25) 시 누락 skill 자동 주입.

## Related Pipelines
- [P3 Hypothesis](./P3_hypothesis.md) — 앞 단계 (가설 소스)
- [P7 Hardware](./P7_hardware.md) — 뒤 단계 (하드웨어 attack)
- [P8 Synthesis](./P8_synthesis.md) — 뒤 단계 (체인 합성)
