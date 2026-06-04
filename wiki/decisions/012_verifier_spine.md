---
name: ADR-012 — Verifier Spine (모든 finding 이 adversarial verify + PoC 게이트 통과)
type: decision
status: active
when_to_read: zero-FP 를 코드로 어떻게 강제하나 / verifier 게이트 위치 / 왜 전 severity / PoC 필수 / 신규 아니라 기존 강화
updated: 2026-06-02
sources:
  - ../../docs/superpowers/plans/2026-06-02-cognitive-engine-v3.md
related:
  - ./011_v3_consolidation.md
  - ./008_finding_precision_smoothing.md
  - ./004_ncc_group_report_format.md
code_anchors:
  - src/vxis/agent/tools/verifier_tools.py
  - src/vxis/agent/scan_loop_run.py:489
---
# ADR-012 — Verifier Spine

## 핵심 사실
| 항목 | 값 |
|---|---|
| Status | Accepted |
| Date | 2026-06-02 |
| Moat | v2 전략의 zero-FP — 모든 경쟁사가 false positive 에서 무너짐 |
| 기존 상태 | `verifier_tools.py`("default to refute") + `scan_loop_run.py:489-618` 게이트가 이미 ~70% |
| 갭 1 | 게이트가 high/critical 만 발동 (`:496`) → medium/low 우회 |
| 갭 2 | `report_finding` 경계에서만 게이트 → skill 자동보고 우회 |
| 결정 | 전 severity + `findings[]` chokepoint 이동 + PoC 코드 게이트 |

## TL;DR
인지엔진의 **척추는 Verifier**다. 보고되는 모든 finding 은 adversarial verify 를 통과하고 재현 가능한 PoC 아티팩트를 가져야 한다 — 아니면 `unverified` 로 강등되어 리포트에서 제외. 신규 빌드가 아니라 이미 있는 verifier 게이트의 두 구멍(severity 한정·report_finding 경계)을 막고 PoC 코드 게이트를 추가하는 작업이다. 레닥션도 같은 chokepoint 에 co-locate.

## Context
시장의 보편적 실패는 검증 안 된 finding. VXIS 의 선언된 moat 가 정확히 zero-FP 인데, v3 인지엔진(PTI/DAG/coverage/cost)은 이를 *지원*하지 정면으로 강화하진 않았다. plan-review 가 verifier 가 이미 존재하나(REFUTED 차단) 두 구멍이 zero-FP 를 깬다고 확인.

## Options
1. **신규 verifier 모듈** — 기존 `verifier_tools.py` 와 중복 (ADR-011 가 막는 패턴). 기각.
2. **기존 게이트 강화: 전 severity + findings[] chokepoint + PoC 게이트** — 채택.
3. **프롬프트로만 "신중하라"** — 코드 강제 아님, 경쟁사 수준. 기각.

## Decision
옵션 2. (a) severity 필터를 high/critical → 전체로 낮춤; (b) 게이트를 Brain `report_finding` 경계에서 단일 `findings[].append` chokepoint 로 이동(skill 자동보고도 못 우회); (c) PoC 아티팩트(req/resp 쌍 또는 스크립트) 없으면 `unverified` 강등·리포트 제외; (d) refuter N-vote 는 borderline 에만(비용 bound); (e) 시크릿 레닥션을 같은 chokepoint 에 co-locate(report 경로까지). H 는 confirmed finding 만 익스플로잇.

## Consequences
- **Pro**: clean-control 타겟 CONFIRMED critical = 0 을 CI 차단 게이트로. 모든 CONFIRMED 에 PoC.
- **Pro**: F(self-critique)는 recall 갭 담당이고 V 가 precision 담당 — 역할 분리, F 가 FP 게이트 완화 금지.
- **Con**: 후보 finding 마다 verify 호출 → 비용. 후보 dedupe + borderline-only refuter 로 bound.
- **Enforcement**: cassette 티어가 게이트 코드 회귀(severity·PoC) 차단; clean-control 0-FP 는 full-live 게이트.
