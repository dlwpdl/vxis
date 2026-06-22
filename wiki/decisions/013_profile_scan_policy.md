---
name: ADR-013 — Profile-driven ScanPolicy (익스플로잇 깊이·테넌트 격리·우회를 프로필 한 축으로)
type: decision
status: active
when_to_read: 같은 엔진이 prod 안전 + lab 무제한 어떻게 / 프로필별 권한 / H 익스플로잇 게이트 / 테넌트 격리·시크릿 / fail-closed
updated: 2026-06-19
sources:
  - ../../docs/superpowers/plans/2026-06-19-current-core-plan.md
  - ../../docs/superpowers/DECISIONS.md
related:
  - ./011_v3_consolidation.md
  - ./012_verifier_spine.md
  - ./003_no_raw_httpx.md
code_anchors:
  - src/vxis/config/schema.py:355
  - src/vxis/scope/enforcer.py
  - src/vxis/agent/tools/shell_tools.py
---
# ADR-013 — Profile-driven ScanPolicy

## 핵심 사실
| 항목 | 값 |
|---|---|
| Status | Accepted |
| Date | 2026-06-02 |
| 통합 | 익스플로잇 깊이 + 테넌트 격리 + 시크릿 + 우회 = 프로필 한 축(`ScanPolicy`) |
| resolve | `config.active_profile`(normalized, default `crown`) 로 정책 결정 |
| 핵심 원칙 | 유효 권한 = min(프로필 상한, 엔게이지먼트 인가) |
| 기본값 | 미지정/unknown → fail-closed (가장 제한적); chokepoint 는 `policy=None` 에서 FORBIDDEN |
| crown | `lateral`(scope 내 피벗, exfil/persist 없음); `full` 은 `aggressive`-lab / 서명된 DD 만 |
| 비협상 | scope chokepoint(Phase 1.5) + PTI tenant 형식은 프로필과 무관하게 구축 |

## TL;DR
같은 `crown` 엔진을 고객 prod 에서 안전하게, lab 에서 무제한으로 돌리는 방법은 **시작 프로필이 정책을 결정**하는 것. `ScanPolicy` 가 익스플로잇 깊이·scope 엄격도·테넌트 격리·시크릿 처리·우회를 한 번에 정한다. lab(`aggressive`)=full, prod=read-only+격리+레닥션, 미지정=fail-closed. 단 차단 관문과 PTI tenant 형식은 프로필이 강도만 조절하지 존재 자체를 대체 못 하므로 반드시 구축.

## Context
H(post-finding exploitation: DB dump→cred→lateral→exfil)를 v3 로 당기자 보안 리뷰가 BLOCKING: shell 경로가 무제한(`shell_tools.py`)이고 `ScopeEnforcer` 가 연결 안 됨·빈 scope 면 allow-all(fail-open), PTI 는 테넌트 차원 0(크로스테넌트 dossier 유출), 시크릿 평문 영속. 오너 결정: 깊이/격리를 전역 플래그가 아니라 v2 의 프로필 시스템에 매단다.

## Options
1. **전역 on/off 플래그** — 같은 엔진을 안전+무제한 둘 다 못 함. 기각.
2. **프로필 → ScanPolicy 한 축** — 채택.
3. **H 를 beyond-v3 로 연기** — chain-to-crown-jewel moat 미완. 기각(대신 Phase 1.5 선행조건).

## Decision
옵션 2. `resolve_policy()` 가 `config.active_profile` 로 정책 해석; `_default_profiles()` 전체에 행 존재(누락 시 fail-closed 로 떨어져 무력화). chokepoint 3개(`permit_strategy`/`permit_pivot`/`persist_secret`)는 `policy=None` 에서 FORBIDDEN. lab-allowlist 는 운영자 파일로 구체화 — `full` 프로필은 타겟이 목록에 없으면 시작 거부. PTI 는 `tenant_id`(인증된 엔게이지먼트 trust root 유래) + `data/pti/<tenant>/<target>/` 형식을 지금 박되, 격리/암호화 동작은 프로필이 켬. H 는 Phase 1.5(scope chokepoint 구축)가 머지된 뒤에만 머지.

## Consequences
- **Pro**: lab/DD 에서 crown-jewel 데모 유지, prod 안전. v2 safe-for-prod moat 구현.
- **Pro**: tenant 형식이 day-one 이라 멀티테넌트 retrofit 불필요.
- **Con**: ScopeEnforcer 가 현재 깨짐·URL 기반·fail-open → Phase 1.5 가 fix+wire+host:port+empty-deny 까지 해야 함(단순 호출 아님).
- **Enforcement**: cassette 티어가 H flag-on 경로에서 `permit_pivot` 미호출 시 실패 → "H 는 1.5 전 머지 불가" 가 테스트.

## 2026-06-19 note
Old v2/v3 plan files were removed. Treat this ADR as historical rationale for
policy gates, not as an active phase roadmap.
