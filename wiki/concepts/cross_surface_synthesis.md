---
name: Cross-Surface Synthesis
type: concept
status: active
when_to_read: surface boundary marker / desktop+web 체인 / OSILayer.DESKTOP 매핑 / _agent_to_layer 사용처 / Evidence.surface 의미
updated: 2026-04-23
sources:
  - ../../src/vxis/synthesis/cross_protocol.py
related:
  - ./chain_intelligence.md
  - ./vxis_architecture.md
  - ../entities/pipelines/P8_synthesis.md
---
# Cross-Surface Synthesis

## 핵심 사실
| 항목 | 값 |
|---|---|
| 목적 | desktop·web·mobile 등 서로 다른 surface findings 를 하나의 attack chain 으로 묶기 |
| 핵심 helper | `_agent_to_layer(agent_id) -> OSILayer` (module-level, public) |
| Layer 매핑 우선순위 | (1) `_AGENT_LAYER_MAP` 명시 entry → (2) `agent_id.startswith("desktop_")` fallback → DESKTOP |
| 신규 OSI 레이어 | `OSILayer.DESKTOP` — 기존 PHYSICAL~CLOUD 위에 추가 |
| Evidence 필드 | `Evidence.surface: Surface` (web/desktop/mobile/game) — round-trip 가능 |
| 도입 commit | `266aa97` (phase-G), 2026-04-23 |
| 테스트 | `tests/synthesis/test_desktop_layer_mapping.py` (10) + `tests/unit/evidence/test_evidence_surface.py` (8) + `tests/agent/tools/test_finding_tools_surface_tag.py` (5) — 총 23, 93 passed |

## TL;DR
ProtoPie 같은 desktop 앱에서 발견된 dylib hijack 과 update 채널의 web finding 을 한 chain 으로 합성하려면 layer 가 같은 차원에서 비교돼야 한다. Phase G 가 `OSILayer.DESKTOP` 을 도입하고 `_agent_to_layer()` public helper 로 raw skill name (`test_dylib_hijack`) 도 DESKTOP 으로 라우팅한다. Evidence 에 `surface` 필드를 박아 pipeline 전반에 propagate.

## What
Cross-Surface Synthesis 는 P8 Synthesis 파이프라인이 surface 경계를 가로지르는 attack chain 을 그릴 수 있게 해주는 기반 레이어다. 이전에는 `CrossProtocolSynthesizer._tag_layer()` 가 인스턴스 메서드라 테스트가 항상 객체를 만들어야 했고, `desktop_*` 접두사 fallback 만 있어 raw skill name 으로 호출하면 layer 미정. Phase G 에서 (1) module-level `_agent_to_layer()` public helper, (2) `_AGENT_LAYER_MAP` 에 macOS 스킬 명시 entry 6개 (`test_dylib_hijack` 등), (3) `Evidence.surface` 필드 round-trip 보장.

## Why
Surface 가 다른 finding 끼리 chain 을 그리려면 두 가지가 필요하다. 첫째 layer 라는 공통 좌표축에서 비교 가능해야 하고 (web=APPLICATION, desktop=DESKTOP, 같은 enum), 둘째 finding 단위에 surface tag 가 박혀 P8 synthesizer 가 `crosses surface boundary` 마커를 결정 가능해야 한다. Phase G 이전에는 desktop finding 이 그냥 generic APPLICATION 으로 떨어져 web 과 구분 안 됨 → "이게 진짜 cross-surface chain 이냐 same-surface chain 이냐" 판정 불가.

## How
- **Layer 매핑** (`cross_protocol.py:148`): `_agent_to_layer(agent_id)` — `_AGENT_LAYER_MAP.get()` → `desktop_` 접두사 → `OSILayer.APPLICATION` (default fallback).
- **명시 entry** (`cross_protocol.py:139-144`): `test_dylib_hijack`, `test_local_storage_secrets`, `test_electron_misconfig`, `test_entitlement_audit`, `test_signature_audit`, `test_deeplink_abuse` 모두 `OSILayer.DESKTOP` 직매핑 — sweep alias 가 아닌 real skill name 이기 때문.
- **Evidence.surface 전파**: `agent/tools/finding_tools.py` 가 finding 등록 시 `surface` 를 결정 (target.kind 기준), Evidence dump → reload round-trip 보장.

## Related
- [chain_intelligence](./chain_intelligence.md) — chain 카운팅 / nudge 의 desktop chain 인식
- [vxis_architecture](./vxis_architecture.md) — Brain/Hands/Eyes/X-Ray 와 surface 분리의 관계
- [P8 Synthesis](../entities/pipelines/P8_synthesis.md) — 이 helper 를 호출하는 합성 파이프라인
