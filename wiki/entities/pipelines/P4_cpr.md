---
name: P4 CPR
type: pipeline
status: active
when_to_read: 초기 recon / Hands·Eyes·X-Ray 통합 / 타겟 인터랙션 entry / 기술 스택 지문
updated: 2026-04-16
sources:
  - ../../../src/vxis/interaction/hands.py
  - ../../../src/vxis/interaction/eyes.py
  - ../../../src/vxis/interaction/xray.py
  - ../../../src/vxis/interaction/controller.py
related:
  - ./P1_director.md
  - ./P15_digital_twin.md
  - ../modules/hands.md
  - ../modules/eyes.md
  - ../modules/xray.md
code_anchors:
  - src/vxis/interaction/controller.py
  - src/vxis/interaction/hands.py:SessionManager
  - src/vxis/interaction/eyes.py:BrowserEngine
  - src/vxis/interaction/xray.py:TrafficInterceptor
---
# P4 — CPR (Controller·Perception·Reasoning)

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 2 Recon |
| 앞 단계 | P1 Director |
| 뒤 단계 | P15 Digital Twin |
| 역할 | Hands·Eyes·X-Ray 3계층 통합 인터랙션 |
| Controller | `controller.py` — 3개 모듈 오케스트레이션 |
| 출력 | tech stack 지문, endpoint map, 초기 세션 |

## TL;DR
타겟과의 첫 인터랙션 계층. Hands(HTTP) + Eyes(Playwright) + X-Ray(mitmproxy) 3개 모듈을 Controller 가 조율, 기술 스택·엔드포인트·auth 플로우를 수집해 뒷 단계(P15 twin, P5 exploitation) 에 공급.

## Stage
Recon — 2 번째 단계. Foundation(P0,P1) 이후 첫 타겟 접촉.

## Inputs-Outputs
- Input: target URL, auth credentials (optional).
- Output: tech stack, endpoint list, auth session, 초기 traffic capture.

## Triggers
- `DirectorAgent` 가 `Controller.start(target)` 호출.
- scan_loop iteration 시 HttpRequest/Browser/Intercept tool 로 연동.

## Related Pipelines
- [P1 Director](./P1_director.md) — 앞 단계
- [P15 Digital Twin](./P15_digital_twin.md) — 뒤 단계 (tech stack 으로 twin 빌드)
- [P13 Biometrics](./P13_biometrics.md) — 병렬 recon (OSINT)
