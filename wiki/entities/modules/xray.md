---
name: xray
type: module
status: active
when_to_read: 트래픽 인터셉트·변조 / mitmproxy 연동 / 토큰·API 키 자동 추출 / 요청 리플레이 / 패시브 분석
updated: 2026-04-16
sources:
  - ../../../src/vxis/interaction/xray.py
  - ../../../src/vxis/agent/tools/hands_tools.py
related:
  - ./hands.md
  - ./eyes.md
code_anchors:
  - src/vxis/interaction/xray.py:TrafficInterceptor
  - src/vxis/interaction/xray.py:CapturedFlow
  - src/vxis/interaction/xray.py:FlowAnalyzer
  - src/vxis/agent/tools/hands_tools.py:InterceptProxyTool
---
# xray

## 핵심 사실
| 항목 | 값 |
|---|---|
| Role | Brain 의 "투시" — Hands/Eyes 사이 트래픽 인터셉트 |
| 구현 | mitmproxy 서브프로세스 + addon script |
| Degradation | mitmproxy 미설치 시 순수 Python 패시브 분석만 |
| 컴포넌트 | FlowCapture, FlowAnalyzer, FlowModifier, FlowReplayer |
| 자동 탐지 | 인증 토큰, API 키, 세션 ID 패턴 매칭 |
| 변조 | FlowModifier 규칙으로 실시간 req/resp 수정 |
| 데이터 공유 | 파일/메모리 IPC (인프로세스 아님) |

## TL;DR
Hands/Eyes 가 보내고 받는 모든 HTTP(S) 트래픽을 중간에서 캡처·분석·변조. mitmproxy 를 별도 프로세스로 실행하고 addon 으로 제어. 패시브 분석(토큰 추출, API 키 감지) + 액티브 변조(리플레이·공격 페이로드 주입) 둘 다.

## Key Surfaces
- `TrafficInterceptor` — mitmproxy 래퍼. 시작/중지/캡처 라이프사이클.
- `CapturedFlow` — 단일 req/resp 쌍 dataclass. `id`, `timestamp`, `method`, `url`, `headers`, `body`.
- `FlowDirection` — `REQUEST` / `RESPONSE` enum.
- `FlowCapture` — 트래픽 수집기.
- `FlowAnalyzer` — 패턴 분석 (JWT, API key, session cookie 자동 추출).
- `FlowModifier` — 변조 규칙 엔진. 매처 + 트랜스폼.
- `FlowReplayer` — 캡처된 요청 변조 후 재전송.
- `InterceptProxyTool` (hands_tools.py) — Brain 어댑터.

## Invariants
- mitmproxy 는 인프로세스 아닌 서브프로세스 — scan 종료 시 반드시 종료.
- 캡처된 flow 는 immutable — 변조 시 새 flow 생성.
- 인증 토큰 자동 추출은 passive 모드에서도 동작 — credential leak detection.
- mitmproxy 미설치 시 `TrafficInterceptor` 는 passive-only 모드로 fallback.
- FlowModifier 규칙은 순차 적용 — 첫 매칭 규칙만 실행.

## Related
- [hands](./hands.md) — HTTP 계층, X-Ray 가 감청하는 대상
- [eyes](./eyes.md) — 브라우저 계층, X-Ray 가 감청하는 대상
