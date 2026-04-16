---
name: hands
type: module
status: active
when_to_read: HTTP 세션·쿠키·CSRF 자동 관리 / 폼 파싱 / 멀티스텝 체인 / raw httpx 금지 정책
updated: 2026-04-16
sources:
  - ../../../src/vxis/interaction/hands.py
  - ../../../src/vxis/agent/tools/hands_tools.py
related:
  - ./eyes.md
  - ./xray.md
  - ./scan_loop.md
code_anchors:
  - src/vxis/interaction/hands.py:SessionManager
  - src/vxis/interaction/hands.py:TargetSession
  - src/vxis/agent/tools/hands_tools.py:HttpRequestTool
---
# hands

## 핵심 사실
| 항목 | 값 |
|---|---|
| Role | Brain 의 "손" — HTTP 계층, 세션·쿠키·CSRF 자동 추적 |
| Entry | `SessionManager.get_session(base_url)` → `TargetSession` |
| Tool 어댑터 | `HttpRequestTool` (`http_request`) |
| 기반 | `httpx` 위 세션 FSM |
| 자동 기능 | 쿠키 jar, JWT 추출, CSRF token 추적, 리다이렉트·WAF 감지, 적응형 rate limit |
| 폼 | `session.discover_forms(path)` HTML 파서 |
| 체인 | `session.chain().get().post().execute()` 멀티스텝 |

## TL;DR
단순 HTTP client 가 아니라 auth 상태 FSM 을 내장한 지능형 세션 매니저. Brain 이 raw httpx 를 쓰면 쿠키·CSRF 가 손실되므로 반드시 `HttpRequestTool` 또는 `SessionManager` 경유.

## Key Surfaces
- `SessionManager` — 타겟별 `TargetSession` 풀. 모듈 글로벌 싱글톤 (scan_loop 에서 공유).
- `TargetSession.get/post/put/patch/delete/options()` — HTTP 메서드, 쿠키 자동 주입.
- `TargetSession.login(url, data)` — 로그인 플로우 → `AuthState` FSM 전환.
- `TargetSession.discover_forms(path)` — HTML 파싱 → `FormDescriptor` list.
- `TargetSession.chain()` — 멀티스텝 체인 빌더.
- `HttpRequestTool` (tools/hands_tools.py) — Brain 어댑터. `url` 또는 `base_url`+`path` 받아 session 위임.
- `CookieJar`, `CSRFTracker`, `AuthState` — 내부 FSM 컴포넌트.
- Ghost transport 연동 (`vxis.ghost.transport`) — stealth 모드 시 proxy chain.

## Invariants
- raw `httpx.AsyncClient()` 직접 생성 금지 — 쿠키·CSRF 격리 깨짐 (`feedback_use_vxis_modules` 메모리 원칙).
- 세션 싱글톤은 scan 간 유지 — 테스트에선 `_reset_for_tests()` 호출.
- `login()` 후 `AuthState` 가 AUTHENTICATED 로 전환 — 후속 요청이 인증 컨텍스트에 자동 포함.
- CSRF 토큰은 응답에서 파싱 → 다음 POST/PUT 에 자동 주입.
- Rate limit 은 response 헤더(Retry-After, X-RateLimit-*) 감지 후 adaptive backoff.

## Related
- [eyes](./eyes.md) — 브라우저 계층 (Hands 와 달리 JS 실행)
- [xray](./xray.md) — Hands/Eyes 사이 트래픽 인터셉트
- [scan_loop](./scan_loop.md) — HttpRequestTool 을 호출하는 Brain 루프
