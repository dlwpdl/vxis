---
name: ADR-003 — No Raw httpx (Hands / X-Ray / Controller / Finding Only)
type: decision
status: active
when_to_read: HTTP 요청 작성 방법 / raw httpx 금지 이유 / Hands·X-Ray·Controller·Finding 모듈 사용 근거 / SessionManager 강제 시점
updated: 2026-04-23
sources:
  - /Users/eliot/.claude/projects/-Users-eliot-Desktop---vxis/memory/feedback_use_vxis_modules.md
related:
  - ../concepts/brain_first.md
---
# ADR-003 — No Raw httpx — VXIS Modules Only

## 핵심 사실
| 항목 | 값 |
|---|---|
| Status | Accepted |
| Date | 2026-04-16 |
| 필수 모듈 | Hands (`SessionManager`/`TargetSession`), X-Ray (`FlowAnalyzer`), Controller (`InteractionController`), Finding (`Finding` 모델) |
| 리포트 | `ReportGenerator` (NCC Group HTML) |
| 예외 | VXIS 모듈이 처리 못 하는 특수 케이스 (예: 복잡한 multipart 업로드) 만 최소 raw |
| 목적 | 세션·CSRF·X-Ray 플로우·구조화 finding 을 자동 활용 |

## TL;DR
Brain 이 공격할 때 raw `httpx` 스크립트 금지. Hands 로 HTTP, X-Ray 로 트래픽 플로우, Controller 로 intent→감각 선택, Finding 모델로 CVSS/CWE/Evidence 구조화, ReportGenerator 로 HTML 렌더. raw httpx 는 VXIS 실제 제품이 동작함을 증명하지 못하고 X-Ray 패시브 분석·세션 추적·자동 CSRF 같은 이점을 모두 버린다.

## Context
초기 스캔 스크립트가 `httpx.AsyncClient()` raw 요청 사용. 빠르지만 (a) 세션 추적 없음 (b) X-Ray 플로우 미기록 → 패시브 탐지 불가 (c) CSRF 토큰 자동 재획득 없음 (d) finding 이 임시 dict — CVSS/Evidence 구조 없음 (e) 리포트 포맷 재작업 필요. VXIS 가 실제 동작함을 증명하려면 모든 공격이 제품 모듈 통과해야.

## Options
1. **Raw httpx 허용** — 속도 최대, 제품 모듈 미검증.
2. **VXIS 모듈 강제 + 극히 예외적 raw** — dogfooding, 리포트 자연 연결.
3. **Sandboxed raw + 결과 변환** — 변환 레이어 복잡도 과다.

## Decision
옵션 2 채택. HTTP 는 `SessionManager` + `TargetSession`, 플로우는 `FlowAnalyzer`, 도구 선택은 `InteractionController` (Brain intent → 자동 감각), finding 은 `Finding` (CVSS/CWE/Evidence), 리포트는 `ReportGenerator.generate_html_file()`. raw httpx 는 multipart 업로드 같이 wrapper 미지원만 최소 사용, 결과도 Finding 에 담아 리포트로.

## Consequences
- **Pro**: 모든 요청이 X-Ray 플로우 자동 기록 → 패시브 탐지·세션 재사용·CSRF 자동.
- **Pro**: finding 이 구조화돼 리포트 렌더 시 변환 불필요.
- **Pro**: 제품 모듈 dogfooded — 버그·API 누락 조기 노출.
- **Con**: WebSocket / gRPC / multipart 미지원 시 raw + 변환 코드 부담.
- **Enforcement (2026-04-23, commit `6bafb80`)**: phase-B 에서 lazy `import httpx` + `httpx.AsyncClient` 컨텍스트를 15 skills (test_xss / test_sensitive_files / test_auth_deep / test_business_logic / test_api_security / test_csrf / test_injection / attempt_auth / post_auth_enum / test_idor / test_infra / test_ssrf / test_misconfig / test_crypto / enumerate_endpoints) + 2 growth 모듈 (payload_validator·analyze) 에서 제거하고 `SessionManager.request()` 로 교체. AST guard `tests/unit/interaction/test_no_raw_httpx.py` 가 `ALLOWED` 3개만 통과시키고 신규 위반은 빌드 fail. 효과: rate limit·cookie persistence·WAF 감지·CSRF auto-injection 이 전체 공격 경로에 일관 적용 (raw httpx 는 이 모든 걸 우회).
