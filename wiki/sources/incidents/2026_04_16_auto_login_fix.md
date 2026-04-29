---
name: 2026-04-16 Auto-login BrowserPage.fill + Enter-key Fix
type: incident
status: active
when_to_read: auto-login 전체 실패 / BrowserPage.fill TypeError / Enter 키 미전달 / login pivot 메시지
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/scan_loop.py
related:
  - ./2026_04_16_seven_disconnections.md
  - ../../entities/modules/scan_loop.md
  - ../../concepts/brain_first.md
---
# 2026-04-16 — Auto-login: BrowserPage.fill TypeError & Enter-key Fix

## 핵심 사실
| 항목 | 값 |
|---|---|
| Scope | `scan_loop.py` auto-login 블록 (L1550~L1612) |
| 증상 | 모든 credential 시도 silent fail, Brain 은 시도 사실조차 모름 |
| Root cause 1 | `BrowserPage.fill(selector, value)` 에 `timeout=` kwarg 전달 → TypeError swallow |
| Root cause 2 | `BrowserPage.press(key)` 는 key 만 받음 — 특정 필드에 Enter 보낼 방법 없음 |
| Root cause 3 | 실패 시 Brain 에 PIVOT 신호 없음 → Brain 이 auto-login 자체를 인지 못 함 |
| 수정 커밋 | d13d6d9 |

## TL;DR
`BrowserPage.fill()` 의 실제 시그니처는 timeout 없음. 이전 코드가 `timeout=2500` 전달해 매번 TypeError → 예외 swallow → 전 credential silent fail. fill 은 raw 시그니처로, Enter 는 `_bp._page.press(selector, "Enter")` 로 언더라잉 Playwright page 경유. 실패 시 Brain 에 EXHAUSTED PIVOT 메시지 + 4 개 옵션 (test_auth_deep / test_injection on login / enumerate / register) 명시.

## Symptom
- 스캔에서 auto-login 시도 흔적 0.
- 로그에 "auto-login failed" 만 반복, 어느 credential 이 왜 실패했는지 불명.
- Brain 은 unauthenticated surface 만 긁다 vector_coverage plateau.
- `browser_fill_form` tool 기록 0 → Brain 수동 로그인 시도도 없음.

## Root Cause
1. **fill kwarg mismatch**: `_bp.fill(s, value, timeout=2500)` → `TypeError`, `except Exception: continue` 로 swallow → 모든 selector 실패.
2. **press() 시그니처 오인**: `BrowserPage.press(key)` 는 전역 key 만. 특정 input 에 Enter 보내려면 raw page 필요.
3. **Silent exhaustion**: 모든 creds 실패해도 Brain state 에 메시지 주입 없음 → Brain 이 시도 자체를 모름.

## Fix
- **`_fill_any()`**: `_bp.fill(s, value)` raw 시그니처. 실패 시 `_bp._page.fill(s, value, timeout=2500)` fallback.
- **Enter key**: submit 버튼 없으면 `_bp._page.press(_pw_sel, "Enter")` — 언더라잉 page 가 selector+key 지원.
- **DOM 어댑티브**: form inputs 파싱해 user/pw/submit selector 확장. creds 매트릭스 확대 (admin/admin, guest/guest, webgoat/webgoat, `' OR 1=1--`).
- **PIVOT 메시지**: `AUTO-LOGIN EXHAUSTED` + 4 옵션 (a) `test_auth_deep` (b) `test_injection` on login (c) `enumerate_endpoints` (d) register. 발견 form selector 도 Brain 에 노출.

## Lessons
- Wrapper 사용 시 실제 시그니처 확인. `except: continue` 는 디버깅 킬러 — 실패 이유 debug 로그 필수.
- 자동 동작은 성공·실패 모두 Brain state 반영. silent fail = Brain 에 "안 했다" 와 동의어.
- Enter 같은 UI 디테일은 wrapper 보다 raw page 가 확실.
- PIVOT 메시지는 구체적 다음 action 4 개 이상. 추상적 "시도 실패" 는 Brain 을 stuck 시킨다.
