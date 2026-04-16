---
name: test_csrf
type: skill
status: active
when_to_read: CSRF 토큰 없이 state-changing 요청 허용 / SameSite 부재 / invalid token 허용
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/skills/test_csrf.py
related:
  - ./test_api_security.md
  - ./test_misconfig.md
code_anchors:
  - src/vxis/agent/skills/test_csrf.py:execute
---
# test_csrf

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | csrf |
| Rotation | no |
| State-changing paths | 14 개 (`/api/users` POST, `/api/transfer` POST, `/api/admin/users` DELETE ...) |
| 검증 로직 | (1) 토큰 없이 요청 → 허용? (2) invalid `X-CSRF-Token` → 허용? |
| Non-blocking status | 403/419/405/404/401 외 — 통과로 간주 |
| SameSite check | root `/` GET 응답 Set-Cookie 에 `samesite` 문자열 없으면 medium |
| Concurrency | `asyncio.Semaphore(15)` |

## TL;DR
state-changing 엔드포인트 14 개에 dummy body 로 (1) CSRF 토큰 없이, (2) invalid 토큰으로 두 번 요청. 둘 다 403/419 안 뜨면 `csrf_no_protection` high. 별도로 root 쿠키 SameSite 미지정 체크.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | 타겟 base URL |
| `token` | str \| None | None | 있으면 `Authorization: Bearer`만 붙여서 요청 |
| `**kwargs` | Any | — | 무시 |

## Known Limitations
- dummy body `{"test": "csrf_probe"}` 고정 — schema mismatch 로 400 떠도 "보호 없다"고 판단 안 됨 (정확한 신호)
- CSRF 토큰이 Cookie + body 이중 검증 (double-submit) 패턴은 `X-CSRF-Token` 헤더만 봐서 miss
- Origin / Referer 기반 검증 타겟 미체크
- SameSite 는 root `/` 응답만 확인 — 로그인 후 발급 쿠키 미체크
- State-changing paths 는 Juice Shop / 일반 REST 편향

## Source Files
- `src/vxis/agent/skills/test_csrf.py`
