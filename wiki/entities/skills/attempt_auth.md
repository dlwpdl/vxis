---
name: attempt_auth
type: skill
status: active
when_to_read: 로그인 우회 / default creds / SQLi bypass / password reset 체크 순서
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/skills/attempt_auth.py
related:
  - ./post_auth_enum.md
  - ./test_auth_deep.md
  - ../modules/scan_loop.md
code_anchors:
  - src/vxis/agent/skills/attempt_auth.py:execute
---
# attempt_auth

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | auth |
| Rotation | no |
| Method 우선순위 | 1) SQLi bypass → 2) default creds → 3) password reset |
| Login paths | 11 개 (`/rest/user/login`, `/api/auth/login`, `/oauth/token` 등) |
| Default creds | 13 조합 (admin/admin, admin/password, test/test ...) |
| SQLi creds | 4 조합 (`' OR 1=1--`, `admin'--` ...) |
| Token 경로 | `authentication.token`, `token`, `access_token`, `data.token` |

## TL;DR
인증 skill — 3 phase 순서로 시도. SQLi 먼저 (highest value), 실패 시 default creds, 그래도 실패 시 password reset (Juice Shop `admin@juice-sh.op` / security answer 사전 내장). 성공 시 token 반환 → `post_auth_enum` 이 이어받음.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | 타겟 base URL |
| `**kwargs` | Any | — | 무시 |

## Known Limitations
- 로그인 엔드포인트 동적 탐지 없음 — 정적 `LOGIN_PATHS` 리스트
- `{email, password}` JSON 본문 고정 — form-urlencoded / username 필드만 있는 타겟 실패
- Password reset 은 `admin@juice-sh.op`·`jim@juice-sh.op` 등 Juice Shop 편향
- OAuth flow / CAPTCHA / 2FA 미지원
- MFA 우회 시도 없음

## Source Files
- `src/vxis/agent/skills/attempt_auth.py`
