---
name: post_auth_enum
type: skill
status: active
when_to_read: 인증 후 접근 가능 경로 / broken access control / IDOR 후보 탐지
updated: 2026-04-17
sources:
  - ../../../src/vxis/agent/skills/post_auth_enum.py
related:
  - ./attempt_auth.md
  - ./test_idor.md
  - ./enumerate_endpoints.md
code_anchors:
  - src/vxis/agent/skills/post_auth_enum.py:execute
---
# post_auth_enum

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | recon (post-auth) |
| Rotation | no |
| Paths | 약 30 개 (`/api/Users/`, `/api/Orders/`, `/rest/basket/N`, `/administration/`) |
| 비교 | 동일 경로에 `Authorization: Bearer <token>` with/without 각 1회 |
| 감지 | `new_endpoints` (auth 시 200 & no-auth 시 401) |
| `no_auth_required` | auth 응답 == no-auth 응답 → broken access control |
| `user_data_exposed` | body 에 `email|password|role|token|secret` 포함 |

## TL;DR
`attempt_auth` 성공 후 이어받아 token 으로 authenticated 경로 enum. 인증 전/후 응답 비교하여 (1) 정말 auth 로 풀리는 엔드포인트, (2) 인증 없이도 열리는 endpoint, (3) 민감 데이터 노출 경로 3 가지 분류.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | 타겟 base URL |
| `token` | str | 필수 | `attempt_auth` 에서 받은 Bearer 토큰 |
| `**kwargs` | Any | — | 무시 |

## Known Limitations
- 정적 경로 리스트 — Juice Shop REST 구조 편향 (`/api/BasketItems/`, `/rest/basket/N`)
- ID enum 은 1 개만 시도 (`/api/Users/1` 등) — IDOR 깊이 체크는 `test_idor` 로 위임
- 응답 동일성 판정 `r_noauth.text == r_auth.text` — timestamp 차이나면 miss
- POST/PUT 메서드 미시도 (GET 만)
- Cookie 와 Bearer 둘 다 동시 전송 → 중복되는 auth 스킴 구분 불가

## Source Files
- `src/vxis/agent/skills/post_auth_enum.py`
