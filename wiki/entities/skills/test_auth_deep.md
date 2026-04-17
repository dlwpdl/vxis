---
name: test_auth_deep
type: skill
status: active
when_to_read: JWT alg:none / RS→HS 혼동 / session fixation / password reset host poisoning
updated: 2026-04-17
sources:
  - ../../../src/vxis/agent/skills/test_auth_deep.py
related:
  - ./attempt_auth.md
  - ./test_csrf.md
code_anchors:
  - src/vxis/agent/skills/test_auth_deep.py:execute
  - src/vxis/agent/skills/test_auth_deep.py:_forge_alg_none
---
# test_auth_deep

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | auth (deep) |
| Rotation | no |
| JWT alg:none variants | 4 개 (`none`, `None`, `NONE`, `nOnE`) |
| JWT RS→HS | 원본 header 가 `RS*` 로 시작할 때만 시도 |
| 검증 경로 | `/api/users/me` 에 forged token 으로 GET |
| Session fixation | `Cookie: session=attacker_fixed_session` → Set-Cookie 에 반영되면 high |
| Reset poisoning | `Host: evil.com` + `X-Forwarded-Host` 헤더로 RESET_PATHS 6 개 시도 |

## TL;DR
JWT 공격 3종 + 세션 고정 + 패스워드 리셋 호스트 포이즈닝. `token` 받아 JWT 파싱 → `alg:none` 4 variant 위조 → RS→HS 혼동 시도. 성공 여부는 `/api/users/me` 200 응답으로 판정.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | 타겟 base URL |
| `token` | str \| None | None | JWT 토큰 (없으면 JWT 공격 skip, fixation/reset 만) |
| `**kwargs` | Any | — | 무시 |

## Known Limitations
- JWT 검증 엔드포인트 하드코딩 (`/api/users/me`) — 다른 기반 타겟은 false-negative
- RS→HS 혼동 시 공개키 획득 시도 없음 — `fakesig` 로만 전송 (정상 구현 서버는 reject)
- Session fixation 은 Set-Cookie 반영만 체크 — 실제 hijack 검증 없음
- Reset poisoning 은 `"evil.com"` 이 응답에 포함되는지만 체크 — 실제 이메일 body 까지는 못 봄
- kid injection / JKU/JWK header confusion 미구현

## Source Files
- `src/vxis/agent/skills/test_auth_deep.py`
