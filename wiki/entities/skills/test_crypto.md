---
name: test_crypto
type: skill
status: active
when_to_read: TLS 약한 버전 / JS 번들 하드코드 시크릿 / MD5/SHA1 해시 노출
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/skills/test_crypto.py
related:
  - ./test_sensitive_files.md
  - ./test_infra.md
code_anchors:
  - src/vxis/agent/skills/test_crypto.py:execute
---
# test_crypto

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | crypto |
| Rotation | no |
| TLS 체크 | SSLv3 (high) / TLSv1.0 (medium) / TLSv1.1 (medium) — `https://` 일 때만 |
| Secret patterns | 10 (api key / AWS AKIA / AWS secret / bearer / private key / `ghp_`, `sk-`, DB URL, Slack) |
| JS 스캔 경로 | 10 정적 + HTML `<script src>` 자동 추출 (외부 CDN skip) |
| Weak hash | `/api/users`·`/api/profile`·`/api/account` 에서 MD5 (32 hex) / SHA1 (40 hex) 매칭 |
| Concurrency | `asyncio.Semaphore(15)` |

## TL;DR
3 축 암호 취약점. (1) HTTPS 타겟에 SSLv3/TLS1.0/TLS1.1 소켓 연결 성공 시 weak TLS. (2) JS 번들에서 AWS·GitHub·OpenAI·DB URL 등 10 패턴 정규식 매칭. (3) user/profile API 응답에서 MD5/SHA1 해시 길이 탐지.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | 타겟 base URL (scheme 로 HTTPS 판단) |
| `**kwargs` | Any | — | 무시 |

## Known Limitations
- 약한 cipher suite (RC4, 3DES) · 약한 curve 미체크 — version 만
- 인증서 validity / SAN / expiry 미체크
- JS 패턴은 정규식 기반 — minified/난독화 bundle 에서 match 실패 가능
- 외부 CDN 제외 → sourcemap 으로 다시 fetch 하는 경로 miss
- Weak hash 는 JSON `"(?:password|hash|passwd)":\s*"[a-f0-9]{32,40}"` 만 — 다른 key 이름 miss
- bcrypt/argon2 확인 없음 (hash 형식 안 맞으면 무시)

## Source Files
- `src/vxis/agent/skills/test_crypto.py`
