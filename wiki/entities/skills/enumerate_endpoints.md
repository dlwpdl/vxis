---
name: enumerate_endpoints
type: skill
status: active
when_to_read: 120+ common paths blast / SPA baseline detection / accessible/auth_required 분류
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/skills/enumerate_endpoints.py
related:
  - ./test_sensitive_files.md
  - ./post_auth_enum.md
  - ../modules/scan_loop.md
code_anchors:
  - src/vxis/agent/skills/enumerate_endpoints.py:execute
---
# enumerate_endpoints

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | recon |
| Rotation | no |
| Paths | 120+ (REST / API / admin / config / docs / auth / metrics) |
| SPA baseline | `/definitely-not-real-xyz-probe` 로 200 catch-all 감지 → 동일 size 응답 skip |
| 분류 | accessible (200/3xx) / auth_required (401) / errors (500) |
| Concurrency | `asyncio.Semaphore(20)` |
| Timeout | 요청당 5s |

## TL;DR
비인증 타겟에 공통 경로 120+ 개를 비동기 blast. 404 / SPA baseline 은 무시, 200/3xx → `accessible`, 401 → `auth_required`, 500 → `errors`. 응답 크기 내림차순 정렬 (큰 응답이 정보가 많음).

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | 타겟 base URL (trailing `/` 제거됨) |
| `**kwargs` | Any | — | 무시 |

## Known Limitations
- 정적 wordlist (COMMON_PATHS) — SecLists 같은 대용량 fuzz 미통합
- `follow_redirects=False` — 3xx 체인 따라가지 않음
- POST-only 엔드포인트 미발견 (GET 만 시도)
- SPA 감지가 size 정확 일치에 의존 — 동적 에러 페이지는 false-positive
- Juice Shop/WebGoat 편향 경로 (`/rest/...`, `/api/Feedbacks/`) 다수

## Source Files
- `src/vxis/agent/skills/enumerate_endpoints.py`
