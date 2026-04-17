---
name: test_ssrf
type: skill
status: active
when_to_read: SSRF URL 파라미터 탐지 / 클라우드 metadata / protocol smuggling / IP bypass
updated: 2026-04-17
sources:
  - ../../../src/vxis/agent/skills/test_ssrf.py
related:
  - ./test_injection.md
  - ./test_infra.md
code_anchors:
  - src/vxis/agent/skills/test_ssrf.py:execute
---
# test_ssrf

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | ssrf |
| Rotation | no |
| Payload 군 | 약 19 개 (localhost / private / 클라우드 metadata / file:// / gopher / dict / IP bypass) |
| URL params hint | `url, uri, path, redirect, next, link, src, href, file, page, callback` |
| 감지 방식 | signature hit (`ami-`, `AccessKeyId`, `root:`, `redis`) → critical |
| Size heuristic | `size > baseline+200` & status 200 → `ssrf_possible` high |
| Concurrency | `asyncio.Semaphore(15)` |

## TL;DR
URL 수락하는 파라미터에 localhost·private·AWS/GCP/Azure/DO metadata·file://·gopher·dict · hex/decimal/short IP bypass 19종 삽입. signature 매치 시 critical, 단순 size 차이만 있으면 `ssrf_possible` high.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `url` | str | 필수 | 타겟 URL |
| `param_name` | str \| None | None | 없으면 `URL_PARAMS` 힌트에서 매칭 → 첫 쿼리키 → `url` 생성 |
| `**kwargs` | Any | — | 무시 |

## Known Limitations
- Out-of-band (DNS exfil) 미지원 — Burp Collab / 자체 listener 필요
- POST body / JSON 필드 기반 SSRF 미테스트
- `file://` · `gopher://` 는 httpx 가 HTTP(s) 만 따라가서 실제 전송 안 됨 — 타겟이 proxy 역할 해야 탐지
- DNS rebinding `127.0.0.1.nip.io` 는 서버 측 DNS 캐시에 따라 false-negative
- baseline 1 회만 측정 — 동적 응답 크기면 `ssrf_possible` false-positive

## Source Files
- `src/vxis/agent/skills/test_ssrf.py`
