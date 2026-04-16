---
name: test_infra
type: skill
status: active
when_to_read: .git / .env 노출 / 클라우드 metadata / 서브도메인 DNS / Firebase public
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/skills/test_infra.py
related:
  - ./test_sensitive_files.md
  - ./test_ssrf.md
  - ./test_crypto.md
code_anchors:
  - src/vxis/agent/skills/test_infra.py:execute
---
# test_infra

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | infrastructure |
| Rotation | no |
| Git paths | 6 (`/.git/HEAD`, `/.git/config`, `/.git/index` ...) with signature |
| Env paths | 9 (`/.env`, `/.env.local`, `/.env.production`, `/.env.bak` ...) |
| Cloud endpoints | 4 (AWS EC2 metadata, AWS IAM, GCP Metadata-Flavor, Azure Metadata:true) |
| Subdomain prefixes | 20 (`admin`, `api`, `dev`, `staging`, `jenkins`, `grafana` ...) — IP 가 아닐 때만 DNS resolve |
| Firebase | `{subdomain}.firebaseio.com/.json` 200 & `!= "null"` → critical |
| Concurrency | `asyncio.Semaphore(15)` |

## TL;DR
5 축 인프라 노출 체크. git 디렉토리, env 파일, 클라우드 인스턴스 metadata 직접 호출 (SSRF 없이 타겟 서버 자체가 해당 URL 반환할 때), DNS 로 서브도메인 enum, Firebase open DB 체크. IP 타겟은 서브도메인·Firebase skip.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | 타겟 base URL (hostname 에서 base_domain 추출) |
| `**kwargs` | Any | — | 무시 |

## Known Limitations
- 클라우드 metadata 는 타겟이 proxy/SSRF 역할을 해야 반환 — 직접 `httpx` 요청은 169.254 라우팅 안 됨 (SSRF 는 `test_ssrf` 가 담당)
- 서브도메인은 `socket.gethostbyname` — DNS wildcard 면 모두 resolve → false-positive
- base_domain 추출은 `parts[-2:]` 단순 조인 → `co.uk` · `com.au` 등 ccTLD 에서 부정확
- Env 검출은 `^[A-Z_]+=.+` 라인 1 개 이상 — 주석만 있는 `.env` miss
- Firebase 는 subdomain 첫 부분만 사용 → `my-app.example.com` → `my-app.firebaseio.com`
- Out-of-band / zone transfer / AWS S3 bucket 열람 없음

## Source Files
- `src/vxis/agent/skills/test_infra.py`
