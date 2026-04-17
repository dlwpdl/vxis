---
name: test_misconfig
type: skill
status: active
when_to_read: 보안 헤더 부재 / CORS / debug endpoint / verbose error / server version
updated: 2026-04-17
sources:
  - ../../../src/vxis/agent/skills/test_misconfig.py
related:
  - ./test_sensitive_files.md
  - ./test_api_security.md
code_anchors:
  - src/vxis/agent/skills/test_misconfig.py:execute
---
# test_misconfig

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | misconfiguration |
| Rotation | no |
| Required headers | 7 (CSP high, HSTS high, XFO/XCTO medium, XSS/Referrer/Permissions low) |
| CORS origins | 3 (`evil.com`, `null`, `attacker.example.com`) |
| Debug paths | 15 (`/debug`, `/actuator`, `/actuator/heapdump`, `/__debug__/`, `/elmah.axd` ...) |
| Verbose error signals | `traceback / stack trace / exception / at line / debug / sqlstate` on `/A*500` URL |
| CORS ACAC true + ACAO reflect | high, 아니면 medium |

## TL;DR
헤더·CORS·debug·verbose error 4 축 체크. (1) 필수 보안 헤더 7 개 부재 별로 severity 태그. (2) `Origin` reflect 또는 `*` 와 ACAC true 조합. (3) 15 debug 경로 200 & 100B 이상. (4) 긴 URL 로 500 유도 후 스택 트레이스 누출.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | 타겟 base URL |
| `**kwargs` | Any | — | 무시 |

## Known Limitations
- 헤더 체크는 root `/` 응답 1 회만 — 다른 경로에 CSP 적용된 케이스 miss
- CORS는 `Origin` 요청 헤더만 — preflight `OPTIONS` 별도 확인 없음
- Debug path 리스트 고정 — Rails `/rails/info/routes` 등 미포함
- Server version disclosure 는 `isdigit()` 로만 판단 → `Server: nginx` 는 pass (버전 숨긴 것), `Server: Apache/2.4` catch
- Verbose error 트리거 URL 은 `/AAA...` 500 자 — WAF 에 차단되면 false-negative

## Source Files
- `src/vxis/agent/skills/test_misconfig.py`
