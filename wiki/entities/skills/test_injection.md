---
name: test_injection
type: skill
status: active
when_to_read: SQLi/XSS/SSTI/CMDi payload rotation 동작 / round 구분 / time-based 감지 임계값
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/skills/test_injection.py
related:
  - ../modules/scan_loop.md
  - ../modules/skill_runner.md
code_anchors:
  - src/vxis/agent/skills/test_injection.py:execute
  - src/vxis/agent/skills/test_injection.py:_payloads_for_round
---
# test_injection

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | injection (SQLi/XSS/SSTI/CMDi/SSRF/Path/NoSQL/XXE/CRLF/LDAP) |
| Rotation | yes (round 1/2/3, >=4 or <=0 = all combined) |
| Round 1 | classic error-based (`' OR 1=1--`, `<script>alert(1)</script>`, `${7*7}`) |
| Round 2 | blind/time-based (`SLEEP(3)`, `pg_sleep`, `WAITFOR`) + filter bypass + XXE/LDAP/CRLF |
| Round 3 | polyglot / WAF evasion (0xsobky, URL-encoded, unicode, `{id,}`) |
| Time-based 감지 | `sqli_time` + `_elapsed >= 2.5s` → critical |
| Concurrency | `asyncio.Semaphore(10)` |

## TL;DR
단일 파라미터에 SQLi·XSS·SSTI·CMDi·SSRF·XXE 등 11 종 페이로드 난사. `round` 인자로 3 단계 로테이션. scan_loop 이 동일 URL 재큐잉 시 round 증가시켜 WAF 있는 타겟에서도 deeper probe.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `url` | str | 필수 | 타겟 URL (쿼리파라미터 포함 가능) |
| `param_name` | str \| None | None | 주입 대상 파라미터. 없으면 첫 쿼리키, 아예 없으면 `q` 생성 |
| `round` | int | 1 | 1=classic / 2=blind+time / 3=polyglot+WAF / else=all |
| `**kwargs` | Any | — | 무시 (forward-compat) |

## Payload Rounds
- **Round 1 (`PAYLOADS`)**: error-based SQLi (`'`, `UNION SELECT`), 기본 XSS (`<script>alert(1)`), SSTI (`{{7*7}}`, `${7*7}`), cmdi (`;id`, `$(id)`), path (`../../etc/passwd`), SSRF (`169.254.169.254`), NoSQL (`{'$ne': null}`).
- **Round 2 (`PAYLOADS_ROUND2`)**: 시간 기반 blind SQLi (`SLEEP(3)`, `WAITFOR DELAY`, `pg_sleep(3)`), stacked/UNION, OOB probe, XSS 필터 우회 (`<ScRiPt>`, `javascript:`, `<body onload>`), SSTI (Ruby ERB `#{}`, Thymeleaf `*{}`, Razor `@()`), CRLF, XXE, LDAP.
- **Round 3 (`PAYLOADS_ROUND3`)**: 0xsobky 폴리글롯, URL/double-URL encoded, 유니코드 zero-width, SQL 주석 기반 우회 (`'/**/OR/**/1=1--`), null byte path, IFS cmdi (`$IFS$9id`), Jinja2 MRO (`__subclasses__`).

`round >= 4` 또는 `<= 0` → 세 세트 합친 exhaustive 모드.

## Known Limitations
- NoSQL operator 주입만 probe (no query-body injection)
- XXE / OOB는 반사 응답만 감지 (실제 Burp Collab DNS exfil 없음)
- blind SQLi size-delta 임계값 50 바이트 고정
- 파라미터 1개만 동시 테스트 (URL 의 첫 param 또는 `param_name`)

## Source Files
- `src/vxis/agent/skills/test_injection.py`
