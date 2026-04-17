---
name: test_sensitive_files
type: skill
status: active
when_to_read: 노출 파일·백업·키 탐지 / body-aware severity 조정 / actuator masking
updated: 2026-04-17
sources:
  - ../../../src/vxis/agent/skills/test_sensitive_files.py
related:
  - ../../concepts/severity_oracle.md
  - ./test_infra.md
  - ./enumerate_endpoints.md
code_anchors:
  - src/vxis/agent/skills/test_sensitive_files.py:execute
  - src/vxis/agent/skills/test_sensitive_files.py:_adjust_severity
---
# test_sensitive_files

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | info-disclosure |
| Rotation | no |
| Paths | 약 50 개 + severity tagged (git / env / backup / keys / actuator / docs / logs) |
| Severity oracle | `_adjust_severity()` — body 내용 기반 up/downgrade |
| Actuator masking | `/actuator/env` 에 `"******"` 비율 > 60% → `low` |
| Unmasked secret | `secret|password|jdbc:|mongodb://|postgres://` 발견 → `critical` |
| Baseline | `/definitely-not-real-probe` 로 SPA 200 감지 |

## TL;DR
정적 경로 50 여개를 blast 하되, `_adjust_severity()` 가 실제 응답 body 를 보고 severity 조정. Spring Boot sanitizer 가 가린 env 는 `critical` → `low`, 빈 `/metrics` 도 `low`. 반대로 unmasked 시크릿 발견 시 `critical` 유지/격상.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | 타겟 base URL |
| `baseline_size` | int \| None (kwargs) | None | SPA catch-all 크기 — 없으면 skill 내부서 probe |
| `**kwargs` | Any | — | 기타 무시 |

## Known Limitations
- `_adjust_severity` 는 `/actuator/env`, `/actuator/health`, `/.env`, `/metrics` 4 종만 커스텀 로직 — 다른 경로는 declared severity 그대로
- 200 & size > 50 응답만 finding (empty dir listing 놓침)
- `/etc/passwd` · `/.htpasswd` 같은 시스템 경로가 웹서버에서 직접 노출되는 케이스만 (traversal 은 `test_injection`)
- 동적 token 이 들어간 backup URL (`/backup-XXXX.sql`) 미지원

## Source Files
- `src/vxis/agent/skills/test_sensitive_files.py`
