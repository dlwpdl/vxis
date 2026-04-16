---
name: ADR-004 — NCC Group Report Format (Single HTML, Bilingual)
type: decision
status: active
when_to_read: 리포트 포맷 규칙 / Finding 필드 구조 / bilingual ||| 사용법 / ReportData 필수 필드 / WEBGOAT_FINDINGS 템플릿
updated: 2026-04-16
sources:
  - /Users/eliot/.claude/projects/-Users-eliot-Desktop---vxis/memory/feedback_report_format.md
related:
  - ./003_no_raw_httpx.md
---
# ADR-004 — NCC Group Report Format: Single HTML + Bilingual

## 핵심 사실
| 항목 | 값 |
|---|---|
| Status | Accepted |
| Date | 2026-04-16 |
| 정식 템플릿 | `scripts/generate_benchmark_reports.py` 의 `WEBGOAT_FINDINGS` 섹션 |
| 렌더러 | `ReportGenerator.generate_html_file(data, path)` 또는 `render_html(data)` |
| Bilingual | `title`/`description`/`remediation`/`executive_summary` = `"English|||한국어"` |
| client_name | 영어 고정, `\|\|\|` 금지 |
| description 순서 | WHAT → HOW (Step 1~N) → IMPACT → PoC → ATTACK PATH (한국어도 동일 순서) |
| remediation 순서 | Immediate / Short-term / Long-term (한국어: 즉시 / 단기 / 장기) |

## TL;DR
리포트는 단일 HTML (NCC Group 스타일), Finding 필드는 bilingual `|||` 로 영/한 병기. `WEBGOAT_FINDINGS` 가 정식 템플릿 — 매번 필드 오류로 5+ 회 재작성한 경험으로 박제. `cvss` 는 `CVSSVector(vector_string=..., base_score=...)`, `evidence` 는 `list[Evidence]`, `affected_component` 는 단수 문자열. `ReportGenerator` import 는 `vxis.report.generator`.

## Context
리포트 작성 시 Finding 필드 오류 반복: `evidence` 문자열 전달, `affected_components` 복수형, `cvss_score` 직접 전달, `scan_id`/`target` 누락, `|||` 미사용, description 순서 뒤섞임. 5+ 회 재작성. NCC Group 스타일은 업계 표준 — single HTML, Executive Summary + Findings (severity 순) + Appendix.

## Options
1. **자유 포맷** — 매번 재정의, 재작성 비용 지속.
2. **NCC 스타일 고정 + bilingual `\|\|\|`** — 초기 학습 1 회.
3. **PDF + 영·한 별도 파일** — 복수 파일 혼란.

## Decision
옵션 2 채택. `ReportGenerator.generate_html_file()` 단일 choke point. Finding 필수 (id/scan_id/target/title/description/severity/finding_type/source_plugin), bilingual `|||` 4 필드 (title/description/remediation/executive_summary). description = WHAT → HOW → IMPACT → PoC → ATTACK PATH (한국어 동일). remediation = Immediate/Short-term/Long-term. `cvss=CVSSVector(vector_string=..., base_score=...)`, `evidence=list[Evidence(...)]`, `affected_component=단수 str`. client_name 영어 고정.

## Consequences
- **Pro**: 리포트 재작업 제로 — 템플릿 그대로.
- **Pro**: 한국어 고객 친숙, 영·한 동등 품질.
- **Pro**: 단일 HTML → 이메일/첨부/오프라인 쉬움.
- **Con**: Finding 필드 규약 기억 필요 — 본 ADR + CLAUDE.md 이중 참조로 완화.
- **Con**: bilingual 규칙 위반 시 렌더러 깨짐 — CI 스키마 검증 향후 추가.
