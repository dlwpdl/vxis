---
name: report_generator
type: module
status: active
when_to_read: NCC 스타일 HTML 렌더 / generate_html_file 호출점 / bilingual 필터 / ReportData 스키마
updated: 2026-04-16
sources:
  - ../../../src/vxis/report/generator.py
related:
  - ./scan_loop.md
  - ../pipelines/P6_ncc_style.md
code_anchors:
  - src/vxis/report/generator.py:ReportGenerator
  - src/vxis/report/generator.py:ReportData
  - src/vxis/report/generator.py:ReportGenerator.generate_html_file
---
# report_generator

## 핵심 사실
| 항목 | 값 |
|---|---|
| Role | NCC Group 스타일 단일 HTML 렌더러 |
| Engine | Jinja2 + FileSystemLoader (`report/templates/`) |
| 기본 템플릿 | `profiles/default.html` |
| 필터 | `severity_color`, `severity_badge`, `bilingual` |
| 글로벌 | `severity_donut_svg`, `severity_bar_svg` (차트 inline SVG) |
| PDF | `wkhtmltopdf` 쉘아웃 (optional) |
| Severity 순서 | critical → high → medium → low → informational |

## TL;DR
ReportData (findings, chains, 메타) → Jinja2 템플릿 → NCC 스타일 단일 HTML. `|||` bilingual 필터가 English|||한국어 문자열을 자동 분리. PDF 는 HTML 먼저 렌더 후 wkhtmltopdf 로 변환.

## Key Surfaces
- `ReportGenerator.__init__(template_dir)` — Jinja2 env + 필터/글로벌 등록.
- `ReportGenerator.render_html(data, template_name)` — HTML 문자열 반환.
- `ReportGenerator.generate_html_file(data, output_path, template_name)` — UTF-8 파일 쓰기. parent dir 자동 생성.
- `ReportGenerator.generate_pdf(data, output_path, template_name)` — wkhtmltopdf 쉘아웃.
- `ReportData` — dataclass. `scan_id`, `client_name`, `target`, `findings: list[Finding]`, `attack_chains: list[list[str]]`, `screenshots: dict[str, str]`, `methodology`.
- `_SEVERITY_ORDER`, `_SEVERITY_WEIGHTS` — 위험 점수 계산용 상수.

## Invariants
- `client_name` 은 영어 고정 — `|||` 사용 금지 (프레젠테이션 노이즈).
- `Finding.title/description/remediation` 은 `|||` bilingual 필수 — 한국어도 영어만큼 상세.
- `attack_chains` 는 `list[list[str]]` — finding_id 체인.
- `generate_html_file` 의 output_path 는 resolve 후 parent mkdir — 절대 경로 권장.
- `cvss` 필드는 `CVSSVector` 객체 (vector_string + base_score) — 직접 `cvss_score` 할당 금지.

## Related
- [P6_ncc_style](../pipelines/P6_ncc_style.md) — 이 모듈을 호출하는 리포트 파이프라인
- [scan_loop](./scan_loop.md) — 스캔 완료 후 ReportData 를 생성
