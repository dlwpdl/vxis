---
name: P6 NCC Style
type: pipeline
status: active
when_to_read: NCC 스타일 HTML 리포트 생성 / ReportData 구성 / bilingual 필수 필드 / Finding 직렬화
updated: 2026-04-16
sources:
  - ../../../src/vxis/report/generator.py
  - ../../../src/vxis/report/attack_graph.py
  - ../../../src/vxis/report/ai_summary.py
related:
  - ./P8_synthesis.md
  - ./P12_evolution.md
  - ../modules/report_generator.md
code_anchors:
  - src/vxis/report/generator.py:ReportGenerator
  - src/vxis/report/generator.py:ReportData
  - src/vxis/report/attack_graph.py:build_attack_graph_from_findings
---
# P6 — NCC Style

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 7 Report |
| 앞 단계 | P8 Synthesis (chains) / P5 Special (findings) |
| 뒤 단계 | P12 Evolution (learning) |
| 역할 | NCC Group 스타일 단일 HTML 리포트 생성 |
| 템플릿 | `report/templates/profiles/default.html` |
| 필수 | Finding.title/description/remediation 는 `|||` bilingual |
| 확장 | attack_graph SVG, AI summary, 차트 |

## TL;DR
findings + chains + screenshots 를 ReportData 로 조립, Jinja2 템플릿으로 NCC 스타일 단일 HTML 렌더. bilingual `|||` 필터, severity 도넛/바 SVG, attack graph 네트워크 다이어그램 포함.

## Stage
Report — 모든 exploitation·synthesis 완료 후 최종 deliverable.

## Inputs-Outputs
- Input: `ScanContext.findings`, `attack_chains`, `screenshots`, client/target 메타.
- Output: `<scan_id>.html` 파일 (UTF-8).

## Triggers
- `ScanPipelineV2._generate_report(ctx)` 호출.
- `scripts/generate_benchmark_reports.py` 으로 벤치마크 리포트 생성.

## Related Pipelines
- [P8 Synthesis](./P8_synthesis.md) — 앞 단계 (체인 공급)
- [P12 Evolution](./P12_evolution.md) — 뒤 단계 (학습 피드백)
