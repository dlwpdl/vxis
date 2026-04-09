# `src/vxis/report/` — NCC-Style HTML Report Generator

> Single-file HTML reports in the NCC Group pentest-report style. Used by `ScanPipelineV2._generate_report()` at the end of every scan.

## Files

| File | Role |
|---|---|
| `generator.py` | `ReportGenerator` class. Methods: `generate_html_file(data, path)` and `render_html(data)`. Re-exports `ReportData`. |
| `templates/` | Jinja2 HTML templates (NCC style) |
| `assets/` | CSS / fonts / logos bundled into the HTML |

## Report data contract (`ReportData`)

```python
ReportData(
    scan_id="VXIS-YYYYMMDD-HHMMSS",
    client_name="English only — no ||| separator",   # ⚠ title stays English
    target="http://…",
    scan_date="YYYY-MM-DD",
    findings=[Finding(...), …],                       # list[Finding]
    company_name="VXIS Security",
    author="VXIS Autonomous Brain",
    executive_summary="English summary|||한국어 요약",  # bilingual
    attack_chains=[["VXIS-001", "VXIS-002"], …],       # list[list[str]]
)
```

## Bilingual convention

All user-facing text fields (except `client_name`) use the `"English|||한국어"` format. The template renders both halves side-by-side. See `CLAUDE.md` "리포트 작성 규칙" for the full field-by-field spec.

## Strict rules from CLAUDE.md

- `client_name` MUST be English only — no `|||` separator
- `evidence` MUST be `list[Evidence]`, never a plain string
- `affected_component` (singular), NOT `affected_components` (plural)
- `cvss` MUST use `CVSSVector(...)`, never a bare `cvss_score` float
- `scan_id` and `target` are required on every Finding

## Phase A adaptation

`ScanPipelineV2._finding_dict_to_finding_object()` converts the in-memory `finding_tools` store dicts (simple shape: title/severity/description/evidence as strings) into proper `Finding` objects with safe defaults for the rich fields (CVSS severity-weighted, CWE optional, bilingual auto-duplicated as `"EN|||EN"`).

Phase B will enrich this conversion to produce real bilingual translations via a dedicated LLM call.
