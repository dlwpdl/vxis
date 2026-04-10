# `src/vxis/report/` — NCC-Style HTML Report Generator

> Single-file HTML reports in the NCC Group pentest-report style. Used by `ScanPipelineV2._generate_report()` at the end of every scan.

## Files

| File | Role |
|---|---|
| `generator.py` | `ReportGenerator` class. Methods: `generate_html_file(data, path)` and `render_html(data)`. Re-exports `ReportData`. |
| `templates/` | Jinja2 HTML templates (NCC style) |
| `templates/profiles/default.html` | Main report template — includes verification summary + MITRE ATT&CK coverage table |
| `templates/partials/_finding_card.html` | Per-finding card with MITRE ATT&CK block, CWE links, evidence sections |
| `templates/styles/main.css` | CSS including MITRE block styling |
| `assets/` | CSS / fonts / logos bundled into the HTML |

## Report data contract (`ReportData`)

```python
ReportData(
    scan_id="VXIS-YYYYMMDD-HHMMSS",
    client_name="English only — no ||| separator",   # title stays English
    target="http://...",
    scan_date="YYYY-MM-DD",
    findings=[Finding(...), ...],                     # list[Finding]
    company_name="VXIS Security",
    author="VXIS Autonomous Brain",
    executive_summary="English summary|||한국어 요약",  # bilingual
    attack_chains=[["VXIS-001", "VXIS-002"], ...],     # list[list[str]]
    mitre_coverage={                                   # from mitre_data.compute_mitre_coverage()
        "techniques_covered": ["T1190", ...],
        "tactics_covered": ["Initial Access", ...],
        "coverage_pct": 50.0,
        "total_known_techniques": 16,
        "per_technique": [{"id": "T1190", "name": "...", "tactic": "...", "finding_count": 2}, ...],
    },
)
```

## Report sections

The default report template includes these major sections:

1. **Executive Summary** — bilingual overview
2. **Findings** — per-finding cards with severity, CVSS, CWE, evidence, remediation, MITRE ATT&CK
3. **Verification Summary** — adversarial verifier results (CONFIRMED / UNCONFIRMED / REFUTED counts)
4. **MITRE ATT&CK Coverage** — technique/tactic coverage table with percentage of curated set
5. **Attack Chains** — linked finding chains showing escalation paths

## Verification Summary section (Phase C)

Shows the adversarial verifier's verdict distribution:
- Number of CONFIRMED, UNCONFIRMED, and REFUTED findings
- Zero false positive guarantee when all findings are CONFIRMED

## MITRE ATT&CK Coverage section (Phase C)

Table showing:
- Total techniques covered / total in curated set (16)
- Tactics represented
- Per-technique breakdown with finding counts

Data comes from `mitre_data.compute_mitre_coverage(findings)` in `src/vxis/agent/tools/mitre_data.py`.

## Bilingual convention

All user-facing text fields (except `client_name`) use the `"English|||한국어"` format. The template renders both halves. See `CLAUDE.md` "리포트 작성 규칙" for the full field-by-field spec.

## Strict rules from CLAUDE.md

- `client_name` MUST be English only — no `|||` separator
- `evidence` MUST be `list[Evidence]`, never a plain string
- `affected_component` (singular), NOT `affected_components` (plural)
- `cvss` MUST use `CVSSVector(...)`, never a bare `cvss_score` float
- `scan_id` and `target` are required on every Finding

## Finding enrichment in ScanPipelineV2

`_finding_dict_to_finding_object()` converts in-memory store dicts into `Finding` objects:
- Severity → `Severity` enum
- Title / description / remediation → bilingual `"EN|||EN"`
- Evidence → `list[Evidence]`
- CVSS → severity-weighted `CVSSVector`
- MITRE ATT&CK → auto-inferred from `finding_type` via `mitre_data.infer_techniques()`
- Verification verdict → from adversarial verifier
