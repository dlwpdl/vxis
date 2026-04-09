# `src/vxis/models/` — Pydantic Data Models

> Canonical data model definitions. The authoritative location for Finding and related types.

## Files

| File | Defines |
|---|---|
| `finding.py` | `Finding`, `Severity` (UPPERCASE enum: CRITICAL/HIGH/MEDIUM/LOW/INFO), `Evidence`, `EvidenceType`, `CVSSVector`, `Reference`, `MitreAttack` |

## Key types

### `Finding`

```python
Finding(
    id="XX-NNN",                           # target abbreviation + number
    scan_id="VXIS-YYYYMMDD-HHMMSS",
    target="http://…",
    title="English title|||한국어 제목",     # bilingual
    description="WHAT/HOW/IMPACT/PoC/ATTACK PATH|||…",
    severity=Severity.CRITICAL,
    finding_type="sql_injection",          # snake_case
    source_plugin="scan_agent_loop",       # Phase A uses this value
    affected_component="…",                # SINGULAR
    cvss=CVSSVector(vector_string="CVSS:3.1/…", base_score=9.5),
    cwe_ids=["CWE-89"],
    mitre_attack=MitreAttack(...),         # recommended for Critical/High
    evidence=[Evidence(evidence_type="log", title="…", content="…")],
    remediation="Immediate/Short/Long-term|||…",
    references=[Reference(title="…", url="…")],
)
```

### `Severity` (UPPERCASE enum)

Common footgun: members are UPPERCASE. Mapping table for string → enum:

| String | Enum |
|---|---|
| `"critical"` | `Severity.CRITICAL` |
| `"high"` | `Severity.HIGH` |
| `"medium"` | `Severity.MEDIUM` |
| `"low"` | `Severity.LOW` |
| `"informational"` | `Severity.INFO` ⚠ note: `INFO`, not `INFORMATIONAL` |

### `Evidence`

Evidence items attached to a Finding. `evidence_type` is one of:
- `http_request_response`
- `log`
- `packet_capture`

Content is a raw string (HTTP text, log excerpt, hex dump, etc.). **Never pass a string to `evidence=` directly** — always wrap in a list: `evidence=[Evidence(...)]`.

## Do NOT duplicate these types

Any new code needing Finding / Evidence / CVSSVector should import from `vxis.models.finding`. The re-export in `vxis.evidence.schema` is kept for backward compat only.
