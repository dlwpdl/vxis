# `src/vxis/evidence/` — Evidence Schema Re-Exports

> Thin re-export layer for the Finding / Evidence / Severity types that live in `src/vxis/models/finding.py`. Exists for backward-compat with legacy imports.

## Files

| File | Role |
|---|---|
| `__init__.py` | Re-exports `Evidence`, `Severity`, `EvidenceType` from `vxis.models.finding` |
| `schema.py` | Historical location — now a redirect |
| `engine.py` | `EvidenceEngine` — finding persistence helper (used by legacy agents/runner.py) |

## Canonical location

The authoritative definitions of `Finding`, `Evidence`, `Severity`, `CVSSVector`, `Reference`, `MitreAttack` are in **`src/vxis/models/finding.py`**. Always import from there in new code:

```python
from vxis.models.finding import Finding, Severity, Evidence, CVSSVector
```

`vxis.evidence.schema` still works but is deprecated — it exists so that old imports in legacy files don't break.

## Phase A integration

`ScanPipelineV2._finding_dict_to_finding_object()` imports from `vxis.models.finding` (canonical path) to construct Finding objects from the in-memory store dicts. See `pipeline/scan_pipeline_v2.py`.

## Severity enum (UPPERCASE!)

```python
from vxis.models.finding import Severity
Severity.CRITICAL
Severity.HIGH
Severity.MEDIUM
Severity.LOW
Severity.INFO        # ⚠ note: INFO not "informational"
```

This is a common footgun — the `finding_tools.ReportFindingTool` input schema uses the string `"informational"`, which is mapped to `Severity.INFO` in `_finding_dict_to_finding_object`.
