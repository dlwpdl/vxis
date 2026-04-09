# `src/vxis/scoring/` — VXIS Capability Scoring

Dynamic scoring system that computes the "VXIS score" (0-1000, A/B/C/D/F grade) based on scan outcomes.

The legacy pipeline uses the full weighted scoring. Phase A's `ScanPipelineV2._compute_vxis_score()` uses a simpler severity-weighted heuristic (critical=200, high=100, medium=50, low=20, info=5, capped at 1000) because finding dicts from `finding_tools` don't carry all the metadata the full scorer needs. Phase B will wire the full scorer back once finding conversion is enriched.

Key file: `tracker.py` (score accumulation + grade mapping).
