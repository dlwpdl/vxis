# `src/vxis/industry/` — Industry-Wide Autonomous Scanning

Orchestrator for scanning all companies in a given industry vertical (e.g. "all fintech unicorns") via bulk target enumeration + scheduled scans.

Operational layer — not consumed by per-scan Phase A loop. Depends on `scheduler/` and `integrations/`.
