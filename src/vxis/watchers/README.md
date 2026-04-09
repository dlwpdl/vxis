# `src/vxis/watchers/` — 24/7 Threat Watchers

Background daemons that monitor external signals continuously:
- CVE watch (`cve-watch.yml` GH Action) — polls NVD / GitHub security advisories hourly
- Domain intel (`domain-intel.yml`) — forecast + industry intel daily/weekly/monthly
- Upstream watch (`upstream-watch.yml`) — dependency updates weekly

These run OUTSIDE the per-scan loop — they feed the knowledge base and optionally trigger targeted rescans via `scheduler/`.

Phase A scans do not invoke watchers. Watchers are ops-level infrastructure.
