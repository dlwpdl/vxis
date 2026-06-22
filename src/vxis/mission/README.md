# `src/vxis/mission/` — Scan Mission Config

Pydantic config for scan missions: scope (external/internal/code), depth,
perspective, and target list shape.

Kept for mission-shape compatibility and legacy config loading. The live
Brain-first scan path does not select an agent fleet from this package; it
decides scope dynamically from the target URL and scan policy.

Key types: `MissionConfig`, `Depth`, `Perspective`, `Scope`.
