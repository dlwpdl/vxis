# `src/vxis/mission/` — Scan Mission Config

Pydantic config for scan missions: scope (external/internal/code), depth, perspective, target list, agent fleet selection.

Used by the legacy `AgentRunner` (agent/runner.py) to map `--profile standard` and scan types (`external`/`internal`/`code`/`zero_touch`) to agent selections. Phase A's v2 shim does not read this — the Brain decides its own scope dynamically from the target URL.

Key types: `MissionConfig`, `Depth`, `Perspective`, `Scope`.
