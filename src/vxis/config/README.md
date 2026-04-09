# `src/vxis/config/` — Configuration Loading

Configuration file loader + env-var merging. Reads `config.toml` at the worktree root, validates fields, and exposes a singleton config object used by `ScanPipeline` and CLI entry points.

Primary consumers: `cli/main.py`, `pipeline/scan_pipeline_v2.py` (accepts config as optional constructor arg).

Do not store secrets in `config.toml` — use env vars for API keys.
