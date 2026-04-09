# `src/vxis/primitives/` — Pure Tool Functions

Pure Python functions that perform specific probe/analysis operations — zero LLM calls, zero I/O state, deterministic. Used by legacy pipeline phases as building blocks.

Files:
- `chain.py` — request chain builder / replayer
- `ghost.py` — ghost layer primitives (used by `vxis.ghost`)
- `knowledge.py` — knowledge store primitives
- `output.py` — output formatters
- `patterns.py` — payload + signature pattern helpers
- `sensing.py` — response sensing (WAF detection, tech stack fingerprinting)
- `session.py` — session-related helpers
- `waf_bypass_db.json` — WAF bypass signature database

Phase A's Brain calls these indirectly via the `http_request` BrainTool → `SessionManager.request()` → primitive helpers internally. The sandbox path (`shell_exec`, `python_exec`) does not use these.
