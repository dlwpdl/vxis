# `src/vxis/ghost/` — Stealth / Anti-Attribution Layer

Proxy rotation, User-Agent spoofing, TLS fingerprint masking (via curl-cffi), timing jitter, and metadata scrubbing. Activated via `--ghost` flag or `ghost://` URL prefix.

Phase A preserves ghost activation in `ScanPipelineV2.run()` via `parse_ghost_trigger`. When active, `GhostTransport` is injected into the HTTP client's transport layer. Affects ONLY the in-process Hands path — the sandbox tools (`shell_exec`/`python_exec`) would need their own curl / requests wrapping to benefit, which Phase A does not do.

Key files: `layer.py` (GhostLayer), `trigger.py` (URL prefix parser), `transport.py` (httpx transport).
