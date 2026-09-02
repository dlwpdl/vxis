# `src/vxis/ghost/` — Stealth / Anti-Attribution Layer

Proxy rotation, User-Agent spoofing, TLS fingerprint masking (via curl-cffi), timing jitter, and metadata scrubbing. Activated via `--ghost` flag or `ghost://` URL prefix.

Ghost activation still starts from `parse_ghost_trigger`, but coverage is no longer limited to the in-process Hands path. Today:

- `TargetSession` / `http_request`: covered by `GhostTransport`
- browser tools: proxied or UA-routed when Ghost is active
- `shell_exec` / `python_exec`: partial coverage through injected proxy env only
- `run_skill` / `agent_graph`: delegated paths; inspect the egress contract for per-tool truth
- `nmap_scan`: intentionally direct raw-socket traffic, not anonymized by proxy env

The runtime `ghost_status()` / control-plane snapshot now exposes those exact gaps so the operator sees where Ghost is authoritative and where it is not.

Key files: `layer.py` (GhostLayer), `trigger.py` (URL prefix parser), `transport.py` (httpx transport).
