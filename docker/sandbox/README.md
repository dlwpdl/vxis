# `docker/sandbox/` — VXIS Sandbox Docker Image

> The `vxis/sandbox:latest` image — Strix-equivalent Debian pentest container. Used by `shell_exec` and `python_exec` BrainTools.

## Build

```bash
docker build -t vxis/sandbox:latest docker/sandbox/
```

First build takes 5–10 minutes (apt install + nuclei download from GitHub releases + pip installs). Subsequent rebuilds use the Docker layer cache.

Image size: ~980 MB.

## What's inside

`FROM debian:trixie-slim` plus:

| Category | Tools |
|---|---|
| SQLi | `sqlmap 1.9.6` |
| Web fuzzing | `ffuf 2.1.0`, `gobuster 3.6`, `dirb` |
| Vuln scanning | `nuclei 3.3.4` (downloaded from GitHub releases) |
| Legacy Perl scanner | `nikto` (cloned from GitHub — `libjson-perl`/`libxml-writer-perl` missing, see Phase B fix) |
| Python scanners | `wapiti3` (pip, optional — silent fail allowed) |
| Python runtime | `python3`, `httpx`, `aiohttp`, `requests` (via pip `--break-system-packages`) |
| HTTP utility | `curl`, `wget`, `jq`, `unzip`, `git`, `ca-certificates` |

## Why not Kali?

Kali is ~5 GB. Debian trixie-slim + targeted tools is ~980 MB. Phase A prioritizes image size (fast pulls, lower disk usage on dev laptops) over tool breadth. Phase C enterprise mode may offer a Kali variant as an opt-in.

## Runtime invocation

The `ShellExecTool` in `src/vxis/agent/tools/shell_tools.py` manages the container lifecycle:

1. **Lazy init**: On first `shell_exec` call, `_ensure_sandbox_running()` checks:
   - Docker CLI available on host
   - `vxis/sandbox:latest` image exists locally (if not → error message with build instructions)
   - Container `vxis-sandbox` is running (if not → `docker run -d --name vxis-sandbox --network host -v /tmp/vxis-workspace:/workspace vxis/sandbox:latest sleep infinity`)

2. **Warm reuse**: The container stays running across scans (Strix convention). Only the first scan pays the startup cost.

3. **Dispatch**: Every `shell_exec(command=…)` becomes `docker exec vxis-sandbox sh -c '<command>'` with a configurable timeout (default 120s, max 600s).

4. **Workspace bind mount**: `/tmp/vxis-workspace` on host ↔ `/workspace` inside container. `shell_exec` output files and `python_exec` scripts share this directory. State persists across tool calls within a scan.

## Network mode: host

The container uses `--network host` so targets at `localhost:3000` (Juice Shop) and `localhost:8080` (WebGoat) are directly reachable from inside the sandbox without DNS/port mapping gymnastics.

**⚠ macOS caveat**: Docker Desktop on macOS runs containers in a Linux VM, and `--network host` binds to the VM's network, not the Mac host. Juice Shop / WebGoat running via `docker run` on the same Mac ARE reachable because Docker Desktop's VM shares the network namespace. If targets run outside Docker (e.g. a local Python app on the Mac), they need `host.docker.internal` instead. Phase A benchmarks use Docker-run targets so this works transparently.

## Known issues (tracked for Phase B)

| Tool | Issue | Fix |
|---|---|---|
| `nikto` | Missing Perl modules `JSON` and `XML::Writer` in trixie-slim | Add `libjson-perl libxml-writer-perl` to the apt list |
| `wapiti` | Silent pip install failure | Switch to `apt install wapiti` (if available in trixie-backports) or pin wapiti3 version |
| `arjun` | pip install disabled via `\|\| true` | Verify install succeeds, enable hard fail |
| `dalfox` | Not installed | Add via Go binary download |
| `jwt_tool` | Not installed | Add via pip |

Current working tool set (5/7): sqlmap, ffuf, nuclei, gobuster, dirb — plus curl and python3/httpx/aiohttp. Enough for Phase A benchmarking.

## Verify a built image

```bash
docker exec vxis-sandbox sh -c "sqlmap --version && nuclei -version && ffuf -V && gobuster version"
```

All four should print version strings.

## Do NOT commit image tarballs

Only the Dockerfile is tracked in git. The built image is rebuilt on-demand locally.
