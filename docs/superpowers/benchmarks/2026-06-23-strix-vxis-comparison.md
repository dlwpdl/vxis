# 2026-06-23 - Strix vs VXIS Comparison

Status: pending full same-environment run.

This file is the single comparison record for the current direction decision:
Strix is the product/UX benchmark, while VXIS should win on accepted evidence,
exploit chain depth, policy gates, and reproducible reporting.

## Environment

| Field | Value |
|---|---|
| Date | 2026-06-23 |
| VXIS working directory | `/Users/eliot/Desktop/Git/vxis` |
| VXIS git SHA | TBD at run time |
| Strix command availability | `command -v strix` returned no path in this workspace check |
| Model | TBD |
| Budget | TBD |

## Targets

| Target | URL | State |
|---|---|---|
| Juice Shop | `http://localhost:3000` | pending |
| WebGoat | `http://localhost:8080/WebGoat` | pending |
| Local repo/source target | TBD | blocked until source-aware VXIS tools are production-promoted |

## Metric Contract

| Metric | Definition |
|---|---|
| confirmed findings | Findings with replayable proof accepted by verifier or VXIS evidence contract |
| critical/high count | Accepted critical/high findings only |
| false positives | Reported findings that cannot be reproduced or lack controls |
| chain depth | Longest validated exploit chain length |
| time | Wall-clock scan time |
| LLM requests/tokens | Provider request and token counts where available |
| repro completeness | Whether request, response/effect, control, replay command, and impact are present |

## Commands

### VXIS

```bash
uv run vxis scan http://localhost:3000 --profile bugbounty --allow-inject --output reports/bench-juice-vxis.html
uv run vxis export <scan_id> --format bugbounty --output reports/bench-juice-vxis-bugbounty.json

uv run vxis scan http://localhost:8080/WebGoat --profile bugbounty --allow-inject --output reports/bench-webgoat-vxis.html
uv run vxis export <scan_id> --format bugbounty --output reports/bench-webgoat-vxis-bugbounty.json
```

### Strix

```bash
strix scan http://localhost:3000
strix scan http://localhost:8080/WebGoat
```

Use the actual installed Strix CLI syntax if it differs. Record the run
directory and token/cost artifacts here.

## Results

### Juice Shop

| Tool | confirmed findings | critical/high | false positives | chain depth | time | LLM requests/tokens | repro completeness |
|---|---:|---:|---:|---:|---:|---:|---|
| Strix | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| VXIS | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

### WebGoat

| Tool | confirmed findings | critical/high | false positives | chain depth | time | LLM requests/tokens | repro completeness |
|---|---:|---:|---:|---:|---:|---:|---|
| Strix | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| VXIS | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

### Local Repo / Source-Aware Target

Blocked for VXIS until source-aware tools are production-promoted from
incubator. Do not compare a Strix source-aware run against VXIS black-box web
mode as if they are equivalent products.

## Analysis

Pending benchmark execution. The current implementation work prepares the VXIS
side by adding `--profile bugbounty`, stricter high/critical evidence contracts,
and `--format bugbounty` accepted-finding JSON.
