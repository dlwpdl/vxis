# `.github/` — GitHub-Level Configuration

> All GitHub-specific automation + metadata. Primary content: 12 workflow definitions under `workflows/`.

## Contents

| Path | Purpose |
|---|---|
| `workflows/*.yml` | 12 GitHub Actions workflows — see [`../GITHUB_ACTIONS.md`](../GITHUB_ACTIONS.md) for the full system overview |

## Quick reference — workflow groups

| Group | Workflows | Role |
|---|---|---|
| **Threat intel feeders** | `cve-watch.yml`, `upstream-watch.yml`, `domain-intel.yml` | Produce raw signals from external sources |
| **Signal pipeline** | `signal-ingest.yml`, `signal-analyze.yml`, `action-bridge.yml` | Unify signals → decide actions → open issues |
| **Self-coding loop** | `auto-implement.yml` | Claude Code spawns on `claude-implement` label → writes patches → opens PRs |
| **PR quality gates** | `lint.yml`, `test.yml`, `benchmark.yml` | Block bad merges |
| **Growth measurement** | `growth-loop.yml`, `growth-digest.yml` | Weekly benchmark + summary, feeds back into issue opener |

**Full documentation**: [`../GITHUB_ACTIONS.md`](../GITHUB_ACTIONS.md) — explains how these workflows chain together to form the self-improvement cycle.

## Adding a new workflow

1. Place the `.yml` file in `.github/workflows/`
2. Follow the naming convention: `<domain>-<verb>.yml` (e.g. `cve-watch`, `signal-ingest`, `growth-loop`)
3. Include a top-level comment explaining the trigger and what the workflow achieves
4. Update `../GITHUB_ACTIONS.md` with a row in the workflow catalog table
5. If the workflow opens issues / modifies code, wire it into the self-growth cycle explicitly
