# `src/vxis/cli/` — Command-Line Entry Point

> `vxis` command (installed via `pyproject.toml` `[project.scripts] vxis = "vxis.cli.main:app"`). Typer + Textual tree TUI, with Rich fallback for headless/no-TTY runs.

## Primary command

```bash
vxis scan <target> [OPTIONS]
```

### Options

| Flag | Purpose |
|---|---|
| `--profile`, `-p` | `stealth` / `standard` / `aggressive` |
| `--ghost`, `-g` | Ghost mode — proxy rotation, UA spoof, timing jitter |
| `--output`, `-o` | HTML report output path |
| `--resume` | Resume from checkpoint (compatibility option; no-op in the current single-loop runtime) |
| `--interactive`, `-i` | Claude Code as Brain (InteractiveBrain path, stdin/stdout NDJSON) |
| `--tui/--no-tui` | Clickable Textual tree TUI by default on a real terminal; Rich fallback when disabled/headless |
| `--verbose`, `-v` | DEBUG logging |
| `--allow-inject` | Auto-approve injection gate (benchmarks only) |
| `--kind` | Target surface. Use `web` for the production-tested dynamic scan path. |
| `--box` | `auto` or `black`. Production scans are black-box only; unsupported white/grey values fail closed to black until source-aware CODE tools are promoted. |
| `--instruction` | Inline operator instructions for credentials, focus, exclusions, or approach |
| `--instruction-file` | Markdown/text file with detailed scan instructions |

## Files

| File | Role |
|---|---|
| **`main.py`** (~900 lines) | Typer app with `scan`, `client`, `db` subcommands. Instantiates `ScanPipeline`, runs it, renders final output, and prints the `VXIS_BENCHMARK` line for grep-parseable metrics. |
| `interactive.py` | Interactive wizard for scan config (`vxis` with no args → scan wizard) |
| `scan_tui.py` | Canonical clickable Strix-style tree TUI: Director iterations, delegated agents, drill-in detail, cost/context/status bar |
| `scan_display.py` | Single Rich Live fallback module for Brain-first scans and the small legacy snapshot compatibility renderer |
| `preflight.py` | Pre-flight checks (reachable target, required tools, disk space) |
| `installer.py` | Optional scanner tool installer (apt/pip/go install automation) |

## Hybrid LLM Roles

VXIS now resolves role-specific LLM settings before `AgentBrain` starts:

- Director/root brain: `VXIS_DIRECTOR_LLM[_PROVIDER/_MODEL]`
- Worker/task agents: `VXIS_WORKER_LLM[_PROVIDER/_MODEL/_BASE_URL]`
- Verifier/judge: `VXIS_VERIFIER_LLM[_PROVIDER/_MODEL]`
- Summarizer/compressor: `VXIS_SUMMARIZER_LLM[_PROVIDER/_MODEL/_BASE_URL]`

The no-args TUI still writes `UPSTREAM_LLM_PROVIDER` and
`UPSTREAM_LLM_MODEL` for compatibility. Cloud choices additionally become the
director/verifier role. Local choices additionally become the worker/summarizer
role, so a scan can use a frontier director with local bounded task execution.

## Custom Instructions

Strix-style operator instructions are injected into the Brain loop via:

```bash
vxis scan https://app.example --instruction "Focus on IDOR; exclude /admin"
vxis scan https://app.example --instruction-file ./pentest-instructions.md
```

Inline and file instructions can be combined. The merged value is passed as
`VXIS_SCAN_INSTRUCTIONS` and appears in the model prompt as an explicit
operator-instruction block.

## Local llama.cpp Worker

The no-args TUI path supports scan start -> AI autonomous scan -> `Local Runtime` -> `llama.cpp server`.
It sets `UPSTREAM_LLM_PROVIDER=llamacpp`, `UPSTREAM_LLM_MODEL`, and
`VXIS_LLAMACPP_BASE_URL`, asks for the runtime context window
(`VXIS_LLAMACPP_CONTEXT`), then verifies `GET /v1/models` before delegating to
the same Brain-first pipeline used by `vxis scan`. Local runtimes use a tighter
history-compression profile than cloud models. The TUI prefers a running
compact proxy at `http://127.0.0.1:8090`, otherwise it falls back to
`http://localhost:8080`. The llama.cpp context default is `8192`; keep it
matched to `llama-server -c/--ctx-size`.

Start llama.cpp separately first:

```bash
llama-server -m /path/to/model.gguf -c 8192 --host 127.0.0.1 --port 8080
```

## Pre-flight behavior

`preflight.py` runs before `ScanPipeline.run()`. It checks:
- Target reachable (HEAD or GET)
- Required secrets (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / etc., for the LLM Brain fallback chain)
- Optional: GitHub token for OSINT (warned if missing)

On failure it exits non-zero with a clear message.

## Scan exit flow

After `pipeline.run(target)` returns:

1. Final findings table rendered via Rich Table
2. VXIS score printed (`758.8/1000 A` style)
3. Summary line: `Scan completed | <duration>s | <N> finding(s)`
4. `VXIS_BENCHMARK peak_context_bytes=… llm_call_count=… brain_decision_count=… findings_count=…` — grep-parseable instrumentation line, used by Task 11/14 benchmark capture
5. HTML report path printed if `ctx.findings` is non-empty
