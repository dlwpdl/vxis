# `src/vxis/cli/` — Command-Line Entry Point

> `vxis` command (installed via `pyproject.toml` `[project.scripts] vxis = "vxis.cli.main:app"`). Typer + Rich Live TUI.

## Primary command

```bash
vxis scan <target> [OPTIONS]
```

### Options

| Flag | Purpose |
|---|---|
| `--profile`, `-p` | `stealth` / `standard` / `aggressive` |
| `--ghost`, `-g` | Ghost mode — proxy rotation, UA spoof, timing jitter |
| `--output`, `-o` | HTML report output path (honored by Phase A via `09379c2` fix) |
| `--resume` | Resume from checkpoint (legacy, no-op in Phase A v2 shim) |
| `--interactive`, `-i` | Claude Code as Brain (InteractiveBrain path, stdin/stdout NDJSON) |
| `--verbose`, `-v` | DEBUG logging |
| `--allow-inject` | Auto-approve injection gate (benchmarks only) |
| `--instruction` | Inline operator instructions for credentials, focus, exclusions, or approach |
| `--instruction-file` | Markdown/text file with detailed scan instructions |

## Files

| File | Role |
|---|---|
| **`main.py`** (~900 lines) | Typer app with `scan`, `client`, `db` subcommands. Instantiates `ScanPipeline` at line 437, runs it, renders final TUI output. Also prints the `VXIS_BENCHMARK` line for grep-parseable metrics. |
| `interactive.py` | Interactive wizard for scan config (`vxis` with no args → scan wizard) |
| `live_display.py` | Rich Live display object — subscribes to pipeline events (`phase_start`, `phase_end`, `attack`, `hit`, `brain_thinking`) |
| `scan_display.py` | Scan result rendering (findings table, score, duration) |
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

## Phase A change — single-line import swap

`cli/main.py:437` switched from `vxis.pipeline.pipeline` to `vxis.pipeline.scan_pipeline_v2`. Everything else (constructor call at :590, run() call at :602, event callback plumbing, injection gate wiring) is untouched — `ScanPipelineV2` preserves the legacy signature exactly.

## Pre-flight behavior

`preflight.py` runs before `ScanPipeline.run()`. It checks:
- Target reachable (HEAD or GET)
- Required secrets (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / etc., for the LLM Brain fallback chain)
- Optional: GitHub token for OSINT (warned if missing)

On failure it exits non-zero with a clear message. Phase A did not modify pre-flight.

## Rich Live TUI limitations in Phase A

The TUI shows a "Phases" panel with 14 phase boxes (P0 through P18). In Phase A's v2 shim, the Brain loop emits only one `phase_start("scan_loop")` + one `phase_end("scan_loop")` event — so the 14-phase panel shows `0/14 phases` throughout the scan. This is expected and intentional. The panel will be rewritten in Phase B to reflect Brain-driven iteration count.

## Scan exit flow

After `pipeline.run(target)` returns:

1. Final findings table rendered via Rich Table
2. VXIS score printed (`758.8/1000 A` style)
3. Summary line: `Scan completed | <duration>s | <N> finding(s) | <X>/<Y> phases`
4. `VXIS_BENCHMARK peak_context_bytes=… llm_call_count=… brain_decision_count=… findings_count=…` — grep-parseable instrumentation line, used by Task 11/14 benchmark capture
5. HTML report path printed if `ctx.findings` is non-empty

## Do NOT modify main.py further in Phase A

The one-line import swap in Task 10 is the only Phase A change to this file. Any additional CLI changes (argparse, new flags, TUI revamp) should wait for Phase B.
