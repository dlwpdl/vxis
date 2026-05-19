# Local LLM Runbook

Operational notes for running VXIS against a local llama.cpp backend.

## Baseline Runtime

- Date observed: 2026-04-30 KST.
- llama.cpp server: `./build/bin/llama-server ... -c 8192 --host 127.0.0.1 --port 8080 --no-warmup`.
- Compact proxy: `/Users/ash/Desktop/Git/llama.cpp/tmp/vxis_compact_proxy.py` on `http://127.0.0.1:8090`.
- Proxy health observed at `GET http://127.0.0.1:8090/health`:
  `ctx_size=8192`, `target_input_tokens=6200`, `recent_messages=8`, `default_enable_thinking=false`.
- Proxy OpenAI-compatible endpoint observed working at `POST http://127.0.0.1:8090/v1/chat/completions`.
- VXIS base URL should be `http://127.0.0.1:8090` when using the compact proxy. Do not append `/v1`; VXIS appends `/v1/chat/completions`.
- Keep `VXIS_LLAMACPP_CONTEXT=8192` matched to `llama-server -c 8192`.

## TUI Behavior

- Path: `vxis` -> scan start -> AI autonomous scan -> `Local Runtime` -> `llama.cpp server`.
- The TUI probes `http://127.0.0.1:8090/v1/models` first and uses it as the default if the compact proxy is alive.
- If `VXIS_LLAMACPP_BASE_URL` is already set, that env var wins. Set it to `http://127.0.0.1:8090` or clear it before launch if the TUI keeps defaulting to direct `8080`.
- The context prompt default comes from proxy `/health.ctx_size`; if unavailable, VXIS falls back to `8192`.
- New scans log the effective LLM runtime as `llm runtime selected: provider=... model=... base_url=... context=... output_cap=... profile=...`.

## Current Run Notes

- Scan log observed: `logs/scan_20260430_234558.log`.
- VXIS PID observed: `11217`.
- Current process was observed with a direct `127.0.0.1:8080` connection, not `8090`. That means the active TUI process likely started before the compact-proxy default patch, or `VXIS_LLAMACPP_BASE_URL` was set to `8080`.
- Restart the TUI for the 8090 auto-detect and LLM-runtime logging changes to apply.
- Progress observed in the run:
  - `enumerate_endpoints`: 2 accessible (`/admin/`, `/favicon`).
  - `test_sensitive_files`: 0 exposed out of 54 scanned.
  - `test_infra`: clean, 40 tested.
  - `attempt_auth`: failed after 17 attempts.
  - `test_idor`: repeated clean probes against common account/order/profile paths.
  - auto-login entered a 9-attempt loop; individual attempts were taking about 37 seconds in this run.
  - auto-login exhausted all 9 credentials, then told Brain to pivot.
  - Local memory compression engaged for `provider=llamacpp`: `5682 -> 3999` estimated tokens after compressing 5 messages into 1 summary.
  - Local memory compression ran again: `4036 -> 1919` estimated tokens after two summaries.
  - `auto-ffuf` started at iteration 10.
  - `test_injection` found SQLi, XSS, and SSTI candidates on parameter `q`.
  - `test_misconfig` found 7 findings, including missing CSP and reflected CORS origins.
  - Finding reporting recorded `VXIS-0001 [HIGH] misconfiguration`, then deduplicated additional misconfiguration items against the same target.
  - Director attempted `browser_fill_form` against `/admin/`, but the tool execution failed at iteration 12.
  - An injection candidate was auto-enriched, then auto-verify returned `REFUTED`; `report_finding` was blocked for that candidate.
  - `test_crypto` found a hardcoded secret/password in a Next.js static chunk and recorded `VXIS-0002 [CRITICAL] weak_crypto`.
  - `test_api_security` and `test_business_logic` completed clean.
  - Director attempted `shell_exec` with `docker build -t vxis/sandbox:latest docker/sandbox/` twice; both failed.
  - Sweep at iteration 25 queued untried skills: `post_auth_enum`, `test_auth_deep`, `test_ssrf`, `test_xss`; all completed clean.
  - XSS payload rotation re-queued round 2, then round 3 after another clean result.
  - Brain emitted malformed JSON once; VXIS recovered 4 actions via regex fallback and continued.
  - Memory compression remained stable across later iterations, e.g. `3504 -> 1875` estimated tokens.
  - XSS round 3 also completed clean.
  - Director attempted a third `shell_exec` docker-build variant from `/`; it failed again. This action used `cmd` instead of the tool schema's required `command` key.
  - `spring_boot` playbook was requested again and deduped.
  - `test_injection` repeated on parameter `q`, again finding SQLi/SSTI/XSS candidates.
  - Director executed a basic `http_request` successfully at iteration 36.

## Improvement Memo

- Add or keep explicit LLM runtime logging in every scan log. Without this, local/cloud/provider/context debugging requires `lsof` and process inspection.
- Reduce metadata endpoint probe drag for normal public web targets. The current run still spent three 4-second attempts on `169.254.169.254` paths and one DNS failure on `metadata.google.internal`.
- Cap or profile-gate auth brute-force defaults for local LLM runs. The observed `attempt_auth` 17 attempts plus auto-login 9 attempts are slow and noisy when there is no strong login signal.
- Add skill duration summaries to final scan output. The log shows which skills ran, but not a compact per-skill latency table.
- Add LLM call latency/token summaries for local runs. The compact proxy already knows `ctx_size` and `target_input_tokens`; VXIS should surface request count, average latency, and failed-call count.
- Revisit finding dedup granularity for `misconfiguration`. Header issues and CORS reflection should not collapse into one target-level finding when their evidence and remediation differ.
- Log full failure reasons for browser tool actions. The current `browser_fill_form -> fail` line does not show whether the selector schema, page state, navigation, or Playwright action failed.
- Log auto-verifier rationale compactly. `REFUTED` is useful, but the scan log should show the deciding evidence so false-positive tuning does not require deep debugging.
- Penalize or block repeated failing `shell_exec` commands in the Brain loop. The repeated `docker build` attempt is not target-specific progress and should not be selected repeatedly after failure.
- Canonicalize local-model tool args before dispatch, e.g. map `shell_exec.cmd` to `shell_exec.command`, or reject with a schema-repair prompt before counting it as a normal failed tool execution.
- Add a local-model JSON strictness repair loop. Regex fallback worked, but malformed JSON is a model-quality signal; the next prompt should explicitly correct schema compliance.
- Add payload-rotation stop conditions. Re-queuing XSS rounds after repeated clean results should depend on a new signal, not just elapsed iteration count.
- Deduplicate repeated injection candidates by `(parameter, payload class, evidence)` and route repeats into verifier/reporting instead of rescanning the same input.
- Preserve provider-specific context behavior. `llamacpp` should remain a small local profile around 8192 context, while cloud providers can keep larger history and larger output caps.
- Consider a "local-fast" scan profile that skips high-latency probes by default and only expands when the Brain has a concrete signal.
