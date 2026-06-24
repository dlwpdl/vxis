# Deterministic Replay Gate - 2026-06-24

## Goal

Turn "Brain says this finding is real" into "VXIS just replayed the proof and it
still holds" for high/critical findings.

This is a gate, not a new scanner. Reuse existing finding evidence, replay
commands, raw HTTP transcripts, `http_request`, and verifier status. No SDK, no
planner, no new agent.

## Non-Goals

- Do not rewrite the verifier.
- Do not replay destructive requests by default.
- Do not invent a second evidence model.
- Do not block medium/low findings in the first pass.
- Do not parse every possible tool transcript. Start with raw HTTP and explicit
  `replay_command`.

## Inputs

Use fields already carried by `Finding` / report-finding metadata:

- `severity`
- `status`
- `replay_command`
- `poc_script_code`
- `raw_data.request_or_payload`
- `raw_data.response_or_effect`
- `raw_data.control_comparison`
- `evidence[].content`

Accepted replay source order:

1. explicit safe raw HTTP request
2. explicit `curl`/`python` replay command that can be safely classified
3. `poc_script_code` raw HTTP request block
4. evidence raw HTTP request block

## Safety Rule

Replay only when the request is safe by policy:

- `GET`, `HEAD`, and `OPTIONS`: allowed
- `POST`, `PUT`, `PATCH`, `DELETE`: require existing mutation approval path
- unknown command shape: not replayed; mark `blocked_policy`

No shell execution in v1 gate unless the command classifier can prove it is a
single safe HTTP replay. Prefer raw HTTP through existing `http_request`.

## Oracle

Replay result is accepted when all are true:

- replay request executes successfully
- response/effect still matches the vulnerable signal
- control comparison is present and still differs from the replay result
- finding has an impact statement

Minimal deterministic oracle:

- status delta: expected status appears, or control/replay status differs as
  claimed
- body marker: a short marker from `response_or_effect` appears
- negative marker: control marker does not appear in replay, or replay marker
  does not appear in control

If no deterministic marker can be extracted, return `blocked_oracle`, not pass.

## Output

Attach a compact replay verdict to the finding metadata:

```json
{
  "replay_gate": {
    "status": "passed | failed | blocked_policy | blocked_oracle",
    "method": "machine_http | replay_command",
    "control_status": 403,
    "replay_status": 200,
    "matched_markers": ["orderId"],
    "reason": "short human-readable reason"
  }
}
```

## Finish Gate

`finish_scan` rejects when any critical/high finding lacks:

- `status == confirmed`
- `replay_gate.status == passed`

If replay fails, the finding is not deleted. It is demoted for final report
purposes:

- `critical/high + failed` -> `unconfirmed`
- `blocked_policy` -> keep internal, exclude from client-facing high/critical
  report unless operator explicitly accepts risk
- `blocked_oracle` -> needs analyst review, not accepted

## First Implementation Cut

Smallest useful diff:

Current cut implements safe raw HTTP replay through the existing `http_request`
tool path. Curl/python command classification is still deferred.

1. Add `ReplayGateResult` helper type or plain dict helper near finding/finish
   gate code.
2. Add a pure parser for one raw HTTP request block.
3. Add a pure oracle function for status/body marker comparison.
4. Add `ScanAgentLoop` finish-gate check for critical/high accepted findings.
5. Add tests:
   - high finding with passed replay can finish
   - high finding without replay gate rejects finish
   - unsafe POST without approval returns `blocked_policy`
   - no deterministic marker returns `blocked_oracle`

Stop there. Policy pruning comes after this gate exists.
