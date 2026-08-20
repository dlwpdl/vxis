# VXIS Codex Security Hardening — Specification

## Objective

Adopt three applicable Codex Security patterns without adding its runtime or
dependencies: least-privilege sandbox startup, coverage-aware scan comparison,
and repository-specific security guidance.

## Tech Stack

Python 3.12, pytest, SQLAlchemy, Typer, and the existing Docker CLI runtime.
No new dependency or database migration is permitted.

## Commands

```bash
uv run pytest -q tests/agent/tools/test_shell_tools.py
uv run pytest -q tests/unit/test_scan_diff.py tests/unit/test_cli.py
uv run ruff check src/vxis/agent/tools/shell_tools.py src/vxis/core/scan_diff.py src/vxis/cli/main.py tests/agent/tools/test_shell_tools.py tests/unit/test_scan_diff.py
```

## Project Structure

- `src/vxis/agent/tools/shell_tools.py`: active per-scan Docker runtime.
- `src/vxis/core/scan_diff.py`: finding comparison contract.
- `src/vxis/cli/main.py`: human-readable diff projection.
- `tests/`: behavioral regression checks.
- `SECURITY.md`, `docs/THREAT_MODEL.md`: authoritative security guidance.

## Code Style

Keep the existing direct style and safe defaults. Extend the current result
model rather than introducing a new comparison layer:

```python
result = compare_finding_lists(before, after, missing_is_resolved=False)
assert result.unknown_findings == before
```

## Testing Strategy

Use pytest unit tests. Docker calls remain mocked. Scan comparison gets one pure
logic regression and DB-backed checks for incomplete and mismatched-profile
scans. Documentation is reviewed for consistency with the implemented runtime.

## Boundaries

- Always: preserve only the `NET_RAW` capability required by raw packet tools,
  fail closed on uncertain scan coverage, and keep all existing local edits intact.
- Ask first: database migrations, CI integration, or a custom seccomp profile.
- Never: vendor Codex Security code, add its Node SDK, weaken scope/egress gates,
  or classify a missing finding as resolved after an incomplete/different-profile
  scan.

## Success Criteria

1. New sandbox containers drop all capabilities except `NET_RAW` and enable
   `no-new-privileges`; `NET_ADMIN` is not granted on the host network.
2. Baseline-only findings are `unknown` when the newer scan is not completed or
   the target/profile differs; existing complete same-scope behavior remains.
3. CLI diff output displays the unknown category.
4. `SECURITY.md` and `docs/THREAT_MODEL.md` describe VXIS's actual boundaries,
   authorized-use requirements, sensitive artifacts, and reporting process.
5. Focused tests and Ruff pass.

## Open Questions

None for this slice. Detailed per-surface coverage receipts and a VXIS-specific
seccomp/AppArmor profile are deferred until their runtime requirements are known.
