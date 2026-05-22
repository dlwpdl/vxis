# `scripts/` — Operational Scripts

Standalone scripts for development ops — not part of the `vxis` library. Examples: benchmark runners, migration helpers, one-off data fixes, environment bootstrappers.

None of these are used by the Phase A migration path. Review contents before running anything.

## Context audit

`python scripts/context_audit.py` reports files that are too large for LLM-friendly review and prints role-specific prompt budgets. Add `--fail-on-warning` when you want to use the current thresholds as a CI/refactor gate.
