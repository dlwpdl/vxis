# `docs/superpowers/` — Superpowers Skill Output

> Home for artifacts produced by the `superpowers` skill system (plans, benchmarks, specs). Every `superpowers:*` skill that produces persistent output writes here.

## Subdirectories

- [`plans/`](plans/README.md) — Implementation plans (`superpowers:writing-plans`)
- [`benchmarks/`](benchmarks/README.md) — Benchmark captures + scan artifacts
- `specs/` — Design specs (rarely used — most design lives in plans)

## Convention

Every file in here is dated (`YYYY-MM-DD-<name>.md`) and has a clear author (me or the human user) plus the git SHA of the worktree at the time of writing. This makes it easy to correlate a plan with the branch that executed it.
