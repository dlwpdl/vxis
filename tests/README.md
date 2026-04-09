# `tests/` — pytest Test Suite

> ~1400 tests across unit, agent, pipeline, and slow categories. Phase A added ~30 tests.

## Structure

| Directory | Scope |
|---|---|
| `tests/unit/` | Pure unit tests — schema, models, primitives, instrumentation |
| `tests/agent/` | AgentBrain + ScanAgentLoop + ToolRegistry tests |
| `tests/agent/tools/` | BrainTool implementation tests (control/hands/shell/python/finding) |
| `tests/pipeline/` | `ScanPipelineV2` shim tests (Phase A) |
| `tests/slow/` | Slow integration tests — skipped by default |

## Running

```bash
# Full suite (excluding slow)
PYTHONPATH=$PWD/src poetry run pytest tests/unit tests/agent tests/pipeline --ignore=tests/slow

# Just Phase A additions
PYTHONPATH=$PWD/src poetry run pytest tests/agent tests/pipeline -v

# Single file
PYTHONPATH=$PWD/src poetry run pytest tests/agent/tools/test_shell_tools.py -v
```

## 🚨 PYTHONPATH requirement in worktrees

Poetry's editable install is pinned to the MAIN repo's `src/` directory. If you run tests from inside a worktree without `PYTHONPATH=<worktree>/src`, you get the main repo's code, not the worktree's. This silently masks bugs and falsely passes tests.

Every pytest invocation inside `.worktrees/phase-a/` must prefix with:

```bash
export PYTHONPATH=/Users/eliot/Desktop/유/vxis/.worktrees/phase-a/src
```

See `WORKTREE_README.md` at the worktree root.

## Known pre-existing failures (13)

These failures exist on `main` and were inherited into the `phase-a/strix-parity` branch. They're unrelated to Phase A changes and should not block merges:

- CLI/typer argparse edge cases (~5 failures in `tests/cli`)
- Ghost verifier network edge cases (~1 failure in `tests/unit/test_ghost`)
- Gitleaks plugin env detection (~1 failure in `tests/unit/test_plugins_phase1`)
- Alembic env harness (~1 failure)
- Minor others

Phase A acceptance: the pre-existing failure count must equal 13 before and after each task commit. New failures are blocking.

## Forward-compat assertion convention

Registry integration tests use `assert len(names) >= N` (not `== N`) so adding a new tool in a future task doesn't retroactively break an earlier task's test. Pattern established in commit `3f3b908`.

## Writing a new test

1. Follow the test file naming: `test_<module>.py` in the matching `tests/` subfolder
2. Use `pytest.mark.asyncio` for async tools (they need `async run()`)
3. Use `_reset_for_tests()` helpers from tool modules in autouse fixtures for test isolation
4. Use mocks for Docker / subprocess / external services — never hit real Docker in unit tests
5. Verify RED→GREEN transition manually (run the test before implementing, see it fail with the expected error)
