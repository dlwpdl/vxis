# VXIS Incubator

Incomplete feature work lives here, not under `src/vxis`.

## Promotion Rule

A feature can move from `incubator/` into production code only when it has:

- a clear owner note describing the target runtime path,
- local tests or fixtures that prove the behavior,
- no placeholder public CLI/MCP/dashboard wiring,
- a deliberate integration point in `src/vxis`,
- regression coverage for the promoted public surface,
- no test that passes by only proving a placeholder imports or raises
  `NotImplementedError`.

## Current Candidates

- CODE/white-box Brain tools: code surface helpers exist in `src/vxis/interaction/code`
  as library/test assets, but no source-aware Brain tools are promoted into the
  live scan loop yet. Production scans therefore remain black-box.

Keep this directory small. Delete experiments when their decision changes.
