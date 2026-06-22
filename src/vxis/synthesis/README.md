# `src/vxis/synthesis/` — Focused Chain Synthesis Helpers

The live scan loop builds attack chains through the `link_chain` BrainTool in
`agent/tools/finding_tools.py`. This package only keeps focused helpers that are
still imported or tested:

- `cross_protocol.py` tags evidence by surface/layer and synthesizes known
  cross-surface chain patterns.
Old standalone chain-builder, PoC-generator, honeypot, red/blue defense, and
defense-simulator files were removed because they were not connected to runtime
entrypoints.
