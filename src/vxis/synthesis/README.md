# `src/vxis/synthesis/` — Cross-Protocol Attack Chain Synthesis

Attack chain builder that combines findings from different phases/protocols into multi-step compromise paths. Legacy P8 phase logic.

Phase A's Brain is expected to build chains itself via the `link_chain` BrainTool (`agent/tools/finding_tools.py`). This module is not consumed by the v2 shim — slated for review in Phase B cleanup.
