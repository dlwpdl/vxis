# `src/vxis/display/` — Rich TUI Live Display

Rich-based live rendering primitives — CRT-style scanline output, Phase panel, Brain Thinking panel, Attack Chains panel, Findings counter.

Subscribed to pipeline events via `event_callback` (emitted by `ScanPipelineV2._emit`). Phase A emits reduced event granularity (only `phase_start`/`phase_end` for "scan_loop") so the TUI shows less detail during scan — Phase B will rewrite this to show per-iteration Brain decisions.

Key class: `CRTLiveDisplay` (from `display.live`).
