# Strix-style Scan TUI — Design (2026-06-19)

Reference: Strix's TUI (owner-provided screenshots). Goal: VXIS `vxis scan` opens a
TUI that, *the moment it starts*, makes it obvious what the agent is doing — a
flowing, color-coded narrative on the left and a nested agent tree on the right.

> Hard dependency: this is worthless while the Brain is dead. The left panel is
> empty with no events. Ship the **brain model-validation fix first** (preflight
> real-call validation + re-pick), then this layout. Owner chose this order.

## Layout (flip of the current tree-left / detail-right)

```
┌─ narrative (main, ~72%, focused green border) ──┬─ Agents (right, ~28%) ─┐
│ ✗ CDP error (Page.handleJavaScriptDialog) …     │ ▼ ● director           │
│ The dialog is gone; I'm waiting for the snapshot │   ├ ● Juice Shop Recon │
│ >_ getting logs... session #37793                │   └ ◌ XSS Validation   │
│ I'm probing the password-recovery question …     │      (per-agent TOPIC  │
│ >_ $ python3 - <<'PY' …  (syntax-tinted)         │       + live status)   │
│ admin@juice-sh.op {"question":{"id":2,…}}        ├────────────────────────┤
│ …scrolls live, newest at bottom…                 │ openai/gpt-5.4-mini     │
│                                                  │ 7.0M tokens · $0.92     │
├──────────────────────────────────────────────── │ v1.0.4                  │
│ ■■···· esc stop                       ctrl-q quit └────────────────────────┘
```

## Left — flowing live narrative (the headline feature)

What the owner called out explicitly:
- **뭘 하고 있는지 바로 보인다** — intent lines in the agent's own words
  ("I'm probing the password-recovery question lookup for user enumeration.").
- **어떤 시도를 했는지 보인다** — the concrete action: shell `>_ $ …`, the
  payload/code, and the **tool output** right under it.
- **색깔로 나뉜다** — color-coded by line kind, not one gray wall:
  - intent / reasoning  → plain bright text
  - tool action (`>_`, `$`)  → accent (cyan/green) prompt + tinted command
  - output / evidence  → dim/white body
  - errors (`✗ …`)  → red/dim
  - findings / hits  → highlighted (e.g. bold + severity color)
- Streams live, **immediately** (no waiting for a phase to finish), newest at the
  bottom, auto-scroll unless the user has scrolled up.
- Shows the narrative for the **currently selected agent** in the right tree.

Substrate that already exists: `vxis.agent.event_log.format_event` +
`vxis.agent.tui_renderers.render_detail` (the "Strix-style scan-log narrative").
Reuse and extend the renderer registry for per-kind color.

## Right — nested agent tree, topic-aware

- Nested by `parent_id`: root director → delegated sub-agents (the existing
  `build_agent_tree`).
- Each node shows **what topic it is attempting** — not just an id. Strix shows
  "Juice Shop Recon", "Juice Shop XSS Validation". Map VXIS agent
  `task`/`skill`/`role` → human topic (reuse `attack_category`), and prefer the
  agent's mission label when present.
- Live **status dot**, color-coded: ● running (cyan/green), ◌ waiting (yellow),
  ✓ done (green), ■ blocked (red).
- **Clickable**: selecting an agent switches the left narrative to that agent's
  stream. Selection/expansion must survive live updates (the incremental
  reconcile already shipped — keep it).

## Status

- Bottom-left: progress pulse + `esc stop`. Bottom-right (or right-bottom box):
  `provider/model`, total tokens, est. cost, version — VXIS `_status_text`
  already aggregates cost/model; relocate + add tokens/version.

## Out of scope (for now)

- Chat-to-agent input box (Strix has it; defer).
- Modal finding drill-in (defer; the narrative carries findings inline).

## Build order

1. Brain model-validation fix (separate, prerequisite) — DONE before this.
2. Recompose `ScanTUI`: swap panels (narrative main-left, agents right), keep the
   incremental reconcile, route narrative by selected agent.
3. Per-kind color in the narrative renderer.
4. Topic + colored status in agent-tree labels.
5. Status bar relocation (cost/model/tokens/version) + progress pulse.

## Verification

- Pilot tests (`run_test()`): narrative panel populates on events; selecting a
  right-tree agent swaps the narrative; node identity/selection survives bursts.
- Live: real scan against juice-shop with a working Brain — confirm the left
  fills immediately, colors read, right tree shows topics + live status, clicking
  an agent switches the stream.
