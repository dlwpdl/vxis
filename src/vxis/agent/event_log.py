"""Strix-style narrative for the live scan event stream.

The scan loop and finding tools already emit typed events (``attack``,
``brain_thinking``, ``hit``, ``chain_start``/``chain_step``, ``control_plane``)
through a single callback. ``format_event`` turns the meaningful ones into a
one-line human narrative so the scan log file reads like "what attack ran, how,
and the result" — ``tail -f logs/scan_*.log`` becomes a live trace, and the same
formatter feeds the TUI drill-in. Telemetry/noise events return ``None`` (skip).

Pure: no I/O, no global state — the pipeline tees the returned line to ``logger``.
"""
from __future__ import annotations

from typing import Any

from vxis.agent.attack_taxonomy import attack_category


def format_event(event_type: str, data: dict[str, Any] | None) -> str | None:
    """Map one live scan event to a plain-text narrative log line, or None to
    skip. Identifiers render as their human pentest category; the leading word is
    a clean text tag (the log file has no colour), no decorative emoji.
    """
    d = data or {}

    if event_type == "brain_thinking":
        vectors = d.get("vectors") or []
        reasoning = ""
        if vectors and isinstance(vectors[0], dict):
            reasoning = str(vectors[0].get("reasoning") or "").strip()
        return f"plan   {reasoning}" if reasoning else None

    if event_type == "attack":
        category = attack_category(str(d.get("vector_id") or ""))
        where = f"  {d.get('method') or ''} {d.get('endpoint') or ''}".rstrip()
        return f"try    {category}{where}".rstrip()

    if event_type == "hit":
        category = attack_category(str(d.get("vector_id") or d.get("finding_id") or ""))
        sev = str(d.get("confidence") or "").strip()
        return f"FOUND  {category}" + (f" ({sev})" if sev else "")

    if event_type == "chain_start":
        category = attack_category(str(d.get("vector_id") or ""))
        return f"chain  {category} @ {d.get('endpoint', '')}".rstrip()

    if event_type == "chain_step":
        category = attack_category(str(d.get("vector_id") or ""))
        return f"chain  step {category} @ {d.get('endpoint', '')}".rstrip()

    return None


__all__ = ["format_event"]
