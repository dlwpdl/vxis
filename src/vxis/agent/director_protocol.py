"""Compact director protocol memory injected into scan-loop prompts."""

from __future__ import annotations

from typing import Any


def render_director_protocol_memory(*, local_strict: bool, target_kind: Any = "web") -> str:
    kind = str(getattr(target_kind, "value", target_kind) or "web").lower()
    if local_strict:
        return (
            "Protocol: keep one active proof path. Use agent_graph only for bounded worker tasks. "
            "Worker must run tool/skill before positive finish. Positive result => post_exploit_worker. "
            "Finish only after verify/report/link_chain or clean blockers."
        )
    if kind == "desktop":
        surface = "desktop tools only; no web skills unless target has a real URL surface"
    else:
        surface = "browser/proxy requests are evidence; replay captured requests for auth, IDOR, injection"
    return (
        "Protocol: director owns strategy; workers own bounded proof. "
        "Send task -> run worker/tool -> read evidence -> finish/send sharper task. "
        "Inject only relevant skills. Positive worker result must spawn post_exploit_worker for session, "
        "privilege, data, and chain closure. Report only verified impact; link related findings. "
        f"{surface}."
    )


__all__ = ["render_director_protocol_memory"]
