from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from vxis.config.schema import ScanProfile
from vxis.p1.audit import AuditLog
from vxis.p1.enforcer import EnforcementError, enforce
from vxis.p1.resolver import DnsResolver
from vxis.p1.store import EngagementStore, p1_home

_TARGET_TOOLS: dict[str, str] = {
    "http_request": "recon",
    "browser_render": "recon",
    "browser_navigate": "recon",
    "nmap_scan": "recon",
    "run_skill": "recon",
    "agent_graph": "recon",
    "shell_exec": "emulate",
    "python_exec": "emulate",
    "c2_listen": "c2",
    "c2_beacon": "c2",
    "c2_callback": "c2",
    "lateral_move": "lateral",
    "persist_agent": "persist",
}
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class RuntimeGateDecision:
    allowed: bool
    reason: str = ""
    audit_entry: dict[str, Any] | None = None


def enforce_tool_invocation(tool_name: str, args: dict[str, Any]) -> RuntimeGateDecision | None:
    """Apply P1 scope/audit only when a P1 engagement is active in the env."""
    engagement_id = os.environ.get("VXIS_P1_ENGAGEMENT_ID", "").strip()
    if not engagement_id:
        return None
    technique = _TARGET_TOOLS.get(tool_name)
    if technique is None:
        return None
    targets = _extract_targets(tool_name, args)
    if not targets:
        if tool_name in {"shell_exec", "python_exec"}:
            return RuntimeGateDecision(
                allowed=False,
                reason=f"{tool_name} in P1 mode requires p1_target or an explicit URL/IP in the payload",
            )
        return None
    store = EngagementStore()
    audit = AuditLog(p1_home() / "audit.jsonl")
    resolver = DnsResolver()
    try:
        engagement = store.load(engagement_id)
        entry: dict[str, Any] | None = None
        for target in targets:
            entry = enforce(
                engagement,
                technique=technique,
                target=target,
                resolver=resolver,
                audit=audit,
                action=tool_name,
                metadata={"tool_args_keys": sorted(args.keys())},
            )
    except (FileNotFoundError, EnforcementError) as exc:
        audit_entry = getattr(exc, "audit_entry", None)
        return RuntimeGateDecision(allowed=False, reason=str(exc), audit_entry=audit_entry)
    return RuntimeGateDecision(allowed=True, audit_entry=entry)


def enforce_plugin_invocation(
    plugin_name: str,
    target: str,
    *,
    profile: ScanProfile,
) -> RuntimeGateDecision | None:
    """Apply the P1 chokepoint to the plugin scan path when the profile demands it."""
    if not getattr(profile, "requires_engagement", False):
        return None
    engagement_id = os.environ.get("VXIS_P1_ENGAGEMENT_ID", "").strip()
    if not engagement_id:
        return RuntimeGateDecision(
            allowed=False,
            reason=f"profile '{profile.name}' requires VXIS_P1_ENGAGEMENT_ID",
        )
    store = EngagementStore()
    audit = AuditLog(p1_home() / "audit.jsonl")
    try:
        engagement = store.load(engagement_id)
        entry = enforce(
            engagement,
            technique="recon",
            target=target,
            resolver=DnsResolver(),
            audit=audit,
            action=f"plugin:{plugin_name}",
            metadata={"plugin": plugin_name, "profile": profile.name},
        )
    except (FileNotFoundError, EnforcementError) as exc:
        audit_entry = getattr(exc, "audit_entry", None)
        return RuntimeGateDecision(allowed=False, reason=str(exc), audit_entry=audit_entry)
    return RuntimeGateDecision(allowed=True, audit_entry=entry)


def _extract_targets(tool_name: str, args: dict[str, Any]) -> list[str]:
    explicit = args.get("p1_target")
    if explicit:
        return _coerce_targets(explicit)
    for key in ("url", "target_url", "base_url", "target"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return [_normalize_target(value.strip())]
    if tool_name in {"shell_exec", "python_exec"}:
        text = str(args.get("command") or args.get("code") or "")
        return _dedupe(_URL_RE.findall(text) + [_normalize_target(ip) for ip in _IP_RE.findall(text)])
    return []


def _coerce_targets(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        cleaned = value.rstrip("),.;")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            out.append(cleaned)
    return out


def _normalize_target(value: str) -> str:
    cleaned = value.rstrip("),.;")
    if cleaned.startswith(("http://", "https://")):
        return cleaned
    return f"http://{cleaned}"
