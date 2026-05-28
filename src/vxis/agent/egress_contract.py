from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


VALID_TARGET_EGRESS_MODES = {
    "offline",
    "ghost_transport",
    "browser_proxy_or_ua",
    "env_proxy",
    "direct_raw_socket",
    "capture_proxy_control",
    "delegated",
    "llm_api",
}
VALID_GHOST_COVERAGE = {
    "not_applicable",
    "covered",
    "partial",
    "not_covered",
    "delegated",
}
VALID_EGRESS_RISK = {"none", "low", "partial", "direct", "delegated"}


@dataclass(frozen=True)
class TargetEgressContract:
    mode: str
    target_facing: bool
    ghost_coverage: str
    risk: str
    note: str = ""

    def compact(self) -> dict[str, Any]:
        data = asdict(self)
        return {key: value for key, value in data.items() if value not in ("", None)}


TOOL_TARGET_EGRESS: dict[str, TargetEgressContract] = {
    "finish_scan": TargetEgressContract("offline", False, "not_applicable", "none"),
    "think": TargetEgressContract("offline", False, "not_applicable", "none"),
    "wait": TargetEgressContract("offline", False, "not_applicable", "none"),
    "report_finding": TargetEgressContract("offline", False, "not_applicable", "none"),
    "query_findings": TargetEgressContract("offline", False, "not_applicable", "none"),
    "link_chain": TargetEgressContract("offline", False, "not_applicable", "none"),
    "list_playbooks": TargetEgressContract("offline", False, "not_applicable", "none"),
    "load_playbook": TargetEgressContract("offline", False, "not_applicable", "none"),
    "query_scan_memory": TargetEgressContract("offline", False, "not_applicable", "none"),
    "verify_finding": TargetEgressContract(
        "llm_api",
        False,
        "not_applicable",
        "none",
        "May call an LLM provider API, but does not send target traffic.",
    ),
    "http_request": TargetEgressContract("ghost_transport", True, "covered", "low"),
    "fingerprint_target": TargetEgressContract("ghost_transport", True, "covered", "low"),
    "browser_render": TargetEgressContract("browser_proxy_or_ua", True, "covered", "low"),
    "browser_navigate": TargetEgressContract("browser_proxy_or_ua", True, "covered", "low"),
    "browser_analyze_dom": TargetEgressContract("browser_proxy_or_ua", True, "covered", "low"),
    "browser_click": TargetEgressContract("browser_proxy_or_ua", True, "covered", "low"),
    "browser_fill_form": TargetEgressContract("browser_proxy_or_ua", True, "covered", "low"),
    "browser_screenshot": TargetEgressContract("browser_proxy_or_ua", True, "covered", "low"),
    "browser_eval_js": TargetEgressContract("browser_proxy_or_ua", True, "covered", "low"),
    "browser_get_cookies": TargetEgressContract("browser_proxy_or_ua", True, "covered", "low"),
    "intercept_proxy": TargetEgressContract(
        "capture_proxy_control",
        False,
        "not_applicable",
        "none",
        "Controls/listens to capture proxy state; target traffic flows through other tools.",
    ),
    "shell_exec": TargetEgressContract(
        "env_proxy",
        True,
        "partial",
        "partial",
        "Injects HTTP_PROXY/HTTPS_PROXY/ALL_PROXY, but raw-socket tools may ignore env proxy.",
    ),
    "python_exec": TargetEgressContract(
        "env_proxy",
        True,
        "partial",
        "partial",
        "Injects proxy env for child process; Python code or raw sockets may bypass it.",
    ),
    "nmap_scan": TargetEgressContract(
        "direct_raw_socket",
        True,
        "not_covered",
        "direct",
        "nmap uses raw TCP/UDP socket scanning and is not anonymized by HTTP/SOCKS env.",
    ),
    "run_skill": TargetEgressContract(
        "delegated",
        True,
        "delegated",
        "delegated",
        "Skill code must keep using SessionManager or explicit tool wrappers.",
    ),
    "agent_graph": TargetEgressContract(
        "delegated",
        True,
        "delegated",
        "delegated",
        "Child agents inherit the selected worker tool coverage.",
    ),
}


def describe_tool_target_egress(tool_name: str) -> dict[str, Any]:
    contract = TOOL_TARGET_EGRESS.get(str(tool_name or ""))
    if contract is None:
        return {
            "mode": "missing",
            "target_facing": True,
            "ghost_coverage": "missing",
            "risk": "direct",
            "note": "No target egress contract declared for this tool.",
        }
    return contract.compact()


def validate_registry_target_egress(registry: Any) -> list[str]:
    errors: list[str] = []
    for tool_name in registry.list_tools():
        contract = TOOL_TARGET_EGRESS.get(tool_name)
        if contract is None:
            errors.append(f"{tool_name}: missing target egress contract")
            continue
        if contract.mode not in VALID_TARGET_EGRESS_MODES:
            errors.append(f"{tool_name}: invalid mode {contract.mode!r}")
        if contract.ghost_coverage not in VALID_GHOST_COVERAGE:
            errors.append(f"{tool_name}: invalid ghost_coverage {contract.ghost_coverage!r}")
        if contract.risk not in VALID_EGRESS_RISK:
            errors.append(f"{tool_name}: invalid risk {contract.risk!r}")
        if contract.target_facing and contract.mode == "offline":
            errors.append(f"{tool_name}: target-facing tool cannot be offline")
    return errors


def registry_target_egress_snapshot(registry: Any) -> dict[str, Any]:
    tools = []
    counts: dict[str, int] = {}
    warnings: list[str] = []
    for tool_name in registry.list_tools():
        contract = TOOL_TARGET_EGRESS.get(tool_name)
        if contract is None:
            tools.append(
                {
                    "name": tool_name,
                    **describe_tool_target_egress(tool_name),
                }
            )
            counts["missing"] = counts.get("missing", 0) + 1
            warnings.append(f"{tool_name}: missing target egress contract")
            continue
        counts[contract.risk] = counts.get(contract.risk, 0) + 1
        tools.append({"name": tool_name, **contract.compact()})
        if contract.risk in {"direct", "partial", "delegated"}:
            warnings.append(f"{tool_name}: {contract.risk} egress ({contract.mode})")
    return {
        "counts": counts,
        "tools": tools,
        "warnings": warnings[:8],
        "errors": validate_registry_target_egress(registry),
    }
