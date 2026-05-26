"""Pure agent-graph runtime helpers used by the scan loop and TUI."""

from __future__ import annotations

from typing import Any


def agent_graph_agents_from_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    agents: dict[str, dict[str, Any]] = {}
    for message in messages:
        content = message.get("content", {})
        if not isinstance(content, dict) or content.get("name") != "agent_graph":
            continue
        result = content.get("result", {})
        if not isinstance(result, dict):
            continue
        data = result.get("data", {})
        if not isinstance(data, dict):
            continue

        single = data.get("agent")
        if isinstance(single, dict) and single.get("id"):
            agents[str(single["id"])] = dict(single)

        for key in ("agents", "active_agents"):
            collection = data.get(key)
            if not isinstance(collection, list):
                continue
            for item in collection:
                if isinstance(item, dict) and item.get("id"):
                    agents[str(item["id"])] = dict(item)

    def _sort_key(item: dict[str, Any]) -> tuple[int, str, str]:
        status = str(item.get("status") or "")
        active_rank = 0 if status in {"running", "waiting"} else 1
        return (active_rank, str(item.get("created_at") or ""), str(item.get("id") or ""))

    return sorted(agents.values(), key=_sort_key)


def agent_graph_director_brief(
    agents: list[dict[str, Any]],
    *,
    local_strict: bool,
) -> list[str]:
    limit = 3 if local_strict else 5
    width = 95 if local_strict else 150
    lines: list[str] = []
    for agent in agents[:limit]:
        agent_id = str(agent.get("id") or "?")
        role = str(agent.get("role") or "worker")
        status = str(agent.get("status") or "unknown").lower()
        task = str(agent.get("task") or "").strip()
        skills = [
            str(skill).strip() for skill in list(agent.get("skills") or []) if str(skill).strip()
        ]
        latest_summary = ""
        executions = agent.get("executions")
        if isinstance(executions, list) and executions:
            latest = executions[-1] if isinstance(executions[-1], dict) else {}
            latest_tool = str(latest.get("tool") or "child")
            latest_ok = "ok" if latest.get("ok") else "fail"
            latest_summary = f"{latest_tool} {latest_ok}: {str(latest.get('summary') or '')}"
        envelope = (
            agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        )
        expected = str(envelope.get("expected_artifact") or "").strip()
        result_package = (
            agent.get("result_package") if isinstance(agent.get("result_package"), dict) else {}
        )
        verdict_guess = str(result_package.get("verdict_guess") or "").strip()
        escalation = agent.get("escalation") if isinstance(agent.get("escalation"), dict) else {}
        escalation_reason = str(escalation.get("reason") or "").strip()
        result = str(agent.get("result") or "").strip()
        next_step = agent_graph_director_next_step(agent)
        skill_hint = f" skills={','.join(skills[:3])}" if skills else ""
        evidence = result or latest_summary or "no worker evidence yet"
        lines.append(
            f"  {agent_id} {status} {role}{skill_hint}: "
            f"{task[:70]} | evidence={evidence[:70]} | director_next={next_step}"
        )
        if expected:
            lines.append(f"     contract: expect {expected[:width]}")
        if verdict_guess:
            lines.append(f"     worker_verdict: {verdict_guess[:width]}")
        if escalation_reason:
            lines.append(f"     escalate: {escalation_reason[:width]}")
        skill_context = str(agent.get("skill_context") or "").strip()
        if skill_context and not local_strict:
            first_action = next(
                (
                    line.strip()
                    for line in skill_context.splitlines()
                    if line.strip().startswith("action:")
                ),
                "",
            )
            if first_action:
                lines.append(f"     worker_card: {first_action[:width]}")
    return lines


def agent_graph_director_next_step(agent: dict[str, Any]) -> str:
    agent_id = str(agent.get("id") or "").strip()
    status = str(agent.get("status") or "").lower()
    executions = agent.get("executions")
    has_success = isinstance(executions, list) and any(
        isinstance(item, dict) and item.get("ok") for item in executions
    )
    if status in {"running", "waiting"}:
        if has_success:
            return f"finish or send sharper instruction to {agent_id}"
        return f"run {agent_id} or send a narrower instruction"
    chain_next = agent_graph_crown_chain_next(agent)
    if chain_next:
        return chain_next
    return "use result to update branch, report, or mark exhausted"


def agent_graph_crown_chain_next(agent: dict[str, Any]) -> str:
    result = str(agent.get("result") or "").strip()
    if not result or not agent_graph_result_needs_crown_chain(result):
        return ""
    role = str(agent.get("role") or "")
    if role == "post_exploit_worker":
        return "verify impact, link_chain, then report/finish only with crown-jewel evidence"
    return (
        "create post_exploit_worker from this result; test session reuse, "
        "privilege, data access, and chain closure"
    )


def agent_graph_crown_jewel_for_result(result: str) -> str:
    text = str(result or "").lower()
    if any(token in text for token in ("sql", "sqli", "database", "db dump", "table", "row")):
        return "DB dump or admin credentials"
    if any(token in text for token in ("admin", "privilege", "role")):
        return "admin takeover"
    if any(token in text for token in ("session", "token", "credential", "auth bypass")):
        return "authenticated data access"
    if any(token in text for token in ("idor", "object", "account", "tenant")):
        return "cross-account data exfiltration"
    if any(token in text for token in ("rce", "command execution", "shell")):
        return "remote command execution"
    return "crown-jewel impact"


def agent_graph_result_needs_crown_chain(result: str) -> bool:
    text = str(result or "").lower()
    positive = any(
        token in text
        for token in (
            "confirmed",
            "vulnerable",
            "exploited",
            "session",
            "token",
            "admin",
            "credential",
            "sqli",
            "sql injection",
            "idor",
            "auth bypass",
            "ssrf",
            "rce",
        )
    )
    clean = any(token in text for token in ("clean", "not vulnerable", "no issue", "blocked"))
    return positive and not clean


def agent_graph_branch_id(agent_id: str) -> str:
    clean = str(agent_id or "").strip()
    return f"agent:{clean}" if clean else ""


def agent_graph_branch_priority(agent: dict[str, Any]) -> int:
    role = str(agent.get("role") or "").strip().lower()
    base = {
        "recon_worker": 86,
        "exploit_worker": 90,
        "post_exploit_worker": 94,
        "review_worker": 84,
        "reporting_worker": 78,
        "fix_worker": 80,
    }.get(role, 82)
    blob = " ".join(str(agent.get(key) or "") for key in ("task", "result", "role")).lower()
    if any(token in blob for token in ("admin", "credential", "token", "db dump", "rce", "exfil")):
        base += 4
    if any(token in blob for token in ("sql", "xss", "idor", "ssrf", "auth", "privilege")):
        base += 2
    return min(96, base)


def agent_graph_terminal_branch_status(agent: dict[str, Any]) -> str:
    status = str(agent.get("status") or "").strip().lower()
    if status == "blocked":
        return "blocked"
    if status != "finished":
        return "active"
    result = str(agent.get("result") or "").strip().lower()
    if any(
        token in result
        for token in ("not vulnerable", "nothing found", "no issue", "no route found", "clean")
    ):
        return "exhausted"
    if any(
        token in result
        for token in (
            "confirmed",
            "vulnerable",
            "exploited",
            "admin access",
            "admin takeover",
            "session token",
            "db dump",
            "data exfil",
            "rce",
        )
    ):
        return "proven"
    return "exhausted"


__all__ = [
    "agent_graph_agents_from_messages",
    "agent_graph_branch_id",
    "agent_graph_branch_priority",
    "agent_graph_crown_chain_next",
    "agent_graph_crown_jewel_for_result",
    "agent_graph_director_brief",
    "agent_graph_director_next_step",
    "agent_graph_result_needs_crown_chain",
    "agent_graph_terminal_branch_status",
]
