from __future__ import annotations

from typing import Any

from vxis.agent.agent_graph_runtime import (
    agent_graph_evidence_artifact_brief,
    agent_graph_has_valid_evidence_artifact,
    agent_graph_needs_evidence_artifact,
)
from vxis.agent.scan_loop_state import _TERMINAL_VECTOR_STATUSES
from vxis.agent.scan_loop_v3 import v3_dashboard_summary


def build_scan_dashboard(loop: Any) -> str:
    """Build a compact scan-progress dashboard injected every iteration.

    Brain sees this every iteration instead of scrolling through 200+
    messages. Focused on: what did you find, what haven't you tested,
    what should your next GOAL be.
    """
    s = loop.state
    local_strict = loop._llm_discipline_profile() == "local_strict"
    finding_limit = 3 if local_strict else 5
    candidate_limit = 6 if local_strict else 10
    branch_limit = 4 if local_strict else 8
    review_limit = 3 if local_strict else 5
    endpoint_limit = 4 if local_strict else 8
    note_limit = 2 if local_strict else 4

    # Collect state from messages
    tools_used: set[str] = set()
    endpoints_seen: set[str] = set()
    for m in s.messages:
        content = m.get("content", {})
        if isinstance(content, dict) and content.get("name"):
            tools_used.add(content["name"])
            args = content.get("args", {})
            if isinstance(args, dict):
                for k in ("url", "affected_component"):
                    if args.get(k):
                        endpoints_seen.add(str(args[k])[:80])

    try:
        from vxis.agent.tools.finding_tools import _get_findings

        reported = _get_findings()
    except Exception:
        reported = []

    # Build attack vector checklist
    tested_vectors: dict[str, str] = {}  # vector → status
    finding_types = {f.get("finding_type", "") for f in reported}

    vectors = [
        ("SQLi", "sql_injection", "shell_exec" in tools_used or "sql" in str(finding_types)),
        ("XSS", "xss", "browser_eval_js" in tools_used),
        ("Auth bypass", "auth_bypass", "browser_fill_form" in tools_used),
        ("IDOR", "idor", any("idor" in str(f.get("finding_type", "")).lower() for f in reported)),
        ("Sensitive files", "information_disclosure", "load_playbook" in tools_used),
        (
            "Dir bruteforce",
            "directory",
            any(
                m.get("role") == "tool" and "ffuf" in str(m.get("content", {}).get("args", ""))
                for m in s.messages
            ),
        ),
        (
            "CVE scan",
            "cve",
            any(
                m.get("role") == "tool" and "nuclei" in str(m.get("content", {}).get("args", ""))
                for m in s.messages
            ),
        ),
    ]
    for name, ftype, tested in vectors:
        found = ftype in finding_types
        if found:
            tested_vectors[name] = "✓ FOUND"
        elif tested:
            tested_vectors[name] = "tested, nothing yet"
        else:
            tested_vectors[name] = "⬚ NOT TESTED"

    # Determine current goal based on what's missing
    untested = [name for name, status in tested_vectors.items() if "NOT TESTED" in status]
    agent_graph_agents = loop._agent_graph_agents_from_messages()
    director_worker_brief = loop._agent_graph_director_brief(
        agent_graph_agents,
        local_strict=local_strict,
    )

    # Check existing chains
    try:
        from vxis.agent.tools.finding_tools import _get_chains

        existing_chains = _get_chains()
    except Exception:
        existing_chains = []

    header = "SCAN DASHBOARD" if not local_strict else "LOCAL SCAN DASHBOARD"
    lines: list[str] = [f"═══ {header} (iter {s.iteration}) ═══"]

    # Findings
    if reported:
        lines.append(f"Findings ({len(reported)}):")
        for f in reported[-finding_limit:]:
            lines.append(
                f"  [{f.get('severity', '?').upper()}] {f['id']}: {f.get('title', '?')[:60]}"
            )
    else:
        lines.append("Findings: 0")

    # Attack vector checklist
    lines.append("Attack vectors:")
    for name, status in tested_vectors.items():
        lines.append(f"  {status} {name}")

    auth_identities = [i for i in getattr(s, "auth_identities", []) if isinstance(i, dict)]
    if auth_identities:
        principals = ", ".join(
            str(i.get("name") or i.get("email") or "authenticated")[:40]
            + (f"/{str(i.get('role'))[:24]}" if i.get("role") else "")
            for i in auth_identities[:4]
        )
        lines.append(f"Auth state: authenticated ({principals})")
    else:
        lines.append("Auth state: anonymous/no verified session")

    # Durable vector candidate queue. This is the stateful contract: Brain
    # must drive each plausible vector to found/clean/blocked/dead instead
    # of merely picking from a tool list and forgetting failed hypotheses.
    candidates = sorted(
        s.vector_candidates.values(),
        key=lambda c: (-c.priority, c.status in _TERMINAL_VECTOR_STATUSES, c.attempts, c.id),
    )
    if candidates:
        lines.append("Vector candidates (durable state):")
        for c in candidates[:candidate_limit]:
            marker = {
                "open": "OPEN",
                "retryable": "RETRY",
                "attempted": "TRY",
                "failed": "FAIL",
                "found": "FOUND",
                "clean": "CLEAN",
                "blocked": "BLOCK",
                "dead": "DEAD",
            }.get(c.status, c.status.upper())
            lines.append(
                f"  {marker} p{c.priority} {c.id} ({c.vector_id}) attempts={c.attempts}: {c.title}"
            )

    active_branches = s.active_branches()
    if active_branches:
        lines.append("Branch dossiers (root-owned attack paths):")
        for b in active_branches[:branch_limit]:
            lines.append(
                f"  {b.status.upper()} p{b.priority} {b.id} role={b.role} phase={b.phase} owner={b.owner} "
                f"attempts={b.attempts} -> {b.title}"
            )
            if b.objective:
                lines.append(f"     objective: {b.objective[: 80 if local_strict else 110]}")
            if b.crown_jewel:
                lines.append(f"     crown: {b.crown_jewel[: 80 if local_strict else 110]}")
            if b.next_step:
                lines.append(f"     next: {b.next_step[: 80 if local_strict else 110]}")
            if b.last_report:
                lines.append(f"     last: {b.last_report[: 80 if local_strict else 110]}")
            if b.blocker:
                lines.append(f"     blocker: {b.blocker[: 70 if local_strict else 90]}")

    if agent_graph_agents:
        if director_worker_brief:
            lines.append("Director-worker exchange:")
            lines.extend(director_worker_brief)
        lines.append("Agent graph:")
        planner_metrics = getattr(loop, "_agent_graph_worker_planner_metrics", {})
        if isinstance(planner_metrics, dict):
            attempts = int(planner_metrics.get("attempts") or 0)
            if attempts:
                successes = int(planner_metrics.get("successes") or 0)
                repairs = int(planner_metrics.get("repairs") or 0)
                repair_successes = int(planner_metrics.get("repair_successes") or 0)
                fallbacks = int(planner_metrics.get("fallbacks") or 0)
                unavailable = int(planner_metrics.get("unavailable") or 0)
                lines.append(
                    "  Worker planner quality: "
                    f"success={successes}/{attempts} repair={repair_successes}/{repairs} "
                    f"fallback={fallbacks} unavailable={unavailable}"
                )
        for agent in agent_graph_agents[:branch_limit]:
            status = str(agent.get("status") or "unknown").upper()
            role = str(agent.get("role") or "worker")
            agent_id = str(agent.get("id") or "?")
            task = str(agent.get("task") or "")[: 80 if local_strict else 110]
            message_count = int(agent.get("message_count") or 0)
            execution_count = int(agent.get("execution_count") or 0)
            lines.append(
                f"  {status} {agent_id} role={role} msgs={message_count} "
                f"runs={execution_count}: {task}"
            )
            envelope = (
                agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
            )
            expected_artifact = str(envelope.get("expected_artifact") or "").strip()
            stop_condition = str(envelope.get("stop_condition") or "").strip()
            if expected_artifact:
                lines.append(f"     contract: {expected_artifact[: 80 if local_strict else 120]}")
            if stop_condition and not local_strict:
                lines.append(f"     stop: {stop_condition[: 80 if local_strict else 120]}")
            executions = agent.get("executions")
            has_successful_execution = False
            needs_artifact = agent_graph_needs_evidence_artifact(agent)
            has_valid_artifact = agent_graph_has_valid_evidence_artifact(agent)
            if isinstance(executions, list) and executions:
                has_successful_execution = any(
                    isinstance(execution, dict) and execution.get("ok") for execution in executions
                )
                latest = executions[-1] if isinstance(executions[-1], dict) else {}
                tool_name = str(latest.get("tool") or "child")
                verdict = "ok" if latest.get("ok") else "fail"
                summary = str(latest.get("summary") or "")[: 80 if local_strict else 120]
                if summary:
                    lines.append(f"     last_run: {tool_name} {verdict}: {summary}")
                latest_data = latest.get("data") if isinstance(latest.get("data"), dict) else {}
                planner = (
                    latest_data.get("planner")
                    if isinstance(latest_data.get("planner"), dict)
                    else {}
                )
                if planner:
                    source = str(planner.get("source") or "unknown")
                    reason = str(planner.get("fallback_reason") or "").strip()
                    health = str(planner.get("health") or "").strip()
                    intent = str(planner.get("evidence_intent") or "").strip()
                    tokens = int(planner.get("prompt_tokens") or 0)
                    repair_attempted = bool(planner.get("repair_attempted"))
                    repair_succeeded = bool(planner.get("repair_succeeded"))
                    initial_reason = str(planner.get("initial_failure_reason") or "").strip()
                    detail = f"     planner: {source}"
                    if reason:
                        detail += f" reason={reason}"
                    if repair_attempted:
                        detail += f" repair={'ok' if repair_succeeded else 'fail'}"
                    if initial_reason:
                        detail += f" initial={initial_reason}"
                    if health:
                        detail += f" health={health}"
                    if tokens:
                        detail += f" tokens={tokens}"
                    if intent and not local_strict:
                        detail += f" intent={intent[:70]}"
                    lines.append(detail[: 100 if local_strict else 170])
                sdk_runtime = (
                    latest_data.get("sdk_runtime")
                    if isinstance(latest_data.get("sdk_runtime"), dict)
                    else {}
                )
                if sdk_runtime:
                    record = (
                        sdk_runtime.get("agent")
                        if isinstance(sdk_runtime.get("agent"), dict)
                        else {}
                    )
                    runtime_status = str(record.get("status") or "").strip()
                    events = [
                        str(event.get("event_type") or "")
                        for event in list(sdk_runtime.get("events") or [])[-3:]
                        if isinstance(event, dict) and event.get("event_type")
                    ]
                    session_items = list(sdk_runtime.get("session_items") or [])
                    session_tail = ""
                    if session_items and isinstance(session_items[-1], dict):
                        session_tail = str(session_items[-1].get("content") or "").strip()
                    detail = f"     sdk_session: {runtime_status or 'active'}"
                    if events:
                        detail += f" events={','.join(events)}"
                    if session_tail and not local_strict:
                        detail += f" tail={session_tail[:70]}"
                    lines.append(detail[: 100 if local_strict else 170])
            if status in {"RUNNING", "WAITING"}:
                if needs_artifact:
                    lines.append(f'     next: agent_graph(action="run", agent_id="{agent_id}")')
                elif has_successful_execution or has_valid_artifact:
                    lines.append(
                        f'     next: agent_graph(action="finish", agent_id="{agent_id}", result="...")'
                    )
                else:
                    lines.append(f'     next: agent_graph(action="run", agent_id="{agent_id}")')
            result_package = (
                agent.get("result_package") if isinstance(agent.get("result_package"), dict) else {}
            )
            verdict_guess = str(result_package.get("verdict_guess") or "").strip()
            if verdict_guess:
                lines.append(f"     worker_verdict: {verdict_guess[:30]}")
            proof_brief = agent_graph_evidence_artifact_brief(
                agent, width=80 if local_strict else 120
            )
            if proof_brief:
                lines.append(f"     {proof_brief}")
            escalation = (
                agent.get("escalation") if isinstance(agent.get("escalation"), dict) else {}
            )
            escalation_reason = str(escalation.get("reason") or "").strip()
            if escalation_reason:
                lines.append(f"     escalate: {escalation_reason[: 80 if local_strict else 120]}")
            result = str(agent.get("result") or "").strip()
            if result:
                lines.append(f"     result: {result[: 80 if local_strict else 120]}")
                chain_next = loop._agent_graph_crown_chain_next(agent)
                if chain_next:
                    lines.append(f"     crown_next: {chain_next[: 90 if local_strict else 130]}")

    service_pivots = [
        branch
        for branch in s.active_branches()
        if getattr(branch, "vector_id", "") == "NET-SERVICE-PIVOT"
    ][: 3 if local_strict else 5]
    if service_pivots:
        lines.append("Service pivots:")
        for branch in service_pivots:
            lines.append(
                f"  {branch.status.upper()} {branch.id} p{branch.priority}: "
                f"{branch.title[: 70 if local_strict else 100]}"
            )
            if branch.evidence:
                lines.append(f"     evidence: {branch.evidence[: 80 if local_strict else 120]}")
            if branch.next_step and not local_strict:
                lines.append(f"     next: {branch.next_step[:120]}")
            if branch.child_ids:
                lines.append(f"     workers: {', '.join(branch.child_ids[:3])}")

    # Endpoints
    if endpoints_seen:
        lines.append(f"Known endpoints: {', '.join(sorted(endpoints_seen)[:endpoint_limit])}")

    if s.shared_notes:
        lines.append("Shared notes:")
        for note in s.shared_notes[-note_limit:]:
            lines.append(f"  - {note[: 80 if local_strict else 120]}")
        memory_notes = [note for note in s.shared_notes if note.startswith("memory")]
        if memory_notes:
            lines.append("Memory directives:")
            strategy = next(
                (note for note in memory_notes if note.startswith("memory strategy:")), ""
            )
            if strategy:
                lines.append(f"  {strategy[: 90 if local_strict else 160]}")
            refuted = [note for note in memory_notes if note.startswith("memory refuted:")][
                : 2 if local_strict else 3
            ]
            for note in refuted:
                lines.append(f"  {note[: 90 if local_strict else 160]}")
            branch_reopens = [note for note in memory_notes if note.startswith("memory branch:")][
                : 2 if local_strict else 3
            ]
            for note in branch_reopens:
                lines.append(f"  {note[: 90 if local_strict else 160]}")

    review_items = s.review_queue_as_dicts()
    if review_items:
        lines.append("AI review queue:")
        for item in review_items[:review_limit]:
            lines.append(
                f"  {item['status'].upper()} {item['stage']} {item['id']}: "
                f"{item['title'][: 48 if local_strict else 70]}"
            )
            if item.get("reason"):
                lines.append(f"     reason: {str(item['reason'])[: 72 if local_strict else 120]}")
            if item.get("action_hint"):
                lines.append(
                    f"     next: {str(item['action_hint'])[: 72 if local_strict else 120]}"
                )

    # ── Chain Intelligence section (always on when 2+ findings) ──
    # Brain-First: Brain decides HOW to chain, we just keep the pressure
    # on every iteration. No "fire once and forget" — chain awareness must
    # persist in Brain's working context for the entire scan.
    _desired_chains = max(3, len(reported) // 3)
    if len(reported) >= 2 and not local_strict:
        lines.append("")
        lines.append("═══ CHAIN INTELLIGENCE ═══")
        if existing_chains:
            lines.append(f"Chains recorded: {len(existing_chains)} / {_desired_chains}+ target")
            for c in existing_chains:
                lines.append(
                    f"  {c.get('id', '?')}: {' → '.join(c.get('finding_ids', []))} → {c.get('crown_jewel', '?')[:40]}"
                )
            if len(existing_chains) < _desired_chains:
                lines.append(
                    f"  ⚠ Build MORE chains — {_desired_chains - len(existing_chains)} more to reach target."
                )
        else:
            lines.append(
                f"Chains recorded: 0 / {_desired_chains}+ target  ⚠ BUILD ATTACK CHAINS NOW"
            )

        # Broad finding-type grouping — every type lands somewhere
        # so Brain always sees chain candidates regardless of scan target.
        _cat = {
            "entry": (  # unauthenticated entry vectors
                "sql_injection",
                "xss",
                "xss_reflected",
                "xss_stored",
                "xss_dom",
                "ssrf",
                "xxe",
                "command_injection",
                "ssti",
                "csrf",
                "open_redirect",
                "path_traversal",
            ),
            "auth": (  # authentication / session weaknesses
                "auth_bypass",
                "weak_auth",
                "jwt_none",
                "jwt_confusion",
                "session_fixation",
                "default_credentials",
                "password_reset_poisoning",
            ),
            "access": (  # authorization / access control
                "broken_access_control",
                "idor",
                "verb_tampering",
                "mass_assignment",
                "privilege_escalation",
                "no_rate_limit",
            ),
            "infra": (  # infra / misconfig / crypto
                "misconfiguration",
                "weak_crypto",
                "information_disclosure",
                "sensitive_data_exposure",
                "error_oracle",
            ),
            "logic": (  # business logic
                "business_logic",
                "race_condition",
                "price_manipulation",
                "negative_quantity",
                "state_bypass",
            ),
        }
        _by_cat: dict[str, list[dict[str, Any]]] = {k: [] for k in _cat}
        _uncat: list[dict[str, Any]] = []
        for f in reported:
            ft = str(f.get("finding_type", "")).lower()
            placed = False
            for cat, types in _cat.items():
                if ft in types or any(ft.startswith(t) for t in types):
                    _by_cat[cat].append(f)
                    placed = True
                    break
            if not placed:
                _uncat.append(f)

        lines.append("Findings by category:")
        for cat, items in _by_cat.items():
            if items:
                ids = ", ".join(f["id"] for f in items[:4])
                lines.append(
                    f"  {cat}: {ids}" + (f" (+{len(items) - 4})" if len(items) > 4 else "")
                )
        if _uncat:
            lines.append(f"  other: {', '.join(f['id'] for f in _uncat[:4])}")

        # Suggest concrete chain candidates — any cross-category pair
        # with at least one finding each. Brain decides whether the chain
        # is real; we just make the candidates visible.
        _chain_candidates: list[tuple[str, list[str], str]] = []
        if _by_cat["entry"] and _by_cat["access"]:
            _chain_candidates.append(
                (
                    "entry → access",
                    [_by_cat["entry"][0]["id"], _by_cat["access"][0]["id"]],
                    "bypass login then abuse weak authZ for data access",
                )
            )
        if _by_cat["auth"] and _by_cat["access"]:
            _chain_candidates.append(
                (
                    "auth → access",
                    [_by_cat["auth"][0]["id"], _by_cat["access"][0]["id"]],
                    "compromised session then IDOR/rate-limit abuse",
                )
            )
        if _by_cat["infra"] and _by_cat["auth"]:
            _chain_candidates.append(
                (
                    "infra → auth",
                    [_by_cat["infra"][0]["id"], _by_cat["auth"][0]["id"]],
                    "leaked config/keys forge tokens or reset password",
                )
            )
        if _by_cat["infra"] and _by_cat["access"]:
            _chain_candidates.append(
                (
                    "infra → access",
                    [_by_cat["infra"][0]["id"], _by_cat["access"][0]["id"]],
                    "exposed config reveals admin endpoints; hit them without auth",
                )
            )
        if _by_cat["entry"] and _by_cat["logic"]:
            _chain_candidates.append(
                (
                    "entry → logic",
                    [_by_cat["entry"][0]["id"], _by_cat["logic"][0]["id"]],
                    "injection-assisted logic abuse (e.g. race + price manipulation)",
                )
            )
        # CSRF + any auth/access = account takeover vector
        _csrf = [f for f in reported if "csrf" in str(f.get("finding_type", "")).lower()]
        _rate = [f for f in reported if "rate" in str(f.get("finding_type", "")).lower()]
        if _csrf and (_by_cat["auth"] or _by_cat["access"]):
            target_f = (_by_cat["auth"] or _by_cat["access"])[0]
            _chain_candidates.append(
                (
                    "csrf → account takeover",
                    [_csrf[0]["id"], target_f["id"]],
                    "craft CSRF payload hitting authenticated state-change endpoint",
                )
            )
        if _rate and _by_cat["auth"]:
            _chain_candidates.append(
                (
                    "no-rate-limit → credential brute force",
                    [_rate[0]["id"], _by_cat["auth"][0]["id"]],
                    "absence of throttling enables credential stuffing",
                )
            )
        # Fallback: any two findings are candidates if nothing else emerged
        if not _chain_candidates and len(reported) >= 2:
            _chain_candidates.append(
                (
                    "any → any",
                    [reported[0]["id"], reported[-1]["id"]],
                    "explore whether these two findings compound",
                )
            )

        if _chain_candidates:
            lines.append("Potential chains (Brain decides which are real):")
            for label, ids, why in _chain_candidates[:5]:
                lines.append(f"  {label}: {' → '.join(ids)} — {why}")

        lines.append("")
        lines.append("CHAIN PROTOCOL:")
        lines.append("  1. Pick 2+ findings that plausibly compose.")
        lines.append("  2. Actually TRY the chain (use tools to prove exploitability).")
        lines.append("  3. Call link_chain with VerifiedChainArtifact evidence.")
        lines.append("  4. Repeat for every combination you can imagine.")
        lines.append("CROWN JEWELS: admin takeover, DB dump, RCE, key theft, full data exfil.")

    # Current goal — chain pressure never disappears when chains are 0
    _chain_pressure = len(reported) >= 2 and not existing_chains
    open_candidates = [c for c in s.open_vector_candidates() if c.attempts == 0]
    retry_candidates = [c for c in s.open_vector_candidates() if c.attempts > 0]
    if active_branches:
        b = active_branches[0]
        lines.append(
            f"\n>> PRIMARY GOAL: drive branch {b.id} toward {b.crown_jewel or 'real impact'}."
        )
        if b.crown_jewel:
            lines.append(
                "   Crown distance: prove a control/payload delta that reaches this crown, "
                "or mark the path exhausted."
            )
        if b.objective:
            lines.append(f"   Objective: {b.objective}")
        if b.next_step:
            lines.append(f"   Next step: {b.next_step}")
        if b.last_report:
            lines.append(f"   Latest report: {b.last_report[:160]}")
        if b.blocker:
            lines.append(f"   Current blocker: {b.blocker[:160]}")
        if b.owner == "agent_graph":
            forced = loop._forced_branch_action(b)
            if forced is not None and forced[0] == "agent_graph":
                instruction = str(forced[1].get("instruction") or "").strip()
                lines.append(
                    f'   Suggested agent_graph action: agent_graph(action="run", '
                    f'agent_id="{forced[1].get("agent_id", "")}")'
                )
                if instruction:
                    lines.append(f"   Suggested instruction: {instruction[:140]}")
            elif b.blocker:
                lines.append(
                    '   Resolve blocker by calling agent_graph(action="finish", '
                    'agent_id="...", status="blocked", result="...") or finish with evidence.'
                )
        lines.append(
            "   Stay on this branch until you prove it, exhaust it, or spawn a stronger child branch."
        )
        if b.owner == "memory":
            lines.append(
                "   This is a carry-over memory branch: revalidate it quickly, then push past previously known depth."
            )
    elif open_candidates and not _chain_pressure:
        c = open_candidates[0]
        lines.append(f"\n>> YOUR GOAL: Exhaust vector candidate {c.id}.")
        lines.append(f"   Hypothesis: {c.title}. Evidence: {c.evidence or 'seeded'}")
        lines.append(
            "   Pick any tool that proves/refutes it; do not finish until it is found, clean, blocked, or dead."
        )
    elif retry_candidates and not _chain_pressure:
        c = retry_candidates[0]
        lines.append(f"\n>> YOUR GOAL: Resolve retryable vector candidate {c.id}.")
        lines.append(f"   Last try: {c.last_tool} -> {c.last_summary[:160]}")
        lines.append(
            "   Change route/tool/payload, or mark it blocked/dead through clear evidence."
        )
    elif untested and not _chain_pressure:
        goal = untested[0]
        lines.append(f"\n>> YOUR GOAL: Test {goal}.")
        if goal == "SQLi":
            lines.append(
                "   Try: shell_exec sqlmap on an endpoint, or browser_fill_form with ' OR 1=1--"
            )
        elif goal == "XSS":
            lines.append(
                "   Try: browser_navigate to /search?q=<script>alert(1)</script>, then browser_eval_js"
            )
        elif goal == "Auth bypass":
            lines.append(
                "   Try: browser_navigate to login page, browser_fill_form with test creds"
            )
        elif goal == "IDOR":
            lines.append("   Try: access /api/Users/2 or /api/Orders/2 with and without auth token")
        elif goal == "Dir bruteforce":
            lines.append("   Try: shell_exec ffuf with common.txt wordlist")
        elif goal == "CVE scan":
            lines.append("   Try: shell_exec nuclei with http/cves templates")
    elif _chain_pressure:
        lines.append("\n>> PRIMARY GOAL: link_chain NOW — you have findings but 0 chains.")
        lines.append(
            "   Include evidence_artifact: source_output, pivot_action, control/observed result, crown evidence."
        )
        lines.append("   DO NOT call finish_scan until you've tried every chain above.")
        if untested:
            lines.append(f"   Secondary: also test {untested[0]} when you run out of chain ideas.")

    elif reported:
        lines.append("\n>> Good progress. But DO NOT stop here.")
        lines.append("   The more findings you discover, the better the report.")
        lines.append("   Dig DEEPER into every endpoint. If there's even a hint of a")
        lines.append("   vulnerability, pursue it until you hit a dead end.")
        lines.append("   Use EVERYTHING you know — try edge cases, combine payloads,")
        lines.append("   fuzz parameters, test auth boundaries, escalate privileges.")
        if existing_chains and len(existing_chains) < _desired_chains:
            lines.append(f"   Build more chains — {_desired_chains} total is the floor.")
    else:
        lines.append("\n>> No findings yet. Be more aggressive.")

    v3_summary = v3_dashboard_summary(s)
    if v3_summary:
        lines.append(v3_summary)

    lines.append("═══ Use ALL your knowledge. Every finding matters. Keep digging. ═══")
    return "\n".join(lines)
