"""Optional VXIS v3 runtime wiring for ScanAgentLoop.

The v3 engine components are feature-flagged so they can land incrementally
without changing the Phase A-E loop contract. This module owns only the central
attachment points; component implementations live in their own packages.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vxis.agent.scan_loop_state import action_capability


def v3_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def v3_enabled() -> bool:
    return v3_flag("VXIS_V3")


def initialize_v3_runtime(loop: Any) -> None:
    """Attach optional v3 state to a ScanAgentLoop instance."""
    state = loop.state
    state.v3_enabled = v3_enabled()
    state.v3_components = []
    state.v3_errors = []
    state.pti = None
    state.pti_store = None
    state.hypothesis_dag = getattr(state, "hypothesis_dag", None)
    state.coverage_matrix = None
    state.block_history = []
    state.cost_router = None
    state.cost_report = None
    state.ask_queue = None
    state.trajectory_writer = None
    state.trajectories_written = 0
    state.v3_surfaces = []
    state.v3_current_decision_class = "strategy"
    state.v3_current_model = ""
    state.v3_last_critique = None
    state.v3_last_critique_iter = 0
    state.v3_last_finish_gate = None
    state.v3_decision_classes = []

    if not state.v3_enabled:
        return

    _attach_pti(loop)
    _attach_hypothesis_dag(loop)
    _attach_coverage_matrix(loop)
    _attach_cost_router(loop)
    _attach_ask_queue(loop)
    bind_v3_tools(loop)
    v3_sync_runtime_state(loop)


def v3_prepare_decision(loop: Any) -> str:
    """Refresh v3 state and return the decision class for this Brain turn."""
    state = loop.state
    if not getattr(state, "v3_enabled", False):
        return "strategy"

    v3_sync_runtime_state(loop)
    decision_class = _infer_next_decision_class(loop)
    state.v3_current_decision_class = decision_class
    state.v3_decision_classes.append(decision_class)

    state.v3_current_model = _model_ref_for_decision(loop, decision_class)
    return decision_class


def v3_sync_runtime_state(loop: Any) -> None:
    """Keep v3 DAG and coverage matrix synchronized with existing loop state."""
    state = loop.state
    if not getattr(state, "v3_enabled", False):
        return

    _seed_hypotheses_from_candidates(state)
    _seed_coverage_from_pti_and_candidates(state)


def v3_after_action(
    loop: Any,
    *,
    name: str,
    args: dict[str, Any] | Any,
    result: Any,
    candidate_ids: list[str] | tuple[str, ...] | None = None,
    branch_ids: list[str] | tuple[str, ...] | None = None,
) -> None:
    """Record v3 observations after a tool result."""
    state = loop.state
    if not getattr(state, "v3_enabled", False):
        return

    candidate_list = [str(item) for item in (candidate_ids or []) if str(item or "").strip()]
    branch_list = [str(item) for item in (branch_ids or []) if str(item or "").strip()]
    decision_class = _decision_class_for_action(state, name, args)
    state.v3_current_decision_class = decision_class

    block_signal = _classify_block(result)
    if getattr(block_signal, "blocked", False):
        _record_block_signal(state, block_signal, name=name, args=args)
        _add_block_hint(state, block_signal)

    surface = _surface_for_action(state, name, args)
    vector_class = _vector_class_for_action(name, args)
    status = _coverage_status_for_result(name, result, block_signal)
    _mark_coverage(state, surface, vector_class, status)

    _update_hypotheses_after_action(
        state,
        name=name,
        args=args,
        result=result,
        candidate_ids=candidate_list,
        vector_class=vector_class,
        surface_id=surface["surface_id"],
        blocked=bool(getattr(block_signal, "blocked", False)),
    )
    _update_pti_after_action(
        state,
        name=name,
        args=args,
        result=result,
        surface=surface,
        vector_class=vector_class,
        block_signal=block_signal,
    )
    _write_trajectory(
        loop,
        name=name,
        args=args,
        result=result,
        decision_class=decision_class,
        candidate_ids=candidate_list,
        branch_ids=branch_list,
    )
    v3_maybe_run_self_critique(loop)


def v3_maybe_finish_gate(loop: Any) -> dict[str, Any] | None:
    """Return a finish-scan rejection payload when v3 says work remains."""
    state = loop.state
    if not getattr(state, "v3_enabled", False):
        return None
    if not v3_flag("VXIS_V3_FINISH_GATE", default=True):
        return None

    v3_sync_runtime_state(loop)
    critique = v3_maybe_run_self_critique(loop, force=True)
    matrix = getattr(state, "coverage_matrix", None)
    dag = getattr(state, "hypothesis_dag", None)
    if matrix is None and dag is None:
        return None

    gate = None
    if matrix is not None:
        try:
            gate = matrix.finish_gate_report(
                surfaces=_state_surfaces(state),
                hypotheses=list(getattr(dag, "nodes", {}).values()) if dag is not None else [],
                required_coverage_percent=_v3_float_env("VXIS_V3_COVERAGE_REQUIRED", 70.0),
                hypothesis_prior_threshold=_v3_float_env(
                    "VXIS_V3_HYPOTHESIS_PRIOR_GATE",
                    0.65,
                ),
            )
            state.v3_last_finish_gate = gate
        except Exception as exc:  # noqa: BLE001
            state.v3_errors.append(f"finish gate unavailable: {type(exc).__name__}: {exc}")
            gate = None

    reasons: list[str] = []
    data: dict[str, Any] = {}
    if gate is not None and getattr(gate, "blocks_finish", False):
        reasons.extend(list(getattr(gate, "reasons", []) or []))
        data["coverage_gate"] = _safe_to_dict(gate)
    if critique is not None and not getattr(critique, "finish_allowed", True):
        reasons.append("self-critique gaps remain")
        data["self_critique"] = _safe_to_dict(critique)
    if not reasons:
        return None

    summary = (
        "finish_scan REJECTED by v3 cognitive gate - "
        + "; ".join(_dedupe_preserve_order(reasons))
    )
    return {
        "title": "v3_cognitive_gate",
        "reason": summary,
        "action_hint": _v3_action_hint(data),
        "summary": summary,
        "data": data,
    }


def v3_finalize_runtime(loop: Any) -> None:
    """Persist best-effort v3 state at scan end."""
    state = loop.state
    if not getattr(state, "v3_enabled", False):
        return

    store = getattr(state, "pti_store", None)
    dossier = getattr(state, "pti", None)
    if store is None or dossier is None:
        return
    try:
        from vxis.pti.models import HypothesisOutcome, utc_now

        scan_id = _scan_id_for_state(state)
        if scan_id not in dossier.scan_ids:
            dossier.scan_ids.append(scan_id)
        dossier.updated_at = utc_now()

        dag = getattr(state, "hypothesis_dag", None)
        if dag is not None:
            existing = {
                (entry.claim, entry.scan_id)
                for entry in getattr(dossier, "hypothesis_history", [])
            }
            for node in getattr(dag, "nodes", {}).values():
                status = str(getattr(node, "status", ""))
                if status not in {"confirmed", "refuted", "inconclusive"}:
                    continue
                key = (str(getattr(node, "claim", "")), scan_id)
                if key in existing:
                    continue
                dossier.hypothesis_history.append(
                    HypothesisOutcome(
                        claim=key[0],
                        prior_at_start=float(getattr(node, "prior", 0.0)),
                        final_status=status,
                        scan_id=scan_id,
                    )
                )
        store.persist(dossier)
    except Exception as exc:  # noqa: BLE001
        state.v3_errors.append(f"pti persist unavailable: {type(exc).__name__}: {exc}")


def bind_v3_tools(loop: Any) -> None:
    """Point optional v3 BrainTools at this loop's state object."""
    registry = getattr(loop, "registry", None)
    tools = getattr(registry, "_tools", {})
    if not isinstance(tools, dict):
        return
    for tool in tools.values():
        if hasattr(tool, "_state"):
            try:
                setattr(tool, "_state", loop.state)
                if hasattr(tool, "_dag"):
                    setattr(tool, "_dag", None)
            except Exception:
                continue
        if hasattr(tool, "queue") and getattr(loop.state, "ask_queue", None) is not None:
            try:
                setattr(tool, "queue", loop.state.ask_queue)
            except Exception:
                continue
        binder = getattr(tool, "bind_state", None)
        if callable(binder):
            try:
                binder(loop.state)
            except Exception:
                continue


def v3_dashboard_summary(state: Any, *, token_budget: int = 1200) -> str:
    """Return a compact dashboard block for enabled v3 components."""
    if not getattr(state, "v3_enabled", False):
        return ""

    lines = ["", "═══ V3 COGNITIVE STATE ═══"]

    if getattr(state, "pti", None) is not None:
        summary = _safe_summary(state.pti, token_budget=max(200, token_budget // 4))
        lines.append("PTI:")
        lines.extend(f"  {line}" for line in summary.splitlines()[:6])
    else:
        lines.append("PTI: not loaded")

    if getattr(state, "hypothesis_dag", None) is not None:
        summary = _safe_summary(
            state.hypothesis_dag,
            token_budget=max(200, token_budget // 4),
        )
        lines.append("Hypotheses:")
        lines.extend(f"  {line}" for line in summary.splitlines()[:6])

    if getattr(state, "coverage_matrix", None) is not None:
        summary = _safe_summary(
            state.coverage_matrix,
            token_budget=max(200, token_budget // 4),
        )
        lines.append("Coverage:")
        lines.extend(f"  {line}" for line in summary.splitlines()[:6])

    if getattr(state, "ask_queue", None) is not None:
        pending = _safe_pending_count(state.ask_queue, getattr(state, "scan_id", ""))
        lines.append(f"Operator asks: pending={pending}")

    if getattr(state, "cost_report", None) is not None:
        lines.append(f"Cost routing: {state.cost_report}")

    errors = list(getattr(state, "v3_errors", []) or [])
    if errors:
        lines.append("V3 attach warnings:")
        for error in errors[:4]:
            lines.append(f"  - {error}")

    return "\n".join(lines)


def v3_result_payload(state: Any) -> dict[str, Any]:
    """Serialize v3 runtime state into ScanAgentLoop's final result."""
    if not getattr(state, "v3_enabled", False):
        return {"enabled": False}

    payload: dict[str, Any] = {
        "enabled": True,
        "components": list(getattr(state, "v3_components", []) or []),
        "errors": list(getattr(state, "v3_errors", []) or []),
        "trajectories_written": int(getattr(state, "trajectories_written", 0) or 0),
        "current_decision_class": str(getattr(state, "v3_current_decision_class", "")),
        "current_model": str(getattr(state, "v3_current_model", "")),
    }
    if getattr(state, "hypothesis_dag", None) is not None:
        payload["hypothesis_dag"] = _safe_to_dict(state.hypothesis_dag)
    if getattr(state, "coverage_matrix", None) is not None:
        payload["coverage_matrix"] = _safe_to_dict(state.coverage_matrix)
    if getattr(state, "ask_queue", None) is not None:
        payload["ask_queue"] = _safe_to_dict(state.ask_queue)
    if getattr(state, "cost_report", None) is not None:
        payload["cost_report"] = _safe_to_dict(state.cost_report)
    if getattr(state, "v3_last_critique", None) is not None:
        payload["last_critique"] = _safe_to_dict(state.v3_last_critique)
    if getattr(state, "v3_last_finish_gate", None) is not None:
        payload["last_finish_gate"] = _safe_to_dict(state.v3_last_finish_gate)
    return payload


def _attach_pti(loop: Any) -> None:
    if not v3_flag("VXIS_V3_PTI", default=True):
        return
    try:
        from vxis.pti.store import PTIStore

        data_dir = Path(os.environ.get("VXIS_PTI_DIR", "data/pti"))
        store = PTIStore(data_dir)
        loop.state.pti_store = store
        loop.state.pti = store.load_for_target(loop.state.target, create=True)
        loop.state.v3_components.append("pti")
    except Exception as exc:  # noqa: BLE001 - best-effort optional component
        loop.state.v3_errors.append(f"pti unavailable: {type(exc).__name__}: {exc}")


def _attach_hypothesis_dag(loop: Any) -> None:
    if not v3_flag("VXIS_V3_DAG", default=True):
        return
    try:
        from vxis.agent.hypothesis.dag import HypothesisDAG

        if getattr(loop.state, "hypothesis_dag", None) is None:
            loop.state.hypothesis_dag = HypothesisDAG()
        loop.state.v3_components.append("hypothesis_dag")
    except Exception as exc:  # noqa: BLE001
        loop.state.v3_errors.append(f"hypothesis_dag unavailable: {type(exc).__name__}: {exc}")


def _attach_coverage_matrix(loop: Any) -> None:
    if not v3_flag("VXIS_V3_COVERAGE", default=True):
        return
    try:
        from vxis.agent.coverage.matrix import CoverageMatrix

        loop.state.coverage_matrix = CoverageMatrix()
        loop.state.v3_components.append("coverage_matrix")
    except Exception as exc:  # noqa: BLE001
        loop.state.v3_errors.append(f"coverage_matrix unavailable: {type(exc).__name__}: {exc}")


def _attach_cost_router(loop: Any) -> None:
    if not v3_flag("VXIS_V3_ROUTING", default=True):
        return
    try:
        from vxis.agent.routing.cost_router import BrainCostRouter

        loop.state.cost_router = BrainCostRouter()
        loop.state.cost_report = loop.state.cost_router.report()
        loop.state.v3_components.append("cost_router")
    except Exception as exc:  # noqa: BLE001
        loop.state.v3_errors.append(f"cost_router unavailable: {type(exc).__name__}: {exc}")


def _attach_ask_queue(loop: Any) -> None:
    if not v3_flag("VXIS_V3_ASK", default=True):
        return
    try:
        from vxis.agent.ask.queue import AskQueue

        loop.state.ask_queue = AskQueue()
        loop.state.v3_components.append("ask_queue")
    except Exception as exc:  # noqa: BLE001
        loop.state.v3_errors.append(f"ask_queue unavailable: {type(exc).__name__}: {exc}")


def _safe_summary(obj: Any, *, token_budget: int) -> str:
    to_summary = getattr(obj, "to_summary", None)
    if callable(to_summary):
        try:
            return str(to_summary(token_budget=token_budget))
        except TypeError:
            return str(to_summary())
    return str(obj)[:token_budget]


def _safe_pending_count(queue: Any, scan_id: str) -> int:
    pending = getattr(queue, "pending", None)
    if not callable(pending):
        return 0
    try:
        return len(pending(scan_id=scan_id))
    except TypeError:
        return len(pending(scan_id))
    except Exception:
        return 0


def _safe_to_dict(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return str(obj)


def _infer_next_decision_class(loop: Any) -> str:
    state = loop.state
    if state.iteration <= 2:
        return "recon"

    focus = None
    try:
        focus = loop._focus_branch()
    except Exception:
        focus = None
    if focus is not None:
        role = str(getattr(focus, "role", "") or "")
        phase = str(getattr(focus, "phase", "") or "")
        if "review" in role or "adjudication" in phase:
            return "verify"
        if "post_exploit" in role or phase in {"data_access", "chain_closure"}:
            return "exploit"
        if "exploit" in role:
            return "exploit"

    dag = getattr(state, "hypothesis_dag", None)
    if dag is not None:
        top = []
        try:
            top = dag.top_untested(k=1)
        except Exception:
            top = []
        if top:
            return str(getattr(top[0], "decision_class", "strategy") or "strategy")

    if state.iteration % max(1, int(getattr(loop, "critic_interval", 6) or 6)) == 0:
        return "critique"
    return "strategy"


def _model_ref_for_decision(loop: Any, decision_class: str) -> str:
    brain = getattr(loop, "brain", None)
    if brain is None:
        return ""
    role_resolver = getattr(brain, "_model_role_for_decision_class", None)
    config = getattr(brain, "_hybrid_model_config", None)
    if not callable(role_resolver) or config is None:
        return str(getattr(brain, "_model", "") or "")
    try:
        role = role_resolver(decision_class)
        endpoint = config.for_role(role)
        return str(getattr(endpoint, "ref", "") or getattr(endpoint, "model", "") or "")
    except Exception:
        return str(getattr(brain, "_model", "") or "")


def _seed_hypotheses_from_candidates(state: Any) -> None:
    dag = getattr(state, "hypothesis_dag", None)
    if dag is None:
        return
    try:
        from vxis.agent.hypothesis.dag import HypothesisNode
    except Exception as exc:  # noqa: BLE001
        state.v3_errors.append(f"hypothesis seeding unavailable: {type(exc).__name__}: {exc}")
        return

    for candidate_id, candidate in getattr(state, "vector_candidates", {}).items():
        node_id = str(candidate_id)
        if node_id in dag.nodes:
            continue
        vector_class = _vector_class_from_text(
            f"{getattr(candidate, 'vector_id', '')} {getattr(candidate, 'title', '')}"
        )
        decision_class = "recon" if vector_class in {"disclosure", "infra"} else "exploit"
        priority = max(0, min(100, int(getattr(candidate, "priority", 50) or 50)))
        try:
            dag.add(
                HypothesisNode(
                    node_id=node_id,
                    claim=str(getattr(candidate, "title", "") or node_id),
                    decision_class=decision_class,
                    prior=max(0.1, min(0.95, priority / 100.0)),
                    evidence=[str(getattr(candidate, "evidence", "") or "seeded candidate")],
                    proposed_vector_class=vector_class,
                    surface_id=_root_surface_id(state),
                    created_iter=int(getattr(candidate, "created_iter", 0) or 0),
                    last_updated_iter=int(getattr(candidate, "last_iter", 0) or 0),
                )
            )
        except Exception as exc:  # noqa: BLE001
            state.v3_errors.append(f"hypothesis seed failed: {type(exc).__name__}: {exc}")


def _seed_coverage_from_pti_and_candidates(state: Any) -> None:
    matrix = getattr(state, "coverage_matrix", None)
    if matrix is None:
        return

    surfaces = _state_surfaces(state)
    if not surfaces:
        surfaces = [_root_surface(state)]
    state.v3_surfaces = surfaces

    vector_classes = _candidate_vector_classes(state) or (
        "auth-bypass",
        "sqli",
        "idor",
        "disclosure",
        "xss",
        "ssrf",
    )
    for surface in surfaces:
        try:
            matrix.ensure_surface(surface, vector_classes=vector_classes, prior=0.7)
        except Exception as exc:  # noqa: BLE001
            state.v3_errors.append(f"coverage seed failed: {type(exc).__name__}: {exc}")


def _state_surfaces(state: Any) -> list[dict[str, str]]:
    surfaces: list[dict[str, str]] = []
    dossier = getattr(state, "pti", None)
    for item in getattr(dossier, "surface", []) or []:
        surface = {
            "surface_id": str(getattr(item, "surface_id", "") or ""),
            "path": str(getattr(item, "path", "") or "/"),
            "method": str(getattr(item, "method", "") or "GET").upper(),
            "auth_role": str(getattr(item, "auth_role", "") or "anon"),
        }
        if surface["surface_id"]:
            surfaces.append(surface)
    surfaces.extend(list(getattr(state, "v3_surfaces", []) or []))
    if not surfaces:
        return []
    by_id: dict[str, dict[str, str]] = {}
    for surface in surfaces:
        surface_id = str(surface.get("surface_id") or "").strip()
        if surface_id:
            by_id[surface_id] = surface
    return list(by_id.values())


def _root_surface(state: Any) -> dict[str, str]:
    parsed = urlparse(str(getattr(state, "target", "") or ""))
    path = parsed.path or "/"
    return {
        "surface_id": _root_surface_id(state),
        "path": path,
        "method": "GET",
        "auth_role": "anon",
    }


def _root_surface_id(state: Any) -> str:
    target = str(getattr(state, "target", "") or "target")
    return "surface-" + _stable_short_hash(f"GET:{target}:anon")


def _candidate_vector_classes(state: Any) -> tuple[str, ...]:
    vectors: list[str] = []
    for candidate in getattr(state, "vector_candidates", {}).values():
        vector = _vector_class_from_text(
            f"{getattr(candidate, 'vector_id', '')} {getattr(candidate, 'title', '')}"
        )
        if vector not in vectors:
            vectors.append(vector)
    return tuple(vectors)


def _decision_class_for_action(state: Any, name: str, args: dict[str, Any] | Any) -> str:
    if name in {"verify_finding", "self_critique"}:
        return "verify" if name == "verify_finding" else "critique"
    if name == "finish_scan":
        return "critique"
    capability = action_capability(name, args)
    if capability in {"recon", "browse", "memory"}:
        return "recon"
    if capability == "review":
        return "verify"
    if capability in {"exploit", "retrieve", "chain"}:
        return "exploit"
    return str(getattr(state, "v3_current_decision_class", "") or "strategy")


def _classify_block(result: Any) -> Any:
    try:
        from vxis.agent.block.classifier import BlockClassifier

        response = _result_response_snapshot(result)
        return BlockClassifier().inspect(response)
    except Exception:
        return None


def _result_response_snapshot(result: Any) -> dict[str, Any]:
    data = getattr(result, "data", {}) if result is not None else {}
    summary = str(getattr(result, "summary", "") or "")
    if not isinstance(data, dict):
        data = {"value": data}
    status = (
        data.get("status_code")
        or data.get("status")
        or data.get("code")
        or data.get("http_status")
    )
    headers = data.get("headers") or data.get("response_headers") or {}
    body = (
        data.get("body")
        or data.get("text")
        or data.get("stdout")
        or data.get("stderr")
        or summary
    )
    if status is None:
        status_match = re.search(r"\b(401|403|406|409|423|429|451|503)\b", summary)
        status = int(status_match.group(1)) if status_match else None
    return {"status": status, "headers": headers, "body": str(body)}


def _record_block_signal(
    state: Any,
    block_signal: Any,
    *,
    name: str,
    args: dict[str, Any] | Any,
) -> None:
    entry = {
        "kind": str(getattr(block_signal, "kind", "")),
        "detector": str(getattr(block_signal, "detector", "")),
        "confidence": float(getattr(block_signal, "confidence", 0.0) or 0.0),
        "suggested_strategy": getattr(block_signal, "suggested_strategy", None),
        "tool": name,
        "args_preview": str(args)[:300],
        "iteration": int(getattr(state, "iteration", 0) or 0),
        "evidence": list(getattr(block_signal, "evidence", []) or []),
    }
    state.block_history.append(entry)


def _add_block_hint(state: Any, block_signal: Any) -> None:
    strategy = getattr(block_signal, "suggested_strategy", None)
    state.add_message(
        "system",
        {
            "hint": (
                "V3 BLOCK SIGNAL: "
                f"{getattr(block_signal, 'kind', 'block')} by "
                f"{getattr(block_signal, 'detector', 'unknown')} "
                f"(confidence={float(getattr(block_signal, 'confidence', 0.0) or 0.0):.2f}). "
                f"Suggested next strategy: {strategy or 'rescope or verify'}."
            )
        },
    )


def _surface_for_action(
    state: Any,
    name: str,
    args: dict[str, Any] | Any,
) -> dict[str, str]:
    method = "GET"
    raw_url = str(getattr(state, "target", "") or "")
    auth_role = "anon"
    if isinstance(args, dict):
        if name == "http_request":
            method = str(args.get("method") or "GET").upper()
            raw_url = str(args.get("url") or raw_url)
        elif name.startswith("browser_"):
            raw_url = str(args.get("url") or raw_url)
        elif name == "run_skill":
            raw_url = str(args.get("target_url") or raw_url)
            skill = str(args.get("skill") or args.get("_skill_override") or "").lower()
            if "post_auth" in skill or "idor" in skill or "auth" in skill:
                auth_role = "user"
        elif name in {"report_finding", "verify_finding"}:
            raw_url = str(args.get("affected_component") or raw_url)
        else:
            raw_url = str(args.get("url") or args.get("target_url") or raw_url)
    path = _path_from_url_or_text(raw_url)
    surface_id = "surface-" + _stable_short_hash(f"{method}:{path}:{auth_role}")
    surface = {
        "surface_id": surface_id,
        "path": path,
        "method": method,
        "auth_role": auth_role,
    }
    _remember_surface(state, surface)
    return surface


def _remember_surface(state: Any, surface: dict[str, str]) -> None:
    surfaces = list(getattr(state, "v3_surfaces", []) or [])
    if not any(item.get("surface_id") == surface["surface_id"] for item in surfaces):
        surfaces.append(surface)
    state.v3_surfaces = surfaces


def _path_from_url_or_text(value: str) -> str:
    text = str(value or "").strip()
    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path
    if text.startswith("/"):
        return text
    match = re.search(r"(/[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]*)", text)
    if match:
        return match.group(1) or "/"
    return "/"


def _vector_class_for_action(name: str, args: dict[str, Any] | Any) -> str:
    if isinstance(args, dict):
        if name == "report_finding":
            return _vector_class_from_text(str(args.get("finding_type") or args.get("title") or ""))
        if name == "run_skill":
            return _vector_class_from_text(
                str(args.get("skill") or args.get("_skill_override") or "")
            )
        blob = " ".join(str(value) for value in args.values() if isinstance(value, str))
    else:
        blob = str(args or "")
    return _vector_class_from_text(f"{name} {blob}")


def _vector_class_from_text(value: str) -> str:
    text = str(value or "").lower()
    mapping = (
        ("auth-bypass", ("auth", "login", "session", "jwt", "weak_auth")),
        ("sqli", ("sqli", "sql", "injection", "nosql")),
        ("idor", ("idor", "bola", "access control", "broken_access")),
        ("xss", ("xss", "cross-site", "script")),
        ("ssrf", ("ssrf", "server-side request")),
        ("rce", ("rce", "command", "code execution", "shell")),
        ("path-traversal", ("traversal", "../", "lfi", "file read")),
        ("csrf", ("csrf",)),
        ("disclosure", ("sensitive", "file", "config", "disclosure", "secret")),
        ("business-logic", ("business", "logic", "coupon", "gift", "payment")),
        ("infra", ("cve", "nuclei", "infra", "fingerprint", "directory", "dir")),
    )
    for vector, markers in mapping:
        if any(marker in text for marker in markers):
            return vector
    return "generic"


def _coverage_status_for_result(name: str, result: Any, block_signal: Any) -> str:
    if name == "report_finding" and bool(getattr(result, "ok", False)):
        return "found"
    if getattr(block_signal, "blocked", False):
        return "tested-blocked"
    if bool(getattr(result, "ok", False)):
        return "tested-clean"
    summary = str(getattr(result, "summary", "") or "").lower()
    if any(token in summary for token in ("blocked", "forbidden", "rate limit", "waf")):
        return "tested-blocked"
    return "tested-clean"


def _mark_coverage(
    state: Any,
    surface: dict[str, str],
    vector_class: str,
    status: str,
) -> None:
    matrix = getattr(state, "coverage_matrix", None)
    if matrix is None:
        return
    try:
        matrix.ensure_surface(surface, vector_classes=[vector_class], prior=0.7)
        matrix.mark(
            surface["surface_id"],
            vector_class,
            status,
            int(getattr(state, "iteration", 0) or 0),
        )
    except Exception as exc:  # noqa: BLE001
        state.v3_errors.append(f"coverage mark failed: {type(exc).__name__}: {exc}")


def _update_hypotheses_after_action(
    state: Any,
    *,
    name: str,
    args: dict[str, Any] | Any,
    result: Any,
    candidate_ids: list[str],
    vector_class: str,
    surface_id: str,
    blocked: bool,
) -> None:
    dag = getattr(state, "hypothesis_dag", None)
    if dag is None:
        return
    if not candidate_ids:
        top = []
        try:
            top = dag.query(proposed_vector_class=vector_class, status="untested", limit=1)
        except Exception:
            top = []
        candidate_ids = [str(getattr(item, "node_id", "")) for item in top]

    if name == "report_finding" and bool(getattr(result, "ok", False)):
        status_change = "confirmed"
        delta = 0.45
    elif blocked:
        status_change = "inconclusive"
        delta = -0.05
    elif bool(getattr(result, "ok", False)):
        status_change = "testing"
        delta = 0.05
    else:
        status_change = "refuted" if _looks_refuting(result) else "inconclusive"
        delta = -0.25 if status_change == "refuted" else -0.05

    evidence = f"{name}: {str(getattr(result, 'summary', '') or '')[:300]}"
    for node_id in candidate_ids:
        if not node_id or node_id not in getattr(dag, "nodes", {}):
            continue
        try:
            node = dag.nodes[node_id]
            if not getattr(node, "surface_id", None):
                node.surface_id = surface_id
            dag.update_belief(
                node_id,
                evidence,
                delta,
                status_change=status_change,
                iteration=int(getattr(state, "iteration", 0) or 0),
            )
        except Exception as exc:  # noqa: BLE001
            state.v3_errors.append(f"hypothesis update failed: {type(exc).__name__}: {exc}")


def _looks_refuting(result: Any) -> bool:
    text = str(getattr(result, "summary", "") or "").lower()
    return any(
        token in text
        for token in ("not vulnerable", "no finding", "not exploitable", "clean", "refuted")
    )


def _update_pti_after_action(
    state: Any,
    *,
    name: str,
    args: dict[str, Any] | Any,
    result: Any,
    surface: dict[str, str],
    vector_class: str,
    block_signal: Any,
) -> None:
    dossier = getattr(state, "pti", None)
    if dossier is None:
        return
    scan_id = _scan_id_for_state(state)
    try:
        from vxis.pti.models import Defense, FindingHistoryEntry, SurfaceUnit, utc_now

        dossier.updated_at = utc_now()
        if not any(item.surface_id == surface["surface_id"] for item in dossier.surface):
            dossier.surface.append(
                SurfaceUnit(
                    surface_id=surface["surface_id"],
                    path=surface["path"],
                    method=surface["method"],
                    auth_role=surface["auth_role"],
                    status="alive",
                    last_seen_scan=scan_id,
                )
            )
        if getattr(block_signal, "blocked", False):
            kind = str(getattr(block_signal, "kind", "waf-signature"))
            detector = str(getattr(block_signal, "detector", "unknown"))
            exists = any(
                item.kind == kind and item.detector == detector for item in dossier.defenses
            )
            if not exists:
                dossier.defenses.append(
                    Defense(
                        kind=kind,
                        detector=detector,
                        blocked_payload_classes=[vector_class],
                        bypasses_known=[],
                        first_seen_scan=scan_id,
                    )
                )
        if name == "report_finding" and bool(getattr(result, "ok", False)):
            data = getattr(result, "data", {}) if isinstance(getattr(result, "data", {}), dict) else {}
            finding_id = str(data.get("id") or _stable_short_hash(str(args)))
            finding_type = vector_class
            if isinstance(args, dict):
                finding_type = str(args.get("finding_type") or vector_class)
            if not any(item.finding_id == finding_id for item in dossier.findings_history):
                dossier.findings_history.append(
                    FindingHistoryEntry(
                        finding_id=finding_id,
                        finding_type=finding_type,
                        surface_id=surface["surface_id"],
                        status="present",
                        first_seen_scan=scan_id,
                        last_verified_scan=scan_id,
                    )
                )
    except Exception as exc:  # noqa: BLE001
        state.v3_errors.append(f"pti update failed: {type(exc).__name__}: {exc}")


def _write_trajectory(
    loop: Any,
    *,
    name: str,
    args: dict[str, Any] | Any,
    result: Any,
    decision_class: str,
    candidate_ids: list[str],
    branch_ids: list[str],
) -> None:
    state = loop.state
    store = getattr(state, "pti_store", None)
    dossier = getattr(state, "pti", None)
    if store is None or dossier is None:
        return
    try:
        from vxis.pti.models import TrajectoryRecord

        input_context = {
            "target_url": getattr(state, "target", ""),
            "iteration": int(getattr(state, "iteration", 0) or 0),
            "candidate_ids": candidate_ids,
            "branch_ids": branch_ids,
            "dashboard": _safe_summary(state.hypothesis_dag, token_budget=250)
            if getattr(state, "hypothesis_dag", None) is not None
            else "",
            "coverage": _safe_summary(state.coverage_matrix, token_budget=250)
            if getattr(state, "coverage_matrix", None) is not None
            else "",
        }
        output_action = {"tool": name, "args": args if isinstance(args, dict) else {"value": args}}
        summary = str(getattr(result, "summary", "") or "")
        tokens_in = _rough_token_count(input_context)
        tokens_out = _rough_token_count(output_action)
        model_used = (
            str(getattr(state, "v3_current_model", "") or "")
            or str(getattr(getattr(loop, "brain", None), "_model", "") or "unknown")
        )
        outcome_status = _outcome_status(result)
        record = TrajectoryRecord(
            scan_id=_scan_id_for_state(state),
            target_hash=dossier.target_hash,
            iter=int(getattr(state, "iteration", 0) or 0),
            decision_class=decision_class,
            model_used=model_used,
            input_context=input_context,
            input_token_count=tokens_in,
            output_action=output_action,
            output_token_count=tokens_out,
            outcome_status=outcome_status,
            outcome_evidence=summary[:1000] if summary else None,
            cost_usd=0.0,
            latency_ms=0,
        )
        store.append_trajectory(record)
        state.trajectories_written += 1
        router = getattr(state, "cost_router", None)
        if router is not None:
            try:
                router.record(decision_class, tokens_in, tokens_out, 0.0)
                state.cost_report = router.report()
            except Exception:
                pass
    except Exception as exc:  # noqa: BLE001
        state.v3_errors.append(f"trajectory write failed: {type(exc).__name__}: {exc}")


def v3_maybe_run_self_critique(loop: Any, *, force: bool = False) -> Any | None:
    state = loop.state
    if not getattr(state, "v3_enabled", False):
        return None
    if not v3_flag("VXIS_V3_CRITIQUE", default=True):
        return None

    interval = max(1, int(_v3_float_env("VXIS_V3_CRITIQUE_INTERVAL", 6.0)))
    last_iter = int(getattr(state, "v3_last_critique_iter", 0) or 0)
    if not force and int(getattr(state, "iteration", 0) or 0) - last_iter < interval:
        return None
    dag = getattr(state, "hypothesis_dag", None)
    matrix = getattr(state, "coverage_matrix", None)
    if dag is None and matrix is None:
        return None
    if not force and not getattr(dag, "nodes", {}) and not getattr(matrix, "cells", {}):
        return None

    try:
        from vxis.agent.critique.loop import SelfCritique
        from vxis.agent.hypothesis.dag import HypothesisNode

        report = SelfCritique().run(
            dag,
            matrix,
            findings=list(getattr(state, "findings", []) or []),
            pti=getattr(state, "pti", None),
        )
        state.v3_last_critique = report
        state.v3_last_critique_iter = int(getattr(state, "iteration", 0) or 0)
        if dag is not None:
            for proposed in getattr(report, "new_hypotheses_proposed", []) or []:
                claim = str(getattr(proposed, "claim", "") or "").strip()
                if not claim:
                    continue
                if any(getattr(node, "claim", "") == claim for node in dag.nodes.values()):
                    continue
                try:
                    dag.add(
                        HypothesisNode(
                            node_id=dag.next_node_id(prefix="critique"),
                            claim=claim,
                            decision_class=str(
                                getattr(proposed, "decision_class", "strategy") or "strategy"
                            ),
                            prior=float(getattr(proposed, "prior", 0.5) or 0.5),
                            evidence=[str(getattr(proposed, "rationale", "") or "self-critique")],
                            created_iter=int(getattr(state, "iteration", 0) or 0),
                            last_updated_iter=int(getattr(state, "iteration", 0) or 0),
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    state.v3_errors.append(
                        f"critique hypothesis add failed: {type(exc).__name__}: {exc}"
                    )
        if force or not getattr(report, "finish_allowed", True):
            state.add_message(
                "system",
                {
                    "hint": (
                        "V3 SELF-CRITIQUE: "
                        + str(getattr(report, "rationale", "") or "critique complete")
                        + " "
                        + "; ".join(list(getattr(report, "gaps", []) or [])[:4])
                    )[:1200]
                },
            )
        return report
    except Exception as exc:  # noqa: BLE001
        state.v3_errors.append(f"self-critique failed: {type(exc).__name__}: {exc}")
        return None


def _outcome_status(result: Any) -> str:
    if bool(getattr(result, "ok", False)):
        return "success"
    summary = str(getattr(result, "summary", "") or "").lower()
    if any(token in summary for token in ("blocked", "forbidden", "rate limit", "waf")):
        return "blocked"
    if any(token in summary for token in ("no effect", "not vulnerable", "clean")):
        return "no-effect"
    return "error"


def _scan_id_for_state(state: Any) -> str:
    raw = str(getattr(state, "scan_id", "") or "").strip()
    if raw:
        return _safe_scan_id(raw)
    seed = f"{getattr(state, 'target', '')}:{getattr(state, 'started_at', '')}"
    return "scan-" + _stable_short_hash(seed)


def _safe_scan_id(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    normalized = normalized.strip(".-")
    return normalized or "scan"


def _rough_token_count(value: Any) -> int:
    return max(0, len(str(value)) // 4)


def _stable_short_hash(value: str, *, length: int = 16) -> str:
    import hashlib

    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:length]


def _v3_float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _v3_action_hint(data: dict[str, Any]) -> str:
    gate = data.get("coverage_gate") if isinstance(data, dict) else None
    if isinstance(gate, dict):
        gaps = gate.get("high_value_gaps") or gate.get("overall_gaps") or []
        if gaps:
            first = gaps[0]
            if isinstance(first, dict):
                surface = first.get("surface_id", "surface")
                vector = first.get("vector_class", "vector")
                return f"Probe unresolved v3 coverage gap next: {surface}/{vector}."
    critique = data.get("self_critique") if isinstance(data, dict) else None
    if isinstance(critique, dict):
        proposed = critique.get("new_hypotheses_proposed") or []
        if proposed:
            first = proposed[0]
            if isinstance(first, dict):
                return str(first.get("claim") or "Resolve the top self-critique gap.")
    return "Resolve the highest-priority v3 coverage or hypothesis gap before finishing."


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item)
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


__all__ = [
    "initialize_v3_runtime",
    "bind_v3_tools",
    "v3_after_action",
    "v3_dashboard_summary",
    "v3_enabled",
    "v3_finalize_runtime",
    "v3_flag",
    "v3_maybe_finish_gate",
    "v3_maybe_run_self_critique",
    "v3_prepare_decision",
    "v3_result_payload",
    "v3_sync_runtime_state",
]
