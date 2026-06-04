"""Brain tools for operating on a v3 HypothesisDAG.

These tools intentionally depend only on a provided DAG or generic state object. Scan-loop
integration can pass `state.hypothesis_dag`; tests and child runtimes can pass a DAG directly.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

from vxis.agent.hypothesis.dag import (
    HYPOTHESIS_STATUSES,
    HypothesisNode,
    HypothesisDAG,
)
from vxis.agent.tool_registry import ToolResult

HypothesisCandidate = HypothesisNode | dict[str, Any]
HypothesisGenerator = Callable[
    ..., list[HypothesisCandidate] | Awaitable[list[HypothesisCandidate]]
]


class _HypothesisToolBase:
    def __init__(
        self,
        *,
        dag: HypothesisDAG | None = None,
        state: object | dict[str, Any] | None = None,
    ) -> None:
        self._dag = dag
        self._state = state

    @property
    def dag(self) -> HypothesisDAG:
        resolved = resolve_hypothesis_dag(dag=self._dag, state=self._state)
        if self._dag is None and self._state is None:
            self._dag = resolved
        return resolved


class GenerateHypothesesTool(_HypothesisToolBase):
    name = "generate_hypotheses"
    description = (
        "Generate root hypothesis candidates from seed evidence. Uses an injected generator "
        "when provided; otherwise returns conservative built-in security hypotheses."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "seed_evidence": {"type": "string"},
            "n": {"type": "integer", "default": 15, "minimum": 1, "maximum": 50},
            "add_to_dag": {"type": "boolean", "default": True},
            "surface_id": {"type": ["string", "null"]},
            "created_iter": {"type": "integer", "default": 0},
        },
        "required": ["seed_evidence"],
    }

    def __init__(
        self,
        *,
        dag: HypothesisDAG | None = None,
        state: object | dict[str, Any] | None = None,
        generator: HypothesisGenerator | None = None,
    ) -> None:
        super().__init__(dag=dag, state=state)
        self._generator = generator

    async def run(self, **kwargs: Any) -> ToolResult:
        seed_evidence = str(kwargs.get("seed_evidence", "")).strip()
        if not seed_evidence:
            return _error("missing_seed_evidence", "seed_evidence is required")

        limit = _coerce_int(kwargs.get("n", 15), default=15, minimum=1, maximum=50)
        add_to_dag = _coerce_bool(kwargs.get("add_to_dag", True), default=True)
        created_iter = _coerce_int(kwargs.get("created_iter", 0), default=0, minimum=0)
        surface_id = _optional_text(kwargs.get("surface_id"))

        try:
            raw_candidates = await self._generate(seed_evidence, limit)
            hypotheses = normalize_hypothesis_candidates(
                raw_candidates[:limit],
                dag=self.dag,
                default_surface_id=surface_id,
                default_created_iter=created_iter,
            )
            added = 0
            if add_to_dag:
                for hypothesis in hypotheses:
                    if hypothesis.node_id in self.dag.nodes:
                        continue
                    self.dag.add(hypothesis)
                    added += 1
        except Exception as exc:
            return _error("generate_hypotheses_failed", str(exc))

        return ToolResult(
            ok=True,
            data={
                "hypotheses": [hypothesis.brief() for hypothesis in hypotheses],
                "added": added if add_to_dag else 0,
                "total_nodes": len(self.dag.nodes),
            },
            summary=f"generated {len(hypotheses)} hypotheses; added {added if add_to_dag else 0}",
        )

    async def _generate(self, seed_evidence: str, n: int) -> list[HypothesisCandidate]:
        if self._generator is None:
            return default_hypothesis_candidates(seed_evidence, n)
        try:
            result = self._generator(seed_evidence=seed_evidence, n=n)
        except TypeError:
            result = self._generator(seed_evidence, n)
        if inspect.isawaitable(result):
            result = await result
        return list(result or [])


class PrioritizeHypothesisTool(_HypothesisToolBase):
    name = "prioritize_hypothesis"
    description = "Return the highest-prior untested hypotheses from the current DAG."
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "k": {"type": "integer", "default": 1, "minimum": 1, "maximum": 20},
            "min_prior": {"type": ["number", "null"]},
            "include_summary": {"type": "boolean", "default": False},
        },
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        limit = _coerce_int(kwargs.get("k", 1), default=1, minimum=1, maximum=20)
        min_prior = _optional_probability(kwargs.get("min_prior"))
        top = self.dag.top_untested(k=limit)
        if min_prior is not None:
            top = [hypothesis for hypothesis in top if hypothesis.prior >= min_prior]

        data: dict[str, Any] = {
            "hypotheses": [hypothesis.brief() for hypothesis in top],
            "hypothesis": top[0].brief() if top else None,
            "total_untested": self.dag.status_counts()["untested"],
        }
        if _coerce_bool(kwargs.get("include_summary", False), default=False):
            data["summary"] = self.dag.to_summary(token_budget=300)
        return ToolResult(
            ok=True,
            data=data,
            summary=(
                f"selected {len(top)} untested hypotheses"
                if top
                else "no untested hypotheses available"
            ),
        )


class UpdateHypothesisTool(_HypothesisToolBase):
    name = "update_hypothesis"
    description = "Apply evidence, a belief delta, and an optional status change to a DAG node."
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "node_id": {"type": "string"},
            "evidence": {"type": "string"},
            "status_change": {
                "type": ["string", "null"],
                "enum": [*HYPOTHESIS_STATUSES, None],
            },
            "delta": {"type": "number", "default": 0.0},
            "iteration": {"type": ["integer", "null"]},
            "propagate": {"type": "boolean", "default": True},
        },
        "required": ["node_id", "evidence"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        node_id = str(kwargs.get("node_id", "")).strip()
        if not node_id:
            return _error("missing_node_id", "node_id is required")
        try:
            self.dag.update_belief(
                node_id=node_id,
                evidence=str(kwargs.get("evidence", "")).strip(),
                delta=_coerce_float(kwargs.get("delta", 0.0), default=0.0),
                status_change=kwargs.get("status_change"),
                iteration=_optional_int(kwargs.get("iteration")),
                propagate=_coerce_bool(kwargs.get("propagate", True), default=True),
            )
        except KeyError:
            return _error("unknown_hypothesis", f"unknown hypothesis id: {node_id}")
        except Exception as exc:
            return _error("update_hypothesis_failed", str(exc))

        node = self.dag.nodes[node_id]
        return ToolResult(
            ok=True,
            data={
                "hypothesis": node.brief(),
                "counts": self.dag.status_counts(),
                "summary": self.dag.to_summary(token_budget=300),
            },
            summary=f"updated {node_id}: status={node.status} prior={node.prior:.2f}",
        )


class AddChildHypothesisTool(_HypothesisToolBase):
    name = "add_child_hypothesis"
    description = "Add a child hypothesis under an existing parent node."
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "parent_id": {"type": "string"},
            "claim": {"type": "string"},
            "prior": {"type": "number"},
            "vector_class": {"type": ["string", "null"]},
            "decision_class": {
                "type": "string",
                "enum": ["recon", "strategy", "exploit", "verify"],
                "default": "exploit",
            },
            "surface_id": {"type": ["string", "null"]},
            "evidence": {"type": ["string", "array", "null"]},
            "node_id": {"type": ["string", "null"]},
            "created_iter": {"type": "integer", "default": 0},
        },
        "required": ["parent_id", "claim", "prior"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        parent_id = str(kwargs.get("parent_id", "")).strip()
        claim = str(kwargs.get("claim", "")).strip()
        if not parent_id:
            return _error("missing_parent_id", "parent_id is required")
        if not claim:
            return _error("missing_claim", "claim is required")
        if parent_id not in self.dag.nodes:
            return _error("unknown_parent", f"unknown parent hypothesis id: {parent_id}")

        node_id = _optional_text(kwargs.get("node_id")) or self.dag.next_node_id()
        try:
            child = HypothesisNode(
                node_id=node_id,
                claim=claim,
                decision_class=str(kwargs.get("decision_class") or "exploit"),
                prior=_coerce_float(kwargs.get("prior"), default=0.5),
                evidence=_coerce_evidence(kwargs.get("evidence")),
                status="untested",
                parent_ids=[parent_id],
                proposed_vector_class=_optional_text(kwargs.get("vector_class")),
                surface_id=_optional_text(kwargs.get("surface_id")),
                created_iter=_coerce_int(kwargs.get("created_iter", 0), default=0, minimum=0),
                last_updated_iter=_coerce_int(kwargs.get("created_iter", 0), default=0, minimum=0),
            )
            self.dag.add(child, parent_ids=[parent_id])
        except Exception as exc:
            return _error("add_child_hypothesis_failed", str(exc))

        return ToolResult(
            ok=True,
            data={
                "hypothesis": child.brief(),
                "parent": self.dag.nodes[parent_id].brief(),
                "total_nodes": len(self.dag.nodes),
            },
            summary=f"added child hypothesis {child.node_id} under {parent_id}",
        )


class QueryDAGTool(_HypothesisToolBase):
    name = "query_dag"
    description = "Query hypothesis DAG nodes and status counts for critique or planning."
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "filter": {"type": ["object", "string", "null"]},
            "limit": {"type": "integer", "default": 20, "minimum": 0, "maximum": 100},
            "summary_budget": {"type": "integer", "default": 300, "minimum": 0},
        },
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        query_filter = _normalize_filter(kwargs.get("filter"))
        limit = _coerce_int(kwargs.get("limit", 20), default=20, minimum=0, maximum=100)
        try:
            nodes = self.dag.query(
                status=query_filter.get("status"),
                proposed_vector_class=query_filter.get("vector_class")
                or query_filter.get("proposed_vector_class"),
                surface_id=query_filter.get("surface_id"),
                min_prior=_optional_probability(query_filter.get("min_prior")),
                max_prior=_optional_probability(query_filter.get("max_prior")),
                node_id=query_filter.get("node_id"),
                parent_id=query_filter.get("parent_id"),
                limit=limit,
            )
        except Exception as exc:
            return _error("query_dag_failed", str(exc))

        return ToolResult(
            ok=True,
            data={
                "counts": self.dag.status_counts(),
                "roots": list(self.dag.roots),
                "nodes": [node.brief() for node in nodes],
                "total_nodes": len(self.dag.nodes),
                "summary": self.dag.to_summary(
                    token_budget=_coerce_int(
                        kwargs.get("summary_budget", 300),
                        default=300,
                        minimum=0,
                    )
                ),
            },
            summary=f"query returned {len(nodes)} hypotheses",
        )


HypothesisGenerateTool = GenerateHypothesesTool
HypothesisPrioritizeTool = PrioritizeHypothesisTool
HypothesisUpdateTool = UpdateHypothesisTool
HypothesisAddChildTool = AddChildHypothesisTool
HypothesisQueryDAGTool = QueryDAGTool

__all__ = [
    "AddChildHypothesisTool",
    "GenerateHypothesesTool",
    "HypothesisAddChildTool",
    "HypothesisGenerateTool",
    "HypothesisPrioritizeTool",
    "HypothesisQueryDAGTool",
    "HypothesisUpdateTool",
    "PrioritizeHypothesisTool",
    "QueryDAGTool",
    "UpdateHypothesisTool",
    "build_hypothesis_tools",
    "default_hypothesis_candidates",
    "normalize_hypothesis_candidates",
    "resolve_hypothesis_dag",
]


def build_hypothesis_tools(
    *,
    dag: HypothesisDAG | None = None,
    state: object | dict[str, Any] | None = None,
    generator: HypothesisGenerator | None = None,
) -> list[_HypothesisToolBase]:
    """Return the Component B tool instances sharing one DAG/state reference."""
    return [
        GenerateHypothesesTool(dag=dag, state=state, generator=generator),
        PrioritizeHypothesisTool(dag=dag, state=state),
        UpdateHypothesisTool(dag=dag, state=state),
        AddChildHypothesisTool(dag=dag, state=state),
        QueryDAGTool(dag=dag, state=state),
    ]


def resolve_hypothesis_dag(
    *,
    dag: HypothesisDAG | None = None,
    state: object | dict[str, Any] | None = None,
) -> HypothesisDAG:
    if dag is not None:
        return dag
    if isinstance(state, dict):
        current = state.get("hypothesis_dag")
        if isinstance(current, HypothesisDAG):
            return current
        if current is not None:
            resolved = HypothesisDAG.model_validate(current)
            state["hypothesis_dag"] = resolved
            return resolved
        resolved = HypothesisDAG()
        state["hypothesis_dag"] = resolved
        return resolved
    if state is not None:
        current = getattr(state, "hypothesis_dag", None)
        if isinstance(current, HypothesisDAG):
            return current
        if current is not None:
            resolved = HypothesisDAG.model_validate(current)
            setattr(state, "hypothesis_dag", resolved)
            return resolved
        resolved = HypothesisDAG()
        setattr(state, "hypothesis_dag", resolved)
        return resolved
    return HypothesisDAG()


def normalize_hypothesis_candidates(
    candidates: list[HypothesisCandidate],
    *,
    dag: HypothesisDAG,
    default_surface_id: str | None = None,
    default_created_iter: int = 0,
) -> list[HypothesisNode]:
    normalized: list[HypothesisNode] = []
    reserved: set[str] = set()
    for candidate in candidates:
        if isinstance(candidate, HypothesisNode):
            raw = candidate.model_dump()
        else:
            raw = dict(candidate)
        node_id = _optional_text(raw.get("node_id"))
        if not node_id or node_id in dag.nodes or node_id in reserved:
            node_id = dag.next_node_id(reserved=reserved)
        reserved.add(node_id)
        created_iter = _coerce_int(
            raw.get("created_iter", default_created_iter),
            default=default_created_iter,
            minimum=0,
        )
        normalized.append(
            HypothesisNode(
                node_id=node_id,
                claim=str(raw.get("claim", "")).strip(),
                decision_class=str(raw.get("decision_class") or "strategy"),
                prior=_coerce_float(raw.get("prior", 0.5), default=0.5),
                evidence=_coerce_evidence(raw.get("evidence")),
                status=str(raw.get("status") or "untested"),
                parent_ids=[],
                child_ids=[],
                proposed_vector_class=_optional_text(
                    raw.get("proposed_vector_class") or raw.get("vector_class")
                ),
                surface_id=_optional_text(raw.get("surface_id")) or default_surface_id,
                created_iter=created_iter,
                last_updated_iter=_coerce_int(
                    raw.get("last_updated_iter", created_iter),
                    default=created_iter,
                    minimum=0,
                ),
            )
        )
    return normalized


def default_hypothesis_candidates(seed_evidence: str, n: int) -> list[dict[str, Any]]:
    seed = seed_evidence.lower()
    templates: list[tuple[str, str, str, float, tuple[str, ...]]] = [
        (
            "SQL injection may exist in user-controlled query or form parameters",
            "exploit",
            "sql_injection",
            0.68,
            ("sql", "search", "query", "filter", "api"),
        ),
        (
            "Object identifiers may lack authorization checks",
            "exploit",
            "idor",
            0.64,
            ("id", "user", "account", "order", "api"),
        ),
        (
            "Authentication or session handling may allow bypass",
            "verify",
            "auth",
            0.6,
            ("login", "auth", "session", "jwt", "cookie"),
        ),
        (
            "Reflected or stored XSS may be present in rendered user-controlled fields",
            "exploit",
            "xss",
            0.56,
            ("html", "form", "comment", "profile", "search"),
        ),
        (
            "Privileged administrative functionality may be discoverable or weakly gated",
            "recon",
            "access_control",
            0.52,
            ("admin", "role", "dashboard", "manage"),
        ),
        (
            "File upload or import paths may allow unsafe content handling",
            "exploit",
            "file_upload",
            0.48,
            ("upload", "import", "avatar", "file"),
        ),
        (
            "Server-side request features may reach internal resources",
            "exploit",
            "ssrf",
            0.42,
            ("url", "webhook", "callback", "fetch", "import"),
        ),
        (
            "Debug, backup, or metadata endpoints may leak sensitive information",
            "recon",
            "information_disclosure",
            0.4,
            ("debug", "backup", "metadata", "env", "config"),
        ),
        (
            "Business workflow state changes may be replayable or missing invariants",
            "strategy",
            "business_logic",
            0.38,
            ("cart", "checkout", "coupon", "payment", "workflow"),
        ),
        (
            "API schema or client bundles may reveal hidden endpoints",
            "recon",
            "api_recon",
            0.36,
            ("swagger", "openapi", "graphql", "bundle", "javascript"),
        ),
        (
            "CSRF protection may be absent on state-changing requests",
            "verify",
            "csrf",
            0.34,
            ("post", "put", "delete", "form", "cookie"),
        ),
        (
            "Rate limits or lockout controls may be absent on abuse-prone flows",
            "verify",
            "rate_limit",
            0.32,
            ("login", "reset", "otp", "coupon", "invite"),
        ),
        (
            "Deserialization or template rendering inputs may execute attacker-controlled data",
            "exploit",
            "rce",
            0.28,
            ("template", "serialize", "yaml", "pickle", "render"),
        ),
        (
            "CORS or cross-origin policy may expose authenticated data",
            "verify",
            "cors",
            0.26,
            ("cors", "origin", "api", "cookie"),
        ),
        (
            "Secrets may be exposed in static assets or client-side configuration",
            "recon",
            "secrets",
            0.24,
            ("token", "key", "secret", "bundle", "config"),
        ),
    ]

    out: list[dict[str, Any]] = []
    for claim, decision_class, vector_class, base_prior, boost_tokens in templates[: max(0, n)]:
        boost = 0.08 if any(token in seed for token in boost_tokens) else 0.0
        out.append(
            {
                "claim": claim,
                "decision_class": decision_class,
                "prior": min(0.95, base_prior + boost),
                "proposed_vector_class": vector_class,
                "evidence": [f"Seed evidence considered: {_trim(seed_evidence, 240)}"],
                "status": "untested",
            }
        )
    return out


def _normalize_filter(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        if text in HYPOTHESIS_STATUSES:
            return {"status": text}
        return {"vector_class": text}
    if isinstance(value, dict):
        return {str(key): val for key, val in value.items()}
    return {}


def _coerce_evidence(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = [value]
    else:
        raw_items = list(value)
    return [str(item).strip() for item in raw_items if str(item or "").strip()]


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def _coerce_int(
    value: Any,
    *,
    default: int,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    if minimum is not None:
        number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return number


def _coerce_float(value: Any, *, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _optional_probability(value: Any) -> float | None:
    if value is None or value == "":
        return None
    return max(0.0, min(1.0, _coerce_float(value, default=0.0)))


def _coerce_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y"}:
            return True
        if lowered in {"false", "0", "no", "n"}:
            return False
    return bool(value)


def _trim(value: str, max_chars: int) -> str:
    text = str(value or "").strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def _error(error: str, summary: str) -> ToolResult:
    return ToolResult(ok=False, summary=summary, error=error)
