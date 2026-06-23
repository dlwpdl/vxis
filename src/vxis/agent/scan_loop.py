from __future__ import annotations
import logging
import os
from typing import Any, Callable
from vxis.agent.scan_loop_state import (
    BranchState,
    ScanLoopState,
    VectorCandidate,
    action_capability,
    advance_post_exploit_phase,
    infer_branch_phase,
    infer_branch_role,
)
from vxis.agent.scan_loop_actions import ScanLoopActionMixin
from vxis.agent.scan_loop_agent_graph import ScanLoopAgentGraphMixin
from vxis.agent.scan_loop_dashboard import build_scan_dashboard
from vxis.agent.scan_loop_decision_policy import ScanLoopDecisionPolicyMixin
from vxis.agent.scan_loop_run import ScanLoopRunMixin
from vxis.agent.scan_loop_v3 import initialize_v3_runtime
from vxis.agent.scan_loop_policy import (
    DIRECTOR_PROMPT_TEMPLATE,
    POST_EXPLOIT_PHASE_ALLOWED_CAPABILITIES,
    ROLE_ALLOWED_CAPABILITIES,
    _DESKTOP_SKILLS,
)
from vxis.agent.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

__all__ = ["DIRECTOR_PROMPT_TEMPLATE", "ScanAgentLoop", "VectorCandidate", "_DESKTOP_SKILLS"]


def _env_flag(name: str) -> bool:
    return str(os.environ.get(name) or "").strip().lower() in {"1", "true", "yes", "on"}


class ScanAgentLoop(
    ScanLoopActionMixin, ScanLoopDecisionPolicyMixin, ScanLoopAgentGraphMixin, ScanLoopRunMixin
):
    _ROLE_ALLOWED_CAPABILITIES = ROLE_ALLOWED_CAPABILITIES
    _POST_EXPLOIT_PHASE_ALLOWED_CAPABILITIES = POST_EXPLOIT_PHASE_ALLOWED_CAPABILITIES

    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        max_iters: int = 300,
        hard_max_iters: int | None = None,
        adaptive_budget: bool = False,
        extend_iters: int = 0,
        brain: Any | None = None,
        critic_interval: int = 6,
        target_kind: Any = None,
        event_callback: Callable[[str, dict[str, Any]], None] | None = None,
        operator_inbox: Any = None,
    ) -> None:
        self.state = ScanLoopState(target=target, max_iters=max_iters)
        self.registry = registry
        self.brain = brain
        self.critic_interval = critic_interval
        self._last_critic_iter = 0
        self._event_callback = event_callback
        # Mid-scan operator → Brain steering (TUI → thread-safe inbox → loop).
        self._operator_inbox = operator_inbox
        self.hard_max_iters = hard_max_iters if hard_max_iters is not None else max_iters
        self.adaptive_budget = adaptive_budget
        self.extend_iters = max(0, extend_iters)
        self._latest_control_plane: dict[str, Any] = {}
        # Surface kind drives skill-sweep filtering. Without it, a desktop
        # scan ends up running test_xss / test_sqli / etc. on a file:// path
        # — wasted iterations + false-positive noise from web skills hitting
        # a non-HTTP target. Kept as Any for back-compat with callers that
        # don't pass it (default = web behaviour).
        from vxis.interaction.surface import TargetKind as _TK

        self._target_kind = target_kind or _TK.WEB
        self._seed_vector_candidates()
        self._install_agent_graph_executor()
        initialize_v3_runtime(self)

    def _install_agent_graph_executor(self) -> None:
        tool = self.registry.get_tool("agent_graph")
        set_executor = getattr(tool, "set_executor", None)
        set_persistence_path = getattr(tool, "set_persistence_path", None)
        executor = self._run_agent_graph_child_turn
        agent_graph_snapshot_path = os.environ.get("VXIS_AGENT_GRAPH_SNAPSHOT")
        if _env_flag("VXIS_USE_SDK_AGENT_RUNTIME"):
            from vxis.agent.sdk_runtime import SDKChildAgentLoop, SDKRunPaths

            config = getattr(getattr(self, "brain", None), "_hybrid_model_config", None)
            worker_endpoint = getattr(config, "worker", None)
            run_dir = os.environ.get("VXIS_SDK_RUN_DIR") or ".vxis/sdk-runtime/latest"
            run_paths = SDKRunPaths.for_run_dir(run_dir)
            agent_graph_snapshot_path = str(run_paths.runtime_dir / "agent_graph.json")
            try:
                background_worker_concurrency = int(
                    os.environ.get(
                        "VXIS_SDK_BACKGROUND_WORKER_CONCURRENCY",
                        os.environ.get("VXIS_LOCAL_WORKER_CONCURRENCY", "1"),
                    )
                    or "1"
                )
            except ValueError:
                background_worker_concurrency = 1
            self._sdk_agent_loop = SDKChildAgentLoop(
                registry=self.registry,
                run_paths=run_paths,
                target=self.state.target,
                provider=str(getattr(worker_endpoint, "provider", "") or "openai"),
                model=str(getattr(worker_endpoint, "model", "") or "") or None,
                context_window=getattr(worker_endpoint, "context_window", None),
                background_workers=_env_flag("VXIS_SDK_BACKGROUND_WORKERS"),
                background_worker_concurrency=max(1, background_worker_concurrency),
            )
            executor = self._sdk_agent_loop.run_turn
        if callable(set_persistence_path) and agent_graph_snapshot_path:
            set_persistence_path(agent_graph_snapshot_path)
        if callable(set_executor):
            set_executor(executor)
        set_target_kind = getattr(tool, "set_target_kind", None)
        if callable(set_target_kind):
            set_target_kind(self._target_kind)
        set_worker_model = getattr(tool, "set_worker_model", None)
        config = getattr(getattr(self, "brain", None), "_hybrid_model_config", None)
        worker_endpoint = getattr(config, "worker", None)
        if callable(set_worker_model) and worker_endpoint is not None:
            set_worker_model(
                str(getattr(worker_endpoint, "provider", "") or ""),
                str(getattr(worker_endpoint, "model", "") or ""),
            )

    @classmethod
    def _infer_branch_role(
        cls,
        *,
        vector_id: str,
        title: str = "",
        objective: str = "",
        source_finding_id: str = "",
        crown_jewel: str = "",
    ) -> str:
        return infer_branch_role(
            vector_id=vector_id,
            title=title,
            objective=objective,
            source_finding_id=source_finding_id,
            crown_jewel=crown_jewel,
        )

    @classmethod
    def _infer_branch_phase(
        cls,
        *,
        role: str,
        vector_id: str,
        title: str = "",
        objective: str = "",
        next_step: str = "",
        crown_jewel: str = "",
    ) -> str:
        return infer_branch_phase(
            role=role,
            vector_id=vector_id,
            title=title,
            objective=objective,
            next_step=next_step,
            crown_jewel=crown_jewel,
        )

    @classmethod
    def _advance_post_exploit_phase(
        cls,
        phase: str,
        name: str,
        args: dict[str, Any] | Any,
    ) -> str:
        return advance_post_exploit_phase(phase, name, args)

    @staticmethod
    def _action_capability(name: str, args: dict[str, Any] | Any) -> str:
        return action_capability(name, args)

    @staticmethod
    def _normalize_tool_args(name: str, args: dict[str, Any] | Any) -> dict[str, Any] | Any:
        if not isinstance(args, dict):
            return args
        normalized = dict(args)
        if name == "shell_exec" and not normalized.get("command") and normalized.get("cmd"):
            normalized["command"] = normalized["cmd"]
        if (
            name == "agent_graph"
            and str(normalized.get("action") or "").strip().lower() == "create"
        ):
            role = str(normalized.get("role") or "recon_worker").strip().lower() or "recon_worker"
            task = str(normalized.get("task") or normalized.get("message") or "").strip()
            declared_skills = normalized.get("skills")
            skills = (
                [str(item).strip() for item in declared_skills if str(item).strip()]
                if isinstance(declared_skills, list)
                else []
            )
            if task:
                normalized.setdefault("objective", task[:160])
            if not normalized.get("expected_artifact"):
                if role == "recon_worker":
                    normalized["expected_artifact"] = (
                        "surface map with concrete routes, auth boundaries, or parameter shapes"
                    )
                elif role == "post_exploit_worker":
                    normalized["expected_artifact"] = (
                        "session, privilege, or data-access transcript tied to crown-jewel impact"
                    )
                elif skills:
                    normalized["expected_artifact"] = (
                        f"raw proof artifact via {skills[0]}: request/response transcript, control pair, or exploit delta"
                    )
                else:
                    normalized["expected_artifact"] = (
                        "raw proof artifact: transcript, control pair, or concrete blocker"
                    )
            normalized.setdefault(
                "stop_condition",
                "stop after one bounded proof step yields concrete evidence or a blocker",
            )
            normalized.setdefault(
                "escalation_trigger",
                "escalate after ambiguous evidence, blocked execution, or a positive result that needs pivot planning",
            )
        return normalized

    @classmethod
    def _role_allows_action(cls, role: str, name: str, args: dict[str, Any] | Any) -> bool:
        allowed = cls._ROLE_ALLOWED_CAPABILITIES.get(role or "recon_worker", set())
        if not allowed:
            return True
        return cls._action_capability(name, args) in allowed

    @classmethod
    def _phase_allows_action(
        cls, branch: BranchState, name: str, args: dict[str, Any] | Any
    ) -> bool:
        if branch.role != "post_exploit_worker":
            return True
        allowed = cls._POST_EXPLOIT_PHASE_ALLOWED_CAPABILITIES.get(
            branch.phase or "chain_closure", set()
        )
        if not allowed:
            return True
        return cls._action_capability(name, args) in allowed

    def _seed_vector_candidates(self) -> None:
        """Seed the evergreen candidates the loop must exhaust for the surface."""
        try:
            from vxis.interaction.surface import TargetKind as _TK
        except Exception:
            _TK = None

        if _TK is not None and self._target_kind == _TK.DESKTOP:
            seeds = [
                ("desktop:local-storage-secrets", "DESK-LSS-001", "Local storage secrets", 90),
                ("desktop:signature-audit", "DESK-SIG-001", "Code signature trust boundary", 80),
                ("desktop:dylib-hijack", "DESK-DYL-001", "Dylib hijack surface", 80),
                ("desktop:ipc-injection", "DESK-IPC-001", "IPC injection surface", 70),
            ]
        else:
            seeds = [
                ("web:auth-bypass", "WEB-AUTH-001", "Authentication bypass or weak login", 95),
                ("web:sqli", "WEB-SQLI-001", "SQL injection toward DB/admin data", 95),
                ("web:idor", "WEB-AC-001", "IDOR or broken access control", 90),
                ("web:sensitive-files", "WEB-MISCONF-001", "Sensitive files or exposed config", 85),
                ("web:dir-bruteforce", "WEB-INFRA-001", "Hidden routes/directories", 75),
                ("web:xss", "WEB-XSS-001", "XSS toward session theft", 70),
                ("web:cve-scan", "WEB-INFRA-002", "Known CVE/template scan", 65),
                ("web:ssrf", "WEB-SSRF-001", "SSRF/internal reachability", 60),
            ]

        for cid, vid, title, priority in seeds:
            self.state.ensure_vector_candidate(
                cid,
                vid,
                title,
                priority=priority,
                evidence="seeded from target surface",
            )

    def _build_scan_dashboard(self) -> str:
        return build_scan_dashboard(self)

    async def _director_decide(self) -> tuple[str, dict[str, Any]] | None:
        """Strategic Director: stronger model decides the EXACT next tool call.

        Called every critic_interval iterations. Unlike the old critic (which
        gave prose advice Brain ignored), the director outputs executable JSON
        that the scan loop dispatches directly. This is the hybrid pattern:
        gpt-5.4 full for strategy, gpt-5.4-mini for routine execution.

        Returns (tool_name, args) or None if unavailable.
        """
        import asyncio
        import json as _jd

        if self.brain is None or not hasattr(self.brain, "_call_llm_with_fallback"):
            return None
        try:
            from vxis.agent.tools.finding_tools import _get_findings

            current_findings = _get_findings()
        except Exception:
            current_findings = []

        # Build recent action summary
        recent: list[str] = []
        for m in self.state.messages[-20:]:
            c = m.get("content")
            if isinstance(c, dict):
                name = c.get("name", "?")
                summary = (c.get("result") or {}).get("summary", "")[:100]
                recent.append(f"  {name}: {summary}")

        findings_summary = (
            "\n".join(
                f"  [{f['severity']}] {f['finding_type']}: {f.get('title', '')[:80]}"
                for f in current_findings[:10]
            )
            or "  (none yet)"
        )

        # Build vector status from dashboard
        vector_status = self._build_scan_dashboard()

        prompt = DIRECTOR_PROMPT_TEMPLATE.format(
            target=self.state.target,
            iteration=self.state.iteration,
            max_iters=self.state.max_iters,
            finding_count=len(current_findings),
            vector_status=vector_status,
            recent_actions="\n".join(recent[-10:]) or "  (no actions)",
            findings_list=findings_summary,
        )

        # Use gpt-5.4 full for strategic decision
        import os

        orig_model = getattr(self.brain, "_model", None)
        use_stronger = False
        if (
            getattr(self.brain, "_provider", None) == "openai"
            and os.environ.get("OPENAI_API_KEY")
            and orig_model
            and "mini" in str(orig_model)
        ):
            self.brain._model = "gpt-5.4"
            use_stronger = True

        try:
            response = await asyncio.to_thread(
                self.brain._call_llm_with_fallback,
                'Output ONLY a JSON object: {"tool": "...", "args": {...}}. No prose.',
                prompt,
            )
        except Exception as e:
            logger.warning("director_decide failed: %s", e)
            return None
        finally:
            if use_stronger and orig_model is not None:
                self.brain._model = orig_model

        if not response:
            return None

        # Parse the JSON tool call
        try:
            # Try to extract JSON from response
            text = response.strip()
            # Handle markdown fences
            if "```" in text:
                import re

                m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
                if m:
                    text = m.group(1)
            data = _jd.loads(text)
            tool = str(data.get("tool", ""))
            args = data.get("args", {})
            if tool and tool in self.registry.list_tools():
                logger.info("director: decided %s(%s)", tool, str(args)[:100])
                return (tool, args if isinstance(args, dict) else {})
        except Exception:
            logger.debug("director: failed to parse response: %s", response[:200])
        return None
