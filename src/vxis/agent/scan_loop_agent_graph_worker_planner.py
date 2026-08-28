from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from vxis.agent.brain_prompts import _parse_llm_json
from vxis.agent.context_budget import (
    compact_context_value,
    estimate_context_tokens,
    fit_lines_to_token_budget,
    resolve_context_budget,
    trim_text_chars,
)

_WORKER_PLANNER_REPAIRABLE_FAILURES = {
    "invalid_json",
    "invalid_json_shape",
    "missing_tool",
    "disallowed_tool",
    "tool_unavailable",
    "missing_skill",
    "invalid_skill",
    "disallowed_skill",
    "invalid_args",
    "role_disallowed",
}

_WORKER_PLANNER_UNAVAILABLE_REASONS = {
    "worker_llm_not_callable",
    "worker_llm_call_failed",
    "worker_llm_empty_response",
}


class ScanLoopAgentGraphWorkerPlannerMixin:
    async def _agent_graph_worker_llm_action(
        self,
        agent: dict[str, Any],
        instruction: str,
        *,
        allowed_child_tools: set[str],
    ) -> dict[str, Any]:
        brain = getattr(self, "brain", None)
        endpoint = self._agent_graph_worker_endpoint()
        can_call_worker = callable(getattr(brain, "_call_llm_direct", None)) or callable(
            getattr(brain, "_call_openai_compatible", None)
        )
        if brain is None or endpoint is None:
            return self._agent_graph_worker_planner_failure("worker_planner_not_configured")
        if not can_call_worker:
            return self._agent_graph_worker_planner_failure("worker_llm_not_callable")

        system_prompt, user_prompt, budget = self._agent_graph_worker_planner_prompts(
            agent,
            instruction,
            allowed_child_tools=allowed_child_tools,
        )
        prompt_tokens = estimate_context_tokens(system_prompt) + estimate_context_tokens(
            user_prompt
        )
        if prompt_tokens > budget.max_prompt_tokens:
            user_prompt = trim_text_chars(
                user_prompt,
                max(900, int(budget.max_prompt_tokens * 2.2)),
            )
            prompt_tokens = estimate_context_tokens(system_prompt) + estimate_context_tokens(
                user_prompt
            )
        compacted = prompt_tokens > budget.max_prompt_tokens

        semaphore = self._agent_graph_worker_llm_semaphore()
        provider = str(getattr(endpoint, "provider", "") or "")
        model = str(getattr(endpoint, "model", "") or "")
        try:
            async with semaphore:
                loop = asyncio.get_running_loop()
                text = await loop.run_in_executor(
                    None,
                    lambda: self._agent_graph_call_worker_llm_direct(
                        brain,
                        system_prompt,
                        user_prompt,
                        provider=provider,
                        model=model,
                        base_url=str(getattr(endpoint, "base_url", "") or ""),
                    ),
                )
        except Exception as exc:
            return self._agent_graph_worker_planner_failure(
                "worker_llm_call_failed",
                detail=str(exc)[:180],
                provider=provider,
                model=model,
                prompt_tokens=prompt_tokens,
            )
        if not text:
            return self._agent_graph_worker_planner_failure(
                "worker_llm_empty_response",
                provider=provider,
                model=model,
                prompt_tokens=prompt_tokens,
            )

        planned = self._agent_graph_parse_worker_llm_action(
            str(text),
            agent=agent,
            instruction=instruction,
            allowed_child_tools=allowed_child_tools,
        )
        if self._agent_graph_worker_planner_should_repair(planned):
            planned = await self._agent_graph_repair_worker_llm_action(
                brain,
                agent,
                instruction,
                allowed_child_tools=allowed_child_tools,
                initial_failure=planned,
                previous_response=str(text),
                provider=provider,
                model=model,
                base_url=str(getattr(endpoint, "base_url", "") or ""),
            )
        planned.update({"provider": provider, "model": model, "prompt_tokens": prompt_tokens})
        if compacted:
            planned["prompt_compacted"] = True
        return planned

    async def _agent_graph_repair_worker_llm_action(
        self,
        brain: Any,
        agent: dict[str, Any],
        instruction: str,
        *,
        allowed_child_tools: set[str],
        initial_failure: dict[str, Any],
        previous_response: str,
        provider: str,
        model: str,
        base_url: str,
    ) -> dict[str, Any]:
        system_prompt, user_prompt, repair_tokens = self._agent_graph_worker_repair_prompts(
            agent,
            instruction,
            allowed_child_tools=allowed_child_tools,
            initial_failure=initial_failure,
            previous_response=previous_response,
        )
        initial_reason = str(
            initial_failure.get("failure_reason") or "unknown_worker_planner_failure"
        )
        try:
            async with self._agent_graph_worker_llm_semaphore():
                loop = asyncio.get_running_loop()
                text = await loop.run_in_executor(
                    None,
                    lambda: self._agent_graph_call_worker_llm_direct(
                        brain,
                        system_prompt,
                        user_prompt,
                        provider=provider,
                        model=model,
                        base_url=base_url,
                    ),
                )
        except Exception as exc:
            repaired = self._agent_graph_worker_planner_failure(
                "worker_llm_call_failed",
                detail=str(exc)[:180],
                provider=provider,
                model=model,
                prompt_tokens=repair_tokens,
            )
            return self._agent_graph_worker_planner_repair_failure(
                initial_failure,
                repaired,
                repair_tokens=repair_tokens,
            )
        if not text:
            repaired = self._agent_graph_worker_planner_failure(
                "worker_llm_empty_response",
                provider=provider,
                model=model,
                prompt_tokens=repair_tokens,
            )
            return self._agent_graph_worker_planner_repair_failure(
                initial_failure,
                repaired,
                repair_tokens=repair_tokens,
            )

        repaired = self._agent_graph_parse_worker_llm_action(
            str(text),
            agent=agent,
            instruction=instruction,
            allowed_child_tools=allowed_child_tools,
        )
        repaired["repair_attempted"] = True
        repaired["repair_prompt_tokens"] = repair_tokens
        repaired["initial_failure_reason"] = initial_reason
        if repaired.get("ok"):
            repaired["repair_succeeded"] = True
            return repaired
        return self._agent_graph_worker_planner_repair_failure(
            initial_failure,
            repaired,
            repair_tokens=repair_tokens,
        )

    @staticmethod
    def _agent_graph_worker_planner_should_repair(planned: dict[str, Any] | None) -> bool:
        if not planned or planned.get("ok"):
            return False
        return str(planned.get("failure_reason") or "") in _WORKER_PLANNER_REPAIRABLE_FAILURES

    @staticmethod
    def _agent_graph_worker_planner_repair_failure(
        initial_failure: dict[str, Any],
        repaired_failure: dict[str, Any],
        *,
        repair_tokens: int,
    ) -> dict[str, Any]:
        initial_reason = str(
            initial_failure.get("failure_reason") or "unknown_worker_planner_failure"
        )
        repair_reason = str(
            repaired_failure.get("failure_reason") or "unknown_worker_planner_failure"
        )
        detail = str(repaired_failure.get("detail") or initial_failure.get("detail") or "")
        failure = dict(repaired_failure)
        failure.update(
            {
                "ok": False,
                "failure_reason": repair_reason,
                "detail": detail[:240],
                "repair_attempted": True,
                "repair_succeeded": False,
                "initial_failure_reason": initial_reason,
                "repair_failure_reason": repair_reason,
                "repair_prompt_tokens": int(repair_tokens or 0),
            }
        )
        return failure

    @staticmethod
    def _agent_graph_worker_planner_failure(
        reason: str,
        *,
        detail: str = "",
        provider: str = "",
        model: str = "",
        prompt_tokens: int = 0,
    ) -> dict[str, Any]:
        return {
            "ok": False,
            "failure_reason": str(reason or "unknown_worker_planner_failure"),
            "detail": str(detail or "")[:240],
            "provider": provider,
            "model": model,
            "prompt_tokens": int(prompt_tokens or 0),
        }

    def _agent_graph_worker_planner_success_meta(
        self,
        planned: dict[str, Any],
    ) -> dict[str, Any]:
        self._agent_graph_record_worker_planner_metric(planned, succeeded=True)
        meta = {
            "source": "worker_llm",
            "provider": planned.get("provider", ""),
            "model": planned.get("model", ""),
            "evidence_intent": planned.get("evidence_intent", ""),
            "prompt_tokens": planned.get("prompt_tokens", 0),
        }
        self._agent_graph_apply_worker_planner_repair_meta(meta, planned)
        return meta

    def _agent_graph_worker_planner_fallback_meta(
        self,
        planned: dict[str, Any] | None,
    ) -> dict[str, Any]:
        failure = planned or self._agent_graph_worker_planner_failure(
            "worker_planner_not_configured"
        )
        reason = str(failure.get("failure_reason") or "unknown_worker_planner_failure")
        if reason != "worker_planner_not_configured":
            self._agent_graph_record_worker_planner_metric(failure, succeeded=False)
        counts = getattr(self, "_agent_graph_worker_planner_fallback_counts", None)
        if not isinstance(counts, dict):
            counts = {}
            self._agent_graph_worker_planner_fallback_counts = counts
        counts[reason] = int(counts.get(reason, 0)) + 1
        meta = {
            "source": "deterministic_fallback",
            "fallback_reason": reason,
            "fallback_count": counts[reason],
            "provider": str(failure.get("provider") or ""),
            "model": str(failure.get("model") or ""),
            "prompt_tokens": int(failure.get("prompt_tokens") or 0),
        }
        detail = str(failure.get("detail") or "").strip()
        if detail:
            meta["detail"] = detail[:180]
        self._agent_graph_apply_worker_planner_repair_meta(meta, failure)
        if reason in _WORKER_PLANNER_UNAVAILABLE_REASONS and counts[reason] >= 3:
            meta["health"] = "local_worker_unavailable"
            note = f"agent_graph local worker unavailable: {reason} x{counts[reason]}"
            marker = f"agent_graph local worker unavailable: {reason}"
            if not any(str(existing).startswith(marker) for existing in self.state.shared_notes):
                self.state.add_shared_note(note)
        return meta

    def _agent_graph_record_worker_planner_metric(
        self,
        planned: dict[str, Any],
        *,
        succeeded: bool,
    ) -> None:
        metrics = getattr(self, "_agent_graph_worker_planner_metrics", None)
        if not isinstance(metrics, dict):
            metrics = {}
            self._agent_graph_worker_planner_metrics = metrics
        for key in (
            "attempts",
            "successes",
            "fallbacks",
            "repairs",
            "repair_successes",
            "repair_failures",
            "unavailable",
        ):
            metrics[key] = int(metrics.get(key) or 0)
        metrics["attempts"] += 1
        if succeeded:
            metrics["successes"] += 1
        else:
            metrics["fallbacks"] += 1
        if planned.get("repair_attempted"):
            metrics["repairs"] += 1
            if planned.get("repair_succeeded"):
                metrics["repair_successes"] += 1
            else:
                metrics["repair_failures"] += 1
        reason = str(planned.get("failure_reason") or planned.get("fallback_reason") or "")
        if reason in _WORKER_PLANNER_UNAVAILABLE_REASONS:
            metrics["unavailable"] += 1

    @staticmethod
    def _agent_graph_apply_worker_planner_repair_meta(
        meta: dict[str, Any],
        planned: dict[str, Any],
    ) -> None:
        if not planned.get("repair_attempted"):
            return
        meta["repair_attempted"] = True
        meta["repair_succeeded"] = bool(planned.get("repair_succeeded"))
        initial_reason = str(planned.get("initial_failure_reason") or "").strip()
        repair_reason = str(planned.get("repair_failure_reason") or "").strip()
        repair_tokens = int(planned.get("repair_prompt_tokens") or 0)
        if initial_reason:
            meta["initial_failure_reason"] = initial_reason
        if repair_reason:
            meta["repair_failure_reason"] = repair_reason
        if repair_tokens:
            meta["repair_prompt_tokens"] = repair_tokens

    @staticmethod
    def _agent_graph_call_worker_llm_direct(
        brain: Any,
        system_prompt: str,
        user_prompt: str,
        *,
        provider: str,
        model: str,
        base_url: str = "",
    ) -> str | None:
        if base_url and provider in {"llamacpp", "ollama"}:
            call_compatible = getattr(brain, "_call_openai_compatible", None)
            if callable(call_compatible):
                return call_compatible(
                    system_prompt,
                    user_prompt,
                    provider,
                    model,
                    base_url=base_url,
                )
        call_direct = getattr(brain, "_call_llm_direct", None)
        if not callable(call_direct):
            return None
        return call_direct(
            system_prompt,
            user_prompt,
            provider=provider,
            model=model,
        )

    def _agent_graph_worker_endpoint(self) -> Any | None:
        config = getattr(getattr(self, "brain", None), "_hybrid_model_config", None)
        if config is None:
            return None
        try:
            return config.for_role("worker")
        except Exception:
            return getattr(config, "worker", None)

    def _agent_graph_worker_context_budget(self) -> Any:
        endpoint = self._agent_graph_worker_endpoint()
        provider = str(getattr(endpoint, "provider", "") or "llamacpp")
        model = str(getattr(endpoint, "model", "") or "local")
        return resolve_context_budget("worker", provider=provider, model=model)

    def _agent_graph_worker_llm_semaphore(self) -> asyncio.Semaphore:
        raw_limit = os.environ.get("VXIS_LOCAL_WORKER_CONCURRENCY", "1").strip()
        try:
            limit = max(1, int(raw_limit))
        except ValueError:
            limit = 1
        current_limit = getattr(self, "_agent_graph_worker_llm_semaphore_limit", None)
        semaphore = getattr(self, "_agent_graph_worker_llm_semaphore_obj", None)
        if semaphore is None or current_limit != limit:
            semaphore = asyncio.Semaphore(limit)
            self._agent_graph_worker_llm_semaphore_obj = semaphore
            self._agent_graph_worker_llm_semaphore_limit = limit
        return semaphore

    def _agent_graph_worker_planner_prompts(
        self,
        agent: dict[str, Any],
        instruction: str,
        *,
        allowed_child_tools: set[str],
    ) -> tuple[str, str, Any]:
        budget = self._agent_graph_worker_context_budget()
        system_prompt = (
            "You are a bounded VXIS worker planner. Return JSON only. "
            'Schema: {"tool":"run_skill|http_request|nmap_scan|browser_navigate|browser_analyze_dom",'
            '"args":{},"evidence_intent":"short proof goal"}. '
            "Choose exactly one allowed tool. Do not report findings or finish scans. "
            "Positive evidence must preserve EvidenceArtifact fields: "
            "claim,target,control,payload,observed_delta,repro_steps."
        )
        envelope = (
            agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        )
        result_package = (
            agent.get("result_package") if isinstance(agent.get("result_package"), dict) else {}
        )
        critical_lines = [
            f"target={self.state.target}",
            f"agent_id={str(agent.get('id') or '')}",
            f"role={str(agent.get('role') or 'recon_worker')}",
            f"allowed_tools={','.join(sorted(allowed_child_tools))}",
            f"allowed_skills={','.join(str(skill) for skill in list(agent.get('skills') or [])[:6])}",
            'run_skill_args={"skill":"one allowed skill","target_url":"target","params":{}}',
            'http_request_args={"method":"GET|POST|HEAD","url":"target/path"}',
            'browser_navigate_args={"url":"target/path"}',
            "browser_analyze_dom_args={}",
            f"task={trim_text_chars(agent.get('task'), budget.max_message_chars)}",
            f"objective={trim_text_chars(envelope.get('objective'), budget.max_message_chars)}",
            f"expected_artifact={trim_text_chars(envelope.get('expected_artifact'), budget.max_message_chars)}",
            f"stop_condition={trim_text_chars(envelope.get('stop_condition'), budget.max_message_chars)}",
            f"escalation_trigger={trim_text_chars(envelope.get('escalation_trigger'), budget.max_message_chars)}",
        ]
        if instruction:
            critical_lines.append(
                f"director_instruction={trim_text_chars(instruction, budget.max_message_chars)}"
            )

        history_lines = [
            "skill_context=" + trim_text_chars(agent.get("skill_context"), budget.max_skill_chars),
            "result_package="
            + json.dumps(
                compact_context_value(result_package, max_chars=budget.max_execution_chars),
                ensure_ascii=False,
                sort_keys=True,
            ),
        ]
        messages = agent.get("messages") if isinstance(agent.get("messages"), list) else []
        for message in messages[-budget.max_agent_messages :]:
            history_lines.append(
                "message="
                + json.dumps(
                    compact_context_value(message, max_chars=budget.max_message_chars),
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        executions = agent.get("executions") if isinstance(agent.get("executions"), list) else []
        for execution in executions[-budget.max_agent_executions :]:
            history_lines.append(
                "execution="
                + json.dumps(
                    compact_context_value(execution, max_chars=budget.max_execution_chars),
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )

        static_tokens = estimate_context_tokens(system_prompt) + sum(
            estimate_context_tokens(line) for line in critical_lines
        )
        history_budget = max(160, budget.max_prompt_tokens - static_tokens - 96)
        fitted_history = fit_lines_to_token_budget(
            history_lines,
            history_budget,
            prefer_recent=True,
            marker="WORKER-CONTEXT COMPACTION",
        )
        user_prompt = "\n".join(critical_lines + fitted_history)
        return system_prompt, user_prompt, budget

    def _agent_graph_worker_repair_prompts(
        self,
        agent: dict[str, Any],
        instruction: str,
        *,
        allowed_child_tools: set[str],
        initial_failure: dict[str, Any],
        previous_response: str,
    ) -> tuple[str, str, int]:
        budget = self._agent_graph_worker_context_budget()
        envelope = (
            agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        )
        system_prompt = (
            "Repair VXIS worker planner output. JSON only. "
            'Schema: {"tool":"allowed_tool","args":{},"evidence_intent":"short proof goal"}. '
            "No prose. One bounded action."
        )
        user_lines = [
            f"failure_reason={str(initial_failure.get('failure_reason') or '')}",
            f"failure_detail={trim_text_chars(initial_failure.get('detail'), 180)}",
            f"target={self.state.target}",
            f"role={str(agent.get('role') or 'recon_worker')}",
            f"allowed_tools={','.join(sorted(allowed_child_tools))}",
            f"allowed_skills={','.join(str(skill) for skill in list(agent.get('skills') or [])[:6])}",
            'run_skill_args={"skill":"one allowed skill","target_url":"target","params":{}}',
            "EvidenceArtifact_fields=claim,target,control,payload,observed_delta,repro_steps",
            f"task={trim_text_chars(agent.get('task'), 420)}",
            f"objective={trim_text_chars(envelope.get('objective'), 360)}",
            f"expected_artifact={trim_text_chars(envelope.get('expected_artifact'), 240)}",
        ]
        if instruction:
            user_lines.append(f"director_instruction={trim_text_chars(instruction, 280)}")
        user_lines.append(f"bad_output={trim_text_chars(previous_response, 500)}")
        user_lines.append("return_valid_json_now=true")
        user_prompt = "\n".join(user_lines)
        repair_tokens = estimate_context_tokens(system_prompt) + estimate_context_tokens(
            user_prompt
        )
        if repair_tokens > budget.max_prompt_tokens:
            user_lines[-2] = f"bad_output={trim_text_chars(previous_response, 240)}"
            user_prompt = "\n".join(user_lines)
            repair_tokens = estimate_context_tokens(system_prompt) + estimate_context_tokens(
                user_prompt
            )
        return system_prompt, user_prompt, repair_tokens

    def _agent_graph_parse_worker_llm_action(
        self,
        text: str,
        *,
        agent: dict[str, Any],
        instruction: str,
        allowed_child_tools: set[str],
    ) -> dict[str, Any]:
        try:
            parsed = _parse_llm_json(text)
        except Exception as exc:
            return self._agent_graph_worker_planner_failure(
                "invalid_json",
                detail=str(exc)[:180],
            )
        item: Any = parsed
        if isinstance(item, list):
            item = item[0] if item else {}
        if isinstance(item, dict) and isinstance(item.get("actions"), list):
            item = item["actions"][0] if item["actions"] else {}
        if not isinstance(item, dict):
            return self._agent_graph_worker_planner_failure("invalid_json_shape")
        tool_name = str(item.get("tool") or "").strip()
        raw_args = item.get("args") if isinstance(item.get("args"), dict) else {}
        if not tool_name:
            return self._agent_graph_worker_planner_failure("missing_tool")
        if tool_name not in allowed_child_tools:
            return self._agent_graph_worker_planner_failure(
                "disallowed_tool",
                detail=tool_name,
            )
        if not self.registry.has_tool(tool_name):
            return self._agent_graph_worker_planner_failure(
                "tool_unavailable",
                detail=tool_name,
            )
        normalized = self._agent_graph_normalize_worker_tool_args(
            tool_name,
            raw_args,
            agent=agent,
            instruction=instruction,
        )
        if not normalized.get("ok"):
            return self._agent_graph_worker_planner_failure(
                str(normalized.get("failure_reason") or "invalid_args"),
                detail=str(normalized.get("detail") or "")[:180],
            )
        tool_args = normalized["args"]
        role = str(agent.get("role") or "recon_worker").strip() or "recon_worker"
        if not self._role_allows_action(role, tool_name, tool_args):
            return self._agent_graph_worker_planner_failure(
                "role_disallowed",
                detail=f"{role}:{tool_name}",
            )
        return {
            "ok": True,
            "tool": tool_name,
            "args": tool_args,
            "evidence_intent": trim_text_chars(item.get("evidence_intent") or "", 220),
        }

    def _agent_graph_normalize_worker_tool_args(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        agent: dict[str, Any],
        instruction: str,
    ) -> dict[str, Any]:
        if tool_name == "run_skill":
            raw_skill = str(args.get("skill") or args.get("_skill_override") or "").strip()
            if not raw_skill:
                return {"ok": False, "failure_reason": "missing_skill"}
            skill = self._pivoted_skill_name(raw_skill)
            if not skill:
                return {"ok": False, "failure_reason": "invalid_skill", "detail": raw_skill}
            allowed_skills = {
                self._pivoted_skill_name(str(item))
                for item in list(agent.get("skills") or [])
                if self._pivoted_skill_name(str(item))
            }
            if allowed_skills and skill not in allowed_skills:
                return {"ok": False, "failure_reason": "disallowed_skill", "detail": skill}
            hint_blob = " ".join(
                str(value or "")
                for value in (
                    agent.get("role"),
                    agent.get("task"),
                    instruction,
                    args,
                )
            ).lower()
            params = args.get("params") if isinstance(args.get("params"), dict) else {}
            default_params = self._best_skill_params(skill, hint_blob=hint_blob)
            merged_params = {**default_params, **params}
            return {
                "ok": True,
                "args": {
                    "skill": skill,
                    "target_url": str(args.get("target_url") or self.state.target),
                    "params": compact_context_value(merged_params, max_chars=900),
                },
            }
        if tool_name == "http_request":
            method = str(args.get("method") or "GET").strip().upper()
            if method not in {"GET", "POST", "HEAD", "OPTIONS"}:
                return {"ok": False, "failure_reason": "invalid_args", "detail": method}
            out: dict[str, Any] = {
                "method": method,
                "url": str(args.get("url") or self.state.target),
            }
            if isinstance(args.get("headers"), dict):
                out["headers"] = compact_context_value(args["headers"], max_chars=600)
            if "body" in args:
                out["body"] = trim_text_chars(args.get("body"), 1200)
            return {"ok": True, "args": out}
        if tool_name == "nmap_scan":
            out = {"target": str(args.get("target") or self.state.target)}
            for key in ("ports", "scripts"):
                if key in args:
                    out[key] = trim_text_chars(args.get(key), 80)
            if "udp" in args:
                out["udp"] = bool(args.get("udp"))
            if "timing" in args:
                out["timing"] = args.get("timing")
            if "timeout" in args:
                out["timeout"] = args.get("timeout")
            return {"ok": True, "args": out}
        if tool_name == "browser_navigate":
            return {"ok": True, "args": {"url": str(args.get("url") or self.state.target)}}
        if tool_name == "browser_analyze_dom":
            return {
                "ok": True,
                "args": {
                    str(key): compact_context_value(value, max_chars=500)
                    for key, value in args.items()
                    if str(key) in {"selector", "include_text", "limit"}
                },
            }
        return {"ok": False, "failure_reason": "disallowed_tool", "detail": tool_name}

    def _agent_graph_action_from_node(
        self,
        agent: dict[str, Any],
        instruction: str,
    ) -> tuple[str, dict[str, Any]] | None:
        envelope = (
            agent.get("task_envelope") if isinstance(agent.get("task_envelope"), dict) else {}
        )
        blob = " ".join(
            str(value or "")
            for value in (
                agent.get("role"),
                agent.get("task"),
                agent.get("result"),
                " ".join(str(skill) for skill in list(agent.get("skills") or [])),
                str(envelope.get("objective") or ""),
                str(envelope.get("expected_artifact") or ""),
                str(envelope.get("stop_condition") or ""),
                instruction,
            )
        ).lower()
        envelope_allowed = self._agent_graph_envelope_allowed_tools(agent)
        if (
            self.registry.has_tool("nmap_scan")
            and (not envelope_allowed or "nmap_scan" in envelope_allowed)
            and any(
                token in blob
                for token in (
                    "nmap",
                    "open port",
                    "port ",
                    "service",
                    "tcp",
                    "udp",
                    "ssh",
                    "rdp",
                    "redis",
                    "mongodb",
                    "postgres",
                    "mysql",
                    "smb",
                )
            )
        ):
            return ("nmap_scan", self._agent_graph_nmap_args_from_blob(blob))
        if "run_skill" in self.registry.list_tools():
            for raw_skill in list(agent.get("skills") or []):
                skill = self._pivoted_skill_name(str(raw_skill))
                if skill:
                    return (
                        "run_skill",
                        {
                            "skill": skill,
                            "target_url": str(self.state.target),
                            "params": self._best_skill_params(skill, hint_blob=blob),
                        },
                    )
            inferred = (
                ("execute_chain", ("chain", "crown", "post-auth", "post exploit", "post_exploit")),
                ("test_idor", ("idor", "access_control", "broken access", "object")),
                ("test_injection", ("sqli", "sql", "injection", "nosql", "ssti")),
                ("test_xss", ("xss", "script")),
                ("test_ssrf", ("ssrf", "callback", "metadata")),
                ("attempt_auth", ("auth", "login", "credential", "session")),
                ("test_sensitive_files", ("secret", "config", "file", "disclosure", "git")),
                ("enumerate_endpoints", ("route", "endpoint", "surface", "map")),
            )
            for skill_name, tokens in inferred:
                if not any(token in blob for token in tokens):
                    continue
                skill = self._pivoted_skill_name(skill_name)
                if not skill:
                    continue
                return (
                    "run_skill",
                    {
                        "skill": skill,
                        "target_url": str(self.state.target),
                        "params": self._best_skill_params(skill, hint_blob=blob),
                    },
                )

        if "http_request" in self.registry.list_tools():
            return ("http_request", {"method": "GET", "url": str(self.state.target)})
        return None
