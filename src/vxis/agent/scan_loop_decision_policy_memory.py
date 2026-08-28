from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from vxis.agent.tools.memory_tools import _evidence_fingerprint

_REFUTATION_TTL = timedelta(days=30)


class ScanLoopDecisionPolicyMemoryMixin:
    def _memory_profile(self) -> dict[str, Any]:
        profile = getattr(self, "_target_memory_profile", None)
        return profile if isinstance(profile, dict) else {}

    @staticmethod
    def _refuted_memory_is_current(item: dict[str, Any], args: dict[str, Any]) -> bool:
        try:
            last_seen = datetime.fromisoformat(
                str(item.get("last_seen", "")).replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            return False
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - last_seen > _REFUTATION_TTL:
            return False
        current_fingerprint = _evidence_fingerprint(args)
        previous_fingerprint = str(item.get("evidence_fingerprint", ""))
        return not current_fingerprint or current_fingerprint == previous_fingerprint

    def _matches_refuted_memory_pattern(self, args: dict[str, Any]) -> dict[str, Any] | None:
        profile = self._memory_profile()
        refuted = list(profile.get("refuted_patterns") or [])
        if not refuted:
            return None
        ftype = str(args.get("finding_type", "")).lower().strip()
        component = str(args.get("affected_component", "")).strip().lower()
        for item in refuted:
            if not isinstance(item, dict):
                continue
            mem_type = str(item.get("finding_type", "")).lower().strip()
            mem_component = str(item.get("affected_component", "")).strip().lower()
            if not mem_type or not mem_component:
                continue
            if (
                mem_type == ftype
                and mem_component == component
                and self._refuted_memory_is_current(item, args)
            ):
                return item
        return None

    def _memory_action_components(self, name: str, args: dict[str, Any] | Any) -> list[str]:
        if not isinstance(args, dict):
            return []
        components: list[str] = []
        if name == "report_finding":
            component = str(args.get("affected_component", "")).strip().lower()
            if component:
                components.append(component)
        elif name == "run_skill":
            target_url = str(args.get("target_url", "")).strip().lower()
            if target_url:
                components.append(target_url)
            params = args.get("params") or {}
            if isinstance(params, dict):
                for key in ("url", "url_pattern", "path", "endpoint"):
                    value = str(params.get(key, "")).strip().lower()
                    if value:
                        components.append(value)
        else:
            for key in ("url", "target_url", "path", "endpoint"):
                value = str(args.get(key, "")).strip().lower()
                if value:
                    components.append(value)
        deduped: list[str] = []
        for value in components:
            if value and value not in deduped:
                deduped.append(value)
        return deduped

    def _memory_action_finding_types(self, name: str, args: dict[str, Any] | Any) -> list[str]:
        if not isinstance(args, dict):
            return []
        if name == "report_finding":
            value = str(args.get("finding_type", "")).strip().lower()
            return [value] if value else []
        if name != "run_skill":
            return []
        skill = str(args.get("skill", "")).strip().lower()
        skill_map = {
            "enumerate_endpoints": ["error_oracle"],
            "test_sensitive_files": ["information_disclosure"],
            "test_injection": ["sql_injection", "xss_reflected", "ssti", "nosql", "error_oracle"],
            "test_xss": ["xss_reflected"],
            "test_ssrf": ["ssrf"],
            "attempt_auth": ["weak_auth", "auth_bypass"],
            "test_idor": ["idor", "broken_access_control"],
            "post_auth_enum": ["information_disclosure", "broken_access_control"],
            "test_auth_deep": ["weak_auth", "auth_bypass"],
            "test_api_security": ["mass_assignment", "weak_auth"],
            "test_misconfig": ["information_disclosure", "error_oracle"],
        }
        return list(skill_map.get(skill, []))

    def _matches_refuted_memory_action(
        self, name: str, args: dict[str, Any] | Any
    ) -> dict[str, Any] | None:
        profile = self._memory_profile()
        refuted = list(profile.get("refuted_patterns") or [])
        if not refuted:
            return None
        action_types = self._memory_action_finding_types(name, args)
        action_components = self._memory_action_components(name, args)
        if not action_types or not action_components:
            return None
        for item in refuted:
            if not isinstance(item, dict):
                continue
            mem_type = str(item.get("finding_type", "")).strip().lower()
            mem_component = str(item.get("affected_component", "")).strip().lower()
            if not mem_type or not mem_component or mem_type not in action_types:
                continue
            if not self._refuted_memory_is_current(item, args if isinstance(args, dict) else {}):
                continue
            if any(
                mem_component in component or component in mem_component
                for component in action_components
            ):
                return item
        return None

    def _matching_successful_memory_tactic(
        self, name: str, args: dict[str, Any] | Any
    ) -> dict[str, Any] | None:
        profile = self._memory_profile()
        tactics = list(profile.get("successful_tactics") or [])
        if not tactics:
            return None
        action_types = self._memory_action_finding_types(name, args)
        action_components = self._memory_action_components(name, args)
        if not action_types and not action_components:
            return None
        for item in tactics:
            if not isinstance(item, dict):
                continue
            mem_type = str(item.get("finding_type", "")).strip().lower()
            mem_component = str(item.get("affected_component", "")).strip().lower()
            if action_types and mem_type and mem_type not in action_types:
                continue
            if action_components and mem_component:
                if not any(
                    mem_component in component or component in mem_component
                    for component in action_components
                ):
                    continue
            return item
        return None

    def _should_pressure_memory_revalidation(
        self,
        name: str,
        args: dict[str, Any] | Any,
        matched_branch_ids: list[str],
    ) -> bool:
        if self.state.iteration > 6:
            return False
        profile = self._memory_profile()
        if not profile.get("target_known"):
            return False
        if not (profile.get("known_findings") or profile.get("branch_leads")):
            return False
        if any(
            str(branch_id).startswith("carry:") or str(branch_id).startswith("memory:")
            for branch_id in matched_branch_ids
        ):
            return False
        if name in {"finish_scan", "link_chain", "query_scan_memory"}:
            return False
        if self._action_capability(name, args) in {"report", "review", "chain"}:
            return False
        if self._matching_successful_memory_tactic(name, args) is not None:
            return False
        return True
