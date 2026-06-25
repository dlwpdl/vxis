from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import urlparse

from vxis.agent.scan_loop_policy import (
    _DESKTOP_PIVOT_SKILL_GRAPH,
    _DESKTOP_SKILLS,
    _WEB_PIVOT_SKILL_GRAPH,
    _WEB_VECTOR_FAMILY_RULES,
)
from vxis.agent.scan_loop_state import (
    _TERMINAL_BRANCH_STATUSES,
    BranchState,
    ReviewDecision,
    VectorCandidate,
)


def dag_blocks_finish(state: Any, *, prior_threshold: float = 0.5) -> bool:
    """Return true when the DAG still has high-prior untested work."""
    return bool(dag_finish_blocker_node_ids(state, prior_threshold=prior_threshold))


def dag_finish_blocker_node_ids(state: Any, *, prior_threshold: float = 0.5) -> list[str]:
    dag = getattr(state, "hypothesis_dag", None)
    if dag is None:
        return []
    try:
        nodes = list(dag.top_untested(k=100))
    except Exception:
        return []
    out: list[str] = []
    for node in nodes:
        try:
            prior = float(getattr(node, "prior", 0.0) or 0.0)
        except (TypeError, ValueError):
            prior = 0.0
        if prior >= prior_threshold:
            out.append(str(getattr(node, "node_id", "")))
    return [node_id for node_id in out if node_id]


class ScanLoopDecisionPolicyMixin:
    def _dag_finish_blocking_branches(self) -> list[BranchState]:
        """Return branch side-table rows for high-prior untested DAG nodes."""
        blockers: list[BranchState] = []
        blocker_ids = set(dag_finish_blocker_node_ids(self.state, prior_threshold=0.65))
        for branch in self.state.active_branches():
            if self._should_exhaust_stale_root_branch(branch):
                branch.status = "exhausted"
                branch.last_report = (
                    branch.last_report
                    or "exhausted after linked candidate terminated and no live child pivots remained"
                )[:160]
                continue
            if branch.owner == "agent_graph":
                blockers.append(branch)
                continue
            if self._branch_has_open_crown_goal(branch):
                blockers.append(branch)
                continue
            if branch.id not in blocker_ids and branch.source_candidate_id not in blocker_ids:
                if (
                    branch.owner == "memory"
                    or branch.id.startswith(("carry:", "memory:"))
                ) and not self._branch_has_finish_blocking_yield(branch):
                    branch.status = "exhausted"
                    branch.last_report = (
                        branch.last_report
                        or "exhausted after DAG did not retain this memory branch as high-prior work"
                    )[:160]
                continue
            if not self._branch_has_finish_blocking_yield(branch):
                branch.status = "exhausted"
                branch.last_report = (
                    branch.last_report
                    or "exhausted after low expected yield and no remaining platform-appropriate pivots"
                )[:160]
                continue
            blockers.append(branch)
        return self._dedupe_blocking_campaign_branches(blockers)

    def _dedupe_blocking_campaign_branches(self, blockers: list[BranchState]) -> list[BranchState]:
        deduped: list[BranchState] = []
        seen: set[tuple[str, str]] = set()
        for branch in blockers:
            if branch.source_finding_id:
                key = (branch.source_finding_id, branch.phase or "surface")
                if key in seen:
                    continue
                seen.add(key)
            deduped.append(branch)
        return deduped

    def _has_live_child_branch(self, branch: BranchState) -> bool:
        for child_id in branch.child_ids:
            child = self.state.branches.get(child_id)
            if child is None:
                continue
            if child.status not in _TERMINAL_BRANCH_STATUSES:
                return True
        return False

    def _linked_candidate_for_branch(self, branch: BranchState) -> VectorCandidate | None:
        for candidate_id in (branch.source_candidate_id, branch.id):
            if not candidate_id:
                continue
            candidate = self.state.vector_candidates.get(candidate_id)
            if candidate is not None:
                return candidate
        return None

    def _latest_report_finding_args(self) -> dict[str, Any] | None:
        for message in reversed(self.state.messages):
            if message.get("role") != "tool":
                continue
            content = message.get("content", {})
            if not isinstance(content, dict) or content.get("name") != "report_finding":
                continue
            args = content.get("args", {})
            if isinstance(args, dict):
                return dict(args)
        return None

    def _hydrate_verify_finding_args(self, args: dict[str, Any]) -> dict[str, Any]:
        merged = dict(args or {})
        if all(
            str(merged.get(key, "")).strip()
            for key in ("finding_type", "affected_component", "evidence")
        ):
            return merged
        source: dict[str, Any] | None = None
        latest = self._latest_report_finding_args()
        if latest is not None:
            source = latest
        try:
            from vxis.agent.tools.finding_tools import _get_findings

            findings = list(_get_findings() or [])
        except Exception:
            findings = []
        wanted_type = str(merged.get("finding_type", "")).strip().lower()
        wanted_component = str(merged.get("affected_component", "")).strip()
        wanted_title = str(merged.get("title", "")).strip().lower()
        best_score = -1
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            score = 0
            f_type = str(finding.get("finding_type", "")).strip().lower()
            f_component = str(finding.get("affected_component", "")).strip()
            f_title = str(finding.get("title", "")).strip().lower()
            if wanted_type and wanted_type == f_type:
                score += 5
            if wanted_component and wanted_component == f_component:
                score += 6
            if wanted_title and wanted_title == f_title:
                score += 4
            if wanted_title and wanted_title and wanted_title in f_title:
                score += 2
            if wanted_component and wanted_component and wanted_component in f_component:
                score += 2
            if score > best_score:
                best_score = score
                source = finding
        if source is None:
            return merged
        field_map = {
            "title": "title",
            "severity": "severity",
            "finding_type": "finding_type",
            "affected_component": "affected_component",
            "description": "description",
            "impact": "impact",
            "technical_analysis": "technical_analysis",
            "poc_description": "poc_description",
            "poc_script_code": "poc_script_code",
            "evidence": "evidence",
        }
        for target_key, source_key in field_map.items():
            if (
                not str(merged.get(target_key, "")).strip()
                and str(source.get(source_key, "")).strip()
            ):
                merged[target_key] = source.get(source_key, "")
        return merged

    def _should_exhaust_stale_root_branch(self, branch: BranchState) -> bool:
        if branch.source_finding_id:
            return False
        if branch.owner != "root":
            return False
        if self._has_live_child_branch(branch):
            return False
        candidate = self._linked_candidate_for_branch(branch)
        if candidate is None:
            return False
        if candidate.status not in {"failed", "blocked", "dead", "clean", "found"}:
            return False
        if self._forced_branch_action(branch) is not None:
            return False
        family = self._branch_family(branch)
        if branch.role == "recon_worker" or family in {"infra", "disclosure"}:
            return True
        if branch.attempts >= 2 and candidate.status == "found":
            try:
                from vxis.agent.tools.finding_tools import _canonical_finding_type as _canon_ft
            except Exception:

                def _canon_ft(value: object) -> str:
                    return str(value or "").strip().lower()

            related_types = self._family_related_types(family)
            found_types = {
                _canon_ft(str(item.get("finding_type", "")))
                for item in self.state.findings
                if isinstance(item, dict)
            }
            if related_types and (related_types & found_types):
                return True
        return False

    def _branch_expected_yield_score(self, branch: BranchState) -> int:
        try:
            from vxis.agent.tools.finding_tools import _canonical_finding_type as _canon_ft
        except Exception:

            def _canon_ft(value: object) -> str:
                return str(value or "").strip().lower()

        score = int(branch.priority)
        if branch.source_finding_id:
            score += 10
        if branch.role == "post_exploit_worker":
            score += 8
        if branch.phase in {"data_access", "chain_closure"}:
            score += 5
        score -= max(0, branch.attempts - 1) * 12
        if branch.status == "blocked":
            score -= 18
        if branch.last_tool == "run_skill" and "blocked" in str(branch.last_summary).lower():
            score -= 20
        if branch.blocker:
            score -= 8
        next_action = self._forced_branch_action(branch)
        if next_action is None:
            score -= 28
        else:
            score += 6
        family = self._branch_family(branch)
        related_types = self._family_related_types(family)
        related_skills = self._family_related_skills(family)
        found_types = {
            _canon_ft(str(item.get("finding_type", "")))
            for item in self.state.findings
            if isinstance(item, dict)
        }
        covered_family = bool(related_types & found_types)
        is_memory_branch = branch.owner == "memory" or branch.id.startswith("carry:")
        if covered_family:
            if is_memory_branch:
                score -= 34
                if not branch.source_finding_id:
                    score -= 18
                if branch.attempts > 0:
                    score -= 12
            elif branch.status == "blocked" and not branch.source_finding_id:
                score -= 24
        if related_skills and all(
            self._recent_blocked_skill_count(skill) >= 3 for skill in related_skills
        ):
            score -= 18
            if is_memory_branch:
                score -= 14
        if branch.owner == "memory":
            score -= 10
        if branch.id.startswith("carry:"):
            score -= 12
        if branch.attempts == 0:
            score += 8
        if family == "disclosure" and self._has_stronger_foothold_than_disclosure():
            score -= 26
            if branch.source_finding_id:
                score -= 10
        if family == "disclosure" and self._disclosure_campaign_lacks_reusable_material():
            score -= 34
            if branch.source_finding_id:
                score -= 12
        if family == "injection" and self._branch_lacks_meaningful_db_impact(branch):
            score -= 40
        if self._branch_is_redundant_family_root(branch):
            score -= 40
        if self._branch_is_redundant_memory_revalidation(branch):
            score -= 48
        return score

    def _branch_is_redundant_family_root(self, branch: BranchState) -> bool:
        if branch.source_finding_id:
            return False
        if branch.owner not in {"root", ""}:
            return False
        if branch.parent_branch_id:
            return False
        family = self._branch_family(branch)
        if family == "generic":
            return False
        if branch.attempts >= 1 and any(
            other.id != branch.id
            and other.status not in {"proven", "exhausted", "dead", "blocked"}
            and self._branch_family(other) == family
            and bool(other.source_finding_id)
            and other.role == "post_exploit_worker"
            for other in self.state.branches.values()
        ):
            return True
        if branch.attempts < 2:
            return False
        children = [self.state.branches.get(child_id) for child_id in branch.child_ids]
        live_children = [
            child
            for child in children
            if child is not None and child.status not in {"proven", "exhausted", "dead", "blocked"}
        ]
        if not live_children:
            return False
        if not any(child.source_finding_id for child in live_children):
            return False
        sibling_or_child_coverage = any(
            self._branch_family(child) == family and child.role == "post_exploit_worker"
            for child in live_children
        )
        return sibling_or_child_coverage

    def _branch_is_redundant_memory_revalidation(self, branch: BranchState) -> bool:
        if not (
            branch.owner == "memory"
            or branch.id.startswith("carry:")
            or branch.id.startswith("memory:")
        ):
            return False
        family = self._branch_family(branch)
        if family == "generic":
            return False
        try:
            from vxis.agent.tools.finding_tools import _canonical_finding_type as _canon_ft
        except Exception:

            def _canon_ft(value: object) -> str:
                return str(value or "").strip().lower()

        related_types = self._family_related_types(family)
        found_types = {
            _canon_ft(str(item.get("finding_type", "")))
            for item in self.state.findings
            if isinstance(item, dict)
        }
        if branch.attempts == 0 and related_types and (related_types & found_types):
            return True
        if any(
            other.id != branch.id
            and other.status not in {"proven", "exhausted", "dead", "blocked"}
            and self._branch_family(other) == family
            and other.owner != "memory"
            and not other.id.startswith(("carry:", "memory:"))
            for other in self.state.branches.values()
        ):
            return True
        return any(
            other.id != branch.id
            and other.status not in {"proven", "exhausted", "dead", "blocked"}
            and self._branch_family(other) == family
            and other.owner != "memory"
            and not other.id.startswith(("carry:", "memory:"))
            and (
                other.source_finding_id or other.role == "post_exploit_worker" or other.attempts > 0
            )
            for other in self.state.branches.values()
        )

    def _branch_has_finish_blocking_yield(self, branch: BranchState) -> bool:
        if branch.owner == "agent_graph":
            return branch.status not in _TERMINAL_BRANCH_STATUSES
        score = self._branch_expected_yield_score(branch)
        family = self._branch_family(branch)
        if branch.owner == "memory" or branch.id.startswith(("carry:", "memory:")):
            return score >= 82
        if family != "disclosure" and self._branch_has_open_crown_goal(branch):
            return True
        if branch.source_finding_id:
            return score >= 65
        if (
            family == "disclosure"
            and self._has_stronger_foothold_than_disclosure()
        ):
            return score >= 78
        if (
            family == "disclosure"
            and self._disclosure_campaign_lacks_reusable_material()
        ):
            return score >= 82
        return branch.attempts < 2 or score >= 78

    @staticmethod
    def _branch_has_open_crown_goal(branch: BranchState) -> bool:
        if not str(branch.crown_jewel or "").strip():
            return False
        if branch.attempts >= 3:
            return False
        if str(branch.role or "").lower() == "post_exploit_worker":
            return True
        return str(branch.phase or "").lower() in {
            "privilege_probe",
            "data_access",
            "chain_closure",
        }

    def _campaign_groups_for_ui(self, limit: int = 4) -> list[dict[str, Any]]:
        groups: list[dict[str, Any]] = []
        by_key: dict[tuple[str, str], dict[str, Any]] = {}
        blockers = {branch.id for branch in self._dag_finish_blocking_branches()}
        for branch in self.state.active_branches():
            key = (
                branch.source_finding_id or branch.parent_branch_id or branch.id,
                branch.crown_jewel or self._branch_family(branch) or "generic",
            )
            group = by_key.get(key)
            if group is None:
                group = {
                    "campaign_id": key[0],
                    "crown_jewel": key[1],
                    "family": self._branch_family(branch),
                    "source_finding_id": branch.source_finding_id,
                    "branch_ids": [],
                    "roles": set(),
                    "phases": set(),
                    "blockers": 0,
                    "max_priority": 0,
                    "headline": branch.title,
                    "next_step": branch.next_step,
                    "objective": branch.objective,
                }
                by_key[key] = group
                groups.append(group)
            group["branch_ids"].append(branch.id)
            group["roles"].add(branch.role)
            group["phases"].add(branch.phase or "surface")
            group["max_priority"] = max(int(group["max_priority"]), int(branch.priority))
            if branch.id in blockers:
                group["blockers"] = int(group["blockers"]) + 1
            if branch.source_finding_id and branch.next_step:
                group["next_step"] = branch.next_step
            if branch.source_finding_id and branch.objective:
                group["objective"] = branch.objective
        scored = sorted(
            groups,
            key=lambda item: (
                int(item["blockers"]) > 0,
                int(item["max_priority"]),
                len(item["branch_ids"]),
            ),
            reverse=True,
        )
        out: list[dict[str, Any]] = []
        for item in scored[:limit]:
            out.append(
                {
                    "campaign_id": item["campaign_id"],
                    "headline": str(item["headline"])[:84],
                    "source_finding_id": item["source_finding_id"],
                    "crown_jewel": str(item["crown_jewel"])[:72],
                    "family": item["family"],
                    "roles": sorted(str(role) for role in item["roles"]),
                    "phases": sorted(str(phase) for phase in item["phases"]),
                    "branch_count": len(item["branch_ids"]),
                    "blocking_count": int(item["blockers"]),
                    "max_priority": int(item["max_priority"]),
                    "objective": str(item["objective"])[:96],
                    "next_step": str(item["next_step"])[:96],
                }
            )
        return out

    def _focus_campaign_for_ui(self) -> dict[str, Any] | None:
        groups = self._campaign_groups_for_ui(limit=8)
        if not groups:
            return None
        focus = self._focus_branch()
        selected = groups[0]
        if focus is not None:
            focus_family = self._branch_family(focus)
            for group in groups:
                campaign_id = str(group.get("campaign_id") or "")
                if focus.source_finding_id and campaign_id == focus.source_finding_id:
                    selected = group
                    break
                if not focus.source_finding_id and campaign_id == (
                    focus.parent_branch_id or focus.id
                ):
                    selected = group
                    break
                if str(group.get("family") or "") == focus_family:
                    selected = group
                    break
        family = str(selected.get("family") or "")
        reviews: list[dict[str, Any]] = []
        for item in self.state.review_queue_as_dicts():
            source_type = str(item.get("source_finding_type") or "").lower()
            reason = str(item.get("reason") or "").lower()
            affected = str(item.get("affected_component") or "").lower()
            if family and (family in source_type or family in reason or family in affected):
                reviews.append(
                    {
                        "stage": item.get("stage", ""),
                        "status": item.get("status", ""),
                        "title": str(item.get("title") or "")[:72],
                        "reason": str(item.get("reason") or "")[:120],
                    }
                )
        findings: list[dict[str, Any]] = []
        for finding in self.state.findings[-12:]:
            if not isinstance(finding, dict):
                continue
            blob = " ".join(
                str(finding.get(key, ""))
                for key in ("finding_type", "title", "affected_component", "impact")
            ).lower()
            if family and family in blob:
                findings.append(
                    {
                        "id": finding.get("id", ""),
                        "title": str(finding.get("title") or "")[:88],
                        "finding_type": finding.get("finding_type", ""),
                        "severity": finding.get("severity", ""),
                        "affected_component": str(finding.get("affected_component") or "")[:88],
                    }
                )
        delegated_workers: list[dict[str, Any]] = []
        for branch in self.state.active_branches():
            if branch.owner != "agent_graph":
                continue
            branch_family = self._branch_family(branch)
            if family and branch_family != family:
                continue
            delegated_workers.append(
                {
                    "id": branch.id,
                    "role": branch.role,
                    "phase": branch.phase,
                    "status": branch.status,
                    "objective": str(branch.objective or "")[:88],
                    "next_step": str(branch.next_step or "")[:88],
                    "escalation_status": str(branch.escalation_status or ""),
                    "escalation_reason": str(branch.escalation_reason or "")[:120],
                }
            )
        detail = dict(selected)
        detail["reviews"] = reviews[:3]
        detail["findings"] = findings[-3:]
        detail["delegated_workers"] = delegated_workers[:3]
        return detail

    def _has_stronger_foothold_than_disclosure(self) -> bool:
        blobs = []
        for finding in self.state.findings:
            if not isinstance(finding, dict):
                continue
            blobs.append(
                " ".join(
                    str(finding.get(key, ""))
                    for key in (
                        "finding_type",
                        "title",
                        "impact",
                        "technical_analysis",
                        "poc_description",
                    )
                ).lower()
            )
        return any(
            any(
                token in blob
                for token in (
                    "authentication bypass",
                    "authenticated foothold",
                    "session takeover",
                    "token acquired",
                )
            )
            or (
                "sql_injection" in blob
                and any(token in blob for token in ("authenticated", "login", "token", "session"))
            )
            for blob in blobs
        )

    def _disclosure_campaign_lacks_reusable_material(self) -> bool:
        reasons: list[str] = []
        for item in self.state.review_queue.values():
            if str(item.source_finding_type or "").lower() in {
                "information_disclosure",
                "misconfiguration",
            }:
                reasons.append(str(item.reason or "").lower())
        for item in self.state.review_history:
            if str(item.source_finding_type or "").lower() in {
                "information_disclosure",
                "misconfiguration",
            }:
                reasons.append(str(item.reason or "").lower())
        binary_only_hits = sum(
            1
            for reason in reasons
            if "binary/compressed blob" in reason or "without readable secret material" in reason
        )
        if binary_only_hits < 2:
            return False
        finding_blob = " ".join(
            " ".join(
                str(finding.get(key, ""))
                for key in (
                    "title",
                    "impact",
                    "technical_analysis",
                    "poc_description",
                    "poc_script_code",
                )
            ).lower()
            for finding in self.state.findings
            if isinstance(finding, dict)
            and str(finding.get("finding_type", "")).lower()
            in {"information_disclosure", "misconfiguration"}
        )
        reusable_markers = (
            "password",
            "token",
            "jwt",
            "apikey",
            "api key",
            "secret",
            "credential",
            "session",
            "bearer",
            "admin",
            "login",
            "cookie",
        )
        return not any(marker in finding_blob for marker in reusable_markers)

    def _branch_lacks_meaningful_db_impact(self, branch: BranchState) -> bool:
        if (
            "db"
            not in " ".join((branch.id, branch.title, branch.crown_jewel, branch.objective)).lower()
        ):
            return False
        if branch.attempts < 2:
            return False
        blob = " ".join(
            (
                branch.last_summary,
                branch.last_report,
                branch.evidence,
            )
        ).lower()
        strong_markers = (
            "table",
            "schema",
            "database",
            "dump",
            "union select",
            "sqlmap",
            "credential",
            "admin",
            "user",
        )
        if any(marker in blob for marker in strong_markers):
            return False
        for finding in self.state.findings:
            if not isinstance(finding, dict):
                continue
            if branch.source_finding_id and str(finding.get("id", "")) == branch.source_finding_id:
                continue
            finding_blob = " ".join(
                str(finding.get(key, ""))
                for key in (
                    "finding_type",
                    "title",
                    "impact",
                    "technical_analysis",
                    "poc_script_code",
                )
            ).lower()
            if any(marker in finding_blob for marker in strong_markers):
                return False
        return True

    def _latest_auth_token(self) -> str:
        for identity in getattr(self.state, "auth_identities", []) or []:
            if not isinstance(identity, dict):
                continue
            token = str(identity.get("token") or "").strip()
            if token:
                return token
        for message in reversed(self.state.messages[-96:]):
            if message.get("role") != "tool":
                continue
            content = message.get("content", {})
            if not isinstance(content, dict) or content.get("name") != "run_skill":
                continue
            result = content.get("result", {})
            if not isinstance(result, dict):
                continue
            data = result.get("data", {})
            if not isinstance(data, dict):
                continue
            token = str(data.get("token") or "").strip()
            if token:
                return token
        return ""

    def _latest_authz_context_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        authz_fn = getattr(self.state, "authz_context_params", None)
        if callable(authz_fn):
            try:
                params.update(authz_fn())
            except Exception:
                params = {}
        if params.get("identities"):
            return params

        for message in reversed(self.state.messages[-96:]):
            if message.get("role") != "tool":
                continue
            content = message.get("content", {})
            if not isinstance(content, dict) or content.get("name") != "run_skill":
                continue
            result = content.get("result", {})
            data = result.get("data", {}) if isinstance(result, dict) else {}
            if not isinstance(data, dict):
                continue
            identities = data.get("identities")
            if isinstance(identities, list) and identities:
                params["identities"] = identities
                if isinstance(data.get("owner_map"), dict):
                    params["owner_map"] = data["owner_map"]
                token = str(data.get("token") or "").strip()
                if token:
                    params["token"] = token
                return params
        return params

    def _recent_captured_business_flows(self) -> list[dict[str, Any]]:
        flows: list[dict[str, Any]] = []
        business_markers = (
            "cart",
            "basket",
            "order",
            "checkout",
            "coupon",
            "promo",
            "payment",
            "transfer",
            "account",
            "verify",
        )
        for message in reversed(self.state.messages[-160:]):
            content = message.get("content", {})
            if not isinstance(content, dict):
                continue
            result = content.get("result", {})
            data = result.get("data", {}) if isinstance(result, dict) else {}
            if not isinstance(data, dict):
                continue
            candidates: list[Any] = []
            if isinstance(data.get("requests"), list):
                candidates.extend(data["requests"])
            if any(key in data for key in ("method", "path", "url", "body", "request_body")):
                candidates.append(data)
            for item in candidates:
                if not isinstance(item, dict):
                    continue
                method = str(item.get("method") or "").upper()
                path = str(item.get("path") or item.get("url") or "").lower()
                has_body = any(item.get(key) for key in ("body", "request_body", "json", "json_data"))
                if method in {"POST", "PUT", "PATCH"} and has_body and any(
                    marker in path for marker in business_markers
                ):
                    flows.append(dict(item))
                    if len(flows) >= 12:
                        return list(reversed(flows))
        return list(reversed(flows))

    def _candidate_expected_yield_score(
        self, candidate: VectorCandidate, findings: list[dict[str, Any]]
    ) -> int:
        try:
            from vxis.agent.tools.finding_tools import _canonical_finding_type as _canon_ft
        except Exception:

            def _canon_ft(value: object) -> str:
                return str(value or "").strip().lower()

        score = int(candidate.priority)
        if candidate.attempts > 0:
            score -= candidate.attempts * 12
        family = self._candidate_family(candidate)
        related_types = self._family_related_types(family)
        related_skills = self._family_related_skills(family)
        if family == "infra":
            related_skills.add("enumerate_endpoints")
        found_types = {
            _canon_ft(str(item.get("finding_type", "")))
            for item in findings
            if isinstance(item, dict)
        }
        covered_family = bool(related_types & found_types)
        is_memory_candidate = str(candidate.id).startswith("memory:")
        if covered_family:
            score -= 32
            if is_memory_candidate:
                score -= 28
        if related_skills and all(
            self._recent_blocked_skill_count(skill) >= 3 for skill in related_skills
        ):
            score -= 28
            if is_memory_candidate:
                score -= 14
        if is_memory_candidate and candidate.attempts == 0:
            score -= 10
        if candidate.status in {"blocked", "failed", "dead"}:
            score -= 18
        return score

    def _candidate_family(self, candidate: VectorCandidate) -> str:
        vector_blob = " ".join((candidate.id, candidate.vector_id)).lower()
        blob = " ".join((candidate.vector_id, candidate.title, candidate.evidence)).lower()
        return self._family_from_blobs(vector_blob, blob)

    def _branch_family(self, branch: BranchState) -> str:
        vector_blob = " ".join(
            (
                branch.id,
                branch.vector_id,
                branch.source_candidate_id,
                branch.source_finding_id,
            )
        ).lower()
        blob = " ".join(
            (
                branch.vector_id,
                branch.title,
                branch.objective,
                branch.next_step,
                branch.evidence,
                branch.blocker,
                branch.crown_jewel,
            )
        ).lower()
        return self._family_from_blobs(vector_blob, blob)

    def _family_from_blobs(self, vector_blob: str, blob: str) -> str:
        explicit_map = {
            "web:xss": "xss",
            "web:ssrf": "ssrf",
            "web:sqli": "injection",
            "web-sqli": "injection",
            "web-xss": "xss",
            "web-ssrf": "ssrf",
            "web:idor": "idor",
            "web-idor": "idor",
            "web:auth-bypass": "auth",
            "web-auth": "auth",
            "web:sensitive-files": "disclosure",
            "web-misconf": "disclosure",
            "web:dir-bruteforce": "infra",
            "web-cve": "infra",
        }
        for needle, family in explicit_map.items():
            if needle in vector_blob:
                return family
        for family, tokens, _types in _WEB_VECTOR_FAMILY_RULES:
            if any(token in blob for token in tokens):
                return family
        return "generic"

    def _family_related_types(self, family: str) -> set[str]:
        for rule_family, _tokens, family_types in _WEB_VECTOR_FAMILY_RULES:
            if family == rule_family:
                return set(family_types)
        return set()

    def _family_related_skills(self, family: str) -> set[str]:
        if family == "auth":
            return {"attempt_auth", "post_auth_enum"}
        if family == "injection":
            return {"test_injection"}
        if family == "idor":
            return {"test_idor"}
        if family == "disclosure":
            return {"test_sensitive_files", "test_infra"}
        if family == "xss":
            return {"test_xss"}
        if family == "ssrf":
            return {"test_ssrf"}
        if family == "infra":
            return {"test_infra"}
        return set()

    def _candidate_has_finish_blocking_yield(
        self, candidate: VectorCandidate, findings: list[dict[str, Any]]
    ) -> bool:
        if candidate.priority < 75 or candidate.attempts > 0:
            return False
        threshold = 78 if str(candidate.id).startswith("memory:") else 72
        return self._candidate_expected_yield_score(candidate, findings) >= threshold

    def _dag_remaining_high_yield_candidates(
        self, findings: list[dict[str, Any]]
    ) -> list[VectorCandidate]:
        blocker_ids = set(dag_finish_blocker_node_ids(self.state, prior_threshold=0.65))
        open_candidates = [
            c
            for c in self.state.open_vector_candidates()
            if c.id in blocker_ids and self._candidate_has_finish_blocking_yield(c, findings)
        ]
        deduped: list[VectorCandidate] = []
        seen_families: set[str] = set()
        for candidate in open_candidates:
            family = self._candidate_family(candidate)
            if family in seen_families and family != "generic":
                continue
            seen_families.add(family)
            deduped.append(candidate)
        return deduped

    def _retryable_family_candidates(self, findings: list[dict[str, Any]]) -> list[VectorCandidate]:
        retryable = [
            c
            for c in self.state.open_vector_candidates()
            if c.status == "retryable" and self._candidate_expected_yield_score(c, findings) >= 48
        ]
        deduped: list[VectorCandidate] = []
        seen_families: set[str] = set()
        for candidate in retryable:
            family = self._candidate_family(candidate)
            if family in seen_families and family != "generic":
                continue
            seen_families.add(family)
            deduped.append(candidate)
        return deduped

    def _next_retry_round(
        self, skill_name: str, candidate: VectorCandidate | None = None
    ) -> int | None:
        skill = str(skill_name).strip().lower()
        if skill not in {"test_injection", "test_xss", "test_ssrf"}:
            return None
        seen_round = 1
        if candidate is not None:
            match = re.search(r"round\s+(\d+)", str(candidate.last_summary or ""), re.IGNORECASE)
            if match:
                try:
                    seen_round = max(seen_round, int(match.group(1)))
                except Exception:
                    pass
        for message in self.state.messages[-48:]:
            if message.get("role") != "tool":
                continue
            content = message.get("content", {})
            if not isinstance(content, dict) or content.get("name") != "run_skill":
                continue
            args = content.get("args", {})
            if not isinstance(args, dict):
                continue
            if str(args.get("skill") or "").strip().lower() != skill:
                continue
            params = args.get("params", {})
            if isinstance(params, dict):
                try:
                    seen_round = max(seen_round, int(params.get("round", 1)))
                except Exception:
                    pass
        return min(seen_round + 1, 3)

    def _maybe_finalize_budget_exhausted_scan(self) -> bool:
        if self.state.completed:
            return True
        try:
            from vxis.agent.tools.finding_tools import _get_chains, _get_findings

            findings = list(_get_findings() or [])
            chains = list(_get_chains() or [])
        except Exception:
            findings = list(self.state.findings or [])
            chains = []
        if not findings:
            return False
        if self._dag_finish_blocking_branches():
            return False
        open_candidates = self._dag_remaining_high_yield_candidates(findings)
        if open_candidates:
            return False
        try:
            from vxis.agent.replay_gate import blocking_replay_gate_findings

            if blocking_replay_gate_findings(findings):
                return False
        except Exception:
            return False
        desired = self._desired_chain_count(findings)
        if desired > 0 and len(chains) < desired:
            return False
        self.state.completed = True
        self.state.record_review_decision(
            stage="judge",
            verdict="ACCEPTED",
            title="budget_exhausted_completion",
            reason=(
                "Scan budget was exhausted after meaningful branches were resolved and no high-yield blockers remained."
            ),
            action_hint="Finalize reporting; remaining work is low-yield relative to the exhausted budget.",
            blocked_action="finish_scan",
            affected_component=self.state.target,
        )
        for item in self.state.review_queue.values():
            if item.stage == "judge" and item.title in {
                "unfinished_branches",
                "needs_chains",
                "needs_replay_gate",
                "unattempted_candidates",
                "premature_finish",
            }:
                item.status = "closed"
        self.state.add_message(
            "system",
            {
                "hint": (
                    "SYSTEM HINT: scan budget exhausted with no meaningful blockers remaining. "
                    "Accepting completion and finalizing the current report set."
                ),
            },
        )
        return True

    @staticmethod
    def _finish_branch_guard_until(max_iters: int) -> int:
        """Keep branch pressure high on real scans without deadlocking short smokes."""
        return min(max_iters, min(60, max(3, max_iters - 5)))

    @staticmethod
    def _error_oracle_preview_is_actionable(preview: str) -> bool:
        """Only promote 500s that leak concrete backend details."""
        if not preview:
            return False
        lower = preview.lower()
        markers = (
            "traceback",
            "stack trace",
            "exception:",
            "sql",
            "sqlite",
            "mysql",
            "postgres",
            "ora-",
            "syntax error",
            "sequelize",
            "typeorm",
            "prisma",
            "undefined",
            "cannot read",
        )
        return any(marker in lower for marker in markers)

    def _record_judge_escalation(
        self,
        *,
        title: str,
        reason: str,
        action_hint: str,
        affected_component: str = "",
    ) -> None:
        self.state.record_review_item(
            f"judge:{title}:{affected_component or self.state.target}",
            stage="judge",
            status="escalated",
            title=title,
            reason=reason,
            action_hint=action_hint,
            affected_component=affected_component or self.state.target,
        )

    def _record_verifier_decision(
        self,
        *,
        args: dict[str, Any],
        verdict: str,
        reasoning: str,
        confidence: str = "",
    ) -> None:
        stage = "verifier"
        title = str(args.get("title", "finding review"))
        component = str(args.get("affected_component", ""))
        source_finding_type = str(args.get("finding_type", ""))
        action_hint = {
            "CONFIRMED": "Keep chaining this finding toward impact.",
            "UNCONFIRMED": "Gather control pairs or stronger exploit transcript before reporting again.",
            "REFUTED": "Do not report this again unless you obtain materially different evidence.",
        }.get(verdict, "")
        item_status = "open" if verdict == "UNCONFIRMED" else "closed"
        if verdict == "CONFIRMED":
            item_status = "closed"
        self.state.record_review_item(
            f"verify:{title}:{component}",
            stage=stage,
            status=item_status,
            title=title,
            reason=reasoning or f"Verifier returned {verdict}.",
            action_hint=action_hint,
            affected_component=component,
            source_finding_type=source_finding_type,
        )
        self.state.record_review_decision(
            stage=stage,
            verdict=verdict,
            title=title,
            reason=(f"[{confidence}] " if confidence else "")
            + (reasoning or f"Verifier returned {verdict}."),
            action_hint=action_hint,
            blocked_action="report_finding" if verdict == "REFUTED" else "",
            affected_component=component,
            source_finding_type=source_finding_type,
        )

    def _reject_finish_scan(
        self,
        *,
        title: str,
        reason: str,
        action_hint: str,
        summary: str,
        data: dict[str, Any],
        affected_component: str = "",
    ) -> None:
        component = affected_component or self.state.target
        self._record_judge_escalation(
            title=title,
            reason=reason,
            action_hint=action_hint,
            affected_component=component,
        )
        self.state.record_review_decision(
            stage="judge",
            verdict="REJECTED",
            title=title,
            reason=reason,
            action_hint=action_hint,
            blocked_action="finish_scan",
            affected_component=component,
        )
        self.state.add_message(
            "tool",
            {
                "name": "finish_scan",
                "args": {},
                "result": {
                    "ok": False,
                    "summary": summary,
                    "data": data,
                },
            },
        )

    def _recent_finish_rejections(self, *, limit: int = 3) -> list[ReviewDecision]:
        items = [
            item
            for item in self.state.review_history
            if item.stage == "judge" and item.blocked_action == "finish_scan"
        ]
        return items[-limit:]

    def _judge_replan_hint(self) -> str:
        focus = self._focus_branch()
        if focus and focus.owner == "agent_graph" and focus.escalation_status:
            if focus.escalation_status == "positive_needs_pivot":
                return (
                    f"Delegated worker {focus.id} produced a positive result. Director must now pivot: "
                    "finish the worker with concrete impact, open a post-exploit/crown-chain task, or link the finding."
                )
            if focus.escalation_status == "ambiguous":
                return (
                    f"Delegated worker {focus.id} is ambiguous after repeated failed turns. "
                    "Send a narrower instruction or create a sharper bounded worker instead of repeating the same probe."
                )
            if focus.escalation_status == "run_limit":
                return (
                    f"Delegated worker {focus.id} hit the child-run limit. "
                    "Do not rerun it blindly; finish it as blocked/clean or spawn a new bounded worker with a narrower objective."
                )
            if focus.escalation_status == "blocked":
                return (
                    f"Delegated worker {focus.id} is blocked. "
                    "Either rescope the task, route around the blocker, or close the worker explicitly before finish_scan."
                )
        if focus and focus.status not in {"proven", "exhausted", "dead", "blocked"}:
            return (
                f"Focus on branch {focus.id} [{focus.role}/{focus.phase}] and advance it with a concrete "
                f"exploit, data-access, or chain-building step before trying to finish again."
            )
        findings = list(self.state.findings or [])
        auth_titles = " ".join(str(f.get("title", "")).lower() for f in findings)
        finding_types = {str(f.get("finding_type", "")).lower() for f in findings}
        if (
            any(
                token in auth_titles
                for token in ("authentication bypass", "authenticated", "token acquired")
            )
            or "weak_auth" in finding_types
            or "broken_access_control" in finding_types
        ):
            return (
                "Reuse the foothold now: validate post-authenticated data access, enumerate admin/API routes, "
                "and link the auth finding to the post-auth data exposure before trying finish_scan again."
            )
        for item in reversed(self.state.review_queue_as_dicts()):
            title = str(item.get("title", "")).lower()
            if title == "needs_chains":
                return (
                    "Build or validate an attack chain next. Link confirmed findings together or push a "
                    "post-exploit branch until it proves a concrete pivot."
                )
            if title == "needs_replay_gate":
                return (
                    "Replay every high/critical finding through the verifier path, attach replay_gate.status=passed, "
                    "or downgrade findings that no longer reproduce."
                )
            if title == "unfinished_branches":
                return "Close the highest-priority open branch by proving, exhausting, or blocking it with evidence."
            if title == "unattempted_candidates":
                return "Exercise at least one unresolved high-priority vector candidate with a concrete payload."
        return "Perform one concrete high-signal action before attempting finish_scan again."

    def _run_skill_action(
        self,
        requested_skill: str,
        *,
        target: str,
        hint_blob: str = "",
        params: dict[str, Any] | None = None,
        retry_candidate: VectorCandidate | None = None,
    ) -> tuple[str, dict[str, Any]] | None:
        skill = self._pivoted_skill_name(requested_skill)
        if not skill:
            return None
        action_params = (
            dict(params)
            if params is not None
            else self._best_skill_params(skill, hint_blob=hint_blob)
        )
        if retry_candidate is not None and retry_candidate.status == "retryable":
            next_round = self._next_retry_round(skill, retry_candidate)
            if next_round is not None:
                action_params["round"] = next_round
        if skill == "attempt_auth" and not action_params:
            action_params = {}
        return ("run_skill", {"skill": skill, "target_url": target, "params": action_params})

    def _forced_candidate_action(
        self, candidate: VectorCandidate
    ) -> tuple[str, dict[str, Any]] | None:
        allowed = self._platform_allowed_skills()
        if "run_skill" not in self.registry.list_tools() or not allowed:
            return None
        blob = f"{candidate.vector_id} {candidate.title} {candidate.evidence}".lower()
        target = str(self.state.target)
        kind = self._target_kind_name()
        family = self._candidate_family(candidate)
        if kind == "desktop":
            for tokens, skills in (
                (("secret", "storage", "keychain", "token"), ("test_local_storage_secrets",)),
                (("deep", "link", "url", "scheme"), ("test_deeplink_abuse",)),
                (("signature", "trust", "entitlement", "binary"), ("test_signature_audit",)),
                ((), ("test_ipc_injection", "test_binary_protections")),
            ):
                if tokens and not any(token in blob for token in tokens):
                    continue
                for requested in skills:
                    action = self._run_skill_action(
                        requested, target=target, hint_blob=blob, params={}
                    )
                    if action is not None:
                        return action
            return None
        if kind != "web":
            return None
        family_skill_map = {
            "auth": "attempt_auth",
            "idor": "test_idor",
            "injection": "test_injection",
            "xss": "test_xss",
            "ssrf": "test_ssrf",
            "disclosure": "test_sensitive_files",
            "infra": "enumerate_endpoints",
        }
        family_skill = family_skill_map.get(family)
        if family_skill:
            return self._run_skill_action(
                family_skill, target=target, hint_blob=blob, retry_candidate=candidate
            )
        return self._run_skill_action("enumerate_endpoints", target=target, params={})

    def _forced_branch_action(self, branch: BranchState) -> tuple[str, dict[str, Any]] | None:
        allowed = self._platform_allowed_skills()
        target = str(self.state.target)
        role = str(branch.role).lower()
        phase = str(branch.phase).lower()
        kind = self._target_kind_name()
        blob = " ".join(
            [
                str(branch.vector_id or ""),
                str(branch.title or ""),
                str(branch.objective or ""),
                str(branch.next_step or ""),
                str(branch.crown_jewel or ""),
            ]
        ).lower()
        shell_exec_failed = (
            branch.last_tool == "shell_exec" and "exit=" in str(branch.last_summary).lower()
        )
        crown_report = self._agent_graph_crown_report_action(branch)
        if crown_report is not None:
            return crown_report
        crown_agent_create = self._agent_graph_crown_followup_create_action(branch)
        if crown_agent_create is not None:
            return crown_agent_create
        service_agent_create = self._agent_graph_service_followup_create_action(branch)
        if service_agent_create is not None:
            return service_agent_create
        if "run_skill" not in self.registry.list_tools() or not allowed:
            return None
        if branch.owner == "agent_graph":
            if self._agent_graph_branch_has_successful_child_evidence(branch):
                return None
            if any(
                token in str(branch.blocker or branch.last_summary).lower()
                for token in (
                    "run_limit_reached",
                    "child-run limit",
                    "executor_unavailable",
                    "child_tool_unavailable",
                    "child_tool_not_allowed",
                    "no executable child step",
                    "no executable step",
                    "not registered",
                    "not allowed for bounded child execution",
                    "blocked_with_reason",
                    "same evidenceartifact gap repeated",
                )
            ):
                return None
            agent_id = branch.id.removeprefix("agent:")
            if agent_id and self.registry.has_tool("agent_graph"):
                args = {"action": "run", "agent_id": agent_id}
                instruction = self._agent_graph_branch_gap_instruction(branch)
                if instruction:
                    args["instruction"] = instruction
                return ("agent_graph", args)
            for declared_skill in self._declared_agent_graph_branch_skills(branch):
                action = self._run_skill_action(declared_skill, target=target, hint_blob=blob)
                if action is not None:
                    return action
        if kind == "desktop":
            for tokens, skills in (
                (("secret", "storage", "keychain"), ("test_local_storage_secrets",)),
                (("ipc", "deeplink", "url scheme"), ("test_ipc_injection", "test_deeplink_abuse")),
                ((), ("test_signature_audit", "test_binary_protections")),
            ):
                if tokens and not any(token in blob for token in tokens):
                    continue
                for requested in skills:
                    action = self._run_skill_action(
                        requested, target=target, hint_blob=blob, params={}
                    )
                    if action is not None:
                        return action
            return None
        if kind != "web":
            return None
        if role == "post_exploit_worker" or any(
            token in phase for token in ("privilege_probe", "data_access", "chain_closure")
        ):
            if shell_exec_failed and any(
                token in blob
                for token in ("admin", "token", "session", "credential", "role", "export")
            ):
                return (
                    "http_request",
                    {"method": "GET", "url": target.rstrip("/") + "/rest/user/whoami"},
                )
            return self._run_skill_action("post_auth_enum", target=target, hint_blob=blob)
        if any(
            token in blob for token in ("idor", "access_control", "broken access control", "object")
        ):
            return self._run_skill_action("test_idor", target=target, hint_blob=blob)
        if any(token in blob for token in ("auth", "login", "session", "token")):
            return self._run_skill_action("attempt_auth", target=target, hint_blob=blob)
        if any(token in blob for token in ("admin", "data", "profile", "account")):
            return self._run_skill_action("post_auth_enum", target=target, hint_blob=blob)
        if any(token in blob for token in ("sqli", "sql", "injection", "nosql", "ssti")):
            return self._run_skill_action("test_injection", target=target, hint_blob=blob)
        return None

    def _agent_graph_service_followup_create_action(
        self,
        branch: BranchState,
    ) -> tuple[str, dict[str, Any]] | None:
        if branch.owner == "agent_graph" or not self.registry.has_tool("agent_graph"):
            return None
        if str(branch.vector_id or "") != "NET-SERVICE-PIVOT":
            return None
        if any(
            child_id in self.state.branches
            and self.state.branches[child_id].owner == "agent_graph"
            for child_id in branch.child_ids
        ):
            return None
        if (
            branch.last_tool == "agent_graph"
            and "created" in str(branch.last_summary or "").lower()
        ):
            return None

        blob = " ".join(
            str(value or "")
            for value in (
                branch.title,
                branch.objective,
                branch.next_step,
                branch.crown_jewel,
                branch.evidence,
                " ".join(branch.watch_terms),
            )
        ).lower()
        is_control_plane = any(
            token in blob
            for token in (
                "control-plane",
                "kubernetes",
                "docker",
                "etcd",
                "consul",
                "jenkins",
                "prometheus",
                "grafana",
            )
        )
        is_http_like = "http" in blob or "api" in blob
        if is_control_plane:
            role = "exploit_worker"
        elif is_http_like:
            role = "recon_worker"
        else:
            role = "exploit_worker"
        skills: list[str] = []
        if is_control_plane:
            skills = ["test_api_security", "test_misconfig"]
        elif is_http_like:
            skills = ["enumerate_endpoints", "test_misconfig"]
        elif any(token in blob for token in ("database", "redis", "mongodb", "postgres", "mysql")):
            skills = ["test_infra"]
        elif any(token in blob for token in ("remote", "share", "file", "smb", "ftp", "nfs")):
            skills = ["test_sensitive_files"]

        target_hint = ""
        port_hint = ""
        protocol_hint = ""
        service_match = re.search(r"\b([A-Za-z0-9._-]+):(\d{1,5})/(tcp|udp)\b", blob)
        if service_match:
            target_hint = service_match.group(1)
            port_hint = service_match.group(2)
            protocol_hint = service_match.group(3)
        scripts = "default,safe,vuln" if role == "exploit_worker" else "default,safe"

        task = (
            f"Deepen nmap service pivot: {branch.title}. "
            f"Evidence: {str(branch.evidence or branch.last_report)[:220]}"
        )
        args: dict[str, Any] = {
            "action": "create",
            "role": role,
            "task": task[:320],
            "objective": str(branch.objective or task)[:160],
            "expected_artifact": (
                "service-specific transcript or valid EvidenceArtifact with target, "
                "control, payload, observed_delta, and repro_steps"
            ),
            "stop_condition": (
                "stop after proving exploitable service impact or recording a concrete blocker"
            ),
            "escalation_trigger": (
                "escalate if nmap service evidence implies database, remote access, admin, "
                "file disclosure, or lateral-movement impact"
            ),
            "message": (
                "Use bounded tools only. Prefer nmap_scan for service fingerprinting, "
                "then choose http_request/browser/run_skill only when the service evidence fits. "
                f"Start with nmap_scan target={target_hint or self.state.target} "
                f"ports={port_hint or '<exact-port>'} scripts={scripts}"
                f"{' udp=true' if protocol_hint == 'udp' else ''}."
            ),
        }
        if skills:
            args["skills"] = skills
        return ("agent_graph", args)

    @staticmethod
    def _agent_graph_branch_gap_instruction(branch: BranchState) -> str:
        text = " ".join(str(value or "") for value in (branch.next_step, branch.blocker))
        marker = "Evidence gap:"
        if marker not in text:
            return ""
        return text[text.index(marker) :].split(" Evidence:", 1)[0][:260].strip()

    def _agent_graph_crown_followup_create_action(
        self, branch: BranchState
    ) -> tuple[str, dict[str, Any]] | None:
        if branch.owner == "agent_graph" or not self.registry.has_tool("agent_graph"):
            return None
        if str(branch.role or "").lower() != "post_exploit_worker":
            return None
        if branch.vector_id not in {"WEB-CROWN-PIVOT", "DESK-CROWN-PIVOT"}:
            return None
        if any(
            child_id in self.state.branches
            and self.state.branches[child_id].owner == "agent_graph"
            and self.state.branches[child_id].role == "post_exploit_worker"
            for child_id in branch.child_ids
        ):
            return None
        if (
            branch.last_tool == "agent_graph"
            and "created" in str(branch.last_summary or "").lower()
            and "post_exploit_worker" in str(branch.last_summary or "").lower()
        ):
            return None

        parent_agent_id = ""
        parent_branch_id = str(branch.parent_branch_id or "").strip()
        if parent_branch_id.startswith("agent:"):
            parent_agent_id = parent_branch_id.removeprefix("agent:").split(":", 1)[0]
        task = f"Turn validated proof into crown-jewel impact: {branch.crown_jewel or branch.title}"
        args: dict[str, Any] = {
            "action": "create",
            "role": "post_exploit_worker",
            "task": task,
            "objective": str(branch.objective or task)[:160],
            "expected_artifact": (
                "valid EvidenceArtifact proving session reuse, privilege boundary, "
                "data access, or chain closure with control/payload/repro_steps"
            ),
            "stop_condition": (
                "stop after proving or refuting crown-jewel impact with valid EvidenceArtifact"
            ),
            "escalation_trigger": (
                "escalate if auth/session/crown path is blocked, ambiguous, or proof is missing"
            ),
            "skills": ["post_auth_enum"],
            "message": (
                f"Use prior proof from {parent_agent_id or branch.parent_branch_id}: "
                f"{str(branch.evidence or branch.last_report)[:220]}"
            ),
        }
        if parent_agent_id:
            args["parent_id"] = parent_agent_id
        return ("agent_graph", args)

    def _agent_graph_crown_report_action(
        self, branch: BranchState
    ) -> tuple[str, dict[str, Any]] | None:
        if not self.registry.has_tool("report_finding"):
            return None
        if str(branch.escalation_status or "").strip() != "needs_report":
            return None
        if str(branch.role or "").lower() != "post_exploit_worker":
            return None
        if branch.vector_id not in {"WEB-CROWN-PIVOT", "DESK-CROWN-PIVOT"}:
            return None
        args = self._agent_graph_crown_report_args(branch)
        if self._agent_graph_crown_report_already_exists(branch, args):
            return None
        return ("report_finding", args)

    def _agent_graph_crown_report_args(self, branch: BranchState) -> dict[str, Any]:
        text = " ".join(
            str(value or "")
            for value in (
                branch.title,
                branch.objective,
                branch.crown_jewel,
                branch.evidence,
                branch.last_report,
            )
        )
        lower = text.lower()
        component = self._agent_graph_crown_report_component(branch)
        finding_type = self._agent_graph_crown_report_type(branch)
        severity = (
            "critical"
            if any(token in lower for token in ("admin", "db dump", "database rows", "rce"))
            else "high"
        )
        crown = str(branch.crown_jewel or "crown-jewel impact").strip()
        title = f"Post-exploit crown impact: {crown}"
        poc = (
            f"Branch: {branch.id}\n"
            f"Crown jewel: {crown}\n"
            f"Component: {component}\n\n"
            f"{str(branch.evidence or branch.last_report or branch.objective)[:3600]}"
        )
        return self._build_report_finding_args(
            title=title[:140],
            severity=severity,
            finding_type=finding_type,
            affected_component=component,
            description=(
                "A post-exploit worker validated crown-jewel impact from a prior foothold "
                "using a structured EvidenceArtifact."
            ),
            impact=(
                f"The validated path reaches {crown}, converting the initial foothold into "
                "reportable business/security impact."
            ),
            technical_analysis=(
                "VXIS agent_graph marked the post_exploit_worker proof as valid and tied it "
                f"to branch {branch.id}. The evidence includes control/payload comparison, "
                "observed delta, and reproduction steps. post_exploit_worker report candidate."
            ),
            poc_description=(
                "Replay the EvidenceArtifact control, then replay the payload/session step, "
                "and compare the observed delta proving the crown-jewel impact."
            ),
            poc_script_code=poc,
            remediation_steps=(
                "Remove the foothold, enforce least-privilege authorization on the affected "
                "data/session boundary, add server-side access checks, and regression-test the "
                "recorded control/payload path."
            ),
            endpoint=component,
            method="",
            cwe="CWE-862" if finding_type == "broken_access_control" else "",
            extra_evidence=[
                {
                    "evidence_type": "agent_graph_evidence_artifact",
                    "title": f"{branch.id} post-exploit proof",
                    "content": poc[:3000],
                    "content_type": "text/plain",
                }
            ],
        )

    @staticmethod
    def _agent_graph_crown_report_type(branch: BranchState) -> str:
        text = " ".join(
            str(value or "")
            for value in (branch.crown_jewel, branch.title, branch.objective, branch.evidence)
        ).lower()
        if re.search(r"\b(?:rce|shell)\b|command execution", text):
            return "rce"
        if any(token in text for token in ("session", "token", "admin", "privilege", "role")):
            return "broken_access_control"
        if any(token in text for token in ("data", "database", "db dump", "row", "exfil")):
            return "broken_access_control"
        return "information_disclosure"

    def _agent_graph_crown_report_component(self, branch: BranchState) -> str:
        blob = " ".join(str(value or "") for value in (branch.evidence, branch.last_report))
        match = re.search(r"https?://[^\s|;,'\")]+", blob)
        if match:
            return match.group(0).rstrip(".,)")
        path = re.search(r"(/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=%-]+)", blob)
        if path:
            return path.group(1).rstrip(".,)")
        return str(self.state.target)

    @staticmethod
    def _agent_graph_crown_report_already_exists(
        branch: BranchState,
        args: dict[str, Any],
    ) -> bool:
        try:
            from vxis.agent.tools.finding_tools import _get_findings
        except Exception:
            return False
        finding_type = str(args.get("finding_type") or "").strip().lower()
        component = str(args.get("affected_component") or "").strip().rstrip("/")
        branch_id = str(branch.id or "")
        for finding in list(_get_findings() or []):
            if not isinstance(finding, dict):
                continue
            same_type = str(finding.get("finding_type") or "").strip().lower() == finding_type
            same_component = (
                str(finding.get("affected_component") or "").strip().rstrip("/") == component
            )
            blob = " ".join(
                str(finding.get(key) or "") for key in ("title", "description", "evidence")
            )
            if same_type and (same_component or branch_id in blob):
                return True
        return False

    @staticmethod
    def _agent_graph_branch_has_successful_child_evidence(branch: BranchState) -> bool:
        if branch.owner != "agent_graph":
            return False
        if str(branch.escalation_status or "").strip() == "needs_proof":
            return False
        text = " ".join(
            str(value or "") for value in (branch.next_step, branch.evidence, branch.last_report)
        ).lower()
        if any(
            token in text
            for token in (
                "proof is incomplete",
                "requires valid evidenceartifact",
                "proof: invalid",
            )
        ):
            return False
        return (
            "successful child execution is available" in text
            or "valid evidenceartifact is available" in text
        )

    def _declared_agent_graph_branch_skills(self, branch: BranchState) -> list[str]:
        if branch.owner != "agent_graph":
            return []
        allowed = self._platform_allowed_skills()
        declared: list[str] = []
        seen: set[str] = set()
        for raw in [
            *list(branch.watch_terms or []),
            branch.next_step,
            branch.objective,
            branch.title,
        ]:
            text = str(raw or "").strip().lower()
            if not text:
                continue
            candidates = [text] if text in allowed else []
            candidates.extend(skill for skill in allowed if skill in text)
            for skill in candidates:
                if skill and skill not in seen:
                    seen.add(skill)
                    declared.append(skill)
        return declared

    def _recent_blocked_skill_count(self, skill_name: str, *, window: int = 12) -> int:
        skill = str(skill_name).strip().lower()
        if not skill:
            return 0
        counted = int(self.state.blocked_skill_counts.get(skill, 0))
        total = 0
        for item in list(self.state.attempt_outcomes)[-window:]:
            if item.tool != "run_skill" or item.status != "blocked":
                continue
            if (
                f'"skill": "{skill}"' in item.args_preview
                or f"'skill': '{skill}'" in item.args_preview
            ):
                total += 1
        return max(total, counted)

    def _target_kind_name(self) -> str:
        try:
            return str(getattr(self._target_kind, "value", self._target_kind)).lower()
        except Exception:
            return "web"

    def _platform_allowed_skills(self) -> set[str]:
        all_tools = set(self.registry.list_tools())
        if "run_skill" not in all_tools:
            return set()
        kind = self._target_kind_name()
        if kind == "desktop":
            return set(_DESKTOP_SKILLS)
        if kind == "web":
            return {
                "enumerate_endpoints",
                "test_sensitive_files",
                "test_infra",
                "attempt_auth",
                "post_auth_enum",
                "test_injection",
                "test_xss",
                "test_ssrf",
                "test_idor",
                "test_auth_deep",
                "test_csrf",
                "test_misconfig",
                "test_api_security",
                "test_business_logic",
                "test_crypto",
            }
        if kind in {"mobile", "code", "game"}:
            return set()
        return set()

    def _platform_skill_pivot_graph(self) -> dict[str, tuple[str, ...]]:
        kind = self._target_kind_name()
        if kind == "desktop":
            return _DESKTOP_PIVOT_SKILL_GRAPH
        if kind == "web":
            return _WEB_PIVOT_SKILL_GRAPH
        return {}

    def _pivoted_skill_name(self, requested_skill: str) -> str:
        skill = str(requested_skill).strip().lower()
        if not skill:
            return ""
        allowed = self._platform_allowed_skills()
        if skill not in allowed:
            return ""
        graph = self._platform_skill_pivot_graph()
        blocked = self._recent_blocked_skill_count(skill)
        if blocked < 3:
            return skill
        for alt in graph.get(skill, ()):
            if alt in allowed and self._recent_blocked_skill_count(alt) < 3:
                return alt
        return ""

    def _normalize_skill_params(
        self, skill_name: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        skill = str(skill_name).strip().lower()
        normalized = dict(params or {})
        target = str(self.state.target)
        if skill in {"post_auth_enum", "test_idor"}:
            if not any(key in normalized for key in ("base_url", "url_pattern", "token")):
                normalized["base_url"] = target
            if skill == "test_idor":
                for key, value in self._latest_authz_context_params().items():
                    if value and key not in normalized:
                        normalized[key] = value
                if normalized.get("identities") and "max_id" not in normalized:
                    normalized["max_id"] = 30
        elif skill == "execute_chain":
            for key, value in self._latest_authz_context_params().items():
                if value and key not in normalized:
                    normalized[key] = value
            normalized.setdefault("template", "post_auth_crown")
        elif skill in {
            "test_injection",
            "test_xss",
            "test_ssrf",
            "test_api_security",
            "test_business_logic",
        }:
            if "url" not in normalized and "url_pattern" not in normalized:
                normalized["url"] = target
        return normalized

    def _known_surface_urls(self) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()

        def _remember(value: str) -> None:
            clean = str(value or "").strip()
            if not clean or clean in seen:
                return
            seen.add(clean)
            urls.append(clean)

        for message in self.state.messages:
            content = message.get("content", {})
            if not isinstance(content, dict):
                continue
            args = content.get("args", {})
            result = content.get("result", {})
            if isinstance(args, dict):
                for key in ("url", "target_url", "affected_component"):
                    if args.get(key):
                        _remember(str(args[key]))
            if isinstance(result, dict):
                data = result.get("data", {})
                if isinstance(data, dict):
                    for key in ("url", "affected_component"):
                        if data.get(key):
                            _remember(str(data[key]))
                    for ep in data.get("accessible", []) or []:
                        if isinstance(ep, dict) and ep.get("path"):
                            path = str(ep["path"])
                            if path.startswith("http"):
                                _remember(path)
                            else:
                                _remember(self.state.target.rstrip("/") + path)
        for finding in self.state.findings:
            component = str(finding.get("affected_component", "") or "")
            if component:
                _remember(component)
        return urls

    def _recent_skill_surface_counts(self, skill_name: str, *, window: int = 24) -> dict[str, int]:
        skill = str(skill_name).strip().lower()
        if not skill:
            return {}
        counts: dict[str, int] = {}
        for message in self.state.messages[-window:]:
            if message.get("role") != "tool":
                continue
            content = message.get("content", {})
            if not isinstance(content, dict) or content.get("name") != "run_skill":
                continue
            args = content.get("args", {})
            if not isinstance(args, dict):
                continue
            real_skill = str(args.get("skill") or "").strip().lower()
            if real_skill != skill:
                continue
            params = args.get("params", {}) if isinstance(args.get("params"), dict) else {}
            surface = str(
                params.get("url")
                or params.get("url_pattern")
                or params.get("base_url")
                or args.get("target_url")
                or ""
            ).strip()
            if not surface:
                continue
            counts[surface] = counts.get(surface, 0) + 1
        return counts

    def _surface_candidates_for_skill(self, skill_name: str, *, hint_blob: str = "") -> list[str]:
        skill = str(skill_name).strip().lower()
        target = str(self.state.target).rstrip("/")
        urls = self._known_surface_urls()
        blob = hint_blob.lower()
        seen: set[str] = set()
        ordered: list[str] = []

        def _push(url: str) -> None:
            clean = str(url or "").strip()
            if not clean or clean in seen:
                return
            seen.add(clean)
            ordered.append(clean)

        def _matches(url: str) -> bool:
            lower = url.lower()
            if skill == "test_injection":
                return "?" in lower and any(
                    token in lower for token in ("search", "login", "q=", "query", "filter")
                )
            if skill == "test_xss":
                return "?" in lower and any(
                    token in lower
                    for token in (
                        "search",
                        "q=",
                        "query",
                        "return",
                        "redirect",
                        "next",
                        "message",
                        "comment",
                    )
                )
            if skill == "test_ssrf":
                return any(
                    token in lower
                    for token in (
                        "url=",
                        "uri=",
                        "dest=",
                        "redirect",
                        "next=",
                        "callback",
                        "return",
                        "proxy",
                        "fetch",
                    )
                )
            if skill in {"test_api_security", "test_business_logic"}:
                return any(
                    token in lower
                    for token in ("/api/", "order", "cart", "checkout", "profile", "account")
                )
            return False

        if blob:
            for url in urls:
                lower = url.lower()
                if any(
                    token and token in lower
                    for token in re.split(r"[^a-z0-9_/.-]+", blob)
                    if len(token) >= 4
                ):
                    _push(url)

        for url in urls:
            if _matches(url):
                _push(url)
        for url in urls:
            if "?" in url:
                _push(url)
        if skill == "test_injection":
            _push(f"{target}/search?q=test")
        elif skill == "test_xss":
            _push(f"{target}/search?q=test")
            _push(f"{target}/redirect?next=/profile")
        elif skill == "test_ssrf":
            _push(f"{target}/redirect?url=http://example.com")
            _push(f"{target}/proxy?url=http://example.com")
        elif skill in {"test_api_security", "test_business_logic"}:
            _push(target)
        return ordered

    def _best_skill_params(self, skill_name: str, *, hint_blob: str = "") -> dict[str, Any]:
        skill = str(skill_name).strip().lower()
        target = str(self.state.target).rstrip("/")
        urls = self._known_surface_urls()
        blob = hint_blob.lower()

        def _pick(predicate: Callable[[str], bool]) -> str | None:
            for url in urls:
                lower = url.lower()
                if predicate(lower):
                    return url
            return None

        def _seed_paths(limit: int = 8) -> list[str]:
            seen: set[str] = set()
            out: list[str] = []
            for url in urls:
                parsed = urlparse(url)
                path = (parsed.path or "/").strip()
                if not path or path == "/":
                    continue
                if len(path) > 1:
                    path = path.rstrip("/")
                if path in seen:
                    continue
                seen.add(path)
                out.append(path)
                if len(out) >= limit:
                    break
            return out

        def _pick_untried(candidates: list[str]) -> str | None:
            recent = self._recent_skill_surface_counts(skill)
            scored = sorted(
                enumerate(candidates),
                key=lambda item: (recent.get(item[1], 0), item[0]),
            )
            return scored[0][1] if scored else None

        if skill == "test_injection":
            picked = _pick_untried(self._surface_candidates_for_skill(skill, hint_blob=blob)) or (
                _pick(
                    lambda u: (
                        "?" in u
                        and any(
                            token in u for token in ("search", "login", "q=", "query", "filter")
                        )
                    )
                )
                or _pick(lambda u: "?" in u)
                or f"{target}/search?q=test"
            )
            return {"url": picked}
        if skill == "test_xss":
            picked = _pick_untried(self._surface_candidates_for_skill(skill, hint_blob=blob)) or (
                _pick(
                    lambda u: (
                        "?" in u
                        and any(
                            token in u
                            for token in ("search", "q=", "query", "return", "redirect", "next")
                        )
                    )
                )
                or _pick(lambda u: "?" in u)
                or f"{target}/search?q=test"
            )
            return {"url": picked, "browser_confirm": True}
        if skill == "test_ssrf":
            picked = _pick_untried(self._surface_candidates_for_skill(skill, hint_blob=blob)) or (
                _pick(
                    lambda u: any(
                        token in u
                        for token in (
                            "url=",
                            "uri=",
                            "dest=",
                            "redirect",
                            "next=",
                            "callback",
                            "return",
                        )
                    )
                )
                or f"{target}/redirect?url=http://example.com"
            )
            return {"url": picked}
        if skill == "test_idor":
            picked = _pick(lambda u: bool(re.search(r"/\d+(?:/|$)", u)))
            token = self._latest_auth_token()
            authz_params = self._latest_authz_context_params()
            if picked:
                pattern = re.sub(r"/\d+(?=(/|$))", "/{id}", picked, count=1)
                params = {"url_pattern": pattern}
                if token:
                    params["token"] = token
                    params["max_id"] = 30
                params.update({k: v for k, v in authz_params.items() if v})
                if params.get("identities"):
                    params.setdefault("max_id", 30)
                return params
            params = {"base_url": target}
            if token:
                params["token"] = token
                params["max_id"] = 30
            params.update({k: v for k, v in authz_params.items() if v})
            if params.get("identities"):
                params.setdefault("max_id", 30)
            return params
        if skill in {"test_api_security", "test_business_logic"}:
            picked = (
                _pick(
                    lambda u: any(
                        token in u
                        for token in ("/api/", "order", "cart", "checkout", "profile", "account")
                    )
                )
                or target
            )
            params = {"url": picked}
            if skill == "test_business_logic":
                captured_flows = self._recent_captured_business_flows()
                if captured_flows:
                    params["captured_flows"] = captured_flows
            return params
        if skill == "execute_chain":
            token = self._latest_auth_token()
            params: dict[str, Any] = {
                "template": "post_auth_crown",
                "url_pattern": f"{target}/api/users/{{id}}",
            }
            if token:
                params["token"] = token
            params.update({k: v for k, v in self._latest_authz_context_params().items() if v})
            return params
        if skill == "post_auth_enum":
            return {"base_url": target}
        if skill == "test_infra":
            return {"seed_paths": _seed_paths()}
        return {}

    def _skill_supports_surface_retry(self, skill_name: str) -> bool:
        return str(skill_name).strip().lower() in {
            "test_injection",
            "test_xss",
            "test_ssrf",
            "test_api_security",
            "test_business_logic",
        }

    def _should_retry_skill_on_fresh_surface(
        self,
        skill_name: str,
        current_params: dict[str, Any] | None = None,
    ) -> bool:
        skill = str(skill_name).strip().lower()
        if not self._skill_supports_surface_retry(skill):
            return False
        params = dict(current_params or {})
        current_surface = str(
            params.get("url") or params.get("url_pattern") or params.get("base_url") or ""
        ).strip()
        alternatives = self._surface_candidates_for_skill(skill)
        if current_surface and any(surface != current_surface for surface in alternatives):
            return True
        fresh = self._best_skill_params(skill)
        next_surface = str(
            fresh.get("url") or fresh.get("url_pattern") or fresh.get("base_url") or ""
        ).strip()
        if not current_surface or not next_surface:
            return False
        return current_surface != next_surface

    def _alternate_surface_params(
        self,
        skill_name: str,
        current_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        skill = str(skill_name).strip().lower()
        params = dict(current_params or {})
        current_surface = str(
            params.get("url") or params.get("url_pattern") or params.get("base_url") or ""
        ).strip()
        for surface in self._surface_candidates_for_skill(skill):
            if surface and surface != current_surface:
                if skill == "test_idor":
                    return {"url_pattern": surface}
                if skill == "post_auth_enum":
                    return {"base_url": surface}
                return {"url": surface}
        return self._best_skill_params(skill)

    def _reroute_blocked_skill(
        self,
        requested_skill: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        skill = str(requested_skill).strip().lower()
        if not skill:
            return "", dict(params or {})
        if self._recent_blocked_skill_count(
            skill
        ) >= 3 and self._should_retry_skill_on_fresh_surface(skill, params):
            return skill, self._normalize_skill_params(
                skill, self._alternate_surface_params(skill, params)
            )
        rerouted = self._pivoted_skill_name(skill)
        if not rerouted:
            if self._recent_blocked_skill_count(skill) >= 3:
                return "", dict(params or {})
            rerouted = skill
        return rerouted, self._normalize_skill_params(rerouted, params)

    def _suggested_replan_action(
        self, rejection_title: str
    ) -> tuple[str, dict[str, Any], str] | None:
        title = str(rejection_title or "").strip().lower()
        if title == "needs_chains" and "link_chain" in self.registry.list_tools():
            candidates = self._suggest_chain_candidates(limit=1)
            if candidates:
                cand = candidates[0]
                return (
                    "link_chain",
                    {
                        "finding_ids": [cand["source_id"], cand["target_id"]],
                        "rationale": cand["rationale"],
                        "crown_jewel": cand["crown_jewel"],
                        "evidence_artifact": self._chain_evidence_artifact_for_ids(
                            cand["source_id"],
                            cand["target_id"],
                            cand,
                        ),
                    },
                    f"suggesting chain link {cand['source_id']} -> {cand['target_id']}",
                )
        if title == "unfinished_branches":
            focus = self._focus_branch()
            if focus is None:
                blockers = self._dag_finish_blocking_branches()
                focus = blockers[0] if blockers else None
            if focus is not None:
                forced = self._forced_branch_action(focus)
                if forced is not None:
                    return forced[0], forced[1], f"suggesting branch advancement on {focus.id}"
            try:
                from vxis.agent.tools.finding_tools import _get_findings

                findings = list(_get_findings() or [])
            except Exception:
                findings = []
            retryable_candidates = self._retryable_family_candidates(findings)
            if retryable_candidates:
                forced = self._forced_candidate_action(retryable_candidates[0])
                if forced is not None:
                    family = self._candidate_family(retryable_candidates[0])
                    return (
                        forced[0],
                        forced[1],
                        f"suggesting deeper retry on {family} family via {retryable_candidates[0].id}",
                    )
            family_candidates = self._dag_remaining_high_yield_candidates(findings)
            if family_candidates:
                forced = self._forced_candidate_action(family_candidates[0])
                if forced is not None:
                    family = self._candidate_family(family_candidates[0])
                    return (
                        forced[0],
                        forced[1],
                        f"suggesting remaining {family} family exploration via {family_candidates[0].id}",
                    )
        if title == "unattempted_candidates":
            try:
                from vxis.agent.tools.finding_tools import _get_findings

                findings = list(_get_findings() or [])
            except Exception:
                findings = []
            retryable_candidates = self._retryable_family_candidates(findings)
            if retryable_candidates:
                forced = self._forced_candidate_action(retryable_candidates[0])
                if forced is not None:
                    return (
                        forced[0],
                        forced[1],
                        f"suggesting retryable candidate {retryable_candidates[0].id}",
                    )
            open_candidates = self._dag_remaining_high_yield_candidates(findings)
            if open_candidates:
                forced = self._forced_candidate_action(open_candidates[0])
                if forced is not None:
                    return forced[0], forced[1], f"suggesting first attempt on {open_candidates[0].id}"
        return None

    @staticmethod
    def _chainable_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return findings that are realistic building blocks for attack chains."""
        try:
            from vxis.agent.tools.finding_tools import _canonical_finding_type
        except Exception:

            def _canonical_finding_type(value: str) -> str:
                return str(value or "").lower().strip()

        chainable_types = {
            "weak_auth",
            "information_disclosure",
            "misconfiguration",
            "broken_access_control",
            "idor",
            "sql_injection",
            "xss",
            "ssrf",
            "csrf",
            "insecure_deserialization",
            "command_injection",
            "path_traversal",
            "business_logic",
        }
        out: list[dict[str, Any]] = []
        for finding in findings:
            severity = str(finding.get("severity", "low")).lower()
            if severity not in {"critical", "high", "medium"}:
                continue
            ftype = _canonical_finding_type(str(finding.get("finding_type", "")))
            if ftype in chainable_types:
                out.append(finding)
        return out

    def _desired_chain_count(self, findings: list[dict[str, Any]]) -> int:
        chainable = self._chainable_findings(findings)
        if len(chainable) < 2:
            return 0
        if len(chainable) < 4:
            return 1
        return max(2, len(chainable) // 3)

    def _focus_branch(self) -> BranchState | None:
        active = self.state.active_branches()
        if not active:
            return None
        return active[0]

    def _llm_discipline_profile(self) -> str:
        provider = str(getattr(self.brain, "_provider", "") or "").lower()
        model = str(getattr(self.brain, "_model", "") or "").lower()
        if provider in {"llamacpp", "ollama"}:
            return "local_strict"
        if provider in {"openai", "anthropic", "gemini", "google"} and (
            any(
                token in model
                for token in (
                    "gpt-5.5",
                    "gpt-5.4",
                    "claude-opus",
                    "claude-sonnet",
                    "gemini-2.5-pro",
                )
            )
            or "opus" in model
            or "sonnet" in model
        ):
            return "frontier_loose"
        if provider:
            return "cloud_balanced"
        return "default"

    def _focus_grace_iterations(self) -> int:
        base = min(8, max(3, self.state.max_iters // 12))
        profile = self._llm_discipline_profile()
        if profile == "local_strict":
            return max(2, base - 2)
        if profile == "cloud_balanced":
            return min(10, base + 1)
        if profile == "frontier_loose":
            return min(12, base + 3)
        return base

    def _focus_drift_block_threshold(self) -> int:
        profile = self._llm_discipline_profile()
        if profile == "local_strict":
            return 2
        if profile == "cloud_balanced":
            return 3
        if profile == "frontier_loose":
            return 4
        return 2

    def _off_branch_capability_thresholds(self) -> tuple[int, int, int]:
        profile = self._llm_discipline_profile()
        if profile == "local_strict":
            return (18, 20, 14)
        if profile == "cloud_balanced":
            return (14, 18, 0)
        if profile == "frontier_loose":
            return (10, 16, 0)
        return (12, 18, 0)

    def _action_capability_score(self, name: str, args: dict[str, Any] | Any) -> int:
        capability = self._action_capability(name, args)
        return {
            "recon": 22,
            "plan": 18,
            "probe": 14,
            "browse": 12,
            "review": 10,
            "report": 8,
            "chain": 8,
            "exploit": 6,
            "retrieve": 6,
            "control": 4,
            "memory": 4,
        }.get(capability, 0)

    def _should_allow_off_branch_action(
        self,
        branch: BranchState | None,
        name: str,
        args: dict[str, Any] | Any,
        matched_branch_ids: list[str],
        matched_candidate_ids: list[str],
    ) -> bool:
        if branch is None:
            return True
        if name in {"finish_scan", "link_chain"}:
            return True
        findings_count = len(self.state.findings)
        cap_score = self._action_capability_score(name, args)
        grace_threshold, free_threshold, uncovered_family_floor = (
            self._off_branch_capability_thresholds()
        )
        if self.state.iteration <= self._focus_grace_iterations() and findings_count == 0:
            return cap_score >= grace_threshold
        if cap_score >= free_threshold:
            return True
        if matched_branch_ids and any(
            self._branch_same_campaign(branch, branch_id) for branch_id in matched_branch_ids
        ):
            return True
        if self._is_high_value_cross_campaign_exception(
            branch,
            matched_branch_ids=matched_branch_ids,
            matched_candidate_ids=matched_candidate_ids,
            capability_score=cap_score,
        ):
            return True
        if matched_candidate_ids:
            focus_family = self._branch_family(branch)
            for candidate_id in matched_candidate_ids:
                candidate = self.state.vector_candidates.get(candidate_id)
                if candidate is None:
                    continue
                candidate_family = self._candidate_family(candidate)
                if candidate_family != focus_family and candidate_family != "generic":
                    related = self._family_related_types(candidate_family)
                    found_types = {
                        str(item.get("finding_type", "")).strip().lower()
                        for item in self.state.findings
                        if isinstance(item, dict)
                    }
                    if not (related & found_types):
                        if uncovered_family_floor and cap_score < uncovered_family_floor:
                            continue
                        return True
        if matched_branch_ids and any(
            str(branch_id).startswith(("memory:", "carry:")) for branch_id in matched_branch_ids
        ):
            return True
        return False

    def _is_high_value_cross_campaign_exception(
        self,
        branch: BranchState,
        *,
        matched_branch_ids: list[str],
        matched_candidate_ids: list[str],
        capability_score: int,
    ) -> bool:
        if capability_score < 12:
            return False
        focus_family = self._branch_family(branch)
        if focus_family not in {"auth", "injection"}:
            return False
        if branch.role != "post_exploit_worker" and branch.phase not in {
            "session_reuse",
            "privilege_probe",
            "data_access",
        }:
            return False
        target_families: set[str] = set()
        for branch_id in matched_branch_ids:
            other = self.state.branches.get(branch_id)
            if other is None:
                continue
            target_families.add(self._branch_family(other))
        for candidate_id in matched_candidate_ids:
            candidate = self.state.vector_candidates.get(candidate_id)
            if candidate is None:
                continue
            target_families.add(self._candidate_family(candidate))
        target_families.discard("generic")
        target_families.discard(focus_family)
        if not target_families:
            return False
        if not (target_families & {"idor", "disclosure", "xss", "ssrf"}):
            return False
        try:
            from vxis.agent.tools.finding_tools import _canonical_finding_type as _canon_ft
        except Exception:

            def _canon_ft(value: object) -> str:
                return str(value or "").strip().lower()

        found_types = {
            _canon_ft(str(item.get("finding_type", "")))
            for item in self.state.findings
            if isinstance(item, dict)
        }
        if focus_family == "injection" and "sql_injection" not in found_types:
            return False
        if focus_family == "auth" and not ({"weak_auth", "sql_injection"} & found_types):
            return False
        return True

    @staticmethod
    def _branch_lineage_match(branch: BranchState, branch_id: str) -> bool:
        if not branch_id:
            return False
        return (
            branch_id == branch.id
            or branch_id.startswith(f"{branch.id}:")
            or branch.id.startswith(f"{branch_id}:")
        )

    def _branch_same_campaign(self, branch: BranchState, branch_id: str) -> bool:
        other = self.state.branches.get(branch_id)
        if other is None:
            return False
        if (
            branch.source_finding_id
            and other.source_finding_id
            and branch.source_finding_id == other.source_finding_id
        ):
            return True
        if (
            branch.parent_branch_id
            and other.parent_branch_id
            and branch.parent_branch_id == other.parent_branch_id
        ):
            return True
        if (
            branch.source_candidate_id
            and other.source_candidate_id
            and branch.source_candidate_id == other.source_candidate_id
        ):
            return True
        return False

    def _branch_focus_terms(self, branch: BranchState) -> list[str]:
        terms: list[str] = []
        terms.extend(branch.watch_terms or [])
        raw_fields = [
            branch.vector_id,
            branch.title,
            branch.objective,
            branch.next_step,
            branch.crown_jewel,
            branch.evidence,
        ]
        for field_value in raw_fields:
            blob = str(field_value or "").lower()
            if blob:
                terms.append(blob)
                terms.extend(
                    token
                    for token in re.findall(r"[a-z0-9_./:-]{4,}", blob)
                    if token
                    not in {
                        "http",
                        "https",
                        "with",
                        "then",
                        "into",
                        "from",
                        "that",
                        "this",
                        "real",
                        "impact",
                    }
                )
        deduped: list[str] = []
        seen: set[str] = set()
        for term in terms:
            clean = str(term).strip().lower()
            if len(clean) < 4 or clean in seen:
                continue
            seen.add(clean)
            deduped.append(clean)
        return deduped

    def _action_advances_focus_branch(
        self,
        branch: BranchState | None,
        name: str,
        args: dict[str, Any] | Any,
        matched_branch_ids: list[str],
    ) -> bool:
        if branch is None:
            return True
        if name in {"finish_scan", "link_chain"}:
            return True
        if not self._role_allows_action(branch.role, name, args):
            return False
        if not self._phase_allows_action(branch, name, args):
            return False
        if name == "report_finding":
            return bool(matched_branch_ids) or bool(
                branch.source_candidate_id or branch.source_finding_id
            )
        if any(self._branch_lineage_match(branch, branch_id) for branch_id in matched_branch_ids):
            return True
        blob = f"{name} {self._preview_args(args)}".lower()
        return any(term in blob for term in self._branch_focus_terms(branch))

    def _memory_profile(self) -> dict[str, Any]:
        profile = getattr(self, "_target_memory_profile", None)
        return profile if isinstance(profile, dict) else {}

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
            if mem_type == ftype and mem_component == component:
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
