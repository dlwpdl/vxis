from __future__ import annotations

from typing import Any

from vxis.agent.scan_loop_state import _TERMINAL_BRANCH_STATUSES, BranchState, VectorCandidate


class ScanLoopDecisionPolicyCampaignMixin:
    def _dedupe_blocking_campaign_branches(self, blockers: list[BranchState]) -> list[BranchState]:
        deduped: list[BranchState] = []
        seen: set[tuple[str, str]] = set()
        for branch in blockers:
            campaign_id = self._campaign_id_for_branch(branch)
            if campaign_id != branch.id:
                key = (campaign_id, branch.phase or "surface")
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

    @staticmethod
    def _campaign_id_for_branch(branch: BranchState) -> str:
        return str(
            branch.source_finding_id
            or branch.source_candidate_id
            or branch.parent_branch_id
            or branch.id
        )

    def _should_yield_to_live_agent_graph_child(self, branch: BranchState) -> bool:
        if branch.owner == "agent_graph":
            return False
        if str(branch.role or "").lower() != "post_exploit_worker":
            return False
        for child_id in branch.child_ids:
            child = self.state.branches.get(child_id)
            if child is None or child.status in _TERMINAL_BRANCH_STATUSES:
                continue
            if child.owner == "agent_graph":
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

    @staticmethod
    def _branch_has_open_crown_goal(branch: BranchState) -> bool:
        if not str(branch.crown_jewel or "").strip():
            return False
        if branch.attempts >= 4:
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
                self._campaign_id_for_branch(branch),
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
            focus_campaign_id = self._campaign_id_for_branch(focus)
            focus_family = self._branch_family(focus)
            for group in groups:
                campaign_id = str(group.get("campaign_id") or "")
                if campaign_id == focus_campaign_id:
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
