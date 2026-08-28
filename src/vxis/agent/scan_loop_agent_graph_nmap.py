from __future__ import annotations

import ast
from typing import Any

from vxis.agent.scan_loop_state import _TERMINAL_BRANCH_STATUSES
from vxis.agent.tool_registry import ToolResult


class ScanLoopAgentGraphNmapMixin:
    def _promote_agent_graph_nmap_result(
        self,
        result: ToolResult,
        *,
        child_args: dict[str, Any],
        child_result: ToolResult,
    ) -> bool:
        if not isinstance(child_result.data, dict):
            return False
        open_ports = self._nmap_open_ports_from_child_result(child_result)
        if not open_ports:
            return False
        agent = result.data.get("agent") if isinstance(result.data, dict) else {}
        parent_agent_id = str(agent.get("id") or child_result.data.get("agent_id") or "").strip()
        parent_branch_id = self._agent_graph_branch_id(parent_agent_id)
        if parent_branch_id not in self.state.branches:
            parent_branch_id = "root"

        promoted = False
        ranked_services = sorted(
            [item for item in open_ports if isinstance(item, dict)],
            key=self._nmap_service_priority,
            reverse=True,
        )[:5]
        for service in ranked_services:
            port = str(service.get("port") or "").strip()
            protocol = str(service.get("protocol") or "tcp").strip().lower() or "tcp"
            if not port:
                continue
            profile = self._nmap_service_followup_profile(service)
            branch_id = f"{parent_branch_id}:svc:{protocol}-{port}"
            host = str(
                service.get("host")
                or child_result.data.get("target")
                or child_args.get("target")
                or self.state.target
            )
            service_label = self._nmap_service_label(service)
            evidence = (
                f"nmap_scan {host}:{port}/{protocol} {service_label}; "
                f"reason={str(service.get('reason') or '')}"
            ).strip()
            branch = self.state.ensure_branch(
                branch_id,
                "NET-SERVICE-PIVOT",
                f"Probe {service_label} on {host}:{port}/{protocol}"[:120],
                priority=profile["priority"],
                role=profile["role"],
                phase="service_pivot",
                owner="root",
                parent_branch_id=parent_branch_id if parent_branch_id != "root" else "",
                source_candidate_id=parent_branch_id
                if parent_branch_id != "root"
                else "network:services",
                objective=profile["objective"],
                next_step=profile["next_step"],
                crown_jewel=profile["crown_jewel"],
                evidence=evidence,
                watch_terms=profile["watch_terms"],
            )
            if branch.status not in _TERMINAL_BRANCH_STATUSES:
                branch.status = "open"
            branch.last_tool = "nmap_scan"
            branch.last_summary = child_result.summary[:240]
            branch.last_report = evidence[:160]
            branch.last_iter = self.state.iteration
            todo = self.state.ensure_scan_todo(
                branch.id,
                branch.title,
                priority=branch.priority,
                source_candidate_id=branch.source_candidate_id or branch.id,
            )
            todo.status = "pending" if branch.status == "open" else todo.status
            todo.detail = branch.next_step[:120]
            todo.last_iter = self.state.iteration
            self.state.add_shared_note(
                f"nmap service pivot {host}:{port}/{protocol}: {service_label}"
            )
            promoted = True
        return promoted

    @staticmethod
    def _nmap_open_ports_from_child_result(child_result: ToolResult) -> list[dict[str, Any]]:
        if not isinstance(child_result.data, dict):
            return []
        raw_open_ports = child_result.data.get("open_ports")
        if isinstance(raw_open_ports, str):
            try:
                raw_open_ports = ast.literal_eval(raw_open_ports)
            except (SyntaxError, ValueError):
                raw_open_ports = []
        if not isinstance(raw_open_ports, list):
            return []
        return [dict(item) for item in raw_open_ports if isinstance(item, dict)]

    @staticmethod
    def _nmap_service_label(service: dict[str, Any]) -> str:
        parts = [
            str(service.get("service") or "unknown").strip(),
            str(service.get("product") or "").strip(),
            str(service.get("version") or "").strip(),
        ]
        return " ".join(part for part in parts if part).strip() or "unknown service"

    @staticmethod
    def _nmap_service_priority(service: dict[str, Any]) -> int:
        label = ScanLoopAgentGraphNmapMixin._nmap_service_label(service).lower()
        port = str(service.get("port") or "")
        if any(
            token in label
            for token in (
                "redis",
                "mongodb",
                "postgres",
                "mysql",
                "mssql",
                "oracle",
                "elasticsearch",
            )
        ):
            return 96
        if any(
            token in label
            for token in ("rdp", "vnc", "telnet", "ftp", "smb", "microsoft-ds", "nfs")
        ) or port in {"21", "23", "445", "3389", "5900"}:
            return 92
        if any(
            token in label
            for token in (
                "kubernetes",
                "docker",
                "etcd",
                "consul",
                "jenkins",
                "admin",
                "prometheus",
                "grafana",
            )
        ):
            return 91
        if "http" in label or port in {"80", "443", "8080", "8443", "8000", "9000"}:
            return 88
        if "ssh" in label or port == "22":
            return 84
        return 78

    @staticmethod
    def _nmap_service_followup_profile(service: dict[str, Any]) -> dict[str, Any]:
        label = ScanLoopAgentGraphNmapMixin._nmap_service_label(service).lower()
        port = str(service.get("port") or "")
        base_watch = [
            "nmap_scan",
            port,
            str(service.get("service") or ""),
            str(service.get("product") or ""),
        ]
        if any(
            token in label
            for token in (
                "kubernetes",
                "docker",
                "etcd",
                "consul",
                "jenkins",
                "prometheus",
                "grafana",
                "admin",
            )
        ):
            return {
                "priority": 94,
                "role": "exploit_worker",
                "objective": "Validate whether the exposed control-plane/admin service permits unauthenticated access or privilege-changing actions.",
                "next_step": f"Create an exploit_worker. Re-run nmap_scan on exact port {port or '<port>'}, then test only safe unauth/admin/API probes with control evidence.",
                "crown_jewel": "control-plane takeover or admin data access",
                "service_family": "control_plane",
                "recommended_scripts": "default,safe,vuln",
                "watch_terms": [
                    *base_watch,
                    "admin",
                    "control-plane",
                    "unauth",
                    "api",
                    "privilege",
                ],
            }
        if "http" in label or port in {"80", "443", "8080", "8443", "8000", "9000"}:
            return {
                "priority": 88,
                "role": "recon_worker",
                "objective": "Map the HTTP service, identify admin/API/auth surfaces, then hand off to exploit validation.",
                "next_step": f"Create a bounded agent_graph worker for this service. First re-run nmap_scan against exact port {port or '<port>'}, then use http_request/browser plus enumerate_endpoints/test_misconfig before reporting anything.",
                "crown_jewel": "admin route, API data, or service-side exploit path",
                "service_family": "http",
                "recommended_scripts": "default,http-title,http-headers",
                "watch_terms": [
                    *base_watch,
                    "http",
                    "api",
                    "admin",
                    "enumerate_endpoints",
                    "test_misconfig",
                ],
            }
        if any(
            token in label
            for token in (
                "redis",
                "mongodb",
                "postgres",
                "mysql",
                "mssql",
                "oracle",
                "elasticsearch",
            )
        ):
            return {
                "priority": 96,
                "role": "exploit_worker",
                "objective": "Determine whether the database service exposes unauthenticated access, weak auth, or data exposure.",
                "next_step": f"Create an exploit_worker. Re-run nmap_scan with safe/vuln scripts for exact port {port or '<port>'}, then prove no-auth/weak-auth data access or mark blocked with exact service evidence.",
                "crown_jewel": "database data exposure or credential material",
                "service_family": "database",
                "recommended_scripts": "default,safe,vuln",
                "watch_terms": [*base_watch, "database", "noauth", "credential", "dump", "data"],
            }
        if "ssh" in label or port == "22":
            return {
                "priority": 84,
                "role": "recon_worker",
                "objective": "Fingerprint SSH exposure and decide whether credential, weak-algorithm, or lateral-movement validation is warranted.",
                "next_step": f"Create a recon_worker. Re-run nmap_scan on exact port {port or '22'} with ssh2-enum-algos, then escalate only if concrete weak config or credential path exists.",
                "crown_jewel": "credential reuse or lateral movement",
                "service_family": "ssh",
                "recommended_scripts": "default,ssh2-enum-algos",
                "watch_terms": [*base_watch, "ssh", "credential", "algorithm", "lateral"],
            }
        if any(
            token in label
            for token in ("rdp", "vnc", "telnet", "ftp", "smb", "microsoft-ds", "nfs")
        ) or port in {"21", "23", "445", "3389", "5900"}:
            return {
                "priority": 92,
                "role": "exploit_worker",
                "objective": "Validate whether the remote/file service creates credential, file, or lateral-movement impact.",
                "next_step": f"Create an exploit_worker. Re-run nmap_scan on exact port {port or '<port>'} with safe scripts and service-specific controls; require transcript evidence before reporting.",
                "crown_jewel": "remote access, file disclosure, or lateral movement",
                "service_family": "remote_file",
                "recommended_scripts": "default,safe,vuln",
                "watch_terms": [*base_watch, "remote", "credential", "share", "lateral", "file"],
            }
        return {
            "priority": 78,
            "role": "recon_worker",
            "objective": "Fingerprint this exposed service and decide whether it warrants exploit validation.",
            "next_step": f"Create a bounded worker or re-run nmap_scan with safe scripts on exact port {port or '<port>'}; escalate only with concrete service evidence.",
            "crown_jewel": "service-specific exploit path",
            "service_family": "generic_service",
            "recommended_scripts": "default,safe",
            "watch_terms": [*base_watch, "service", "fingerprint"],
        }
