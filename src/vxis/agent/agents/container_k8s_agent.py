"""L7 ContainerK8sAgent — Docker escape, K8s RBAC, privilege escalation."""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class ContainerK8sAgent(BaseAgent):
    agent_id = "container_k8s"
    description = "Docker escape, K8s RBAC audit, container privilege escalation"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Trivy container image scanning
        trivy_results = await self._run_trivy(target)
        for tr in trivy_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=tr["title"],
                severity=tr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=tr["description"],
                cvss_score=tr.get("cvss"),
                response=tr.get("detail", ""),
                tags=["container", "trivy"] + tr.get("tags", []),
            ))
            if tr["severity"] in (Severity.CRITICAL, Severity.HIGH):
                hypotheses.append(Hypothesis(
                    title=f"Container escape via {tr['title']}",
                    rationale=f"Critical container vulnerability: {tr['title']}",
                    probability=0.6, impact=0.95,
                    suggested_agent="os_host",
                ))

        # Phase 2: kube-bench CIS benchmarks
        kubebench_results = await self._run_kube_bench()
        for kb in kubebench_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"K8s CIS: {kb['description']}",
                severity=kb["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=kb["detail"],
                tags=["container", "kubernetes", "cis", kb.get("section", "")],
            ))

        # Phase 3: Check exposed K8s/Docker endpoints
        k8s_endpoints = await self._check_k8s_endpoints(target)
        for ep in k8s_endpoints:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=ep["title"],
                severity=ep["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=ep["description"],
                response=ep.get("response", ""),
                tags=["container", "kubernetes", "exposed-api"],
            ))
            if ep["severity"] in (Severity.CRITICAL, Severity.HIGH):
                hypotheses.append(Hypothesis(
                    title=f"K8s cluster takeover via exposed API on {target}",
                    rationale=ep["description"],
                    probability=0.8, impact=1.0,
                    suggested_agent="container_k8s",
                ))

        # Phase 4: Docker API / registry exposure
        docker_results = await self._check_docker_exposure(target)
        for dr in docker_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=dr["title"],
                severity=dr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=dr["description"],
                response=dr.get("response", ""),
                tags=["container", "docker"] + dr.get("tags", []),
            ))
            if dr["severity"] in (Severity.CRITICAL, Severity.HIGH):
                hypotheses.append(Hypothesis(
                    title=f"Container breakout via Docker API on {target}",
                    rationale=dr["description"],
                    probability=0.85, impact=0.95,
                    suggested_agent="os_host",
                ))

        # Phase 5: Nuclei container/k8s templates
        nuclei_results = await self._run_nuclei_k8s(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", "")
            matched = nf.get("matched-at", target)
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{name} — {matched}",
                severity=severity,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["container", "nuclei", nf.get("template-id", "")],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "trivy_findings": len(trivy_results),
                "kubebench_findings": len(kubebench_results),
            },
        )

    async def _run_trivy(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("trivy"):
            return []
        # Scan for misconfigurations on the target
        proc = await asyncio.create_subprocess_exec(
            "trivy", "repo", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM",
            "--scanners", "misconfig,vuln", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            data = json.loads(stdout.decode())
            results: list[dict[str, Any]] = []
            sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                       "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
            for result_block in data.get("Results", []):
                for vuln in result_block.get("Vulnerabilities", []):
                    results.append({
                        "title": f"{vuln.get('VulnerabilityID', '')}: {vuln.get('Title', '')}",
                        "severity": sev_map.get(vuln.get("Severity", ""), Severity.INFO),
                        "description": vuln.get("Description", "")[:500],
                        "cvss": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                        "detail": json.dumps(vuln)[:2048],
                        "tags": ["cve", vuln.get("VulnerabilityID", "")],
                    })
                for misconfig in result_block.get("Misconfigurations", []):
                    results.append({
                        "title": misconfig.get("Title", ""),
                        "severity": sev_map.get(misconfig.get("Severity", ""), Severity.INFO),
                        "description": misconfig.get("Description", "")[:500],
                        "detail": json.dumps(misconfig)[:2048],
                        "tags": ["misconfig"],
                    })
            return results
        except (asyncio.TimeoutError, json.JSONDecodeError):
            return []

    async def _run_kube_bench(self) -> list[dict[str, Any]]:
        if not shutil.which("kube-bench"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "kube-bench", "run", "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            data = json.loads(stdout.decode())
            results: list[dict[str, Any]] = []
            for control in data.get("Controls", []):
                section = control.get("id", "")
                for test in control.get("tests", []):
                    for result in test.get("results", []):
                        if result.get("status") == "FAIL":
                            results.append({
                                "description": result.get("test_desc", ""),
                                "severity": Severity.HIGH if "critical" in result.get("scored", "") else Severity.MEDIUM,
                                "detail": result.get("remediation", ""),
                                "section": section,
                            })
            return results
        except (asyncio.TimeoutError, json.JSONDecodeError):
            return []

    async def _check_k8s_endpoints(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        k8s_paths = [
            (f"https://{target}:6443/api", "K8s API server"),
            (f"https://{target}:6443/api/v1/pods", "K8s pods listing"),
            (f"https://{target}:6443/api/v1/secrets", "K8s secrets listing"),
            (f"http://{target}:10250/pods", "Kubelet API"),
            (f"http://{target}:10255/pods", "Kubelet read-only API"),
            (f"http://{target}:8001/api", "kubectl proxy"),
            (f"http://{target}:2379/version", "etcd API"),
        ]
        for url, desc in k8s_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-k", url, "-w", "\n%{http_code}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                if status in ("200", "201", "401", "403"):
                    sev = Severity.CRITICAL if status == "200" and "secrets" in url else (
                        Severity.HIGH if status == "200" else Severity.MEDIUM
                    )
                    results.append({
                        "title": f"{desc} accessible: {url} (HTTP {status})",
                        "severity": sev,
                        "description": f"{desc} at {url} returns HTTP {status}",
                        "response": body[:2048],
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_docker_exposure(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        docker_endpoints = [
            (f"http://{target}:2375/version", "Docker API (unencrypted)"),
            (f"https://{target}:2376/version", "Docker API (TLS)"),
            (f"http://{target}:5000/v2/_catalog", "Docker Registry"),
            (f"http://{target}:5000/v2/", "Docker Registry API"),
        ]
        for url, desc in docker_endpoints:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-k", url, "-w", "\n%{http_code}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                if status == "200":
                    sev = Severity.CRITICAL if "2375" in url else Severity.HIGH
                    results.append({
                        "title": f"{desc} exposed: {url}",
                        "severity": sev,
                        "description": f"{desc} at {url} is publicly accessible",
                        "response": body[:2048],
                        "tags": ["docker-api" if "version" in url else "registry"],
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _run_nuclei_k8s(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "kubernetes,docker,k8s,container,etcd",
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1800)
        results: list[dict[str, Any]] = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results
