"""L7 SupplyChainAgent — Deps CVE, Dependency Confusion, CI/CD, SBOM analysis."""

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
class SupplyChainAgent(BaseAgent):
    agent_id = "supply_chain"
    description = "Dependency CVEs, Dependency Confusion, CI/CD pipeline, SBOM analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Trivy dependency scanning
        trivy_results = await self._run_trivy(target)
        for tr in trivy_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=tr["title"],
                severity=tr["severity"],
                evidence_type=EvidenceType.CODE_FINDING,
                description=tr["description"],
                cvss_score=tr.get("cvss"),
                response=tr.get("detail", ""),
                tags=["supply-chain", "dependency", "cve"] + tr.get("tags", []),
            ))
            if tr["severity"] in (Severity.CRITICAL, Severity.HIGH):
                hypotheses.append(Hypothesis(
                    title=f"Exploit vulnerable dependency: {tr['title']}",
                    rationale=f"Critical dependency vulnerability: {tr['title']}",
                    probability=0.65, impact=0.85,
                    suggested_agent="web",
                    suggested_tool="nuclei",
                ))

        # Phase 2: Snyk vulnerability check
        snyk_results = await self._run_snyk(target)
        for sr in snyk_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=sr["title"],
                severity=sr["severity"],
                evidence_type=EvidenceType.CODE_FINDING,
                description=sr["description"],
                tags=["supply-chain", "snyk"] + sr.get("tags", []),
            ))

        # Phase 3: CI/CD exposure checks
        cicd_results = await self._check_cicd_exposure(target)
        for cr in cicd_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=cr["title"],
                severity=cr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=cr["description"],
                response=cr.get("response", ""),
                tags=["supply-chain", "cicd"] + cr.get("tags", []),
            ))
            if cr["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"CI/CD pipeline compromise on {target}",
                    rationale=cr["description"],
                    probability=0.7, impact=0.95,
                    suggested_agent="secrets_lifecycle",
                ))

        # Phase 4: Dependency confusion checks
        depconf_results = await self._check_dependency_confusion(target)
        for dc in depconf_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=dc["title"],
                severity=dc["severity"],
                evidence_type=EvidenceType.CODE_FINDING,
                description=dc["description"],
                tags=["supply-chain", "dependency-confusion"],
            ))
            if dc["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Dependency confusion attack on {target}",
                    rationale="Internal package names may be claimable on public registries",
                    probability=0.55, impact=0.9,
                    suggested_agent="supply_chain",
                ))

        # Phase 5: Package manifest exposure
        manifest_results = await self._check_manifest_exposure(target)
        for mr in manifest_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=mr["title"],
                severity=mr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=mr["description"],
                response=mr.get("content", "")[:4096],
                tags=["supply-chain", "manifest-exposure"],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "trivy_vulns": len(trivy_results),
                "snyk_vulns": len(snyk_results),
                "cicd_exposures": len(cicd_results),
            },
        )

    async def _run_trivy(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("trivy"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "trivy", "repo", "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM",
            "--scanners", "vuln", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            data = json.loads(stdout.decode())
            results: list[dict[str, Any]] = []
            sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                       "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
            for block in data.get("Results", []):
                for vuln in block.get("Vulnerabilities", []):
                    results.append({
                        "title": f"{vuln.get('VulnerabilityID', '')}: {vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')}",
                        "severity": sev_map.get(vuln.get("Severity", ""), Severity.INFO),
                        "description": vuln.get("Title", vuln.get("Description", ""))[:500],
                        "cvss": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                        "detail": json.dumps(vuln)[:2048],
                        "tags": [vuln.get("VulnerabilityID", "")],
                    })
            return results
        except (asyncio.TimeoutError, json.JSONDecodeError):
            return []

    async def _run_snyk(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("snyk"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "snyk", "test", "--json", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            data = json.loads(stdout.decode())
            results: list[dict[str, Any]] = []
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            for vuln in data.get("vulnerabilities", []):
                results.append({
                    "title": f"{vuln.get('id', '')}: {vuln.get('packageName', '')}",
                    "severity": sev_map.get(vuln.get("severity", ""), Severity.INFO),
                    "description": vuln.get("title", "")[:500],
                    "tags": [vuln.get("id", "")],
                })
            return results
        except (asyncio.TimeoutError, json.JSONDecodeError):
            return []

    async def _check_cicd_exposure(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        cicd_paths = [
            ("/.github/workflows/", "GitHub Actions workflows"),
            ("/.gitlab-ci.yml", "GitLab CI config"),
            ("/Jenkinsfile", "Jenkinsfile"),
            ("/.circleci/config.yml", "CircleCI config"),
            ("/.travis.yml", "Travis CI config"),
            ("/bitbucket-pipelines.yml", "Bitbucket Pipelines"),
            ("/azure-pipelines.yml", "Azure DevOps Pipelines"),
            ("/.drone.yml", "Drone CI config"),
        ]
        for path, desc in cicd_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/stdout", "-w", "\n%{http_code}",
                f"{target}{path}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                if status == "200" and len(body) > 20:
                    sev = Severity.HIGH if any(kw in body.lower() for kw in ("secret", "token", "password", "key")) else Severity.MEDIUM
                    results.append({
                        "title": f"CI/CD config exposed: {desc} at {path}",
                        "severity": sev,
                        "description": f"{desc} publicly accessible at {target}{path}",
                        "response": body[:2048],
                        "tags": ["cicd-config"],
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_dependency_confusion(self, target: str) -> list[dict[str, Any]]:
        """Check for package manifests that may reveal internal package names."""
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        manifests = [
            ("/package.json", "npm"),
            ("/requirements.txt", "pip"),
            ("/Gemfile", "rubygems"),
            ("/go.mod", "go"),
            ("/pom.xml", "maven"),
        ]
        for path, registry in manifests:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", f"{target}{path}", "-w", "\n%{http_code}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                if status == "200" and len(body) > 20:
                    # Check for scoped/internal packages
                    has_internal = any(
                        indicator in body
                        for indicator in ("@internal", "@private", "internal-", "company-")
                    )
                    sev = Severity.HIGH if has_internal else Severity.MEDIUM
                    results.append({
                        "title": f"Package manifest exposed ({registry}): {path}",
                        "severity": sev,
                        "description": (
                            f"Exposed {registry} manifest at {path}. "
                            + ("Internal package names found — dependency confusion risk." if has_internal else "")
                        ),
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_manifest_exposure(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        lock_files = [
            "/package-lock.json", "/yarn.lock", "/Pipfile.lock",
            "/composer.lock", "/Cargo.lock",
        ]
        for path in lock_files:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                f"{target}{path}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                status = stdout.decode().strip()
                if status == "200":
                    results.append({
                        "title": f"Lock file exposed: {path}",
                        "severity": Severity.LOW,
                        "description": f"Dependency lock file at {target}{path} reveals exact versions",
                    })
            except asyncio.TimeoutError:
                continue
        return results
