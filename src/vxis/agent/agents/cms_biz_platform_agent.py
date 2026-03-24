"""L7 CMSBizPlatformAgent — WordPress, Drupal, Salesforce, SAP, SharePoint analysis."""

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

_NUCLEI_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


@register
class CMSBizPlatformAgent(BaseAgent):
    agent_id = "cms_biz_platform"
    description = "WordPress, Drupal, Salesforce, SAP, SharePoint CMS/business platform analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: CMS detection
        cms_info = await self._detect_cms(target)
        if cms_info:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"CMS detected: {cms_info['cms']} on {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.OSINT,
                description=f"CMS: {cms_info['cms']}, Version: {cms_info.get('version', 'unknown')}",
                response=json.dumps(cms_info, indent=2),
                tags=["cms", cms_info["cms"].lower()],
            ))

        # Phase 2: WPScan for WordPress
        wp_results = await self._run_wpscan(target)
        for wr in wp_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=wr["title"],
                severity=wr["severity"],
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=wr["description"],
                response=wr.get("detail", ""),
                tags=["cms", "wordpress"] + wr.get("tags", []),
            ))
            if wr["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"WordPress exploitation: {wr['title']}",
                    rationale=wr["description"],
                    probability=0.7, impact=0.85,
                    suggested_agent="web",
                ))

        # Phase 3: Nuclei CMS-specific templates
        nuclei_results = await self._run_nuclei_cms(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            severity = _NUCLEI_SEV_MAP.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", "")
            matched = nf.get("matched-at", target)
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{name} — {matched}",
                severity=severity,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["cms", "nuclei", nf.get("template-id", "")],
            ))
            if severity in (Severity.CRITICAL, Severity.HIGH):
                hypotheses.append(Hypothesis(
                    title=f"CMS exploit chain: {name}",
                    rationale=f"CMS vulnerability found: {name}",
                    probability=0.75, impact=0.9,
                    suggested_agent="web",
                ))

        # Phase 4: Business platform checks
        biz_results = await self._check_business_platforms(target)
        for br in biz_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=br["title"],
                severity=br["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=br["description"],
                response=br.get("detail", ""),
                tags=["cms", "business-platform"] + br.get("tags", []),
            ))
            if br["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Business platform data exposure on {target}",
                    rationale=br["description"],
                    probability=0.6, impact=0.9,
                    suggested_agent="api",
                ))

        # Phase 5: SharePoint specific checks
        sp_results = await self._check_sharepoint(target)
        for sr in sp_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=sr["title"],
                severity=sr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=sr["description"],
                tags=["cms", "sharepoint"],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "cms_detected": cms_info.get("cms") if cms_info else None,
                "wp_findings": len(wp_results),
            },
        )

    async def _detect_cms(self, target: str) -> dict[str, Any] | None:
        if not shutil.which("curl"):
            return None
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-L", target, "--max-time", "15",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            body = stdout.decode(errors="replace").lower()
            if "wp-content" in body or "wp-includes" in body:
                return {"cms": "WordPress"}
            elif "drupal" in body or "sites/default" in body:
                return {"cms": "Drupal"}
            elif "joomla" in body:
                return {"cms": "Joomla"}
            elif "sharepoint" in body or "/_layouts/" in body:
                return {"cms": "SharePoint"}
            elif "salesforce" in body or "force.com" in body:
                return {"cms": "Salesforce"}
            elif "/sap/" in body or "sap-ui" in body:
                return {"cms": "SAP"}
        except asyncio.TimeoutError:
            pass
        return None

    async def _run_wpscan(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("wpscan"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "wpscan", "--url", target, "--format", "json",
            "--enumerate", "vp,vt,u1-10",
            "--detection-mode", "mixed",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            data = json.loads(stdout.decode())
            results: list[dict[str, Any]] = []

            # Process vulnerabilities
            for vuln_type in ("main_theme", "plugins", "themes"):
                items = data.get(vuln_type, {})
                if isinstance(items, dict):
                    for name, info in items.items():
                        for vuln in info.get("vulnerabilities", []):
                            sev_str = vuln.get("severity", "medium")
                            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                                       "medium": Severity.MEDIUM, "low": Severity.LOW}
                            results.append({
                                "title": f"WP {vuln_type}: {vuln.get('title', name)}",
                                "severity": sev_map.get(sev_str, Severity.MEDIUM),
                                "description": vuln.get("title", ""),
                                "detail": json.dumps(vuln)[:2048],
                                "tags": ["wpscan", vuln_type],
                            })

            # Process users
            users = data.get("users", {})
            if users:
                usernames = list(users.keys())[:10]
                results.append({
                    "title": f"WordPress users enumerated: {', '.join(usernames)}",
                    "severity": Severity.LOW,
                    "description": f"Found {len(users)} WordPress users",
                    "tags": ["wpscan", "users"],
                })
            return results
        except (asyncio.TimeoutError, json.JSONDecodeError):
            return []

    async def _run_nuclei_cms(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "wordpress,drupal,joomla,sharepoint,sap,cms",
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

    async def _check_business_platforms(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        endpoints = [
            ("/api/v1/", "REST API", []),
            ("/services/data/", "Salesforce API", ["salesforce"]),
            ("/sap/bc/rest/", "SAP REST", ["sap"]),
            ("/sap/opu/odata/", "SAP OData", ["sap"]),
            ("/_api/web/lists", "SharePoint API", ["sharepoint"]),
            ("/sites/", "SharePoint Sites", ["sharepoint"]),
        ]
        for path, desc, tags in endpoints:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                f"{target}{path}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                status = stdout.decode().strip()
                if status in ("200", "301", "302"):
                    results.append({
                        "title": f"Business platform endpoint: {desc} at {path}",
                        "severity": Severity.MEDIUM,
                        "description": f"{desc} accessible at {target}{path} (HTTP {status})",
                        "tags": tags,
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_sharepoint(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        sp_paths = [
            "/_layouts/viewlsts.aspx",
            "/_vti_bin/owssvr.dll?Cmd=GetProjSchema",
            "/_api/web/siteusers",
        ]
        for path in sp_paths:
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
                    sev = Severity.HIGH if "siteusers" in path else Severity.MEDIUM
                    results.append({
                        "title": f"SharePoint endpoint exposed: {path}",
                        "severity": sev,
                        "description": f"SharePoint endpoint {path} accessible (HTTP {status})",
                    })
            except asyncio.TimeoutError:
                continue
        return results
