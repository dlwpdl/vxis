"""L7 CollaborationAgent — Slack, Teams, JIRA, Confluence, Notion, Zoom analysis."""

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
class CollaborationAgent(BaseAgent):
    agent_id = "collaboration"
    description = "Slack, Teams, JIRA, Confluence, Notion, Zoom collaboration platform analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Detect collaboration platforms
        platforms = await self._detect_platforms(target)
        for pf in platforms:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Collaboration platform: {pf['platform']} for {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.OSINT,
                description=pf["description"],
                response=pf.get("detail", ""),
                tags=["collaboration", pf["platform"].lower()],
            ))

        # Phase 2: Atlassian JIRA / Confluence exposure
        atlassian_results = await self._check_atlassian(target)
        for ar in atlassian_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=ar["title"],
                severity=ar["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=ar["description"],
                response=ar.get("detail", ""),
                tags=["collaboration", "atlassian"] + ar.get("tags", []),
            ))
            if ar["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Sensitive data exposure via Atlassian on {target}",
                    rationale=ar["description"],
                    probability=0.7, impact=0.8,
                    suggested_agent="osint",
                ))

        # Phase 3: Slack / Webhook exposure
        slack_results = await self._check_slack_exposure(target)
        for sr in slack_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=sr["title"],
                severity=sr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=sr["description"],
                response=sr.get("detail", ""),
                tags=["collaboration", "slack"],
            ))
            if sr["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Slack webhook abuse for {target}",
                    rationale="Exposed Slack webhook allows message injection",
                    probability=0.8, impact=0.7,
                    suggested_agent="third_party_webhook",
                ))

        # Phase 4: Exposed admin/management interfaces
        admin_results = await self._check_admin_interfaces(target)
        for ar in admin_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=ar["title"],
                severity=ar["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=ar["description"],
                tags=["collaboration", "admin-interface"],
            ))

        # Phase 5: Nuclei collaboration templates
        nuclei_results = await self._run_nuclei_collab(target, context.mission.stealth)
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
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["collaboration", "nuclei", nf.get("template-id", "")],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"platforms_detected": len(platforms)},
        )

    async def _detect_platforms(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("dig"):
            return []
        results: list[dict[str, Any]] = []
        # Check DNS for common collaboration platform CNAMEs
        platform_checks = [
            (f"jira.{target}", "JIRA"),
            (f"confluence.{target}", "Confluence"),
            (f"wiki.{target}", "Wiki/Confluence"),
            (f"slack.{target}", "Slack"),
            (f"teams.{target}", "Microsoft Teams"),
            (f"zoom.{target}", "Zoom"),
            (f"notion.{target}", "Notion"),
        ]
        for subdomain, platform in platform_checks:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "A", subdomain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                ip = stdout.decode().strip()
                if ip:
                    results.append({
                        "platform": platform,
                        "description": f"{platform} subdomain {subdomain} resolves to {ip}",
                        "detail": ip,
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_atlassian(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Check JIRA endpoints
        jira_checks = [
            (f"https://jira.{target}/rest/api/latest/serverInfo", "JIRA Server Info", ["jira"]),
            (f"https://jira.{target}/rest/api/latest/project", "JIRA Projects", ["jira"]),
            (f"https://{target}/rest/api/latest/serverInfo", "JIRA Server Info (root)", ["jira"]),
            (f"https://confluence.{target}/rest/api/space", "Confluence Spaces", ["confluence"]),
            (f"https://{target}/wiki/rest/api/space", "Confluence Spaces (wiki)", ["confluence"]),
        ]
        for url, desc, tags in jira_checks:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", url, "-w", "\n%{http_code}", "--max-time", "5",
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
                    sev = Severity.HIGH if "project" in url.lower() or "space" in url.lower() else Severity.MEDIUM
                    results.append({
                        "title": f"{desc} accessible",
                        "severity": sev,
                        "description": f"{desc} at {url} returns data without authentication",
                        "detail": body[:2048],
                        "tags": tags,
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_slack_exposure(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Look for slack webhook patterns in page source
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", f"https://{target}", "--max-time", "15",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            body = stdout.decode(errors="replace")
            import re
            # Slack webhook URLs
            slack_hooks = re.findall(r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+', body)
            for hook in set(slack_hooks[:3]):
                results.append({
                    "title": f"Slack webhook URL exposed on {target}",
                    "severity": Severity.HIGH,
                    "description": f"Slack incoming webhook found in page source: {hook[:50]}...",
                    "detail": hook,
                })
            # Slack API tokens
            slack_tokens = re.findall(r'xox[bpoas]-[0-9]+-[0-9A-Za-z-]+', body)
            for token in set(slack_tokens[:3]):
                results.append({
                    "title": f"Slack API token exposed on {target}",
                    "severity": Severity.CRITICAL,
                    "description": "Slack API token found in page source",
                    "detail": f"{token[:15]}...",
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_admin_interfaces(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        admin_paths = [
            ("/admin/", "Admin panel"),
            ("/administrator/", "Administrator panel"),
            ("/manage/", "Management interface"),
            ("/dashboard/", "Dashboard"),
        ]
        for path, desc in admin_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                f"https://{target}{path}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                status = stdout.decode().strip()
                if status in ("200", "301", "302"):
                    results.append({
                        "title": f"{desc} found at {path}",
                        "severity": Severity.MEDIUM,
                        "description": f"{desc} at {target}{path} (HTTP {status})",
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _run_nuclei_collab(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "jira,confluence,slack,teams,zoom,atlassian",
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
