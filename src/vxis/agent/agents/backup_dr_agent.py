"""L7-29 BackupDRAgent — Backup file public access, NAS, DR systems."""

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

_BACKUP_PATHS = [
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/dump.sql", "/database.sql",
    "/.git", "/.svn", "/.env", "/.env.bak", "/.env.backup",
    "/wp-config.php.bak", "/config.php.bak",
    "/web.config.bak", "/web.config.old",
    "/.htpasswd", "/.htaccess.bak",
    "/server-status", "/server-info",
]


@register
class BackupDRAgent(BaseAgent):
    agent_id = "backup_dr"
    description = "Backup file exposure, NAS access, DR system security"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        if shutil.which("curl"):
            tasks = [self._probe(target, p) for p in _BACKUP_PATHS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for path, result in zip(_BACKUP_PATHS, results):
                if isinstance(result, dict) and result.get("exposed"):
                    sev = Severity.CRITICAL if any(ext in path for ext in (".sql", ".zip", ".tar", ".env")) else Severity.HIGH
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"Backup/sensitive file exposed: {target}{path}",
                        severity=sev,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description=f"Backup or sensitive file accessible at {path} (HTTP {result.get('status')}, {result.get('size')} bytes)",
                        tags=["backup", "exposure", path.split(".")[-1] if "." in path else "dir"],
                    ))

        # Nuclei backup/exposure templates
        nuclei_results = await self._run_nuclei(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{nf.get('info', {}).get('name', '')} — {nf.get('matched-at', target)}",
                severity=sev_map.get(sev_str, Severity.INFO),
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=nf.get("info", {}).get("description", ""),
                tags=["backup", "nuclei"],
            ))

        if findings:
            hypotheses.append(Hypothesis(
                title=f"Credential / DB extraction from backup files on {target}",
                rationale=f"{len(findings)} backup/sensitive files exposed",
                probability=0.85, impact=0.95,
                suggested_agent="secrets_lifecycle",
            ))

        return AgentResult(
            agent_id=self.agent_id, findings=findings, hypotheses=hypotheses,
            status="completed", metadata={"exposed_files": len(findings)},
        )

    async def _probe(self, target: str, path: str) -> dict[str, Any]:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-o", "/dev/null", "-w", '{"status":%{http_code},"size":%{size_download}}',
            f"{target}{path}", "--max-time", "5",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            info = json.loads(stdout.decode())
            if info.get("status") == 200 and info.get("size", 0) > 100:
                return {"exposed": True, "status": 200, "size": info["size"]}
        except (asyncio.TimeoutError, json.JSONDecodeError, ValueError):
            pass
        return {"exposed": False}

    async def _run_nuclei(self, target: str, stealth: bool) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-u", target, "-tags", "backup,exposure,git,svn,env-file",
            "-severity", "critical,high,medium", "-rate-limit", rate, "-jsonl", "-silent",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
        results = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results
