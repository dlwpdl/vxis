"""L7 BackupDRAgent — Backup file public access, NAS exposure, DR system analysis."""

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
    "/backup.sql.gz", "/db.sql", "/dump.sql", "/database.sql",
    "/site.zip", "/site.tar.gz", "/www.zip",
    "/.git", "/.svn", "/.env", "/.env.bak", "/.env.backup",
    "/wp-config.php.bak", "/config.php.bak",
    "/web.config.bak", "/web.config.old",
    "/.htpasswd", "/.htaccess.bak",
    "/server-status", "/server-info",
    "/data.zip", "/export.zip", "/archive.zip",
]


@register
class BackupDRAgent(BaseAgent):
    agent_id = "backup_dr"
    description = "Backup file exposure, NAS access, disaster recovery system analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Backup file exposure scan
        backup_results = await self._check_backup_files(target)
        for br in backup_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=br["title"],
                severity=br["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=br["description"],
                tags=["backup", "exposure", br.get("ext", "file")],
            ))
            if br["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Credential extraction from backup on {target}",
                    rationale=br["description"],
                    probability=0.8, impact=0.95,
                    suggested_agent="secrets_lifecycle",
                ))

        # Phase 2: NAS/storage exposure
        nas_results = await self._check_nas_exposure(target)
        for nr in nas_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=nr["title"],
                severity=nr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=nr["description"],
                response=nr.get("detail", ""),
                tags=["backup", "nas"] + nr.get("tags", []),
            ))
            if nr["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Data exfiltration via exposed NAS on {target}",
                    rationale=nr["description"],
                    probability=0.75, impact=0.9,
                    suggested_agent="data_exfiltration",
                ))

        # Phase 3: Source code VCS exposure
        vcs_results = await self._check_vcs_exposure(target)
        for vr in vcs_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=vr["title"],
                severity=vr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=vr["description"],
                tags=["backup", "source-code", "vcs"],
            ))
            if vr["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Source code analysis for vulns from {target}",
                    rationale="Source code repository accessible; enables whitebox analysis",
                    probability=0.85, impact=0.85,
                    suggested_agent="supply_chain",
                ))

        # Phase 4: DR infrastructure discovery
        dr_results = await self._check_dr_infra(target)
        for dr in dr_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=dr["title"],
                severity=dr["severity"],
                evidence_type=EvidenceType.NETWORK,
                description=dr["description"],
                tags=["backup", "disaster-recovery"],
            ))

        # Phase 5: Nuclei backup/exposure templates
        nuclei_results = await self._run_nuclei(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{nf.get('info', {}).get('name', '')} — {nf.get('matched-at', target)}",
                severity=sev_map.get(sev_str, Severity.INFO),
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["backup", "nuclei", nf.get("template-id", "")],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"exposed_files": len(backup_results)},
        )

    async def _check_backup_files(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        tasks = [self._probe_backup(target, p) for p in _BACKUP_PATHS]
        probe_results = await asyncio.gather(*tasks, return_exceptions=True)
        for path, result in zip(_BACKUP_PATHS, probe_results):
            if isinstance(result, dict) and result.get("exposed"):
                ext = path.split(".")[-1] if "." in path else "dir"
                sev = Severity.CRITICAL if any(
                    e in path for e in (".sql", ".zip", ".tar", ".env")
                ) else Severity.HIGH
                results.append({
                    "title": f"Backup file exposed: {target}{path} ({result.get('size', '?')} bytes)",
                    "severity": sev,
                    "description": f"Backup file at {path} is publicly accessible (HTTP {result.get('status')}, {result.get('size')} bytes)",
                    "ext": ext,
                })
        return results

    async def _probe_backup(self, target: str, path: str) -> dict[str, Any]:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-o", "/dev/null", "-w",
            '{"status":%{http_code},"size":%{size_download}}',
            f"{target}{path}", "--max-time", "5",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            info = json.loads(stdout.decode())
            if info.get("status") == 200 and info.get("size", 0) > 100:
                return {"exposed": True, "status": 200, "size": info["size"]}
        except (asyncio.TimeoutError, json.JSONDecodeError):
            pass
        return {"exposed": False}

    async def _check_nas_exposure(self, target: str) -> list[dict[str, Any]]:
        domain = target.lstrip("https://").lstrip("http://").split("/")[0]
        results: list[dict[str, Any]] = []
        if shutil.which("nmap"):
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-Pn", "-p", "111,2049,445,139",
                "--script", "nfs-showmount,smb-ls", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                output = stdout.decode()
                if "nfs-showmount" in output and "/" in output:
                    results.append({
                        "title": f"NFS shares exposed on {domain}",
                        "severity": Severity.HIGH,
                        "description": "NFS exports accessible, may contain backup data",
                        "detail": output[:2048],
                        "tags": ["nfs"],
                    })
                if "smb-ls" in output:
                    results.append({
                        "title": f"SMB shares on {domain}",
                        "severity": Severity.MEDIUM,
                        "description": "SMB/CIFS shares detected",
                        "detail": output[:2048],
                        "tags": ["smb"],
                    })
            except asyncio.TimeoutError:
                pass
        return results

    async def _check_vcs_exposure(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        vcs_paths = [
            ("/.git/HEAD", "Git"),
            ("/.svn/entries", "SVN"),
            ("/.hg/dirstate", "Mercurial"),
            ("/CVS/Root", "CVS"),
        ]
        for path, vcs in vcs_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", f"{target}{path}", "-w", "\n%{http_code}",
                "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                if status == "200" and len(body) > 5:
                    results.append({
                        "title": f"{vcs} repository exposed: {path}",
                        "severity": Severity.CRITICAL,
                        "description": f"{vcs} repository at {target}{path} is accessible",
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_dr_infra(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("dig"):
            return []
        results: list[dict[str, Any]] = []
        domain = target.lstrip("https://").lstrip("http://").split("/")[0]
        dr_subs = [f"dr.{domain}", f"backup.{domain}", f"failover.{domain}"]
        for sub in dr_subs:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "A", sub,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                ip = stdout.decode().strip()
                if ip:
                    results.append({
                        "title": f"DR infrastructure: {sub} -> {ip}",
                        "severity": Severity.INFO,
                        "description": f"Disaster recovery subdomain {sub} resolves to {ip}",
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _run_nuclei(self, target: str, stealth: bool) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-u", target,
            "-tags", "backup,exposure,git,svn,env-file",
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent",
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
