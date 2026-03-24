"""L7 SecretsLifecycleAgent — Git history, CI/CD vars, K8s Secrets scanning."""

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
class SecretsLifecycleAgent(BaseAgent):
    agent_id = "secrets_lifecycle"
    description = "Git history secrets, CI/CD variable exposure, K8s Secrets scanning"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: TruffleHog scan
        trufflehog_results = await self._run_trufflehog(target)
        for tf in trufflehog_results:
            detector = tf.get("DetectorName", "unknown")
            verified = tf.get("Verified", False)
            sev = Severity.CRITICAL if verified else Severity.HIGH

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Secret found: {detector}" + (" (VERIFIED)" if verified else ""),
                severity=sev,
                evidence_type=EvidenceType.SECRET,
                description=f"{'Verified' if verified else 'Unverified'} {detector} secret in target repository",
                response=json.dumps({k: v for k, v in tf.items() if k != "Raw"}, indent=2)[:4096],
                tags=["secrets", "trufflehog", detector.lower()],
            ))
            if verified:
                hypotheses.append(Hypothesis(
                    title=f"Lateral access via verified {detector} credential",
                    rationale=f"Live credential found for {detector}",
                    probability=0.9, impact=0.95,
                    suggested_agent="lateral_move",
                ))

        # Phase 2: Gitleaks scan
        gitleaks_results = await self._run_gitleaks(target)
        for gl in gitleaks_results:
            rule = gl.get("RuleID", gl.get("rule", "unknown"))
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Gitleaks: {rule} match",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.SECRET,
                description=f"Secret pattern matched by gitleaks rule: {rule}",
                response=json.dumps(gl, indent=2)[:4096],
                tags=["secrets", "gitleaks", rule.lower()],
            ))

        # Phase 3: Web-accessible secrets scan
        web_secrets = await self._check_web_secrets(target)
        for ws in web_secrets:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=ws["title"],
                severity=ws["severity"],
                evidence_type=EvidenceType.SECRET,
                description=ws["description"],
                response=ws.get("content", "")[:4096],
                tags=["secrets", "web-exposed"] + ws.get("tags", []),
            ))
            if ws["severity"] == Severity.CRITICAL:
                hypotheses.append(Hypothesis(
                    title=f"Infrastructure compromise via exposed secret on {target}",
                    rationale=ws["description"],
                    probability=0.85, impact=0.95,
                    suggested_agent="cloud",
                ))

        # Phase 4: Secret file exposure
        file_results = await self._check_secret_files(target)
        for fr in file_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=fr["title"],
                severity=fr["severity"],
                evidence_type=EvidenceType.SECRET,
                description=fr["description"],
                response=fr.get("content", "")[:4096],
                tags=["secrets", "file-exposure"],
            ))

        # Phase 5: Nuclei secret/exposure templates
        nuclei_results = await self._run_nuclei(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{nf.get('info', {}).get('name', '')} — {nf.get('matched-at', target)}",
                severity=sev_map.get(sev_str, Severity.INFO),
                evidence_type=EvidenceType.SECRET,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["secrets", "nuclei", nf.get("template-id", "")],
            ))

        # Phase 6: Environment variable / config exposure
        env_results = await self._check_env_exposure(target)
        for er in env_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=er["title"],
                severity=er["severity"],
                evidence_type=EvidenceType.SECRET,
                description=er["description"],
                response=er.get("content", "")[:4096],
                tags=["secrets", "env-exposure"],
            ))
            if er["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Credential harvesting from exposed env on {target}",
                    rationale=er["description"],
                    probability=0.8, impact=0.9,
                    suggested_agent="identity_ad",
                ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "trufflehog_secrets": len(trufflehog_results),
                "gitleaks_secrets": len(gitleaks_results),
                "total_secrets": len(findings),
            },
        )

    async def _run_trufflehog(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("trufflehog"):
            return []
        domain = target.lstrip("*.")
        org = domain.split(".")[0]
        cmd = ["trufflehog", "--json", "--no-update"]
        if target.startswith("http"):
            cmd.extend(["git", target])
        else:
            cmd.extend(["github", "--org", org])
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3600)
            results: list[dict[str, Any]] = []
            for line in stdout.decode(errors="replace").splitlines():
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return results
        except asyncio.TimeoutError:
            return []

    async def _run_gitleaks(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("gitleaks"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "gitleaks", "detect", "--source", ".",
            "--report-format", "json", "--report-path", "/dev/stdout",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            data = json.loads(stdout.decode()) if stdout.decode().strip() else []
            return data if isinstance(data, list) else []
        except (asyncio.TimeoutError, json.JSONDecodeError):
            return []

    async def _check_web_secrets(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", target, "--max-time", "15",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            body = stdout.decode(errors="replace")
            import re
            # AWS keys
            aws_keys = re.findall(r'AKIA[0-9A-Z]{16}', body)
            for key in set(aws_keys[:3]):
                results.append({
                    "title": f"AWS Access Key exposed on {target}",
                    "severity": Severity.CRITICAL,
                    "description": f"AWS Access Key ID found in page source: {key[:10]}...",
                    "content": f"Key: {key}",
                    "tags": ["aws"],
                })
            # Generic API keys
            api_keys = re.findall(
                r'(?:api[_-]?key|apikey|api_secret)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,60})["\']?',
                body, re.IGNORECASE,
            )
            for key in set(api_keys[:3]):
                results.append({
                    "title": f"API key exposed on {target}",
                    "severity": Severity.HIGH,
                    "description": "API key pattern found in page source",
                    "content": f"Key: {key[:15]}...",
                    "tags": ["api-key"],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_secret_files(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        secret_paths = [
            ("/.env", "Environment file"),
            ("/.env.local", "Local environment file"),
            ("/.env.production", "Production environment file"),
            ("/.git/config", "Git config"),
            ("/.git/HEAD", "Git HEAD"),
            ("/wp-config.php.bak", "WordPress config backup"),
            ("/.htpasswd", "htpasswd file"),
            ("/credentials.json", "Credentials file"),
            ("/config.yml", "YAML config"),
        ]
        for path, desc in secret_paths:
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
                if status == "200" and len(body) > 10:
                    has_secrets = any(
                        kw in body.lower()
                        for kw in ("password", "secret", "token", "key=", "api_key", "private")
                    )
                    sev = Severity.CRITICAL if has_secrets else Severity.HIGH
                    results.append({
                        "title": f"Secret file exposed: {desc} at {path}",
                        "severity": sev,
                        "description": f"{desc} at {target}{path} is publicly accessible",
                        "content": body[:4096],
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_env_exposure(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        env_endpoints = ["/actuator/env", "/api/debug/vars", "/debug/vars", "/phpinfo.php"]
        for path in env_endpoints:
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
                if status == "200" and len(body) > 50:
                    has_secrets = any(
                        kw in body.lower()
                        for kw in ("password", "secret", "token", "database_url")
                    )
                    sev = Severity.CRITICAL if has_secrets else Severity.HIGH
                    results.append({
                        "title": f"Environment exposure: {path}",
                        "severity": sev,
                        "description": f"Environment/config endpoint {path} exposed",
                        "content": body[:4096],
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
            "-tags", "exposure,token,secret,api-key,env",
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
