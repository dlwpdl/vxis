"""CRT-P11 QUICHttp3Agent — QUIC 0-RTT replay, Connection Migration, UDP firewall bypass."""

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
class QUICHttp3Agent(BaseAgent):
    agent_id = "quic_http3"
    description = (
        "QUIC 0-RTT replay attacks, Connection Migration abuse, HTTP/3, UDP firewall bypass"
    )

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        domain = target.lstrip("*.").split("/")[0].split(":")[0]

        # 1. Check if QUIC/HTTP3 is supported (Alt-Svc header)
        quic_supported = await self._check_quic_support(domain)
        if not quic_supported:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"QUIC/HTTP3 not detected on {domain}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description="No Alt-Svc h3 header or QUIC endpoint detected",
                    tags=["quic", "http3", "not-detected"],
                )
            )
            return AgentResult(
                agent_id=self.agent_id,
                findings=findings,
                hypotheses=hypotheses,
                status="completed",
                metadata={"quic_supported": False},
            )

        findings.append(
            Evidence(
                agent_id=self.agent_id,
                title=f"QUIC/HTTP3 enabled on {domain}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=f"QUIC/HTTP3 support detected: {quic_supported}",
                response=quic_supported,
                tags=["quic", "http3", "enabled"],
            )
        )

        # 2. UDP port scan for QUIC endpoints
        udp_findings = await self._scan_quic_ports(domain)
        findings.extend(udp_findings)

        # 3. Check for 0-RTT support (replay attack surface)
        zero_rtt = await self._check_0rtt(domain)
        if zero_rtt:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"QUIC 0-RTT enabled on {domain}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        "QUIC 0-RTT (early data) is enabled. 0-RTT data is "
                        "replayable — if non-idempotent operations accept 0-RTT, "
                        "replay attacks are possible."
                    ),
                    response=zero_rtt,
                    tags=["quic", "0-rtt", "replay"],
                )
            )
            hypotheses.append(
                Hypothesis(
                    title=f"0-RTT replay attack on {domain}",
                    rationale="QUIC 0-RTT enabled; early data can be replayed to "
                    "duplicate transactions or bypass rate limits",
                    probability=0.5,
                    impact=0.75,
                    suggested_agent="web",
                )
            )
            hypotheses.append(
                Hypothesis(
                    title=f"0-RTT state manipulation on {domain}",
                    rationale="If server accepts non-idempotent requests in 0-RTT, "
                    "state-changing operations can be replayed",
                    probability=0.4,
                    impact=0.8,
                    suggested_agent="api",
                )
            )

        # 4. Connection migration analysis
        findings.append(
            Evidence(
                agent_id=self.agent_id,
                title=f"QUIC Connection Migration surface on {domain}",
                severity=Severity.LOW,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    "QUIC supports connection migration across IP addresses. "
                    "If not properly validated, an attacker can hijack QUIC "
                    "connections by spoofing migration packets."
                ),
                tags=["quic", "connection-migration"],
            )
        )
        hypotheses.append(
            Hypothesis(
                title=f"QUIC connection hijacking via migration on {domain}",
                rationale="QUIC connection migration can be abused for session hijacking "
                "if path validation is weak",
                probability=0.3,
                impact=0.85,
                suggested_agent="network",
            )
        )

        # 5. UDP firewall bypass analysis
        hypotheses.append(
            Hypothesis(
                title=f"Firewall bypass via QUIC/UDP on {domain}",
                rationale="QUIC uses UDP/443; many firewalls and DPI systems "
                "cannot inspect QUIC encrypted payloads",
                probability=0.6,
                impact=0.7,
                suggested_agent="network",
            )
        )

        # 6. Nuclei HTTP/3 specific checks
        nuclei_results = await self._run_nuclei_http3(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", "")
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"{name} — {domain}",
                    severity=severity,
                    evidence_type=EvidenceType.HTTP_EXCHANGE,
                    description=nf.get("info", {}).get("description", ""),
                    request=nf.get("request"),
                    response=nf.get("response"),
                    tags=["quic", "http3", "nuclei", nf.get("template-id", "")],
                )
            )

        # 7. Version negotiation / downgrade hypothesis
        hypotheses.append(
            Hypothesis(
                title=f"QUIC version downgrade attack on {domain}",
                rationale="If server supports multiple QUIC versions, "
                "version negotiation may be manipulated",
                probability=0.3,
                impact=0.6,
                suggested_agent="crypto_tls",
            )
        )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"quic_supported": True},
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _check_quic_support(self, domain: str) -> str:
        """Check for QUIC/HTTP3 via Alt-Svc header or curl --http3."""
        if shutil.which("curl"):
            # Check Alt-Svc header
            proc = await asyncio.create_subprocess_exec(
                "curl",
                "-s",
                "-I",
                "-m",
                "10",
                f"https://{domain}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                headers = stdout.decode()
                for line in headers.splitlines():
                    if "alt-svc" in line.lower() and "h3" in line.lower():
                        return line.strip()
            except asyncio.TimeoutError:
                pass

            # Try curl --http3 if available
            proc = await asyncio.create_subprocess_exec(
                "curl",
                "-s",
                "--http3",
                "-I",
                "-m",
                "10",
                f"https://{domain}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
                if proc.returncode == 0 and stdout:
                    return "HTTP/3 direct connection successful"
            except asyncio.TimeoutError:
                pass

        return ""

    async def _scan_quic_ports(self, domain: str) -> list[Evidence]:
        """Scan for QUIC UDP endpoints."""
        if not shutil.which("nmap"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "-sU",
            "-p",
            "443,8443,4433",
            "-sV",
            "-oX",
            "-",
            domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            findings: list[Evidence] = []
            if 'state="open"' in output:
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"QUIC UDP ports open on {domain}",
                        severity=Severity.INFO,
                        evidence_type=EvidenceType.NETWORK,
                        description="UDP ports for QUIC protocol are accessible",
                        response=output[:4096],
                        tags=["quic", "udp", "portscan"],
                    )
                )
            return findings
        except asyncio.TimeoutError:
            return []

    async def _check_0rtt(self, domain: str) -> str:
        """Check for QUIC/TLS 1.3 0-RTT support."""
        if not shutil.which("openssl"):
            return ""
        # TLS 1.3 early data check (QUIC uses TLS 1.3)
        proc = await asyncio.create_subprocess_exec(
            "openssl",
            "s_client",
            "-connect",
            f"{domain}:443",
            "-tls1_3",
            "-servername",
            domain,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=b""),
                timeout=10,
            )
            combined = stdout.decode() + stderr.decode()
            if "early data" in combined.lower() or "0-rtt" in combined.lower():
                return combined[:2048]
        except asyncio.TimeoutError:
            pass
        return ""

    async def _run_nuclei_http3(
        self,
        target: str,
        stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "60"
        cmd = [
            "nuclei",
            "-u",
            target,
            "-tags",
            "http,quic,h3,http3",
            "-severity",
            "critical,high,medium",
            "-rate-limit",
            rate,
            "-jsonl",
            "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=900)
            results = []
            for line in stdout.decode().splitlines():
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return results
        except asyncio.TimeoutError:
            return []
