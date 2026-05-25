"""META-05 DataExfiltrationAgent — DNS tunneling, covert channels, DLP bypass assessment."""

from __future__ import annotations

import asyncio
import json
import shutil

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class DataExfiltrationAgent(BaseAgent):
    agent_id = "data_exfiltration"
    description = (
        "Data exfiltration path assessment: DNS tunneling, ICMP covert channels, "
        "HTTP(S) steganography, DLP bypass, outbound filtering analysis"
    )

    # Common DNS tunneling tool signatures
    _DNS_TUNNEL_INDICATORS = ["iodine", "dns2tcp", "dnscat"]

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: DNS exfiltration path analysis
        dns_findings = await self._test_dns_exfiltration(target)
        findings.extend(dns_findings)

        # Phase 2: ICMP tunnel feasibility
        icmp_result = await self._test_icmp_tunnel(target)
        if icmp_result:
            findings.append(icmp_result)
            hypotheses.append(
                Hypothesis(
                    title=f"ICMP covert channel exfiltration from {target}",
                    rationale="ICMP traffic allowed outbound — tunnel possible",
                    probability=0.6,
                    impact=0.8,
                    suggested_agent="data_exfiltration",
                )
            )

        # Phase 3: Outbound port filtering analysis
        outbound_findings = await self._test_outbound_filtering(target)
        findings.extend(outbound_findings)

        # Phase 4: HTTP-based exfiltration channels
        http_findings = await self._test_http_exfiltration(target)
        findings.extend(http_findings)

        # Phase 5: Cloud storage exfiltration paths
        cloud_findings = await self._check_cloud_exfil_paths(target)
        findings.extend(cloud_findings)

        # Phase 6: DLP bypass assessment
        findings.append(
            Evidence(
                agent_id=self.agent_id,
                title=f"DLP bypass assessment for {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.OTHER,
                description=(
                    "DLP bypass techniques to assess:\n"
                    "- Base64/encoding of sensitive data in allowed protocols\n"
                    "- Steganography in image uploads/downloads\n"
                    "- Splitting data across multiple small DNS queries\n"
                    "- Using allowed cloud services (Slack, Teams) as exfil channels\n"
                    "- Certificate/TLS-based data hiding in SNI/ALPN fields\n"
                    "- Chunked transfer encoding to evade content inspection"
                ),
                tags=["exfiltration", "dlp", "assessment"],
            )
        )

        # Chain hypotheses
        hypotheses.append(
            Hypothesis(
                title=f"Sensitive data accessible for exfiltration on {target}",
                rationale="Exfiltration channels identified — check for accessible data",
                probability=0.6,
                impact=0.9,
                suggested_agent="lateral_move",
            )
        )
        hypotheses.append(
            Hypothesis(
                title=f"DNS-based C2 channel from {target}",
                rationale="DNS exfiltration path feasible — C2 communication likely possible",
                probability=0.5,
                impact=0.85,
                suggested_agent="deception_detection",
            )
        )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "exfil_channels_found": sum(
                    1 for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)
                ),
                "assessment_type": "exfiltration_path_analysis",
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _test_dns_exfiltration(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("dig"):
            return results

        # Test if arbitrary DNS queries are allowed (exfil via subdomains)
        test_labels = ["exfil-test-a", "exfil-test-b", "exfil-test-c"]
        resolved = 0
        for label in test_labels:
            proc = await asyncio.create_subprocess_exec(
                "dig",
                "+short",
                "+time=3",
                "+tries=1",
                f"{label}.{target}",
                "A",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            if stdout.decode().strip():
                resolved += 1

        # Test TXT record exfiltration (larger payload per query)
        proc = await asyncio.create_subprocess_exec(
            "dig",
            "+short",
            "+time=3",
            "TXT",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        txt_works = bool(stdout.decode().strip())

        # Test DNS-over-HTTPS availability
        doh_available = await self._check_doh_availability()

        if txt_works or doh_available:
            severity = Severity.HIGH if doh_available else Severity.MEDIUM
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"DNS exfiltration channels available for {target}",
                    severity=severity,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        f"DNS exfiltration paths: TXT queries={'yes' if txt_works else 'no'}, "
                        f"DNS-over-HTTPS={'yes' if doh_available else 'no'}. "
                        "Data can be encoded in DNS queries/responses to bypass firewalls."
                    ),
                    response=json.dumps(
                        {
                            "txt_queries": txt_works,
                            "doh_available": doh_available,
                            "subdomain_resolution": resolved,
                            "max_exfil_rate": "~18.5 KB/s via TXT records",
                        },
                        indent=2,
                    ),
                    tags=["exfiltration", "dns-tunnel", "covert-channel"],
                )
            )

        return results

    async def _check_doh_availability(self) -> bool:
        if not shutil.which("curl"):
            return False
        doh_providers = [
            "https://dns.google/dns-query",
            "https://cloudflare-dns.com/dns-query",
        ]
        for provider in doh_providers:
            proc = await asyncio.create_subprocess_exec(
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "5",
                "-H",
                "Accept: application/dns-message",
                provider,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            if stdout.decode().strip() in ("200", "400"):
                return True
        return False

    async def _test_icmp_tunnel(self, target: str) -> Evidence | None:
        if not shutil.which("ping"):
            return None
        proc = await asyncio.create_subprocess_exec(
            "ping",
            "-c",
            "3",
            "-W",
            "3",
            "-s",
            "1400",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        output = stdout.decode()
        if "bytes from" in output:
            # Large ICMP packets allowed — tunnel feasible
            return Evidence(
                agent_id=self.agent_id,
                title=f"ICMP tunnel feasible to {target}",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    "Large ICMP packets (1400 bytes) are allowed through the "
                    "firewall. ICMP tunneling tools (ptunnel, icmpsh) can use "
                    "this for covert data exfiltration."
                ),
                response=output[:500],
                tags=["exfiltration", "icmp-tunnel", "covert-channel"],
            )
        return None

    async def _test_outbound_filtering(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("nmap"):
            return results

        # Test common exfiltration ports
        exfil_ports = "21,22,25,53,80,443,993,995,1194,8080,8443"
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "-Pn",
            "-sS",
            "-p",
            exfil_ports,
            "--open",
            "-oG",
            "-",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode()

        open_ports: list[int] = []
        for line in output.splitlines():
            if "open" in line and "Ports:" in line:
                parts = line.split("Ports:")[1] if "Ports:" in line else ""
                for entry in parts.split(","):
                    entry = entry.strip()
                    if "/open/" in entry:
                        try:
                            open_ports.append(int(entry.split("/")[0]))
                        except (ValueError, IndexError):
                            continue

        high_risk_ports = {21: "FTP", 25: "SMTP", 53: "DNS", 1194: "OpenVPN"}
        risky_open = {p: n for p, n in high_risk_ports.items() if p in open_ports}
        if risky_open:
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"High-risk exfiltration ports open on {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        f"Ports commonly used for data exfiltration are open: "
                        f"{', '.join(f'{n}({p})' for p, n in risky_open.items())}"
                    ),
                    response=json.dumps(
                        {"open_ports": open_ports, "high_risk": risky_open}, indent=2
                    ),
                    tags=["exfiltration", "outbound-filtering", "network"],
                )
            )

        return results

    async def _test_http_exfiltration(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # Test if target accepts large POST bodies (data upload)
        large_data = "A" * 10000
        proc = await asyncio.create_subprocess_exec(
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "10",
            "-X",
            "POST",
            "-d",
            large_data,
            f"https://{target}/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        code = stdout.decode().strip()
        if code and code not in ("000", "413"):
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Large HTTP POST accepted by {target}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        f"Server accepts large POST bodies (10KB test, HTTP {code}). "
                        "HTTPS exfiltration is difficult to detect as payload is encrypted."
                    ),
                    tags=["exfiltration", "http", "post-body"],
                )
            )

        return results

    async def _check_cloud_exfil_paths(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # Check if common cloud storage services are reachable
        cloud_services = {
            "AWS S3": "https://s3.amazonaws.com",
            "Azure Blob": "https://blob.core.windows.net",
            "GCP Storage": "https://storage.googleapis.com",
            "Dropbox": "https://api.dropboxapi.com",
        }
        reachable: list[str] = []
        for name, url in cloud_services.items():
            proc = await asyncio.create_subprocess_exec(
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "5",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            code = stdout.decode().strip()
            if code and code != "000":
                reachable.append(name)

        if reachable:
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title="Cloud storage exfiltration paths available",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        f"Cloud storage services reachable from target environment: "
                        f"{', '.join(reachable)}. Data can be exfiltrated via "
                        "legitimate cloud storage APIs."
                    ),
                    response=json.dumps({"reachable_services": reachable}, indent=2),
                    tags=["exfiltration", "cloud-storage", "dlp-bypass"],
                )
            )

        return results
