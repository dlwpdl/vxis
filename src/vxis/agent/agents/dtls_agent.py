"""CRT-P12 DTLSAgent — VoIP/WebRTC DTLS vulnerabilities, SRTP key extraction."""

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
class DTLSAgent(BaseAgent):
    agent_id = "dtls"
    description = "DTLS vulnerabilities, VoIP/WebRTC security, SRTP analysis"

    # Common DTLS/VoIP/WebRTC ports
    DTLS_PORTS = "443,3478,3479,5004,5060,5061,5349,10000-10100"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        domain = target.lstrip("*.").split("/")[0].split(":")[0]

        # 1. Scan for DTLS/VoIP/WebRTC ports
        dtls_services = await self._scan_dtls_ports(domain)
        if dtls_services:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"DTLS/VoIP services on {domain}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"{len(dtls_services)} DTLS/VoIP/WebRTC ports open: "
                    f"{', '.join(s['port'] for s in dtls_services[:15])}"
                ),
                response=json.dumps(dtls_services[:20], indent=2),
                tags=["dtls", "voip", "webrtc", "discovery"],
            ))
        else:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"No DTLS/VoIP services detected on {domain}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description="No common DTLS, VoIP, or WebRTC ports found open",
                tags=["dtls", "not-detected"],
            ))
            return AgentResult(
                agent_id=self.agent_id,
                findings=findings,
                hypotheses=hypotheses,
                status="completed",
                metadata={"dtls_services": 0},
            )

        # 2. DTLS handshake analysis via openssl
        dtls_analysis = await self._run_dtls_handshake(domain)
        if dtls_analysis:
            findings.extend(dtls_analysis)

        # 3. SIP service analysis
        sip_findings = await self._check_sip_services(domain, dtls_services)
        findings.extend(sip_findings)
        if sip_findings:
            hypotheses.append(Hypothesis(
                title=f"SIP registration hijacking on {domain}",
                rationale="SIP service exposed; registration spoofing or "
                          "toll fraud may be possible",
                probability=0.6, impact=0.8,
                suggested_agent="network",
            ))
            hypotheses.append(Hypothesis(
                title=f"VoIP eavesdropping via SRTP downgrade on {domain}",
                rationale="SIP/VoIP detected; if SRTP is optional or SDES key "
                          "exchange is used, media can be intercepted",
                probability=0.5, impact=0.85,
                suggested_agent="l2_network",
            ))

        # 4. STUN/TURN server analysis
        stun_findings = await self._check_stun_turn(domain, dtls_services)
        findings.extend(stun_findings)
        if stun_findings:
            hypotheses.append(Hypothesis(
                title=f"TURN server abuse for traffic relay on {domain}",
                rationale="TURN server detected; may be usable as an open proxy "
                          "for tunneling traffic",
                probability=0.5, impact=0.7,
                suggested_agent="network",
            ))

        # 5. WebRTC-specific hypotheses
        webrtc_ports = [s for s in dtls_services if s.get("port") in ("3478", "3479", "5349")]
        if webrtc_ports:
            hypotheses.append(Hypothesis(
                title=f"WebRTC ICE candidate IP leak on {domain}",
                rationale="WebRTC infrastructure detected; ICE candidates may "
                          "leak internal IP addresses",
                probability=0.7, impact=0.5,
                suggested_agent="web",
            ))
            hypotheses.append(Hypothesis(
                title=f"DTLS certificate validation bypass on {domain}",
                rationale="DTLS-SRTP uses self-signed certs by default in WebRTC; "
                          "fingerprint verification may be bypassable",
                probability=0.4, impact=0.8,
                suggested_agent="crypto_tls",
            ))

        # 6. Nuclei VoIP/SIP templates
        nuclei_results = await self._run_nuclei_voip(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", "")
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{name} — {domain}",
                severity=severity,
                evidence_type=EvidenceType.EXPLOIT,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["dtls", "voip", "nuclei", nf.get("template-id", "")],
            ))

        # 7. DTLS DoS hypothesis (Amplification)
        hypotheses.append(Hypothesis(
            title=f"DTLS amplification DoS via {domain}",
            rationale="DTLS endpoints can be abused for amplification attacks "
                      "if ClientHello handling is not rate-limited",
            probability=0.4, impact=0.6,
            suggested_agent="network",
        ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"dtls_services": len(dtls_services)},
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _scan_dtls_ports(self, domain: str) -> list[dict[str, Any]]:
        """Scan for DTLS, VoIP, and WebRTC-related UDP and TCP ports."""
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []

        # UDP scan for DTLS/STUN/TURN/RTP
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sU", "-sV",
            "-p", self.DTLS_PORTS,
            "-oX", "-", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            results.extend(self._parse_nmap_services(stdout.decode()))
        except asyncio.TimeoutError:
            pass

        # TCP scan for SIP/SIP-TLS
        proc2 = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-p", "5060,5061,8080,8443",
            "-oX", "-", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=60)
            results.extend(self._parse_nmap_services(stdout2.decode()))
        except asyncio.TimeoutError:
            pass

        return results

    async def _run_dtls_handshake(self, domain: str) -> list[Evidence]:
        """Test DTLS handshake using openssl s_client -dtls."""
        if not shutil.which("openssl"):
            return []
        findings: list[Evidence] = []

        for port in ("443", "3478", "5004"):
            proc = await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-dtls",
                "-connect", f"{domain}:{port}",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=b""), timeout=10,
                )
                combined = stdout.decode() + stderr.decode()

                if "handshake" in combined.lower() and "error" not in combined.lower():
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"DTLS handshake successful on {domain}:{port}",
                        severity=Severity.INFO,
                        evidence_type=EvidenceType.NETWORK,
                        description="DTLS endpoint responded to handshake",
                        response=combined[:4096],
                        tags=["dtls", "handshake", f"port-{port}"],
                    ))

                    # Check for weak DTLS versions
                    if "dtls1.0" in combined.lower() or "dtls 1.0" in combined.lower():
                        findings.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"DTLS 1.0 supported on {domain}:{port}",
                            severity=Severity.MEDIUM,
                            evidence_type=EvidenceType.MISCONFIGURATION,
                            description="DTLS 1.0 (based on TLS 1.1) is deprecated. "
                                        "Vulnerable to known TLS 1.1 attacks.",
                            response=combined[:2048],
                            tags=["dtls", "dtls1.0", "deprecated"],
                        ))
            except asyncio.TimeoutError:
                continue

        return findings

    async def _check_sip_services(
        self, domain: str, services: list[dict[str, Any]],
    ) -> list[Evidence]:
        """Analyse SIP services."""
        findings: list[Evidence] = []
        sip_services = [s for s in services if "sip" in s.get("service", "").lower()]

        for svc in sip_services:
            port = svc.get("port", "5060")
            product = svc.get("product", "")

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"SIP service on {domain}:{port}",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"SIP service ({product}) exposed on port {port}. "
                    "SIP without TLS allows eavesdropping and registration "
                    "hijacking. SIP INVITE flooding causes DoS."
                ),
                response=json.dumps(svc, indent=2),
                tags=["dtls", "sip", "voip", f"port-{port}"],
            ))

        # Check for SIP without TLS (port 5060 vs 5061)
        has_sip_plain = any(s.get("port") == "5060" for s in sip_services)
        has_sip_tls = any(s.get("port") == "5061" for s in sip_services)
        if has_sip_plain and not has_sip_tls:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"SIP without TLS on {domain}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description="SIP port 5060 (plaintext) open but 5061 (TLS) not detected. "
                            "VoIP signaling is unencrypted.",
                tags=["dtls", "sip", "no-tls", "plaintext"],
            ))

        return findings

    async def _check_stun_turn(
        self, domain: str, services: list[dict[str, Any]],
    ) -> list[Evidence]:
        """Analyse STUN/TURN services."""
        findings: list[Evidence] = []
        stun_ports = {"3478", "3479", "5349"}
        stun_services = [s for s in services if s.get("port") in stun_ports]

        for svc in stun_services:
            port = svc.get("port", "")
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"STUN/TURN service on {domain}:{port}",
                severity=Severity.LOW,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"STUN/TURN service on port {port}. "
                    "TURN can be abused as a traffic relay; STUN reveals "
                    "server-reflexive addresses."
                ),
                response=json.dumps(svc, indent=2),
                tags=["dtls", "stun", "turn", "webrtc", f"port-{port}"],
            ))

        return findings

    async def _run_nuclei_voip(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "60"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "voip,sip,webrtc,rtp",
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
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

    @staticmethod
    def _parse_nmap_services(xml_output: str) -> list[dict[str, Any]]:
        import xml.etree.ElementTree as ET
        results: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_output)
            for port_el in root.iter("port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                if state_el is not None and state_el.get("state") == "open":
                    results.append({
                        "port": port_el.get("portid", ""),
                        "protocol": port_el.get("protocol", ""),
                        "service": service_el.get("name", "") if service_el is not None else "",
                        "product": service_el.get("product", "") if service_el is not None else "",
                        "version": service_el.get("version", "") if service_el is not None else "",
                    })
        except ET.ParseError:
            pass
        return results
