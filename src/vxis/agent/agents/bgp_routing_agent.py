"""CRT-P8 BGPRoutingAgent — BGP hijacking analysis, OSPF/EIGRP, route origin validation."""

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
class BGPRoutingAgent(BaseAgent):
    agent_id = "bgp_routing"
    description = "BGP hijacking analysis, OSPF/EIGRP assessment, ASN/route origin validation"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # 1. Resolve target to IP and ASN
        ip_info = await self._resolve_target(target)
        target_ip = ip_info.get("ip", "")
        if not target_ip:
            return AgentResult(
                agent_id=self.agent_id,
                findings=findings,
                hypotheses=hypotheses,
                status="completed",
                metadata={"note": "Could not resolve target IP"},
            )

        # 2. Whois / ASN lookup
        asn_info = await self._run_whois_asn(target_ip)
        if asn_info:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"ASN information for {target} ({target_ip})",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.OSINT,
                    description=f"ASN: {asn_info.get('asn', 'unknown')}, "
                    f"Org: {asn_info.get('org', 'unknown')}, "
                    f"Prefix: {asn_info.get('prefix', 'unknown')}",
                    response=json.dumps(asn_info, indent=2),
                    tags=["bgp", "asn", "whois"],
                )
            )

        # 3. Traceroute for path analysis
        trace_data = await self._run_traceroute(target_ip)
        if trace_data:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Network path analysis to {target}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description=f"Traceroute completed: {len(trace_data)} hops",
                    response="\n".join(trace_data[:30]),
                    tags=["bgp", "traceroute", "path-analysis"],
                )
            )

            # Check for AS path anomalies (multiple transit ASNs)
            as_hops = await self._resolve_as_path(trace_data)
            if as_hops:
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"AS path to {target}: {' -> '.join(as_hops[:10])}",
                        severity=Severity.INFO,
                        evidence_type=EvidenceType.NETWORK,
                        description=f"Traverses {len(as_hops)} autonomous systems",
                        response=json.dumps(as_hops, indent=2),
                        tags=["bgp", "as-path"],
                    )
                )

        # 4. Check BGP route origin via RPKI/ROA
        rpki_result = await self._check_rpki_validity(target_ip, asn_info)
        if rpki_result:
            findings.append(rpki_result)
            if rpki_result.severity in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(
                    Hypothesis(
                        title=f"BGP prefix hijack risk for {target}",
                        rationale=f"RPKI validation failed: {rpki_result.description}",
                        probability=0.5,
                        impact=0.95,
                        suggested_agent="bgp_routing",
                    )
                )

        # 5. Nmap scan for routing protocol exposure
        routing_findings = await self._check_routing_protocols(target_ip)
        findings.extend(routing_findings)
        for rf in routing_findings:
            if rf.severity in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(
                    Hypothesis(
                        title=f"Routing protocol injection on {target}",
                        rationale=f"Routing protocol exposed: {rf.title}",
                        probability=0.6,
                        impact=0.95,
                        suggested_agent="l2_network",
                    )
                )

        # 6. Check for BGP session exposure (TCP/179)
        bgp_session = await self._check_bgp_port(target_ip)
        if bgp_session:
            findings.append(bgp_session)
            hypotheses.append(
                Hypothesis(
                    title=f"BGP session hijacking on {target}",
                    rationale="BGP TCP/179 accessible — session reset or route injection possible",
                    probability=0.5,
                    impact=1.0,
                    suggested_agent="bgp_routing",
                )
            )
            hypotheses.append(
                Hypothesis(
                    title=f"BGP MD5 authentication bypass on {target}",
                    rationale="BGP port open; if MD5 auth is weak/missing, "
                    "session takeover is possible",
                    probability=0.4,
                    impact=1.0,
                    suggested_agent="crypto_tls",
                )
            )

        # 7. General routing security hypotheses
        hypotheses.append(
            Hypothesis(
                title=f"DNS hijacking via BGP leak for {target}",
                rationale="BGP analysis complete; DNS resolution depends on routing integrity",
                probability=0.3,
                impact=0.9,
                suggested_agent="network",
            )
        )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "target_ip": target_ip,
                "asn": asn_info.get("asn", "unknown"),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _resolve_target(self, target: str) -> dict[str, str]:
        """Resolve target hostname to IP."""
        if not shutil.which("dig"):
            return {}
        domain = target.lstrip("*.").split("/")[0].split(":")[0]
        proc = await asyncio.create_subprocess_exec(
            "dig",
            "+short",
            domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            lines = [line.strip() for line in stdout.decode().splitlines() if line.strip()]
            # Find first IP address
            import re

            for line in lines:
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                    return {"ip": line}
            return {}
        except asyncio.TimeoutError:
            return {}

    async def _run_whois_asn(self, ip: str) -> dict[str, str]:
        """Get ASN information via whois."""
        if not shutil.which("whois"):
            return {}
        proc = await asyncio.create_subprocess_exec(
            "whois",
            "-h",
            "whois.cymru.com",
            f" -v {ip}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode()
            result: dict[str, str] = {"raw": output}
            for line in output.splitlines():
                if "|" in line and not line.startswith("Bulk"):
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 3:
                        result["asn"] = parts[0]
                        result["prefix"] = parts[1] if len(parts) > 1 else ""
                        result["org"] = parts[-1] if len(parts) > 2 else ""
            return result
        except asyncio.TimeoutError:
            return {}

    async def _run_traceroute(self, ip: str) -> list[str]:
        """Run traceroute to analyse network path."""
        binary = "traceroute" if shutil.which("traceroute") else None
        if not binary:
            binary = "tracert" if shutil.which("tracert") else None
        if not binary:
            return []
        proc = await asyncio.create_subprocess_exec(
            binary,
            "-n",
            "-m",
            "30",
            ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return [line.strip() for line in stdout.decode().splitlines() if line.strip()]
        except asyncio.TimeoutError:
            return []

    async def _resolve_as_path(self, trace_data: list[str]) -> list[str]:
        """Extract unique ASNs from traceroute hops."""
        if not shutil.which("whois"):
            return []
        import re

        ips = []
        for line in trace_data:
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if ip_match:
                ips.append(ip_match.group(1))

        as_path: list[str] = []
        seen: set[str] = set()
        for ip in ips[:15]:  # Limit lookups
            proc = await asyncio.create_subprocess_exec(
                "whois",
                "-h",
                "whois.cymru.com",
                f" -v {ip}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                for line in stdout.decode().splitlines():
                    if "|" in line and not line.startswith("Bulk"):
                        asn = line.split("|")[0].strip()
                        if asn and asn not in seen and asn.isdigit():
                            seen.add(asn)
                            as_path.append(f"AS{asn}")
            except asyncio.TimeoutError:
                continue
        return as_path

    async def _check_rpki_validity(
        self,
        ip: str,
        asn_info: dict[str, str],
    ) -> Evidence | None:
        """Check RPKI/ROA validity for the prefix."""
        if not shutil.which("curl"):
            return None
        prefix = asn_info.get("prefix", "")
        asn = asn_info.get("asn", "")
        if not prefix or not asn:
            return None

        # Use RIPE RPKI validator API
        proc = await asyncio.create_subprocess_exec(
            "curl",
            "-s",
            "-m",
            "10",
            f"https://stat.ripe.net/data/rpki-validation/data.json?resource={asn}&prefix={prefix}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            data = json.loads(stdout.decode())
            data.get("data", {}).get("validating_roas", [])
            validity = data.get("data", {}).get("status", "unknown")

            if validity == "valid":
                return Evidence(
                    agent_id=self.agent_id,
                    title=f"RPKI ROA valid for {prefix} (AS{asn})",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description="Route origin is RPKI-validated — hijack resilience is higher",
                    response=json.dumps(data.get("data", {}), indent=2)[:4096],
                    tags=["bgp", "rpki", "roa", "valid"],
                )
            elif validity in ("invalid", "unknown"):
                sev = Severity.HIGH if validity == "invalid" else Severity.MEDIUM
                return Evidence(
                    agent_id=self.agent_id,
                    title=f"RPKI ROA {validity} for {prefix} (AS{asn})",
                    severity=sev,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"Route origin RPKI status: {validity}. "
                        "Prefix may be susceptible to BGP hijacking."
                    ),
                    response=json.dumps(data.get("data", {}), indent=2)[:4096],
                    tags=["bgp", "rpki", "roa", validity],
                )
        except (asyncio.TimeoutError, json.JSONDecodeError, KeyError):
            pass
        return None

    async def _check_routing_protocols(self, ip: str) -> list[Evidence]:
        """Check for exposed routing protocol ports."""
        if not shutil.which("nmap"):
            return []
        # BGP=179, OSPF=89(proto), RIP=520(udp), EIGRP=88(proto)
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "-sV",
            "-p",
            "179,520,2601,2602,2604,2605",
            "-oX",
            "-",
            ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            findings: list[Evidence] = []
            import xml.etree.ElementTree as ET

            try:
                root = ET.fromstring(output)
                for port_el in root.iter("port"):
                    state_el = port_el.find("state")
                    service_el = port_el.find("service")
                    if state_el is not None and state_el.get("state") == "open":
                        port = port_el.get("portid", "")
                        svc = service_el.get("name", "") if service_el is not None else ""
                        product = service_el.get("product", "") if service_el is not None else ""
                        findings.append(
                            Evidence(
                                agent_id=self.agent_id,
                                title=f"Routing protocol port open: {ip}:{port} ({svc})",
                                severity=Severity.HIGH,
                                evidence_type=EvidenceType.MISCONFIGURATION,
                                description=(
                                    f"Routing protocol service '{svc}' ({product}) "
                                    f"on port {port}. May allow route injection."
                                ),
                                tags=["bgp", "routing", svc, f"port-{port}"],
                            )
                        )
            except ET.ParseError:
                pass
            return findings
        except asyncio.TimeoutError:
            return []

    async def _check_bgp_port(self, ip: str) -> Evidence | None:
        """Specifically check BGP TCP/179."""
        if not shutil.which("nmap"):
            return None
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "-sV",
            "-p",
            "179",
            "-oX",
            "-",
            ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode()
            if 'state="open"' in output:
                return Evidence(
                    agent_id=self.agent_id,
                    title=f"BGP port (TCP/179) open on {ip}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        "BGP session port is externally accessible. "
                        "Allows session reset attacks, route injection, "
                        "or MD5 auth brute-force."
                    ),
                    response=output[:4096],
                    tags=["bgp", "tcp-179", "session"],
                )
        except asyncio.TimeoutError:
            pass
        return None
