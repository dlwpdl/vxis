"""L7 DNSDeepAgent — Zone Transfer, DNSSEC, DNS Rebinding, internal DNS exposure."""

from __future__ import annotations

import asyncio
import shutil
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class DNSDeepAgent(BaseAgent):
    agent_id = "dns_deep"
    description = "Zone Transfer, DNSSEC validation, DNS Rebinding, internal DNS exposure"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Zone Transfer (AXFR) attempt
        axfr_results = await self._try_zone_transfer(target)
        if axfr_results.get("records"):
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"DNS Zone Transfer successful for {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"Zone transfer (AXFR) allowed on {axfr_results.get('nameserver', 'unknown')}. "
                        f"Exposed {len(axfr_results['records'])} DNS records."
                    ),
                    response="\n".join(axfr_results["records"][:200]),
                    tags=["dns", "zone-transfer", "axfr"],
                )
            )
            hypotheses.append(
                Hypothesis(
                    title=f"Internal host enumeration via zone transfer for {target}",
                    rationale="Zone transfer exposes all DNS records including internal hosts",
                    probability=0.9,
                    impact=0.85,
                    suggested_agent="recon",
                )
            )
            # Check for internal hostnames in zone data
            internal_hosts = [
                r
                for r in axfr_results["records"]
                if any(
                    kw in r.lower()
                    for kw in ("internal", "intranet", "vpn", "dev", "staging", "admin")
                )
            ]
            if internal_hosts:
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"Internal hostnames leaked via zone transfer: {len(internal_hosts)} found",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description="Internal hostnames discovered in DNS zone data",
                        response="\n".join(internal_hosts[:50]),
                        tags=["dns", "internal-exposure"],
                    )
                )

        # Phase 2: DNSSEC validation
        dnssec_result = await self._check_dnssec(target)
        if dnssec_result.get("status"):
            sev = Severity.INFO if dnssec_result["valid"] else Severity.MEDIUM
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"DNSSEC status for {target}: {'valid' if dnssec_result['valid'] else 'INVALID/missing'}",
                    severity=sev,
                    evidence_type=EvidenceType.MISCONFIGURATION
                    if not dnssec_result["valid"]
                    else EvidenceType.NETWORK,
                    description=dnssec_result["detail"],
                    response=dnssec_result.get("raw", ""),
                    tags=["dns", "dnssec"],
                )
            )
            if not dnssec_result["valid"]:
                hypotheses.append(
                    Hypothesis(
                        title=f"DNS spoofing/cache poisoning for {target}",
                        rationale="DNSSEC not properly configured; DNS cache poisoning possible",
                        probability=0.4,
                        impact=0.8,
                        suggested_agent="dns_deep",
                    )
                )

        # Phase 3: DNS Rebinding check
        rebind_results = await self._check_dns_rebinding(target)
        for rb in rebind_results:
            if rb.get("vulnerable"):
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"DNS Rebinding possible for {target}",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description=(
                            f"DNS rebinding attack possible. Low TTL ({rb.get('ttl', 'unknown')}s) "
                            f"and no Host header validation detected."
                        ),
                        response=rb.get("detail", ""),
                        tags=["dns", "rebinding"],
                    )
                )
                hypotheses.append(
                    Hypothesis(
                        title=f"Internal network access via DNS rebinding on {target}",
                        rationale="DNS rebinding can bypass same-origin policy to reach internal services",
                        probability=0.5,
                        impact=0.9,
                        suggested_agent="web",
                    )
                )

        # Phase 4: Internal DNS leakage via various record types
        leak_results = await self._check_internal_dns_leak(target)
        for lr in leak_results:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Internal DNS info leaked: {lr['type']} record for {target}",
                    severity=lr.get("severity", Severity.LOW),
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=lr["description"],
                    response=lr.get("records", ""),
                    tags=["dns", "internal-leak", lr["type"].lower()],
                )
            )

        # Phase 5: DNS wildcard and subdomain enumeration indicators
        wildcard_result = await self._check_wildcard_dns(target)
        if wildcard_result.get("wildcard"):
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"DNS wildcard detected for {target}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description=f"Wildcard DNS resolves to {wildcard_result.get('ip', 'unknown')}",
                    tags=["dns", "wildcard"],
                )
            )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "zone_transfer": bool(axfr_results.get("records")),
                "dnssec_valid": dnssec_result.get("valid", False),
            },
        )

    async def _try_zone_transfer(self, target: str) -> dict[str, Any]:
        if not shutil.which("dig"):
            return {}
        # Get nameservers first
        proc = await asyncio.create_subprocess_exec(
            "dig",
            "+short",
            "NS",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            nameservers = [
                ns.strip().rstrip(".") for ns in stdout.decode().splitlines() if ns.strip()
            ]
        except asyncio.TimeoutError:
            return {}

        for ns in nameservers[:3]:
            proc = await asyncio.create_subprocess_exec(
                "dig",
                "AXFR",
                target,
                f"@{ns}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                output = stdout.decode()
                records = [
                    line
                    for line in output.splitlines()
                    if line.strip() and not line.startswith(";") and "\t" in line
                ]
                if records:
                    return {"nameserver": ns, "records": records}
            except asyncio.TimeoutError:
                continue
        return {}

    async def _check_dnssec(self, target: str) -> dict[str, Any]:
        if not shutil.which("dig"):
            return {}
        proc = await asyncio.create_subprocess_exec(
            "dig",
            "+dnssec",
            "+short",
            "DNSKEY",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode().strip()
            has_dnskey = bool(
                output and "DNSKEY" not in output.upper().split(";;")[0]
                if ";;" in output
                else bool(output)
            )

            # Check DS record
            ds_proc = await asyncio.create_subprocess_exec(
                "dig",
                "+short",
                "DS",
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            ds_stdout, _ = await asyncio.wait_for(ds_proc.communicate(), timeout=15)
            has_ds = bool(ds_stdout.decode().strip())

            valid = has_dnskey and has_ds
            return {
                "status": True,
                "valid": valid,
                "detail": (
                    f"DNSSEC {'properly configured' if valid else 'not fully configured'}. "
                    f"DNSKEY: {'present' if has_dnskey else 'missing'}. "
                    f"DS: {'present' if has_ds else 'missing'}."
                ),
                "raw": output[:2048],
            }
        except asyncio.TimeoutError:
            return {}

    async def _check_dns_rebinding(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("dig"):
            return []
        results: list[dict[str, Any]] = []
        # Check TTL
        proc = await asyncio.create_subprocess_exec(
            "dig",
            "+noall",
            "+answer",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            for line in stdout.decode().splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        ttl = int(parts[1])
                        if ttl <= 60:
                            results.append(
                                {
                                    "vulnerable": True,
                                    "ttl": ttl,
                                    "detail": f"Very low TTL ({ttl}s) facilitates DNS rebinding",
                                }
                            )
                        break
                    except ValueError:
                        continue
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_internal_dns_leak(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("dig"):
            return []
        results: list[dict[str, Any]] = []
        record_types = ["MX", "TXT", "SRV", "SOA", "CNAME"]
        for rtype in record_types:
            proc = await asyncio.create_subprocess_exec(
                "dig",
                "+short",
                rtype,
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode().strip()
                if output:
                    # Check for internal IPs or hostnames
                    has_internal = any(
                        indicator in output.lower()
                        for indicator in (
                            "10.",
                            "192.168.",
                            "172.16.",
                            "172.17.",
                            "172.18.",
                            "internal",
                            "local",
                            "intranet",
                            "corp",
                        )
                    )
                    if has_internal:
                        results.append(
                            {
                                "type": rtype,
                                "severity": Severity.MEDIUM,
                                "description": f"{rtype} record leaks internal information",
                                "records": output[:1024],
                            }
                        )
                    else:
                        results.append(
                            {
                                "type": rtype,
                                "severity": Severity.INFO,
                                "description": f"{rtype} record: {output[:200]}",
                                "records": output[:1024],
                            }
                        )
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_wildcard_dns(self, target: str) -> dict[str, Any]:
        if not shutil.which("dig"):
            return {}
        random_sub = f"xz9q7w3randomtest.{target}"
        proc = await asyncio.create_subprocess_exec(
            "dig",
            "+short",
            "A",
            random_sub,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            ip = stdout.decode().strip()
            if ip:
                return {"wildcard": True, "ip": ip}
        except asyncio.TimeoutError:
            pass
        return {"wildcard": False}
