"""L7 SubdomainTakeoverAgent — Dangling DNS, GitHub Pages/S3/Netlify takeover detection."""

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

# Known CNAME fingerprints for subdomain takeover
_TAKEOVER_FINGERPRINTS: dict[str, dict[str, str]] = {
    "github.io": {"service": "GitHub Pages", "indicator": "There isn't a GitHub Pages site here"},
    "s3.amazonaws.com": {"service": "AWS S3", "indicator": "NoSuchBucket"},
    "herokuapp.com": {"service": "Heroku", "indicator": "no-such-app"},
    "netlify.app": {"service": "Netlify", "indicator": "Not Found - Request ID"},
    "azurewebsites.net": {"service": "Azure", "indicator": "404 Web Site not found"},
    "cloudfront.net": {"service": "CloudFront", "indicator": "Bad request"},
    "shopify.com": {"service": "Shopify", "indicator": "Sorry, this shop is currently unavailable"},
    "surge.sh": {"service": "Surge", "indicator": "project not found"},
    "zendesk.com": {"service": "Zendesk", "indicator": "Help Center Closed"},
    "ghost.io": {
        "service": "Ghost",
        "indicator": "The thing you were looking for is no longer here",
    },
    "bitbucket.io": {"service": "Bitbucket", "indicator": "Repository not found"},
    "pantheon.io": {"service": "Pantheon", "indicator": "404 error unknown site"},
    "readme.io": {"service": "ReadMe", "indicator": "Project doesnt exist"},
    "cargo.site": {"service": "Cargo", "indicator": "If you're moving your domain"},
}


@register
class SubdomainTakeoverAgent(BaseAgent):
    agent_id = "subdomain_takeover"
    description = "Dangling DNS detection and GitHub Pages/S3/Netlify/Azure subdomain takeover"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Enumerate subdomains
        subdomains = await self._get_subdomains(target)
        if not subdomains:
            subdomains = [target]

        # Phase 2: Check CNAME records for dangling references
        cname_results = await self._check_cnames(subdomains)
        for result in cname_results:
            if result.get("dangling"):
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"Dangling CNAME: {result['subdomain']} -> {result['cname']}",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description=(
                            f"Subdomain {result['subdomain']} has a CNAME pointing to "
                            f"{result['cname']} ({result['service']}), which appears unclaimed. "
                            f"This may allow subdomain takeover."
                        ),
                        response=json.dumps(result, indent=2),
                        tags=["subdomain-takeover", "dangling-dns", result["service"].lower()],
                    )
                )
                hypotheses.append(
                    Hypothesis(
                        title=f"Subdomain takeover of {result['subdomain']} via {result['service']}",
                        rationale=f"Dangling CNAME to {result['cname']} detected",
                        probability=0.85,
                        impact=0.9,
                        suggested_agent="subdomain_takeover",
                    )
                )
            elif result.get("cname"):
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"CNAME record: {result['subdomain']} -> {result['cname']}",
                        severity=Severity.INFO,
                        evidence_type=EvidenceType.NETWORK,
                        description=f"CNAME points to {result['cname']}",
                        tags=["subdomain-takeover", "cname"],
                    )
                )

        # Phase 3: Nuclei takeover templates
        nuclei_results = await self._run_nuclei_takeover(subdomains, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", nf.get("template-id", ""))
            matched = nf.get("matched-at", "")
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Takeover: {name} — {matched}",
                    severity=severity,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=nf.get("info", {}).get("description", ""),
                    request=nf.get("request"),
                    response=nf.get("response"),
                    tags=["subdomain-takeover", "nuclei", nf.get("template-id", "")],
                )
            )
            if severity in (Severity.CRITICAL, Severity.HIGH):
                hypotheses.append(
                    Hypothesis(
                        title=f"Cookie/session hijack via subdomain takeover at {matched}",
                        rationale=f"Subdomain takeover confirmed: {name}",
                        probability=0.75,
                        impact=0.9,
                        suggested_agent="web",
                    )
                )

        # Phase 4: NS delegation checks
        ns_results = await self._check_ns_takeover(target)
        for ns in ns_results:
            if ns.get("vulnerable"):
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"NS delegation takeover: {ns['subdomain']}",
                        severity=Severity.CRITICAL,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description=(
                            f"NS record for {ns['subdomain']} delegates to {ns['nameserver']} "
                            f"which does not resolve. Full DNS takeover possible."
                        ),
                        tags=["subdomain-takeover", "ns-delegation"],
                    )
                )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "subdomains_checked": len(subdomains),
                "dangling_cnames": len([r for r in cname_results if r.get("dangling")]),
            },
        )

    async def _get_subdomains(self, target: str) -> list[str]:
        if not shutil.which("subfinder"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "subfinder",
            "-d",
            target,
            "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            return [line.strip() for line in stdout.decode().splitlines() if line.strip()]
        except asyncio.TimeoutError:
            return []

    async def _check_cnames(self, subdomains: list[str]) -> list[dict[str, Any]]:
        if not shutil.which("dig"):
            return []
        tasks = [self._check_single_cname(sub) for sub in subdomains[:500]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    async def _check_single_cname(self, subdomain: str) -> dict[str, Any]:
        proc = await asyncio.create_subprocess_exec(
            "dig",
            "+short",
            "CNAME",
            subdomain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            cname = stdout.decode().strip().rstrip(".")
            if not cname:
                return {"subdomain": subdomain, "cname": None, "dangling": False}

            # Check if CNAME target matches known takeover fingerprints
            for pattern, info in _TAKEOVER_FINGERPRINTS.items():
                if pattern in cname:
                    # Probe the subdomain for the takeover indicator
                    is_dangling = await self._probe_for_takeover(subdomain, info["indicator"])
                    return {
                        "subdomain": subdomain,
                        "cname": cname,
                        "service": info["service"],
                        "dangling": is_dangling,
                    }
            return {"subdomain": subdomain, "cname": cname, "dangling": False, "service": "unknown"}
        except asyncio.TimeoutError:
            return {"subdomain": subdomain, "cname": None, "dangling": False}

    async def _probe_for_takeover(self, subdomain: str, indicator: str) -> bool:
        if not shutil.which("curl"):
            return False
        proc = await asyncio.create_subprocess_exec(
            "curl",
            "-sS",
            "-L",
            f"http://{subdomain}",
            "--max-time",
            "10",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            body = stdout.decode(errors="replace")
            return indicator.lower() in body.lower()
        except asyncio.TimeoutError:
            return False

    async def _run_nuclei_takeover(
        self,
        subdomains: list[str],
        stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        stdin_data = "\n".join(subdomains[:500]).encode()
        cmd = [
            "nuclei",
            "-tags",
            "takeover",
            "-severity",
            "critical,high,medium",
            "-rate-limit",
            rate,
            "-jsonl",
            "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(input=stdin_data), timeout=1800)
        results: list[dict[str, Any]] = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results

    async def _check_ns_takeover(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("dig"):
            return []
        # Get NS records for the domain
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
            results: list[dict[str, Any]] = []
            for line in stdout.decode().splitlines():
                ns = line.strip().rstrip(".")
                if not ns:
                    continue
                # Check if NS resolves
                ns_proc = await asyncio.create_subprocess_exec(
                    "dig",
                    "+short",
                    "A",
                    ns,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                ns_stdout, _ = await asyncio.wait_for(ns_proc.communicate(), timeout=10)
                if not ns_stdout.decode().strip():
                    results.append(
                        {
                            "subdomain": target,
                            "nameserver": ns,
                            "vulnerable": True,
                        }
                    )
            return results
        except asyncio.TimeoutError:
            return []
