"""L6-01 DeserializationAgent — Java/PHP/Python/.NET/Ruby/YAML/XML deserialization."""

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

# Known deserialization indicators in tech stack
_DESER_TECH_MAP: dict[str, dict[str, Any]] = {
    "java": {
        "indicators": ["java", "spring", "tomcat", "jboss", "wildfly", "weblogic", "websphere"],
        "nuclei_tags": "java,deserialization,rce,spring,tomcat,jboss,weblogic",
        "severity": Severity.CRITICAL,
    },
    "php": {
        "indicators": ["php", "laravel", "symfony", "wordpress", "drupal", "magento"],
        "nuclei_tags": "php,deserialization,unserialize,laravel,symfony",
        "severity": Severity.HIGH,
    },
    "python": {
        "indicators": ["python", "django", "flask", "fastapi", "pickle"],
        "nuclei_tags": "python,pickle,deserialization",
        "severity": Severity.CRITICAL,
    },
    "dotnet": {
        "indicators": [".net", "asp.net", "iis", "blazor", "sharepoint"],
        "nuclei_tags": "dotnet,deserialization,viewstate,asp",
        "severity": Severity.HIGH,
    },
    "ruby": {
        "indicators": ["ruby", "rails", "sinatra"],
        "nuclei_tags": "ruby,rails,deserialization,marshal",
        "severity": Severity.HIGH,
    },
}

# Common deserialization payloads / probe paths
_PROBE_PATHS: list[dict[str, str]] = [
    {"path": "/invoker/readonly", "tech": "jboss", "desc": "JBoss Invoker deserialization"},
    {"path": "/wls-wsat/CoordinatorPortType", "tech": "weblogic", "desc": "WebLogic WSAT XMLDecoder"},
    {"path": "/console", "tech": "weblogic", "desc": "WebLogic admin console"},
    {"path": "/_ignition/execute-solution", "tech": "laravel", "desc": "Laravel Ignition RCE"},
    {"path": "/actuator/env", "tech": "spring", "desc": "Spring Actuator exposure"},
    {"path": "/jolokia", "tech": "java", "desc": "Jolokia JMX exposure"},
    {"path": "/api/jsonws", "tech": "java", "desc": "Liferay JSON Web Services"},
]


@register
class DeserializationAgent(BaseAgent):
    agent_id = "deserialization"
    description = "Java/PHP/Python/.NET/Ruby/YAML/XML deserialization vulnerability detection"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Detect target tech stack from attack graph (previous recon findings)
        detected_techs = self._detect_tech_from_graph(context)

        # 1. Nuclei deserialization-specific templates
        nuclei_tags = set()
        for tech, info in _DESER_TECH_MAP.items():
            if tech in detected_techs or not detected_techs:
                nuclei_tags.update(info["nuclei_tags"].split(","))

        nuclei_results = await self._run_nuclei(
            target, ",".join(nuclei_tags), context.mission.stealth,
        )
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
                evidence_type=EvidenceType.EXPLOIT,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["deserialization", "nuclei", nf.get("template-id", "")],
            ))

            if severity in (Severity.CRITICAL, Severity.HIGH):
                hypotheses.append(Hypothesis(
                    title=f"RCE via deserialization at {matched}",
                    rationale=f"Deserialization vulnerability: {name}",
                    probability=0.85, impact=1.0,
                    suggested_agent="os_host",
                ))

        # 2. Probe known deserialization endpoints
        probe_findings = await self._probe_endpoints(target)
        findings.extend(probe_findings)
        for pf in probe_findings:
            if pf.severity in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Exploit deserialization endpoint: {pf.title}",
                    rationale="Known vulnerable endpoint accessible",
                    probability=0.8, impact=1.0,
                    suggested_agent="os_host",
                ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"detected_techs": list(detected_techs)},
        )

    def _detect_tech_from_graph(self, context: AgentContext) -> set[str]:
        """Extract technology hints from existing attack graph nodes."""
        techs: set[str] = set()
        for node in context.attack_graph.nodes.values():
            desc = (node.description + " " + node.title).lower()
            for tech, info in _DESER_TECH_MAP.items():
                if any(ind in desc for ind in info["indicators"]):
                    techs.add(tech)
        return techs

    async def _run_nuclei(
        self, target: str, tags: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", tags,
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent", "-irr",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1800)
        results = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results

    async def _probe_endpoints(self, target: str) -> list[Evidence]:
        if not shutil.which("curl"):
            return []
        findings: list[Evidence] = []
        tasks = [self._check_endpoint(target, p) for p in _PROBE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for probe, result in zip(_PROBE_PATHS, results):
            if isinstance(result, dict) and result.get("vulnerable"):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"{probe['desc']} exposed on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.EXPLOIT,
                    description=f"Deserialization endpoint accessible: {target}{probe['path']}",
                    response=f"HTTP {result.get('status')}",
                    tags=["deserialization", probe["tech"], "endpoint"],
                ))
        return findings

    async def _check_endpoint(self, target: str, probe: dict[str, str]) -> dict[str, Any]:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
            f"{target}{probe['path']}", "--max-time", "5",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            status = int(stdout.decode().strip())
            if status in (200, 500):  # 500 can indicate deser endpoint exists
                return {"vulnerable": True, "status": status}
        except (asyncio.TimeoutError, ValueError):
            pass
        return {"vulnerable": False}
