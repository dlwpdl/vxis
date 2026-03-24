"""L7 BigDataAnalyticsAgent — Hadoop, Spark, Jupyter, Airflow, Superset analysis."""

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

_BIGDATA_ENDPOINTS: list[tuple[int, str, str, list[str]]] = [
    (8088, "/cluster", "YARN ResourceManager", ["hadoop", "yarn"]),
    (50070, "/", "HDFS NameNode", ["hadoop", "hdfs"]),
    (9870, "/", "HDFS NameNode (3.x)", ["hadoop", "hdfs"]),
    (50075, "/", "HDFS DataNode", ["hadoop", "hdfs"]),
    (8042, "/", "YARN NodeManager", ["hadoop", "yarn"]),
    (19888, "/", "MapReduce History", ["hadoop", "mapreduce"]),
    (8080, "/", "Spark Master", ["spark"]),
    (4040, "/", "Spark Application UI", ["spark"]),
    (18080, "/", "Spark History Server", ["spark"]),
    (8888, "/", "Jupyter Notebook", ["jupyter"]),
    (8889, "/", "JupyterLab", ["jupyter"]),
    (8793, "/", "Airflow Worker Log", ["airflow"]),
    (8080, "/health", "Airflow Webserver", ["airflow"]),
    (8088, "/superset/welcome/", "Superset", ["superset"]),
    (8787, "/", "Zeppelin Notebook", ["zeppelin"]),
    (9090, "/", "Presto/Trino", ["presto"]),
]


@register
class BigDataAnalyticsAgent(BaseAgent):
    agent_id = "big_data_analytics"
    description = "Hadoop, Spark, Jupyter, Airflow, Superset big data platform analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Check big data web interfaces
        web_results = await self._check_bigdata_web(target)
        for wr in web_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=wr["title"],
                severity=wr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=wr["description"],
                response=wr.get("response", ""),
                tags=["big-data"] + wr.get("tags", []),
            ))
            if wr["severity"] in (Severity.HIGH, Severity.CRITICAL):
                if "jupyter" in str(wr.get("tags", [])):
                    hypotheses.append(Hypothesis(
                        title=f"RCE via Jupyter Notebook on {target}",
                        rationale="Jupyter Notebook without auth allows arbitrary code execution",
                        probability=0.9, impact=1.0,
                        suggested_agent="os_host",
                    ))
                elif "hadoop" in str(wr.get("tags", [])):
                    hypotheses.append(Hypothesis(
                        title=f"Data exfiltration via Hadoop on {target}",
                        rationale="Hadoop web interface exposed without auth",
                        probability=0.8, impact=0.9,
                        suggested_agent="data_exfiltration",
                    ))
                elif "airflow" in str(wr.get("tags", [])):
                    hypotheses.append(Hypothesis(
                        title=f"Airflow DAG manipulation on {target}",
                        rationale="Airflow web UI accessible",
                        probability=0.7, impact=0.9,
                        suggested_agent="supply_chain",
                    ))

        # Phase 2: Hadoop HDFS specific checks
        hdfs_results = await self._check_hdfs(target)
        for hr in hdfs_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=hr["title"],
                severity=hr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=hr["description"],
                response=hr.get("detail", ""),
                tags=["big-data", "hadoop", "hdfs"],
            ))

        # Phase 3: YARN application submission check
        yarn_results = await self._check_yarn_rce(target)
        for yr in yarn_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=yr["title"],
                severity=yr["severity"],
                evidence_type=EvidenceType.EXPLOIT,
                description=yr["description"],
                response=yr.get("detail", ""),
                tags=["big-data", "hadoop", "yarn", "rce"],
            ))
            if yr["severity"] == Severity.CRITICAL:
                hypotheses.append(Hypothesis(
                    title=f"RCE via YARN application submission on {target}",
                    rationale="YARN ResourceManager accepts unauthenticated application submission",
                    probability=0.9, impact=1.0,
                    suggested_agent="os_host",
                ))

        # Phase 4: Nuclei big data templates
        nuclei_results = await self._run_nuclei_bigdata(target, context.mission.stealth)
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
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["big-data", "nuclei", nf.get("template-id", "")],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"interfaces_found": len(web_results)},
        )

    async def _check_bigdata_web(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        seen_ports: set[int] = set()
        for port, path, name, tags in _BIGDATA_ENDPOINTS:
            if port in seen_ports:
                continue
            url = f"http://{target}:{port}{path}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/stdout", "-w", "\n%{http_code}",
                url, "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                if status in ("200", "301", "302") and len(body) > 50:
                    seen_ports.add(port)
                    # Determine if auth is required
                    no_auth = "login" not in body.lower()[:500] and "password" not in body.lower()[:500]
                    sev = Severity.HIGH if no_auth else Severity.MEDIUM
                    results.append({
                        "title": f"{name} exposed on {target}:{port}",
                        "severity": sev,
                        "description": (
                            f"{name} web interface accessible at {url}" +
                            (" without authentication" if no_auth else "")
                        ),
                        "response": body[:1024],
                        "tags": tags,
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_hdfs(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Check HDFS WebHDFS REST API
        for port in (50070, 9870):
            url = f"http://{target}:{port}/webhdfs/v1/?op=LISTSTATUS"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", url, "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                body = stdout.decode(errors="replace")
                if "FileStatuses" in body:
                    results.append({
                        "title": f"HDFS WebHDFS API accessible on {target}:{port}",
                        "severity": Severity.CRITICAL,
                        "description": "HDFS root listing accessible without auth via WebHDFS API",
                        "detail": body[:2048],
                    })
                    break
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_yarn_rce(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Check if YARN REST API allows application submission
        url = f"http://{target}:8088/ws/v1/cluster/apps"
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", url, "--max-time", "5",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            body = stdout.decode(errors="replace")
            if "apps" in body.lower() and ("app" in body or "null" in body):
                results.append({
                    "title": f"YARN REST API exposed on {target}:8088",
                    "severity": Severity.CRITICAL,
                    "description": (
                        "YARN ResourceManager REST API accessible. "
                        "May allow unauthenticated application submission (RCE)."
                    ),
                    "detail": body[:2048],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _run_nuclei_bigdata(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "hadoop,spark,jupyter,airflow,apache,bigdata",
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
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
