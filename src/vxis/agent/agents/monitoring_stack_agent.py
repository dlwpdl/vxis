"""L7 MonitoringStackAgent — Prometheus, Grafana, Kibana, Jaeger, Netdata analysis."""

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

_MONITORING_ENDPOINTS: list[tuple[int, str, str, list[str]]] = [
    (9090, "/api/v1/targets", "Prometheus", ["prometheus"]),
    (3000, "/api/health", "Grafana", ["grafana"]),
    (5601, "/api/status", "Kibana", ["kibana"]),
    (16686, "/api/traces", "Jaeger", ["jaeger"]),
    (19999, "/", "Netdata", ["netdata"]),
    (9093, "/-/healthy", "Alertmanager", ["alertmanager"]),
    (9091, "/metrics", "Pushgateway", ["pushgateway"]),
    (8086, "/ping", "InfluxDB", ["influxdb"]),
    (3100, "/ready", "Loki", ["loki"]),
    (4317, "/", "OTEL Collector", ["opentelemetry"]),
    (9411, "/zipkin/", "Zipkin", ["zipkin"]),
    (8428, "/api/v1/status/tsdb", "VictoriaMetrics", ["victoriametrics"]),
]


@register
class MonitoringStackAgent(BaseAgent):
    agent_id = "monitoring_stack"
    description = "Prometheus, Grafana, Kibana, Jaeger, Netdata monitoring stack analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Detect monitoring endpoints
        monitoring_results = await self._check_monitoring_endpoints(target)
        for mr in monitoring_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=mr["title"],
                severity=mr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=mr["description"],
                response=mr.get("response", ""),
                tags=["monitoring"] + mr.get("tags", []),
            ))
            # Generate platform-specific hypotheses
            if mr["severity"] in (Severity.HIGH, Severity.CRITICAL):
                platform = mr.get("tags", [""])[0] if mr.get("tags") else ""
                if "prometheus" in platform:
                    hypotheses.append(Hypothesis(
                        title=f"Metrics data exfiltration via Prometheus on {target}",
                        rationale="Prometheus accessible; may expose internal metrics and secrets",
                        probability=0.8, impact=0.85,
                        suggested_agent="secrets_lifecycle",
                    ))
                elif "grafana" in platform:
                    hypotheses.append(Hypothesis(
                        title=f"Grafana admin exploitation on {target}",
                        rationale="Grafana accessible; check for default creds or auth bypass",
                        probability=0.6, impact=0.8,
                        suggested_agent="web",
                    ))
                elif "kibana" in platform:
                    hypotheses.append(Hypothesis(
                        title=f"Log data exposure via Kibana on {target}",
                        rationale="Kibana accessible; may expose application logs with sensitive data",
                        probability=0.75, impact=0.85,
                        suggested_agent="data_exfiltration",
                    ))

        # Phase 2: Prometheus specific checks
        prom_results = await self._check_prometheus_deep(target)
        for pr in prom_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=pr["title"],
                severity=pr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=pr["description"],
                response=pr.get("detail", ""),
                tags=["monitoring", "prometheus"],
            ))

        # Phase 3: Grafana specific checks
        grafana_results = await self._check_grafana(target)
        for gr in grafana_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=gr["title"],
                severity=gr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=gr["description"],
                response=gr.get("detail", ""),
                tags=["monitoring", "grafana"],
            ))

        # Phase 4: /metrics endpoint exposure
        metrics_results = await self._check_metrics_endpoints(target)
        for mer in metrics_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=mer["title"],
                severity=mer["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=mer["description"],
                response=mer.get("response", "")[:4096],
                tags=["monitoring", "metrics-exposure"],
            ))

        # Phase 5: Nuclei monitoring templates
        nuclei_results = await self._run_nuclei_monitoring(target, context.mission.stealth)
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
                tags=["monitoring", "nuclei", nf.get("template-id", "")],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"monitoring_endpoints": len(monitoring_results)},
        )

    async def _check_monitoring_endpoints(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        for port, path, name, tags in _MONITORING_ENDPOINTS:
            url = f"http://{target}:{port}{path}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", url, "-w", "\n%{http_code}", "--max-time", "5",
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
                    no_auth = "login" not in body.lower()[:300]
                    sev = Severity.HIGH if no_auth else Severity.MEDIUM
                    results.append({
                        "title": f"{name} exposed on {target}:{port}",
                        "severity": sev,
                        "description": (
                            f"{name} at {url} is accessible" +
                            (" without authentication" if no_auth else "")
                        ),
                        "response": body[:2048],
                        "tags": tags,
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_prometheus_deep(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        prom_endpoints = [
            (f"http://{target}:9090/api/v1/label/__name__/values", "Metric names"),
            (f"http://{target}:9090/api/v1/status/config", "Prometheus config"),
            (f"http://{target}:9090/api/v1/status/flags", "Prometheus flags"),
        ]
        for url, desc in prom_endpoints:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", url, "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                body = stdout.decode(errors="replace")
                if '"status":"success"' in body:
                    sev = Severity.HIGH if "config" in url else Severity.MEDIUM
                    results.append({
                        "title": f"Prometheus {desc} exposed on {target}",
                        "severity": sev,
                        "description": f"Prometheus {desc} endpoint accessible without auth",
                        "detail": body[:2048],
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_grafana(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Default admin/admin
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-X", "GET",
            f"http://{target}:3000/api/org",
            "-u", "admin:admin", "--max-time", "5",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            body = stdout.decode(errors="replace")
            if "id" in body and "name" in body:
                results.append({
                    "title": f"Grafana default credentials on {target}:3000",
                    "severity": Severity.CRITICAL,
                    "description": "Grafana accessible with admin:admin default credentials",
                    "detail": body[:2048],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_metrics_endpoints(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Check /metrics on common ports
        for port in (80, 443, 8080, 8443, 3000, 9090):
            scheme = "https" if port in (443, 8443) else "http"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-k", f"{scheme}://{target}:{port}/metrics",
                "-w", "\n%{http_code}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                if status == "200" and ("# HELP" in body or "# TYPE" in body):
                    # Check for sensitive metrics
                    has_secrets = any(
                        kw in body.lower()
                        for kw in ("password", "secret", "token", "api_key", "credential")
                    )
                    sev = Severity.HIGH if has_secrets else Severity.MEDIUM
                    results.append({
                        "title": f"Prometheus metrics exposed on {target}:{port}/metrics",
                        "severity": sev,
                        "description": (
                            f"Prometheus metrics endpoint exposed on port {port}" +
                            (". Contains potentially sensitive metric names." if has_secrets else ".")
                        ),
                        "response": body[:4096],
                    })
                    break  # Only report once
            except asyncio.TimeoutError:
                continue
        return results

    async def _run_nuclei_monitoring(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "prometheus,grafana,kibana,elasticsearch,monitoring",
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
