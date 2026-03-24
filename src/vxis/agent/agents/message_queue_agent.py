"""L7 MessageQueueAgent — Kafka, RabbitMQ, ActiveMQ, Redis Streams, NATS analysis."""

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

_MQ_PORTS: dict[int, str] = {
    5672: "RabbitMQ-AMQP",
    15672: "RabbitMQ-Management",
    9092: "Kafka",
    2181: "ZooKeeper",
    61613: "ActiveMQ-STOMP",
    61616: "ActiveMQ-OpenWire",
    8161: "ActiveMQ-Web",
    4222: "NATS",
    8222: "NATS-Monitoring",
    6650: "Pulsar",
    8080: "Pulsar-Admin",
    1883: "MQTT",
    4369: "Erlang-EPMD",
    25672: "RabbitMQ-Clustering",
}


@register
class MessageQueueAgent(BaseAgent):
    agent_id = "message_queue"
    description = "Kafka, RabbitMQ, ActiveMQ, Redis Streams, NATS message queue analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: MQ port scan
        mq_services = await self._scan_mq_ports(target)
        for svc in mq_services:
            port = svc.get("port", 0)
            service = svc.get("service", _MQ_PORTS.get(port, "unknown"))
            product = svc.get("product", "")

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Message queue: {service} on {target}:{port}",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.NETWORK,
                description=f"Message queue service {service} ({product}) on port {port}",
                response=json.dumps(svc, indent=2),
                tags=["message-queue", service.lower().split("-")[0], f"port-{port}"],
            ))

        # Phase 2: RabbitMQ management interface
        rabbitmq_results = await self._check_rabbitmq(target)
        for rr in rabbitmq_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=rr["title"],
                severity=rr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=rr["description"],
                response=rr.get("detail", ""),
                tags=["message-queue", "rabbitmq"],
            ))
            if rr["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Message interception via RabbitMQ on {target}",
                    rationale=rr["description"],
                    probability=0.75, impact=0.85,
                    suggested_agent="data_exfiltration",
                ))

        # Phase 3: ActiveMQ checks
        activemq_results = await self._check_activemq(target)
        for ar in activemq_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=ar["title"],
                severity=ar["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=ar["description"],
                response=ar.get("detail", ""),
                tags=["message-queue", "activemq"],
            ))
            if ar["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"RCE via ActiveMQ deserialization on {target}",
                    rationale="ActiveMQ may be vulnerable to CVE-2023-46604",
                    probability=0.6, impact=0.95,
                    suggested_agent="deserialization",
                ))

        # Phase 4: Kafka / ZooKeeper checks
        kafka_results = await self._check_kafka(target)
        for kr in kafka_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=kr["title"],
                severity=kr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=kr["description"],
                response=kr.get("detail", ""),
                tags=["message-queue", "kafka"],
            ))
            if kr["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Data exfiltration via Kafka on {target}",
                    rationale="Kafka accessible without authentication",
                    probability=0.8, impact=0.9,
                    suggested_agent="data_exfiltration",
                ))

        # Phase 5: NATS checks
        nats_results = await self._check_nats(target)
        for nr in nats_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=nr["title"],
                severity=nr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=nr["description"],
                response=nr.get("detail", ""),
                tags=["message-queue", "nats"],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"mq_services": len(mq_services)},
        )

    async def _scan_mq_ports(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        ports = ",".join(str(p) for p in _MQ_PORTS)
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-Pn", "--open", "-p", ports, "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            import xml.etree.ElementTree as ET
            results: list[dict[str, Any]] = []
            root = ET.fromstring(stdout.decode())
            for port_elem in root.findall(".//port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") == "open":
                    svc = port_elem.find("service")
                    port_id = int(port_elem.get("portid", 0))
                    results.append({
                        "port": port_id,
                        "service": svc.get("name", "") if svc is not None else "",
                        "product": svc.get("product", "") if svc is not None else "",
                    })
            return results
        except (asyncio.TimeoutError, Exception):
            return []

    async def _check_rabbitmq(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Default guest/guest credentials
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-u", "guest:guest",
            f"http://{target}:15672/api/overview",
            "--max-time", "10",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            body = stdout.decode(errors="replace")
            if "rabbitmq_version" in body or "cluster_name" in body:
                data = json.loads(body)
                results.append({
                    "title": f"RabbitMQ management with default creds on {target}",
                    "severity": Severity.CRITICAL,
                    "description": (
                        f"RabbitMQ management API accessible with guest:guest. "
                        f"Version: {data.get('rabbitmq_version', 'unknown')}"
                    ),
                    "detail": body[:2048],
                })
        except (asyncio.TimeoutError, json.JSONDecodeError):
            pass

        # Check without auth
        proc2 = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
            f"http://{target}:15672/", "--max-time", "5",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc2.communicate(), timeout=8)
            status = stdout.decode().strip()
            if status in ("200", "301", "302"):
                results.append({
                    "title": f"RabbitMQ management UI on {target}:15672",
                    "severity": Severity.MEDIUM,
                    "description": "RabbitMQ management interface is accessible",
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_activemq(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Default admin/admin
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-u", "admin:admin",
            f"http://{target}:8161/admin/", "-w", "\n%{http_code}",
            "--max-time", "10",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode(errors="replace")
            lines = output.rsplit("\n", 1)
            body = lines[0] if len(lines) > 1 else ""
            status = lines[-1].strip()
            if status == "200" and ("activemq" in body.lower() or "queue" in body.lower()):
                results.append({
                    "title": f"ActiveMQ admin with default creds on {target}",
                    "severity": Severity.CRITICAL,
                    "description": "ActiveMQ web console accessible with admin:admin",
                    "detail": body[:2048],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_kafka(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        # Check ZooKeeper (often exposes Kafka cluster info)
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "-sV", "-p", "2181,9092", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            if "2181" in output and "open" in output:
                results.append({
                    "title": f"ZooKeeper exposed on {target}:2181",
                    "severity": Severity.HIGH,
                    "description": "ZooKeeper accessible; may expose Kafka configuration and ACLs",
                    "detail": output[:1024],
                })
            if "9092" in output and "open" in output:
                results.append({
                    "title": f"Kafka broker exposed on {target}:9092",
                    "severity": Severity.HIGH,
                    "description": "Kafka broker accessible; may allow topic listing and message consumption",
                    "detail": output[:1024],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_nats(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # NATS monitoring endpoint
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", f"http://{target}:8222/varz", "--max-time", "5",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            body = stdout.decode(errors="replace")
            if "server_id" in body or "nats" in body.lower():
                results.append({
                    "title": f"NATS monitoring exposed on {target}:8222",
                    "severity": Severity.MEDIUM,
                    "description": "NATS server monitoring endpoint accessible, reveals configuration",
                    "detail": body[:2048],
                })
        except asyncio.TimeoutError:
            pass
        return results
