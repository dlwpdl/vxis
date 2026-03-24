"""L7 DatabaseAgent — MongoDB/Redis/Elasticsearch no-auth, NoSQL Injection."""

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

_DB_PORTS: dict[int, str] = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    1521: "Oracle",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    9300: "Elasticsearch-transport",
    5984: "CouchDB",
    8529: "ArangoDB",
    7474: "Neo4j",
    7687: "Neo4j-Bolt",
    26257: "CockroachDB",
    28015: "RethinkDB",
    8086: "InfluxDB",
    9042: "Cassandra",
}


@register
class DatabaseAgent(BaseAgent):
    agent_id = "database"
    description = "MongoDB/Redis/Elasticsearch no-auth, NoSQL Injection, database exposure"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Port scan for database services
        db_services = await self._scan_db_ports(target)
        for svc in db_services:
            port = svc.get("port", 0)
            service = svc.get("service", _DB_PORTS.get(port, "unknown"))
            product = svc.get("product", "")

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Database service: {service} on {target}:{port}",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.NETWORK,
                description=f"{service} ({product}) accessible on port {port}",
                response=json.dumps(svc, indent=2),
                tags=["database", service.lower(), f"port-{port}"],
            ))

        # Phase 2: No-auth checks for common databases
        noauth_results = await self._check_noauth(target, db_services)
        for na in noauth_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"No authentication: {na['service']} on {target}:{na['port']}",
                severity=Severity.CRITICAL,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=f"{na['service']} at {target}:{na['port']} allows unauthenticated access",
                response=na.get("proof", "")[:4096],
                tags=["database", "no-auth", na["service"].lower()],
            ))
            hypotheses.append(Hypothesis(
                title=f"Data exfiltration via unauthenticated {na['service']} on {target}",
                rationale=f"{na['service']} has no authentication",
                probability=0.95, impact=1.0,
                suggested_agent="data_exfiltration",
            ))

        # Phase 3: Nmap database scripts
        nmap_results = await self._run_nmap_db_scripts(target)
        for nr in nmap_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=nr["title"],
                severity=nr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=nr["description"],
                response=nr.get("output", ""),
                tags=["database", "nmap-script"],
            ))

        # Phase 4: HTTP-based database interfaces
        web_db = await self._check_web_db_interfaces(target)
        for wd in web_db:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=wd["title"],
                severity=wd["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=wd["description"],
                tags=["database", "web-interface"],
            ))
            if wd["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Database admin panel exploitation on {target}",
                    rationale=wd["description"],
                    probability=0.7, impact=0.9,
                    suggested_agent="web",
                ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "db_services": len(db_services),
                "noauth_found": len(noauth_results),
            },
        )

    async def _scan_db_ports(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        ports = ",".join(str(p) for p in _DB_PORTS)
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-Pn", "--open", "-p", ports, "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            return self._parse_nmap_xml(stdout.decode())
        except asyncio.TimeoutError:
            return []

    def _parse_nmap_xml(self, xml_data: str) -> list[dict[str, Any]]:
        import xml.etree.ElementTree as ET
        results: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_data)
            for port_elem in root.findall(".//port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") == "open":
                    svc = port_elem.find("service")
                    port_id = int(port_elem.get("portid", 0))
                    results.append({
                        "port": port_id,
                        "service": svc.get("name", "") if svc is not None else "",
                        "product": svc.get("product", "") if svc is not None else "",
                        "version": svc.get("version", "") if svc is not None else "",
                    })
        except ET.ParseError:
            pass
        return results

    async def _check_noauth(self, target: str, services: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        port_set = {s["port"] for s in services}

        # MongoDB no-auth check
        if 27017 in port_set and shutil.which("curl"):
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", f"http://{target}:27017", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                body = stdout.decode(errors="replace")
                if "mongodb" in body.lower() or "ismaster" in body.lower():
                    results.append({
                        "service": "MongoDB", "port": 27017,
                        "proof": body[:2048],
                    })
            except asyncio.TimeoutError:
                pass

        # Redis no-auth check
        if 6379 in port_set and shutil.which("nmap"):
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-Pn", "-p", "6379", "--script", "redis-info", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                output = stdout.decode()
                if "redis_version" in output:
                    results.append({
                        "service": "Redis", "port": 6379,
                        "proof": output[:2048],
                    })
            except asyncio.TimeoutError:
                pass

        # Elasticsearch no-auth
        if 9200 in port_set and shutil.which("curl"):
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", f"http://{target}:9200/_cat/indices", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                body = stdout.decode(errors="replace")
                if "green" in body or "yellow" in body or "red" in body:
                    results.append({
                        "service": "Elasticsearch", "port": 9200,
                        "proof": body[:2048],
                    })
            except asyncio.TimeoutError:
                pass

        # CouchDB no-auth
        if 5984 in port_set and shutil.which("curl"):
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", f"http://{target}:5984/_all_dbs", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                body = stdout.decode(errors="replace")
                if body.strip().startswith("["):
                    results.append({
                        "service": "CouchDB", "port": 5984,
                        "proof": body[:2048],
                    })
            except asyncio.TimeoutError:
                pass

        return results

    async def _run_nmap_db_scripts(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-Pn", "-p", "3306,5432,1433,27017,6379,9200",
            "--script", "mysql-info,mysql-empty-password,pgsql-brute,ms-sql-info,mongodb-info",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            output = stdout.decode()
            if "empty-password" in output and "Login" in output:
                results.append({
                    "title": f"MySQL empty password on {target}",
                    "severity": Severity.CRITICAL,
                    "description": "MySQL allows login with empty password",
                    "output": output[:2048],
                })
            if "mysql-info" in output:
                results.append({
                    "title": f"MySQL info disclosure on {target}",
                    "severity": Severity.LOW,
                    "description": "MySQL version and capabilities disclosed",
                    "output": output[output.find("mysql-info"):][:1024],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_web_db_interfaces(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        interfaces = [
            (f"http://{target}:8080/phpmyadmin/", "phpMyAdmin"),
            (f"http://{target}/phpmyadmin/", "phpMyAdmin"),
            (f"http://{target}:8081/", "phpPgAdmin"),
            (f"http://{target}:1234/", "Adminer"),
            (f"http://{target}:8081/db/", "Mongo Express"),
            (f"http://{target}:5601/", "Kibana"),
            (f"http://{target}:9200/_plugin/head/", "Elasticsearch Head"),
        ]
        for url, name in interfaces:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                url, "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                status = stdout.decode().strip()
                if status in ("200", "301", "302"):
                    results.append({
                        "title": f"Database management UI: {name} at {url}",
                        "severity": Severity.HIGH,
                        "description": f"{name} accessible at {url} (HTTP {status})",
                    })
            except asyncio.TimeoutError:
                continue
        return results
