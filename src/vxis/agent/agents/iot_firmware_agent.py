"""L7 IoTFirmwareAgent — Firmware analysis, default credentials, JTAG/UART detection."""

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

_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("root", "root"), ("root", "toor"), ("admin", ""),
    ("user", "user"), ("guest", "guest"), ("support", "support"),
    ("ubnt", "ubnt"), ("pi", "raspberry"), ("admin", "admin123"),
]

_IOT_PORTS: dict[int, str] = {
    80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT",
    23: "Telnet", 22: "SSH", 161: "SNMP",
    1883: "MQTT", 8883: "MQTT-TLS",
    5683: "CoAP", 502: "Modbus",
    8443: "HTTPS-ALT", 49152: "UPnP",
}


@register
class IoTFirmwareAgent(BaseAgent):
    agent_id = "iot_firmware"
    description = "IoT firmware analysis, default credentials, JTAG/UART, protocol testing"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: IoT port scan
        iot_services = await self._scan_iot_ports(target)
        for svc in iot_services:
            port = svc.get("port", 0)
            service = svc.get("service", "")
            product = svc.get("product", "")
            version = svc.get("version", "")

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"IoT service: {service} on {target}:{port} ({product} {version})",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=f"IoT-related service found: {service} ({product})",
                response=json.dumps(svc, indent=2),
                tags=["iot", service.lower(), f"port-{port}"],
            ))

            if port == 1883:
                hypotheses.append(Hypothesis(
                    title=f"MQTT no-auth or weak-auth on {target}",
                    rationale="MQTT broker exposed on port 1883",
                    probability=0.6, impact=0.8,
                    suggested_agent="iot_firmware",
                ))

        # Phase 2: Default credential testing
        default_cred_results = await self._test_default_creds(target, iot_services)
        for dcr in default_cred_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Default credentials: {dcr['service']} on {target} ({dcr['username']}:{dcr['password']})",
                severity=Severity.CRITICAL,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"Default credentials {dcr['username']}:{dcr['password']} "
                    f"accepted by {dcr['service']} on {target}"
                ),
                tags=["iot", "default-credentials", dcr["service"].lower()],
            ))
            hypotheses.append(Hypothesis(
                title=f"Full device control via default creds on {target}",
                rationale=f"Default credentials work for {dcr['service']}",
                probability=0.9, impact=0.95,
                suggested_agent="os_host",
            ))

        # Phase 3: MQTT broker analysis
        mqtt_results = await self._check_mqtt(target)
        for mr in mqtt_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=mr["title"],
                severity=mr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=mr["description"],
                response=mr.get("detail", ""),
                tags=["iot", "mqtt"],
            ))

        # Phase 4: UPnP discovery
        upnp_results = await self._check_upnp(target)
        for ur in upnp_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=ur["title"],
                severity=ur["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=ur["description"],
                response=ur.get("detail", ""),
                tags=["iot", "upnp"],
            ))
            if ur["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"UPnP exploitation for port mapping on {target}",
                    rationale="UPnP enabled and may allow arbitrary port forwarding",
                    probability=0.55, impact=0.8,
                    suggested_agent="iot_firmware",
                ))

        # Phase 5: Nuclei IoT templates
        nuclei_results = await self._run_nuclei_iot(target, context.mission.stealth)
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
                tags=["iot", "nuclei", nf.get("template-id", "")],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "iot_services": len(iot_services),
                "default_creds_found": len(default_cred_results),
            },
        )

    async def _scan_iot_ports(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        ports = ",".join(str(p) for p in _IOT_PORTS)
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

    async def _test_default_creds(
        self, target: str, services: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Test HTTP basic auth with default credentials
        http_ports = [s["port"] for s in services if s.get("port") in (80, 443, 8080, 8443)]
        for port in http_ports:
            scheme = "https" if port in (443, 8443) else "http"
            for username, password in _DEFAULT_CREDS[:6]:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                    "-u", f"{username}:{password}", "-k",
                    f"{scheme}://{target}:{port}/", "--max-time", "5",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                    status = stdout.decode().strip()
                    if status == "200":
                        results.append({
                            "service": f"HTTP({port})",
                            "username": username,
                            "password": password or "(empty)",
                        })
                        break  # Found valid creds, skip remaining
                except asyncio.TimeoutError:
                    continue
        return results

    async def _check_mqtt(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-Pn", "-p", "1883,8883",
            "--script", "mqtt-subscribe", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            if "mqtt-subscribe" in output and "Topics" in output:
                results.append({
                    "title": f"MQTT broker accessible without auth on {target}",
                    "severity": Severity.HIGH,
                    "description": "MQTT broker allows unauthenticated subscription",
                    "detail": output[:2048],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_upnp(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sU", "-Pn", "-p", "1900",
            "--script", "upnp-info", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            if "upnp-info" in output:
                results.append({
                    "title": f"UPnP service on {target}",
                    "severity": Severity.MEDIUM,
                    "description": "UPnP enabled; may allow unauthorized port mapping",
                    "detail": output[:2048],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _run_nuclei_iot(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "iot,router,camera,default-login,firmware",
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
