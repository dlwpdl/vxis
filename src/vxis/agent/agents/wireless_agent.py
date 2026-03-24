"""CRT-P5 WirelessAgent — WiFi WPA2/3, Evil Twin, PMKID, KRACK, WPS attacks."""

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
class WirelessAgent(BaseAgent):
    agent_id = "wireless"
    description = "WiFi WPA2/3, Evil Twin, PMKID capture, KRACK, WPS PIN attacks"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # 1. Check for wireless tools availability
        has_aircrack = shutil.which("aircrack-ng") is not None
        has_airodump = shutil.which("airodump-ng") is not None
        has_wash = shutil.which("wash") is not None
        has_hcxdumptool = shutil.which("hcxdumptool") is not None
        has_iwlist = shutil.which("iwlist") is not None

        tools_available = []
        if has_aircrack:
            tools_available.append("aircrack-ng")
        if has_airodump:
            tools_available.append("airodump-ng")
        if has_wash:
            tools_available.append("wash")
        if has_hcxdumptool:
            tools_available.append("hcxdumptool")
        if has_iwlist:
            tools_available.append("iwlist")

        if not tools_available:
            # No wireless tools — document attack surface theoretically
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Wireless attack surface assessment for {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.OTHER,
                description=(
                    "No wireless tools available (aircrack-ng, hcxdumptool, iwlist). "
                    "Wireless attack vectors documented: WPA2 PMKID capture, "
                    "4-way handshake capture, Evil Twin / Karma attack, "
                    "KRACK (CVE-2017-13077), WPS PIN brute-force, "
                    "WPA3 Dragonblood (CVE-2019-9494/9496)."
                ),
                tags=["wireless", "assessment", "no-tools"],
            ))
            # Still generate hypotheses for the attack graph
            hypotheses.append(Hypothesis(
                title=f"WPA2 PMKID/handshake capture near {target}",
                rationale="Wireless assessment requested; PMKID attacks require "
                          "only a single frame and no client interaction",
                probability=0.5, impact=0.8,
                suggested_agent="wireless",
                suggested_tool="hcxdumptool",
            ))
            return AgentResult(
                agent_id=self.agent_id,
                findings=findings,
                hypotheses=hypotheses,
                status="completed",
                metadata={"tools_available": tools_available},
            )

        # 2. Scan for wireless networks using iwlist
        if has_iwlist:
            wifi_networks = await self._run_iwlist_scan()
            if wifi_networks:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Wireless networks detected near {target}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description=f"Found {len(wifi_networks)} wireless networks in range",
                    response=json.dumps(wifi_networks[:20], indent=2),
                    tags=["wireless", "discovery", "ssid"],
                ))

                # Analyse each network for weaknesses
                for net in wifi_networks:
                    encryption = net.get("encryption", "").upper()
                    ssid = net.get("ssid", "Hidden")

                    if "WEP" in encryption:
                        findings.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"WEP network detected: {ssid}",
                            severity=Severity.CRITICAL,
                            evidence_type=EvidenceType.MISCONFIGURATION,
                            description="WEP encryption is trivially broken. "
                                        "Key recovery in minutes with aircrack-ng.",
                            tags=["wireless", "wep", "critical"],
                        ))
                        hypotheses.append(Hypothesis(
                            title=f"WEP key recovery for {ssid}",
                            rationale="WEP network found; key can be cracked in minutes",
                            probability=0.95, impact=0.9,
                            suggested_agent="wireless",
                            suggested_tool="aircrack-ng",
                        ))
                    elif "WPA" in encryption and "WPA3" not in encryption:
                        hypotheses.append(Hypothesis(
                            title=f"WPA2 PMKID capture for {ssid}",
                            rationale="WPA2 network found; PMKID clientless attack viable",
                            probability=0.7, impact=0.8,
                            suggested_agent="wireless",
                            suggested_tool="hcxdumptool",
                        ))
                    elif "OPEN" in encryption or not encryption:
                        findings.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"Open wireless network: {ssid}",
                            severity=Severity.HIGH,
                            evidence_type=EvidenceType.MISCONFIGURATION,
                            description="Open (unencrypted) wireless network. "
                                        "All traffic is cleartext.",
                            tags=["wireless", "open", "no-encryption"],
                        ))

        # 3. WPS-enabled network detection
        if has_wash:
            wps_networks = await self._run_wash_scan()
            for net in wps_networks:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"WPS enabled: {net.get('ssid', 'Unknown')}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"WPS version {net.get('version', '?')} enabled on "
                        f"BSSID {net.get('bssid', '?')}. "
                        f"Locked: {net.get('locked', 'No')}. "
                        "Pixie-Dust or online brute-force may recover WPS PIN."
                    ),
                    tags=["wireless", "wps", "pin-attack"],
                ))
                if net.get("locked", "No") == "No":
                    hypotheses.append(Hypothesis(
                        title=f"WPS PIN brute-force on {net.get('ssid', 'Unknown')}",
                        rationale="WPS enabled and not locked — PIN brute-force viable",
                        probability=0.8, impact=0.85,
                        suggested_agent="wireless",
                        suggested_tool="reaver",
                    ))

        # 4. Cross-agent hypotheses
        if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
            hypotheses.append(Hypothesis(
                title=f"Credential interception via wireless MITM near {target}",
                rationale="Vulnerable wireless networks found; Evil Twin or "
                          "deauth + handshake capture enables credential theft",
                probability=0.6, impact=0.9,
                suggested_agent="identity_ad",
            ))
            hypotheses.append(Hypothesis(
                title=f"L2 pivot via compromised wireless near {target}",
                rationale="Wireless access grants L2 segment access",
                probability=0.6, impact=0.85,
                suggested_agent="l2_network",
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"tools_available": tools_available},
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _run_iwlist_scan(self) -> list[dict[str, Any]]:
        """Scan for wireless networks using iwlist."""
        proc = await asyncio.create_subprocess_exec(
            "iwlist", "wlan0", "scan",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            return self._parse_iwlist(stdout.decode())
        except asyncio.TimeoutError:
            return []

    @staticmethod
    def _parse_iwlist(output: str) -> list[dict[str, Any]]:
        """Parse iwlist scan output into structured data."""
        networks: list[dict[str, Any]] = []
        current: dict[str, Any] = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Cell"):
                if current:
                    networks.append(current)
                current = {}
                parts = line.split("Address:")
                if len(parts) > 1:
                    current["bssid"] = parts[1].strip()
            elif "ESSID:" in line:
                ssid = line.split("ESSID:")[-1].strip().strip('"')
                current["ssid"] = ssid
            elif "Encryption key:" in line:
                current["encryption_key"] = "on" in line.lower()
            elif "IE:" in line:
                ie = line.split("IE:")[-1].strip()
                current.setdefault("encryption", "")
                if "WPA2" in ie:
                    current["encryption"] = "WPA2"
                elif "WPA" in ie:
                    current["encryption"] = "WPA"
            elif "Frequency:" in line:
                current["frequency"] = line.split("Frequency:")[-1].split("(")[0].strip()
            elif "Signal level=" in line:
                current["signal"] = line.split("Signal level=")[-1].strip()

        if current:
            networks.append(current)

        # Mark open networks
        for net in networks:
            if not net.get("encryption_key", True):
                net["encryption"] = "OPEN"
            elif not net.get("encryption"):
                net["encryption"] = "WEP"  # encryption key on, but no WPA IE = WEP

        return networks

    async def _run_wash_scan(self) -> list[dict[str, Any]]:
        """Detect WPS-enabled networks using wash."""
        proc = await asyncio.create_subprocess_exec(
            "wash", "-i", "wlan0", "-s",  # single scan
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            return self._parse_wash(stdout.decode())
        except asyncio.TimeoutError:
            return []

    @staticmethod
    def _parse_wash(output: str) -> list[dict[str, Any]]:
        """Parse wash output."""
        networks: list[dict[str, Any]] = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 6 and ":" in parts[0]:
                networks.append({
                    "bssid": parts[0],
                    "channel": parts[1],
                    "rssi": parts[2],
                    "version": parts[3],
                    "locked": parts[4],
                    "ssid": " ".join(parts[5:]),
                })
        return networks
