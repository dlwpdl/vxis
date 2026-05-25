"""CRT-P6 BluetoothDeepAgent — KNOB, BIAS, BlueSnarfing, BLE attacks."""

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
class BluetoothDeepAgent(BaseAgent):
    agent_id = "bluetooth_deep"
    description = "KNOB, BIAS, BlueSnarfing, BLE GATT abuse, Bluetooth reconnaissance"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        has_hcitool = shutil.which("hcitool") is not None
        has_bluetoothctl = shutil.which("bluetoothctl") is not None
        has_spooftooph = shutil.which("spooftooph") is not None
        has_redfang = shutil.which("redfang") is not None
        has_gatttool = shutil.which("gatttool") is not None

        tools_available = [
            t
            for t, ok in [
                ("hcitool", has_hcitool),
                ("bluetoothctl", has_bluetoothctl),
                ("spooftooph", has_spooftooph),
                ("redfang", has_redfang),
                ("gatttool", has_gatttool),
            ]
            if ok
        ]

        # 1. Classic Bluetooth device discovery
        if has_hcitool:
            bt_devices = await self._run_hcitool_scan()
            if bt_devices:
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"Bluetooth devices discovered near {target}",
                        severity=Severity.INFO,
                        evidence_type=EvidenceType.NETWORK,
                        description=f"Found {len(bt_devices)} Bluetooth devices in range",
                        response=json.dumps(bt_devices, indent=2),
                        tags=["bluetooth", "discovery", "classic"],
                    )
                )

                for dev in bt_devices:
                    bd_addr = dev.get("addr", "")
                    name = dev.get("name", "Unknown")

                    # Service enumeration
                    services = await self._run_sdp_browse(bd_addr)
                    if services:
                        findings.append(
                            Evidence(
                                agent_id=self.agent_id,
                                title=f"Bluetooth services on {name} ({bd_addr})",
                                severity=Severity.LOW,
                                evidence_type=EvidenceType.NETWORK,
                                description=f"{len(services)} SDP services enumerated",
                                response="\n".join(services[:30]),
                                tags=["bluetooth", "sdp", "services"],
                            )
                        )

                        # Check for OBEX / file transfer services
                        obex_services = [s for s in services if "obex" in s.lower()]
                        if obex_services:
                            findings.append(
                                Evidence(
                                    agent_id=self.agent_id,
                                    title=f"OBEX file transfer on {name} ({bd_addr})",
                                    severity=Severity.HIGH,
                                    evidence_type=EvidenceType.MISCONFIGURATION,
                                    description="OBEX push/FTP service exposed — may allow "
                                    "unauthorized file access (BlueSnarfing)",
                                    response="\n".join(obex_services),
                                    tags=["bluetooth", "obex", "bluesnarfing"],
                                )
                            )
                            hypotheses.append(
                                Hypothesis(
                                    title=f"BlueSnarfing attack on {name} ({bd_addr})",
                                    rationale="OBEX service exposed without apparent auth",
                                    probability=0.6,
                                    impact=0.8,
                                    suggested_agent="bluetooth_deep",
                                )
                            )

                    # KNOB/BIAS hypothesis for all classic BT devices
                    hypotheses.append(
                        Hypothesis(
                            title=f"KNOB attack (entropy reduction) on {name}",
                            rationale=(
                                "Classic Bluetooth device found; KNOB (CVE-2019-9506) "
                                "allows forcing 1-byte encryption key entropy"
                            ),
                            probability=0.4,
                            impact=0.9,
                            suggested_agent="bluetooth_deep",
                        )
                    )

        # 2. BLE device scanning
        if has_hcitool:
            ble_devices = await self._run_ble_scan()
            if ble_devices:
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"BLE devices discovered near {target}",
                        severity=Severity.INFO,
                        evidence_type=EvidenceType.NETWORK,
                        description=f"Found {len(ble_devices)} BLE devices in range",
                        response=json.dumps(ble_devices, indent=2),
                        tags=["bluetooth", "ble", "discovery"],
                    )
                )

                for dev in ble_devices:
                    bd_addr = dev.get("addr", "")
                    # GATT service enumeration
                    if has_gatttool:
                        gatt_services = await self._run_gatt_discovery(bd_addr)
                        if gatt_services:
                            findings.append(
                                Evidence(
                                    agent_id=self.agent_id,
                                    title=f"BLE GATT services on {bd_addr}",
                                    severity=Severity.MEDIUM,
                                    evidence_type=EvidenceType.NETWORK,
                                    description="GATT characteristics enumerated. "
                                    "Writable characteristics may allow control.",
                                    response="\n".join(gatt_services[:30]),
                                    tags=["bluetooth", "ble", "gatt"],
                                )
                            )
                            hypotheses.append(
                                Hypothesis(
                                    title=f"BLE GATT characteristic manipulation on {bd_addr}",
                                    rationale="Writable GATT characteristics may allow "
                                    "unauthorized device control",
                                    probability=0.5,
                                    impact=0.7,
                                    suggested_agent="bluetooth_deep",
                                    suggested_tool="gatttool",
                                )
                            )

        # 3. If no BT tools, document the attack surface
        if not tools_available:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Bluetooth attack surface assessment for {target}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.OTHER,
                    description=(
                        "No Bluetooth tools available. Documented attack vectors: "
                        "KNOB (CVE-2019-9506), BIAS (CVE-2020-10135), "
                        "BlueSnarfing, BlueBugging, BLE GATT manipulation, "
                        "BLE pairing bypass, SweynTooth (BLE SoC vulns)."
                    ),
                    tags=["bluetooth", "assessment", "no-tools"],
                )
            )

        # 4. IoT/embedded context hypotheses
        if any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings):
            hypotheses.append(
                Hypothesis(
                    title=f"IoT device compromise via Bluetooth near {target}",
                    rationale="Bluetooth vulnerabilities found; IoT devices often lack updates",
                    probability=0.6,
                    impact=0.8,
                    suggested_agent="os_host",
                )
            )
            hypotheses.append(
                Hypothesis(
                    title=f"Network pivot via compromised Bluetooth device near {target}",
                    rationale="Bluetooth device may bridge to wired network",
                    probability=0.4,
                    impact=0.85,
                    suggested_agent="l2_network",
                )
            )

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

    async def _run_hcitool_scan(self) -> list[dict[str, Any]]:
        """Classic Bluetooth inquiry scan."""
        proc = await asyncio.create_subprocess_exec(
            "hcitool",
            "scan",
            "--flush",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            devices: list[dict[str, Any]] = []
            for line in stdout.decode().splitlines():
                line = line.strip()
                if line and not line.startswith("Scanning"):
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        devices.append({"addr": parts[0].strip(), "name": parts[1].strip()})
            return devices
        except asyncio.TimeoutError:
            return []

    async def _run_sdp_browse(self, bd_addr: str) -> list[str]:
        """Enumerate SDP services on a Bluetooth device."""
        if not shutil.which("sdptool"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "sdptool",
            "browse",
            bd_addr,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            return [line.strip() for line in stdout.decode().splitlines() if line.strip()]
        except asyncio.TimeoutError:
            return []

    async def _run_ble_scan(self) -> list[dict[str, Any]]:
        """BLE device scan using hcitool lescan."""
        proc = await asyncio.create_subprocess_exec(
            "hcitool",
            "lescan",
            "--duplicates",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            # BLE scan runs continuously — kill after 10 seconds
            await asyncio.sleep(10)
            proc.terminate()
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            devices: list[dict[str, Any]] = []
            seen: set[str] = set()
            for line in stdout.decode().splitlines():
                line = line.strip()
                if line and not line.startswith("LE Scan"):
                    parts = line.split(maxsplit=1)
                    if len(parts) >= 1 and parts[0] not in seen:
                        seen.add(parts[0])
                        devices.append(
                            {
                                "addr": parts[0],
                                "name": parts[1] if len(parts) > 1 else "(unknown)",
                            }
                        )
            return devices
        except asyncio.TimeoutError:
            proc.kill()
            return []

    async def _run_gatt_discovery(self, bd_addr: str) -> list[str]:
        """Enumerate BLE GATT characteristics."""
        proc = await asyncio.create_subprocess_exec(
            "gatttool",
            "-b",
            bd_addr,
            "--characteristics",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            return [line.strip() for line in stdout.decode().splitlines() if line.strip()]
        except asyncio.TimeoutError:
            return []
