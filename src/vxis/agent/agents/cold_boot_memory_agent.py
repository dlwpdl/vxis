"""L8-04 ColdBootMemoryAgent — RAM artifact analysis, hibernation files, VM snapshot examination."""

from __future__ import annotations

import asyncio
import shutil

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class ColdBootMemoryAgent(BaseAgent):
    agent_id = "cold_boot_memory"
    description = (
        "RAM artifact analysis, hibernation file examination, VM snapshot "
        "memory extraction, cold boot attack surface assessment"
    )

    # Common memory artifact paths
    _HIBERNATION_PATHS = [
        "/sys/power/state",
        "/sys/power/mem_sleep",
        "/proc/meminfo",
    ]

    _VM_SNAPSHOT_INDICATORS = [
        ".vmem",
        ".vmsn",
        ".vmss",  # VMware
        ".sav",  # Hyper-V
        ".qcow2",
        ".img",  # QEMU/KVM
    ]

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Check for memory dump / hibernation exposure
        mem_findings = await self._check_memory_exposure(target)
        findings.extend(mem_findings)

        # Phase 2: VM snapshot analysis if target is virtualized
        vm_findings = await self._check_vm_snapshots(target)
        findings.extend(vm_findings)

        # Phase 3: Check for memory disclosure via /proc or debug interfaces
        proc_findings = await self._check_proc_exposure(target)
        findings.extend(proc_findings)

        # Phase 4: Assess cold boot attack surface
        cold_boot_assessment = self._assess_cold_boot_surface(target)
        findings.append(cold_boot_assessment)

        # Phase 5: Check for core dump configuration
        core_findings = await self._check_core_dumps(target)
        findings.extend(core_findings)

        # Generate chain hypotheses
        if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
            hypotheses.append(
                Hypothesis(
                    title=f"Credential extraction from memory artifacts on {target}",
                    rationale="Memory artifacts found that may contain plaintext credentials",
                    probability=0.7,
                    impact=0.95,
                    suggested_agent="lateral_move",
                    suggested_tool="volatility",
                )
            )
            hypotheses.append(
                Hypothesis(
                    title=f"Encryption key recovery from memory on {target}",
                    rationale="Memory dumps may contain disk encryption keys (BitLocker, LUKS)",
                    probability=0.5,
                    impact=0.95,
                    suggested_agent="cold_boot_memory",
                    suggested_tool="aeskeyfind",
                )
            )

        hypotheses.append(
            Hypothesis(
                title=f"VM escape via snapshot manipulation on {target}",
                rationale="VM snapshots may expose hypervisor state for escape analysis",
                probability=0.2,
                impact=0.95,
                suggested_agent="virtualization",
            )
        )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "total_findings": len(findings),
                "critical_findings": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "assessment_type": "memory_forensics",
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _check_memory_exposure(self, target: str) -> list[Evidence]:
        """Check for exposed memory/hibernation files via network shares or HTTP."""
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # Check for exposed hiberfil.sys or pagefile.sys via common paths
        memory_files = [
            "/hiberfil.sys",
            "/pagefile.sys",
            "/swapfile.sys",
            "/proc/kcore",
            "/dev/mem",
            "/dev/kmem",
        ]
        for path in memory_files:
            proc = await asyncio.create_subprocess_exec(
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "5",
                f"http://{target}{path}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            status = stdout.decode().strip()
            if status in ("200", "206"):
                results.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"Memory artifact exposed via HTTP: {path}",
                        severity=Severity.CRITICAL,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description=(
                            f"Memory artifact {path} is accessible via HTTP on {target}. "
                            "This may allow extraction of credentials, encryption keys, "
                            "and sensitive data from system memory."
                        ),
                        request=f"GET http://{target}{path}",
                        response=f"HTTP {status}",
                        tags=["memory", "cold-boot", "data-exposure"],
                    )
                )
        return results

    async def _check_vm_snapshots(self, target: str) -> list[Evidence]:
        """Check for accessible VM snapshot files via SMB or NFS."""
        results: list[Evidence] = []
        if not shutil.which("smbclient"):
            return results

        proc = await asyncio.create_subprocess_exec(
            "smbclient",
            "-L",
            target,
            "-N",
            "-g",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode()
        shares = [line.split("|")[1] for line in output.splitlines() if line.startswith("Disk|")]
        for share in shares:
            # Check for VM memory files in accessible shares
            proc2 = await asyncio.create_subprocess_exec(
                "smbclient",
                f"//{target}/{share}",
                "-N",
                "-c",
                "recurse; ls *.vmem; ls *.vmsn; ls *.vmss; ls *.sav",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=30)
            vm_output = stdout2.decode()
            for ext in self._VM_SNAPSHOT_INDICATORS:
                if ext in vm_output.lower():
                    results.append(
                        Evidence(
                            agent_id=self.agent_id,
                            title=f"VM snapshot/memory file found in share //{target}/{share}",
                            severity=Severity.CRITICAL,
                            evidence_type=EvidenceType.MISCONFIGURATION,
                            description=(
                                f"VM memory/snapshot files ({ext}) accessible in SMB share. "
                                "These files contain raw memory contents including credentials."
                            ),
                            response=vm_output[:2000],
                            tags=["memory", "vm-snapshot", "smb", "data-exposure"],
                        )
                    )
                    break
        return results

    async def _check_proc_exposure(self, target: str) -> list[Evidence]:
        """Check for /proc/*/mem or debug memory interfaces."""
        results: list[Evidence] = []
        if not shutil.which("nmap"):
            return results

        # Check for debug ports that expose memory (JTAG over network, GDB, etc.)
        debug_ports = "1234,3333,4444,9090,11211"
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "-Pn",
            "-sV",
            "-p",
            debug_ports,
            "--open",
            "-oG",
            "-",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stdout.decode()
        debug_keywords = ["gdb", "memcached", "debug", "jtag"]
        if any(kw in output.lower() for kw in debug_keywords):
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Debug/memory service detected on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        "Debug or memory-access service port is open. Services like "
                        "GDB server or Memcached may allow direct memory reading."
                    ),
                    response=output,
                    tags=["memory", "debug", "gdb"],
                )
            )
        return results

    def _assess_cold_boot_surface(self, target: str) -> Evidence:
        """Document cold boot attack surface assessment."""
        return Evidence(
            agent_id=self.agent_id,
            title=f"Cold boot attack surface assessment for {target}",
            severity=Severity.INFO,
            evidence_type=EvidenceType.OTHER,
            description=(
                "Cold boot attack assessment:\n"
                "- DDR3/DDR4 DRAM retains data for seconds after power loss\n"
                "- Cooling RAM extends retention to minutes\n"
                "- Encryption keys (AES, RSA) recoverable via aeskeyfind/rsakeyfind\n"
                "- Mitigations: full memory encryption (AMD SEV/SME, Intel TME), "
                "memory scrambling, secure memory wipe on shutdown\n"
                "- Physical access required for hardware-based cold boot attacks\n"
                "- VM snapshots and hibernation files provide equivalent access remotely"
            ),
            tags=["cold-boot", "assessment", "physical"],
        )

    async def _check_core_dumps(self, target: str) -> list[Evidence]:
        """Check for exposed core dumps that contain memory contents."""
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # Check for common core dump exposure paths
        core_paths = [
            "/core",
            "/tmp/core",
            "/var/crash/",
            "/var/cores/",
            "/.core",
        ]
        for path in core_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "5",
                f"http://{target}{path}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            status = stdout.decode().strip()
            if status == "200":
                results.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"Core dump path accessible: {path}",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description=(
                            f"Core dump path {path} returns HTTP 200 on {target}. "
                            "Core dumps contain process memory including credentials."
                        ),
                        request=f"GET http://{target}{path}",
                        response=f"HTTP {status}",
                        tags=["memory", "core-dump", "data-exposure"],
                    )
                )
        return results
