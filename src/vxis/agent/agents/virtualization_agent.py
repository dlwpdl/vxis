"""META-11 VirtualizationAgent — VM escape, hypervisor vulnerabilities, snapshot leaks."""

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


# Known hypervisor CVEs for reference
_HYPERVISOR_CVES = {
    "vmware_esxi": [
        {"cve": "CVE-2024-37085", "desc": "ESXi AD group privilege escalation", "cvss": 9.8},
        {"cve": "CVE-2023-20867", "desc": "VMware Tools authentication bypass", "cvss": 3.9},
        {"cve": "CVE-2021-22005", "desc": "vCenter file upload RCE", "cvss": 9.8},
    ],
    "virtualbox": [
        {"cve": "CVE-2024-21111", "desc": "VirtualBox local privilege escalation", "cvss": 7.8},
    ],
    "hyper-v": [
        {"cve": "CVE-2024-21407", "desc": "Hyper-V RCE vulnerability", "cvss": 8.1},
    ],
    "qemu_kvm": [
        {"cve": "CVE-2023-3019", "desc": "QEMU use-after-free in e1000e", "cvss": 6.5},
    ],
}


@register
class VirtualizationAgent(BaseAgent):
    agent_id = "virtualization"
    description = (
        "Virtualization security: VM escape vectors, hypervisor vulnerabilities, "
        "snapshot/memory leak, shared resource isolation assessment"
    )

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Detect virtualization environment
        vm_info = await self._detect_virtualization(target)
        if vm_info.get("detected"):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Virtualization detected: {vm_info.get('platform', 'unknown')}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"Target appears to be running on {vm_info.get('platform')} "
                    f"virtualization. Indicators: {vm_info.get('indicators', [])}"
                ),
                response=json.dumps(vm_info, indent=2),
                tags=["virtualization", vm_info.get("platform", "").lower()],
            ))

        # Phase 2: Check for exposed hypervisor management
        mgmt_findings = await self._check_hypervisor_management(target)
        findings.extend(mgmt_findings)

        # Phase 3: VMware-specific checks
        vmware_findings = await self._check_vmware(target)
        findings.extend(vmware_findings)

        # Phase 4: Container escape vectors (if containerized)
        container_findings = await self._check_container_escape(target)
        findings.extend(container_findings)

        # Phase 5: Snapshot and memory exposure
        snapshot_findings = await self._check_snapshot_exposure(target)
        findings.extend(snapshot_findings)

        # Phase 6: Known hypervisor CVE assessment
        platform = vm_info.get("platform", "").lower()
        cve_assessment = self._assess_hypervisor_cves(target, platform)
        if cve_assessment:
            findings.append(cve_assessment)

        # Phase 7: Shared resource isolation assessment
        findings.append(Evidence(
            agent_id=self.agent_id,
            title=f"VM isolation assessment for {target}",
            severity=Severity.INFO,
            evidence_type=EvidenceType.OTHER,
            description=(
                "VM Escape Attack Vectors Assessment:\n"
                "- Shared memory (dedup): Cross-VM data leakage via memory dedup\n"
                "- Shared CPU: Spectre/Meltdown side-channel across VMs\n"
                "- Virtual device emulation: Bugs in virtual NIC/disk/GPU drivers\n"
                "- Guest additions/tools: Privilege escalation via VM tools\n"
                "- Shared clipboard/drag-drop: Data leakage between host and guest\n"
                "- Network isolation: VLAN hopping between VM segments\n"
                "- Storage: Shared datastore access between VMs"
            ),
            tags=["virtualization", "isolation", "assessment"],
        ))

        # Generate hypotheses
        if vm_info.get("detected"):
            hypotheses.append(Hypothesis(
                title=f"VM escape from {target} to hypervisor",
                rationale=f"Target runs on {vm_info.get('platform')} — escape vectors exist",
                probability=0.15,
                impact=0.99,
                suggested_agent="virtualization",
            ))
            hypotheses.append(Hypothesis(
                title=f"Cross-VM side-channel attack from {target}",
                rationale="Shared CPU may allow Spectre/Meltdown variants",
                probability=0.3,
                impact=0.8,
                suggested_agent="virtualization",
            ))
        if mgmt_findings:
            hypotheses.append(Hypothesis(
                title=f"Hypervisor takeover via management interface on {target}",
                rationale="Hypervisor management interface exposed",
                probability=0.5,
                impact=0.99,
                suggested_agent="web",
            ))
        hypotheses.append(Hypothesis(
            title=f"VM snapshot containing credentials for {target}",
            rationale="VM snapshots may contain memory dumps with secrets",
            probability=0.4,
            impact=0.9,
            suggested_agent="cold_boot_memory",
        ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "virtualization_detected": vm_info.get("detected", False),
                "platform": vm_info.get("platform", "unknown"),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _detect_virtualization(self, target: str) -> dict[str, Any]:
        result: dict[str, Any] = {"detected": False}
        if not shutil.which("nmap"):
            return result

        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "-sV", "-O", "--osscan-guess",
            "-p", "22,80,443", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode().lower()

        indicators: list[str] = []
        platform = "unknown"

        vm_signatures = {
            "vmware": ["vmware", "vsphere", "esxi"],
            "virtualbox": ["virtualbox", "vbox"],
            "hyper-v": ["hyper-v", "microsoft virtual"],
            "kvm": ["kvm", "qemu", "virtio"],
            "xen": ["xen", "citrix"],
            "aws": ["amazon", "aws", "ec2"],
            "azure": ["azure", "microsoft cloud"],
            "gcp": ["google", "gcp"],
        }
        for plat, keywords in vm_signatures.items():
            for kw in keywords:
                if kw in output:
                    result["detected"] = True
                    platform = plat
                    indicators.append(kw)

        # Check MAC address OUI for virtual NICs
        if "08:00:27" in output:  # VirtualBox
            indicators.append("VirtualBox MAC OUI")
            platform = "virtualbox"
        elif "00:50:56" in output or "00:0c:29" in output:  # VMware
            indicators.append("VMware MAC OUI")
            platform = "vmware"

        result["platform"] = platform
        result["indicators"] = indicators
        if indicators:
            result["detected"] = True
        return result

    async def _check_hypervisor_management(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        mgmt_endpoints = {
            "/ui/": "VMware vSphere Client",
            "/vsphere-client/": "VMware vSphere Client (legacy)",
            "/sdk": "VMware vSphere SDK",
            "/nsx/": "VMware NSX Manager",
            ":9440/console/": "Nutanix Prism",
            "/ovirt-engine/": "oVirt/RHEV Manager",
            ":8006/": "Proxmox VE",
        }
        for path, name in mgmt_endpoints.items():
            port = ""
            if path.startswith(":"):
                parts = path.split("/", 1)
                port = parts[0][1:]
                path = "/" + parts[1] if len(parts) > 1 else "/"
                url = f"https://{target}:{port}{path}"
            else:
                url = f"https://{target}{path}"

            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", "5", "-k", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            code = stdout.decode().strip()
            if code in ("200", "301", "302", "401", "403"):
                results.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Hypervisor management: {name} on {target}",
                    severity=Severity.CRITICAL if code in ("200", "301", "302") else Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"{name} management interface accessible at {url} "
                        f"(HTTP {code}). Compromising this grants full control "
                        "over all virtual machines."
                    ),
                    request=f"GET {url}",
                    response=f"HTTP {code}",
                    tags=["virtualization", "management", "hypervisor"],
                ))
        return results

    async def _check_vmware(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # Check VMware SOAP API
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--max-time", "5", "-k",
            f"https://{target}/sdk/vimServiceVersions.xml",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        content = stdout.decode()
        if "vimService" in content or "vcVersion" in content:
            results.append(Evidence(
                agent_id=self.agent_id,
                title=f"VMware vSphere API exposed on {target}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    "VMware vSphere SOAP API is accessible. Version information "
                    "disclosed. This API allows full VM management with valid credentials."
                ),
                request=f"GET https://{target}/sdk/vimServiceVersions.xml",
                response=content[:1000],
                tags=["virtualization", "vmware", "api-exposure"],
            ))
        return results

    async def _check_container_escape(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # Check for Docker API exposure
        docker_endpoints = [
            (f"http://{target}:2375/version", "Docker API (unencrypted)"),
            (f"https://{target}:2376/version", "Docker API (TLS)"),
            (f"http://{target}:2375/containers/json", "Docker container list"),
        ]
        for url, desc in docker_endpoints:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "5", "-k", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            content = stdout.decode()
            if "ApiVersion" in content or "docker" in content.lower():
                results.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Docker API exposed: {desc}",
                    severity=Severity.CRITICAL,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"Docker daemon API accessible at {url}. This allows "
                        "creating privileged containers for host escape."
                    ),
                    request=f"GET {url}",
                    response=content[:1000],
                    cvss_score=9.8,
                    tags=["virtualization", "docker", "container-escape"],
                ))
                break

        # Check for Kubernetes API
        k8s_url = f"https://{target}:6443/version"
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--max-time", "5", "-k", k8s_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        content = stdout.decode()
        if "gitVersion" in content or "kubernetes" in content.lower():
            results.append(Evidence(
                agent_id=self.agent_id,
                title=f"Kubernetes API exposed on {target}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    "Kubernetes API server accessible. May allow pod creation "
                    "for node escape or cluster-wide compromise."
                ),
                request=f"GET {k8s_url}",
                response=content[:1000],
                tags=["virtualization", "kubernetes", "container-escape"],
            ))

        return results

    async def _check_snapshot_exposure(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("nmap"):
            return results

        # Check for NFS/SMB shares that might contain VM snapshots
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "-sV", "-p", "111,2049,445,139",
            "--open", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stdout.decode()

        if "nfs" in output.lower() or "2049/tcp" in output:
            results.append(Evidence(
                agent_id=self.agent_id,
                title=f"NFS service on {target} — potential VM datastore",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    "NFS service detected. If this is a VM datastore, snapshots "
                    "and VMDK files may be accessible, allowing offline credential "
                    "extraction and VM cloning."
                ),
                response=output[:1000],
                tags=["virtualization", "snapshot", "nfs", "datastore"],
            ))
        return results

    def _assess_hypervisor_cves(
        self, target: str, platform: str,
    ) -> Evidence | None:
        # Map platform to CVE database key
        platform_map = {
            "vmware": "vmware_esxi",
            "virtualbox": "virtualbox",
            "hyper-v": "hyper-v",
            "kvm": "qemu_kvm",
        }
        key = platform_map.get(platform)
        if not key or key not in _HYPERVISOR_CVES:
            return None

        cves = _HYPERVISOR_CVES[key]
        cve_list = "\n".join(
            f"- {c['cve']}: {c['desc']} (CVSS {c['cvss']})" for c in cves
        )
        max_cvss = max(c["cvss"] for c in cves)
        severity = Severity.CRITICAL if max_cvss >= 9.0 else Severity.HIGH

        return Evidence(
            agent_id=self.agent_id,
            title=f"Known {platform} hypervisor CVEs applicable to {target}",
            severity=severity,
            evidence_type=EvidenceType.OTHER,
            description=(
                f"Relevant CVEs for {platform} hypervisor (verify patching):\n"
                f"{cve_list}\n\n"
                "Run authenticated vulnerability scan to confirm patch status."
            ),
            response=json.dumps(cves, indent=2),
            tags=["virtualization", "cve", platform],
        )
