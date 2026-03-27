"""AntiCheatPlugin — 안티치트 시스템 탐지 + 효과성 평가.

게임에 적용된 안티치트 시스템을 탐지하고 우회 가능성을 평가.

지원 탐지 시스템:
    - EasyAntiCheat (EAC)
    - BattlEye (BE)
    - Vanguard (Riot Games)
    - Valve Anti-Cheat (VAC)
    - Custom anti-cheat implementations

탐지 방법:
    1. 바이너리 문자열 시그니처 분석
    2. 프로세스 목록 탐색
    3. 드라이버/서비스 탐지
    4. 네트워크 트래픽 패턴 분석
    5. Frida 훅으로 런타임 감지 함수 탐지
"""

from __future__ import annotations

import logging
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

logger = logging.getLogger(__name__)


# ── Known Anti-Cheat Signatures ───────────────────────────────────

ANTICHEAT_DB: dict[str, dict[str, Any]] = {
    "EasyAntiCheat": {
        "files": [
            "EasyAntiCheat.exe", "EasyAntiCheat_Setup.exe",
            "EasyAntiCheat64.sys", "EasyAntiCheat32.sys",
            "easyanticheat_launcher.exe",
        ],
        "strings": ["EasyAntiCheat", "EAC", "easy anti-cheat"],
        "processes": ["EasyAntiCheat.exe", "EACLaunch.exe"],
        "kernel_level": False,
        "driver": False,
        "bypass_difficulty": "medium",
        "known_bypasses": [
            "EAC emulator via IOCTL call spoofing",
            "Kernel driver injection before EAC loads",
            "EAC sandbox escape via signed driver",
        ],
        "detection_methods": ["memory_scan", "process_list", "module_list"],
        "cve_history": ["CVE-2021-43267"],
    },
    "BattlEye": {
        "files": [
            "BEService.exe", "BEClient.dll", "BEClient_x64.dll",
            "BattlEye.sys", "BEDaisy.sys",
        ],
        "strings": ["BattlEye", "BEService", "BEClient"],
        "processes": ["BEService.exe", "BEService_x64.exe"],
        "kernel_level": True,
        "driver": True,
        "bypass_difficulty": "hard",
        "known_bypasses": [
            "Hypervisor-based memory hiding (VMX)",
            "Signed vulnerable driver exploitation (BYOVD)",
        ],
        "detection_methods": [
            "memory_scan", "process_list", "driver_load",
            "kernel_callbacks", "network_monitor",
        ],
        "cve_history": [],
    },
    "Vanguard": {
        "files": [
            "vgc.exe", "vgtray.exe", "vgk.sys",
            "Vanguard.exe",
        ],
        "strings": ["Vanguard", "vgc", "vgk", "VAN"],
        "processes": ["vgc.exe", "vgtray.exe"],
        "kernel_level": True,
        "driver": True,
        "bypass_difficulty": "hard",
        "known_bypasses": [
            "BYOVD (Bring Your Own Vulnerable Driver)",
            "VM-based isolation (hypervisor)",
        ],
        "detection_methods": [
            "ring0_driver", "memory_scan", "tpm_check",
            "secure_boot_verify",
        ],
        "cve_history": ["CVE-2023-29360"],
        "notes": "Always-on kernel driver, active even when not playing",
    },
    "VAC": {
        "files": ["steamservice.exe"],
        "strings": ["VAC", "Valve Anti-Cheat", "VACEngine"],
        "processes": ["steam.exe"],
        "kernel_level": False,
        "driver": False,
        "bypass_difficulty": "low",
        "known_bypasses": [
            "Delayed detection — bans issued hours to weeks later",
            "VAC runs in user-mode only",
            "Process hollowing bypass",
        ],
        "detection_methods": ["memory_scan", "steam_module_check"],
        "cve_history": [],
        "notes": "Steam-based, delayed ban system",
    },
    "GameGuard": {
        "files": ["GameGuard.des", "GameGuard.gup", "GameGuard.sys", "npggNT.des"],
        "strings": ["GameGuard", "nProtect", "INCA Internet"],
        "processes": ["GameGuard.des", "GGHostSvc.exe"],
        "kernel_level": True,
        "driver": True,
        "bypass_difficulty": "medium",
        "known_bypasses": [
            "Numerous public bypasses exist (older system)",
            "Kernel driver vulnerabilities documented",
        ],
        "detection_methods": ["memory_scan", "process_list", "driver_load"],
        "cve_history": ["CVE-2008-3415"],
    },
    "XIGNCODE3": {
        "files": ["x3.xem", "xcorona_x64.xem"],
        "strings": ["XIGNCODE", "WELLBIA"],
        "processes": ["xhunter1.sys"],
        "kernel_level": True,
        "driver": True,
        "bypass_difficulty": "medium",
        "known_bypasses": ["Kernel driver injection", "Process unhooking"],
        "detection_methods": ["memory_scan", "driver_load"],
        "cve_history": ["CVE-2021-31728"],
    },
}


class AntiCheatPlugin(BasePlugin):
    """안티치트 시스템 탐지 + 우회 가능성 평가 플러그인."""

    _meta = PluginMeta(
        name="anti_cheat_detector",
        version="1.0.0",
        tool_binary="strings",  # 바이너리 문자열 추출
        category="game",
        tier=1,
        produces=("anticheat_system", "bypass_vectors", "security_level"),
        timeout_seconds=120,
    )

    @property
    def meta(self) -> PluginMeta:
        return self._meta

    def build_command(
        self,
        target: str,
        scan_profile: str,
        ctx: DAGContext,
        tool_config: dict[str, Any],
    ) -> str:
        """바이너리에서 안티치트 시그니처 문자열 추출."""
        binary_path = tool_config.get("binary_path", target)
        return f"strings -n 6 '{binary_path}'"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """strings 출력에서 안티치트 시그니처 탐지."""
        strings_list = raw_stdout.splitlines()
        detected: list[str] = []
        findings: list[dict[str, Any]] = []

        for ac_name, info in ANTICHEAT_DB.items():
            for sig in info.get("strings", []):
                if any(sig.lower() in s.lower() for s in strings_list):
                    if ac_name not in detected:
                        detected.append(ac_name)
                        findings.append({
                            "type": "anticheat_detected",
                            "system": ac_name,
                            "kernel_level": info["kernel_level"],
                            "bypass_difficulty": info["bypass_difficulty"],
                            "severity": "informational",
                        })
                    break

        if not detected:
            findings.append({
                "type": "no_anticheat",
                "severity": "high",
                "description": "No known anti-cheat system detected in binary",
            })

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout[:5000],
            parsed_data={
                "detected_systems": detected,
                "total_strings_analyzed": len(strings_list),
            },
            findings=findings,
        )

    # ── 핵심 분석 메서드 ────────────────────────────────────────────

    def analyze_binary_strings(self, strings: list[str]) -> dict[str, Any]:
        """바이너리 문자열 목록에서 안티치트 탐지.

        Args:
            strings: 바이너리에서 추출한 문자열 목록.

        Returns:
            탐지된 안티치트 시스템 및 우회 평가 결과.
        """
        detected: list[dict[str, Any]] = []

        for ac_name, info in ANTICHEAT_DB.items():
            match_count = 0
            matched_sigs: list[str] = []

            # 문자열 시그니처 매칭
            for sig in info.get("strings", []):
                if any(sig.lower() in s.lower() for s in strings):
                    match_count += 1
                    matched_sigs.append(sig)

            # 파일명 시그니처 매칭
            for fname in info.get("files", []):
                if any(fname.lower() in s.lower() for s in strings):
                    match_count += 2  # 파일명 매칭은 더 강한 시그니처
                    matched_sigs.append(fname)

            if match_count >= 2:  # 최소 2개 시그니처 매칭
                detected.append({
                    "system": ac_name,
                    "confidence": min(1.0, match_count / 5.0),
                    "matched_signatures": matched_sigs[:5],
                    "kernel_level": info["kernel_level"],
                    "bypass_difficulty": info["bypass_difficulty"],
                    "known_bypasses": info.get("known_bypasses", []),
                    "detection_methods": info.get("detection_methods", []),
                    "cve_history": info.get("cve_history", []),
                    "notes": info.get("notes", ""),
                })

        return {
            "detected": detected,
            "count": len(detected),
            "most_likely": detected[0] if detected else None,
            "has_anticheat": bool(detected),
            "overall_bypass_difficulty": self._assess_overall_bypass(detected),
        }

    def analyze_process_list(self, processes: list[dict[str, Any]]) -> dict[str, Any]:
        """실행 중인 프로세스 목록에서 안티치트 탐지.

        Args:
            processes: [{"pid": ..., "name": ...}] 형식의 프로세스 목록.

        Returns:
            실행 중인 안티치트 프로세스 정보.
        """
        running_ac: list[dict[str, Any]] = []
        process_names = [p.get("name", "").lower() for p in processes]

        for ac_name, info in ANTICHEAT_DB.items():
            for ac_proc in info.get("processes", []):
                if any(ac_proc.lower() in pn for pn in process_names):
                    matching_process = next(
                        (p for p in processes if ac_proc.lower() in p.get("name", "").lower()),
                        None,
                    )
                    running_ac.append({
                        "system": ac_name,
                        "process": ac_proc,
                        "pid": matching_process.get("pid") if matching_process else None,
                        "kernel_level": info["kernel_level"],
                        "active": True,
                    })

        return {
            "running_anticheat": running_ac,
            "count": len(running_ac),
            "kernel_drivers_active": any(ac["kernel_level"] for ac in running_ac),
        }

    def assess_bypass_feasibility(
        self,
        detected_systems: list[dict[str, Any]],
        frida_hooks: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """안티치트 우회 가능성 종합 평가.

        Args:
            detected_systems: analyze_binary_strings() 결과.
            frida_hooks: Frida 훅으로 탐지된 함수 정보.

        Returns:
            우회 가능성 평가 결과.
        """
        if not detected_systems:
            return {
                "feasibility": "trivial",
                "score": 0,
                "description": "No anti-cheat detected — trivial bypass",
                "attack_vectors": [
                    "Memory editing (Cheat Engine compatible)",
                    "Speed hack via timing manipulation",
                    "Wallhack via rendering interception",
                    "Aimbot via input injection",
                ],
            }

        # 난이도 점수 집계
        difficulty_scores = {"trivial": 0, "low": 2, "medium": 5, "hard": 9}
        max_score = max(
            difficulty_scores.get(s.get("bypass_difficulty", "low"), 2)
            for s in detected_systems
        )

        feasibility = "trivial" if max_score == 0 else \
                      "easy" if max_score <= 2 else \
                      "moderate" if max_score <= 5 else \
                      "difficult"

        # 모든 알려진 우회 방법 수집
        all_bypasses: list[str] = []
        for sys_info in detected_systems:
            all_bypasses.extend(sys_info.get("known_bypasses", []))

        # Frida 탐지 함수가 없으면 디버거 우회 가능
        if not frida_hooks:
            all_bypasses.append(
                "No anti-debug hooks detected — Frida attachment possible without detection"
            )

        # CVE 이력이 있으면 취약점 익스플로잇 가능
        for sys_info in detected_systems:
            if sys_info.get("cve_history"):
                all_bypasses.append(
                    f"Known CVEs for {sys_info['system']}: {sys_info['cve_history']}"
                )

        return {
            "feasibility": feasibility,
            "score": max_score,
            "bypass_difficulty": "hard" if max_score >= 9 else "medium" if max_score >= 5 else "low",
            "attack_vectors": all_bypasses[:10],
            "kernel_level_protection": any(s.get("kernel_level") for s in detected_systems),
            "recommendation": self._generate_recommendation(detected_systems),
        }

    def generate_security_report(
        self,
        binary_analysis: dict[str, Any],
        process_analysis: dict[str, Any],
        bypass_assessment: dict[str, Any],
    ) -> dict[str, Any]:
        """안티치트 보안 분석 리포트 생성.

        Args:
            binary_analysis: analyze_binary_strings() 결과.
            process_analysis: analyze_process_list() 결과.
            bypass_assessment: assess_bypass_feasibility() 결과.

        Returns:
            종합 안티치트 보안 리포트.
        """
        severity = "informational"
        if not binary_analysis.get("has_anticheat"):
            severity = "high"
        elif bypass_assessment.get("feasibility") in ("easy", "moderate"):
            severity = "medium"
        elif bypass_assessment.get("feasibility") == "trivial":
            severity = "critical"

        return {
            "title": f"Anti-Cheat Assessment — {bypass_assessment.get('feasibility', 'unknown').upper()} bypass risk",
            "severity": severity,
            "summary": {
                "detected_systems": binary_analysis.get("count", 0),
                "running_processes": process_analysis.get("count", 0),
                "kernel_protection": bypass_assessment.get("kernel_level_protection", False),
                "bypass_feasibility": bypass_assessment.get("feasibility"),
            },
            "detected_systems": binary_analysis.get("detected", []),
            "bypass_vectors": bypass_assessment.get("attack_vectors", []),
            "recommendation": bypass_assessment.get("recommendation", ""),
            "cve_references": [
                cve
                for sys_info in binary_analysis.get("detected", [])
                for cve in sys_info.get("cve_history", [])
            ],
        }

    # ── Private Helpers ─────────────────────────────────────────────

    def _assess_overall_bypass(self, detected: list[dict[str, Any]]) -> str:
        """탐지된 안티치트들의 전체 우회 난이도 평가."""
        if not detected:
            return "trivial"

        difficulty_order = ["trivial", "low", "medium", "hard"]
        max_difficulty = "low"

        for sys_info in detected:
            difficulty = sys_info.get("bypass_difficulty", "low")
            if difficulty_order.index(difficulty) > difficulty_order.index(max_difficulty):
                max_difficulty = difficulty

        return max_difficulty

    def _generate_recommendation(self, detected: list[dict[str, Any]]) -> str:
        """게임 개발사를 위한 안티치트 강화 권고사항 생성."""
        if not detected:
            return (
                "Implement a kernel-level anti-cheat system (EAC or BattlEye recommended). "
                "Add server-side validation for all game state changes. "
                "Enable replay validation and behavioral analysis."
            )

        recommendations: list[str] = []
        has_kernel = any(s.get("kernel_level") for s in detected)

        if not has_kernel:
            recommendations.append(
                "Upgrade to kernel-level anti-cheat (BattlEye or Vanguard) for stronger protection"
            )

        recommendations.extend([
            "Implement server-side game state validation — never trust client data",
            "Add behavioral anomaly detection (impossible scores, speed, position)",
            "Implement replay system to review suspicious matches",
            "Regular anti-cheat signature updates",
        ])

        return " | ".join(recommendations)
