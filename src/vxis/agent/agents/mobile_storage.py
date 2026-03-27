"""MobileStorageAgent — 모바일 앱 데이터 스토리지 보안 에이전트."""

from __future__ import annotations

import json
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class MobileStorageAgent(BaseAgent):
    """모바일 로컬 스토리지 보안 분석.

    Android: SharedPreferences, SQLite, 내부 스토리지, 외부 스토리지, ADB 백업
    iOS: NSUserDefaults, SQLite, Keychain, 앱 샌드박스, iTunes 백업
    """

    agent_id = "mobile_storage"
    description = "Mobile data storage security: SharedPrefs, SQLite, Keychain, ADB backup"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []
        metadata: dict[str, Any] = {}

        package = getattr(context, "app_package", "") or ""
        platform = getattr(context, "platform", "android")

        if not package:
            return AgentResult(
                agent_id=self.agent_id,
                findings=findings,
                hypotheses=hypotheses,
                status="skipped",
                metadata={"reason": "No app package provided"},
            )

        if platform == "android":
            android_findings = await self._analyze_android_storage(package)
            findings.extend(android_findings)
            metadata["android_storage"] = len(android_findings)
        else:
            ios_findings = await self._analyze_ios_storage(package)
            findings.extend(ios_findings)
            metadata["ios_storage"] = len(ios_findings)

        # 백업 취약점
        backup_findings = await self._check_backup(package, platform)
        findings.extend(backup_findings)
        metadata["backup"] = len(backup_findings)

        # 외부 스토리지 사용
        ext_findings = await self._check_external_storage(package, platform)
        findings.extend(ext_findings)

        # 고위험 발견 시 가설 생성
        high_sev = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if high_sev:
            hypotheses.append(Hypothesis(
                title=f"Sensitive data exfiltration from {target} local storage",
                rationale=(
                    f"{len(high_sev)} high+ severity storage issues. "
                    "Attacker with physical/ADB access can extract credentials."
                ),
                probability=0.8,
                impact=0.9,
                suggested_agent="data_exfiltration",
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata=metadata,
        )

    async def _analyze_android_storage(self, package: str) -> list[Evidence]:
        """Android 앱 스토리지 분석."""
        findings: list[Evidence] = []
        import shutil

        if not shutil.which("adb"):
            return findings

        # SharedPreferences 분석
        sp_findings = await self._inspect_shared_prefs(package)
        findings.extend(sp_findings)

        # SQLite 데이터베이스 목록
        db_findings = await self._inspect_sqlite_dbs(package)
        findings.extend(db_findings)

        return findings

    async def _inspect_shared_prefs(self, package: str) -> list[Evidence]:
        """SharedPreferences XML 파일 민감 데이터 탐색."""
        import asyncio
        import re

        findings: list[Evidence] = []
        sensitive_pattern = re.compile(
            r'(?i)(password|token|secret|api[_-]?key|jwt|bearer|ssn|email|phone)',
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "shell", "run-as", package,
                "ls", f"/data/data/{package}/shared_prefs/",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            files = [f.strip() for f in stdout.decode().splitlines() if f.strip()]

            for pref_file in files:
                if not pref_file.endswith(".xml"):
                    continue
                proc2 = await asyncio.create_subprocess_exec(
                    "adb", "shell", "run-as", package,
                    "cat", f"/data/data/{package}/shared_prefs/{pref_file}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                content_out, _ = await asyncio.wait_for(proc2.communicate(), timeout=10)
                content = content_out.decode(errors="replace")

                if sensitive_pattern.search(content):
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"Sensitive Data in SharedPreferences: {pref_file}",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.CODE_FINDING,
                        description=(
                            f"SharedPreferences file '{pref_file}' contains sensitive keywords. "
                            "Credentials stored in SharedPreferences are accessible to "
                            "root users and via ADB backup."
                        ),
                        response=content[:500],
                        tags=["mobile", "android", "sharedprefs", "storage"],
                    ))
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

        return findings

    async def _inspect_sqlite_dbs(self, package: str) -> list[Evidence]:
        """SQLite 데이터베이스 파일 목록 및 민감 컬럼 탐색."""
        import asyncio

        findings: list[Evidence] = []

        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "shell", "run-as", package,
                "ls", f"/data/data/{package}/databases/",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            db_files = [f.strip() for f in stdout.decode().splitlines() if f.strip().endswith(".db")]

            for db_file in db_files:
                # DB 파일을 로컬로 pull
                import tempfile
                local_db = tempfile.mktemp(suffix=".db", prefix="vxis_")
                proc2 = await asyncio.create_subprocess_exec(
                    "adb", "shell", "run-as", package,
                    "cat", f"/data/data/{package}/databases/{db_file}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                db_bytes, _ = await asyncio.wait_for(proc2.communicate(), timeout=30)

                if len(db_bytes) > 100:
                    # 파일 저장 후 sqlite3로 분석
                    from pathlib import Path
                    Path(local_db).write_bytes(db_bytes)
                    storage_plugin = self._get_storage_plugin()
                    db_findings = await storage_plugin.inspect_sqlite_databases([local_db])
                    for df in db_findings:
                        if "error" not in df:
                            findings.append(Evidence(
                                agent_id=self.agent_id,
                                title=(
                                    f"Sensitive Column in SQLite: "
                                    f"{db_file}.{df['table']}.{df['column']}"
                                ),
                                severity=Severity.HIGH if df["severity"] == "high" else Severity.MEDIUM,
                                evidence_type=EvidenceType.CODE_FINDING,
                                description=(
                                    f"SQLite database '{db_file}', table '{df['table']}', "
                                    f"column '{df['column']}' contains {df['data_type']} data. "
                                    f"Sample values: {df['sample']}"
                                ),
                                response=json.dumps(df, ensure_ascii=False),
                                tags=["mobile", "android", "sqlite", "storage"],
                            ))
        except Exception:
            pass

        return findings

    async def _analyze_ios_storage(self, package: str) -> list[Evidence]:
        """iOS 앱 스토리지 분석 (Frida 키체인 덤프)."""
        findings: list[Evidence] = []

        try:
            from vxis.plugins.mobile.frida_scanner import FridaScannerPlugin
            plugin = FridaScannerPlugin()
            results = await plugin.run_script_suite(package, "ios", ["storage"])

            for script_name, result in results.items():
                if not isinstance(result, dict):
                    continue
                entries = result.get("entries", [])
                for entry in entries if isinstance(entries, list) else []:
                    svc = entry.get("service", "")
                    acct = entry.get("account", "")
                    data_preview = str(entry.get("data", ""))[:80]
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"iOS Keychain Entry: {svc}/{acct}",
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.CODE_FINDING,
                        description=(
                            f"Keychain entry extracted: service='{svc}', account='{acct}'. "
                            f"Data preview: {data_preview}"
                        ),
                        response=json.dumps(entry, ensure_ascii=False),
                        tags=["mobile", "ios", "keychain", "storage"],
                    ))
        except Exception:
            pass

        return findings

    async def _check_backup(self, package: str, platform: str) -> list[Evidence]:
        """백업을 통한 데이터 추출 가능 여부 확인."""
        import shutil
        import asyncio
        import tempfile
        from pathlib import Path

        findings: list[Evidence] = []

        if platform == "android" and shutil.which("adb"):
            backup_file = Path(tempfile.mkdtemp()) / "test_backup.ab"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "adb", "backup", "-f", str(backup_file), "-noapk", package,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=30)

                if backup_file.exists() and backup_file.stat().st_size > 24:
                    size_kb = backup_file.stat().st_size / 1024
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"ADB Backup Extractable: {size_kb:.1f} KB",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description=(
                            f"ADB backup extracted {size_kb:.1f} KB of app data without root. "
                            "Set android:allowBackup=false or use BackupAgent to restrict."
                        ),
                        tags=["mobile", "android", "backup", "adb"],
                    ))
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

        return findings

    async def _check_external_storage(
        self, package: str, platform: str,
    ) -> list[Evidence]:
        """외부 스토리지(SD카드)에 민감 데이터 저장 여부."""
        import asyncio
        import shutil

        findings: list[Evidence] = []
        if platform != "android" or not shutil.which("adb"):
            return findings

        try:
            proc = await asyncio.create_subprocess_exec(
                "adb", "shell",
                "find", "/sdcard/Android/data/", "-name", "*.log", "-o", "-name", "*.db",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            app_files = [
                f.strip() for f in stdout.decode().splitlines()
                if package in f
            ]

            if app_files:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"App Data Files on External Storage: {len(app_files)} files",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"Found {len(app_files)} app data files on external/shared storage. "
                        "External storage is world-readable — other apps can access these files. "
                        f"Files: {', '.join(app_files[:5])}"
                    ),
                    response="\n".join(app_files[:20]),
                    tags=["mobile", "android", "external_storage"],
                ))
        except Exception:
            pass

        return findings

    def _get_storage_plugin(self) -> Any:
        from vxis.plugins.mobile.storage_inspector import StorageInspectorPlugin
        return StorageInspectorPlugin()
