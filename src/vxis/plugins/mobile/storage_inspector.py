"""StorageInspectorPlugin — 모바일 앱 로컬 데이터 스토리지 분석 플러그인."""

from __future__ import annotations

import asyncio
import re
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# 민감 데이터 패턴
_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("password",    re.compile(r'(?i)password|passwd|pwd|secret')),
    ("token",       re.compile(r'(?i)token|jwt|bearer|api[_-]?key|auth')),
    ("pii",         re.compile(r'(?i)email|phone|ssn|credit_card|dob|national_id')),
    ("location",    re.compile(r'(?i)latitude|longitude|gps|location|coordinate')),
    ("health",      re.compile(r'(?i)health|medical|diagnosis|prescription|blood')),
    ("financial",   re.compile(r'(?i)account.number|iban|routing|balance|transaction')),
]


class StorageInspectorPlugin(BasePlugin):
    """로컬 데이터 스토리지 분석.

    Android: SharedPreferences, SQLite, 내부/외부 스토리지
    iOS: NSUserDefaults, SQLite, Keychain (Frida 필요), Plist 파일
    """

    _meta = PluginMeta(
        name="storage_inspector",
        version="1.0.0",
        tool_binary="adb",
        category="mobile",
        tier=2,
        depends_on=(),
        optional_depends=("frida",),
        timeout_seconds=300,
        produces=("storage_findings",),
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
        """ADB로 앱 데이터 디렉터리 목록 조회."""
        package = tool_config.get("package") or ctx.get_data("mobile", "package", target)
        return f"adb shell run-as {package} ls /data/data/{package}/"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """ADB ls 출력 파싱."""
        dirs = [d.strip() for d in raw_stdout.splitlines() if d.strip()]
        interesting = []
        for d in dirs:
            if any(k in d.lower() for k in ["shared_prefs", "databases", "files", "cache"]):
                interesting.append(d)

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={
                "directories": dirs,
                "interesting_dirs": interesting,
            },
        )

    async def inspect_sqlite_databases(
        self,
        db_files: list[str],
    ) -> list[dict[str, Any]]:
        """SQLite 데이터베이스에서 민감 데이터 탐색."""
        findings: list[dict[str, Any]] = []

        for db_path in db_files:
            if not Path(db_path).exists():
                continue

            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                # 테이블 목록
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]

                for table in tables:
                    try:
                        cursor.execute(f"SELECT * FROM [{table}] LIMIT 20")  # noqa: S608
                        rows = cursor.fetchall()
                        col_names = [d[0] for d in cursor.description]

                        # 컬럼명 + 데이터에서 민감 패턴 검색
                        for col_name in col_names:
                            for data_type, pattern in _SENSITIVE_PATTERNS:
                                if pattern.search(col_name):
                                    # 실제 데이터 미리보기
                                    col_idx = col_names.index(col_name)
                                    sample_values = [
                                        str(row[col_idx])[:50]
                                        for row in rows
                                        if row[col_idx] is not None
                                    ][:3]
                                    findings.append({
                                        "db": Path(db_path).name,
                                        "table": table,
                                        "column": col_name,
                                        "data_type": data_type,
                                        "sample": sample_values,
                                        "row_count": len(rows),
                                        "severity": "high" if data_type in ("password", "token") else "medium",
                                    })
                                    break
                    except sqlite3.Error:
                        continue

                conn.close()
            except sqlite3.Error as exc:
                findings.append({
                    "db": Path(db_path).name,
                    "error": str(exc),
                })

        return findings

    def inspect_shared_preferences(
        self,
        prefs_dir: str,
    ) -> list[dict[str, Any]]:
        """SharedPreferences XML 파일에서 민감 데이터 검색."""
        findings: list[dict[str, Any]] = []
        prefs_path = Path(prefs_dir)

        if not prefs_path.exists():
            return findings

        for xml_file in prefs_path.glob("*.xml"):
            try:
                content = xml_file.read_text(errors="replace")
                for data_type, pattern in _SENSITIVE_PATTERNS:
                    if pattern.search(content):
                        findings.append({
                            "file": xml_file.name,
                            "data_type": data_type,
                            "preview": content[:300],
                            "severity": "high" if data_type in ("password", "token") else "medium",
                        })
                        break
            except OSError:
                continue

        return findings

    async def pull_and_inspect(
        self,
        package: str,
        output_dir: str | None = None,
    ) -> list[dict[str, Any]]:
        """ADB를 사용해 앱 데이터 디렉터리 전체 추출 후 분석."""
        if not shutil.which("adb"):
            return []

        tmp = output_dir or tempfile.mkdtemp(prefix="vxis_storage_")
        findings: list[dict[str, Any]] = []

        try:
            # adb backup으로 앱 데이터 추출
            backup_path = Path(tmp) / "app_backup.ab"
            proc = await asyncio.create_subprocess_exec(
                "adb", "backup", "-f", str(backup_path), "-noapk", package,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=30)

            if backup_path.exists() and backup_path.stat().st_size > 24:
                findings.append({
                    "type": "backup_extractable",
                    "size_bytes": backup_path.stat().st_size,
                    "path": str(backup_path),
                    "severity": "high",
                })
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

        return findings

    def validate_environment(self) -> bool:
        """Python sqlite3은 항상 사용 가능."""
        return True
