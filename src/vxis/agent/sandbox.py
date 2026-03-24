"""VXIS Agent Sandbox — Docker 컨테이너 격리 실행.

보안 도구를 Docker 컨테이너 안에서 실행하여:
1. 호스트 시스템 보호 (도구가 시스템을 손상시키지 않음)
2. 네트워크 격리 가능 (필요 시)
3. 일관된 실행 환경 (도구 버전 통일)

Architecture:
    AgentExecutor
        └── SandboxManager (컨테이너 풀 관리, target별 1개)
                └── DockerSandbox (단일 컨테이너 래퍼)
                        └── docker CLI subprocess (docker-py SDK 불필요)

Usage:
    mgr = SandboxManager()
    sandbox = await mgr.get_or_create("example.com")
    result = await sandbox.run_tool("nmap -sV example.com")
    await mgr.cleanup_all()
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import time
import uuid
import atexit
from dataclasses import dataclass

from vxis.core.scanner import ToolResult

logger = logging.getLogger(__name__)

# 컨테이너 내 워크스페이스 경로 (호스트 마운트 대응)
_WORKSPACE_HOST = "/tmp/vxis_workspace"
_WORKSPACE_CONTAINER = "/workspace"

# Docker 이미지 — Kali Linux Rolling (nmap, nuclei, sqlmap 등 사전 설치됨)
_DEFAULT_IMAGE = "kalilinux/kali-rolling"

# docker CLI 타임아웃 (컨테이너 생성/삭제 등 관리 작업용)
_DOCKER_ADMIN_TIMEOUT = 30


# ── DockerSandbox ────────────────────────────────────────────────


class DockerSandbox:
    """단일 Docker 컨테이너 래퍼.

    컨테이너 생명주기를 관리하고 그 안에서 보안 도구 명령을 실행한다.
    docker SDK 없이 subprocess로 docker CLI를 직접 호출한다.
    """

    def __init__(
        self,
        image: str = _DEFAULT_IMAGE,
        timeout: int = 600,
    ) -> None:
        self.image = image
        self.default_timeout = timeout
        self._container_id: str | None = None

    # ── Availability check ───────────────────────────────────────

    @staticmethod
    def is_available() -> bool:
        """Docker 데몬이 실행 중인지 확인.

        Returns:
            True if `docker info` succeeds (daemon is running and accessible).
        """
        if not shutil.which("docker"):
            logger.debug("Docker CLI가 PATH에 없음 — sandbox 비활성화")
            return False
        try:
            proc = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=_DOCKER_ADMIN_TIMEOUT,
            )
            available = proc.returncode == 0
            if not available:
                logger.debug(
                    "docker info 실패 (code=%d) — daemon이 실행 중이지 않을 수 있음",
                    proc.returncode,
                )
            return available
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.debug("Docker 가용성 확인 실패: %s", exc)
            return False

    # ── Container lifecycle ──────────────────────────────────────

    async def create_container(self) -> str:
        """컨테이너를 생성하고 시작한 뒤 container_id를 반환.

        컨테이너는 `sleep infinity`로 대기 상태를 유지한다.
        이후 `docker exec`로 명령을 주입해 실행한다.

        Mount:
            {_WORKSPACE_HOST} → {_WORKSPACE_CONTAINER}  (read-write)

        Network:
            bridge — 타겟 도달 가능, 호스트 인터페이스로부터 격리

        Returns:
            Full Docker container ID string.

        Raises:
            RuntimeError: If `docker run` fails.
        """
        # 호스트 워크스페이스 디렉토리 보장
        os.makedirs(_WORKSPACE_HOST, exist_ok=True)

        container_name = f"vxis-sandbox-{uuid.uuid4().hex[:12]}"

        cmd = [
            "docker", "run",
            "--detach",
            "--name", container_name,
            "--network", "bridge",
            # 워크스페이스 볼륨 마운트
            "--volume", f"{_WORKSPACE_HOST}:{_WORKSPACE_CONTAINER}:rw",
            # 리소스 제한 — 단일 컨테이너가 호스트 CPU/메모리를 독점하지 않도록
            "--memory", "2g",
            "--cpus", "2.0",
            # 보안: 불필요한 privilege 제거, read-only rootfs 불가(도구 설치 필요)
            "--cap-drop", "ALL",
            "--cap-add", "NET_RAW",    # nmap SYN scan 필요
            "--cap-add", "NET_ADMIN",  # nmap/hping 등 raw socket
            "--security-opt", "no-new-privileges:true",
            # 레이블: VXIS가 생성한 컨테이너 식별용
            "--label", "vxis.managed=true",
            self.image,
            "sleep", "infinity",
        ]

        logger.info("Docker 컨테이너 생성 중: image=%s name=%s", self.image, container_name)

        result = await asyncio.to_thread(
            subprocess.run,
            cmd,
            capture_output=True,
            text=True,
            timeout=_DOCKER_ADMIN_TIMEOUT * 2,  # 이미지 pull 포함 가능
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"컨테이너 생성 실패 (code={result.returncode}): {result.stderr.strip()}"
            )

        container_id = result.stdout.strip()
        self._container_id = container_id
        logger.info("컨테이너 시작됨: %s", container_id[:12])
        return container_id

    async def destroy_container(self, container_id: str) -> None:
        """컨테이너를 강제 중지하고 삭제.

        Args:
            container_id: docker run이 반환한 full container ID.
        """
        logger.info("컨테이너 제거 중: %s", container_id[:12])

        # --force: 실행 중인 컨테이너도 즉시 삭제
        result = await asyncio.to_thread(
            subprocess.run,
            ["docker", "rm", "--force", container_id],
            capture_output=True,
            text=True,
            timeout=_DOCKER_ADMIN_TIMEOUT,
        )

        if result.returncode != 0:
            # 이미 삭제된 경우(race condition) 무시
            stderr = result.stderr.strip()
            if "No such container" not in stderr:
                logger.warning(
                    "컨테이너 삭제 중 오류 (code=%d): %s",
                    result.returncode,
                    stderr,
                )

        if self._container_id == container_id:
            self._container_id = None

    # ── Tool execution ───────────────────────────────────────────

    async def run_tool(
        self,
        command: str,
        timeout: int | None = None,
    ) -> ToolResult:
        """컨테이너 안에서 명령을 실행하고 ToolResult를 반환.

        `docker exec`를 사용해 이미 실행 중인 컨테이너에 명령을 주입한다.
        기존 `vxis.core.scanner.run_tool`과 동일한 ToolResult 형식을 반환하므로
        호출 코드를 변경하지 않아도 된다.

        Args:
            command: 컨테이너 안에서 실행할 셸 명령 문자열.
                     예: "nmap -sV -p 80,443 example.com"
            timeout: 최대 실행 시간(초). None이면 self.default_timeout 사용.

        Returns:
            ToolResult with stdout, stderr, return_code, command, elapsed_seconds.

        Raises:
            RuntimeError: 컨테이너가 아직 생성되지 않은 경우.
            TimeoutError: 명령이 timeout 내에 완료되지 않은 경우.
        """
        if self._container_id is None:
            raise RuntimeError(
                "컨테이너가 초기화되지 않았습니다. "
                "먼저 create_container()를 호출하세요."
            )

        effective_timeout = timeout if timeout is not None else self.default_timeout
        container_id = self._container_id

        # `docker exec`로 /bin/bash -c "command" 실행
        # 셸 래핑을 통해 파이프라인, 리다이렉션 등 복합 명령 지원
        exec_cmd = [
            "docker", "exec",
            container_id,
            "/bin/bash", "-c", command,
        ]

        command_label = f"[sandbox:{container_id[:12]}] {command}"
        logger.debug("sandbox 실행: %s", command_label)

        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *exec_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=float(effective_timeout),
                )
            except asyncio.TimeoutError:
                # 타임아웃 시 컨테이너 내 프로세스 강제 종료
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()
                raise TimeoutError(
                    f"sandbox 명령이 {effective_timeout}초 내에 완료되지 않았습니다: "
                    f"{command[:120]}"
                )

        except TimeoutError:
            raise
        except Exception as exc:
            elapsed = time.monotonic() - start
            logger.error("sandbox docker exec 실패: %s", exc)
            return ToolResult(
                stdout="",
                stderr=str(exc),
                return_code=-1,
                command=command_label,
                elapsed_seconds=elapsed,
            )

        elapsed = time.monotonic() - start

        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")
        return_code = proc.returncode if proc.returncode is not None else -1

        logger.debug(
            "sandbox 완료: rc=%d elapsed=%.1fs stdout_len=%d",
            return_code,
            elapsed,
            len(stdout),
        )

        return ToolResult(
            stdout=stdout,
            stderr=stderr,
            return_code=return_code,
            command=command_label,
            elapsed_seconds=elapsed,
        )


# ── SandboxManager ───────────────────────────────────────────────


class SandboxManager:
    """컨테이너 풀을 관리하는 매니저.

    타겟별로 컨테이너를 1개씩 생성하고 재사용한다.
    동일 타겟에 대한 여러 도구 실행이 같은 컨테이너 안에서
    세션을 공유하므로, 도구 간 상태(파일, 환경) 공유가 가능하다.

    프로세스 종료 시 atexit 핸들러로 모든 컨테이너를 자동 정리한다.
    """

    def __init__(
        self,
        image: str = _DEFAULT_IMAGE,
        default_timeout: int = 600,
    ) -> None:
        self._image = image
        self._default_timeout = default_timeout
        # target str → DockerSandbox
        self._sandboxes: dict[str, DockerSandbox] = {}
        # 컨테이너 생성 중 동시 접근 방지용 락 (target별)
        self._locks: dict[str, asyncio.Lock] = {}
        # atexit: 비정상 종료 시에도 컨테이너 정리
        atexit.register(self._sync_cleanup_all)

    # ── Public API ───────────────────────────────────────────────

    async def get_or_create(self, target: str) -> DockerSandbox:
        """타겟에 대한 sandbox를 반환. 없으면 새로 생성.

        동일 target으로 동시에 여러 코루틴이 진입해도
        컨테이너가 중복 생성되지 않도록 asyncio.Lock으로 보호한다.

        Args:
            target: 타겟 식별자 (e.g., "example.com", "192.168.1.1")
                    컨테이너를 구분하는 키로만 사용되며, 컨테이너 내부로
                    전달되지 않는다.

        Returns:
            생성되어 실행 중인 DockerSandbox 인스턴스.
        """
        # 락이 없으면 생성 (이벤트 루프 내에서만 호출됨을 전제)
        if target not in self._locks:
            self._locks[target] = asyncio.Lock()

        async with self._locks[target]:
            if target in self._sandboxes:
                return self._sandboxes[target]

            sandbox = DockerSandbox(
                image=self._image,
                timeout=self._default_timeout,
            )
            await sandbox.create_container()
            self._sandboxes[target] = sandbox
            logger.info(
                "SandboxManager: 새 컨테이너 할당 — target=%s cid=%s",
                target,
                sandbox._container_id[:12] if sandbox._container_id else "?",
            )
            return sandbox

    async def cleanup_all(self) -> None:
        """모든 컨테이너를 병렬로 정지 및 삭제."""
        if not self._sandboxes:
            return

        logger.info(
            "SandboxManager: %d개 컨테이너 정리 중...", len(self._sandboxes)
        )

        tasks = []
        for target, sandbox in list(self._sandboxes.items()):
            cid = sandbox._container_id
            if cid:
                tasks.append(sandbox.destroy_container(cid))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for exc in results:
                if isinstance(exc, Exception):
                    logger.warning("컨테이너 정리 중 오류: %s", exc)

        self._sandboxes.clear()
        self._locks.clear()
        logger.info("SandboxManager: 정리 완료")

    # ── Internal / atexit ────────────────────────────────────────

    def _sync_cleanup_all(self) -> None:
        """atexit 핸들러용 동기 정리.

        이벤트 루프가 이미 닫혀 있을 수 있으므로
        asyncio 대신 subprocess.run으로 직접 정리한다.
        """
        for target, sandbox in list(self._sandboxes.items()):
            cid = sandbox._container_id
            if cid:
                try:
                    subprocess.run(
                        ["docker", "rm", "--force", cid],
                        capture_output=True,
                        timeout=10,
                    )
                    logger.debug("atexit: 컨테이너 제거됨 — %s", cid[:12])
                except Exception as exc:
                    logger.debug("atexit cleanup 오류: %s", exc)

        self._sandboxes.clear()


# ── 모듈 레벨 싱글톤 (AgentExecutor에서 공유) ─────────────────────

# AgentExecutor가 import 시 바로 사용할 수 있는 전역 매니저 인스턴스.
# 별도 설정이 없으면 기본 Kali 이미지와 타임아웃 사용.
_global_manager: SandboxManager | None = None


def get_sandbox_manager(
    image: str = _DEFAULT_IMAGE,
    default_timeout: int = 600,
) -> SandboxManager:
    """전역 SandboxManager 싱글톤을 반환 (없으면 생성).

    Args:
        image: Docker 이미지. 첫 호출 시에만 적용된다.
        default_timeout: 기본 툴 실행 타임아웃(초).

    Returns:
        SandboxManager 싱글톤 인스턴스.
    """
    global _global_manager
    if _global_manager is None:
        _global_manager = SandboxManager(
            image=image,
            default_timeout=default_timeout,
        )
    return _global_manager
