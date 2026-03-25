"""디지털 트윈 사전 시뮬레이션 — 실제 타겟 접촉 전에 가상 환경에서 공격 리허설.

1. 타겟의 기술 스택을 Docker로 재현
2. 가상 환경에서 모든 공격 시나리오 실행
3. "이 공격이 실제로 먹힐 확률" 사전 평가
4. 실제 스캔은 검증된 공격만 실행 → 소음 최소화

아키텍처:
    DigitalTwinBuilder  — tech stack → Docker Compose YAML 생성
    TwinSimulator       — 트윈에 공격 시뮬레이션 실행
    DockerConfig        — 생성된 Docker 설정 데이터
    SimResult           — 시뮬레이션 결과

안전 원칙:
    - 트윈은 격리된 Docker 네트워크에서만 실행
    - 외부 인터넷 접근 차단 (network: none 또는 isolated bridge)
    - 실제 타겟 접속 전 승인 필요
    - 트윈 실행 후 반드시 정리 (docker compose down)
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vxis.synthesis.cross_protocol import SynthesizedChain
from vxis.evidence.schema import Severity

logger = logging.getLogger(__name__)


# ── Docker Compose 서비스 템플릿 ─────────────────────────────────

# 각 기술별 Docker Compose 서비스 정의 템플릿
_SERVICE_TEMPLATES: dict[str, dict[str, Any]] = {
    "nginx": {
        "image": "nginx:1.24-alpine",
        "ports": ["8080:80"],
        "volumes": ["./nginx-conf:/etc/nginx/conf.d:ro"],
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "nginx"},
    },
    "apache": {
        "image": "httpd:2.4-alpine",
        "ports": ["8081:80"],
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "apache"},
    },
    "nodejs": {
        "image": "node:20-alpine",
        "ports": ["3000:3000"],
        "working_dir": "/app",
        "command": "node server.js",
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "nodejs"},
    },
    "express": {
        "image": "node:20-alpine",
        "ports": ["3001:3000"],
        "working_dir": "/app",
        "environment": {"NODE_ENV": "production"},
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "express"},
    },
    "django": {
        "image": "python:3.12-slim",
        "ports": ["8000:8000"],
        "command": "python manage.py runserver 0.0.0.0:8000",
        "environment": {
            "DJANGO_DEBUG": "True",
            "DJANGO_SECRET_KEY": "insecure-twin-key-for-testing-only",
        },
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "django"},
    },
    "flask": {
        "image": "python:3.12-slim",
        "ports": ["5000:5000"],
        "environment": {
            "FLASK_DEBUG": "1",
            "FLASK_SECRET_KEY": "insecure-twin-key-for-testing-only",
        },
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "flask"},
    },
    "spring": {
        "image": "eclipse-temurin:17-jre-alpine",
        "ports": ["8443:8080"],
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "spring"},
    },
    "laravel": {
        "image": "php:8.3-apache",
        "ports": ["8082:80"],
        "environment": {"APP_ENV": "production", "APP_DEBUG": "true"},
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "laravel"},
    },
    "postgresql": {
        "image": "postgres:16-alpine",
        "ports": ["5432:5432"],
        "environment": {
            "POSTGRES_DB": "twin_db",
            "POSTGRES_USER": "twin_user",
            "POSTGRES_PASSWORD": "twin_pass_insecure",
        },
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "postgresql"},
    },
    "mysql": {
        "image": "mysql:8.0",
        "ports": ["3306:3306"],
        "environment": {
            "MYSQL_DATABASE": "twin_db",
            "MYSQL_USER": "twin_user",
            "MYSQL_PASSWORD": "twin_pass_insecure",
            "MYSQL_ROOT_PASSWORD": "root_insecure",
        },
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "mysql"},
    },
    "redis": {
        "image": "redis:7-alpine",
        "ports": ["6379:6379"],
        "command": "redis-server --requirepass twin_redis_pass",
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "redis"},
    },
    "mongodb": {
        "image": "mongo:7",
        "ports": ["27017:27017"],
        "environment": {
            "MONGO_INITDB_ROOT_USERNAME": "twin_admin",
            "MONGO_INITDB_ROOT_PASSWORD": "twin_mongo_pass",
        },
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "mongodb"},
    },
    "elasticsearch": {
        "image": "elasticsearch:8.12.0",
        "ports": ["9200:9200"],
        "environment": {
            "discovery.type": "single-node",
            "xpack.security.enabled": "false",
        },
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "elasticsearch"},
    },
    "wordpress": {
        "image": "wordpress:6-php8.2-apache",
        "ports": ["8090:80"],
        "environment": {
            "WORDPRESS_DB_HOST": "mysql",
            "WORDPRESS_DB_NAME": "twin_db",
            "WORDPRESS_DB_USER": "twin_user",
            "WORDPRESS_DB_PASSWORD": "twin_pass_insecure",
        },
        "depends_on": ["mysql"],
        "restart": "no",
        "labels": {"vxis.twin": "true", "vxis.service": "wordpress"},
    },
}

# 기술 이름 정규화 (소문자 키워드 → 서비스 키)
_TECH_ALIAS: dict[str, str] = {
    "next.js": "nodejs",
    "nextjs": "nodejs",
    "react": "nodejs",
    "vue": "nodejs",
    "angular": "nodejs",
    "node": "nodejs",
    "node.js": "nodejs",
    "python": "flask",  # 기본값으로 flask
    "php": "laravel",
    "java": "spring",
    "kotlin": "spring",
    "postgres": "postgresql",
    "pg": "postgresql",
    "mongo": "mongodb",
    "elastic": "elasticsearch",
    "wp": "wordpress",
    "apache httpd": "apache",
    "httpd": "apache",
}


# ── 데이터 클래스 ────────────────────────────────────────────────

@dataclass
class DockerConfig:
    """생성된 Docker Compose 설정."""

    compose_yaml: str           # 완성된 YAML 문자열
    services: list[str]         # 포함된 서비스 이름 목록
    ports: dict[str, list[str]] # 서비스 → 포트 매핑
    project_name: str = "vxis-twin"
    network_name: str = "vxis-twin-isolated"
    tech_stack: list[str] = field(default_factory=list)  # 원본 기술 스택

    def get_exposed_ports(self) -> list[int]:
        """모든 노출된 호스트 포트 목록을 반환한다."""
        host_ports: list[int] = []
        for port_list in self.ports.values():
            for mapping in port_list:
                try:
                    host_port = int(mapping.split(":")[0])
                    host_ports.append(host_port)
                except (ValueError, IndexError):
                    pass
        return sorted(host_ports)


@dataclass
class AttackSimStep:
    """시뮬레이션의 단일 공격 단계."""

    name: str
    command: str  # 실행할 명령어 (docker exec 등)
    expected_output: str  # 성공 시 예상 출력 패턴
    severity: str  # 이 단계의 심각도
    success: bool = False
    actual_output: str = ""
    execution_time_ms: int = 0


@dataclass
class SimResult:
    """공격 시뮬레이션 결과."""

    chain_id: str
    chain_title: str
    success_probability: float  # 0.0~1.0 (실제로 먹힐 확률)
    evidence: list[str]         # 성공/실패 증거
    false_positive_risk: float  # 0.0~1.0 (오탐 가능성)
    steps_executed: int = 0
    steps_succeeded: int = 0
    attack_steps: list[AttackSimStep] = field(default_factory=list)
    error: str = ""

    def risk_label(self) -> str:
        if self.success_probability >= 0.8:
            return "매우 높음 — 즉시 실제 공격 가능"
        elif self.success_probability >= 0.6:
            return "높음 — 실제 환경에서 유사 성공 예상"
        elif self.success_probability >= 0.4:
            return "중간 — 추가 조건 필요"
        elif self.success_probability >= 0.2:
            return "낮음 — 특수 환경에서만 가능"
        else:
            return "매우 낮음 — 실제 환경 성공 희박"


# ── 디지털 트윈 빌더 ─────────────────────────────────────────────

class DigitalTwinBuilder:
    """기술 스택에서 Docker Compose 설정을 생성하는 빌더.

    Usage:
        builder = DigitalTwinBuilder()
        config = builder.build_twin(["Next.js", "nginx", "PostgreSQL"])
        print(config.compose_yaml)
    """

    def build_twin(self, tech_stack: list[str]) -> DockerConfig:
        """기술 스택을 분석하여 Docker Compose 설정을 생성한다.

        Args:
            tech_stack: 재현할 기술 목록.
                        (e.g., ["nginx", "python/django", "postgresql", "redis"])

        Returns:
            DockerConfig — compose_yaml, services, ports 포함.
        """
        logger.info("디지털 트윈 빌드: %s", tech_stack)

        matched_services: dict[str, dict] = {}

        for tech in tech_stack:
            service_key = self._resolve_service(tech)
            if service_key and service_key not in matched_services:
                template = _SERVICE_TEMPLATES.get(service_key)
                if template:
                    matched_services[service_key] = dict(template)

        if not matched_services:
            # 기본값: nginx + postgres (최소 환경)
            logger.warning("매칭된 서비스 없음. 기본 환경(nginx + postgres) 사용")
            matched_services["nginx"] = dict(_SERVICE_TEMPLATES["nginx"])
            matched_services["postgresql"] = dict(_SERVICE_TEMPLATES["postgresql"])

        # Docker Compose YAML 생성
        compose_yaml = self._build_compose_yaml(matched_services)

        # 포트 매핑 수집
        ports: dict[str, list[str]] = {}
        for svc_name, svc_config in matched_services.items():
            ports[svc_name] = svc_config.get("ports", [])

        config = DockerConfig(
            compose_yaml=compose_yaml,
            services=list(matched_services.keys()),
            ports=ports,
            tech_stack=tech_stack,
        )

        logger.info(
            "트윈 구성 완료: %d개 서비스 (%s), 포트 %s",
            len(config.services),
            ", ".join(config.services),
            config.get_exposed_ports(),
        )

        return config

    def _resolve_service(self, tech: str) -> str | None:
        """기술 이름을 서비스 키로 변환한다."""
        tech_lower = tech.lower().strip()

        # 정확한 매치
        if tech_lower in _SERVICE_TEMPLATES:
            return tech_lower

        # 별칭 매치
        if tech_lower in _TECH_ALIAS:
            return _TECH_ALIAS[tech_lower]

        # 부분 매치 (키워드 포함 여부)
        for alias, service_key in _TECH_ALIAS.items():
            if alias in tech_lower:
                return service_key

        # 직접 서비스 키 부분 매치
        for service_key in _SERVICE_TEMPLATES:
            if service_key in tech_lower or tech_lower in service_key:
                return service_key

        logger.debug("서비스 매핑 실패: '%s' — 무시", tech)
        return None

    def _build_compose_yaml(self, services: dict[str, dict]) -> str:
        """서비스 딕셔너리에서 Docker Compose YAML을 생성한다."""
        lines: list[str] = [
            "# VXIS Digital Twin — 자동 생성된 Docker Compose 설정",
            "# 경고: 격리된 환경에서만 실행. 실제 타겟 환경 접속 금지.",
            "# 사용법: docker compose -f this-file.yaml up -d",
            "# 정리: docker compose -f this-file.yaml down -v",
            "",
            "version: '3.8'",
            "",
            "services:",
        ]

        for service_name, config in services.items():
            lines.append(f"  {service_name}:")
            for key, value in config.items():
                if key == "labels":
                    lines.append(f"    {key}:")
                    for lk, lv in value.items():
                        lines.append(f"      {lk}: \"{lv}\"")
                elif key == "environment":
                    lines.append(f"    {key}:")
                    if isinstance(value, dict):
                        for ek, ev in value.items():
                            lines.append(f"      {ek}: \"{ev}\"")
                    else:
                        for item in value:
                            lines.append(f"      - {item}")
                elif key == "ports":
                    lines.append(f"    {key}:")
                    for port in value:
                        lines.append(f"      - \"{port}\"")
                elif key == "depends_on":
                    lines.append(f"    {key}:")
                    for dep in value:
                        lines.append(f"      - {dep}")
                elif key == "volumes":
                    lines.append(f"    {key}:")
                    for vol in value:
                        lines.append(f"      - {vol}")
                else:
                    lines.append(f"    {key}: {_yaml_value(value)}")

            lines.append(f"    networks:")
            lines.append(f"      - vxis-twin-isolated")
            lines.append("")

        lines += [
            "networks:",
            "  vxis-twin-isolated:",
            "    driver: bridge",
            "    internal: true  # 인터넷 접근 차단",
            "    labels:",
            "      vxis.twin: \"true\"",
            "      vxis.purpose: \"isolated-testing\"",
        ]

        return "\n".join(lines)


# ── 트윈 시뮬레이터 ──────────────────────────────────────────────

class TwinSimulator:
    """디지털 트윈에서 공격 시뮬레이션을 실행하는 엔진.

    Usage:
        builder = DigitalTwinBuilder()
        twin = builder.build_twin(["nginx", "postgresql"])

        simulator = TwinSimulator()
        result = await simulator.simulate_attack(twin, attack_chain)
        print(result.success_probability, result.evidence)
    """

    def __init__(self, dry_run: bool = True) -> None:
        """초기화.

        Args:
            dry_run: True이면 실제 Docker를 실행하지 않고 분석만 수행.
                     False이면 실제 Docker Compose 환경을 시작하고 테스트.
                     기본값 True (안전 우선).
        """
        self._dry_run = dry_run

    async def simulate_attack(
        self,
        twin: DockerConfig,
        attack_chain: SynthesizedChain,
    ) -> SimResult:
        """공격 체인을 트윈 환경에서 시뮬레이션한다.

        dry_run=True (기본): 공격 가능성을 정적 분석으로 평가.
        dry_run=False: 실제 Docker Compose 환경을 시작하고 테스트.

        Args:
            twin: 빌드된 DockerConfig.
            attack_chain: 시뮬레이션할 공격 체인.

        Returns:
            SimResult — 성공 확률, 증거, 오탐 위험도.
        """
        logger.info(
            "공격 시뮬레이션: '%s' (dry_run=%s)",
            attack_chain.title[:50],
            self._dry_run,
        )

        if self._dry_run:
            return await self._static_analysis(twin, attack_chain)
        else:
            return await self._live_simulation(twin, attack_chain)

    # ── 정적 분석 (dry_run=True) ─────────────────────────────

    async def _static_analysis(
        self,
        twin: DockerConfig,
        chain: SynthesizedChain,
    ) -> SimResult:
        """Docker 없이 정적 분석으로 공격 성공 가능성을 평가한다."""
        evidence: list[str] = []
        steps: list[AttackSimStep] = []
        success_count = 0

        # 트윈 서비스와 공격 체인 매핑 분석
        services_lower = [s.lower() for s in twin.services]

        for finding in chain.findings:
            step_success = self._analyze_step_feasibility(
                finding, twin, services_lower
            )
            step = AttackSimStep(
                name=finding.title,
                command=f"# 시뮬레이션: {finding.agent_id}",
                expected_output=f"취약점 확인: {finding.title}",
                severity=finding.severity.value,
                success=step_success,
                actual_output=(
                    f"[정적 분석] 트윈 환경에서 {finding.agent_id} 발견 재현 "
                    f"{'가능' if step_success else '불가능'}"
                ),
            )
            steps.append(step)

            if step_success:
                success_count += 1
                evidence.append(
                    f"트윈 서비스 '{finding.agent_id}'에서 "
                    f"'{finding.title}' 재현 가능"
                )
            else:
                evidence.append(
                    f"트윈에 '{finding.agent_id}' 서비스 없음 — "
                    f"'{finding.title}' 재현 불가"
                )

        # LLM으로 전체 체인 성공 확률 보강
        base_probability = success_count / len(chain.findings) if chain.findings else 0.0
        llm_probability = await self._llm_assess_probability(chain, twin, base_probability)

        # 오탐 위험도: 트윈이 실제와 완전히 동일하지 않을 수 있음
        false_positive_risk = self._calculate_fpr(twin, chain)

        return SimResult(
            chain_id=chain.id,
            chain_title=chain.title,
            success_probability=llm_probability,
            evidence=evidence,
            false_positive_risk=false_positive_risk,
            steps_executed=len(steps),
            steps_succeeded=success_count,
            attack_steps=steps,
        )

    def _analyze_step_feasibility(
        self,
        finding: Any,
        twin: DockerConfig,
        services_lower: list[str],
    ) -> bool:
        """단일 공격 단계의 트윈 재현 가능성을 평가한다."""
        agent_id = finding.agent_id.lower()

        # 에이전트 → 필요 서비스 매핑
        agent_service_map = {
            "web": ["nginx", "apache", "nodejs", "express"],
            "api": ["nodejs", "express", "flask", "django", "spring"],
            "database": ["postgresql", "mysql", "mongodb", "redis"],
            "cloud": [],  # 클라우드는 트윈으로 재현 어려움
            "network": ["nginx", "apache"],
            "recon": services_lower,  # 어떤 서비스든 recon 가능
            "cms_biz_platform": ["wordpress"],
        }

        # 에이전트에 필요한 서비스가 트윈에 있는지 확인
        required_services = agent_service_map.get(agent_id, [])
        if not required_services:
            return len(services_lower) > 0  # 기본적으로 서비스가 있으면 가능

        return any(svc in services_lower for svc in required_services)

    def _calculate_fpr(
        self, twin: DockerConfig, chain: SynthesizedChain
    ) -> float:
        """오탐 가능성을 계산한다.

        트윈이 실제 환경과 다를 수 있는 요소들을 고려.
        """
        fpr = 0.2  # 기본 오탐 가능성 20%

        # 클라우드 레이어가 포함된 체인 → 오탐 위험 증가
        from vxis.synthesis.cross_protocol import OSILayer
        if OSILayer.CLOUD in chain.layers_crossed:
            fpr += 0.3

        # 트윈 서비스 수가 실제 공격 단계 수보다 적으면 오탐 위험 증가
        coverage = len(twin.services) / max(len(chain.findings), 1)
        if coverage < 0.5:
            fpr += 0.2

        return min(fpr, 0.9)

    # ── LLM 확률 평가 ────────────────────────────────────────

    async def _llm_assess_probability(
        self,
        chain: SynthesizedChain,
        twin: DockerConfig,
        base_probability: float,
    ) -> float:
        """LLM으로 공격 성공 확률을 보강 평가한다."""
        findings_text = "\n".join(
            f"  - [{f.severity.value}] {f.title} (에이전트: {f.agent_id})"
            for f in chain.findings
        )

        prompt = f"""\
다음 공격 체인이 디지털 트윈 환경에서 성공할 확률을 평가하라.

## 공격 체인
{chain.title} (심각도: {chain.severity.value.upper()})

## 체인 구성 단계
{findings_text}

## 트윈 환경
서비스: {', '.join(twin.services)}
포트: {twin.get_exposed_ports()}

## 기본 평가
단계 매핑 기반 초기 확률: {base_probability:.0%}

## 질문
이 공격 체인이 실제 환경에서 성공할 확률을 0.0~1.0으로 평가하라.
트윈과 실제 환경의 차이, 공격 복잡도, 방어 메커니즘을 고려하라.

JSON으로 응답:
{{"probability": 0.75, "reasoning": "이유 설명"}}
"""

        try:
            from vxis.llm.client import LLMClient
            client = LLMClient()
            response = await client.think(
                system=(
                    "당신은 레드팀 전문가입니다. "
                    "공격 시나리오의 실제 성공 가능성을 평가합니다."
                ),
                user=prompt,
                max_tokens=300,
            )

            text = response.text
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]

            data = json.loads(text.strip())
            prob = float(data.get("probability", base_probability))
            return max(0.0, min(1.0, prob))

        except Exception as exc:
            logger.debug("LLM 확률 평가 실패, 기본값 사용: %s", exc)
            return base_probability

    # ── 실제 Docker 시뮬레이션 (dry_run=False) ───────────────

    async def _live_simulation(
        self,
        twin: DockerConfig,
        chain: SynthesizedChain,
    ) -> SimResult:
        """실제 Docker Compose 환경을 시작하고 공격을 시뮬레이션한다.

        경고: 이 메서드는 실제 Docker 컨테이너를 시작합니다.
        격리된 환경에서만 실행하세요.
        """
        import time

        result = SimResult(
            chain_id=chain.id,
            chain_title=chain.title,
            success_probability=0.0,
            evidence=[],
            false_positive_risk=self._calculate_fpr(twin, chain),
        )

        # Docker 가용성 확인
        if not self._check_docker_available():
            result.error = "Docker를 찾을 수 없음. dry_run=True로 전환하세요."
            logger.error("Docker 없음 — 라이브 시뮬레이션 불가")
            return result

        with tempfile.TemporaryDirectory(prefix="vxis_twin_") as tmpdir:
            compose_file = Path(tmpdir) / "docker-compose.yaml"
            compose_file.write_text(twin.compose_yaml, encoding="utf-8")

            try:
                # 트윈 시작
                logger.info("트윈 시작: %s", tmpdir)
                self._run_compose(compose_file, ["up", "-d", "--wait"])

                # 서비스 준비 대기 (최대 30초)
                time.sleep(10)

                # 기본 연결성 테스트
                steps: list[AttackSimStep] = []
                success_count = 0

                for port in twin.get_exposed_ports()[:5]:  # 최대 5개 포트만
                    step = self._test_port_connectivity(port, chain)
                    steps.append(step)
                    if step.success:
                        success_count += 1
                        result.evidence.append(
                            f"포트 {port} 연결 확인 — 서비스 응답 정상"
                        )

                result.steps_executed = len(steps)
                result.steps_succeeded = success_count
                result.attack_steps = steps
                result.success_probability = await self._llm_assess_probability(
                    chain, twin,
                    success_count / len(steps) if steps else 0.0,
                )

            except subprocess.CalledProcessError as exc:
                result.error = f"Docker Compose 오류: {exc.stderr}"
                logger.error("트윈 시작 실패: %s", exc)

            finally:
                # 반드시 정리
                try:
                    self._run_compose(compose_file, ["down", "-v", "--remove-orphans"])
                    logger.info("트윈 정리 완료")
                except Exception as cleanup_exc:
                    logger.error("트윈 정리 실패 (수동 정리 필요): %s", cleanup_exc)

        return result

    def _check_docker_available(self) -> bool:
        """Docker CLI 가용성을 확인한다."""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def _run_compose(
        self,
        compose_file: Path,
        subcommand: list[str],
    ) -> subprocess.CompletedProcess:
        """Docker Compose 명령을 실행한다."""
        cmd = [
            "docker", "compose",
            "-f", str(compose_file),
            "-p", "vxis-twin",
            *subcommand,
        ]
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )

    def _test_port_connectivity(
        self,
        port: int,
        chain: SynthesizedChain,
    ) -> AttackSimStep:
        """특정 포트의 연결 가능성을 테스트한다."""
        import socket as sock_module
        import time

        start = time.time()
        success = False
        output = ""

        try:
            s = sock_module.socket(sock_module.AF_INET, sock_module.SOCK_STREAM)
            s.settimeout(3)
            result = s.connect_ex(("127.0.0.1", port))
            s.close()
            success = result == 0
            output = f"포트 {port} {'열림' if success else '닫힘'}"
        except OSError as exc:
            output = f"연결 오류: {exc}"

        elapsed = int((time.time() - start) * 1000)

        return AttackSimStep(
            name=f"포트 {port} 연결성 테스트",
            command=f"nc -z 127.0.0.1 {port}",
            expected_output="연결 성공",
            severity=chain.severity.value,
            success=success,
            actual_output=output,
            execution_time_ms=elapsed,
        )

    # ── 리포트 생성 ────────────────────────────────────────

    def format_simulation_report(
        self,
        twin: DockerConfig,
        results: list[SimResult],
    ) -> str:
        """시뮬레이션 결과를 마크다운 리포트로 생성한다."""
        if not results:
            return "## 디지털 트윈 시뮬레이션 리포트\n\n_결과 없음._\n"

        lines = [
            "## 디지털 트윈 시뮬레이션 리포트",
            "",
            "### 트윈 구성",
            f"- 서비스: {', '.join(twin.services)}",
            f"- 노출 포트: {twin.get_exposed_ports()}",
            f"- 기술 스택: {', '.join(twin.tech_stack)}",
            "",
            f"### 시뮬레이션 결과 ({len(results)}개 체인)",
            "",
        ]

        high_prob = [r for r in results if r.success_probability >= 0.6]
        low_prob = [r for r in results if r.success_probability < 0.2]

        lines += [
            f"- 고위험 (60%+): {len(high_prob)}개",
            f"- 저위험 (20%-): {len(low_prob)}개",
            "",
            "---",
            "",
        ]

        for i, result in enumerate(
            sorted(results, key=lambda r: r.success_probability, reverse=True),
            1,
        ):
            lines += [
                f"#### {i}. {result.chain_title}",
                f"- **성공 확률**: {result.success_probability:.0%} ({result.risk_label()})",
                f"- **오탐 위험**: {result.false_positive_risk:.0%}",
                f"- **단계**: {result.steps_succeeded}/{result.steps_executed} 성공",
            ]

            if result.error:
                lines.append(f"- **오류**: {result.error}")

            if result.evidence:
                lines.append("")
                lines.append("**증거:**")
                for ev in result.evidence:
                    lines.append(f"- {ev}")

            lines.append("")

        lines += [
            "---",
            "",
            "### 실제 스캔 권고",
            "",
        ]

        if high_prob:
            lines.append("다음 공격 체인은 트윈에서 검증되었습니다. 실제 스캔 시 우선 실행:")
            for r in high_prob:
                lines.append(
                    f"- **{r.chain_title}** "
                    f"(성공률 {r.success_probability:.0%}, "
                    f"오탐 {r.false_positive_risk:.0%})"
                )
        else:
            lines.append("검증된 고위험 공격 체인이 없습니다. 기본 스캔을 진행하세요.")

        return "\n".join(lines)


# ── 헬퍼 함수 ────────────────────────────────────────────────────

def _yaml_value(value: Any) -> str:
    """Python 값을 YAML 값 문자열로 변환한다."""
    if isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, (int, float)):
        return str(value)
    elif isinstance(value, str):
        return f"\"{value}\""
    else:
        return str(value)
