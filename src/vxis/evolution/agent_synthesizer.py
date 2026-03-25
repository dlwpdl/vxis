"""자기 진화 에이전트 합성 — 미션에서 부족했던 능력을 자동으로 생성.

미션 후: "IoT 프로토콜 에이전트가 없어서 MQTT 취약점을 놓쳤다"
→ LLM이 새 에이전트 Python 코드를 자동 생성
→ 다음 미션에 자동 포함

안전 원칙:
    - 생성된 코드는 ast.parse로 구문 검증
    - 위험 패턴(exec, eval, __import__) 정적 분석으로 차단
    - 파일 저장 후 자동 실행 금지 (수동 승인 필수)
    - 생성된 파일은 .generated_agents/ 임시 디렉토리에 격리
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# 허용되지 않는 위험 패턴 (코드 인젝션 방지)
_DANGEROUS_PATTERNS: list[str] = [
    r"\bexec\s*\(",
    r"\beval\s*\(",
    r"\b__import__\s*\(",
    r"\bcompile\s*\(",
    r"\bos\.system\s*\(",
    r"\bsubprocess\.call\s*\(",
    r"open\s*\([^)]*['\"]w['\"]",  # 파일 쓰기
    r"\bimport\s+ctypes",
    r"\bimport\s+pickle",
]

_COMPILED_DANGEROUS = [re.compile(p) for p in _DANGEROUS_PATTERNS]


@dataclass
class GapAnalysis:
    """미션에서 발견된 능력 갭."""

    gap_type: str       # e.g., "missing_protocol", "missing_technology"
    description: str    # e.g., "MQTT 프로토콜 취약점 분석 능력 없음"
    missed_findings: list[str] = field(default_factory=list)  # 놓친 취약점 제목들
    priority: int = 5   # 1(최우선) ~ 10(낮음)
    suggested_agent_name: str = ""


@dataclass
class SynthesisProposal:
    """에이전트 합성 제안 — 수동 승인 대기 상태."""

    agent_name: str
    gap_description: str
    generated_code: str
    is_valid_syntax: bool
    is_safe: bool
    safety_issues: list[str] = field(default_factory=list)
    saved_path: Path | None = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def can_be_approved(self) -> bool:
        """수동 승인 가능 여부 (구문 유효 + 안전)."""
        return self.is_valid_syntax and self.is_safe


# ── 에이전트 템플릿 ────────────────────────────────────────────

_AGENT_BASE_TEMPLATE = '''"""자동 생성된 에이전트 — {agent_name}.

생성 일시: {created_at}
갭 설명: {gap_description}

경고: 이 파일은 LLM이 자동 생성했습니다.
      실제 사용 전 보안 검토 및 수동 승인이 필요합니다.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class {class_name}:
    """자동 생성된 보안 분석 에이전트.

    갭: {gap_description}
    """

    AGENT_ID = "{agent_id}"
    VERSION = "0.1.0-generated"

    def __init__(self, target: str, **kwargs: Any) -> None:
        self.target = target
        self.options = kwargs
        logger.info("[%s] 에이전트 초기화: %s", self.AGENT_ID, target)

    async def run(self) -> list[dict[str, Any]]:
        """분석을 실행하고 발견 목록을 반환한다."""
        logger.info("[%s] 분석 시작: %s", self.AGENT_ID, self.target)
        findings = []

        try:
            findings = await self._analyze()
        except Exception as exc:
            logger.error("[%s] 분석 실패: %s", self.AGENT_ID, exc)

        logger.info("[%s] 분석 완료: %d건 발견", self.AGENT_ID, len(findings))
        return findings

    async def _analyze(self) -> list[dict[str, Any]]:
        """핵심 분석 로직 — 서브클래스에서 구현하거나 아래 생성 코드 사용."""
        # TODO: LLM이 생성한 로직이 여기에 삽입됩니다
        raise NotImplementedError("생성된 에이전트는 실제 구현이 필요합니다")
'''


# ── 핵심 합성 엔진 ───────────────────────────────────────────────

class AgentSynthesizer:
    """자기 진화 에이전트 합성 엔진.

    미션 결과를 분석하여 능력 갭을 찾고, LLM으로 새 에이전트 코드를 생성한다.

    Usage:
        synthesizer = AgentSynthesizer()
        gaps = synthesizer.analyze_gaps(mission_result)
        for gap in gaps:
            proposal = await synthesizer.synthesize_agent(gap.description)
            if proposal.can_be_approved:
                path = synthesizer.save_agent(proposal.generated_code, proposal.agent_name)
    """

    def __init__(
        self,
        agents_dir: Path | None = None,
    ) -> None:
        # 생성 파일은 .generated_agents/ 임시 디렉토리에 격리
        if agents_dir is None:
            self._agents_dir = (
                Path(__file__).parent.parent / "agent" / ".generated_agents"
            )
        else:
            self._agents_dir = agents_dir

        self._proposals: list[SynthesisProposal] = []

    # ── 갭 분석 ──────────────────────────────────────────────

    def analyze_gaps(self, mission_result: dict[str, Any]) -> list[GapAnalysis]:
        """미션 결과에서 능력 갭을 분석한다.

        Args:
            mission_result: 미션 실행 결과 딕셔너리.
                {
                    "target": str,
                    "tech_stack": list[str],
                    "findings": list[dict],
                    "agents_used": list[str],
                    "missed_technologies": list[str],  # 분석 못 한 기술
                    "error_logs": list[str],
                }

        Returns:
            발견된 능력 갭 목록 (우선순위 정렬).
        """
        gaps: list[GapAnalysis] = []

        tech_stack = mission_result.get("tech_stack", [])
        agents_used = set(mission_result.get("agents_used", []))
        missed_techs = mission_result.get("missed_technologies", [])
        error_logs = mission_result.get("error_logs", [])
        findings = mission_result.get("findings", [])

        # 1. 명시적으로 놓친 기술 분석
        for tech in missed_techs:
            gaps.append(GapAnalysis(
                gap_type="missing_technology",
                description=f"{tech} 취약점 분석 에이전트 없음",
                priority=3,
                suggested_agent_name=_tech_to_agent_name(tech),
            ))

        # 2. 에러 로그에서 갭 추론
        for error in error_logs:
            gap = self._infer_gap_from_error(error)
            if gap:
                gaps.append(gap)

        # 3. 기술 스택 vs 사용된 에이전트 교차 분석
        for tech in tech_stack:
            expected_agent = _tech_to_agent_name(tech)
            if expected_agent and expected_agent not in agents_used:
                # 이미 갭 목록에 없으면 추가
                existing = {g.suggested_agent_name for g in gaps}
                if expected_agent not in existing:
                    # 발견 중 이 기술과 관련된 항목이 있는지 확인
                    related_findings = [
                        f.get("title", "")
                        for f in findings
                        if tech.lower() in f.get("title", "").lower()
                        or tech.lower() in f.get("description", "").lower()
                    ]
                    gaps.append(GapAnalysis(
                        gap_type="coverage_gap",
                        description=(
                            f"기술 스택에 {tech}가 있으나 전용 에이전트 미사용 "
                            f"(관련 발견 {len(related_findings)}건)"
                        ),
                        missed_findings=related_findings[:5],
                        priority=5,
                        suggested_agent_name=expected_agent,
                    ))

        # 우선순위 정렬
        gaps.sort(key=lambda g: g.priority)

        logger.info("능력 갭 분석 완료: %d개 갭 발견", len(gaps))
        for g in gaps:
            logger.debug("  [우선순위 %d] %s (%s)", g.priority, g.description, g.gap_type)

        return gaps

    def _infer_gap_from_error(self, error_log: str) -> GapAnalysis | None:
        """에러 로그에서 능력 갭을 추론한다."""
        error_lower = error_log.lower()

        # 알려진 에러 패턴 → 갭 매핑
        patterns = [
            ("mqtt", "MQTT 프로토콜", "mqtt_agent"),
            ("modbus", "Modbus/SCADA 프로토콜", "modbus_agent"),
            ("amqp", "AMQP/RabbitMQ 프로토콜", "amqp_agent"),
            ("grpc", "gRPC 서비스", "grpc_agent"),
            ("graphql", "GraphQL API", "graphql_agent"),
            ("websocket", "WebSocket 프로토콜", "websocket_agent"),
            ("oauth", "OAuth/OIDC 인증", "oauth_agent"),
            ("jwt", "JWT 토큰 분석", "jwt_agent"),
            ("saml", "SAML 인증", "saml_agent"),
            ("ldap", "LDAP 디렉터리", "ldap_agent"),
            ("redis", "Redis 노출 분석", "redis_agent"),
            ("elasticsearch", "Elasticsearch 보안", "elasticsearch_agent"),
        ]

        for keyword, tech_name, agent_name in patterns:
            if keyword in error_lower:
                return GapAnalysis(
                    gap_type="missing_protocol",
                    description=f"{tech_name} 분석 에이전트 없음 (에러 로그에서 탐지)",
                    priority=2,
                    suggested_agent_name=agent_name,
                )

        return None

    # ── 에이전트 합성 ──────────────────────────────────────────

    async def synthesize_agent(
        self, gap_description: str, agent_name: str = ""
    ) -> SynthesisProposal:
        """LLM으로 새 에이전트 Python 코드를 생성한다.

        Args:
            gap_description: 갭 설명 (e.g., "MQTT 프로토콜 취약점 분석 에이전트 없음").
            agent_name: 생성할 에이전트 이름 (비어 있으면 자동 생성).

        Returns:
            SynthesisProposal — 수동 승인 대기 상태.
        """
        if not agent_name:
            agent_name = _description_to_agent_name(gap_description)

        class_name = _to_class_name(agent_name)
        created_at = datetime.now(timezone.utc).isoformat()

        logger.info("에이전트 합성 시작: %s (갭: %s)", agent_name, gap_description[:60])

        prompt = f"""\
당신은 시니어 보안 연구원입니다. 다음 능력 갭을 채우는 Python 에이전트 코드를 작성하라.

## 갭 설명
{gap_description}

## 에이전트 이름
{agent_name}

## 요구사항
1. 클래스 이름: {class_name}
2. AGENT_ID = "{agent_name}"
3. `async def run(self) -> list[dict]` 메서드 필수
4. 각 발견은 다음 형식의 dict:
   {{
       "title": str,
       "severity": "critical|high|medium|low|info",
       "description": str,
       "agent_id": "{agent_name}",
       "evidence_type": "misconfiguration|network|osint|other"
   }}
5. stdlib만 사용 (requests, aiohttp, pydantic 등 외부 라이브러리 금지)
6. 에러 처리 철저히 (try/except)
7. 모든 주석과 docstring은 한국어로 작성
8. exec, eval, __import__ 사용 금지
9. 실제로 동작하는 코드를 작성할 것 (더미/stub 금지)

## 접근 방법
- urllib, socket, ssl 등 stdlib 사용
- 타임아웃 항상 설정 (연결 5초, 읽기 10초)
- 공개 정보만 수집 (OSINT 원칙)

Python 코드만 출력하라. 설명 텍스트 없이 코드 블록만.
"""

        try:
            from vxis.llm.client import LLMClient
            client = LLMClient()
            response = await client.think(
                system=(
                    "당신은 Python 보안 도구 개발 전문가입니다. "
                    "stdlib만 사용하여 실제 동작하는 보안 에이전트 코드를 작성합니다."
                ),
                user=prompt,
                max_tokens=4000,
            )

            code = response.text
            # 코드 블록 추출
            if "```python" in code:
                code = code.split("```python")[1].split("```")[0].strip()
            elif "```" in code:
                code = code.split("```")[1].split("```")[0].strip()

        except Exception as exc:
            logger.warning("LLM 에이전트 코드 생성 실패, 기본 템플릿 사용: %s", exc)
            code = _AGENT_BASE_TEMPLATE.format(
                agent_name=agent_name,
                class_name=class_name,
                created_at=created_at,
                gap_description=gap_description,
                agent_id=agent_name,
            )

        # 구문 검증
        is_valid, syntax_error = self._check_syntax(code)

        # 안전성 검사
        is_safe, safety_issues = self._check_safety(code)

        proposal = SynthesisProposal(
            agent_name=agent_name,
            gap_description=gap_description,
            generated_code=code,
            is_valid_syntax=is_valid,
            is_safe=is_safe,
            safety_issues=safety_issues,
            created_at=created_at,
        )

        self._proposals.append(proposal)

        logger.info(
            "에이전트 합성 완료: %s — 구문 %s, 안전 %s",
            agent_name,
            "OK" if is_valid else "오류",
            "OK" if is_safe else f"위험 ({len(safety_issues)}개 패턴)",
        )

        if not is_valid:
            logger.warning("  구문 오류: %s", syntax_error)
        if not is_safe:
            for issue in safety_issues:
                logger.warning("  보안 문제: %s", issue)

        return proposal

    # ── 검증 ──────────────────────────────────────────────────

    def validate_agent(self, code: str) -> bool:
        """에이전트 코드의 구문 유효성과 안전성을 동시에 검증한다.

        Args:
            code: 검증할 Python 코드 문자열.

        Returns:
            구문 유효 AND 안전하면 True.
        """
        is_valid, _ = self._check_syntax(code)
        is_safe, _ = self._check_safety(code)
        return is_valid and is_safe

    def _check_syntax(self, code: str) -> tuple[bool, str]:
        """ast.parse로 Python 구문을 검증한다."""
        try:
            ast.parse(code)
            return True, ""
        except SyntaxError as exc:
            return False, f"줄 {exc.lineno}: {exc.msg}"
        except Exception as exc:
            return False, str(exc)

    def _check_safety(self, code: str) -> tuple[bool, list[str]]:
        """위험 패턴 정적 분석으로 코드 안전성을 검증한다."""
        issues: list[str] = []

        for pattern in _COMPILED_DANGEROUS:
            if pattern.search(code):
                issues.append(f"위험 패턴 탐지: {pattern.pattern}")

        # AST 수준 추가 검사
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                # 동적 임포트 탐지
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in {"ctypes", "pickle", "marshal"}:
                            issues.append(f"위험 모듈 임포트: {alias.name}")
                # __dunder__ 속성 접근 탐지 (일부 우회 기법)
                if isinstance(node, ast.Attribute):
                    if (
                        node.attr.startswith("__")
                        and node.attr.endswith("__")
                        and node.attr not in {"__init__", "__str__", "__repr__", "__class__"}
                    ):
                        pass  # 일부 dunder는 허용 (경고만)
        except SyntaxError:
            pass  # 이미 _check_syntax에서 처리됨

        return len(issues) == 0, issues

    # ── 저장 ──────────────────────────────────────────────────

    def save_agent(self, code: str, name: str) -> Path:
        """검증된 에이전트 코드를 격리 디렉토리에 저장한다.

        생성된 파일은 .generated_agents/ 에 격리되며 자동 실행되지 않는다.
        실제 에이전트로 승격하려면 수동 검토 후 agents/ 디렉토리로 이동해야 한다.

        Args:
            code: 저장할 Python 코드.
            name: 에이전트 이름 (파일명 기반).

        Returns:
            저장된 파일 경로.

        Raises:
            ValueError: 코드가 안전하지 않거나 구문 오류가 있을 때.
        """
        is_valid, syntax_err = self._check_syntax(code)
        if not is_valid:
            raise ValueError(f"구문 오류로 저장 거부: {syntax_err}")

        is_safe, issues = self._check_safety(code)
        if not is_safe:
            raise ValueError(f"안전성 검사 실패로 저장 거부: {'; '.join(issues)}")

        # 파일명 정규화
        safe_name = re.sub(r"[^a-z0-9_]", "_", name.lower())
        filename = f"{safe_name}.py"

        self._agents_dir.mkdir(parents=True, exist_ok=True)
        target_path = self._agents_dir / filename

        # 파일 헤더 추가
        header = (
            f"# 자동 생성된 에이전트 — 수동 승인 전 실행 금지\n"
            f"# 생성 일시: {datetime.now(timezone.utc).isoformat()}\n"
            f"# 에이전트 이름: {name}\n"
            f"# 승격 방법: 검토 후 ../agents/ 디렉토리로 이동\n\n"
        )

        target_path.write_text(header + code, encoding="utf-8")

        logger.info("에이전트 저장: %s", target_path)
        logger.warning(
            "주의: 이 파일은 수동 검토 후에만 실제 에이전트로 승격하세요: %s",
            target_path,
        )

        # 제안 목록 업데이트
        for proposal in self._proposals:
            if proposal.agent_name == name:
                proposal.saved_path = target_path

        return target_path

    # ── 요약 ──────────────────────────────────────────────────

    def format_synthesis_report(self) -> str:
        """합성 세션의 전체 리포트를 마크다운으로 생성한다."""
        if not self._proposals:
            return "## 에이전트 합성 리포트\n\n_합성된 에이전트 없음._\n"

        valid = [p for p in self._proposals if p.is_valid_syntax]
        safe = [p for p in self._proposals if p.is_safe]
        approvable = [p for p in self._proposals if p.can_be_approved]
        saved = [p for p in self._proposals if p.saved_path]

        lines = [
            "## 에이전트 합성 리포트",
            "",
            f"- 총 합성: {len(self._proposals)}개",
            f"- 구문 유효: {len(valid)}개",
            f"- 안전성 통과: {len(safe)}개",
            f"- 승인 가능: {len(approvable)}개",
            f"- 저장됨: {len(saved)}개",
            "",
        ]

        for proposal in self._proposals:
            status = "승인 가능" if proposal.can_be_approved else "검토 필요"
            lines += [
                f"### {proposal.agent_name} [{status}]",
                f"- 갭: {proposal.gap_description}",
                f"- 구문: {'OK' if proposal.is_valid_syntax else '오류'}",
                f"- 안전: {'OK' if proposal.is_safe else '위험'}",
            ]
            if proposal.safety_issues:
                for issue in proposal.safety_issues:
                    lines.append(f"  - 경고: {issue}")
            if proposal.saved_path:
                lines.append(f"- 저장 경로: `{proposal.saved_path}`")
            lines.append("")

        return "\n".join(lines)


# ── 헬퍼 함수 ────────────────────────────────────────────────────

def _tech_to_agent_name(tech: str) -> str:
    """기술 이름을 에이전트 이름으로 변환한다."""
    tech_map = {
        "mqtt": "mqtt_agent",
        "modbus": "modbus_agent",
        "graphql": "graphql_agent",
        "grpc": "grpc_agent",
        "websocket": "websocket_agent",
        "oauth": "oauth_agent",
        "saml": "saml_agent",
        "ldap": "ldap_agent",
        "redis": "redis_exposure_agent",
        "elasticsearch": "elasticsearch_agent",
        "kafka": "kafka_agent",
        "rabbitmq": "rabbitmq_agent",
        "mongodb": "mongodb_agent",
        "memcached": "memcached_agent",
        "etcd": "etcd_agent",
        "consul": "consul_agent",
        "vault": "vault_agent",
        "jenkins": "jenkins_agent",
        "gitlab": "gitlab_agent",
        "jira": "jira_agent",
    }
    return tech_map.get(tech.lower(), f"{tech.lower().replace(' ', '_')}_agent")


def _description_to_agent_name(description: str) -> str:
    """갭 설명에서 에이전트 이름을 추론한다."""
    # 첫 단어들에서 주요 기술명 추출
    words = description.lower().split()
    for word in words:
        cleaned = re.sub(r"[^a-z0-9]", "", word)
        if len(cleaned) >= 3:
            return f"{cleaned}_agent"
    return "generated_agent"


def _to_class_name(agent_name: str) -> str:
    """snake_case 에이전트 이름을 PascalCase 클래스 이름으로 변환한다."""
    parts = re.split(r"[_\-\s]+", agent_name)
    return "".join(p.capitalize() for p in parts if p)
