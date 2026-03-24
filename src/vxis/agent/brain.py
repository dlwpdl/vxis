"""VXIS Agent Brain — AI-driven pentesting decision engine.

Phase 3 Architecture:
    ┌──────────────────────────────────────────────────────────┐
    │  BRAIN (Cognitive Loop)                                   │
    │                                                          │
    │  1. PERCEIVE  — Context Compressor로 데이터 압축           │
    │  2. RECALL    — Knowledge Store에서 패턴 매칭             │
    │  3. REASON    — Token Router로 최적 모델 선택 → LLM 호출  │
    │  4. CHAIN     — Chain Reasoner로 공격 체인 추론            │
    │  5. REFLECT   — 전략 전환 필요 여부 판단                   │
    │  6. ACT       — 실행할 도구 결정                          │
    │  7. LEARN     — 결과를 Knowledge Store에 축적             │
    └──────────────────────────────────────────────────────────┘

    쓸수록 강해지는 구조:
    - Day 1:   90% LLM, 10% 컴파일 패턴 → 비쌈
    - Day 100: 10% LLM, 90% 컴파일 패턴 → 저렴 & 최강
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vxis.agent.memory import AgentMemory
    from vxis.knowledge.store import KnowledgeStore
    from vxis.knowledge.compressor import ContextCompressor
    from vxis.llm.router import TokenRouter
    from vxis.graph.chain_reasoner import ChainReasoner

logger = logging.getLogger(__name__)


# ── Data structures ─────────────────────────────────────────────

@dataclass
class AgentObservation:
    """Current state visible to the agent."""

    target: str
    tech_stack: list[str] = field(default_factory=list)
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    executed_tools: list[dict[str, str]] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    live_urls: list[str] = field(default_factory=list)


@dataclass
class AgentAction:
    """An action decided by the agent."""

    tool: str  # tool name or special command
    args: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""  # why this action
    priority: str = "medium"  # high, medium, low


@dataclass
class AgentStep:
    """Record of one think→act cycle."""

    step_number: int
    observation_summary: str
    actions: list[AgentAction]
    results: list[dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── System prompt ───────────────────────────────────────────────

AGENT_SYSTEM_PROMPT = """\
You are VXIS, an expert AI penetration tester. You think and act like a senior \
security consultant performing a black-box assessment.

Your workflow:
1. OBSERVE: Review the current findings, open ports, tech stack, and what tools have already run.
2. THINK: Identify gaps in coverage and prioritize the most impactful next steps.
3. ACT: Choose 1-3 tools to run next, with specific arguments.

Available tools (use exact names):
{available_tools}

Rules:
- Always explain your reasoning in Korean (한국어).
- Be strategic: don't repeat tools that already ran unless with different args.
- Prioritize: high-impact vulns first (RCE > SQLi > XSS > info disclosure).
- If nmap found interesting ports, probe them deeper.
- If nuclei found nothing, try different template categories or manual checks.
- If a WAF is detected, adjust your approach (slower rate, different payloads).
- When you believe testing is complete, return tool="DONE".

Output valid JSON:
{{
  "reasoning": "한국어로 현재 상황 분석 및 다음 행동 이유 설명",
  "actions": [
    {{
      "tool": "tool_name",
      "args": {{"key": "value"}},
      "reasoning": "이 도구를 선택한 이유",
      "priority": "high|medium|low"
    }}
  ]
}}

If testing is complete:
{{
  "reasoning": "테스트 완료 이유 설명",
  "actions": [{{"tool": "DONE", "reasoning": "충분한 커버리지 달성"}}]
}}
"""

# ── Tool descriptions for the agent ─────────────────────────────

# ── Sub-agent team definitions ──────────────────────────────────

AGENT_TEAMS = {
    "recon": {
        "name": "정찰팀 (Recon)",
        "desc": "공격 표면 수집 — 서브도메인, 포트, 기술 스택, 인증서",
        "tools": ["subfinder", "httpx", "nmap", "crtsh", "shodan"],
    },
    "vuln": {
        "name": "취약점 분석팀 (Vulnerability)",
        "desc": "알려진 취약점 + 설정 오류 탐지",
        "tools": ["nuclei", "wafw00f"],
    },
    "crypto": {
        "name": "암호화 분석팀 (Crypto/TLS)",
        "desc": "TLS/SSL 설정, 인증서, 암호화 취약점",
        "tools": ["testssl", "sslyze"],
    },
    "email": {
        "name": "이메일 보안팀 (Email Security)",
        "desc": "SPF, DMARC, DKIM, 스푸핑 방지",
        "tools": ["checkdmarc", "dnstwist", "swaks"],
    },
    "secrets": {
        "name": "시크릿 탐지팀 (Secret Detection)",
        "desc": "노출된 자격증명, API 키, 토큰 탐색",
        "tools": ["trufflehog", "gitleaks"],
    },
    "webapp": {
        "name": "웹 앱 공격팀 (Web App Exploitation)",
        "desc": "SQL 인젝션, XSS, 디렉토리 탐색, 인증 우회",
        "tools": ["sqlmap", "ffuf"],
    },
    "code": {
        "name": "코드 분석팀 (Code Analysis)",
        "desc": "소스코드 정적 분석 + 의존성 취약점",
        "tools": ["semgrep", "bandit", "checkov", "trivy", "gitleaks"],
    },
    "cloud": {
        "name": "클라우드 보안팀 (Cloud Security)",
        "desc": "AWS/Azure/GCP 설정 감사 + 컨테이너",
        "tools": ["prowler", "s3scanner", "trivy-k8s", "kube-bench"],
    },
    "infra": {
        "name": "인프라/AD팀 (Infrastructure/AD)",
        "desc": "내부 네트워크, Active Directory, 권한 상승",
        "tools": ["bloodhound", "certipy", "netexec", "linpeas"],
    },
}

TOOL_DESCRIPTIONS = {
    # Recon
    "nmap": "포트 스캔 + 서비스 탐지. args: ports(str), scripts(str), udp(bool)",
    "httpx": "HTTP 프로빙 + 기술 스택 탐지 + 보안 헤더. args: targets(list[str])",
    "subfinder": "서브도메인 열거 (패시브). args: domain(str)",
    "crtsh": "인증서 투명성 로그에서 서브도메인 조회. args: domain(str)",
    "shodan": "인터넷 노출 서비스 조회 (유료 API). args: target(str)",
    # Vulnerability
    "nuclei": "템플릿 기반 취약점 스캐너 (CVE, 설정오류, 노출). args: severity(str), tags(str)",
    "wafw00f": "WAF 탐지 — 방화벽 존재 시 전략 조정 필요. args: urls(list[str])",
    # Crypto
    "testssl": "TLS 프로토콜/취약점/헤더/인증서 전체 검사. args: host(str)",
    "sslyze": "SSL 심층 분석 (Heartbleed, ROBOT, CCS injection 등). args: host(str)",
    # Email
    "checkdmarc": "SPF/DMARC/DKIM 이메일 인증 검사. args: domain(str)",
    "dnstwist": "유사 도메인 탐지 + MX 체크 + WHOIS. args: domain(str)",
    "swaks": "SMTP 오픈 릴레이 / 이메일 스푸핑 테스트. args: target(str)",
    # Secrets
    "trufflehog": "GitHub org 전체 시크릿 스캔. args: github_org(str)",
    "gitleaks": "Git 커밋 히스토리 시크릿 탐지. args: source_path(str)",
    # Web App Exploitation
    "ffuf": "디렉토리/파일/파라미터 brute-force. args: url(str), wordlist(str)",
    "sqlmap": "SQL 인젝션 자동 탐지 + 익스플로잇. args: url(str)",
    # Code
    "semgrep": "SAST 정적 코드 분석 (OWASP Top 10). args: source_path(str)",
    "bandit": "Python 보안 정적 분석. args: source_path(str)",
    "checkov": "IaC 보안 점검 (Terraform, K8s, Docker). args: source_path(str)",
    "trivy": "의존성 취약점 + 시크릿 + IaC 스캔. args: source_path(str)",
    # Cloud
    "prowler": "AWS/Azure/GCP 보안 감사. args: provider(str)",
    "s3scanner": "S3 버킷 권한 스캔. args: domain(str)",
    # Special
    "DONE": "테스트 완료 — 충분한 커버리지를 달성했을 때 사용",
}


# ── Brain class ─────────────────────────────────────────────────

class AgentBrain:
    """AI decision engine for autonomous pentesting.

    Usage:
        brain = AgentBrain(max_steps=20)
        while not brain.is_done:
            observation = collect_observations()
            actions = brain.think(observation)
            for action in actions:
                result = execute_tool(action)
                brain.record_result(action, result)
    """

    def __init__(
        self,
        max_steps: int = 20,
        provider: str | None = None,
        model: str | None = None,
        memory: "AgentMemory | None" = None,
        knowledge_store: "KnowledgeStore | None" = None,
        compressor: "ContextCompressor | None" = None,
        token_router: "TokenRouter | None" = None,
        chain_reasoner: "ChainReasoner | None" = None,
    ) -> None:
        self.max_steps = max_steps
        self.steps: list[AgentStep] = []
        self.is_done = False
        self._provider = provider or os.environ.get("UPSTREAM_LLM_PROVIDER", "together")
        self._model = model or os.environ.get("UPSTREAM_LLM_MODEL", "")
        self._step_count = 0
        self._memory = memory
        # Phase 3 모듈
        self._knowledge_store = knowledge_store
        self._compressor = compressor
        self._token_router = token_router
        self._chain_reasoner = chain_reasoner
        self._reflection_interval = 5  # 매 N스텝마다 자기 평가
        self._consecutive_no_findings = 0  # 연속 발견 없는 스텝 수
        # LLM Fallback 체인 (정책 거부 대응)
        self._fallback_providers = self._build_fallback_chain()

    def _build_fallback_chain(self) -> list[dict[str, str]]:
        """LLM Fallback 체인을 구성한다.

        정책 거부 시 순차적으로 다음 모델로 전환.

        전략:
        - Tier 1: Anthropic (추론 최강, 하지만 보안 정책 엄격)
        - Tier 2: Together.ai 통합 게이트웨이 (중국 모델 포함, 정책 느슨)
          → Kimi K2.5 (1T, 추론 특화)
          → GLM-5 (744B, 에이전트 특화)
          → GLM-4.7 (202K 컨텍스트)
          → DeepSeek-V3.1 (671B, 코드/분석 강력)
          → DeepSeek-R1 (추론 체인)
          → Qwen3-235B (빠른 응답)
          → OpenAI GPT-OSS-120B (저렴한 범용)
          → Llama-3.3-70B (오픈소스 최강)

        Together.ai 하나로 거의 모든 모델을 커버.
        별도 API 키 없이 중국 모델까지 사용 가능.
        """
        chain: list[dict[str, str]] = []

        # Tier 1: Anthropic (기본 Brain — 추론/전략 최강)
        if os.environ.get("ANTHROPIC_API_KEY"):
            chain.append({"provider": "anthropic", "model": "claude-opus-4-6"})
            chain.append({"provider": "anthropic", "model": "claude-sonnet-4-6"})
            chain.append({"provider": "anthropic", "model": "claude-haiku-4-5-20251001"})

        # Tier 2: Together.ai 통합 게이트웨이 (중국 모델 전부 여기서 사용)
        # → API 키 하나로 Kimi, GLM, DeepSeek, Qwen, Llama 전부 접근
        if os.environ.get("TOGETHER_API_KEY"):
            # 추론 특화 (Opus 대체 후보)
            chain.append({"provider": "together", "model": "moonshotai/Kimi-K2.5"})
            # 에이전트 특화 (도구 사용, function calling)
            chain.append({"provider": "together", "model": "zai-org/GLM-5"})
            # 긴 컨텍스트 (202K)
            chain.append({"provider": "together", "model": "zai-org/GLM-4.7"})
            # 코드/분석 강력 (보안 정책 느슨)
            chain.append({"provider": "together", "model": "deepseek-ai/DeepSeek-V3.1"})
            # 추론 체인 (단계별 사고)
            chain.append({"provider": "together", "model": "deepseek-ai/DeepSeek-R1"})
            # 빠른 범용
            chain.append({"provider": "together", "model": "Qwen/Qwen3-235B-A22B"})
            # 저렴한 범용 ($0.15/M)
            chain.append({"provider": "together", "model": "openai/gpt-oss-120b"})
            # 오픈소스 최강
            chain.append({"provider": "together", "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo"})

        # Tier 3: OpenAI 직접 (Together에 없는 경우 대비)
        if os.environ.get("OPENAI_API_KEY"):
            chain.append({"provider": "openai", "model": "gpt-4o"})
            chain.append({"provider": "openai", "model": "gpt-4o-mini"})

        # Tier 4: Google Gemini 직접
        if os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"):
            chain.append({"provider": "gemini", "model": "gemini-2.5-pro"})
            chain.append({"provider": "gemini", "model": "gemini-2.5-flash"})

        return chain

    def think(self, observation: AgentObservation) -> list[AgentAction]:
        """Phase 3 인지 루프: Perceive → Recall → Reason → Chain → Reflect → Act.

        기존 think()를 대체하며, 컴파일된 패턴이 있으면 LLM 호출을 건너뛴다.
        """
        if self.is_done or self._step_count >= self.max_steps:
            self.is_done = True
            return []

        self._step_count += 1

        # ── Step 1: RECALL — 컴파일된 패턴 매칭 (LLM 호출 없이) ──
        compiled_actions = self._try_compiled_patterns(observation)
        if compiled_actions:
            logger.info(
                "Step %d: 컴파일 패턴 매칭 — LLM 호출 생략 (%s)",
                self._step_count,
                ", ".join(a.tool for a in compiled_actions),
            )
            self._record_step(observation, compiled_actions)
            return compiled_actions

        # ── Step 2: REFLECT — 전략 전환 필요 여부 (매 N스텝) ──
        if self._step_count % self._reflection_interval == 0:
            self._reflect(observation)

        # ── Step 3: REASON — LLM 호출 (Token Router 사용) ──
        tools_text = "\n".join(
            f"  - {name}: {desc}" for name, desc in TOOL_DESCRIPTIONS.items()
        )
        system = AGENT_SYSTEM_PROMPT.format(available_tools=tools_text)

        # Knowledge Store + Memory + Chain Reasoner 컨텍스트 통합
        enriched_context = self._build_enriched_context(observation)
        user_prompt = self._build_observation_prompt(observation, enriched_context)

        # LLM 호출 (Fallback 체인 적용)
        response = self._call_llm_with_fallback(system, user_prompt)
        if response is None:
            logger.warning("모든 LLM 호출 실패 at step %d", self._step_count)
            self.is_done = True
            return []

        actions = self._parse_response(response)

        # ── Step 4: CHAIN — 공격 체인 추론 결과로 추가 액션 ──
        chain_actions = self._get_chain_driven_actions()
        if chain_actions:
            actions.extend(chain_actions)

        # Check for DONE
        if any(a.tool == "DONE" for a in actions):
            self.is_done = True
            actions = [a for a in actions if a.tool == "DONE"]

        self._record_step(observation, actions)

        logger.info(
            "Step %d: %d action(s) — %s",
            self._step_count,
            len(actions),
            ", ".join(a.tool for a in actions),
        )

        return actions

    def record_result(self, action: AgentAction, result: dict[str, Any]) -> None:
        """결과 기록 + Knowledge Store 학습 + Chain Reasoner 업데이트."""
        if self.steps:
            self.steps[-1].results.append({
                "tool": action.tool,
                "result_summary": str(result.get("summary", ""))[:500],
                "findings_count": result.get("findings_count", 0),
                "success": result.get("success", True),
            })

        # 연속 발견 없음 추적
        if result.get("findings_count", 0) > 0:
            self._consecutive_no_findings = 0
        else:
            self._consecutive_no_findings += 1

        # ── Knowledge Store 학습 ──
        self._learn_from_result(action, result)

    # ── Phase 3: Compiled Pattern Matching ───────────────────────

    def _try_compiled_patterns(
        self, observation: AgentObservation,
    ) -> list[AgentAction]:
        """Knowledge Store에서 컴파일된 패턴을 매칭하여 LLM 없이 판단."""
        if self._knowledge_store is None:
            return []

        try:
            from vxis.knowledge.store import KnowledgeStore

            context_sig = KnowledgeStore.build_context_signature(
                tech_stack=observation.tech_stack,
                open_ports=[
                    p.get("port", 0) for p in observation.open_ports
                    if isinstance(p.get("port"), int)
                ],
            )

            patterns = self._knowledge_store.match_patterns(context_sig)

            # 이미 실행한 도구는 제외
            executed = {t.get("tool") for t in observation.executed_tools}

            actions = []
            for pattern in patterns:
                if (
                    pattern.confidence >= 0.85
                    and pattern.action_tool not in executed
                ):
                    actions.append(AgentAction(
                        tool=pattern.action_tool,
                        args=pattern.action_args,
                        reasoning=f"[컴파일 패턴] {pattern.reasoning}",
                        priority="high",
                    ))

            return actions[:3]  # 최대 3개
        except Exception as exc:
            logger.debug("컴파일 패턴 매칭 실패 (무시): %s", exc)
            return []

    # ── Phase 3: Reflection ──────────────────────────────────────

    def _reflect(self, observation: AgentObservation) -> None:
        """자기 평가: 전략 전환이 필요한지 판단한다."""
        # 5스텝 연속 발견 없으면 전략 전환 시그널
        if self._consecutive_no_findings >= 4:
            logger.info(
                "반성: %d스텝 연속 발견 없음 — 전략 전환 필요",
                self._consecutive_no_findings,
            )
            # 남은 스텝이 적으면 종료
            remaining = self.max_steps - self._step_count
            if remaining <= 2:
                self.is_done = True

    # ── Phase 3: Enriched Context ────────────────────────────────

    def _build_enriched_context(self, observation: AgentObservation) -> str:
        """모든 Phase 3 모듈의 컨텍스트를 통합하여 LLM 프롬프트를 풍부하게 만든다."""
        parts: list[str] = []

        # 1. 기존 Memory 컨텍스트
        memory_ctx = self._build_memory_context(
            observation.target, observation.tech_stack
        )
        if memory_ctx:
            parts.append(memory_ctx)

        # 2. Knowledge Store 컨텍스트 (컴파일된 지식, 추천 도구, 상관관계)
        if self._knowledge_store is not None:
            try:
                from vxis.knowledge.store import KnowledgeStore

                context_sig = KnowledgeStore.build_context_signature(
                    tech_stack=observation.tech_stack,
                    open_ports=[
                        p.get("port", 0) for p in observation.open_ports
                        if isinstance(p.get("port"), int)
                    ],
                )
                ks_ctx = self._knowledge_store.format_for_brain(
                    context_sig, observation.tech_stack
                )
                if ks_ctx:
                    parts.append(ks_ctx)
            except Exception as exc:
                logger.debug("Knowledge Store 컨텍스트 실패 (무시): %s", exc)

        # 3. Chain Reasoner 컨텍스트 (발견된 체인, 완성 가능 체인)
        if self._chain_reasoner is not None:
            try:
                chain_ctx = self._chain_reasoner.format_chains_for_brain()
                if chain_ctx:
                    parts.append(chain_ctx)
            except Exception as exc:
                logger.debug("Chain Reasoner 컨텍스트 실패 (무시): %s", exc)

        # 4. 반성 컨텍스트
        if self._consecutive_no_findings >= 3:
            parts.append(
                f"\n## 주의: {self._consecutive_no_findings}스텝 연속 발견 없음"
                "\n다른 공격 벡터나 도구로 전략을 전환하세요."
            )

        return "\n\n".join(parts)

    # ── Phase 3: Chain-driven Actions ────────────────────────────

    def _get_chain_driven_actions(self) -> list[AgentAction]:
        """Chain Reasoner의 가설에서 추가 액션을 생성한다."""
        if self._chain_reasoner is None:
            return []

        try:
            hypotheses = self._chain_reasoner.get_chain_hypotheses()
            actions = []
            for h in hypotheses[:2]:  # 최대 2개
                # 체인 완성을 위한 탐색 도구 매핑
                vuln_to_tool = {
                    "ssrf": "nuclei",
                    "sqli": "sqlmap",
                    "info_disclosure": "ffuf",
                    "redis_noauth": "nmap",
                    "mongodb_noauth": "nmap",
                    "cloud_metadata": "nuclei",
                    "xss": "nuclei",
                    "secret_exposure": "trufflehog",
                }
                tool = vuln_to_tool.get(
                    h.get("missing_vuln_type", ""),
                    "nuclei",
                )
                actions.append(AgentAction(
                    tool=tool,
                    args={},
                    reasoning=f"[체인 추론] {h['rationale']}",
                    priority="high",
                ))
            return actions
        except Exception as exc:
            logger.debug("체인 기반 액션 생성 실패 (무시): %s", exc)
            return []

    # ── Phase 3: Learning from Results ───────────────────────────

    def _learn_from_result(
        self, action: AgentAction, result: dict[str, Any],
    ) -> None:
        """실행 결과를 Knowledge Store에 축적한다."""
        if self._knowledge_store is None:
            return

        try:
            from vxis.knowledge.store import ExecutionRecord, KnowledgeStore

            # 현재 관찰에서 tech_stack 가져오기
            tech_stack = (
                self.steps[-1].observation_summary
                if self.steps
                else ""
            )

            findings_count = result.get("findings_count", 0)
            effectiveness = min(1.0, findings_count * 0.3) if findings_count > 0 else 0.0

            record = ExecutionRecord(
                tool=action.tool,
                context_signature="",  # Executor에서 설정
                args_summary=json.dumps(action.args, ensure_ascii=False)[:100],
                effectiveness=effectiveness,
                findings_produced=findings_count,
                finding_types=[],  # Executor에서 설정
                target_tech=[],  # Executor에서 설정
            )
            self._knowledge_store.record_execution(record)
        except Exception as exc:
            logger.debug("Knowledge Store 학습 실패 (무시): %s", exc)

    # ── Phase 3: LLM Fallback Chain ──────────────────────────────

    def _call_llm_with_fallback(
        self, system_prompt: str, user_prompt: str,
    ) -> str | None:
        """Fallback 체인을 사용하여 LLM 호출.

        정책 거부(refusal) 시 다음 모델로 자동 전환.
        """
        # 먼저 기본 모델 시도
        response = self._call_llm(system_prompt, user_prompt)
        if response and not self._is_refusal(response):
            return response

        if response and self._is_refusal(response):
            logger.warning(
                "LLM 정책 거부 감지 (provider=%s) — fallback 시도",
                self._provider,
            )

        # Fallback 체인 순회
        for fallback in self._fallback_providers:
            if (
                fallback["provider"] == self._provider
                and fallback["model"] == self._model
            ):
                continue  # 이미 시도한 모델 스킵

            logger.info(
                "Fallback: %s/%s 시도",
                fallback["provider"], fallback["model"],
            )

            response = self._call_llm_direct(
                system_prompt, user_prompt,
                provider=fallback["provider"],
                model=fallback["model"],
            )

            if response and not self._is_refusal(response):
                logger.info(
                    "Fallback 성공: %s/%s",
                    fallback["provider"], fallback["model"],
                )
                return response

            if response and self._is_refusal(response):
                logger.warning(
                    "Fallback도 거부: %s/%s — 다음 시도",
                    fallback["provider"], fallback["model"],
                )

        logger.error("모든 LLM fallback 실패")
        return None

    @staticmethod
    def _is_refusal(response: str) -> bool:
        """LLM 응답이 정책 거부인지 판단."""
        refusal_patterns = [
            "I cannot assist",
            "I can't help with",
            "I'm not able to",
            "I must decline",
            "against my guidelines",
            "unable to provide",
            "ethical guidelines",
            "I apologize, but I cannot",
            "도움을 드릴 수 없",
            "지원할 수 없",
            "보안 정책",
        ]
        response_lower = response.lower()
        return any(pattern.lower() in response_lower for pattern in refusal_patterns)

    def _call_llm_direct(
        self,
        system_prompt: str,
        user_prompt: str,
        provider: str = "",
        model: str = "",
    ) -> str | None:
        """특정 provider/model을 지정하여 LLM 호출."""
        provider = provider or self._provider
        model = model or self._model

        if provider == "anthropic":
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if api_key:
                return self._call_anthropic(api_key, system_prompt, user_prompt)
        elif provider == "gemini":
            return self._call_gemini(system_prompt, user_prompt, model)
        elif provider == "deepseek":
            return self._call_deepseek(system_prompt, user_prompt, model)
        elif provider in ("together", "openai"):
            return self._call_openai_compatible(
                system_prompt, user_prompt, provider, model
            )

        return None

    def _call_openai_compatible(
        self,
        system: str,
        user: str,
        provider: str,
        model: str,
    ) -> str | None:
        """OpenAI 호환 API 호출 (Together, OpenAI)."""
        urls = {
            "together": "https://api.together.xyz/v1/chat/completions",
            "openai": "https://api.openai.com/v1/chat/completions",
        }
        keys = {
            "together": os.environ.get("TOGETHER_API_KEY", ""),
            "openai": os.environ.get("OPENAI_API_KEY", ""),
        }

        url = urls.get(provider)
        api_key = keys.get(provider)
        if not url or not api_key:
            return None

        payload = json.dumps({
            "model": model,
            "max_tokens": 2000,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }).encode("utf-8")

        req = urllib.request.Request(
            url, data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "VXIS-Agent/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.warning("LLM call failed (%s/%s): %s", provider, model, exc)
            return None

    def _call_gemini(
        self, system: str, user: str, model: str = "",
    ) -> str | None:
        """Google Gemini API 호출."""
        api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            return None

        model = model or "gemini-2.5-pro"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

        payload = json.dumps({
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": user}]}],
            "generationConfig": {"maxOutputTokens": 2000},
        }).encode("utf-8")

        req = urllib.request.Request(
            url, data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "VXIS-Agent/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as exc:
            logger.warning("Gemini call failed (%s): %s", model, exc)
            return None

    def _call_deepseek(
        self, system: str, user: str, model: str = "",
    ) -> str | None:
        """DeepSeek API 호출."""
        api_key = os.environ.get("DEEPSEEK_API_KEY", "")
        if not api_key:
            return None

        model = model or "deepseek-chat"
        payload = json.dumps({
            "model": model,
            "max_tokens": 2000,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.deepseek.com/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "VXIS-Agent/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.warning("DeepSeek call failed (%s): %s", model, exc)
            return None

    def _record_step(
        self, observation: AgentObservation, actions: list[AgentAction],
    ) -> None:
        """스텝을 기록한다."""
        step = AgentStep(
            step_number=self._step_count,
            observation_summary=f"Findings: {len(observation.findings)}, "
            f"Ports: {len(observation.open_ports)}, "
            f"Tools run: {len(observation.executed_tools)}",
            actions=actions,
        )
        self.steps.append(step)

    def get_execution_log(self) -> str:
        """Get a formatted log of all steps for reporting."""
        lines = ["## AI Agent Execution Log\n"]
        for step in self.steps:
            lines.append(f"### Step {step.step_number} ({step.timestamp})")
            lines.append(f"**상태:** {step.observation_summary}")
            for action in step.actions:
                lines.append(f"- **{action.tool}**: {action.reasoning}")
            if step.results:
                for r in step.results:
                    status = "✓" if r["success"] else "✗"
                    lines.append(
                        f"  {status} {r['tool']}: {r['result_summary'][:100]}"
                    )
            lines.append("")
        return "\n".join(lines)

    # ── Internal methods ────────────────────────────────────────

    def _build_memory_context(self, target: str, tech_stack: list[str]) -> str:
        """과거 스캔 경험을 LLM 프롬프트 컨텍스트로 변환한다.

        AgentMemory가 주입되지 않았거나, 관련 기억이 없으면 빈 문자열을 반환한다.

        Args:
            target: 현재 스캔 타겟 (도메인 또는 IP).
            tech_stack: 현재까지 탐지된 기술 스택.

        Returns:
            포맷된 메모리 컨텍스트 문자열, 또는 빈 문자열.
        """
        if self._memory is None:
            return ""

        try:
            from vxis.agent.memory import format_memory_context

            similar = self._memory.recall_similar(target, tech_stack)
            if not similar:
                return ""

            context = format_memory_context(similar)
            logger.debug(
                "메모리 컨텍스트 로드: 유사 스캔 %d개 (타겟: %s)", len(similar), target
            )
            return context
        except Exception as exc:
            # 메모리 오류가 핵심 스캔 흐름을 방해하지 않도록 방어 처리
            logger.warning("메모리 컨텍스트 로드 실패 (무시): %s", exc)
            return ""

    def _build_observation_prompt(
        self,
        obs: AgentObservation,
        memory_context: str = "",
    ) -> str:
        """Format observations into a prompt for the LLM."""
        sections = [
            f"## 현재 스캔 상태 (Step {self._step_count}/{self.max_steps})\n",
            f"**타겟:** {obs.target}",
        ]

        if obs.tech_stack:
            sections.append(f"**기술 스택:** {', '.join(obs.tech_stack)}")

        if obs.subdomains:
            sections.append(f"**서브도메인:** {len(obs.subdomains)}개 발견")
            for s in obs.subdomains[:10]:
                sections.append(f"  - {s}")
            if len(obs.subdomains) > 10:
                sections.append(f"  ... +{len(obs.subdomains) - 10}개 더")

        if obs.open_ports:
            sections.append(f"\n**열린 포트:** {len(obs.open_ports)}개")
            for p in obs.open_ports[:20]:
                sections.append(
                    f"  - {p.get('port')}/{p.get('protocol', 'tcp')} "
                    f"— {p.get('service', 'unknown')} {p.get('product', '')}"
                )

        if obs.live_urls:
            sections.append(f"\n**라이브 URL:** {len(obs.live_urls)}개")
            for u in obs.live_urls[:10]:
                sections.append(f"  - {u}")

        if obs.findings:
            sections.append(f"\n**발견된 취약점:** {len(obs.findings)}개")
            for f in obs.findings[:15]:
                sections.append(
                    f"  - [{f.get('severity', '?')}] {f.get('title', 'unknown')}"
                )

        if obs.executed_tools:
            sections.append(f"\n**실행 완료된 도구:** {len(obs.executed_tools)}개")
            for t in obs.executed_tools:
                sections.append(
                    f"  - {t.get('tool')}: {t.get('state', '?')} "
                    f"({t.get('findings', 0)}건 발견)"
                )

        # 과거 스캔 경험 컨텍스트 삽입 (있을 때만)
        if memory_context:
            sections.append(f"\n{memory_context}")

        sections.append("\n---\n위 정보를 바탕으로, 다음에 실행할 도구를 JSON으로 결정하세요.")

        return "\n".join(sections)

    def _parse_response(self, text: str) -> list[AgentAction]:
        """Parse LLM response into AgentAction list."""
        # Extract JSON from response
        json_str = text
        if "```json" in json_str:
            json_str = json_str.split("```json")[1].split("```")[0]
        elif "```" in json_str:
            json_str = json_str.split("```")[1].split("```")[0]

        try:
            data = json.loads(json_str.strip())
        except json.JSONDecodeError:
            logger.warning("Failed to parse agent response as JSON")
            return []

        actions = []
        for item in data.get("actions", []):
            actions.append(AgentAction(
                tool=item.get("tool", ""),
                args=item.get("args", {}),
                reasoning=item.get("reasoning", ""),
                priority=item.get("priority", "medium"),
            ))

        return actions

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str | None:
        """Call LLM using the same abstraction as upstream_watch."""
        try:
            from tools.upstream_watch.llm import chat
            response = chat(system_prompt=system_prompt, user_prompt=user_prompt, max_tokens=2000)
            return response.text if response else None
        except ImportError:
            pass

        # Fallback: direct urllib call
        api_key = os.environ.get("TOGETHER_API_KEY", "") or os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            return None

        provider = self._provider
        if provider == "together":
            url = "https://api.together.xyz/v1/chat/completions"
            model = self._model or "moonshotai/Kimi-K2.5"
        elif provider == "anthropic":
            # Use Anthropic format
            return self._call_anthropic(api_key, system_prompt, user_prompt)
        else:
            url = "https://api.openai.com/v1/chat/completions"
            model = self._model or "gpt-4o-mini"

        payload = json.dumps({
            "model": model,
            "max_tokens": 2000,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }).encode("utf-8")

        req = urllib.request.Request(
            url, data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "VXIS-Agent/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.warning("Agent LLM call failed: %s", exc)
            return None

    def _call_anthropic(self, api_key: str, system: str, user: str) -> str | None:
        """Anthropic-specific call."""
        model = self._model or "claude-sonnet-4-20250514"
        payload = json.dumps({
            "model": model,
            "max_tokens": 2000,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "User-Agent": "VXIS-Agent/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data["content"][0]["text"]
        except Exception as exc:
            logger.warning("Anthropic agent call failed: %s", exc)
            return None
