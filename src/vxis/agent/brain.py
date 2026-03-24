"""VXIS Agent Brain — AI-driven pentesting decision engine.

The Brain is the core of VXIS's autonomous pentesting mode.
It observes scan results, decides the next action, and coordinates
tool execution in an iterative loop.

Architecture:
    Observe → Think → Act → Observe → Think → Act → ... → Report

The LLM receives:
    1. Target context (domain, tech stack, open ports)
    2. Current findings (what we've found so far)
    3. Available tools (what we can run)
    4. Execution history (what we already ran)
    → Returns: next action(s) to take

Uses the same LLM provider abstraction as upstream_watch (Together.ai, Claude, etc.)
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
    ) -> None:
        self.max_steps = max_steps
        self.steps: list[AgentStep] = []
        self.is_done = False
        self._provider = provider or os.environ.get("UPSTREAM_LLM_PROVIDER", "together")
        self._model = model or os.environ.get("UPSTREAM_LLM_MODEL", "")
        self._step_count = 0
        self._memory = memory  # None이면 메모리 기능 비활성화

    def think(self, observation: AgentObservation) -> list[AgentAction]:
        """Given current observations, decide next actions via LLM."""
        if self.is_done or self._step_count >= self.max_steps:
            self.is_done = True
            return []

        self._step_count += 1

        # Build available tools description
        tools_text = "\n".join(
            f"  - {name}: {desc}" for name, desc in TOOL_DESCRIPTIONS.items()
        )

        system = AGENT_SYSTEM_PROMPT.format(available_tools=tools_text)

        # Build user prompt with current state + memory context
        memory_context = self._build_memory_context(
            observation.target, observation.tech_stack
        )
        user_prompt = self._build_observation_prompt(observation, memory_context)

        # Call LLM
        response = self._call_llm(system, user_prompt)
        if response is None:
            logger.warning("LLM call failed at step %d", self._step_count)
            self.is_done = True
            return []

        # Parse actions
        actions = self._parse_response(response)

        # Check for DONE
        if any(a.tool == "DONE" for a in actions):
            self.is_done = True
            actions = [a for a in actions if a.tool == "DONE"]

        # Record step
        step = AgentStep(
            step_number=self._step_count,
            observation_summary=f"Findings: {len(observation.findings)}, "
            f"Ports: {len(observation.open_ports)}, "
            f"Tools run: {len(observation.executed_tools)}",
            actions=actions,
        )
        self.steps.append(step)

        logger.info(
            "Step %d: %d action(s) — %s",
            self._step_count,
            len(actions),
            ", ".join(a.tool for a in actions),
        )

        return actions

    def record_result(self, action: AgentAction, result: dict[str, Any]) -> None:
        """Record the result of an executed action."""
        if self.steps:
            self.steps[-1].results.append({
                "tool": action.tool,
                "result_summary": str(result.get("summary", ""))[:500],
                "findings_count": result.get("findings_count", 0),
                "success": result.get("success", True),
            })

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
