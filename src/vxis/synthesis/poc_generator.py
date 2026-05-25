"""PoC Generator — 합성된 공격 체인의 Proof-of-Concept 자동 생성.

LLM에게 합성된 체인을 설명하고, 실행 가능한 PoC 스크립트/단계를 생성한다.
"""

from __future__ import annotations

import logging

from .cross_protocol import SynthesizedChain

logger = logging.getLogger(__name__)


async def generate_poc(chain: SynthesizedChain) -> str:
    """합성된 체인에 대한 PoC 텍스트를 생성한다.

    Returns:
        PoC 단계별 설명 텍스트 (마크다운).
    """
    # Build context from chain
    steps = []
    for i, finding in enumerate(chain.findings, 1):
        steps.append(
            f"  {i}. [{finding.severity.value}] {finding.title}\n"
            f"     에이전트: {finding.agent_id}\n"
            f"     설명: {finding.description[:200]}"
        )

    prompt = f"""\
다음 크로스-레이어 공격 체인에 대한 **Proof-of-Concept 실행 단계**를 작성하라.

체인: {chain.title}
심각도: {chain.severity.value.upper()}
레이어: {" → ".join(layer.value for layer in chain.layers_crossed)}
Kill Chain: {" → ".join(chain.kill_chain_stages)}

구성 취약점:
{chr(10).join(steps)}

에스컬레이션 이유: {chain.escalation_reason}

요구사항:
1. 각 단계를 **구체적인 명령어/요청**으로 작성 (curl, nmap, python 스니펫 등)
2. 단계 간 **연결 고리**를 명확히 설명 (이전 단계의 어떤 출력이 다음 단계의 입력이 되는지)
3. **검증 방법** 포함 (이 PoC가 성공했는지 확인하는 방법)
4. **면책 조항** 포함 (인가된 테스트에서만 사용)
5. 한국어로 작성

형식:
## PoC: [체인 제목]

### 전제 조건
- ...

### 단계 1: [단계명]
```bash
[명령어]
```
**예상 결과:** ...
**다음 단계 입력:** ...

### 단계 N: ...

### 검증
...

### 영향도
...
"""

    try:
        from vxis.llm.client import LLMClient

        client = LLMClient()
        response = await client.think(
            system=(
                "당신은 시니어 레드팀 컨설턴트입니다. "
                "합성된 공격 체인의 PoC를 작성합니다. "
                "구체적이고 실행 가능한 단계를 제시하되, "
                "반드시 인가된 펜테스트 범위 내에서만 사용하도록 명시합니다."
            ),
            user=prompt,
            max_tokens=3000,
        )
        return response.text
    except Exception as exc:
        logger.warning("PoC 생성 실패: %s", exc)
        # Fallback: 기본 PoC 텍스트
        return _basic_poc(chain)


def _basic_poc(chain: SynthesizedChain) -> str:
    """LLM 없이 기본 PoC 텍스트 생성."""
    lines = [
        f"## PoC: {chain.title}",
        f"**심각도:** {chain.severity.value.upper()}",
        f"**레이어:** {' → '.join(layer.value for layer in chain.layers_crossed)}",
        "",
        "### 공격 단계",
        "",
    ]

    for i, finding in enumerate(chain.findings, 1):
        lines.append(f"**단계 {i}: {finding.title}**")
        lines.append(f"- 에이전트: {finding.agent_id}")
        lines.append(f"- 심각도: {finding.severity.value}")
        lines.append(f"- 설명: {finding.description[:300]}")
        if finding.request:
            lines.append(f"- 요청:\n```\n{finding.request[:500]}\n```")
        lines.append("")

    lines.append("### 에스컬레이션")
    lines.append(chain.escalation_reason or "체인 연결로 인한 severity 상승")
    lines.append("")
    lines.append("---")
    lines.append("*이 PoC는 인가된 펜테스트 범위 내에서만 사용하세요.*")

    return "\n".join(lines)
