"""Phase 12: 자기 진화 에이전트 합성 — 미션에서 부족했던 능력을 자동으로 생성.

미션 후: "IoT 프로토콜 에이전트가 없어서 MQTT 취약점을 놓쳤다"
→ LLM이 새 에이전트 코드를 자동 생성
→ 다음 미션에 자동 포함
"""

from .agent_synthesizer import AgentSynthesizer, SynthesisProposal

__all__ = ["AgentSynthesizer", "SynthesisProposal"]
