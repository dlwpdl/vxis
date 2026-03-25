"""Phase 15: 디지털 트윈 사전 시뮬레이션 — 실제 타겟 접촉 전에 가상 환경에서 공격 리허설.

1. 타겟의 기술 스택을 Docker로 재현
2. 가상 환경에서 모든 공격 시나리오 실행
3. "이 공격이 실제로 먹힐 확률" 사전 평가
4. 실제 스캔은 검증된 공격만 실행 → 소음 최소화
"""

from .simulator import DigitalTwinBuilder, TwinSimulator, DockerConfig, SimResult

__all__ = ["DigitalTwinBuilder", "TwinSimulator", "DockerConfig", "SimResult"]
