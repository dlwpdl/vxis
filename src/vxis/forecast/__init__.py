"""Phase 14: 시간적 취약점 예측 — 향후 90일 내 취약점 발생 확률 예측.

"Next.js 14.x에서 90일 내 critical CVE 확률: 73%"
근거: 과거 CVE 발행 주기, 현재 코드 변경 속도, 유사 프레임워크 패턴
"""

from .predictor import VulnerabilityForecaster, Forecast

__all__ = ["VulnerabilityForecaster", "Forecast"]
