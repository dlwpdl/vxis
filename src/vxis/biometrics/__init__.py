"""Phase 13: 행동 생체인식 분석 — GitHub/LinkedIn OSINT로 인간 행동 패턴 공격 표면.

직원 A가 매일 9시에 GitHub push → 9시에 피싱 이메일 보내면 열 확률 높음
직원 B의 LinkedIn에 "AWS 관리자" → B의 계정이 클라우드 공격 표면
"""

from .analyzer import BehavioralAnalyzer, GitHubProfile, SocialFootprint, HighValueTarget

__all__ = ["BehavioralAnalyzer", "GitHubProfile", "SocialFootprint", "HighValueTarget"]
