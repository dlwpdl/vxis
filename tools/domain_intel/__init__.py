"""VXIS Domain Intelligence Engine — 보안 세계의 강을 지켜본다.

레포가 아닌 도메인(분야) 전체를 감시:
- GitHub Pulse: 새 보안 도구 출현, 트렌딩 레포
- Research Pulse: arXiv 보안 논문
- Community Pulse: HackerNews, Reddit 보안 토론
- CVE Pulse: CVE 패턴 트렌드 분석
- Package Pulse: npm/PyPI 보안 패키지 변동
- CISA KEV: 실제 공격 확인된 취약점

전부 무료 API. 외부 패키지 설치 제로 (urllib/json stdlib만).

Usage:
    python -m tools.domain_intel                    # 전체 수집 + 분석
    python -m tools.domain_intel --collect-only     # 수집만 (LLM 없이)
    python -m tools.domain_intel --analyze-only     # 기존 데이터로 분석만
"""
