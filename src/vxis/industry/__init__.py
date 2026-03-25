"""VXIS Industry — 산업 전체 자율 스캔 시스템.

Phase 16: 도메인 목록 없이도 기업을 자동 발굴하고
          산업 전체를 일괄 스캔하여 리스크 히트맵을 생성합니다.

Public API::

    from vxis.industry import (
        IndustryDiscovery,
        CompanyProfile,
        IndustryScanner,
        IndustryScanResult,
        generate_heatmap_report,
        generate_heatmap_html,
        OutreachQueue,
        OutreachItem,
    )
"""

from __future__ import annotations

from vxis.industry.discovery import CompanyProfile, IndustryDiscovery
from vxis.industry.heatmap import generate_heatmap_html, generate_heatmap_report
from vxis.industry.outreach import OutreachItem, OutreachQueue
from vxis.industry.scanner import IndustryScanResult, IndustryScanner

__all__ = [
    "CompanyProfile",
    "IndustryDiscovery",
    "IndustryScanner",
    "IndustryScanResult",
    "generate_heatmap_report",
    "generate_heatmap_html",
    "OutreachQueue",
    "OutreachItem",
]
