"""GhostLayer 트리거 파싱 유틸."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vxis.mission.config import MissionConfig

_GHOST_SCHEME = "ghost://"

_GHOST_KEYWORDS = re.compile(
    r"ghost|stealth|anon(ymous|ymize)?|익명|스텔스|고스트",
    re.IGNORECASE,
)


def parse_ghost_trigger(
    target: str,
    config: "MissionConfig | None" = None,
) -> tuple[bool, str]:
    """Ghost 트리거 여부와 정규화된 URL 반환.

    Returns:
        (activated, clean_target)
    """
    activated = False
    clean = target

    # Trigger 1: ghost:// URL prefix
    if target.startswith(_GHOST_SCHEME):
        activated = True
        clean = "https://" + target[len(_GHOST_SCHEME):]

    # Trigger 2: MissionConfig.stealth
    if config is not None and getattr(config, "stealth", False):
        activated = True

    return activated, clean


def detect_ghost_keyword(text: str) -> bool:
    """텍스트에 ghost 트리거 키워드가 있으면 True."""
    return bool(_GHOST_KEYWORDS.search(text))
