"""Extraction result cache|||추출 결과 캐시."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

CACHE_DIR = Path(".vxis/cache/extractions")


class ExtractionCache:
    """SHA256-keyed extraction cache|||SHA256 기반 추출 캐시."""

    def __init__(self, ttl_days: int = 30) -> None:
        self.ttl_days = ttl_days
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, signal_id: str) -> Path:
        return CACHE_DIR / f"{signal_id}.json"

    def get(self, signal_id: str) -> dict | None:
        """Return cached extraction or None|||캐시된 추출 반환."""
        path = self._cache_path(signal_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            cached_at = datetime.fromisoformat(data.get("cached_at", ""))
            if datetime.now(timezone.utc) - cached_at > timedelta(
                days=self.ttl_days
            ):
                return None
            extraction = data.get("extraction")
            return extraction if isinstance(extraction, dict) else None
        except Exception:
            return None

    def set(self, signal_id: str, extraction: dict) -> None:
        """Store extraction in cache|||캐시에 추출 저장."""
        path = self._cache_path(signal_id)
        data = {
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "extraction": extraction,
        }
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def clear_expired(self) -> int:
        """Remove expired entries|||만료된 항목 제거."""
        removed = 0
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.ttl_days)
        for path in CACHE_DIR.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                cached_at = datetime.fromisoformat(data.get("cached_at", ""))
                if cached_at < cutoff:
                    path.unlink()
                    removed += 1
            except Exception:
                continue
        return removed
