"""Multi-source signal ingestion|||다중 소스 시그널 수집."""

from __future__ import annotations

import dataclasses as dc
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from vxis.growth.schemas import RawSignal, SignalSource
from vxis.growth.trust import TrustRegistry

INBOX_DIR = Path(".vxis/signals/inbox")


def _signal_id(content: str) -> str:
    """Short SHA256 id|||짧은 SHA256 해시."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def ingest_cve_watch_results() -> list[RawSignal]:
    """Ingest cve-watch candidates|||CVE Watch 결과 수집."""
    cve_file = Path("tools/cve_watch/growth_loop_candidates.json")
    if not cve_file.exists():
        return []
    try:
        data = json.loads(cve_file.read_text(encoding="utf-8"))
    except Exception:
        return []

    signals: list[RawSignal] = []
    trust = TrustRegistry()
    for item in data.get("candidates", []):
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cve_id", "")
        if not cve_id:
            continue
        description = item.get("description", "")
        content = f"{cve_id}: {description}"
        signals.append(
            RawSignal(
                signal_id=_signal_id(content),
                source=SignalSource(
                    name="cve_watch",
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    source_type="api",
                    trust_score=trust.get("nvd"),
                ),
                timestamp=datetime.now(timezone.utc).isoformat(),
                title=cve_id,
                body=description,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                metadata=item,
            )
        )
    return signals


def ingest_threat_news() -> list[RawSignal]:
    """Ingest ThreatNewsWatcher alerts|||위협 뉴스 수집."""
    try:
        import asyncio

        from vxis.watchers.threat_news import ThreatNewsWatcher

        watcher = ThreatNewsWatcher()
        loop = asyncio.new_event_loop()
        try:
            alerts = loop.run_until_complete(watcher.fetch())
        finally:
            loop.close()
    except Exception:
        return []

    signals: list[RawSignal] = []
    trust = TrustRegistry()
    for alert in alerts or []:
        if not isinstance(alert, dict):
            continue
        source_name = alert.get("source", "unknown")
        title = alert.get("title", "") or ""
        body = alert.get("body", "") or ""
        content = f"{title}\n{body}"
        signals.append(
            RawSignal(
                signal_id=_signal_id(content),
                source=SignalSource(
                    name=source_name,
                    url=alert.get("link", "") or "",
                    source_type="rss",
                    trust_score=trust.get(source_name),
                ),
                timestamp=alert.get("pub_date")
                or datetime.now(timezone.utc).isoformat(),
                title=title[:200],
                body=body[:5000],
                url=alert.get("link", "") or "",
                metadata=alert,
            )
        )
    return signals


def ingest_upstream_watch() -> list[RawSignal]:
    """Ingest latest upstream-watch digest|||Upstream Watch 다이제스트 수집."""
    digest_dir = Path("tools/upstream_watch/digests")
    if not digest_dir.exists():
        return []
    digests = sorted(digest_dir.glob("*.md"), reverse=True)
    if not digests:
        return []
    latest = digests[0]
    try:
        content = latest.read_text(encoding="utf-8")
    except Exception:
        return []

    trust = TrustRegistry()
    return [
        RawSignal(
            signal_id=_signal_id(content[:500]),
            source=SignalSource(
                name="upstream_watch",
                url="",
                source_type="rss",
                trust_score=trust.get("github_advisory"),
            ),
            timestamp=datetime.now(timezone.utc).isoformat(),
            title=f"Upstream Watch Digest {latest.stem}",
            body=content[:5000],
            url="",
            metadata={"digest_file": str(latest)},
        )
    ]


def ingest_all() -> int:
    """Ingest from all sources into inbox JSONL|||모든 소스를 inbox에 기록."""
    INBOX_DIR.mkdir(parents=True, exist_ok=True)

    all_signals: list[RawSignal] = []
    all_signals.extend(ingest_cve_watch_results())
    all_signals.extend(ingest_threat_news())
    all_signals.extend(ingest_upstream_watch())

    seen_ids: set[str] = set()
    unique: list[RawSignal] = []
    for sig in all_signals:
        if sig.signal_id not in seen_ids:
            seen_ids.add(sig.signal_id)
            unique.append(sig)

    now = datetime.now(timezone.utc)
    filename = f"ingest-{now.strftime('%Y-%m-%dT%H')}.jsonl"
    out_path = INBOX_DIR / filename

    with out_path.open("a", encoding="utf-8") as f:
        for sig in unique:
            f.write(json.dumps(dc.asdict(sig), ensure_ascii=False) + "\n")

    return len(unique)
