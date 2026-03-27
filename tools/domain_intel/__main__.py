"""python -m tools.domain_intel 진입점."""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from .notify import send_telegram_report
from .signals import Signal, collect_all
from .synthesizer import format_report_markdown, synthesize

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

_DIGEST_DIR = Path(__file__).parent / "digests"
_SIGNALS_DIR = Path(__file__).parent / "signals_cache"


def _save_signals(signals: list[Signal], filename: str) -> Path:
    """시그널을 JSON으로 저장."""
    _SIGNALS_DIR.mkdir(exist_ok=True)
    path = _SIGNALS_DIR / filename
    data = [
        {
            "source": s.source,
            "category": s.category,
            "title": s.title,
            "url": s.url,
            "description": s.description[:500],
            "relevance_tags": s.relevance_tags,
            "score": s.score,
            "timestamp": s.timestamp,
            "metadata": s.metadata,
        }
        for s in signals
    ]
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _load_signals(filename: str) -> list[Signal]:
    """저장된 시그널 로드."""
    path = _SIGNALS_DIR / filename
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return [
        Signal(
            source=d["source"],
            category=d["category"],
            title=d["title"],
            url=d.get("url", ""),
            description=d.get("description", ""),
            relevance_tags=d.get("relevance_tags", []),
            score=d.get("score", 0),
            timestamp=d.get("timestamp", ""),
            metadata=d.get("metadata", {}),
        )
        for d in data
    ]


def _save_digest(content: str, filename: str) -> Path:
    """다이제스트를 마크다운으로 저장."""
    _DIGEST_DIR.mkdir(exist_ok=True)
    path = _DIGEST_DIR / filename
    path.write_text(content, encoding="utf-8")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VXIS Domain Intelligence — 보안 도메인 전체를 감시"
    )
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="시그널 수집만 (LLM 분석 없이)",
    )
    parser.add_argument(
        "--analyze-only",
        action="store_true",
        help="기존 시그널로 분석만 (수집 건너뜀)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="상세 로그",
    )

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    signals_file = f"signals-{date_str}.json"

    # ── 1. 수집 ──
    if args.analyze_only:
        print(f"[LOAD] 기존 시그널 로드: {signals_file}")
        signals = _load_signals(signals_file)
        if not signals:
            print("[ERROR] 저장된 시그널 없음. --collect-only를 먼저 실행하세요.")
            return 1
    else:
        print("[COLLECT] 보안 도메인 시그널 수집 시작...")
        signals = collect_all()
        path = _save_signals(signals, signals_file)
        print(f"[COLLECT] {len(signals)}개 시그널 수집 → {path}")

    if args.collect_only:
        _print_signal_summary(signals)
        return 0

    # ── 2. 분석 ──
    print("[ANALYZE] LLM 종합 분석 시작...")
    report = synthesize(signals)

    # ── 3. 리포트 저장 ──
    md = format_report_markdown(report)
    digest_path = _save_digest(md, f"domain-intel-{date_str}.md")
    print(f"[REPORT] 주간 리포트 → {digest_path}")

    # ── 4. 텔레그램 전송 ──
    if send_telegram_report(report):
        print("[TELEGRAM] Domain Intelligence 리포트 전송 완료")
    else:
        print("[TELEGRAM] 전송 실패 또는 미설정 (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)")

    # ── 5. 요약 출력 ──
    print(f"\n{'='*60}")
    print(f"  Domain Intelligence Report — {date_str}")
    print(f"{'='*60}")
    print(f"  시그널: {report.total_signals}개")
    print(f"  소스별: {report.raw_signal_summary}")
    print(f"  CISA KEV: {len(report.cisa_kev_alerts)}개")
    print(f"  트렌드: {len(report.trends)}개")

    if report.trends:
        print("\n  주요 트렌드:")
        for i, t in enumerate(report.trends, 1):
            icon = {"critical": "🚨", "high": "🔶", "medium": "💡", "low": "📌"}.get(t.priority, "")
            print(f"    {icon} {i}. {t.title}")
            print(f"       추천: {t.recommendation}")
    print()

    return 0


def _print_signal_summary(signals: list[Signal]) -> None:
    """시그널 요약 출력."""
    by_source: dict[str, int] = {}
    for s in signals:
        by_source[s.source] = by_source.get(s.source, 0) + 1

    print("\n  소스별 시그널:")
    for src, cnt in sorted(by_source.items()):
        print(f"    {src}: {cnt}개")

    print("\n  Top 10 시그널 (중요도순):")
    for s in signals[:10]:
        print(f"    [{s.source}] {s.title} (score: {s.score})")


if __name__ == "__main__":
    sys.exit(main())
