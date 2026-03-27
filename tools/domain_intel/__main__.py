"""python -m tools.domain_intel 진입점.

모드:
    daily   — 매일 시그널 수집 + 간단 요약 텔레그램 전송
    weekly  — 주간 LLM 종합 분석 + 트렌드 리포트
    monthly — 월간 롤업 (주간 리포트 종합)
    quarterly — 분기 롤업
    yearly  — 연간 롤업
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .notify import send_telegram_report, send_telegram_rollup
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


def _load_digests(prefix: str, days: int) -> list[str]:
    """최근 N일간의 다이제스트 파일들을 로드."""
    _DIGEST_DIR.mkdir(exist_ok=True)
    now = datetime.now(timezone.utc)
    contents: list[str] = []
    for i in range(days):
        d = now - timedelta(days=i)
        pattern = f"{prefix}-{d.strftime('%Y-%m-%d')}.md"
        path = _DIGEST_DIR / pattern
        if path.exists():
            contents.append(path.read_text(encoding="utf-8"))
    return contents


# ── 모드별 실행 함수 ──────────────────────────────────────────────


def run_daily(verbose: bool = False) -> int:
    """매일: 시그널 수집 + 간단 요약 + 텔레그램."""
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    signals_file = f"signals-{date_str}.json"

    print("[DAILY] 보안 도메인 시그널 수집 시작...")
    signals = collect_all()
    path = _save_signals(signals, signals_file)
    print(f"[DAILY] {len(signals)}개 시그널 수집 → {path}")

    # LLM 분석 (daily는 간단 요약)
    print("[DAILY] LLM 분석 시작...")
    report = synthesize(signals)

    # 리포트 저장
    md = format_report_markdown(report)
    digest_path = _save_digest(md, f"daily-{date_str}.md")
    print(f"[DAILY] 리포트 → {digest_path}")

    # 텔레그램 전송
    if send_telegram_report(report, period="daily"):
        print("[TELEGRAM] Daily 리포트 전송 완료")
    else:
        print("[TELEGRAM] 전송 실패 또는 미설정")

    _print_summary(report)
    return 0


def run_weekly(verbose: bool = False) -> int:
    """매주: 주간 종합 분석 (기존 동작)."""
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    signals_file = f"signals-{date_str}.json"

    print("[WEEKLY] 보안 도메인 시그널 수집 시작...")
    signals = collect_all()
    _save_signals(signals, signals_file)

    print("[WEEKLY] LLM 종합 분석 시작...")
    report = synthesize(signals)

    md = format_report_markdown(report)
    digest_path = _save_digest(md, f"weekly-{date_str}.md")
    print(f"[WEEKLY] 주간 리포트 → {digest_path}")

    if send_telegram_report(report, period="weekly"):
        print("[TELEGRAM] Weekly 리포트 전송 완료")
    else:
        print("[TELEGRAM] 전송 실패 또는 미설정")

    _print_summary(report)
    return 0


def run_rollup(period: str, days: int) -> int:
    """월간/분기/연간: 기존 daily 리포트들을 종합."""
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    period_kr = {"monthly": "월간", "quarterly": "분기", "yearly": "연간"}[period]

    print(f"[{period.upper()}] 최근 {days}일간 리포트 롤업 시작...")
    digests = _load_digests("daily", days)
    weekly_digests = _load_digests("weekly", days)
    all_digests = weekly_digests + digests

    if not all_digests:
        print(f"[{period.upper()}] 롤업할 리포트 없음")
        # 그래도 텔레그램은 보냄 (생존 확인)
        send_telegram_rollup(
            period=period,
            period_kr=period_kr,
            date_str=date_str,
            digest_count=0,
            summary="해당 기간 수집된 리포트가 없습니다.",
        )
        return 0

    # 롤업 마크다운 생성
    rollup_lines = [
        f"# VXIS Domain Intelligence — {period_kr} 롤업",
        f"**기간:** 최근 {days}일 ({date_str} 기준)",
        f"**포함 리포트:** {len(all_digests)}개",
        "",
        "---",
        "",
    ]
    for digest in all_digests:
        rollup_lines.append(digest)
        rollup_lines.append("\n---\n")

    rollup_md = "\n".join(rollup_lines)
    digest_path = _save_digest(rollup_md, f"{period}-{date_str}.md")
    print(f"[{period.upper()}] {period_kr} 롤업 → {digest_path} ({len(all_digests)}개 리포트)")

    # 텔레그램 전송
    # 롤업 요약 추출 (트렌드 제목들)
    trend_titles: list[str] = []
    for d in all_digests:
        for line in d.split("\n"):
            if line.startswith("### ") and "Trend" in line:
                trend_titles.append(line.replace("### ", "").strip())

    summary = "\n".join(f"  • {t}" for t in trend_titles[:10]) if trend_titles else "상세 내용은 리포트 참고"

    if send_telegram_rollup(
        period=period,
        period_kr=period_kr,
        date_str=date_str,
        digest_count=len(all_digests),
        summary=summary,
    ):
        print(f"[TELEGRAM] {period_kr} 롤업 전송 완료")
    else:
        print("[TELEGRAM] 전송 실패 또는 미설정")

    return 0


def _print_summary(report) -> None:
    """콘솔 요약 출력."""
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    print(f"\n{'=' * 60}")
    print(f"  Domain Intelligence Report — {date_str}")
    print(f"{'=' * 60}")
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VXIS Domain Intelligence — 보안 도메인 전체를 감시"
    )
    parser.add_argument(
        "--mode",
        choices=["daily", "weekly", "monthly", "quarterly", "yearly"],
        default="daily",
        help="실행 모드 (기본: daily)",
    )
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="시그널 수집만 (LLM 분석 없이)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="상세 로그",
    )

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # collect-only 모드
    if args.collect_only:
        now = datetime.now(timezone.utc)
        signals_file = f"signals-{now.strftime('%Y-%m-%d')}.json"
        print("[COLLECT] 보안 도메인 시그널 수집 시작...")
        signals = collect_all()
        _save_signals(signals, signals_file)
        _print_signal_summary(signals)
        return 0

    # 모드별 실행
    if args.mode == "daily":
        return run_daily(args.verbose)
    elif args.mode == "weekly":
        return run_weekly(args.verbose)
    elif args.mode == "monthly":
        return run_rollup("monthly", days=30)
    elif args.mode == "quarterly":
        return run_rollup("quarterly", days=90)
    elif args.mode == "yearly":
        return run_rollup("yearly", days=365)

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
