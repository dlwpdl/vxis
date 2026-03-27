"""CVE Watch Daemon — 메인 24/7 감시 루프.

실행 방법:
    1. 독립 프로세스: python -m vxis.watchers
    2. 단발 실행:    python -m vxis.watchers --once
    3. GitHub Actions: cron every 15 minutes → python -m vxis.watchers --once

동작 흐름:
    poll_interval마다 다음을 반복:
    1. GitHub Advisory / NVD / OSV에서 CVE 수집
    2. CVE ID 기준 중복 제거
    3. 타겟 프로파일과 매칭 (점수 > 0.6)
    4. 매칭된 CVE에 대해 exploit 시도
    5. 취약 확인 → Telegram CRITICAL 알림
    6. 상태 파일(.cve_watch_state.json) 업데이트

상태 파일 구조:
    {
        "last_checked": "2026-01-01T00:00:00+00:00",
        "seen_cve_ids": ["CVE-2024-1234", ...],
        "stats": {
            "total_fetched": 0,
            "total_matched": 0,
            "total_exploitable": 0,
            "last_run_duration_sec": 0.0
        }
    }
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .cve_entry import CVEEntry
from .exploit_tester import ExploitResult, test_exploit
from .matcher import TechStackProfile, load_profiles_from_memory, match_cve
from .sources import github_advisory, nvd, osv

logger = logging.getLogger(__name__)

# 상태 파일 위치 (프로젝트 루트 기준)
_STATE_FILE = Path(__file__).parent.parent.parent.parent / ".cve_watch_state.json"

# 기본 폴링 간격 (초)
_DEFAULT_POLL_INTERVAL = 900  # 15분

# 매칭 임계값
_MATCH_THRESHOLD = 0.6

# since_hours: 각 소스에서 가져올 시간 범위 (daemon은 poll_interval 기준)
_FETCH_HOURS_DAEMON = 1
_FETCH_HOURS_ONCE = 1

# OSV 에코시스템 — 감시할 에코시스템 목록
_OSV_ECOSYSTEMS = ["npm", "PyPI", "Maven", "Go"]

# Telegram HTML 이스케이프
def _tg_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _send_telegram_message(token: str, chat_id: str, text: str) -> bool:
    """단일 Telegram 메시지를 전송한다."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=15)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("[Daemon] Telegram 전송 실패: %s", exc)
        return False


def _split_message(text: str, max_len: int = 4000) -> list[str]:
    """Telegram 4096자 제한에 맞게 메시지를 분할."""
    if len(text) <= max_len:
        return [text]
    chunks: list[str] = []
    while text:
        if len(text) <= max_len:
            chunks.append(text)
            break
        split_at = text.rfind("\n", 0, max_len)
        if split_at == -1:
            split_at = max_len
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    return chunks


class CVEWatchDaemon:
    """CVE 감시 데몬.

    Args:
        poll_interval: 폴링 간격 (초). 기본 900초(15분).
        profiles: 타겟 프로파일 목록. None이면 agent_memory.json에서 로드.
        state_file: 상태 파일 경로. None이면 기본 위치 사용.
    """

    def __init__(
        self,
        poll_interval: int = _DEFAULT_POLL_INTERVAL,
        profiles: list[TechStackProfile] | None = None,
        state_file: Path | None = None,
    ) -> None:
        self.poll_interval = poll_interval
        self._profiles = profiles  # None이면 run() 시점에 로드
        self._state_file = state_file or _STATE_FILE
        self._state: dict = self._load_state()
        self._telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self._telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")

    # ─── 상태 관리 ────────────────────────────────────────────────────

    def _load_state(self) -> dict:
        """상태 파일을 로드한다. 없으면 초기 상태를 반환."""
        default: dict = {
            "last_checked": None,
            "seen_cve_ids": [],
            "stats": {
                "total_fetched": 0,
                "total_matched": 0,
                "total_exploitable": 0,
                "last_run_duration_sec": 0.0,
            },
        }
        if not self._state_file.exists():
            return default
        try:
            data = json.loads(self._state_file.read_text(encoding="utf-8"))
            # seen_cve_ids를 set으로 관리하되 파일에는 list로 저장
            data.setdefault("seen_cve_ids", [])
            data.setdefault("stats", default["stats"])
            return data
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("[Daemon] 상태 파일 로드 실패: %s", exc)
            return default

    def _save_state(self) -> None:
        """현재 상태를 파일에 저장."""
        try:
            self._state_file.write_text(
                json.dumps(self._state, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("[Daemon] 상태 파일 저장 실패: %s", exc)

    def _is_new_cve(self, cve_id: str) -> bool:
        """이미 처리한 CVE인지 확인."""
        return cve_id not in self._state["seen_cve_ids"]

    def _mark_seen(self, cve_id: str) -> None:
        """CVE를 처리 완료로 표시."""
        if cve_id not in self._state["seen_cve_ids"]:
            self._state["seen_cve_ids"].append(cve_id)
        # 메모리 절약: 최대 10,000개만 유지
        if len(self._state["seen_cve_ids"]) > 10000:
            self._state["seen_cve_ids"] = self._state["seen_cve_ids"][-8000:]

    # ─── CVE 수집 ─────────────────────────────────────────────────────

    def _fetch_all_sources(self, since_hours: int) -> list[CVEEntry]:
        """세 소스에서 CVE를 병렬로 수집하고 중복 제거한 목록을 반환."""
        all_entries: list[CVEEntry] = []
        seen_ids: set[str] = set()

        # GitHub Advisory
        logger.info("[Daemon] GitHub Advisory 조회 중...")
        try:
            gh_entries = github_advisory.fetch_recent(since_hours=since_hours)
            for e in gh_entries:
                if e.id not in seen_ids:
                    seen_ids.add(e.id)
                    all_entries.append(e)
            logger.info("[Daemon] GitHub Advisory: %d개", len(gh_entries))
        except Exception as exc:  # noqa: BLE001
            logger.warning("[Daemon] GitHub Advisory 오류: %s", exc)

        # NVD
        logger.info("[Daemon] NVD 조회 중...")
        try:
            nvd_entries = nvd.fetch_recent(since_hours=since_hours)
            new_count = 0
            for e in nvd_entries:
                if e.id not in seen_ids:
                    seen_ids.add(e.id)
                    all_entries.append(e)
                    new_count += 1
            logger.info("[Daemon] NVD: %d개 (%d개 신규)", len(nvd_entries), new_count)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[Daemon] NVD 오류: %s", exc)

        # OSV (에코시스템별 순차 조회)
        logger.info("[Daemon] OSV 조회 중 (%s)...", ", ".join(_OSV_ECOSYSTEMS))
        for ecosystem in _OSV_ECOSYSTEMS:
            try:
                osv_entries = osv.fetch_recent(
                    ecosystem=ecosystem, since_hours=since_hours
                )
                new_count = 0
                for e in osv_entries:
                    if e.id not in seen_ids:
                        seen_ids.add(e.id)
                        all_entries.append(e)
                        new_count += 1
                logger.info(
                    "[Daemon] OSV/%s: %d개 (%d개 신규)",
                    ecosystem, len(osv_entries), new_count,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("[Daemon] OSV/%s 오류: %s", ecosystem, exc)

        logger.info("[Daemon] 총 수집: %d개 CVE (중복 제거)", len(all_entries))
        return all_entries

    # ─── 알림 ─────────────────────────────────────────────────────────

    def _send_alert(
        self,
        cve: CVEEntry,
        profile: TechStackProfile,
        match_score: float,
        exploit_result: ExploitResult,
    ) -> None:
        """취약점 발견 시 Telegram 알림을 전송한다."""
        if not self._telegram_token or not self._telegram_chat_id:
            logger.info(
                "[Daemon] Telegram 미설정. 알림 건너뜀: %s", cve.id
            )
            return

        now = datetime.now(timezone.utc)
        kst_hour = (now.hour + 9) % 24
        time_str = f"{now.strftime('%Y-%m-%d')} {kst_hour:02d}:{now.strftime('%M')} KST"

        if exploit_result.exploitable:
            header = "\U0001f6a8 <b>[CRITICAL] 실시간 취약점 확인!</b>"
            status_line = f"\U0001f4a5 <b>상태:</b> <b>익스플로잇 성공</b> (방법: {exploit_result.method})"
        else:
            header = "\u26a0\ufe0f <b>[경고] 잠재적 취약점 감지</b>"
            status_line = "\U0001f50d <b>상태:</b> 취약 가능성 있음 (미검증)"

        cvss_display = f"{cve.cvss_score:.1f}" if cve.cvss_score else "N/A"
        severity_upper = cve.severity.upper()

        products_str = ", ".join(cve.affected_products[:5]) or "알 수 없음"
        versions_str = ", ".join(cve.affected_versions[:3]) or "전 버전"
        refs_str = "\n".join(
            f'  \u2022 <a href="{r}">{_tg_escape(r[:80])}</a>'
            for r in cve.references[:3]
        )

        lines = [
            header,
            f"\U0001f4c5 {time_str}",
            "",
            f"\U0001f4cc <b>CVE:</b> <code>{_tg_escape(cve.id)}</code>",
            f"\U0001f3af <b>타겟:</b> <code>{_tg_escape(profile.target)}</code>",
            f"\u2696\ufe0f <b>매칭 점수:</b> {match_score:.0%}",
            "",
            f"\U0001f4dd <b>취약점:</b> {_tg_escape(cve.title[:120])}",
            f"\U0001f4ca <b>심각도:</b> {severity_upper} (CVSS {cvss_display})",
            f"\U0001f4e6 <b>영향 제품:</b> {_tg_escape(products_str[:200])}",
            f"\U0001f522 <b>영향 버전:</b> {_tg_escape(versions_str[:100])}",
            "",
            status_line,
        ]

        if exploit_result.exploitable and exploit_result.evidence:
            evidence_snippet = exploit_result.evidence[:300].replace("\n", " ")
            lines.append(
                f"\U0001f50e <b>증거:</b> <code>{_tg_escape(evidence_snippet)}</code>"
            )

        if cve.poc_url:
            lines.append(f"\U0001f517 <b>PoC URL:</b> <a href=\"{cve.poc_url}\">링크</a>")

        if refs_str:
            lines.append(f"\n\U0001f4da <b>참고 링크:</b>\n{refs_str}")

        if cve.description:
            desc_short = cve.description[:200]
            if len(cve.description) > 200:
                desc_short += "..."
            lines.append(f"\n\U0001f4c4 <b>설명:</b> {_tg_escape(desc_short)}")

        message = "\n".join(lines)
        chunks = _split_message(message)
        for chunk in chunks:
            _send_telegram_message(self._telegram_token, self._telegram_chat_id, chunk)

        logger.info("[Daemon] Telegram 알림 전송: %s → %s", cve.id, profile.target)

    def _send_summary_alert(
        self, run_stats: dict, matched_count: int, exploitable_count: int
    ) -> None:
        """폴링 주기 완료 후 요약 알림 (항상 전송 — 시스템 생존 확인용)."""
        if not self._telegram_token or not self._telegram_chat_id:
            return

        now = datetime.now(timezone.utc)
        kst_hour = (now.hour + 9) % 24
        time_str = f"{now.strftime('%Y-%m-%d')} {kst_hour:02d}:{now.strftime('%M')} KST"

        fetched = run_stats.get("fetched", 0)

        if matched_count == 0:
            lines = [
                "\U0001f6e1 <b>CVE Watch \u2014 \uc624\ub298\uc758 \uac10\uc2dc \uacb0\uacfc</b>",
                f"\U0001f4c5 {time_str}",
                "",
                f"\u2705 \uc218\uc9d1\ub41c CVE: {fetched}\uac1c | \ub9e4\uce6d: 0\uac1c | \uc704\ud5d8: 0\uac1c",
                "",
                "\ud2b9\uc774\uc0ac\ud56d \uc5c6\uc74c \u2014 \ub2e4\uc74c \uc8fc\uae30\uc5d0 \ub2e4\uc2dc \uac10\uc2dc\ud569\ub2c8\ub2e4.",
            ]
        else:
            lines = [
                "\U0001f4ca <b>CVE Watch \u2014 \uc624\ub298\uc758 \uac10\uc2dc \uacb0\uacfc</b>",
                f"\U0001f4c5 {time_str}",
                "",
                f"  \u2022 \uc218\uc9d1\ub41c CVE: {fetched}\uac1c",
                f"  \u2022 \uc0c8\ub85c\uc6b4 \ub9e4\uce6d: {matched_count}\uac1c",
            ]
            if exploitable_count > 0:
                lines.append(
                    f"  \u2022 \U0001f6a8 \uc775\uc2a4\ud50c\ub85c\uc787 \uc131\uacf5: {exploitable_count}\uac1c"
                )
            else:
                lines.append("  \u2022 \uc775\uc2a4\ud50c\ub85c\uc787 \uc131\uacf5: 0\uac1c")

        message = "\n".join(lines)
        _send_telegram_message(self._telegram_token, self._telegram_chat_id, message)

    # ─── 핵심 루프 ────────────────────────────────────────────────────

    async def _run_once(self, since_hours: int = _FETCH_HOURS_DAEMON) -> dict:
        """단일 폴링 사이클을 실행한다.

        Returns:
            실행 통계 딕셔너리.
        """
        start_time = time.monotonic()
        run_stats = {"fetched": 0, "new": 0, "matched": 0, "exploitable": 0}

        # 프로파일 로드 (없으면 agent_memory에서)
        profiles = self._profiles
        if not profiles:
            profiles = load_profiles_from_memory()
        if not profiles:
            logger.warning(
                "[Daemon] 타겟 프로파일 없음. 매칭을 건너뜁니다. "
                "agent_memory.json을 확인하거나 --target 옵션을 사용하세요."
            )

        # ─ 1. 모든 소스에서 CVE 수집 ──────────────────────────────────
        all_entries = self._fetch_all_sources(since_hours=since_hours)
        run_stats["fetched"] = len(all_entries)

        # ─ 2. 이미 처리한 CVE 제거 ─────────────────────────────────────
        new_entries = [e for e in all_entries if self._is_new_cve(e.id)]
        run_stats["new"] = len(new_entries)
        logger.info(
            "[Daemon] 신규 CVE: %d개 / 전체 %d개",
            len(new_entries), len(all_entries),
        )

        # ─ 3. 타겟 프로파일 매칭 ──────────────────────────────────────
        if not profiles:
            # 프로파일 없어도 상태 업데이트
            for e in new_entries:
                self._mark_seen(e.id)
            return run_stats

        matched_pairs: list[tuple[CVEEntry, TechStackProfile, float]] = []

        for cve in new_entries:
            matches = match_cve(cve, profiles)
            for profile, score in matches:
                if score >= _MATCH_THRESHOLD:
                    matched_pairs.append((cve, profile, score))
                    logger.info(
                        "[Daemon] 매칭: %s ↔ %s (점수: %.2f)",
                        cve.id, profile.target, score,
                    )

        run_stats["matched"] = len(matched_pairs)
        logger.info("[Daemon] 매칭된 CVE-타겟 쌍: %d개", len(matched_pairs))

        # ─ 4. Exploit 시도 ────────────────────────────────────────────
        for cve, profile, score in matched_pairs:
            try:
                exploit_result = await test_exploit(cve, profile.target)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "[Daemon] exploit_tester 오류 (%s): %s", cve.id, exc
                )
                continue

            if exploit_result.exploitable:
                run_stats["exploitable"] += 1
                logger.warning(
                    "[Daemon] 취약 확인! %s on %s (방법: %s)",
                    cve.id, profile.target, exploit_result.method,
                )

            # 취약 여부와 관계없이 매칭된 CVE는 알림 발송
            # (점수가 높거나 취약 확인된 경우)
            if exploit_result.exploitable or score >= 0.7:
                self._send_alert(cve, profile, score, exploit_result)

        # ─ 5. 상태 업데이트 ──────────────────────────────────────────
        for e in new_entries:
            self._mark_seen(e.id)

        now_iso = datetime.now(timezone.utc).isoformat()
        self._state["last_checked"] = now_iso

        stats = self._state["stats"]
        stats["total_fetched"] += run_stats["fetched"]
        stats["total_matched"] += run_stats["matched"]
        stats["total_exploitable"] += run_stats["exploitable"]
        stats["last_run_duration_sec"] = round(time.monotonic() - start_time, 2)

        self._save_state()

        logger.info(
            "[Daemon] 사이클 완료: 소요 %.1f초 | 수집 %d | 매칭 %d | 취약 %d",
            stats["last_run_duration_sec"],
            run_stats["fetched"],
            run_stats["matched"],
            run_stats["exploitable"],
        )
        return run_stats

    async def run(self) -> None:
        """메인 24/7 감시 루프.

        poll_interval마다 _run_once()를 호출한다.
        KeyboardInterrupt 또는 SIGTERM으로 종료 가능.
        """
        logger.info(
            "[Daemon] CVE Watch Daemon 시작. 폴링 간격: %d초 (%d분)",
            self.poll_interval, self.poll_interval // 60,
        )

        while True:
            try:
                run_stats = await self._run_once()
                self._send_summary_alert(
                    run_stats,
                    matched_count=run_stats["matched"],
                    exploitable_count=run_stats["exploitable"],
                )
            except KeyboardInterrupt:
                logger.info("[Daemon] 사용자 중단 신호 수신. 종료합니다.")
                break
            except Exception as exc:  # noqa: BLE001
                logger.error("[Daemon] 예상치 못한 오류: %s", exc, exc_info=True)
                # 오류 발생해도 루프 유지

            logger.info("[Daemon] %d초 후 다음 폴링...", self.poll_interval)
            try:
                await asyncio.sleep(self.poll_interval)
            except asyncio.CancelledError:
                logger.info("[Daemon] 취소 신호. 종료합니다.")
                break

    async def run_once(self) -> dict:
        """단발 실행 (GitHub Actions 등에서 사용).

        Returns:
            실행 통계 딕셔너리.
        """
        logger.info("[Daemon] 단발 실행 모드")
        return await self._run_once(since_hours=_FETCH_HOURS_ONCE)


def _setup_logging(verbose: bool = False) -> None:
    """로깅을 설정한다."""
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(fmt)
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)


def main(argv: list[str] | None = None) -> int:
    """CLI 진입점.

    사용법:
        python -m vxis.watchers          # 데몬 모드 (무한 루프)
        python -m vxis.watchers --once   # 단발 실행
        python -m vxis.watchers --once --target https://example.com --tech "Next.js,Node.js"
    """
    parser = argparse.ArgumentParser(
        description="VXIS CVE Watch — 실시간 취약점 감시 데몬",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="단발 실행 후 종료 (GitHub Actions 등에서 사용)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=_DEFAULT_POLL_INTERVAL,
        help=f"폴링 간격 (초). 기본: {_DEFAULT_POLL_INTERVAL}",
    )
    parser.add_argument(
        "--target",
        type=str,
        default="",
        help="감시할 타겟 URL (예: https://example.com)",
    )
    parser.add_argument(
        "--tech",
        type=str,
        default="",
        help="기술 스택 (쉼표 구분, 예: 'Next.js,Node.js,PostgreSQL')",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="상세 로그 출력",
    )
    parser.add_argument(
        "--state-file",
        type=str,
        default="",
        help="상태 파일 경로 (기본: .cve_watch_state.json)",
    )

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    # 타겟/기술 스택 직접 지정 시 프로파일 생성
    profiles: list[TechStackProfile] | None = None
    if args.target and args.tech:
        from .matcher import TechStackProfile
        techs = [t.strip() for t in args.tech.split(",") if t.strip()]
        profiles = [TechStackProfile(target=args.target, technologies=techs)]
        logger.info(
            "[Daemon] 명령줄 프로파일: %s → %s", args.target, techs
        )

    state_file = Path(args.state_file) if args.state_file else None

    daemon = CVEWatchDaemon(
        poll_interval=args.interval,
        profiles=profiles,
        state_file=state_file,
    )

    if args.once:
        stats = asyncio.run(daemon.run_once())
        print(
            f"\n실행 완료: 수집 {stats['fetched']}개 | "
            f"신규 {stats['new']}개 | "
            f"매칭 {stats['matched']}개 | "
            f"취약 {stats['exploitable']}개"
        )
        return 0 if stats["exploitable"] == 0 else 1
    else:
        try:
            asyncio.run(daemon.run())
        except KeyboardInterrupt:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
