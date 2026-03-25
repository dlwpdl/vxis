"""산업별 기업 자동 발굴 — 도메인 리스트 없이도 기업을 찾아낸다.

세 가지 발굴 경로를 제공합니다:
  1. GitHub 조직 검색 (공개 저장소 → 웹사이트 → 도메인 추출)
  2. CSV 파일 로드 (name, domain, industry, notes 컬럼)
  3. 평문 도메인 목록 (줄바꿈 구분)

발굴된 :class:`CompanyProfile` 목록은 :class:`~vxis.industry.scanner.IndustryScanner`
로 넘겨 보안 등급을 채웁니다.
"""

from __future__ import annotations

import csv
import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CompanyProfile
# ---------------------------------------------------------------------------

_EMPTY_STACK: list[str] = []


@dataclass
class CompanyProfile:
    """스캔 대상 기업 프로필.

    발굴 단계에서는 name/domain/industry 만 채워지고,
    스캔 완료 후 나머지 필드가 채워집니다.
    """

    name: str
    domain: str
    industry: str = ""

    # 스캔 후 채워지는 필드
    tech_stack: list[str] = field(default_factory=list)
    security_grade: str = ""          # A ~ F
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    last_scanned: str = ""
    contact_email: str = ""           # WHOIS / 웹사이트에서 선택적으로 추출
    notes: str = ""

    def __post_init__(self) -> None:
        self.domain = self.domain.strip().lower()
        # 스킴이 붙어 있으면 제거 (http://example.com → example.com)
        if "://" in self.domain:
            self.domain = urlparse(self.domain).netloc or self.domain
        # 선행/후행 슬래시 제거
        self.domain = self.domain.strip("/")

    def to_dict(self) -> dict[str, object]:
        """JSON 직렬화용 dict 변환."""
        return {
            "name": self.name,
            "domain": self.domain,
            "industry": self.industry,
            "tech_stack": self.tech_stack,
            "security_grade": self.security_grade,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "last_scanned": self.last_scanned,
            "contact_email": self.contact_email,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "CompanyProfile":
        """dict에서 복원."""
        return cls(
            name=str(data.get("name", "")),
            domain=str(data.get("domain", "")),
            industry=str(data.get("industry", "")),
            tech_stack=list(data.get("tech_stack", [])),
            security_grade=str(data.get("security_grade", "")),
            findings_count=int(data.get("findings_count", 0)),
            critical_count=int(data.get("critical_count", 0)),
            high_count=int(data.get("high_count", 0)),
            last_scanned=str(data.get("last_scanned", "")),
            contact_email=str(data.get("contact_email", "")),
            notes=str(data.get("notes", "")),
        )


# ---------------------------------------------------------------------------
# IndustryDiscovery
# ---------------------------------------------------------------------------

# GitHub API를 통해 검색할 때 사용하는 언어 필터 — 한국 스타트업 주요 스택
_DEFAULT_LANGUAGES = ["TypeScript", "JavaScript", "Python", "Go", "Java", "Kotlin"]

# 웹사이트 URL에서 도메인만 추출하는 패턴 (경로/쿼리 제거)
_DOMAIN_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:[/?#].*)?$"
)

# 이메일 추출용 간단한 패턴
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


class IndustryDiscovery:
    """산업별 기업 자동 발굴기.

    Args:
        industry: 기본 산업 분류 문자열 (CSV 없이 발굴 시 사용).
    """

    def __init__(self, industry: str = "tech") -> None:
        self.industry = industry

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------

    def discover_by_github(
        self,
        keyword: str,
        country: str = "korea",
        max_results: int = 50,
    ) -> list[CompanyProfile]:
        """GitHub 저장소 검색을 통해 기업 프로필을 발굴합니다.

        ``gh api`` CLI가 설치되어 있고 인증된 상태여야 합니다.
        인증 없이도 공개 API를 사용하지만, rate-limit가 낮습니다.

        Args:
            keyword: 검색 키워드 (예: "SaaS", "fintech", "security").
            country: 국가 필터 키워드 (기본: "korea").
            max_results: 최대 결과 수 (기본: 50, API 최대 100).

        Returns:
            발굴된 :class:`CompanyProfile` 목록.
            도메인을 특정할 수 없는 조직은 제외합니다.
        """
        profiles: list[CompanyProfile] = []
        seen_domains: set[str] = set()

        per_page = min(max_results, 30)  # GitHub 검색 최대 30개/페이지

        for language in _DEFAULT_LANGUAGES:
            if len(profiles) >= max_results:
                break

            query = f"{keyword} {country} language:{language} fork:false"
            logger.debug("GitHub 검색 쿼리: %s", query)

            try:
                raw = self._gh_search_repositories(query, per_page=per_page)
            except RuntimeError as exc:
                logger.warning("GitHub 검색 실패 (언어: %s): %s", language, exc)
                continue

            for item in raw:
                if len(profiles) >= max_results:
                    break

                org_login = self._extract_org_login(item)
                if not org_login:
                    continue

                domain = self._resolve_org_domain(org_login, item)
                if not domain or domain in seen_domains:
                    continue

                seen_domains.add(domain)

                profile = CompanyProfile(
                    name=item.get("full_name", org_login).split("/")[0],
                    domain=domain,
                    industry=self.industry,
                    notes=f"GitHub: {item.get('html_url', '')}",
                )

                # description에서 이메일 추출 시도
                description = item.get("description") or ""
                emails = _EMAIL_RE.findall(description)
                if emails:
                    profile.contact_email = emails[0]

                profiles.append(profile)
                logger.debug("발굴된 기업: %s (%s)", profile.name, profile.domain)

        logger.info(
            "GitHub 발굴 완료: 키워드='%s', 발굴된 기업 %d개", keyword, len(profiles)
        )
        return profiles

    def discover_from_csv(self, path: str) -> list[CompanyProfile]:
        """CSV 파일에서 기업 프로필을 로드합니다.

        CSV 컬럼 (헤더 필수):
            name, domain, industry, notes

        ``industry``와 ``notes`` 컬럼은 선택사항입니다.

        Args:
            path: CSV 파일 경로 (문자열 또는 pathlib.Path 호환).

        Returns:
            :class:`CompanyProfile` 목록. 빈 domain 행은 건너뜁니다.

        Raises:
            FileNotFoundError: 파일이 존재하지 않을 때.
            ValueError: name 또는 domain 컬럼이 없을 때.
        """
        csv_path = Path(path).expanduser().resolve()

        if not csv_path.exists():
            raise FileNotFoundError(f"CSV 파일을 찾을 수 없습니다: {csv_path}")

        profiles: list[CompanyProfile] = []

        with csv_path.open(newline="", encoding="utf-8-sig") as fh:
            profiles.extend(self._parse_csv_rows(fh))

        logger.info("CSV 로드 완료: %s → %d개 기업", csv_path.name, len(profiles))
        return profiles

    def discover_from_text(self, domains_text: str) -> list[CompanyProfile]:
        """평문 도메인 목록에서 기업 프로필을 생성합니다.

        줄당 하나의 도메인. 공백과 ``#`` 주석 행은 무시합니다.

        Args:
            domains_text: 도메인 목록 문자열.

        Returns:
            :class:`CompanyProfile` 목록.
        """
        profiles: list[CompanyProfile] = []

        for line in domains_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            domain = self._clean_domain(line)
            if not domain:
                logger.debug("도메인 파싱 실패 (무시): %r", line)
                continue

            # 도메인에서 이름 추론: example.co.kr → example
            name = domain.split(".")[0].capitalize()

            profiles.append(
                CompanyProfile(
                    name=name,
                    domain=domain,
                    industry=self.industry,
                )
            )

        logger.info("텍스트 파싱 완료: %d개 도메인", len(profiles))
        return profiles

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    def _parse_csv_rows(self, fh: "StringIO | object") -> Iterator[CompanyProfile]:
        """CSV 파일 핸들에서 CompanyProfile 을 yield 합니다."""
        reader = csv.DictReader(fh)

        if reader.fieldnames is None:
            # 비어있는 파일
            return

        fieldnames_lower = [f.lower().strip() for f in reader.fieldnames]
        if "name" not in fieldnames_lower:
            raise ValueError(
                "CSV에 'name' 컬럼이 없습니다. "
                "필수 컬럼: name, domain"
            )
        if "domain" not in fieldnames_lower:
            raise ValueError(
                "CSV에 'domain' 컬럼이 없습니다. "
                "필수 컬럼: name, domain"
            )

        for row in reader:
            # 대소문자 무관 접근
            normalized = {k.lower().strip(): v.strip() for k, v in row.items()}

            domain = self._clean_domain(normalized.get("domain", ""))
            if not domain:
                logger.debug("빈 도메인 행 무시: %r", row)
                continue

            name = normalized.get("name", "").strip()
            if not name:
                name = domain.split(".")[0].capitalize()

            yield CompanyProfile(
                name=name,
                domain=domain,
                industry=normalized.get("industry", self.industry),
                contact_email=normalized.get("email", ""),
                notes=normalized.get("notes", ""),
            )

    @staticmethod
    def _clean_domain(raw: str) -> str:
        """raw 문자열에서 순수 도메인을 추출합니다."""
        raw = raw.strip()
        if not raw:
            return ""

        match = _DOMAIN_RE.match(raw)
        if match:
            return match.group(1).lower()

        return ""

    @staticmethod
    def _gh_search_repositories(query: str, per_page: int = 30) -> list[dict]:
        """``gh api`` CLI를 통해 GitHub 저장소를 검색합니다.

        Raises:
            RuntimeError: gh CLI를 사용할 수 없거나 API 호출 실패 시.
        """
        endpoint = (
            f"search/repositories"
            f"?q={query.replace(' ', '+')}"
            f"&per_page={per_page}"
            f"&sort=stars"
            f"&order=desc"
        )

        try:
            proc = subprocess.run(
                ["gh", "api", endpoint],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "gh CLI가 설치되어 있지 않습니다. "
                "https://cli.github.com 에서 설치 후 `gh auth login` 하세요."
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("GitHub API 응답 시간 초과 (30초)")

        if proc.returncode != 0:
            stderr = proc.stderr[:200] if proc.stderr else "알 수 없는 오류"
            raise RuntimeError(f"GitHub API 오류 (returncode={proc.returncode}): {stderr}")

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"GitHub API 응답 파싱 실패: {exc}") from exc

        return data.get("items", [])

    @staticmethod
    def _extract_org_login(repo_item: dict) -> str:
        """저장소 항목에서 조직/사용자 로그인을 추출합니다."""
        owner = repo_item.get("owner") or {}
        return owner.get("login", "")

    def _resolve_org_domain(self, org_login: str, repo_item: dict) -> str:
        """조직 로그인에서 실제 도메인을 resolve 합니다.

        우선순위:
        1. 저장소의 homepage URL
        2. 조직 프로필 API의 blog/website 필드
        3. 도메인 없이 건너뜀 (github.io 서브도메인 무시)
        """
        # 1. 저장소 homepage
        homepage = repo_item.get("homepage") or ""
        if homepage:
            domain = self._clean_domain(homepage)
            if domain and not domain.endswith("github.io"):
                return domain

        # 2. 조직 API 호출 (선택적 — 실패해도 무시)
        try:
            proc = subprocess.run(
                ["gh", "api", f"orgs/{org_login}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                org_data = json.loads(proc.stdout)
                blog = org_data.get("blog") or ""
                if blog:
                    domain = self._clean_domain(blog)
                    if domain and not domain.endswith("github.io"):
                        return domain
        except Exception:
            pass  # 조직 API 실패는 조용히 무시

        # 3. 개인/유저 API 시도
        try:
            proc = subprocess.run(
                ["gh", "api", f"users/{org_login}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                user_data = json.loads(proc.stdout)
                blog = user_data.get("blog") or ""
                if blog:
                    domain = self._clean_domain(blog)
                    if domain and not domain.endswith("github.io"):
                        return domain
        except Exception:
            pass

        return ""
