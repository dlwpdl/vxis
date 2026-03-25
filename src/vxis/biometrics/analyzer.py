"""행동 생체인식 분석 — GitHub/LinkedIn OSINT로 인간 행동 패턴 공격 표면.

직원 A가 매일 9시에 GitHub push → 9시에 피싱 이메일 보내면 열 확률 높음
직원 B의 LinkedIn에 "AWS 관리자" → B의 계정이 클라우드 공격 표면

데이터 수집 원칙:
    - 공개 정보만 수집 (GitHub public API, 공개 프로필)
    - 인증이 필요한 정보 수집 금지
    - 개인 식별 정보(PII)는 최소 수집
    - 수집 목적: 보안 취약 지점 식별 (승인된 레드팀 활동)

데이터 소스:
    - GitHub REST API v3 (공개 엔드포인트만)
    - gh CLI (인증 없이 접근 가능한 공개 데이터)
    - 공개 DNS 기록
"""

from __future__ import annotations

import json
import logging
import re
import socket
import subprocess
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# GitHub API 기본 URL
_GITHUB_API = "https://api.github.com"

# 높은 권한을 암시하는 키워드 (직책/기술 기반)
_PRIVILEGED_KEYWORDS = {
    # 클라우드/인프라 권한
    "aws": 9, "azure": 9, "gcp": 9, "cloud": 7,
    "kubernetes": 8, "k8s": 8, "terraform": 8, "devops": 7,
    "infrastructure": 8, "platform": 7,
    # 보안/접근 권한
    "security": 8, "admin": 9, "administrator": 9,
    "sre": 8, "site reliability": 8,
    # 데이터 접근 권한
    "database": 7, "dba": 9, "data engineer": 7,
    # 개발 권한
    "lead": 6, "principal": 8, "staff": 7, "architect": 8, "cto": 10,
    "vp": 9, "director": 8, "manager": 6,
    # CI/CD 접근
    "ci": 6, "cd": 6, "pipeline": 6, "jenkins": 7, "github actions": 7,
}

# 위험한 기술 조합 (이 기술들을 동시에 가진 직원은 고가치 타겟)
_DANGEROUS_TECH_COMBOS = [
    {"aws", "terraform", "admin"},
    {"kubernetes", "helm", "production"},
    {"database", "admin", "production"},
    {"security", "pentest", "admin"},
    {"ci", "secret", "deploy"},
]


@dataclass
class GitHubProfile:
    """GitHub 공개 프로필 분석 결과."""

    username: str
    name: str = ""
    bio: str = ""
    company: str = ""
    location: str = ""
    public_repos: int = 0
    followers: int = 0
    following: int = 0
    created_at: str = ""

    # 언어 사용 패턴
    primary_languages: list[str] = field(default_factory=list)
    language_distribution: dict[str, int] = field(default_factory=dict)  # 언어 → repo 수

    # 활동 시간 패턴 (commit 시간대 분석)
    active_hours: list[int] = field(default_factory=list)   # 활동 시간대 (0-23)
    active_days: list[str] = field(default_factory=list)    # 활동 요일
    peak_activity_hour: int = -1  # 가장 많이 커밋하는 시간 (-1이면 데이터 없음)
    avg_commits_per_day: float = 0.0

    # 보안 관련 패턴
    exposed_emails: list[str] = field(default_factory=list)  # 커밋에서 노출된 이메일
    org_memberships: list[str] = field(default_factory=list)  # 공개 조직
    security_relevant_repos: list[str] = field(default_factory=list)  # 민감 repo명

    # 위험도 점수 (0-100)
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)


@dataclass
class SocialFootprint:
    """회사 도메인 기반 소셜 공개 정보."""

    company_domain: str
    discovered_employees: list[dict[str, Any]] = field(default_factory=list)
    github_org_name: str = ""
    public_repos_count: int = 0
    tech_stack_hints: list[str] = field(default_factory=list)  # repo 언어/토픽에서 추론
    dns_records: dict[str, list[str]] = field(default_factory=dict)  # MX, TXT 등


@dataclass
class HighValueTarget:
    """높은 권한이 추정되는 직원 정보."""

    identifier: str          # GitHub username 또는 이메일 (마스킹)
    display_name: str        # 표시 이름
    estimated_access_level: int  # 1-10 (10이 최고 권한)
    privilege_indicators: list[str]  # 권한 추정 근거
    attack_surface: list[str]  # 공격 표면 설명
    recommended_vectors: list[str]  # 권장 공격 벡터 (레드팀용)
    risk_score: int          # 0-100


# ── 핵심 분석 엔진 ───────────────────────────────────────────────

class BehavioralAnalyzer:
    """행동 생체인식 분석 엔진.

    공개 GitHub API와 도메인 OSINT로 직원 행동 패턴을 분석한다.

    Usage:
        analyzer = BehavioralAnalyzer()

        # 단일 GitHub 프로필 분석
        profile = await analyzer.analyze_github_profile("torvalds")

        # 회사 도메인 전체 분석
        footprint = await analyzer.analyze_social_footprint("github.com")

        # 고가치 타겟 식별
        targets = analyzer.identify_high_value_targets([footprint])
    """

    def __init__(self, github_token: str = "") -> None:
        """초기화.

        Args:
            github_token: GitHub Personal Access Token (선택).
                          없으면 rate limit가 60 req/hour로 제한됨.
                          공개 엔드포인트만 사용하므로 없어도 기본 동작.
        """
        self._token = github_token
        self._analyzed_profiles: list[GitHubProfile] = []

    # ── GitHub 프로필 분석 ──────────────────────────────────

    async def analyze_github_profile(self, username: str) -> GitHubProfile:
        """GitHub 공개 프로필을 분석한다.

        수집 데이터:
        - 기본 프로필 (이름, 바이오, 회사, 위치)
        - 언어 사용 패턴 (어떤 언어로 주로 개발하는가)
        - 활동 시간 패턴 (언제 활동하는가 — 피싱 타이밍 최적화)
        - 공개 이메일 (커밋 메타데이터)
        - 조직 멤버십

        Args:
            username: GitHub 사용자명.

        Returns:
            GitHubProfile 분석 결과.
        """
        logger.info("GitHub 프로필 분석: @%s", username)

        profile = GitHubProfile(username=username)

        # 1. 기본 프로필
        user_data = self._github_get(f"/users/{username}")
        if user_data:
            profile.name = user_data.get("name") or ""
            profile.bio = user_data.get("bio") or ""
            profile.company = user_data.get("company") or ""
            profile.location = user_data.get("location") or ""
            profile.public_repos = user_data.get("public_repos", 0)
            profile.followers = user_data.get("followers", 0)
            profile.following = user_data.get("following", 0)
            profile.created_at = user_data.get("created_at", "")

        # 2. 공개 저장소 분석 (언어, 토픽, 이름)
        repos_data = self._github_get(
            f"/users/{username}/repos",
            params={"sort": "updated", "per_page": "30", "type": "public"},
        )
        if repos_data and isinstance(repos_data, list):
            self._analyze_repos(profile, repos_data)

        # 3. 공개 이벤트 (활동 시간 패턴)
        events_data = self._github_get(
            f"/users/{username}/events/public",
            params={"per_page": "100"},
        )
        if events_data and isinstance(events_data, list):
            self._analyze_activity_pattern(profile, events_data)

        # 4. 공개 조직 멤버십
        orgs_data = self._github_get(f"/users/{username}/orgs")
        if orgs_data and isinstance(orgs_data, list):
            profile.org_memberships = [
                org.get("login", "") for org in orgs_data
            ]

        # 5. 위험도 점수 계산
        self._calculate_risk_score(profile)

        self._analyzed_profiles.append(profile)
        logger.info(
            "프로필 분석 완료: @%s — 위험도 %d/100, 피크 활동 %d시",
            username,
            profile.risk_score,
            profile.peak_activity_hour,
        )

        return profile

    def _analyze_repos(
        self, profile: GitHubProfile, repos: list[dict]
    ) -> None:
        """저장소 목록에서 언어 패턴과 민감 repo를 분석한다."""
        lang_count: Counter = Counter()
        sensitive_keywords = [
            "infra", "infrastructure", "deploy", "prod", "production",
            "k8s", "kubernetes", "terraform", "ansible", "secret",
            "credential", "auth", "admin", "internal", "private",
            "security", "pentest", "ctf",
        ]

        for repo in repos:
            # 언어 집계
            lang = repo.get("language")
            if lang:
                lang_count[lang] += 1

            # 민감 repo명 탐지
            repo_name = repo.get("name", "").lower()
            if any(kw in repo_name for kw in sensitive_keywords):
                profile.security_relevant_repos.append(repo.get("name", ""))

            # 커밋 이메일 수집 시도 (공개 commit API)
            # 실제 이메일은 커밋 Author 정보에서만 접근 가능
            # 여기서는 가용 공개 이메일만 수집

        profile.language_distribution = dict(lang_count)
        profile.primary_languages = [
            lang for lang, _ in lang_count.most_common(5)
        ]

    def _analyze_activity_pattern(
        self, profile: GitHubProfile, events: list[dict]
    ) -> None:
        """GitHub 이벤트에서 활동 시간 패턴을 추출한다."""
        hour_counts: Counter = Counter()
        day_counts: Counter = Counter()
        emails_found: set[str] = set()

        day_map = {0: "월", 1: "화", 2: "수", 3: "목", 4: "금", 5: "토", 6: "일"}

        for event in events:
            created_at = event.get("created_at", "")
            if not created_at:
                continue

            # ISO 8601 파싱 (stdlib datetime)
            try:
                # 형식: "2024-01-15T09:23:45Z"
                parts = created_at.replace("Z", "").split("T")
                if len(parts) == 2:
                    time_parts = parts[1].split(":")
                    hour = int(time_parts[0])
                    hour_counts[hour] += 1

                    date_parts = parts[0].split("-")
                    if len(date_parts) == 3:
                        import datetime as dt_module
                        d = dt_module.date(
                            int(date_parts[0]),
                            int(date_parts[1]),
                            int(date_parts[2]),
                        )
                        day_counts[day_map[d.weekday()]] += 1
            except (ValueError, IndexError):
                continue

            # 커밋 이벤트에서 이메일 추출
            payload = event.get("payload", {})
            commits = payload.get("commits", [])
            for commit in commits:
                author = commit.get("author", {})
                email = author.get("email", "")
                if email and "@" in email and not email.endswith("@users.noreply.github.com"):
                    emails_found.add(email)

        if hour_counts:
            profile.active_hours = sorted(hour_counts.keys())
            profile.peak_activity_hour = hour_counts.most_common(1)[0][0]
            total_events = sum(hour_counts.values())
            unique_days = len({
                event.get("created_at", "")[:10]
                for event in events
                if event.get("created_at")
            })
            if unique_days > 0:
                profile.avg_commits_per_day = round(total_events / unique_days, 2)

        profile.active_days = [
            day for day, _ in day_counts.most_common()
        ]
        profile.exposed_emails = list(emails_found)[:10]  # 최대 10개만

    def _calculate_risk_score(self, profile: GitHubProfile) -> None:
        """프로필의 공격 표면 위험도 점수를 계산한다."""
        score = 0
        reasons: list[str] = []

        # 바이오/회사명에서 권한 키워드 탐색
        bio_company = f"{profile.bio} {profile.company}".lower()
        found_keywords = []
        for kw, weight in _PRIVILEGED_KEYWORDS.items():
            if kw in bio_company:
                score += weight * 2
                found_keywords.append(kw)

        if found_keywords:
            reasons.append(f"권한 키워드 탐지: {', '.join(found_keywords[:5])}")

        # 민감 저장소 보유
        if profile.security_relevant_repos:
            score += len(profile.security_relevant_repos) * 5
            reasons.append(
                f"민감 저장소 {len(profile.security_relevant_repos)}개 "
                f"({', '.join(profile.security_relevant_repos[:3])})"
            )

        # 이메일 노출
        if profile.exposed_emails:
            score += 15
            reasons.append(f"커밋에서 이메일 노출: {len(profile.exposed_emails)}개")

        # 조직 멤버십 (많을수록 내부 접근 가능성)
        if profile.org_memberships:
            score += min(len(profile.org_memberships) * 5, 20)
            reasons.append(
                f"공개 조직 멤버: {', '.join(profile.org_memberships[:3])}"
            )

        # 활동 패턴 분석 (피싱 타이밍 가치)
        if profile.peak_activity_hour >= 0:
            reasons.append(
                f"피크 활동 시간: {profile.peak_activity_hour}:00 "
                f"(이 시간 피싱 이메일 효과 극대화)"
            )
            score += 10

        # 인프라 관련 언어 사용 (권한 추정)
        infra_langs = {"HCL", "Dockerfile", "Shell", "Makefile", "YAML"}
        overlap = set(profile.primary_languages) & infra_langs
        if overlap:
            score += len(overlap) * 8
            reasons.append(f"인프라 언어 사용: {', '.join(overlap)}")

        profile.risk_score = min(score, 100)
        profile.risk_reasons = reasons

    # ── 소셜 풋프린트 분석 ──────────────────────────────────

    async def analyze_social_footprint(
        self, company_domain: str
    ) -> SocialFootprint:
        """회사 도메인 기반 공개 정보를 수집한다.

        수집 데이터 (공개 정보만):
        - GitHub 조직 공개 저장소 및 멤버 목록
        - 공개 DNS 기록 (MX, TXT — 이메일 시스템, SPF 등)
        - 기술 스택 힌트 (GitHub 언어/토픽)

        Args:
            company_domain: 회사 도메인 (e.g., "example.com").

        Returns:
            SocialFootprint 분석 결과.
        """
        logger.info("소셜 풋프린트 분석: %s", company_domain)

        footprint = SocialFootprint(company_domain=company_domain)

        # 1. 도메인에서 GitHub org 이름 추론
        org_name = company_domain.split(".")[0]  # example.com → example
        footprint.github_org_name = org_name

        # 2. GitHub 조직 공개 정보
        org_data = self._github_get(f"/orgs/{org_name}")
        if org_data and isinstance(org_data, dict):
            footprint.public_repos_count = org_data.get("public_repos", 0)
            logger.debug(
                "GitHub 조직 '%s': 공개 저장소 %d개",
                org_name,
                footprint.public_repos_count,
            )

        # 3. 공개 저장소에서 기술 스택 힌트 추출
        repos_data = self._github_get(
            f"/orgs/{org_name}/repos",
            params={"sort": "updated", "per_page": "30", "type": "public"},
        )
        if repos_data and isinstance(repos_data, list):
            lang_counter: Counter = Counter()
            for repo in repos_data:
                lang = repo.get("language")
                if lang:
                    lang_counter[lang] += 1
                topics = repo.get("topics", [])
                footprint.tech_stack_hints.extend(topics)

            footprint.tech_stack_hints.extend(
                lang for lang, _ in lang_counter.most_common(10)
            )
            # 중복 제거 + 정렬
            footprint.tech_stack_hints = list(dict.fromkeys(footprint.tech_stack_hints))

        # 4. 공개 조직 멤버 (공개 멤버만)
        members_data = self._github_get(
            f"/orgs/{org_name}/members",
            params={"per_page": "30"},
        )
        if members_data and isinstance(members_data, list):
            for member in members_data:
                login = member.get("login", "")
                if login:
                    footprint.discovered_employees.append({
                        "github_username": login,
                        "profile_url": f"https://github.com/{login}",
                        "avatar_url": member.get("avatar_url", ""),
                    })

        # 5. 공개 DNS 기록 (MX, TXT)
        footprint.dns_records = self._get_dns_records(company_domain)

        logger.info(
            "소셜 풋프린트 완료: %s — 직원 %d명 발견, 기술 %d개",
            company_domain,
            len(footprint.discovered_employees),
            len(footprint.tech_stack_hints),
        )

        return footprint

    def _get_dns_records(self, domain: str) -> dict[str, list[str]]:
        """공개 DNS 기록을 수집한다."""
        records: dict[str, list[str]] = {}

        # dig/nslookup 대신 subprocess로 host 커맨드 사용 (stdlib에 없음)
        # MX, TXT 레코드만 수집 (이메일 시스템, SPF 분석용)
        for record_type in ["MX", "TXT"]:
            try:
                result = subprocess.run(
                    ["dig", "+short", f"-t{record_type}", domain],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    records[record_type] = [
                        line.strip()
                        for line in result.stdout.strip().splitlines()
                        if line.strip()
                    ]
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                # dig가 없거나 DNS 조회 실패 시 skip
                pass

        return records

    # ── 고가치 타겟 식별 ────────────────────────────────────

    def identify_high_value_targets(
        self,
        profiles: list[GitHubProfile] | None = None,
    ) -> list[HighValueTarget]:
        """권한이 높을 것으로 추정되는 직원을 식별한다.

        Args:
            profiles: 분석할 프로필 목록. None이면 내부 캐시 사용.

        Returns:
            위험도 점수 내림차순으로 정렬된 HighValueTarget 목록.
        """
        source = profiles if profiles is not None else self._analyzed_profiles

        targets: list[HighValueTarget] = []

        for profile in source:
            if profile.risk_score < 20:
                continue  # 낮은 위험도는 제외

            # 권한 수준 추정
            access_level = min(10, profile.risk_score // 10)

            # 공격 표면 설명
            attack_surface: list[str] = []
            if profile.exposed_emails:
                attack_surface.append(
                    f"이메일 {profile.exposed_emails[0]} — 스피어피싱 표적"
                )
            if profile.peak_activity_hour >= 0:
                attack_surface.append(
                    f"피크 활동 {profile.peak_activity_hour}:00 "
                    f"— 이 시간 피싱 클릭률 최대화"
                )
            if profile.security_relevant_repos:
                attack_surface.append(
                    f"민감 저장소 접근: "
                    f"{', '.join(profile.security_relevant_repos[:2])}"
                )
            if profile.org_memberships:
                attack_surface.append(
                    f"조직 내부 접근: "
                    f"{', '.join(profile.org_memberships[:2])}"
                )

            # 권장 공격 벡터 (레드팀용)
            vectors: list[str] = []
            if profile.exposed_emails:
                vectors.append(
                    f"스피어피싱 ({profile.peak_activity_hour}:00 전송, "
                    f"{profile.exposed_emails[0]})"
                )
            if profile.security_relevant_repos:
                vectors.append("GitHub 저장소 시크릿 스캔 (`.env`, `config.yaml`)")
            if "HCL" in profile.primary_languages or "Terraform" in profile.bio.lower():
                vectors.append("Terraform state 파일에서 인프라 시크릿 탈취")

            # 이메일 마스킹 (PII 보호)
            display_id = f"@{profile.username}"
            masked_email = (
                _mask_email(profile.exposed_emails[0])
                if profile.exposed_emails
                else ""
            )
            identifier = (
                f"{display_id} ({masked_email})" if masked_email else display_id
            )

            targets.append(HighValueTarget(
                identifier=identifier,
                display_name=profile.name or profile.username,
                estimated_access_level=access_level,
                privilege_indicators=profile.risk_reasons,
                attack_surface=attack_surface,
                recommended_vectors=vectors,
                risk_score=profile.risk_score,
            ))

        # 위험도 내림차순 정렬
        targets.sort(key=lambda t: t.risk_score, reverse=True)

        logger.info("고가치 타겟 식별: %d명 / %d명 분석됨", len(targets), len(source))

        return targets

    # ── 리포트 생성 ────────────────────────────────────────

    def format_behavioral_report(
        self,
        targets: list[HighValueTarget],
        footprint: SocialFootprint | None = None,
    ) -> str:
        """행동 생체인식 분석 리포트를 마크다운으로 생성한다."""
        lines = ["## 행동 생체인식 분석 리포트", ""]

        if footprint:
            lines += [
                f"### 대상 조직: {footprint.company_domain}",
                f"- GitHub 조직: `{footprint.github_org_name}`",
                f"- 공개 저장소: {footprint.public_repos_count}개",
                f"- 탐지된 직원: {len(footprint.discovered_employees)}명",
                f"- 기술 스택 힌트: {', '.join(footprint.tech_stack_hints[:8])}",
                "",
            ]

            if footprint.dns_records:
                lines.append("**DNS 기록:**")
                for rtype, rdata in footprint.dns_records.items():
                    for rd in rdata[:3]:
                        lines.append(f"- {rtype}: {rd[:80]}")
                lines.append("")

        lines += [
            f"### 고가치 타겟 {len(targets)}명",
            "",
        ]

        for i, target in enumerate(targets, 1):
            lines += [
                f"#### {i}. {target.display_name} ({target.identifier})",
                f"- **추정 권한 수준**: {target.estimated_access_level}/10",
                f"- **위험도 점수**: {target.risk_score}/100",
                "",
                "**권한 지표:**",
            ]
            for indicator in target.privilege_indicators:
                lines.append(f"- {indicator}")

            lines.append("")
            lines.append("**공격 표면:**")
            for surface in target.attack_surface:
                lines.append(f"- {surface}")

            if target.recommended_vectors:
                lines.append("")
                lines.append("**권장 공격 벡터 (레드팀용):**")
                for vector in target.recommended_vectors:
                    lines.append(f"- {vector}")

            lines.append("")

        return "\n".join(lines)

    # ── 내부 HTTP 헬퍼 ──────────────────────────────────────

    def _github_get(
        self,
        path: str,
        params: dict[str, str] | None = None,
    ) -> Any:
        """GitHub API GET 요청 (공개 엔드포인트만)."""
        url = f"{_GITHUB_API}{path}"
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{query}"

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "VXIS-Security-Scanner/1.0",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                logger.debug("GitHub API 404: %s", path)
            elif exc.code == 403:
                logger.warning("GitHub API rate limit 초과: %s", path)
            else:
                logger.debug("GitHub API 오류 %d: %s", exc.code, path)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.debug("GitHub API 연결 실패: %s — %s", path, exc)

        return None


# ── 헬퍼 함수 ────────────────────────────────────────────────────

def _mask_email(email: str) -> str:
    """이메일 주소를 부분 마스킹한다 (PII 보호).

    Example:
        "john.doe@example.com" → "j***e@example.com"
    """
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"
