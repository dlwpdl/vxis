"""CVE ↔ 타겟 스택 매칭 엔진.

타겟의 기술 스택(Next.js, Vercel, Node.js 등)과 CVE의 영향 범위를 매칭한다.

매칭 전략:
1. CPE 기반 (NVD 소스): cpe:2.3:a:vendor:product:version 파싱
2. 패키지명 기반 (OSV/GitHub 소스): 에코시스템 + 패키지 이름 비교
3. 키워드 기반 (설명/타이틀 텍스트): 기술 이름 부분 문자열 일치

점수 산정 (0.0 ~ 1.0):
- 정확한 CPE vendor/product 일치: 0.9
- 패키지명 완전 일치: 0.85
- 패키지명 부분 일치: 0.6
- 키워드 일치 (타이틀/설명): 0.4
- 버전 범위 일치 보너스: +0.1
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from .cve_entry import CVEEntry

logger = logging.getLogger(__name__)

# agent_memory.json 기본 위치
_DEFAULT_MEMORY_PATH = Path(__file__).parent.parent / "data" / "agent_memory.json"


@dataclass
class TechStackProfile:
    """타겟의 기술 스택 프로파일.

    Attributes:
        target: 타겟 URL 또는 식별자 (e.g., "https://example.com")
        technologies: 기술 이름 목록 (e.g., ["Next.js", "Node.js", "PostgreSQL"])
        versions: 기술별 버전 딕셔너리 (e.g., {"Next.js": "13.4.0"})
        ecosystem_packages: 에코시스템별 패키지 목록
            (e.g., {"npm": ["next", "react"], "PyPI": ["django"]})
    """

    target: str
    technologies: list[str] = field(default_factory=list)
    versions: dict[str, str] = field(default_factory=dict)
    ecosystem_packages: dict[str, list[str]] = field(default_factory=dict)

    def all_tech_names(self) -> list[str]:
        """모든 기술 이름을 소문자로 반환 (검색용)."""
        names = [t.lower() for t in self.technologies]
        for pkgs in self.ecosystem_packages.values():
            names.extend(p.lower() for p in pkgs)
        return names


# CPE 파싱 패턴: cpe:2.3:type:vendor:product:version:...
_CPE_RE = re.compile(
    r"cpe:2\.3:[aoh]:([^:]+):([^:]+):([^:]+)",
    re.IGNORECASE,
)


def _parse_cpe(cpe_str: str) -> tuple[str, str, str]:
    """CPE 2.3 문자열을 (vendor, product, version) 튜플로 파싱.

    파싱 실패 시 빈 문자열 튜플 반환.
    """
    m = _CPE_RE.match(cpe_str)
    if not m:
        return ("", "", "")
    vendor = m.group(1).lower().replace("_", " ")
    product = m.group(2).lower().replace("_", " ")
    version = m.group(3).lower()
    if version == "*":
        version = ""
    return (vendor, product, version)


def _normalize_name(name: str) -> str:
    """기술 이름을 비교용 정규화.

    공백, 하이픈, 점을 제거하고 소문자로 변환.
    예: "Next.js" → "nextjs", "node-js" → "nodejs"
    """
    return re.sub(r"[\s\-._]", "", name.lower())


def _name_matches(cve_name: str, profile_names: list[str]) -> tuple[bool, bool]:
    """CVE에서 추출한 이름이 프로파일 기술 이름과 일치하는지 확인.

    Returns:
        (exact_match, partial_match) 튜플
    """
    norm_cve = _normalize_name(cve_name)
    if not norm_cve:
        return False, False

    for tech in profile_names:
        norm_tech = _normalize_name(tech)
        if not norm_tech:
            continue
        if norm_cve == norm_tech:
            return True, False
        # 부분 일치: cve_name이 tech에 포함되거나 tech가 cve_name에 포함
        if norm_cve in norm_tech or norm_tech in norm_cve:
            return False, True

    return False, False


def _version_in_range(version: str, range_str: str) -> bool:
    """단순 버전 범위 비교 (semver 완전 파싱 없이 숫자 비교만 수행).

    range_str 예시:
        ">=1.0.0 <2.0.0 (fixed)"
        ">=13.0.0"
        "<14.2.3"
    """
    if not version or not range_str:
        return False

    def _ver_tuple(v: str) -> tuple[int, ...]:
        """버전 문자열을 정수 튜플로 변환."""
        parts = re.findall(r"\d+", v.split("-")[0])
        return tuple(int(p) for p in parts[:3]) if parts else (0,)

    try:
        target = _ver_tuple(version)

        # >= 조건
        for m in re.finditer(r">=\s*([\d.]+)", range_str):
            if target < _ver_tuple(m.group(1)):
                return False

        # > 조건 (미포함)
        for m in re.finditer(r"(?<!<)>(?!=)\s*([\d.]+)", range_str):
            if target <= _ver_tuple(m.group(1)):
                return False

        # <= 조건
        for m in re.finditer(r"<=\s*([\d.]+)", range_str):
            if target > _ver_tuple(m.group(1)):
                return False

        # < 조건 (fixed 포함)
        for m in re.finditer(r"<(?!=)\s*([\d.]+)", range_str):
            if target >= _ver_tuple(m.group(1)):
                return False

        return True

    except (ValueError, TypeError):
        return False


def _score_cve_against_profile(
    cve: CVEEntry, profile: TechStackProfile
) -> float:
    """CVE 하나와 프로파일 하나의 매칭 점수를 계산한다.

    Returns:
        0.0 ~ 1.0 범위의 매칭 점수.
    """
    best_score = 0.0
    profile_names = profile.all_tech_names()
    version_bonus = 0.0

    # ─── 1. CPE 기반 매칭 (NVD 소스) ───────────────────────────────
    for cpe in cve.affected_products:
        if not cpe.startswith("cpe:"):
            continue
        vendor, product, cpe_version = _parse_cpe(cpe)
        if not product:
            continue

        exact_v, partial_v = _name_matches(vendor, profile_names)
        exact_p, partial_p = _name_matches(product, profile_names)

        if exact_v or exact_p:
            score = 0.9
        elif partial_v or partial_p:
            score = 0.6
        else:
            continue

        # 버전 범위 보너스
        tech_name = next(
            (t for t in profile.technologies
             if _normalize_name(t) in (_normalize_name(vendor), _normalize_name(product))),
            None,
        )
        if tech_name and tech_name in profile.versions:
            target_ver = profile.versions[tech_name]
            for ver_range in cve.affected_versions:
                if _version_in_range(target_ver, ver_range):
                    version_bonus = 0.1
                    break

        best_score = max(best_score, score)

    # ─── 2. 패키지명 기반 매칭 (OSV/GitHub 소스) ─────────────────────
    for product_str in cve.affected_products:
        if product_str.startswith("cpe:"):
            continue

        # "ecosystem/package" 또는 "package" 형식
        parts = product_str.split("/", 1)
        pkg_name = parts[-1].lower()
        pkg_ecosystem = parts[0].lower() if len(parts) == 2 else ""

        exact, partial = _name_matches(pkg_name, profile_names)

        if exact:
            score = 0.85
            # 에코시스템 패키지 목록과 대조하여 버전 확인
            if pkg_ecosystem:
                for eco, pkgs in profile.ecosystem_packages.items():
                    if eco.lower() == pkg_ecosystem:
                        for pp in pkgs:
                            if _normalize_name(pp) == _normalize_name(pkg_name):
                                # 버전 확인
                                pkg_ver = profile.versions.get(pp, "")
                                for ver_range in cve.affected_versions:
                                    if pkg_ver and _version_in_range(pkg_ver, ver_range):
                                        version_bonus = 0.1
                                        break
        elif partial:
            score = 0.6
        else:
            continue

        best_score = max(best_score, score)

    # ─── 3. 키워드 기반 매칭 (텍스트 분석) ──────────────────────────
    if best_score < 0.4:
        text = f"{cve.title} {cve.description}".lower()
        for tech in profile.technologies:
            norm = _normalize_name(tech)
            # 단어 경계 체크 (최소 4자 이상)
            if len(norm) >= 4 and norm in re.sub(r"[\s\-._]", "", text):
                best_score = max(best_score, 0.4)
                break
            # 원본 이름도 체크 (공백 포함)
            if tech.lower() in text:
                best_score = max(best_score, 0.4)
                break

    final_score = min(1.0, best_score + version_bonus)
    return final_score


def match_cve(
    cve: CVEEntry, profiles: list[TechStackProfile]
) -> list[tuple[TechStackProfile, float]]:
    """CVE를 타겟 프로파일 목록과 매칭하여 점수 목록을 반환한다.

    Args:
        cve: 매칭할 CVE 엔트리.
        profiles: 타겟 기술 스택 프로파일 목록.

    Returns:
        (프로파일, 점수) 튜플 목록. 점수 내림차순 정렬.
        점수가 0인 프로파일은 제외.
    """
    matches: list[tuple[TechStackProfile, float]] = []

    for profile in profiles:
        score = _score_cve_against_profile(cve, profile)
        if score > 0.0:
            matches.append((profile, score))

    # 점수 내림차순 정렬
    matches.sort(key=lambda x: x[1], reverse=True)
    return matches


def load_profiles_from_memory(
    memory_path: str | Path | None = None,
) -> list[TechStackProfile]:
    """agent_memory.json에서 타겟 기술 스택 프로파일을 로드한다.

    agent_memory.json 구조 예시:
    {
        "targets": {
            "https://example.com": {
                "technologies": ["Next.js", "Node.js"],
                "versions": {"Next.js": "13.4.0"},
                "packages": {
                    "npm": ["next", "react", "express"]
                }
            }
        }
    }

    파일이 없거나 파싱 실패 시 빈 리스트를 반환한다.
    """
    path = Path(memory_path) if memory_path else _DEFAULT_MEMORY_PATH

    if not path.exists():
        logger.debug("[Matcher] agent_memory.json 없음: %s", path)
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("[Matcher] agent_memory.json 로드 실패: %s", exc)
        return []

    profiles: list[TechStackProfile] = []

    # 형식 1: {"targets": {"url": {...}}}
    targets = data.get("targets", {})
    if isinstance(targets, dict):
        for target_url, info in targets.items():
            if not isinstance(info, dict):
                continue
            profile = TechStackProfile(
                target=target_url,
                technologies=list(info.get("technologies", [])),
                versions=dict(info.get("versions", {})),
                ecosystem_packages=dict(info.get("packages", {})),
            )
            profiles.append(profile)

    # 형식 2: {"scans": [{"target": "...", "stack": [...]}]}
    scans = data.get("scans", [])
    if isinstance(scans, list):
        for scan in scans:
            if not isinstance(scan, dict):
                continue
            target_url = scan.get("target", "")
            if not target_url:
                continue
            stack: list[str] = scan.get("stack", [])
            profile = TechStackProfile(
                target=target_url,
                technologies=stack,
                versions=dict(scan.get("versions", {})),
            )
            profiles.append(profile)

    logger.info("[Matcher] %d개 타겟 프로파일 로드됨", len(profiles))
    return profiles


def load_profiles_from_dict(profiles_data: list[dict]) -> list[TechStackProfile]:
    """딕셔너리 목록에서 TechStackProfile 목록을 생성한다.

    CLI나 daemon에서 직접 프로파일을 주입할 때 사용.

    Expected dict format:
        {
            "target": "https://example.com",
            "technologies": ["Next.js", "Node.js"],
            "versions": {"Next.js": "13.4.0"},
            "packages": {"npm": ["next"]}
        }
    """
    profiles: list[TechStackProfile] = []
    for item in profiles_data:
        if not isinstance(item, dict) or not item.get("target"):
            continue
        profiles.append(TechStackProfile(
            target=item["target"],
            technologies=list(item.get("technologies", [])),
            versions=dict(item.get("versions", {})),
            ecosystem_packages=dict(item.get("packages", {})),
        ))
    return profiles
