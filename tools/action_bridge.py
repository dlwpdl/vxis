"""Action Bridge — 인텔리전스를 실제 코드 변경으로 연결하는 브릿지.

수집된 인텔 → 자동 액션:
1. CVE/공급망 위협 → GitHub Issue 자동 생성 + 의존성 스캔
2. Upstream 승인된 제안 → Issue + 코드 변경 제안
3. Discovery 새 도구 → watch_targets.toml 자동 추가
4. Domain 트렌드 → 에이전트 벡터 추가 제안

핵심 원칙:
- 코드를 직접 수정하지 않음 → Issue/PR 제안만
- 사람이 최종 승인 후 머지
- 모든 액션에 근거(시그널/CVE/제안) 연결
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ActionItem:
    """실행할 액션 하나."""

    action_type: str  # "issue", "watch_target", "dependency_alert", "vector_suggest"
    title: str
    body: str
    labels: list[str] = field(default_factory=list)
    source: str = ""  # 어떤 시스템에서 왔는지
    priority: str = "medium"  # critical, high, medium, low
    metadata: dict = field(default_factory=dict)


@dataclass
class ActionResult:
    """액션 실행 결과."""

    action: ActionItem
    success: bool
    result_url: str = ""  # GitHub Issue URL 등
    error: str = ""


# ── 1. CVE → GitHub Issue 자동 생성 ──────────────────────────────


def create_cve_issues_from_state(state_file: str = "") -> list[ActionResult]:
    """CVE Watch 상태에서 critical CVE를 GitHub Issue로 생성."""
    state_path = Path(state_file) if state_file else Path(".cve_watch_state.json")
    if not state_path.exists():
        logger.info("[ActionBridge] CVE 상태 파일 없음")
        return []

    # CISA KEV에서 직접 생성
    return _create_issues_from_cisa_kev()


def _create_issues_from_cisa_kev() -> list[ActionResult]:
    """CISA KEV 시그널에서 GitHub Issue 생성."""
    results: list[ActionResult] = []

    signals_dir = Path(__file__).parent.parent / "domain_intel" / "signals_cache"
    if not signals_dir.exists():
        return results

    # 최신 시그널 파일 로드
    signal_files = sorted(signals_dir.glob("signals-*.json"), reverse=True)
    if not signal_files:
        return results

    signals = json.loads(signal_files[0].read_text())
    kev_signals = [s for s in signals if s.get("source") == "cisa_kev"]

    for sig in kev_signals:
        meta = sig.get("metadata", {})
        cve_id = meta.get("cve_id", "")
        if not cve_id:
            continue

        # 이미 이슈가 있는지 확인
        if _issue_exists(cve_id):
            logger.debug("[ActionBridge] Issue already exists: %s", cve_id)
            continue

        vendor = meta.get("vendor", "Unknown")
        product = meta.get("product", "Unknown")
        action_required = meta.get("action", "Apply vendor patch")
        due_date = meta.get("due_date", "")
        ransomware = meta.get("known_ransomware", "Unknown")

        item = ActionItem(
            action_type="issue",
            title=f"[CISA KEV] {cve_id} — {vendor} {product}",
            body=f"""## CISA Known Exploited Vulnerability

| 항목 | 내용 |
|------|------|
| **CVE** | `{cve_id}` |
| **벤더** | {vendor} |
| **제품** | {product} |
| **랜섬웨어 연관** | {ransomware} |
| **조치 기한** | {due_date} |
| **NVD** | https://nvd.nist.gov/vuln/detail/{cve_id} |

### 필요한 조치
{action_required}

### VXIS 영향 확인 체크리스트
- [ ] 이 제품을 VXIS가 사용하는지 확인 (플러그인, 의존성)
- [ ] 고객 타겟에 이 제품이 있는지 확인
- [ ] nuclei 템플릿 존재 여부 확인
- [ ] 패치/업데이트 적용

### 출처
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- 자동 생성: VXIS Action Bridge

---
*이 이슈는 Domain Intelligence Engine이 자동 생성했습니다.*""",
            labels=["cve-watch", "security", "automated"],
            source="domain_intel/cisa_kev",
            priority="critical" if ransomware != "Unknown" else "high",
            metadata=meta,
        )

        result = _create_github_issue(item)
        results.append(result)

    return results


# ── 2. Upstream 제안 → GitHub Issue 변환 ─────────────────────────


def convert_proposals_to_issues() -> list[ActionResult]:
    """승인된 Upstream Watch 제안을 GitHub Issue로 변환."""
    results: list[ActionResult] = []

    decisions_file = Path(__file__).parent.parent / "upstream_watch" / "decisions.json"
    if not decisions_file.exists():
        logger.info("[ActionBridge] decisions.json 없음")
        return results

    decisions = json.loads(decisions_file.read_text())

    for decision in decisions:
        if decision.get("action") != "approved":
            continue
        if decision.get("issue_created"):
            continue  # 이미 이슈 생성됨

        proposal_id = decision.get("proposal_id", "")
        reason = decision.get("reason", "")

        # 제안 상세 정보 로드
        proposal_data = _load_proposal_details(proposal_id)
        if not proposal_data:
            continue

        title = proposal_data.get("title", proposal_id)
        description = proposal_data.get("description", "")
        category = proposal_data.get("category", "")
        source_ref = proposal_data.get("source_ref", "")
        vxis_files = proposal_data.get("vxis_files", [])

        files_list = "\n".join(f"- `{f}`" for f in vxis_files) if vxis_files else "- 분석 필요"

        item = ActionItem(
            action_type="issue",
            title=f"[Upstream] {title}",
            body=f"""## Upstream Watch — 승인된 제안

**카테고리:** {category}
**승인 사유:** {reason}
**출처:** {source_ref}

### 설명
{description}

### 영향받는 VXIS 파일
{files_list}

### 구현 체크리스트
- [ ] 영향 범위 확인
- [ ] 코드 변경 구현
- [ ] 테스트 작성
- [ ] PR 생성

### 참고
- 제안 ID: `{proposal_id}`
- AGPL 코드 복사 금지 — 컨셉만 참고

---
*이 이슈는 Upstream Watch Action Bridge가 자동 생성했습니다.*""",
            labels=["upstream-watch", category, "automated", "claude-implement"],
            source=f"upstream_watch/{proposal_id}",
            priority="high",
        )

        result = _create_github_issue(item)
        results.append(result)

        # 이슈 생성 기록
        if result.success:
            decision["issue_created"] = True
            decision["issue_url"] = result.result_url

    # decisions.json 업데이트
    if results:
        decisions_file.write_text(json.dumps(decisions, ensure_ascii=False, indent=2))

    return results


# ── 3. Discovery → watch_targets.toml 자동 추가 ─────────────────


def add_discovered_tools_to_watch() -> list[ActionResult]:
    """Discovery에서 발견된 새 도구를 watch_targets.toml에 추가."""
    results: list[ActionResult] = []

    # 최신 weekly 다이제스트에서 discovery 결과 추출
    digests_dir = Path(__file__).parent.parent / "upstream_watch" / "digests"
    if not digests_dir.exists():
        return results

    weekly_files = sorted(digests_dir.glob("weekly-*.md"), reverse=True)
    if not weekly_files:
        return results

    latest = weekly_files[0].read_text()

    # "New Tool Discovery" 섹션 파싱
    discovered = _parse_discovery_from_digest(latest)
    if not discovered:
        logger.info("[ActionBridge] 발견된 새 도구 없음")
        return results

    # watch_targets.toml에 추가
    toml_path = Path(__file__).parent.parent / "upstream_watch" / "watch_targets.toml"

    for repo_name, stars, reason in discovered[:5]:  # 최대 5개
        owner, repo = repo_name.split("/", 1)

        # 이미 감시 중인지 확인
        if _is_already_watched(toml_path, repo_name):
            continue

        # TOML에 추가
        _add_to_watch_targets(toml_path, owner, repo, stars, reason)

        results.append(ActionResult(
            action=ActionItem(
                action_type="watch_target",
                title=f"[Discovery] {repo_name} 감시 추가 ({stars} stars)",
                body=reason,
                source="upstream_watch/discovery",
            ),
            success=True,
            result_url=f"https://github.com/{repo_name}",
        ))

    return results


# ── 4. 의존성 스캔 (CVE 매칭) ────────────────────────────────────


def scan_dependencies_for_cves() -> list[ActionResult]:
    """VXIS 의존성이 알려진 CVE에 영향받는지 스캔."""
    results: list[ActionResult] = []

    # pyproject.toml에서 의존성 추출
    pyproject = Path(__file__).parent.parent.parent / "pyproject.toml"
    if not pyproject.exists():
        return results

    content = pyproject.read_text()
    deps = _extract_dependencies(content)

    # CISA KEV 시그널과 매칭
    signals_dir = Path(__file__).parent.parent / "domain_intel" / "signals_cache"
    if not signals_dir.exists():
        return results

    signal_files = sorted(signals_dir.glob("signals-*.json"), reverse=True)
    if not signal_files:
        return results

    signals = json.loads(signal_files[0].read_text())

    for sig in signals:
        if sig.get("source") != "cisa_kev":
            continue

        meta = sig.get("metadata", {})
        product = meta.get("product", "").lower()
        vendor = meta.get("vendor", "").lower()
        cve_id = meta.get("cve_id", "")

        # 의존성과 매칭
        for dep_name, dep_version in deps:
            dep_lower = dep_name.lower()
            if product in dep_lower or dep_lower in product or vendor in dep_lower:
                item = ActionItem(
                    action_type="dependency_alert",
                    title=f"[DEP ALERT] {dep_name} may be affected by {cve_id}",
                    body=f"""## 의존성 취약점 경고

| 항목 | 내용 |
|------|------|
| **의존성** | `{dep_name}` (현재: {dep_version}) |
| **CVE** | `{cve_id}` |
| **제품** | {meta.get('vendor', '')} {meta.get('product', '')} |

### 확인 필요
- 이 의존성이 해당 CVE에 실제로 영향받는지 확인
- 패치 버전이 있다면 업그레이드

---
*VXIS Action Bridge 자동 의존성 스캔*""",
                    labels=["dependency", "security", "automated"],
                    source="action_bridge/dep_scan",
                    priority="critical",
                )

                result = _create_github_issue(item)
                results.append(result)

    return results


# ── 5. Domain 트렌드 → 벡터 추가 제안 ────────────────────────────


def suggest_vectors_from_trends() -> list[ActionResult]:
    """Domain Intel 트렌드에서 새 공격 벡터 추가 제안."""
    results: list[ActionResult] = []

    digests_dir = Path(__file__).parent.parent / "domain_intel" / "digests"
    if not digests_dir.exists():
        return results

    # 최신 weekly 리포트에서 트렌드 추출
    weekly_files = sorted(digests_dir.glob("weekly-*.md"), reverse=True)
    if not weekly_files:
        return results

    content = weekly_files[0].read_text()

    # 트렌드에서 벡터 키워드 추출
    _vector_keywords = {
        "ssrf": "SSRF", "xss": "XSS", "sqli": "SQL Injection",
        "supply chain": "Supply Chain", "prototype pollution": "Prototype Pollution",
        "mcp": "MCP Protocol", "jwt": "JWT", "graphql": "GraphQL",
        "websocket": "WebSocket", "http/3": "HTTP/3", "quic": "QUIC",
        "ai agent": "AI Agent Security", "llm": "LLM Injection",
        "deserialization": "Deserialization", "race condition": "Race Condition",
    }

    found_vectors: set[str] = set()
    content_lower = content.lower()
    for keyword, vector_name in _vector_keywords.items():
        if keyword in content_lower:
            found_vectors.add(vector_name)

    if not found_vectors:
        return results

    # 현재 벡터 레지스트리 확인
    try:
        from pathlib import Path as P
        vectors_file = P(__file__).parent.parent.parent / "src" / "vxis" / "scoring" / "vectors.py"
        if vectors_file.exists():
            existing = vectors_file.read_text().lower()
            found_vectors = {v for v in found_vectors if v.lower() not in existing}
    except Exception:
        pass

    if not found_vectors:
        return results

    vectors_list = "\n".join(f"- {v}" for v in sorted(found_vectors))
    item = ActionItem(
        action_type="issue",
        title=f"[Trend] 트렌드에서 발견된 새 공격 벡터 {len(found_vectors)}개",
        body=f"""## Domain Intelligence — 새 벡터 추가 제안

이번 주 보안 트렌드 분석에서 VXIS 벡터 레지스트리에 없는 공격 벡터가 감지되었습니다.

### 추가 제안 벡터
{vectors_list}

### 근거
Domain Intelligence Weekly Report에서 추출.

### 구현 체크리스트
- [ ] 각 벡터의 실제 위협 수준 평가
- [ ] `scoring/vectors.py`에 벡터 추가
- [ ] 관련 에이전트에 테스트 로직 추가
- [ ] 벤치마크 재실행

---
*VXIS Action Bridge 자동 생성*""",
        labels=["enhancement", "vectors", "automated"],
        source="domain_intel/trends",
        priority="medium",
    )

    result = _create_github_issue(item)
    results.append(result)
    return results


# ── GitHub Issue 생성 헬퍼 ────────────────────────────────────────


def _create_github_issue(item: ActionItem) -> ActionResult:
    """GitHub Issue 생성."""
    if not shutil.which("gh"):
        logger.warning("[ActionBridge] gh CLI 없음 — Issue 생성 건너뜀")
        return ActionResult(action=item, success=False, error="gh CLI not found")

    labels_str = ",".join(item.labels) if item.labels else ""

    cmd = [
        "gh", "issue", "create",
        "--title", item.title,
        "--body", item.body,
    ]
    if labels_str:
        cmd.extend(["--label", labels_str])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            url = proc.stdout.strip()
            logger.info("[ActionBridge] Issue 생성: %s → %s", item.title[:50], url)
            return ActionResult(action=item, success=True, result_url=url)
        else:
            error = proc.stderr[:200]
            logger.warning("[ActionBridge] Issue 생성 실패: %s", error)
            return ActionResult(action=item, success=False, error=error)
    except Exception as exc:
        return ActionResult(action=item, success=False, error=str(exc))


def _issue_exists(search_term: str) -> bool:
    """GitHub Issue에 이미 같은 제목이 있는지 확인."""
    if not shutil.which("gh"):
        return False
    try:
        proc = subprocess.run(
            ["gh", "issue", "list", "--search", search_term, "--state", "all", "--limit", "1"],
            capture_output=True, text=True, timeout=15,
        )
        return bool(proc.stdout.strip())
    except Exception:
        return False


# ── 유틸리티 ─────────────────────────────────────────────────────


def _load_proposal_details(proposal_id: str) -> dict | None:
    """제안 상세 정보 로드."""
    proposals_dir = Path(__file__).parent.parent / "upstream_watch" / "proposals"
    if not proposals_dir.exists():
        return None

    for json_file in proposals_dir.glob("*.json"):
        try:
            data = json.loads(json_file.read_text())
            proposals = data.get("proposals", [])
            for p in proposals:
                if p.get("id") == proposal_id:
                    return p
        except Exception:
            continue
    return None


def _parse_discovery_from_digest(content: str) -> list[tuple[str, int, str]]:
    """다이제스트에서 Discovery 섹션 파싱."""
    results: list[tuple[str, int, str]] = []
    in_discovery = False

    for line in content.split("\n"):
        if "New Tool Discovery" in line or "Discovery" in line:
            in_discovery = True
            continue
        if in_discovery and line.startswith("| ") and "/" in line:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 4:
                repo = parts[1]
                try:
                    stars = int(parts[2].replace(",", ""))
                except ValueError:
                    stars = 0
                reason = parts[-2] if len(parts) >= 5 else ""
                if "/" in repo and stars > 0:
                    results.append((repo, stars, reason))
        elif in_discovery and line.startswith("#"):
            break  # 다른 섹션 시작

    return results


def _is_already_watched(toml_path: Path, repo_name: str) -> bool:
    """이미 감시 중인 레포인지 확인."""
    if not toml_path.exists():
        return False
    content = toml_path.read_text()
    return repo_name in content


def _add_to_watch_targets(toml_path: Path, owner: str, repo: str, stars: int, reason: str) -> None:
    """watch_targets.toml에 새 타겟 추가."""
    now = datetime.now(timezone.utc).isoformat()
    entry = f"""
[[targets]]
owner = "{owner}"
repo = "{repo}"
reason = "Auto-discovered: {reason} ({stars} stars)"
enabled = true
watch_releases = true
watch_commits = true
branches = ["main"]
relevance_tags = ["ai", "security", "pentest"]
added_at = "{now}"
notes = "Discovered by VXIS Domain Intelligence"
"""

    if toml_path.exists():
        content = toml_path.read_text()
    else:
        content = "# VXIS Upstream Watch — Dynamic Targets\n"

    content += entry
    toml_path.write_text(content)
    logger.info("[ActionBridge] watch_targets에 추가: %s/%s", owner, repo)


def _extract_dependencies(pyproject_content: str) -> list[tuple[str, str]]:
    """pyproject.toml에서 의존성 이름+버전 추출."""
    deps: list[tuple[str, str]] = []
    in_deps = False

    for line in pyproject_content.split("\n"):
        if "dependencies" in line and "[" in line:
            in_deps = True
            continue
        if in_deps and line.strip() == "]":
            in_deps = False
            continue
        if in_deps:
            line = line.strip().strip('"').strip("'").strip(",")
            if not line or line.startswith("#"):
                continue
            # "pydantic>=2.9,<3" → ("pydantic", ">=2.9,<3")
            match = re.match(r"([a-zA-Z0-9_\-\.]+)(.*)", line)
            if match:
                name = match.group(1)
                version = match.group(2).strip()
                deps.append((name, version))

    return deps


# ── Master Runner ────────────────────────────────────────────────


def run_all_actions() -> list[ActionResult]:
    """모든 Action Bridge 액션을 실행."""
    all_results: list[ActionResult] = []

    logger.info("[ActionBridge] === Action Bridge 시작 ===")

    # 1. CISA KEV → Issues
    logger.info("[ActionBridge] 1. CISA KEV → GitHub Issues")
    results = create_cve_issues_from_state()
    all_results.extend(results)
    logger.info("[ActionBridge]    → %d issues created", sum(1 for r in results if r.success))

    # 2. Upstream 승인 제안 → Issues
    logger.info("[ActionBridge] 2. Upstream 승인 제안 → Issues")
    results = convert_proposals_to_issues()
    all_results.extend(results)
    logger.info("[ActionBridge]    → %d issues created", sum(1 for r in results if r.success))

    # 3. Discovery → watch_targets
    logger.info("[ActionBridge] 3. Discovery → watch_targets 추가")
    results = add_discovered_tools_to_watch()
    all_results.extend(results)
    logger.info("[ActionBridge]    → %d targets added", sum(1 for r in results if r.success))

    # 4. 의존성 CVE 스캔
    logger.info("[ActionBridge] 4. 의존성 CVE 스캔")
    results = scan_dependencies_for_cves()
    all_results.extend(results)
    logger.info("[ActionBridge]    → %d alerts", sum(1 for r in results if r.success))

    # 5. 트렌드 → 벡터 제안
    logger.info("[ActionBridge] 5. 트렌드 → 벡터 추가 제안")
    results = suggest_vectors_from_trends()
    all_results.extend(results)
    logger.info("[ActionBridge]    → %d suggestions", sum(1 for r in results if r.success))

    success_count = sum(1 for r in all_results if r.success)
    logger.info(
        "[ActionBridge] === 완료: %d/%d 액션 성공 ===",
        success_count, len(all_results),
    )

    return all_results
