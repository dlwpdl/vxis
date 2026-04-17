---
name: Payloads as external data files (code freeze / data-only updates)
type: decision
status: draft
when_to_read: 페이로드 추가·수정 위치 / skills 코드 freeze 전략 / round=1|2|3 로테이션 데이터화 / non-rotation datasets / growth loop JSON 재배선
updated: 2026-04-17
sources:
  - ../../../.claude/projects/-Users-eliot-Desktop---vxis/memory/feedback_code_freeze.md
  - ../../src/vxis/agent/skills/_payload_loader.py
  - ../../src/vxis/agent/skills/test_injection.py
  - ../../src/vxis/agent/skills/test_xss.py
  - ../../src/vxis/growth/apply.py
  - ../../src/vxis/core/enricher.py
related:
  - ./006_code_freeze_data_only_updates.md
  - ./008_finding_precision_smoothing.md
  - ../concepts/payload_rotation.md
  - ../entities/skills/test_injection.md
  - ../entities/skills/test_xss.md
code_anchors:
  - src/vxis/agent/skills/_payload_loader.py:load_skill_payloads
  - src/vxis/agent/skills/_payload_loader.py:load_skill_dataset
  - src/vxis/agent/skills/test_injection.py:_payloads_for_round
  - src/vxis/agent/skills/test_xss.py:_xss_payloads_for_round
  - src/vxis/growth/apply.py:_apply_skill_payload
  - src/vxis/core/enricher.py:_load_json
---
# ADR-007 (DRAFT) — Payloads as External Data Files

## 핵심 사실
| 항목 | 값 |
|---|---|
| 대상 상수 | 14 skills (2 rotation + 12 non-rotation) |
| 데이터 포맷 | JSON (stdlib) — YAML 기각 (`pyyaml` 미설치·SCFW 위험) |
| 위치 | `src/vxis/data/payloads/` — `importlib.resources` 로드 |
| 로더 | `src/vxis/agent/skills/_payload_loader.py` — pydantic v2 검증, `@cache` 싱글톤 |
| API | `load_skill_payloads(skill, round)` (rotation) · `load_skill_dataset(skill, key)` (non-rotation) |
| round 로테이션 | JSON 내 `rounds: {"1":[...],"2":[...],"3":[...]}` 키로 보존 |
| 비-로테이션 | JSON 내 `datasets: {<key>: [...]}` 키로 — creds·paths·headers·regex 등 |
| 마이그레이션 | Phase 1~9 완료 (2026-04-17, 14/14 skills) |
| 실패 모드 | 파일 없으면 `PayloadDataMissingError`, dataset key 없으면 `PayloadDatasetMissingError` (모두 fail-loud) |

## TL;DR
페이로드·데이터 상수를 `src/vxis/data/payloads/*.json` 으로 분리. 로더는 `importlib.resources` + pydantic 검증 + lazy `@cache`. `execute()` 본문은 무변경 (`list[dict]`·`list[Any]` 반환형 불변) — 이게 freeze 보장의 핵심. rotation 스킬은 `load_skill_payloads(name, round)` 로, 비-rotation 은 `load_skill_dataset(name, key)` 로 접근. Growth loop 의 `_apply_skill_payload` 은 `.py` 마커 삽입 대신 JSON append 로 재배선 (Phase 10).

## Context

ADR-006 (Code Freeze) 에 따라 skills 의 `execute()` 는 freeze. 하지만 현재 14개 skill 이 모두 페이로드 상수를 하드코딩 — 새 페이로드 = 코드 commit. freeze 원칙 위반.

**Audit 결과 (14 skills, 28+ 상수):**
- `test_injection.py`: `PAYLOADS`, `PAYLOADS_ROUND2`, `PAYLOADS_ROUND3` (round 지원)
- `test_xss.py`: `XSS_PAYLOADS`, `XSS_PAYLOADS_ROUND2`, `XSS_PAYLOADS_ROUND3` (round 지원)
- `test_ssrf`, `test_sensitive_files`, `test_api_security`, `test_crypto`, `test_auth_deep`, `test_business_logic`, `test_csrf`, `test_infra`, `test_misconfig`, `attempt_auth`, `enumerate_endpoints`, `post_auth_enum` — round 미지원, 다중 상수 보유.

**기존 precedent:** `src/vxis/core/enricher.py` 가 이미 `importlib.resources.files("vxis.data")` 로 `mitre_attack.json` 로드. 동일 패턴을 `vxis.data.payloads` 로 확장.

**SCFW 제약:** `pyyaml` 설치 금지. stdlib `json` 만 사용.

**Growth 연결:** `src/vxis/growth/apply.py::_apply_skill_payload` 은 `.py` 파일에 `# --- AUTO-UPDATED PAYLOADS BELOW` 마커로 직접 삽입 → Phase 10 에서 JSON append 로 재배선.

## Options

**A. YAML 단일 포맷** (기각) — `pyyaml` 설치 필요·SCFW 위험·기존 precedent 불일치.
**B. JSON 단일 포맷** (선택) — stdlib only, enricher.py 패턴 재사용, syntax validation 빠름.
**C. JSON + 선택 YAML override** (보류) — 이번 리팩터는 B 고정.
**D. 외부 저장소 fetch** (기각) — 부트스트랩 복잡도 ↑·offline 불가.

## Decision

**B. JSON 단일 포맷.** `src/vxis/data/payloads/<skill>.json` + 신규 `_payload_loader.py` (freeze 대상). Pydantic 모델로 schema 검증 (`Any` 금지). `round` 시맨틱은 JSON 내부 구조로 유지. `_payloads_for_round(r)` 반환형 `list[dict]` 불변 → `execute()` 본문 무변경.

## Consequences

**긍정:** 페이로드 PR = 데이터 PR. 코드 diff 0. AI 할루시네이션 감소. Growth loop 가 JSON 에 안전 append (pydantic 게이트).
**부정:** Import 시 I/O 증가 (캐시 후 무시 가능). Test fixture mocking 은 `monkeypatch` helper 필요. `growth/apply.py` 재작성 (Phase 10).

## Verification gate (ADR-008 통합)

이 refactor 는 **behavior-preserving** — 반환형 불변, byte-identical 페이로드·데이터. 따라서 각 phase 의 검증 gate:

1. **1차 증거 (필수)**: `pytest tests/agent/skills/test_payload_loader.py` — 기존 `.py` 상수와 JSON 로더 출력이 byte-identical 임을 증명. Phase 3-9 는 `TestSkillDataset` 클래스 (24 parametrize case + tuple-tolerant normalize compare 9 skills) 로 커버.
2. **2차 보조**: 5벡터 스코어 — ADR-008 적용 후 noise 범위 (±65pt total) 내면 통과. regression 판정 기준 아님.

Phase 1 (injection) 실측 (Juice Shop, 2026-04-17):
- baseline (pre-refactor, ADR-008 retroactive): 432.33 / C
- after-phase-1 (post-refactor, ADR-008 retroactive): 418.04 / C
- Noise run (pre-refactor): 482.33 / C
- Delta baseline↔after: -14pt (noise 범위 내), grade 불변 → **pass**.

Phase 3-9 (12 non-rotation skills) 검증 (2026-04-17):
- 49/49 loader tests pass (TestInjectionParity·TestXssParity·TestLoaderContract·TestSkillDataset)
- 24/24 dataset parity (byte-identical via AST literal_eval of HEAD vs runtime module constant, tuple-normalized compare)
- 5벡터 스코어 실측은 Phase 10 (growth rewire) 후 일괄 수행 — Phase 3-9 는 `execute()` path 무변경이라 behavior-preserving 자명

`feedback_test_score_sync_process.md` 의 "behavior-preserving refactor" 조항이 이 gate 를 정식화.

## Phases

| Phase | 내용 | 상태 |
|---|---|---|
| 1 | Loader + `injection.json` + `test_injection.py` 교체 + 단위 테스트 | ✅ `e6a5a99` (2026-04-17) |
| 2 | XSS migration (`test_xss.py` + `xss.json`) | ✅ `760e3e2` (2026-04-17) |
| 3-9 | 12 non-rotation skills 일괄 배치 — `datasets` 확장 + `PayloadDatasetMissingError` 추가 | ✅ (2026-04-17, single commit by directive) |
| 10 | Growth pipeline rewire (`_apply_skill_payload` → JSON append) | ⏳ |
| 11 | ADR 활성화 (`draft` → `active`), CLAUDE.md 포인터 갱신 | ⏳ |

Phase 3-9 영향 skills (alphabetical): `attempt_auth`, `enumerate_endpoints`, `post_auth_enum`, `test_api_security`, `test_auth_deep`, `test_business_logic`, `test_crypto`, `test_csrf`, `test_infra`, `test_misconfig`, `test_sensitive_files`, `test_ssrf`. 총 24 datasets (`default_creds`, `sqli_creds`, `login_paths`, `reset_paths`, `common_paths`, `auth_paths`, `sensitive_paths`, `jwt_alg_none_headers`, `state_changing_paths`, `ssrf_payloads`, `url_params`, `mass_assign_fields`, `verb_tamper_paths`, `required_headers`, `debug_paths`, `cors_origins`, `logic_tests`, `secret_patterns`, `js_paths`, `git_paths`, `env_paths`, `cloud_endpoints`, `subdomain_prefixes` + `reset_paths` in `test_auth_deep`).

## Out of Scope

- YAML 지원 (SCFW 회피)
- Hot-reload / file-watcher (scan lifetime 캐시로 충분)
- CVE auto-fetch → payload PR 파이프라인 (별도 ADR)
- Severity oracle / detect regex 외부화 (별도 ADR)
- `primitives/waf_bypass_db.json` (이미 JSON, 대상 아님)
