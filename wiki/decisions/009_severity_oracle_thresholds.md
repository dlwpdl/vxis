---
name: ADR-009 — Severity Oracle threshold externalization
type: decision
status: draft
when_to_read: _adjust_severity() 룰 수정 / masking 비율·크기 임계값 조정 / 오라클 파일 freeze 완화 / DSL 유혹 대응
updated: 2026-04-20
sources:
  - ../../src/vxis/agent/skills/test_sensitive_files.py
  - ./006_code_freeze_data_only_updates.md
  - ./007_payloads_as_data_files.md
related:
  - ./007_payloads_as_data_files.md
  - ./006_code_freeze_data_only_updates.md
  - ../concepts/severity_oracle.md
  - ../entities/skills/test_sensitive_files.md
code_anchors:
  - src/vxis/agent/skills/test_sensitive_files.py:_adjust_severity
---
# ADR-009 — Severity Oracle Threshold Externalization

## 핵심 사실
| 항목 | 값 |
|---|---|
| Status | Draft |
| Date | 2026-04-20 |
| 대상 | `test_sensitive_files.py::_adjust_severity()` — 현재 유일 consumer |
| 외부화 대상 | 숫자 임계값 5개 + 경로→기본 severity 맵 |
| 외부화 제외 | Python 분기 로직 (path-prefix match, needle scan) |
| 포맷 | `datasets.severity_thresholds` (JSON) — ADR-007 스키마 재사용 |
| 대안 기각 | 전면 DSL (Option B) — consumer 1개라 과설계 |
| 추후 재평가 | 3+ skill 이 oracle 도입 시 Phase 2 (DSL) 별도 ADR |

## TL;DR
`_adjust_severity()` 안의 5 개 매직 넘버(0.6 masked ratio, 50 health max, 1000 env window, 40 actuator window, 200 metrics max) 와 path→default-severity 맵만 JSON 으로 뽑고, **분기 로직은 코드에 유지**. ADR-007 처럼 `datasets.severity_thresholds` 키 하나로 확장. DSL 은 consumer 늘 때 별도 ADR.

## Context

ADR-007 "Out of Scope" 에 명시된 과제 — severity oracle 외부화. 현황 감사:
- **이미 외부화**: `SECRET_PATTERNS` (test_crypto.json), `sensitive_paths` triple (test_sensitive_files.json), `detect` signatures (93개, 3 파일). ADR-007 범위 안에서 커버됨.
- **하드코딩 잔존**: `_adjust_severity()` 의 5 매직 넘버 + path→handler 분기. 유일 consumer.
- **pseudo-oracle**: `test_misconfig.py:76` CORS 분기 1줄 (`"high" if acac=='true' else "medium"`) — oracle 이라 부르기 애매, 외부화 이득 없음.

ADR-006 원칙: 코드 freeze, 데이터 fresh. 매직 넘버는 "임계값 조정 = 코드 커밋" 유발 — freeze 위반. 반면 분기 로직은 Python 표현력이 필요 (masked ratio 계산, window 슬라이싱) — JSON DSL 로 옮기면 가독성·디버깅 비용 상승.

## Options

**A. Threshold-only externalization** (선택) — 매직 넘버 5 + path-default 맵만 JSON. 로직 stays in Python. 단순, 당장 이득, DSL 탈선 없음.

**B. Full rule DSL** (기각) — condition-type 어휘 (`body_mask_ratio_exceeds`, `body_contains_any`, ...) 정의, rule list 를 JSON 으로. 1 consumer 에 과설계. 디버깅 어려움. 테스트 표면 ↑.

**C. 현상 유지 + 주석만 보강** (기각) — freeze 원칙 위반. 향후 signal-driven 임계값 조정 파이프라인 막힘.

**D. 전면 코드 이전 (별도 py 모듈)** (기각) — 여전히 코드 수정 유발, ADR-007 철학과 불일치.

## Decision

**A 채택.** 추가 대상 파일: `src/vxis/data/payloads/test_sensitive_files.json`. 신규 dataset key:

```json
"severity_thresholds": {
  "actuator_env_masked_ratio": 0.6,
  "actuator_env_unmasked_window": 40,
  "actuator_health_max_size": 50,
  "env_probe_window": 1000,
  "metrics_max_size": 200
}
```

`_adjust_severity()` 는 모듈 로드 시 `_load_ds("test_sensitive_files", "severity_thresholds")` 로 dict 바인딩. 키 누락 시 `PayloadDatasetMissingError` (fail-loud, ADR-007 규약). path-prefix → default-severity 매핑은 이번 Phase 에서 **미이동** (6개 path 하드코딩 — 리팩터 이득 < 리스크).

Growth loop 연동: `_apply_skill_payload` 의 `_TECHNIQUE_TARGETS` 는 기존대로 페이로드 전용. 임계값 갱신은 수동 PR (자동 제안 대상 아님 — 실측 noise 기반 조정이 필요).

## Consequences

**긍정:**
- 임계값 튜닝 = 데이터 PR (ADR-006 freeze 원칙 일관).
- DSL 회피 — `_adjust_severity()` 30 줄 Python 가독성 보존.
- ADR-007 Phase 3-9 패턴 재사용 — 스키마 확장 없음, 로더 재활용.

**부정:**
- 새 path 추가 시 여전히 코드 commit (path→handler 맵은 코드 안). Phase 2 에서 재평가.
- schema 가 느슨 (`extra="allow"`) — 오탈자 감지 어려움. 로드 시점에 필수 키 체크 필요.

## Verification gate

ADR-008 의 behavior-preserving 조항 준수:
1. JSON 로드 → Python 상수와 byte-identical (기본값 동일) 확인: pytest 1 case.
2. Juice Shop/WebGoat 스코어 delta — ADR-008 noise 범위 (±65pt) 내.
3. 로더 캐시 무효화 테스트 (ADR-007 Phase 10 패턴 차용).

## Phases

| Phase | 내용 | 상태 |
|---|---|---|
| 1 | `severity_thresholds` key 추가 + `_adjust_severity` 로더 배선 + pytest 기본값 parity | ⏳ TBD |
| 2 | (조건부) path→default-severity 맵 이동 — 2nd consumer 출현 시만 | 🚫 deferred |

## Out of Scope

- Full rule DSL (Option B) — consumer ≥ 3 시 별도 ADR.
- CORS 등 1-줄 severity 분기 (`test_misconfig.py:76`) — 이득 < 부피.
- CVE 자동 fetch → 임계값 튜닝 파이프라인 (별도 ADR).
- Wilson interval / Beta prior 등 확률적 임계값 (수식이 다른 문제 — 별도 ADR).
