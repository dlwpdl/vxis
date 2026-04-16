# VXIS LLM Wiki — Schema & Maintenance Guide

## 핵심 사실
| 항목 | 값 |
|---|---|
| 목적 | LLM 누적 지식 기지 — 매 세션 RAG 대신 여기 read |
| 유지 주체 | LLM (Claude). 사람은 검토만 |
| 언어 | 한국어 only (코드 스니펫·명령어는 영어 그대로) |
| 페이지 한도 | 본문 ≤ 250~500 단어 (type 별). 표 + TL;DR 은 한도 외 |
| 트리거 | 새 정보 → ingest, 질문 → query, 주기 → lint |

## TL;DR
모든 페이지 = `핵심 사실` 표 (3~7 row) + `TL;DR` (1~3줄) + type 별 본문. 한국어, 상대 cross-link, frontmatter 필수 (`when_to_read` 포함). 5-Loop (관찰-가설-설계-실행-리셋) 와 wiki 구역 매핑은 §1.

---

## 1. 5-Loop ↔ wiki 매핑

| 5-Loop 단계 | wiki 구역 | 작업 |
|---|---|---|
| 관찰 | `sources/` | raw 박제 (immutable) |
| 가설 | `concepts/` | 패턴·원칙 추출 |
| 설계 | `entities/skills/`, `decisions/` | 청사진·결정 |
| 실행 | `entities/modules/`, `entities/pipelines/` | 동작 부품 |
| 리셋 | `log.md`, `index.md` | 다음 세션 인계 |

LLM 은 작업 시작 시 5-Loop 단계 자각 → 해당 구역부터 read.

---

## 2. 3-Layer 모델

```
sources/      raw, IMMUTABLE             ← 한 번 쓰면 수정 X. supersession 만 허용.
  benchmarks/    스캔 리포트 요약
  research/      외부 논문/CVE 요약
  incidents/     사후 분석

concepts/     LLM-maintained             ← 추상 개념·원칙
entities/     LLM-maintained
  skills/       SKILL_REGISTRY 1:1
  modules/      핵심 모듈 1:1
  pipelines/    활성 Phase 1:1
decisions/    LLM-maintained             ← ADR

CLAUDE.md     SCHEMA (this file)
index.md      카탈로그 — ingest 후 갱신
log.md        chronological, append-only
```

Sources 무효화: 새 source 작성 + frontmatter `supersedes: <old path>`.

---

## 3. Frontmatter (모든 페이지 필수)

```yaml
---
name: <human-readable title>
type: concept | skill | module | pipeline | decision | incident | research | benchmark
status: active | draft | superseded | deprecated
when_to_read: <한 줄 — LLM 이 "어떤 질문 받았을 때 이 페이지 펼칠지" 결정용 hint>
updated: YYYY-MM-DD
sources: [<relative path or URL>]
related: [<relative path>]
code_anchors: [<file:symbol>]    # entity 페이지만
superseded_by: <relative path>   # status=superseded 일 때만
---
```

`when_to_read` 가 RAG 의 핵심. 예: `"payload rotation 동작 / 새 페이로드 추가 위치 / WAF 우회 round 매핑"`. LLM 이 이 한 줄로 페이지 펼지 말지 결정.

---

## 4. 페이지 구조 (모든 type 공통)

```markdown
---
[frontmatter]
---
# <title>

## 핵심 사실
| 항목 | 값 |
|---|---|
| ... | ... |     (3~7 row, prose 금지, state 만)

## TL;DR
1~3 줄. 핵심 사실 표를 prose 로 다시 푸는 것 금지 — 표 + TL;DR 은 서로 보완.

[type 별 본문]
```

### 본문 — type 별 섹션

| type | 섹션 (이 순서) |
|---|---|
| concept | What / Why / How / Related |
| skill | Params / Payload Rounds (rotation 만) / Known Limitations / Source Files |
| module | Key Surfaces / Invariants / Related |
| pipeline | Stage / Inputs-Outputs / Triggers / Related Pipelines |
| decision (ADR) | Context / Options / Decision / Consequences |
| incident | Symptom / Root Cause / Fix / Lessons |

---

## 5. Word 예산 (lint warning)

| type | 본문 한도 (단어) |
|---|---|
| concept | 300 |
| skill | 400 |
| module | 500 |
| pipeline | 250 |
| decision | 250 |
| incident | 350 |

핵심 사실 표 + TL;DR + frontmatter 는 한도 외. 초과 시 lint warning (zero exit). 이유: AI 컨텍스트 윈도우 보호 (원칙 ①).

---

## 6. Cross-link 컨벤션

- **항상 상대 경로**: `[name](../concepts/foo.md)`
- **Wikilink 금지** (`[[foo]]`): GitHub 미렌더 + lint 못 잡음
- **Related 순서**: 가장 자주 같이 읽는 것을 위로 (LLM 점프 비용 ↓)
- **외부 코드 ref**: `src/vxis/agent/scan_loop.py:142` 형식
- frontmatter `related:` 와 본문 inline link 둘 다 (lint 용 + AI 읽기용)

---

## 7. Operations (5-Loop 적용)

### Ingest — "박제" (관찰 → 가설/설계/실행 격상)
1. **관찰 박제**: raw → `sources/<sub>/<YYYY-MM-DD>_<topic>.md`. 본문은 fact 만 (해석은 다음 단계).
2. **state 추출**: source 의 핵심 → 영향받는 page 의 `핵심 사실` 표 갱신 + `sources:` 추가 + `updated:` 갱신.
3. **가설 격상**: 패턴 발견 → 새 `concepts/` 페이지.
4. **결정 격상**: 의사결정 분기 → 새 `decisions/` (ADR).
5. **로그**: `python wiki/scripts/log_ingest.py --type ingest --subject "<one-line>"`.

LLM 자문 (ingest 마다): 이 정보가 stale 만드는 page 있나? 새 cross-link 가능한가? decision 격상 가치 있나?

### Query — "alignment" (질문 → 답)
1. **index.md** → category 의 한 줄 `when_to_read` hint 로 후보 페이지 좁힘.
2. 후보 페이지의 **`핵심 사실` + `TL;DR` 만** read. 답 나오면 stop.
3. 부족하면 본문 섹션 + `related:` cross-link 확장.
4. wiki 만으로 답 X → 코드 read → **답 작성 후 즉시 ingest** (다음 세션 비용 0).

### Lint
```bash
python wiki/scripts/lint.py
```

| 체크 | 결과 |
|---|---|
| orphan (index 미등재) / broken link / frontmatter 필수 필드 누락 | **에러** (non-zero exit) |
| `## 핵심 사실` 표 누락 / `## TL;DR` 누락 | **에러** (non-zero exit) |
| 본문 word 초과 / stale (`updated` >90일) / code-anchor stale (`code_anchors` 의 파일이 page `updated` 이후 수정) | **경고** (zero exit) |

---

## 8. Decay & Supersession

- **사실 변경**: 본문 + 표 수정 → `updated:` 갱신.
- **개념 폐기**: `status: deprecated` + 본문 맨 위 `> DEPRECATED — see [<x>](<path>)`. index.md 에서 제거 (자리는 둠).
- **결정 뒤집힘**: 기존 `status: superseded` + `superseded_by:`. 새 ADR. 둘 다 git 보존.
- **source outdated**: 새 source + `supersedes:` (sources 자체는 immutable).

---

## 9. wiki 에 두지 말 것

- 임시 todo, 진행 상황 → 코드 주석 또는 commit message
- 일회성 디버깅 풀이 → commit message
- 코드 자체 (`src/` 가 source of truth)
- secret / credential / token
- 60개 HTML 리포트 전체 — `sources/benchmarks/` 에 요약만
- repo `CLAUDE.md` 와 중복되는 워크플로우

---

## 10. 첫 ingest 체크리스트

새 페이지:
- [ ] frontmatter 모두 채움 (특히 `when_to_read`)
- [ ] `## 핵심 사실` 표 3~7 row
- [ ] `## TL;DR` 1~3 줄
- [ ] 본문 word 한도 내
- [ ] `related:` 최소 1개 (가장 자주 같이 읽는 것 위로)
- [ ] `index.md` 해당 카테고리에 한 줄 + `when_to_read` hint 인용
- [ ] `log.md` append (또는 `log_ingest.py` 사용)
- [ ] `python wiki/scripts/lint.py` 통과
