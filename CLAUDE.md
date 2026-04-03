# VXIS — AI-Powered Autonomous Pentesting Platform

## 절대 원칙: Brain-First Architecture

**모든 파이프라인(Web/Game/Mobile)의 모든 Phase는 이 구조를 반드시 따른다.**

```
Phase 시작
  → Brain이 타겟 현재 상태 분석
  → Brain이 공격 전략 결정
  → Brain이 페이로드 생성
  → Hands/Eyes/X-Ray로 실행
  → 결과를 Brain이 해석
  → 다음 행동을 Brain이 결정
  → 발견한 걸 체이닝
  → 더 깊이 파고들기
Phase 완료
```

### 금지

- 하드코딩된 엔드포인트/페이로드로 공격 시도
- Brain 없이 코드 로직만으로 공격
- Brain을 "가끔 호출하는 헬퍼"로 취급
- 정적 코드 분석으로 스코어링

### 필수

- Brain이 매 Phase의 핵심 의사결정자
- Brain이 동적으로 엔드포인트 발견 + 페이로드 생성
- Brain이 응답 해석 + 다음 행동 결정
- Brain이 체이닝하여 Crown Jewel까지 도달
- 실제 타겟 대상 동적 스캔으로만 점수 측정

### 모듈 역할

```
Brain  = 시니어 펜테스터의 두뇌 (분석, 판단, 전략)
Hands  = 손 (HTTP 요청 실행)
Eyes   = 눈 (브라우저 렌더링, JS 실행)
X-Ray  = 투시 (트래픽 가로채기)
```

## 스코어링 — 동적 스캔 전용

- AI Brain이 실제 타겟 공격 → 결과 → 점수 → 약점 인식 → 코드 개선 → 재공격 루프
- CI 벤치마크: Docker 취약앱(DVWA, Juice Shop) 기동 → 실제 스캔 → 점수 비교
- 정적 코드 grep으로 커버리지 측정하는 것 금지

## 코드 규칙

- `any` 타입 사용 금지 — Zod/Pydantic으로 런타임 검증
- 모든 텍스트 바이링구얼: `"English|||한국어"`
- 리포트는 항상 NCC Group 스타일 단일 HTML (VXIS ReportGenerator 사용)
- AGPL 라이선스 코드 포크 금지 — 100% 자체 구현
- Hands/X-Ray/Controller/Finding 모듈 사용, raw httpx 금지
- 100% 공격 벡터 커버리지 필수, Phase 건너뛰기 금지
- Enterprise 스캔 시 인젝션은 마지막에 승인 후 실행

## 리포트 작성 규칙 (MANDATORY — 절대 변경 금지)

새 스캔 레포트를 작성할 때 `generate_benchmark_reports.py`의 WEBGOAT_FINDINGS 섹션을 템플릿으로 사용한다.

### Finding 필드 규칙

```python
Finding(
    id="XX-NNN",                    # 타겟 약어 + 번호
    scan_id="scan-id-here",
    target="http://...",
    title="English title|||한국어 제목",
    description="...",              # 아래 섹션 구조 필수
    severity=Severity.critical,     # critical/high/medium/low/informational
    finding_type="sql_injection",   # snake_case
    source_plugin="web_pipeline",
    affected_component="...",       # 단수 문자열
    cvss=CVSSVector(vector_string="CVSS:3.1/...", base_score=N.N),
    cwe_ids=["CWE-NNN"],
    mitre_attack=MitreAttack(...),  # Critical/High에 권장
    evidence=[Evidence(evidence_type="http_request_response|log|packet_capture",
                       title="...", content="raw HTTP/log content")],
    remediation="English|||한국어",
    references=[Reference(title="...", url="...")],
)
```

### description 섹션 순서 (영어 → ||| → 한국어)

```
WHAT — Vulnerability Description
HOW — Step-by-Step Attack Scenario  (Step 1: ... Step N: ...)
IMPACT — Business Impact             (- bullet list)
PoC — Proof of Concept               (Request/Response raw)
ATTACK PATH — Chain Analysis
|||
취약점 설명(WHAT)
공격 시나리오(HOW)                    (1단계: ... N단계: ...)
비즈니스 영향(IMPACT)                 (- 글머리)
개념 증명(PoC)
공격 경로(ATTACK PATH)
```

### remediation 구조

```
Immediate: ...
Short-term: ...
Long-term: ...
|||
즉시 조치: ...
단기 조치: ...
장기 조치: ...
```

### ReportData 규칙

```python
ReportData(
    scan_id="...",
    client_name="English only — no ||| separator",   # 제목은 영어 고정
    target="http://...",
    scan_date="YYYY-MM-DD or ISO8601",
    findings=FINDINGS_LIST,
    company_name="VXIS Security",
    author="VXIS Autonomous Brain",
    executive_summary="English summary|||한국어 요약",
    attack_chains=[["ID-001", "ID-002"], ...],       # 체인 공격 경로
)
gen = ReportGenerator()
# gen.generate_html_file(data, Path("reports/filename.html"))  # 파일 저장 시
# gen.render_html(data)                                         # 문자열 반환 시
```

### 절대 금지

- `client_name`에 `|||` 사용 금지 (영어 고정)
- `evidence`를 문자열로 전달 금지 → 반드시 `list[Evidence]`
- `affected_components` (복수) 금지 → `affected_component` (단수)
- `cvss_score` 직접 전달 금지 → `cvss=CVSSVector(...)` 사용
- `scan_id`, `target` 누락 금지 (Finding 필수 필드)
