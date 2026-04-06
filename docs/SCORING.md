# VXIS Scoring System — 완전 가이드

> 5차원 × 1000점 — 한 번의 스캔을 숫자로 측정하고, 매 스캔마다 성장을 추적한다.

---

## 전체 구조

```
┌────────────────────────────────────────────────────────┐
│                VXIS Score: 742 / 1000 (Grade A)         │
│                                                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   Vector     │  │ Exploitation│  │   Chain      │    │
│  │  Coverage    │  │   Reach     │  │Intelligence  │    │
│  │   25%        │  │    30%      │  │    15%       │    │
│  │  187/250     │  │   225/300   │  │   100/150    │    │
│  └─────────────┘  └─────────────┘  └─────────────┘    │
│                                                        │
│  ┌─────────────┐  ┌─────────────┐                     │
│  │  Finding     │  │Completeness │                     │
│  │ Precision    │  │             │                     │
│  │   20%        │  │    10%      │                     │
│  │  160/200     │  │   70/100    │                     │
│  └─────────────┘  └─────────────┘                     │
└────────────────────────────────────────────────────────┘
```

---

## 1. Vector Coverage — 벡터 커버리지 (25%, 250점)

**"얼마나 넓게 공격했는가?"**

공격 벡터 = 테스트할 수 있는 취약점 유형 하나하나.

```
점수 = (시도한 벡터 수 / 전체 벡터 수) × 250

예시 (Web):
  전체 벡터: 56개 (SQL Injection, XSS, SSRF, Auth Bypass, ...)
  시도한 벡터: 42개
  점수 = 42/56 × 250 = 187.5점
```

### 벡터 카테고리별 분류

| 카테고리 | Web 벡터 수 | 예시 |
|----------|-------------|------|
| Injection | ~10 | SQLi, XSS, XXE, SSTI, Command Injection |
| Auth | ~12 | Brute Force, Session Fixation, JWT Manipulation |
| Crypto | ~8 | Weak TLS, Missing HSTS, Bad Cipher |
| Business Logic | ~6 | IDOR, Race Condition, Price Manipulation |
| Infrastructure | ~8 | Open Ports, Default Creds, DNS Zone Transfer |
| Supply Chain | ~4 | Dependency Vuln, Typosquatting |
| Client-Side | ~7 | Prototype Pollution, PostMessage, DOM XSS |

### 벡터 ID 형식
```
WEB-SQLI-001    → Web / SQL Injection / 1번
WEB-AUTH-003    → Web / Authentication / 3번
GAME-PROTO-002  → Game / Protocol / 2번
MOBILE-SSL-001  → Mobile / SSL Pinning / 1번
```

---

## 2. Exploitation Reach — 공격 깊이 (30%, 300점)

**"얼마나 깊이 파고들었는가?"**

발견 하나당 도달한 레벨:

```
Level 0 = 정찰만 (Recon)          → 1점
Level 1 = 취약점 확인 (Confirmed)  → 3점
Level 2 = 익스플로잇 성공 (Exploit) → 6점
Level 3 = 포스트 익스플로잇 (Pivot) → 8점
Level 4 = Crown Jewel 접근         → 10점

점수 = (실제 레벨 점수 합 / 이상적 점수 합) × 300
  이상적 = 모든 발견이 Level 4 (10점씩)

예시:
  발견 10개: L4×2, L3×3, L2×3, L1×2
  실제 합 = 20 + 24 + 18 + 6 = 68
  이상적 합 = 10 × 10 = 100
  점수 = 68/100 × 300 = 204점
```

### 레벨 흐름
```
L0 (정찰)
  → 포트 발견, 서비스 탐지, 기술 스택 확인

L1 (취약점 확인)
  → SQL 에러 메시지, XSS 반사, 인증 우회 가능성

L2 (익스플로잇 성공)
  → 데이터 추출, 파일 읽기, 세션 탈취

L3 (포스트 익스플로잇)
  → 내부 네트워크 피벗, 권한 상승, 다른 서비스 접근

L4 (Crown Jewel)
  → DB 전체 덤프, 관리자 접근, RCE, 민감 데이터 탈취
```

---

## 3. Chain Intelligence — 체인 지능 (15%, 150점)

**"공격을 얼마나 연결했는가?"**

단일 취약점이 아니라, 여러 취약점을 연결해서 더 큰 임팩트를 만들었는가.

```
체인 깊이 기준:
  깊이 0       → 0점   (체인 없음)
  깊이 1-2 스텝 → 50점  (초기 피벗)
  깊이 3-4 스텝 → 100점 (멀티홉 공격)
  깊이 5+ 스텝  → 150점 (풀 킬체인)

예시:
  Chain 1: XSS → Session Hijack → Admin Panel (3 스텝)
  Chain 2: SSRF → Internal API → DB Access → Data Exfil (4 스텝)
  최대 깊이 = 4 → 100점
```

### 체인 예시 (킬체인)
```
[정찰] 서브도메인 발견 (dev.target.com)
  ↓
[취약점] dev 서버에 디버그 모드 활성화
  ↓
[익스플로잇] 소스코드에서 API 키 추출
  ↓
[피벗] API 키로 프로덕션 API 접근
  ↓
[Crown Jewel] 사용자 DB 전체 접근
```

---

## 4. Finding Precision — 발견 정확도 (20%, 200점)

**"발견한 것이 진짜인가?"**

```
기본 점수 = TP / (TP + FP) × 200
  TP = True Positive (진짜 취약점)
  FP = False Positive (오탐)

보너스 1: 증거 품질 (+20점)
  → 증거 2개 이상인 발견의 비율 × 20

보너스 2: Ground Truth 매칭 (+10점)
  → 알려진 취약점 DB와 일치하는 비율 × 10

예시:
  발견 20개: TP 18개, FP 2개
  기본 = 18/20 × 200 = 180점
  증거 보너스 = 15/20 × 20 = 15점
  Ground Truth = 12/20 × 10 = 6점
  최종 = min(180 + 15 + 6, 200) = 200점 (캡)
```

### 정확도가 중요한 이유
```
FP가 많으면:
  → 고객이 리포트를 신뢰 안 함
  → "늑대가 왔다" 효과
  → 실제 위험이 묻힘

TP가 높으면:
  → 리포트 = 즉시 행동 가능한 액션 아이템
  → 고객 신뢰 = 재계약
```

---

## 5. Completeness — 완전성 (10%, 100점)

**"모든 Phase를 빠짐없이 실행했는가?"**

```
점수 = (완료된 Phase / 적용 가능한 Phase) × 100

Phase 상태:
  ✓ completed    → 완료 (분자에 포함)
  ⊘ skipped_na   → N/A 스킵 (분모에서 제외)
  ⊗ skipped_error→ 에러 스킵 (페널티)
  ✗ failed       → 실패 (페널티)

예시 (Web Pipeline):
  완료: 15
  N/A 스킵: 2 (게임 전용 Phase)
  에러 스킵: 1
  실패: 1

  분모 = 15 + 1 + 1 = 17 (N/A 제외)
  점수 = 15/17 × 100 = 88점
```

---

## 등급 시스템

| 등급 | 점수 | 의미 |
|------|------|------|
| **S** | 900-1000 | NCC Group 시니어 레벨 |
| **A** | 750-899 | 프로덕션 레디 |
| **B** | 600-749 | 자동 스캐너보다 우수 |
| **C** | 400-599 | 기본 스캐너 수준 |
| **D** | 0-399 | 개발 중 |

---

## 파이프라인 연동

```
Phase 실행 중:
  → score_tracker.record_vector_attempt("WEB-SQLI-001")
  → score_tracker.record_finding("VXIS-042", "WEB-CRYPTO-003", level=3)
  → score_tracker.record_chain(attack_chain)
  → score_tracker.record_phase_complete("Phase 5", duration_ms=5000)

스캔 완료 후:
  → ScoringEngine.calculate(tracker) → VXISScore (742점, A등급)
  → ScoreReporter.compare(baseline, current) → 성장 추적
  → 리포트에 포함 + Telegram/GitHub PR 알림
```

### CI 성장 루프
```
Day 1:  스캔 → 450점 (C등급)
Day 7:  에이전트 개선 → 580점 (C+)
Day 14: 체인 로직 추가 → 680점 (B등급)
Day 30: 전체 커버리지 → 750점 (A등급)
Day 90: 최적화 → 850점 (A+)
```

---

## 파일 구조

```
src/vxis/scoring/
├── engine.py     — 5차원 점수 계산 엔진
├── tracker.py    — 스캔 중 점수 추적
├── vectors.py    — 공격 벡터 레지스트리 (Web/Game/Mobile)
├── reporter.py   — 비교 리포트 생성
├── benchmark.py  — CI 벤치마크 러너
└── __init__.py   — 공개 API
```
