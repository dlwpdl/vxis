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
