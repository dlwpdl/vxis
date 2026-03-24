# VXIS CRT — Advanced Cognitive Layer: 9-Module Roadmap

> **Status:** Planning
> **Date:** 2026-03-24
> **Prerequisite:** Phase 1 ✅ COMPLETE → Phase 2-7 진행 중
> **Codename:** VXIS CRT Omega Layer

---

## 개요

Phase 1-7이 "엘리트 인간 펜테스터처럼 생각하는 AI"라면,
Omega Layer는 **"어떤 인간도 불가능한 것을 하는 AI"**다.

9개 모듈, 각각 독립 구현 가능. Mission Config `[advanced]` 블록으로 사용자가 개별 활성화.

```
현재 아키텍처:  Director → 57 Agents → Findings → Evidence → Report
Omega Layer:    +Cross-Protocol Synthesis
                +CVE Watch Daemon (24/7)
                +Red vs Blue Co-Intelligence
                +Chain Mutation
                +Self-Evolving Agent Synthesis
                +Behavioral Biometrics
                +Temporal Forecasting
                +Digital Twin Pre-Simulation
                +Collective Intelligence Network
```

---

## 우선순위 로드맵

### Priority 1 — Cross-Protocol Synthesis Engine

**왜 먼저인가:** Phase 2 에이전트들이 올라오는 순간 즉시 효과. Director + Graph 위에 레이어만 얹으면 됨. 레버리지 최고.

**핵심 아이디어:** 57개 에이전트는 각자 자기 레이어만 본다. Cross-Protocol Synthesizer는 모든 에이전트의 발견을 받아서 "레이어를 넘나드는 체인"을 합성한다. 인간이 절대 생각 못 하는 공격 경로.

**구현 파일:**
```
src/vxis/synthesis/
├── __init__.py
├── cross_protocol.py      # CrossProtocolSynthesizer 클래스
├── chain_builder.py       # 멀티-레이어 체인 조합 로직
└── poc_generator.py       # 합성된 체인의 PoC 자동 생성
```

**핵심 로직:**
```python
class CrossProtocolSynthesizer:
    """
    모든 에이전트 발견을 수신하여 단독으로는 불가능한
    크로스-레이어 공격 체인을 LLM으로 합성한다.
    """
    async def synthesize(self, findings: list[Finding]) -> list[AttackChain]:
        # 1. Finding들을 프로토콜/레이어 태그로 분류
        # 2. LLM에게 "이 발견들을 연결하는 공격 체인이 있는가?" 질의
        # 3. 의미론적으로 연결 가능한 체인 조합 탐색
        # 4. 실현 가능성 검증 (그래프 경로 확인)
        # 5. PoC 자동 생성
```

**Mission Config 키:** `cross_protocol_synthesis = true`

**완성 기준:**
- [ ] CrossProtocolSynthesizer 클래스 구현
- [ ] Finding → 레이어 태그 분류기
- [ ] LLM 체인 합성 프롬프트 (Claude opus)
- [ ] 합성된 체인 Attack Graph 자동 추가
- [ ] PoC 텍스트 자동 생성
- [ ] Evidence Engine 통합
- [ ] 단위 테스트

---

### Priority 2 — Living CVE Watch Daemon

**왜 두 번째인가:** 완전히 독립적인 프로세스. 미션과 무관하게 24/7 돌아가면서 타겟 스택에 맞는 CVE가 나오면 즉시 Hypothesis Queue에 주입. 우리 DB 없음 — GitHub/NVD/OSV가 소스.

**핵심 아이디어:** CVE가 publish되는 순간, 메모리에 있는 타겟 스택과 매칭 → 타겟 환경에 맞춤화된 가설 자동 생성 → Hypothesis Queue에 CRITICAL 우선순위로 삽입.

**소스 (우리 DB 아님, 외부 API):**
- GitHub Security Advisory API (GraphQL) — 가장 빠른 알림
- NVD REST API v2.0 — 공식 CVSS 점수
- OSV.dev API — 에코시스템별 (npm, PyPI, Maven 등)
- GitHub Actions workflow (cron: `*/15 * * * *`) — 15분 간격 자동 실행

**구현 파일:**
```
src/vxis/watchers/
├── __init__.py
├── cve_daemon.py          # 메인 daemon 프로세스
├── sources/
│   ├── github_advisory.py # GitHub Advisory GraphQL API
│   ├── nvd.py             # NVD REST API v2.0
│   └── osv.py             # OSV.dev API
├── matcher.py             # CVE ↔ 타겟 스택 매칭 엔진
└── hypothesis_injector.py # Hypothesis Queue 주입

.github/workflows/
└── cve-watch.yml          # GitHub Actions cron (백업 실행 방법)
```

**핵심 로직:**
```python
class CVEWatchDaemon:
    """
    외부 CVE 소스를 구독하며 타겟 스택에 맞는 취약점을
    실시간으로 감지하여 Hypothesis Queue에 자동 주입한다.
    """
    SOURCES = [GitHubAdvisory, NVD, OSV]
    POLL_INTERVAL = 900  # 15분

    async def watch(self):
        async for cve in self.stream_all_sources():
            matched_targets = self.matcher.match(cve, self.memory.all_stacks())
            for target, score in matched_targets:
                if score > 0.6:
                    hypothesis = self.build_hypothesis(cve, target)
                    await self.queue.push(hypothesis, priority=score)
```

**GitHub Actions (백업 실행):**
```yaml
# .github/workflows/cve-watch.yml
on:
  schedule:
    - cron: '*/15 * * * *'
jobs:
  watch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: python -m vxis.watchers.cve_daemon --once
```

**Mission Config 키:** `live_cve_watch = true`

**완성 기준:**
- [ ] GitHub Advisory GraphQL 클라이언트
- [ ] NVD REST API v2.0 폴링
- [ ] OSV.dev API 클라이언트
- [ ] 스택 매칭 엔진 (버전 범위 비교)
- [ ] Hypothesis 자동 생성 (CVE → 타겟 맞춤)
- [ ] Hypothesis Queue 주입 어댑터
- [ ] GitHub Actions workflow
- [ ] daemon 실행/중지 CLI 커맨드

---

### Priority 3 — Red vs Blue Co-Intelligence

**왜 세 번째인가:** Evidence Engine에 훅 하나 추가로 구현 가능. 각 Finding마다 병렬 Claude API 호출 → 방어 콘텐츠 자동 생성. 고객 가치 즉시 극대화.

**핵심 아이디어:** 공격 Finding이 저장되는 순간 Blue AI가 병렬로 "이걸 어떻게 탐지하고 막는가"를 생성한다. 보고서 한 장에 공격 + 방어 플레이북이 동시에 들어간다.

**구현 파일:**
```
src/vxis/blue/
├── __init__.py
├── co_intelligence.py     # BlueAI 클래스 (Evidence Engine 훅)
├── generators/
│   ├── siem_rules.py      # Splunk/Elastic 탐지 쿼리 생성
│   ├── waf_rules.py       # Nginx/ModSecurity WAF 룰 생성
│   ├── patch_code.py      # 언어별 패치 코드 생성
│   └── detection_check.py # "지금 탐지되고 있는가?" 판단
└── report_merger.py       # Red + Blue 보고서 병합
```

**핵심 로직:**
```python
class BlueAI:
    """
    모든 Red Team finding에 대해 병렬로 방어 콘텐츠를 생성.
    """
    async def on_finding(self, finding: Finding) -> BlueResponse:
        tasks = [
            self.generate_siem_rule(finding),
            self.generate_waf_rule(finding),
            self.generate_patch(finding),
            self.assess_current_detection(finding),
        ]
        results = await asyncio.gather(*tasks)
        return BlueResponse(finding=finding, defenses=results)
```

**보고서 출력 변화:**
```
[CRITICAL] JWT Algorithm Confusion
  ├── [RED]  PoC: curl -H "Authorization: Bearer <forged>" ...
  ├── [BLUE] SIEM: index=web_logs | search "alg":"none" | alert
  ├── [BLUE] WAF:  SecRule REQUEST_HEADERS:Authorization "@rx alg.*none"
  ├── [BLUE] PATCH: python — verify=algorithms=["RS256"]
  └── [BLUE] STATUS: ⚠ 현재 미탐지 (WAF 미설정)
```

**Mission Config 키:** `red_vs_blue = true`

**완성 기준:**
- [ ] BlueAI 클래스 (Evidence Engine 훅)
- [ ] SIEM 룰 생성 (Splunk/Elastic)
- [ ] WAF 룰 생성 (Nginx/ModSecurity)
- [ ] 언어별 패치 코드 (Python/Java/Node/Go)
- [ ] 탐지 상태 실시간 판단
- [ ] Red + Blue 보고서 병합 포맷
- [ ] CLI Display에 Blue 섹션 추가

---

### Priority 4 — Attack Chain Mutation Engine

**왜 네 번째인가:** Living Attack Graph가 이미 있다. 그래프 위에서 BFS/DFS + LLM 변이 → 동등한 체인 발굴. "부분 패치"의 허상을 수학적으로 증명.

**핵심 아이디어:** Critical 체인 하나를 발견하면 → 같은 목적지에 도달하는 모든 대체 경로를 자동 탐색. "SQLi 막아도 3개 더 있음"을 보여줌.

**구현 파일:**
```
src/vxis/mutation/
├── __init__.py
├── chain_mutator.py       # AttackChainMutator 클래스
├── graph_traversal.py     # BFS/DFS 동등 노드 탐색
└── semantic_mutator.py    # LLM 의미론적 변이 생성
```

**핵심 로직:**
```python
class AttackChainMutator:
    """
    발견된 공격 체인의 모든 동등 변종을 탐색한다.
    같은 목적지, 다른 경로 — 부분 패치의 허상을 증명.
    """
    async def mutate(self, chain: AttackChain) -> list[AttackChain]:
        structural = self.graph_traversal.find_equivalent_paths(chain)
        semantic = await self.llm_mutator.generate_variants(chain)
        all_candidates = structural + semantic
        return [c for c in all_candidates if self.validate(c)]
```

**Mission Config 키:** `chain_mutation = true`

**완성 기준:**
- [ ] 동등 노드 탐색 (그래프 BFS/DFS)
- [ ] LLM 의미론적 변이 생성
- [ ] 변이 체인 실현 가능성 검증
- [ ] "N개의 독립 경로" 보고서 포맷
- [ ] Attack Graph 시각화 통합

---

### Priority 5 — Self-Evolving Agent Synthesis + Cross-Mission Collective Intelligence

**왜 다섯 번째인가:** 이미 진행 중인 방향과 연계. Self-Evolve + Collective Intel은 동전의 양면. 함께 구현하면 시너지.

#### 5A — Self-Evolving Agent Synthesis

**핵심 아이디어:** 미션 종료 후 Director가 "커버 못 한 공격 표면"을 분석하고, 새 에이전트 코드를 Claude로 생성, 샌드박스 검증 후 카탈로그에 자동 추가. 57개에서 시작, 사용할수록 증가.

```
src/vxis/evolution/
├── __init__.py
├── gap_analyzer.py        # 미션 후 커버리지 갭 분석
├── agent_synthesizer.py   # 신규 에이전트 코드 생성 (Claude API)
├── sandbox.py             # 생성된 에이전트 격리 테스트
└── catalog_updater.py     # 검증 완료 에이전트 카탈로그 등록
```

**Mission Config 키:** `self_evolve = true` (depth=elite 전용)

#### 5B — Cross-Mission Collective Intelligence

**핵심 아이디어:** 미션 종료 시 완전 익명화된 패턴 벡터를 Collective DB에 업로드. N개 이상의 미션에서 같은 패턴 emerge 시 모든 진행 중인 미션에 신호.

```
src/vxis/collective/
├── __init__.py
├── anonymizer.py          # 클라이언트 정보 완전 제거 + 벡터화
├── pattern_store.py       # 익명화 패턴 벡터 DB (ChromaDB)
├── emergence_detector.py  # N≥3 임계값 패턴 감지
└── signal_broadcaster.py  # 진행 중인 미션 Hypothesis Queue에 신호
```

**Mission Config 키:** `collective_intel = true`

**완성 기준 (5A+5B 통합):**
- [ ] 미션 종료 후 갭 분석 파이프라인
- [ ] 에이전트 코드 생성 프롬프트 (Claude API)
- [ ] 격리 샌드박스 (subprocess + timeout)
- [ ] 카탈로그 자동 등록 (registry.py 통합)
- [ ] 익명화/벡터화 파이프라인
- [ ] 패턴 emerge 탐지 (임계값 설정 가능)
- [ ] 실시간 신호 → Hypothesis Queue 주입

---

### Priority 6 — Behavioral Biometrics Layer

**핵심 아이디어:** 코드/인프라가 아닌 **인간 행동 패턴**이 공격 표면. GitHub API로 커밋 타임스탬프, 빈도, 배포 패턴 분석 → "가장 취약한 인간 접근 시점" 자동 탐지.

```
src/vxis/biometrics/
├── __init__.py
├── github_analyzer.py     # GitHub API: 커밋/PR/배포 패턴
├── persona_builder.py     # 고권한 사용자 행동 프로파일
├── timing_analyzer.py     # 취약 시점 분석 (자정 마이그레이션 등)
└── se_scenario_gen.py     # 소셜 엔지니어링 시나리오 자동 생성
```

**Mission Config 키:** `behavioral_biometrics = true`

**완성 기준:**
- [ ] GitHub API 커밋/PR 패턴 수집
- [ ] 고권한 사용자 식별 (CTO, DBA, DevOps)
- [ ] 행동 패턴 모델링 (시간대, 빈도, 습관)
- [ ] "취약 시점" 자동 탐지
- [ ] SE 시나리오 자동 생성 (누구, 언제, 어떻게)
- [ ] 보고서 Human Attack Surface 섹션 추가

---

### Priority 7 — Temporal Vulnerability Forecast

**핵심 아이디어:** 현재 상태만 보지 않는다. 현재 스택 + CVE 트렌드 + EOL 일정으로 "향후 90일 위험도 타임라인" 예측. 펜테스트 = 사후 분석 → 예방 인텔리전스.

```
src/vxis/forecast/
├── __init__.py
├── stack_tracker.py       # Memory에서 현재 스택 추출
├── eol_calendar.py        # EOL/EOS 일정 DB (endoflife.date API)
├── cve_trend_analyzer.py  # CVE 빈도 트렌드 분석
├── pqc_calculator.py      # Quantum Risk + PQC 전환 시점 계산
└── timeline_generator.py  # 90일 타임라인 보고서 생성
```

**Mission Config 키:** `temporal_forecast = true`

**완성 기준:**
- [ ] EOL/EOS 데이터 수집 (endoflife.date API)
- [ ] CVE 트렌드 분석 (버전별 취약점 빈도)
- [ ] 업그레이드 위험도 계산
- [ ] PQC 타임라인 계산
- [ ] 90일 위험도 타임라인 생성
- [ ] 보고서 Forecast 섹션 추가

---

### Priority 8 — Digital Twin Pre-Simulation

**핵심 아이디어:** 타겟에 실제로 닿기 전에 OSINT로 구축한 디지털 트윈에서 모든 공격을 시뮬레이션. 성공 확률 높은 것만 실제로 실행 → 완벽한 스텔스 precision-strike.

```
src/vxis/twin/
├── __init__.py
├── builder.py             # OSINT → 인프라 트윈 그래프 구축
├── simulator.py           # 트윈 위에서 공격 시뮬레이션 (확률 계산)
├── probability_scorer.py  # 각 공격 성공 확률 스코어링
└── precision_filter.py    # 상위 N% 고신뢰 공격만 실제 실행 큐에 삽입
```

**Mission Config 키:** `digital_twin = true` (stealth=true 시 자동 권장)

**완성 기준:**
- [ ] OSINT 데이터 → 인프라 트윈 그래프 빌더
- [ ] 공격 시뮬레이션 엔진 (그래프 기반)
- [ ] 성공 확률 스코어링
- [ ] 필터 임계값 설정 (기본: 상위 30%)
- [ ] 트윈 vs 실제 결과 비교 피드백 루프
- [ ] stealth=true 시 자동 활성 로직

---

### Priority 9 — Distributed Collective Intelligence Network

**핵심 아이디어:** 여러 동시 인게이지먼트에서 같은 취약점 패턴이 emerge할 때 네트워크 전체에 신호. 쓰는 조직이 많을수록 모두가 더 강해진다.

Priority 5B의 확장. 단일 인스턴스 → 분산 네트워크.

```
src/vxis/network/
├── __init__.py
├── node.py                # VXIS 인스턴스 노드 (P2P 또는 중앙화)
├── federated_patterns.py  # 연합 학습 방식 패턴 공유
├── consensus.py           # 패턴 신뢰도 합의 (N≥3)
└── privacy_guard.py       # 완전 비식별화 보장 레이어
```

**Mission Config 키:** `collective_intel = true` + `[network]` 블록

**완성 기준:**
- [ ] 분산 패턴 저장 프로토콜
- [ ] 연합 학습 방식 가중치 공유
- [ ] 비식별화 보장 (차분 프라이버시 적용)
- [ ] 패턴 신뢰도 합의 메커니즘
- [ ] 실시간 크로스-미션 신호 브로드캐스트
- [ ] 네트워크 참여 consent 관리

---

## 통합 Mission Config (최종)

```toml
[mission]
target = "*.acme.com"
perspective = "external"
scope = "full"
depth = "elite"
stealth = true

[advanced]
# ─── Cognitive Modules ─────────────────────────────────────────
cross_protocol_synthesis = true   # Priority 1: 크로스-레이어 체인 합성
live_cve_watch       = true       # Priority 2: GitHub/NVD CVE 실시간 감시
red_vs_blue          = true       # Priority 3: 공격+방어 동시 생성
chain_mutation       = true       # Priority 4: 동등 공격 체인 변이 탐색
self_evolve          = false      # Priority 5a: 에이전트 자동 합성 (elite)
collective_intel     = true       # Priority 5b+9: 크로스-미션 패턴 공유
behavioral_biometrics = false     # Priority 6: 인간 행동 공격 표면
temporal_forecast    = true       # Priority 7: 90일 취약점 예측
digital_twin         = false      # Priority 8: 실제 접촉 전 트윈 시뮬레이션

[memory]
client_id = "acme-corp"
learn = true

[network]
participate = false               # Priority 9: 분산 집단지성 참여
consent_share_patterns = false    # 익명화 패턴 공유 동의
```

---

## 기술 스택 추가 요구사항

| 모듈 | 새 의존성 |
|------|---------|
| CVE Watch | `httpx` (async HTTP), GitHub GraphQL, NVD REST v2, `apscheduler` |
| Collective Intel | `chromadb` (벡터 DB, 이미 계획됨), `sentence-transformers` |
| Agent Synthesis | Claude API (이미 있음), `subprocess` sandbox |
| Digital Twin | NetworkX (이미 있음), 경량 시뮬레이션 레이어 |
| Behavioral | GitHub REST API v3 (`PyGithub`) |
| Temporal | `endoflife.date` API, 회귀 분석 (`scipy`) |
| Red vs Blue | Claude API (이미 있음), 병렬 호출만 추가 |

---

## 빌드 순서 원칙

1. **각 모듈은 Mission Config 키 하나로 완전 on/off** — 기존 기능 영향 없음
2. **Phase 2 에이전트 최소 4개 완성 후** Cross-Protocol Synthesis 의미 있음
3. **CVE Daemon은 Phase와 무관하게 독립 실행 가능** — 지금 당장 구현 가능
4. **Red vs Blue는 Evidence Engine 훅 하나** — 가장 빠르게 고객 가치 전달
5. **Digital Twin이 가장 복잡** — 나중에, 하지만 스텔스 미션의 게임체인저

---

*이 문서는 VXIS CRT Phase 1 완료 이후의 Omega Layer 로드맵이다.*
*"불가능한 프로젝트"의 두 번째 챕터. 엘리트 AI → 인간을 초월하는 AI.*
