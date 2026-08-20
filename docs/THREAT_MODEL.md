# VXIS Repository Threat Model|||VXIS 저장소 위협 모델

## Scope|||범위

This model covers the VXIS CLI and dashboard, Brain/agent orchestration, tool and
plugin execution, the Docker scanner sandbox, scope and egress enforcement,
scan persistence, reports, and external model or intelligence integrations. It
models VXIS itself, not the vulnerability posture of any scan target.|||이 모델은
VXIS CLI와 대시보드, Brain/에이전트 오케스트레이션, 도구 및 플러그인 실행,
Docker 스캐너 샌드박스, 스코프와 이그레스 강제, 스캔 저장, 보고서 및 외부 모델
또는 인텔리전스 연동을 다룹니다. 스캔 타깃의 취약점 상태가 아니라 VXIS 자체를
모델링합니다.

## Assets|||보호 자산

- Operator and customer authorization scope.|||운영자 및 고객의 승인 스코프.
- API keys, target credentials, cookies, tokens, and authenticated traffic.|||API
  키, 타깃 자격 증명, 쿠키, 토큰 및 인증 트래픽.
- Source code, target responses, evidence, PoCs, findings, reports, and scan
  history.|||소스 코드, 타깃 응답, 증거, PoC, finding, 보고서 및 스캔 이력.
- Integrity of verifier verdicts, replay evidence, completion state, and
  resolution status.|||검증자 판정, 재현 증거, 완료 상태 및 해결 상태의 무결성.
- The operator host, Docker daemon, filesystem, network identity, and compute or
  model budget.|||운영자 호스트, Docker 데몬, 파일시스템, 네트워크 정체성 및
  컴퓨팅/모델 예산.

## Actors and attacker-controlled inputs|||행위자 및 공격자 통제 입력

- An authorized operator controls scan configuration and approval decisions.|||
  권한 있는 운영자가 스캔 구성과 승인 결정을 통제합니다.
- A target can control HTTP responses, HTML/JavaScript, redirects, certificates,
  banners, files, and timing.|||타깃은 HTTP 응답, HTML/JavaScript, 리다이렉트,
  인증서, 배너, 파일 및 타이밍을 통제할 수 있습니다.
- Repository authors and imported skill/plugin authors can control text and code
  loaded into analysis or execution paths.|||저장소 작성자와 가져온 스킬/플러그인
  작성자는 분석 또는 실행 경로에 로드되는 텍스트와 코드를 통제할 수 있습니다.
- LLM and third-party service responses are nondeterministic external input.|||LLM
  및 제3자 서비스 응답은 비결정적 외부 입력입니다.
- An unauthenticated or lower-privileged dashboard user may attempt to start
  scans or read another user's data.|||미인증 또는 낮은 권한의 대시보드 사용자가
  스캔 시작이나 다른 사용자의 데이터 읽기를 시도할 수 있습니다.

## Trust boundaries and data flow|||신뢰 경계 및 데이터 흐름

```text
Operator
  -> CLI / Dashboard
  -> scope + approval policy
  -> Brain / external or local LLM
  -> validated ToolRegistry action
  -> host tool or per-scan Docker sandbox
  -> explicitly scoped target network
  -> evidence + verifier + replay gates
  -> database / private logs / reports
```

The critical boundaries are model output to tool arguments, host process to
Docker, sandbox to target network, untrusted target content to the Brain,
runtime to external providers, and runtime memory to persistent artifacts.|||
핵심 경계는 모델 출력에서 도구 인자로, 호스트 프로세스에서 Docker로,
샌드박스에서 타깃 네트워크로, 신뢰할 수 없는 타깃 내용에서 Brain으로,
런타임에서 외부 제공자로, 런타임 메모리에서 영구 산출물로 넘어가는 지점입니다.

## Security invariants|||보안 불변조건

1. No input, model, skill, plugin, or target response can grant authorization or
   expand the operator-approved scope.|||어떤 입력, 모델, 스킬, 플러그인 또는 타깃
   응답도 권한을 부여하거나 운영자가 승인한 스코프를 확장할 수 없습니다.
2. LLM output is data until a typed tool boundary validates it; prompt text is
   never an authorization control.|||LLM 출력은 타입이 지정된 도구 경계에서
   검증되기 전까지 데이터이며 프롬프트 텍스트는 인가 통제가 아닙니다.
3. Arbitrary commands require explicit approval and execute inside the per-scan
   sandbox with least privilege and a bounded workspace.|||임의 명령은 명시적 승인이
   필요하며 최소 권한과 제한된 작업공간을 가진 스캔별 샌드박스 안에서
   실행됩니다.
4. Target-facing tools must enforce or declare their egress path; delegated tools
   cannot silently bypass scope.|||타깃을 향하는 도구는 이그레스 경로를 강제하거나
   선언해야 하며 위임된 도구가 조용히 스코프를 우회할 수 없습니다.
5. High-impact findings require observed evidence, controls, repeatability, and
   verifier/replay acceptance.|||고영향 finding은 관찰된 증거, 대조군, 반복 재현성
   및 검증자/재현 게이트 승인이 필요합니다.
6. Secrets and customer data are redacted before entering routine logs, agent
   history, errors, or shared output.|||비밀정보와 고객 데이터는 일반 로그,
   에이전트 이력, 오류 또는 공유 출력에 들어가기 전에 제거됩니다.
7. An incomplete or differently scoped scan cannot prove that a missing finding
   is resolved and cannot be presented as a clean result.|||불완전하거나 다른
   스코프의 스캔은 누락된 finding의 해결을 증명할 수 없고 안전한 결과로 표시될
   수 없습니다.
8. Persistent artifacts use private permissions and remain outside source
   control unless they are sanitized fixtures.|||영구 산출물은 비공개 권한을
   사용하며 정제된 fixture가 아닌 한 소스 관리 밖에 유지됩니다.

## Primary threats and controls|||주요 위협 및 통제

| Threat\|\|\|위협 | Relevant controls\|\|\|관련 통제 |
|---|---|
| Prompt or target-output injection causes excessive agency\|\|\|프롬프트/타깃 출력 인젝션으로 과도한 권한 행사 | Typed tool schemas, scope runtime gate, approval gates, egress policy, one-action loop\|\|\|타입 도구 스키마, 런타임 스코프 게이트, 승인 게이트, 이그레스 정책, 단일 액션 루프 |
| Command injection through targets, plugins, dashboard, or model arguments\|\|\|타깃·플러그인·대시보드·모델 인자를 통한 명령 인젝션 | Argument validation, no-shell subprocess paths, dashboard target validation, sandbox-only arbitrary execution\|\|\|인자 검증, shell 없는 subprocess 경로, 대시보드 타깃 검증, 샌드박스 전용 임의 실행 |
| Sandbox escape or host privilege escalation\|\|\|샌드박스 탈출 또는 호스트 권한 상승 | Per-scan container, dropped capabilities, `NET_RAW` only, `no-new-privileges`, no Docker socket mount\|\|\|스캔별 컨테이너, capability 제거, `NET_RAW`만 허용, `no-new-privileges`, Docker 소켓 미마운트 |
| Unauthorized network access or scope drift\|\|\|무단 네트워크 접근 또는 스코프 이탈 | Scope policy, egress contracts, Ghost/direct-egress gates, explicit arbitrary-execution approval\|\|\|스코프 정책, 이그레스 계약, Ghost/직접 이그레스 게이트, 명시적 임의 실행 승인 |
| Credential or evidence disclosure\|\|\|자격 증명 또는 증거 노출 | Output redaction, private log permissions, gitignore, minimal environment, authenticated dashboard\|\|\|출력 민감정보 제거, 비공개 로그 권한, gitignore, 최소 환경변수, 인증된 대시보드 |
| False finding, forged evidence, or premature completion\|\|\|오탐, 위조 증거 또는 조기 완료 | Evidence contract, control pairs, repeat counts, adversarial verifier, replay and finish gates\|\|\|증거 계약, 대조군, 반복 횟수, 적대적 검증자, 재현 및 완료 게이트 |
| Incorrectly reported resolution after partial coverage\|\|\|부분 coverage 후 잘못된 해결 판정 | Scan status propagation and `unknown` comparison state unless target/profile match a completed scan\|\|\|스캔 상태 전달 및 완료 스캔의 target/profile이 일치하지 않으면 `unknown` 비교 상태 |
| Resource or model-cost exhaustion\|\|\|리소스 또는 모델 비용 고갈 | Iteration, timeout, token, optional Docker CPU/memory/PID, and cost limits\|\|\|반복, 타임아웃, 토큰, 선택적 Docker CPU/메모리/PID 및 비용 제한 |
| Scan-state tampering or repudiation\|\|\|스캔 상태 변조 또는 부인 | Structured events, database records, timestamps, evidence retention, private artifacts\|\|\|구조화 이벤트, DB 기록, 타임스탬프, 증거 보존, 비공개 산출물 |

## Residual risks|||잔여 위험

- The active scanner sandbox uses host networking and retains `NET_RAW` for
  raw packet tools. It is not equivalent to network-policy isolation, and the
  image still runs as root inside the container.|||활성 스캐너 샌드박스는 host
  네트워크를 사용하며 raw packet 도구를 위해 `NET_RAW`를 유지합니다. 이는
  네트워크 정책 격리와 동등하지 않으며 이미지 내부 프로세스는 여전히 root로
  실행됩니다.
- Shell egress restrictions are partly process-level; a novel binary or raw
  socket path may evade pattern-based checks.|||셸 이그레스 제한 일부는 프로세스
  수준이며 새로운 바이너리나 raw socket 경로가 패턴 기반 검사를 우회할 수
  있습니다.
- No VXIS-specific seccomp/AppArmor profile has been validated against the
  required scanner set. Docker and the host kernel remain security-critical.|||
  필수 스캐너 집합에 대해 검증된 VXIS 전용 seccomp/AppArmor 프로필이 없습니다.
  Docker와 호스트 커널은 계속 보안 핵심 요소입니다.
- External LLM and intelligence providers may receive authorized scan context.
  Operators must choose providers and data-sharing settings appropriate for the
  engagement.|||외부 LLM 및 인텔리전스 제공자가 승인된 스캔 컨텍스트를 받을 수
  있습니다. 운영자는 평가에 적절한 제공자와 데이터 공유 설정을 선택해야
  합니다.
- Local storage is permission-restricted but not necessarily encrypted. VXIS
  local state is not designed for mutually untrusted tenants.|||로컬 저장소는 접근
  권한이 제한되지만 반드시 암호화되는 것은 아닙니다. VXIS 로컬 상태는 서로
  신뢰하지 않는 테넌트를 위해 설계되지 않았습니다.

## Assumptions|||가정

- The operator controls the host account and Docker daemon and keeps them
  patched.|||운영자가 호스트 계정과 Docker 데몬을 통제하고 최신 패치를
  유지합니다.
- The operator supplies truthful authorization scope and does not intentionally
  override safety gates for an unauthorized target.|||운영자가 정확한 승인 스코프를
  제공하고 무단 타깃을 위해 안전 게이트를 의도적으로 우회하지 않습니다.
- Production deployments configure authentication, TLS, retention, backups,
  and secret management appropriate to their environment.|||운영 배포는 환경에
  적합한 인증, TLS, 보존, 백업 및 비밀정보 관리를 구성합니다.

## Review triggers|||재검토 조건

Review this model when VXIS adds a new execution backend, white-box runtime,
external integration, multi-tenant deployment, container privilege, persistent
artifact type, or authorization path.|||새 실행 백엔드, 화이트박스 런타임, 외부
연동, 멀티테넌트 배포, 컨테이너 권한, 영구 산출물 유형 또는 인가 경로가
추가될 때 이 모델을 재검토하십시오.
