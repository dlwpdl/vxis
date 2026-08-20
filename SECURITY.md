# VXIS Security Policy|||VXIS 보안 정책

VXIS is an autonomous security validation tool for systems the operator owns or
has explicit permission to assess. This policy defines the security boundaries
of VXIS itself; it does not authorize testing any target.|||VXIS는 운영자가
소유하거나 명시적으로 평가 허가를 받은 시스템을 위한 자율 보안 검증
도구입니다. 이 정책은 VXIS 자체의 보안 경계를 정의하며 어떤 타깃에 대한
테스트 권한도 부여하지 않습니다.

The repository threat model is maintained in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).|||저장소 위협 모델은
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)에서 관리합니다.

## Supported versions|||지원 버전

Security fixes target the latest release and the current `main` branch. Before
reporting, reproduce the issue on one of those versions when possible.|||보안
수정은 최신 릴리스와 현재 `main` 브랜치를 대상으로 합니다. 가능하면 제보
전에 해당 버전 중 하나에서 문제를 재현하십시오.

## Report a VXIS vulnerability|||VXIS 취약점 제보

Report vulnerabilities privately through the repository host's private security
advisory feature. If that is unavailable, contact the maintainers privately
before opening a public issue. Do not publish live credentials, customer data,
unpatched exploits, or sensitive scan artifacts.|||저장소 호스트의 비공개 보안
권고 기능을 통해 취약점을 제보하십시오. 해당 기능을 사용할 수 없다면 공개
이슈를 만들기 전에 관리자에게 비공개로 연락하십시오. 실제 자격 증명, 고객
데이터, 패치되지 않은 익스플로잇 또는 민감한 스캔 산출물을 공개하지
마십시오.

Include the affected commit/version, deployment mode, attacker starting
permissions, crossed trust boundary, minimal reproduction, expected behavior,
actual behavior, and impact. Sanitize all attached logs and reports.|||영향받는
커밋/버전, 배포 모드, 공격자의 초기 권한, 침해된 신뢰 경계, 최소 재현 절차,
예상 동작, 실제 동작 및 영향을 포함하십시오. 첨부 로그와 보고서는 모두
민감정보를 제거하십시오.

## Security boundaries|||보안 경계

- Target responses, repository content, imported artifacts, browser content,
  plugin output, and LLM output are untrusted data. None of them can grant
  permission or expand scope.|||타깃 응답, 저장소 내용, 가져온 산출물, 브라우저
  내용, 플러그인 출력 및 LLM 출력은 신뢰할 수 없는 데이터입니다. 어느 것도
  권한을 부여하거나 스코프를 확장할 수 없습니다.
- `shell_exec` and `python_exec` run in a per-scan Docker container only after
  explicit arbitrary-execution approval. The container is a defense boundary,
  not permission to access unrelated hosts or files.|||`shell_exec`와
  `python_exec`는 임의 실행에 대한 명시적 승인 후 스캔별 Docker 컨테이너에서
  실행됩니다. 컨테이너는 방어 경계이지 관련 없는 호스트나 파일에 접근할
  권한이 아닙니다.
- Scope, egress, approval, evidence, replay, and verifier gates are enforced in
  code. Prompt instructions are not security controls.|||스코프, 이그레스, 승인,
  증거, 재현 및 검증자 게이트는 코드로 강제됩니다. 프롬프트 지시는 보안
  통제가 아닙니다.
- Scan credentials, authenticated traffic, PoCs, reports, logs, and sandbox
  workspaces may contain sensitive data. They must remain private and outside
  source control.|||스캔 자격 증명, 인증 트래픽, PoC, 보고서, 로그 및 샌드박스
  작업공간에는 민감정보가 포함될 수 있습니다. 비공개로 유지하고 소스 관리에
  포함하지 마십시오.
- VXIS local state is not a multi-user or multi-tenant security boundary. Do not
  share one OS account, data directory, or credential set between mutually
  untrusted users.|||VXIS 로컬 상태는 다중 사용자 또는 멀티테넌트 보안 경계가
  아닙니다. 서로 신뢰하지 않는 사용자가 하나의 OS 계정, 데이터 디렉터리 또는
  자격 증명 세트를 공유하지 마십시오.

## In-scope VXIS security reports|||VXIS 보안 제보 범위

- A scope or egress bypass that contacts an unauthorized target.|||허가되지 않은
  타깃에 접속하는 스코프 또는 이그레스 우회.
- Command injection, sandbox escape, unauthorized host-file access, or privilege
  escalation through a supported execution path.|||지원되는 실행 경로를 통한 명령
  인젝션, 샌드박스 탈출, 무단 호스트 파일 접근 또는 권한 상승.
- Dashboard authentication/authorization bypass or cross-user data exposure.|||
  대시보드 인증/인가 우회 또는 사용자 간 데이터 노출.
- Credentials, private evidence, or customer data exposed through prompts,
  logs, reports, errors, exports, or integrations without authorization.|||자격
  증명, 비공개 증거 또는 고객 데이터가 승인 없이 프롬프트, 로그, 보고서,
  오류, 내보내기 또는 연동을 통해 노출되는 문제.
- An incomplete or differently scoped scan reported as clean, resolved, or
  successfully completed.|||불완전하거나 다른 스코프의 스캔이 안전, 해결됨
  또는 성공 완료로 보고되는 문제.
- Prompt or target-output injection that crosses an enforced tool, filesystem,
  network, approval, or authorization boundary.|||프롬프트 또는 타깃 출력
  인젝션이 강제된 도구, 파일시스템, 네트워크, 승인 또는 인가 경계를 넘는 문제.

## Usually out of scope|||일반적인 범위 제외

- Vulnerabilities in a target being assessed; report them to that target's
  authorized owner.|||평가 대상 타깃의 취약점은 해당 타깃의 권한 있는 소유자에게
  제보하십시오.
- A model false positive, false negative, or refusal without a security-boundary
  bypass.|||보안 경계 우회가 없는 모델 오탐, 미탐 또는 거부.
- Expected effects of an explicitly approved destructive or intrusive test on a
  disposable target.|||폐기 가능한 타깃에서 명시적으로 승인된 파괴적 또는
  침투적 테스트의 예상 효과.
- Dependency advisories without a reproducible, reachable impact on a supported
  VXIS runtime.|||지원되는 VXIS 런타임에서 재현 가능하고 도달 가능한 영향이 없는
  의존성 권고.

## Run VXIS safely|||VXIS 안전 실행

1. Use a written scope and test only systems you are authorized to assess.|||서면
   스코프를 사용하고 평가 권한이 있는 시스템만 테스트하십시오.
2. Prefer disposable local benchmarks for intrusive validation.|||침투적 검증에는
   폐기 가능한 로컬 벤치마크를 우선 사용하십시오.
3. Provide only the credentials and environment variables required for the
   current scan.|||현재 스캔에 필요한 자격 증명과 환경변수만 제공하십시오.
4. Keep the dashboard on a trusted interface unless deployment authentication,
   TLS, and server-side scope are configured.|||배포 인증, TLS 및 서버 측 스코프가
   구성되지 않았다면 대시보드를 신뢰할 수 있는 인터페이스에만 바인딩하십시오.
5. Store logs, reports, databases, and workspaces with private permissions;
   review and redact them before sharing.|||로그, 보고서, 데이터베이스 및
   작업공간을 비공개 권한으로 저장하고 공유 전에 검토 및 민감정보 제거를
   수행하십시오.
6. Treat `partial`, `failed`, and coverage-`unknown` results as requiring follow-up,
   never as a clean bill of health.|||`partial`, `failed` 및 coverage-`unknown`
   결과는 후속 조치가 필요한 것으로 취급하고 안전 판정으로 간주하지 마십시오.

