"""Rich help rendering for the top-level VXIS CLI."""

from __future__ import annotations

from collections.abc import Callable

from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table


def render_help(console: Console, print_banner: Callable[[], None]) -> None:
    """Render the full VXIS usage guide."""
    print_banner()

    from vxis.registry import (
        BENCHMARK_TARGETS,
        EXTERNAL_PHASES,
        FUTURE_PHASES,
        STAGE_NAMES,
        VERSION,
        WEB_PHASES,
    )

    console.print(f"  [bold]v{VERSION}[/bold]\n")

    guide = """## 스캔

```bash
# 벤치마크 스캔 (스코어링 + HTML 리포트 자동 생성)
python tools/growth_loop_runner.py --targets mutillidae --iterations 1

# 여러 타겟
python tools/growth_loop_runner.py --targets dvwa,juice-shop,webgoat --iterations 1

# 시간 제한 (KST 06시까지 반복)
python tools/growth_loop_runner.py --targets dvwa --until 06:00

# CLI 직접 스캔 (Brain-First 파이프라인)
vxis scan http://localhost:8081                    # LLM API Brain 자율 실행
vxis scan http://localhost:8081 --interactive      # Claude Code가 Brain (MCP)
vxis scan http://localhost:8081 -g                 # Ghost 익명화 켜기
vxis scan http://localhost:8081 --resume <ckpt>    # 체크포인트 재개
vxis scan http://app.acme.com --approve-destructive # 파괴적 액션 사전 승인(기본 차단)
```

## Scope & 안전 (Scope Gate)

`vxis scan`(단일 타깃·`--manifest`)과 웹 대시보드 스캔은 스코프 게이트를 통과합니다 —
각 target-facing tool·플러그인 호출의 타깃 host를 스코프와 대조해 허용/차단합니다.

```bash
# 스코프 파일 우선순위 (먼저 발견되는 것 사용)
#   ./vxis-scope.json → ~/.vxis/scopes/<host>.json → ~/.vxis/scopes/default.json → 안전 기본값
#
# 파일이 없으면: 스캔 타깃 host만 in-scope로 자동 주입(fail-closed)
#   → tool/플러그인이 그 외 host를 직접 겨냥하면 차단
vxis scan http://app.acme.com                       # app.acme.com만 in-scope
vxis scan http://app.acme.com --approve-destructive # approval_required 파괴 액션 허용
vxis scan http://localhost:3000 --allow-inject      # 인젝션 승인 게이트 생략(소유/인가 타깃만)
```

- **파괴적 액션**(DELETE·업로드 등)은 기본 **차단/승인필요** — 위 플래그로만 허용
- 차단 결정은 audit 로그에 기록
- ⚠️ 현재 scope 게이트는 **tool/플러그인 호출 단위**입니다 — HTTP 리다이렉트·스킬 내부 요청의
  per-hop 검증과 `batch`/`client`/대화형/MCP 경로 활성화는 후속 작업 (아래 알려진 한계)

> P1 adversary-emulation 프로필은 여기에 더해 engagement 기반 인가(scope+audit+beacon teardown)를 강제합니다 — 아래 P1 섹션 참조.

## 리포트

```bash
vxis report <SCAN_ID> -o reports/output.html
vxis export <SCAN_ID> --format docx                # DOCX/JSON/CSV/Attestation
```

## Self-Growth Intelligence (`vxis news`)

```bash
vxis news pending              # 검토 대기 중인 자가성장 제안
vxis news show <PROPOSAL_ID>   # 제안 상세 보기
vxis news approve <PROPOSAL_ID># 수동 승인 → 자동 적용
vxis news reject <PROPOSAL_ID> # 거부
vxis news rollback <PROPOSAL_ID>
vxis news digest --days 7      # 주간 요약
vxis news stats                # 부트스트랩 모드 + 누적 통계
```

## MCP 서버 (외부 Brain 연동)

```bash
# Claude Code에 VXIS를 도구로 등록
claude mcp add vxis python -m vxis.mcp_server

# 41개 primitive 툴 노출: sense_*/pattern_*/kb_*/session_*/
#   ghost_*/chain_*/output_*/phase_*/scope_*
```

## P1 Adversary Emulation

```bash
# 1회 인가 컨텍스트 생성. operator=고객이 알아볼 내부 핸들(BAC 기본값)
vxis eng create ACME-2026Q2 --scope app.acme.com,10.0.0.0/24 --expiry 2026-06-18 --technique recon --technique c2 --attest

# engagement-gated live profile. 모든 target-facing 액션은 scope/audit/enforcer 통과 필요
vxis scan app.acme.com --profile p1 --eng eng_acme_2026q2

# 진행 중 스코프나 노출 강도 변경. scan/session을 닫지 않고 저장된 engagement만 갱신
vxis eng scope-add eng_acme_2026q2 --allow api.acme.com --deny payments.acme.com
vxis eng set-intensity eng_acme_2026q2 loud       # stealth | standard | loud
vxis eng show eng_acme_2026q2                     # 현재 operator/scope/intensity/beacons 확인

# 종료. 저장된 beacon registry와 ghost layer를 teardown하고 engagement를 closed로 봉인
vxis eng close eng_acme_2026q2
```

## 기타 명령어

```bash
vxis plugins          # 플러그인 목록
vxis setup            # 도구 설치 현황
vxis diff <ID1> <ID2> # 두 스캔 비교
vxis trend '*'        # 전체 타겟 점수 추이
vxis dashboard        # 웹 대시보드
vxis kb               # 취약점 지식베이스
vxis schedule         # 지속 모니터링 스케줄
vxis client           # 클라이언트 관리
vxis integrations     # Slack/Discord/Jira/Linear/GitHub
vxis version          # 버전 정보
```
"""
    console.print(Markdown(guide))

    console.print("\n[bold]Pipeline Phases[/bold]\n")
    phase_table = Table(show_header=True, header_style="bold cyan")
    phase_table.add_column("Phase", width=8)
    phase_table.add_column("Name", width=45)
    phase_table.add_column("Stage", width=20)

    prev_stage = ""
    for p in WEB_PHASES:
        stage_label = STAGE_NAMES.get(p.stage, p.stage)
        if p.stage != prev_stage:
            phase_table.add_row("", "", "", style="dim")
            prev_stage = p.stage
        phase_table.add_row(f"P{p.id}", p.name, stage_label)

    phase_table.add_row("", "", "", style="dim")
    for p in EXTERNAL_PHASES:
        phase_table.add_row(f"P{p.id}", f"{p.name} [dim](GHA)[/dim]", "External", style="dim")
    for p in FUTURE_PHASES:
        phase_table.add_row(f"P{p.id}", f"{p.name} [dim](planned)[/dim]", "Future", style="dim")

    console.print(phase_table)

    console.print("\n[bold]Benchmark Targets[/bold]\n")
    target_table = Table(show_header=True, header_style="bold cyan")
    target_table.add_column("Name", width=12)
    target_table.add_column("Port", width=10)
    target_table.add_column("Category", width=10)
    target_table.add_column("Description", width=30)
    target_table.add_column("Docker", width=30)

    for t in BENCHMARK_TARGETS:
        port = t.port.split(":")[0]
        docker_cmd = f"docker run -d -p {t.port} {t.image}" if t.image else f"docker compose ({t.compose})"
        target_table.add_row(t.name, port, t.category, t.description, docker_cmd)

    console.print(target_table)
