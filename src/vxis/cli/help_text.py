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
```

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
