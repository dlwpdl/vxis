# VXIS LLM Wiki — Index

> wiki 의 카탈로그. 새 페이지 추가 시 해당 섹션에 한 줄.
> 형식: `- [<title>](<relative path>) — <when_to_read hint>`
> ↑ 한 줄 hint 는 페이지 frontmatter 의 `when_to_read` 를 그대로 가져오면 됨.
>
> 작성 규칙은 [CLAUDE.md](CLAUDE.md) 참조. 모든 페이지 = `핵심 사실` 표 + `TL;DR` + 본문.

## 카테고리 → 어떤 질문에 답하나

| 카테고리 | 어떤 질문에 답하나 | 위치 |
|---|---|---|
| Concepts | "X 는 왜·어떻게 동작?" 추상 원칙 | `concepts/` |
| Skills | "이 skill 무엇 하나·payload 어디·param" | `entities/skills/` |
| Modules | "이 모듈 책임·invariant" | `entities/modules/` |
| Pipelines | "P<N> 은 어느 단계·input/output" | `entities/pipelines/` |
| Decisions (ADR) | "왜 X vs Y 결정했나" | `decisions/` |
| Incidents | "옛날에 무슨 사고 났고 어떻게 풀었나" | `sources/incidents/` |
| Sources/Benchmarks | "스캔 결과 데이터" | `sources/benchmarks/` |
| Sources/Research | "외부 논문·CVE 요약" | `sources/research/` |

---

## Concepts
_(Phase 2 시드 예정 — brain_first, chain_intelligence, payload_rotation, severity_oracle, scoring_model, plan_review_workflow, vxis_architecture, ai_context_hygiene)_

## Entities

### Skills
_(Phase 3 시드 예정 — SKILL_REGISTRY 15개)_

### Modules
_(Phase 4 시드 예정 — scan_loop, skill_runner, report_generator, brain, hands, eyes, xray)_

### Pipelines
_(Phase 4 시드 예정 — P0/P1/P2/P3/P4/P5/P6/P7/P8/P11/P12/P13/P15/P18)_

## Decisions
_(Phase 5 시드 예정 — agpl_forbidden, claude_p_first, no_raw_httpx, ncc_group_report_format, dynamic_not_static)_

## Sources

### Benchmarks
_(유기적 추가 — 새 스캔 리포트 요약)_

### Research
_(유기적 추가 — 외부 논문/블로그/CVE)_

### Incidents
_(Phase 5 시드 예정 — 2026_04_16_seven_disconnections, auto_login_fix, payload_rotation_and_sweep)_
