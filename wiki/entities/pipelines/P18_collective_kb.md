---
name: P18 Collective KB
type: pipeline
status: active
when_to_read: 취약점 지식 베이스 / remediation·CWE·OWASP 매핑 / static lookup / 에이전트 추천
updated: 2026-04-16
sources:
  - ../../../src/vxis/knowledge/kb.py
  - ../../../src/vxis/knowledge/store.py
  - ../../../src/vxis/knowledge/compressor.py
related:
  - ./P12_evolution.md
  - ./P6_ncc_style.md
  - ./P1_director.md
code_anchors:
  - src/vxis/knowledge/kb.py:RemediationInfo
  - src/vxis/knowledge/store.py:KnowledgeStore
  - src/vxis/knowledge/compressor.py:ContextCompressor
---
# P18 — Collective KB

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 8 Learning |
| 앞 단계 | P12 Evolution |
| 뒤 단계 | P1 Director (다음 스캔 전략) |
| 역할 | 취약점 지식 베이스 + 스캔 학습 누적 |
| KB | `kb.py` — static lookup (remediation, CWE, OWASP) |
| Store | `store.py` — 동적 학습 (tool 추천, 상관관계) |
| Compressor | `compressor.py` — ContextCompressor, Brain 입력 압축 |

## TL;DR
"쓸수록 강해지는" Day 1→Day 100 구조의 지식 층. 정적 KB(취약점 분류·remediation) + 동적 Store(과거 스캔 학습). Director 가 다음 스캔 시 tool 추천/스킵 결정에 사용.

## Stage
Learning — Evolution(P12) 이후 최종 학습 단계. 다음 스캔으로 피드백.

## Inputs-Outputs
- Input: 완료된 스캔 결과, 새 에이전트, 외부 CVE feed.
- Output: `KnowledgeStore` 업데이트, `RemediationInfo` DB, Brain 추천 데이터.

## Triggers
- 스캔 완료 후 `DirectorAgent` 가 `KnowledgeStore.learn(result)` 호출.
- `scripts/growth_loop.py --weekly` 에서 주간 동기화.

## Related Pipelines
- [P12 Evolution](./P12_evolution.md) — 앞 단계 (새 에이전트 공급)
- [P1 Director](./P1_director.md) — 뒤 단계 (다음 스캔 시 이 KB 참조)
- [P6 NCC Style](./P6_ncc_style.md) — remediation 필드 채움
