# `src/vxis/growth/` — Growth Layer / Self-Growth Intelligence

Bootstrap layer for the weekly Growth Loop benchmarks (GH Actions `growth-loop.yml`). Runs VXIS against a fixed set of benchmark targets (DVWA/Juice Shop/WebGoat), scores the results, compares against the previous week, and optionally auto-improves via code edits.

Phase A's benchmark captures will feed into this eventually — Phase B will re-enable the auto-improve loop once Brain-First tuning is stable.

Key concept: "AI이 타겟 공격 → 점수 → 약점 인식 → 코드 개선 → 재공격" cycle per CLAUDE.md scoring rules.
