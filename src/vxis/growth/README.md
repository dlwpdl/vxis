# `src/vxis/growth/` — Growth Layer / Self-Growth Intelligence

Bootstrap layer for the manually approved Growth Loop benchmark (GH Actions
`growth-loop.yml`). It runs VXIS against fixed training targets plus an
unexposed holdout, scores the results, and stores bounded LLM suggestions for
human review. It does not apply, execute, commit, or push generated code.

Automatic promotion remains disabled until generation, secret-free validation,
and promotion can run on separate isolated workers with a verified patch digest.

Key concept: "AI가 타겟 평가 → 점수 → 약점 인식 → 검토 제안" cycle per
CLAUDE.md scoring rules.
