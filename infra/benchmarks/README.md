# Benchmark League v2

This directory contains executable benchmark manifests for the `crown` engine.

## Smoke League

Start the local target:

```bash
docker compose -f infra/benchmarks/docker-compose.smoke.yml up -d
```

Run the same manifest entrypoint used by CI:

```bash
uv run python -m vxis.scoring.benchmark_cli \
  --manifest infra/benchmarks/league-v2-smoke.json \
  --baseline tools/benchmark/baseline.json \
  --output benchmark_result_web.json \
  --target-type web \
  --profile crown
```

The smoke league proves the runner, target boot, score serialization, baseline
comparison, and GitHub result artifact path work. It is not the full quality
gate. Full Benchmark League v2 adds WebGoat, DVWA/Mutillidae, crAPI, VAmPI,
DVGA, clean controls, randomized arena targets, and a secret holdout.
