# Benchmark League v2

This directory contains executable benchmark manifests for the `crown` engine.

## Smoke League

Start the local target:

```bash
docker compose -f infra/benchmarks/juice-shop.yml up -d
```

API crown-path smoke target:

```bash
docker compose -f infra/benchmarks/crapi/docker-compose.yml --compatibility up -d
```

- crAPI app: `http://localhost:8889`
- crAPI mail UI: `http://localhost:8026`
- Ports are offset from the official defaults so crAPI can run beside WebGoat on the same host.

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

## Same-environment local league

Boot the three shared local targets:

```bash
docker compose -f infra/benchmarks/juice-shop.yml up -d
docker compose -f infra/benchmarks/webgoat.yml up -d
docker compose -f infra/benchmarks/crapi/docker-compose.yml --compatibility up -d
```

Run the executable same-environment manifest:

```bash
uv run python -m vxis.scoring.benchmark_cli \
  --manifest infra/benchmarks/league-v2-local.json \
  --baseline tools/benchmark/baseline.json \
  --output benchmark_result_local.json \
  --profile crown
```

This closes the contract gap even before a full live comparison report exists:
the exact targets, URLs, and entrypoint now live in one executable manifest.
