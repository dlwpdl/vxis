"""Pure per-model USD cost estimator + a model×role usage aggregator.

Feeds the TUI cost panel. Everything here is an **ESTIMATE** — public prices
change, providers bill in ways we don't model (caching, batch discounts,
context-tier premiums), and unknown/local models have no price at all. The API
signals this explicitly: every dollar figure is paired with a ``cost_known`` /
``cost_estimated`` flag, and the formatted line uses a ``~$`` prefix (and
``~$? (no price)`` for unpriced models) so the human never reads it as a bill.

Prices are USD **per 1M tokens** as ``(input, output)``. Matching is by exact
model id first, else by the prefix before any ``:`` or ``/`` separator — so
``gemini-2.5-flash:thinking`` and ``gemini-2.5-pro/v2`` resolve to their base
model. Unknown models (and local/cli providers) estimate to ``$0.0`` with
``cost_known=False`` rather than guessing.

Pure: no I/O, no global mutable state, no network. ``from __future__`` is on so
the dict/tuple annotations stay strings under 3.9-style evaluation.
"""
from __future__ import annotations

# model_id -> (input_usd_per_1M, output_usd_per_1M). Public list prices.
MODEL_PRICES: dict[str, tuple[float, float]] = {
    "gemini-2.5-pro": (1.25, 10.0),
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.5-flash-lite": (0.10, 0.40),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-opus-4-8": (15.0, 75.0),
    "gpt-5.4": (1.25, 10.0),
    "deepseek-chat": (0.27, 1.10),
}

_PER_MILLION = 1_000_000.0
_ROUND_DP = 6


def _resolve_price(model: str) -> tuple[float, float] | None:
    """Return ``(input, output)`` price for ``model``, or ``None`` if unknown.

    Exact id wins; otherwise fall back to the prefix before the first ``:`` or
    ``/`` (covers variant suffixes like ``...:thinking`` / ``.../v2``). Returns
    ``None`` for anything not in :data:`MODEL_PRICES` — including local/cli
    providers, which simply have no public price.
    """
    if model in MODEL_PRICES:
        return MODEL_PRICES[model]
    # Split on whichever separator appears first so both ":" and "/" work.
    base = model
    for sep in (":", "/"):
        if sep in base:
            base = base.split(sep, 1)[0]
    return MODEL_PRICES.get(base)


def estimate_cost(
    model: str, input_tokens: int, output_tokens: int
) -> tuple[float, bool]:
    """Estimate USD cost for one call.

    Returns ``(usd_rounded_to_6dp, is_known_price)``. An unknown model (or a
    local/cli provider with no public price) returns ``(0.0, False)`` — never a
    guessed number.
    """
    price = _resolve_price(model)
    if price is None:
        return (0.0, False)
    input_per_m, output_per_m = price
    cost = (input_tokens * input_per_m + output_tokens * output_per_m) / _PER_MILLION
    return (round(cost, _ROUND_DP), True)


def summarize_usage(rows: list[dict]) -> dict:
    """Aggregate per-call usage rows into a model×role cost summary.

    Each row is ``{"model", "role", "input_tokens", "output_tokens"}``. Rows are
    bucketed by ``(model, role)``; ``calls`` counts the rows in each bucket.
    Buckets are returned sorted by ``cost_usd`` descending (the priciest line
    sits at the top of the TUI panel). ``cost_estimated`` is ``True`` when at
    least one bucket has a known price — the panel-level "these are estimates"
    flag.
    """
    # Preserve first-seen order within equal cost via insertion-ordered dict.
    buckets: dict[tuple[str, str], dict] = {}

    for row in rows:
        model = str(row.get("model", ""))
        role = str(row.get("role", ""))
        in_tok = int(row.get("input_tokens", 0) or 0)
        out_tok = int(row.get("output_tokens", 0) or 0)
        key = (model, role)

        bucket = buckets.get(key)
        if bucket is None:
            bucket = {
                "model": model,
                "role": role,
                "input_tokens": 0,
                "output_tokens": 0,
                "calls": 0,
            }
            buckets[key] = bucket
        bucket["input_tokens"] += in_tok
        bucket["output_tokens"] += out_tok
        bucket["calls"] += 1

    by_model_role: list[dict] = []
    total_tokens = 0
    total_cost = 0.0
    any_known = False

    for bucket in buckets.values():
        cost, known = estimate_cost(
            bucket["model"], bucket["input_tokens"], bucket["output_tokens"]
        )
        bucket["cost_usd"] = cost
        bucket["cost_known"] = known
        total_tokens += bucket["input_tokens"] + bucket["output_tokens"]
        total_cost += cost
        any_known = any_known or known
        by_model_role.append(bucket)

    by_model_role.sort(key=lambda b: b["cost_usd"], reverse=True)

    return {
        "by_model_role": by_model_role,
        "total_tokens": total_tokens,
        "total_cost_usd": round(total_cost, _ROUND_DP),
        "cost_estimated": any_known,
    }


def format_cost_line(
    model: str, role: str, input_tokens: int, output_tokens: int
) -> str:
    """One-line cost summary for the TUI, e.g.::

        gemini-2.5-flash (director)  12,345 tok  ~$0.0031

    Tokens are the comma-grouped total (input+output). The ``~$`` prefix marks
    the figure as an estimate; unpriced models render ``~$? (no price)``.
    """
    total_tokens = int(input_tokens) + int(output_tokens)
    cost, known = estimate_cost(model, input_tokens, output_tokens)
    money = f"~${cost:.4f}" if known else "~$? (no price)"
    return f"{model} ({role})  {total_tokens:,} tok  {money}"
