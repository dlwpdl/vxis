"""Prior update math for VXIS hypothesis scoring.

The public `delta` value is treated as a log-likelihood-ratio adjustment. Positive
values increase belief, negative values decrease it, and zero leaves the prior unchanged.
"""

from __future__ import annotations

import math
from typing import Any

EPSILON = 1e-6
MAX_ABS_LOG_LIKELIHOOD_DELTA = 8.0
DEFAULT_CONFIRM_PROPAGATION_DELTA = 1.0
DEFAULT_REFUTE_PROPAGATION_DELTA = 1.25
DEFAULT_PROPAGATION_DECAY = 0.5


def clamp_probability(value: Any, *, lower: float = 0.0, upper: float = 1.0) -> float:
    """Return `value` as a finite probability within `[lower, upper]`."""
    try:
        probability = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"probability must be numeric, got {value!r}") from exc
    if not math.isfinite(probability):
        raise ValueError(f"probability must be finite, got {value!r}")
    if lower > upper:
        raise ValueError("lower probability bound cannot exceed upper bound")
    return max(lower, min(upper, probability))


def coerce_delta(value: Any) -> float:
    """Return a bounded finite log-likelihood-ratio delta."""
    if value is None:
        return 0.0
    try:
        delta = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"delta must be numeric, got {value!r}") from exc
    if not math.isfinite(delta):
        raise ValueError(f"delta must be finite, got {value!r}")
    return max(-MAX_ABS_LOG_LIKELIHOOD_DELTA, min(MAX_ABS_LOG_LIKELIHOOD_DELTA, delta))


def _bounded_for_odds(probability: float) -> float:
    return clamp_probability(probability, lower=EPSILON, upper=1.0 - EPSILON)


def logit(probability: Any) -> float:
    """Convert a probability into log-odds."""
    p = _bounded_for_odds(float(clamp_probability(probability)))
    return math.log(p / (1.0 - p))


def inverse_logit(log_odds: float) -> float:
    """Convert log-odds back into a probability."""
    if log_odds >= 0:
        z = math.exp(-log_odds)
        return 1.0 / (1.0 + z)
    z = math.exp(log_odds)
    return z / (1.0 + z)


def bayes_update(prior: Any, delta: Any) -> float:
    """Apply a bounded log-odds update to a prior probability."""
    prior_probability = clamp_probability(prior)
    bounded_delta = coerce_delta(delta)
    posterior = inverse_logit(logit(prior_probability) + bounded_delta)
    return clamp_probability(posterior)


def prior_for_status(prior: Any, status: str | None) -> float:
    """Force final status priors into useful dashboard ranges."""
    probability = clamp_probability(prior)
    if status == "confirmed":
        return max(probability, 0.95)
    if status == "refuted":
        return min(probability, 0.05)
    return probability


def propagation_seed_delta(status: str | None, delta: Any) -> float:
    """Translate a parent update into the first child propagation delta."""
    bounded_delta = coerce_delta(delta)
    if status == "confirmed":
        return max(abs(bounded_delta), DEFAULT_CONFIRM_PROPAGATION_DELTA)
    if status == "refuted":
        return -max(abs(bounded_delta), DEFAULT_REFUTE_PROPAGATION_DELTA)
    return bounded_delta * DEFAULT_PROPAGATION_DECAY
