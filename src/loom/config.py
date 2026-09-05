"""Operator-tunable runtime limits (D-020)."""

import os

_DEFAULT_MAX_BUDGET = 32_000


def max_budget() -> int:
    """Ceiling on a request's token budget, enforced by the read path.

    Default 32k; raise via LOOM_MAX_BUDGET for deployments that read large
    documents back and want bigger packs. The contract allows up to 1e6 as
    an absurd-value guard; this is the real, per-deployment ceiling.
    """
    raw = os.environ.get("LOOM_MAX_BUDGET", "").strip()
    if not raw:
        return _DEFAULT_MAX_BUDGET
    try:
        value = int(raw)
        return value if value > 0 else _DEFAULT_MAX_BUDGET
    except ValueError:
        return _DEFAULT_MAX_BUDGET
