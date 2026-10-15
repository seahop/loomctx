"""Operator-tunable runtime limits (D-020)."""

import os

_DEFAULT_MAX_BUDGET = 32_000


def max_budget() -> int:
    """Ceiling on a request's token budget, enforced by the read path.

    Default 32k; raise via LOOMCTX_MAX_BUDGET for deployments that read large
    documents back and want bigger packs. The contract allows up to 1e6 as
    an absurd-value guard; this is the real, per-deployment ceiling.
    """
    raw = os.environ.get("LOOMCTX_MAX_BUDGET", "").strip()
    if not raw:
        return _DEFAULT_MAX_BUDGET
    try:
        value = int(raw)
        return value if value > 0 else _DEFAULT_MAX_BUDGET
    except ValueError:
        return _DEFAULT_MAX_BUDGET


_DEFAULT_MAX_SCOPE_ENTITIES = 2_000
_DEFAULT_MAX_SCOPE_OBSERVATIONS = 100_000


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        return default
    return value if value > 0 else default


def max_scope_entities() -> int:
    """Ceiling on the entities one scope resolves to (D-058). 500 anchors
    at depth 3 over a 2,740-edge hub reached every entity in reach, each
    gathered up to 1,000 rows. The cut is reported in the pack's
    `truncated` (reason scope_cap), never silent. LOOMCTX_MAX_SCOPE_ENTITIES."""
    return _positive_int("LOOMCTX_MAX_SCOPE_ENTITIES", _DEFAULT_MAX_SCOPE_ENTITIES)


_DEFAULT_MAX_LIST_CANDIDATES = 500_000   # a whole type at 500k objects (370,000 users) fits, D-110


def max_list_candidates() -> int:
    """Ceiling on the entities one listing examines (D-107): the members of a
    group holding every account, at 500,000 objects, are 370,000 of them —
    200,000 cut a type scan there short of the accounts asked for. A
    cut makes the page's total a lower bound and says so (`exact` false),
    never silent. LOOMCTX_MAX_LIST_CANDIDATES."""
    return _positive_int("LOOMCTX_MAX_LIST_CANDIDATES", _DEFAULT_MAX_LIST_CANDIDATES)


def max_scope_observations() -> int:
    """Ceiling on the observations one ask gathers across all its subjects
    (D-058): the memory bound the entity cap alone does not give, since
    each entity may bring up to the gather limit. LOOMCTX_MAX_SCOPE_OBSERVATIONS."""
    return _positive_int("LOOMCTX_MAX_SCOPE_OBSERVATIONS", _DEFAULT_MAX_SCOPE_OBSERVATIONS)
