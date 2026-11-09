"""Statistics: attack success rates with exact intervals, and defence comparisons.

* Clopper-Pearson exact 95% intervals for every success rate (small n, rates near 0 or 1).
* Cochran-Mantel-Haenszel test to compare two defences, stratified by goal, so that easy
  and hard goals are not pooled together as if they were one population.
* Holm correction across the family of per-category comparisons.
"""
from __future__ import annotations

from collections import defaultdict

from scipy.stats import beta, chi2


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple:
    if n == 0:
        return (float("nan"), float("nan"))
    lo = 0.0 if k == 0 else beta.ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(1 - alpha / 2, k + 1, n - k)
    return float(lo), float(hi)


def rate_row(k: int, n: int) -> dict:
    lo, hi = clopper_pearson(k, n)
    return {"k": k, "n": n, "rate": k / n if n else float("nan"), "lo": lo, "hi": hi}


def summarise(results: list, by: str) -> dict:
    """by in {"goal_id", "category", "strategy", "all"} -> {(defence, key): rate_row}."""
    counts = defaultdict(lambda: [0, 0])
    for r in results:
        key = "all" if by == "all" else r[by]
        c = counts[(r["defence"], key)]
        c[0] += int(r["success"])
        c[1] += 1
    return {k: rate_row(*v) for k, v in counts.items()}


def cmh_test(results: list, defence_a: str, defence_b: str, subset=None) -> dict:
    """CMH test of 'success rate differs between defence A and B', strata = goals."""
    tables = defaultdict(lambda: [[0, 0], [0, 0]])  # goal -> [[a_succ, a_fail], [b_succ, b_fail]]
    for r in results:
        if subset and not subset(r):
            continue
        if r["defence"] not in (defence_a, defence_b):
            continue
        row = 0 if r["defence"] == defence_a else 1
        tables[r["goal_id"]][row][0 if r["success"] else 1] += 1

    num = var = or_num = or_den = 0.0
    for (a, b), (c, d) in tables.values():
        n1, n2, m1, m2 = a + b, c + d, a + c, b + d
        N = n1 + n2
        if n1 == 0 or n2 == 0 or N < 2:
            continue
        num += a - n1 * m1 / N
        var += n1 * n2 * m1 * m2 / (N * N * (N - 1))
        or_num += a * d / N
        or_den += b * c / N
    if var == 0:
        stat, p = 0.0, 1.0
    else:
        stat = max(abs(num) - 0.5, 0.0) ** 2 / var  # continuity-corrected
        p = float(chi2.sf(stat, 1))
    odds_ratio = (or_num / or_den) if or_den > 0 else float("inf") if or_num > 0 else float("nan")
    return {"a": defence_a, "b": defence_b, "chi2": stat, "p": p, "mh_odds_ratio": odds_ratio,
            "strata": len(tables)}


def holm(pvalues: list) -> list:
    """Holm step-down adjusted p-values, returned in the original order."""
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    adj, running = [0.0] * m, 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvalues[i]))
        adj[i] = running
    return adj
