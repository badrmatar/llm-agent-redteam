"""Turns a results.jsonl file into report.md and a chart."""
from __future__ import annotations

import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from .goals import CATEGORIES, GOALS, STRATEGIES  # noqa: E402
from .stats import cmh_test, holm, summarise  # noqa: E402

DEF_ORDER = ("none", "prompt", "guard")


def load(path: str) -> list:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def fmt(row) -> str:
    if row is None:
        return "–"
    return f"{100 * row['rate']:.0f}% [{100 * row['lo']:.0f}, {100 * row['hi']:.0f}] ({row['k']}/{row['n']})"


def table(summary: dict, keys, defences, label: str) -> str:
    lines = [f"| {label} | " + " | ".join(defences) + " |",
             "|---|" + "---|" * len(defences)]
    for k in keys:
        lines.append(f"| {k} | " + " | ".join(fmt(summary.get((d, k))) for d in defences) + " |")
    return "\n".join(lines)


def comparisons(results: list, defences) -> list:
    rows = []
    for d in defences:
        if d == "none":
            continue
        rows.append(("all", cmh_test(results, "none", d)))
        for c in CATEGORIES:
            rows.append((c, cmh_test(results, "none", d, subset=lambda r, c=c: r["category"] == c)))
    adj = holm([r[1]["p"] for r in rows])
    return [(scope, res, p) for (scope, res), p in zip(rows, adj)]  # noqa: B905 (Python 3.9 support)


def plot(summary: dict, defences, path: str):
    fig, ax = plt.subplots(figsize=(8, 4.6))
    width = 0.8 / len(defences)
    for i, d in enumerate(defences):
        xs, ys, err = [], [], [[], []]
        for j, c in enumerate(CATEGORIES):
            row = summary.get((d, c))
            if not row:
                continue
            xs.append(j + i * width)
            ys.append(row["rate"])
            err[0].append(row["rate"] - row["lo"])
            err[1].append(row["hi"] - row["rate"])
        ax.bar(xs, ys, width, yerr=err, capsize=3, label=f"defence: {d}")
    ax.set_xticks([j + width * (len(defences) - 1) / 2 for j in range(len(CATEGORIES))])
    ax.set_xticklabels(CATEGORIES)
    ax.set_ylabel("attack success rate")
    ax.set_ylim(0, 1)
    ax.set_title("Attack success by category (95% Clopper-Pearson intervals)")
    ax.legend(frameon=False, ncol=len(defences), loc="upper center", bbox_to_anchor=(0.5, -0.1))
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def example(results: list) -> str:
    for r in sorted(results, key=lambda r: (r["judge_method"] != "rule", r["turns_used"], r["goal_id"])):
        if r["success"] and r["defence"] == "none":
            turns = "\n".join(f"> **Attacker:** {t['attacker']}\n>\n> **Agent:** {t['target']}\n>"
                              for t in r["transcript"])
            return f"Goal {r['goal_id']} ({r['category']}, {r['strategy']}): {r['objective']}\n\n{turns}"
    return "No successful attack against the undefended agent in this run."


def build_report(results_path: str, out_dir: str, meta: dict) -> str:
    results = load(results_path)
    defences = [d for d in DEF_ORDER if any(r["defence"] == d for r in results)]
    by_all = summarise(results, "all")
    by_cat = summarise(results, "category")
    by_strat = summarise(results, "strategy")
    by_goal = summarise(results, "goal_id")
    chart = os.path.join(out_dir, "success_by_category.png")
    plot(by_cat, defences, chart)

    comp_lines = ["| comparison | scope | MH odds ratio | χ² | p (Holm) |", "|---|---|---|---|---|"]
    for scope, res, p_adj in comparisons(results, defences):
        orr = res['mh_odds_ratio']
        orr = "n/a" if orr != orr else ("∞" if orr == float("inf") else f"{orr:.2f}")
        comp_lines.append(f"| none vs {res['b']} | {scope} | {orr} | "
                          f"{res['chi2']:.2f} | {p_adj:.3g} |")

    mock_warning = ("\n> **Note:** these results come from the offline mock models. They only show that "
                    "the pipeline works and are not real findings.\n" if meta.get("provider") == "mock" else "")
    goal_rows = [g.id for g in GOALS if any(r["goal_id"] == g.id for r in results)]
    goal_desc = "\n".join(f"- **{g.id}** ({g.category}, {g.strategy}): {g.objective}" for g in GOALS if g.id in goal_rows)

    md = f"""# Red-teaming report
{mock_warning}
**Setup:** provider `{meta.get('provider')}`, attacker `{meta.get('attacker_model')}`, target `{meta.get('target_model')}`,
judge `{meta.get('judge_model')}`. {meta.get('runs')} runs per goal per defence, up to {meta.get('turns')} attacker turns,
{len(results)} conversations in total.

Each cell is the attack success rate with a 95% Clopper-Pearson interval and the raw count.

## Overall
{table(by_all, ['all'], defences, 'scope')}

## By category
{table(by_cat, [c for c in CATEGORIES if any((d, c) in by_cat for d in defences)], defences, 'category')}

![success by category](success_by_category.png)

## By attack strategy
{table(by_strat, [s for s in STRATEGIES if any((d, s) in by_strat for d in defences)], defences, 'strategy')}

## Does a defence really help?
Cochran-Mantel-Haenszel test, stratified by goal, comparing each defence with no defence.
An odds ratio above 1 means attacks succeed more often without the defence. p-values are
Holm-corrected across every row of this table.

{chr(10).join(comp_lines)}

## By goal
{table(by_goal, goal_rows, defences, 'goal')}

{goal_desc}

## Example successful attack (no defence)
{example(results)}
"""
    path = os.path.join(out_dir, "report.md")
    with open(path, "w") as f:
        f.write(md)
    return path
