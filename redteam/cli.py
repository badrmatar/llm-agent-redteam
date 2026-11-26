"""Command-line interface (also available as the `redteam` command after `pip install -e .`).

Examples:
  redteam --provider mock                      # offline smoke test, no API key
  redteam --provider openai --runs 10          # real run (needs OPENAI_API_KEY)
  redteam --provider anthropic --runs 10       # real run (needs ANTHROPIC_API_KEY)
  redteam --report-only results/openai         # rebuild the report from saved results
"""
from __future__ import annotations

import argparse
import json
import os
import time

from redteam.mcp_target import SCENARIOS, run_mcp_episode
from redteam.models import DEFAULT_MODELS, make_model
from redteam.report import build_report
from redteam.runner import rejudge, run_experiment, run_utility
from redteam.stats import clopper_pearson
from redteam.target import DEFENCES


def run_mcp(args) -> None:
    """Target a local MCP server instead of the fake shop."""
    scenario = SCENARIOS[args.mcp_scenario]
    out = args.out or os.path.join("results", "mcp")
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, f"{scenario.id}.jsonl")
    print(f"Targeting local MCP server: {args.mcp_cmd}")
    print(f"Scenario {scenario.id}: {scenario.attacker_objective}")
    k = 0
    with open(path, "w") as f:
        for r in range(args.runs):
            att = make_model(args.provider, args.attacker_model, seed=r)
            tgt = make_model(args.provider, args.target_model, seed=r + 1000)
            res = run_mcp_episode(scenario, args.mcp_cmd, att, tgt, turns=args.turns)
            res["run"] = r
            k += int(res["success"])
            f.write(json.dumps(res) + "\n")
    lo, hi = clopper_pearson(k, args.runs)
    print(f"\nAttack success: {k}/{args.runs}  ({100 * k / args.runs:.0f}%, "
          f"95% CI [{100 * lo:.0f}, {100 * hi:.0f}])")
    print(f"Transcripts written to {path}")


def main():
    ap = argparse.ArgumentParser(description="Red-team a tool-using LLM customer-support agent.")
    ap.add_argument("--provider", choices=["mock", "openai", "anthropic"], default="mock")
    ap.add_argument("--runs", type=int, default=10, help="repeats per goal per defence")
    ap.add_argument("--turns", type=int, default=5, help="max attacker turns per conversation")
    ap.add_argument("--defences", nargs="+", choices=DEFENCES, default=list(DEFENCES))
    ap.add_argument("--goals", nargs="*", help="only these goal ids, e.g. R1 E3")
    ap.add_argument("--attacker-model")
    ap.add_argument("--target-model")
    ap.add_argument("--judge-model")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", help="output folder (default results/<provider>)")
    ap.add_argument("--mcp-cmd", help="target a LOCAL MCP server instead of the fake shop, "
                    "e.g. 'python examples/mcp_support_server.py' (local processes only)")
    ap.add_argument("--mcp-scenario", choices=list(SCENARIOS), default="mcp-delete")
    ap.add_argument("--no-utility", action="store_true", help="skip the benign utility tasks")
    ap.add_argument("--resume", action="store_true", help="keep finished episodes and only run missing or failed ones")
    ap.add_argument("--rejudge", metavar="FOLDER", help="re-score FOLDER/results.jsonl with the current judges, then rebuild the report")
    ap.add_argument("--report-only", metavar="FOLDER", help="rebuild report from FOLDER/results.jsonl")
    args = ap.parse_args()

    if args.mcp_cmd:
        run_mcp(args)
        return

    if args.rejudge:
        with open(os.path.join(args.rejudge, "meta.json")) as f:
            meta = json.load(f)
        recs = rejudge(os.path.join(args.rejudge, "results.jsonl"), meta["provider"], meta.get("judge_model"), args.workers)
        print(f"Re-judged {len(recs)} conversations, {sum(r['success'] for r in recs)} successful attacks")
        print(build_report(os.path.join(args.rejudge, "results.jsonl"), args.rejudge, meta))
        return

    if args.report_only:
        with open(os.path.join(args.report_only, "meta.json")) as f:
            meta = json.load(f)
        print(build_report(os.path.join(args.report_only, "results.jsonl"), args.report_only, meta))
        return

    out = args.out or os.path.join("results", args.provider)
    os.makedirs(out, exist_ok=True)
    default = DEFAULT_MODELS.get(args.provider, "mock")
    meta = {
        "provider": args.provider, "runs": args.runs, "turns": args.turns, "defences": args.defences,
        "attacker_model": args.attacker_model or default, "target_model": args.target_model or default,
        "judge_model": args.judge_model or default, "seed": args.seed,
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    meta_path = os.path.join(out, "meta.json")
    if args.resume and os.path.exists(meta_path):
        with open(meta_path) as f:
            meta["started"] = json.load(f).get("started", meta["started"])
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"Running {args.provider}: defences={args.defences} runs={args.runs} turns={args.turns}")
    run_experiment(args.provider, args.defences, args.runs, args.turns,
                   os.path.join(out, "results.jsonl"), workers=args.workers, goal_ids=args.goals,
                   attacker_model_name=args.attacker_model, target_model_name=args.target_model,
                   judge_model_name=args.judge_model, seed=args.seed,
                   resume=args.resume)
    if not args.no_utility:
        print("Running benign utility tasks")
        run_utility(args.provider, args.defences, args.runs, os.path.join(out, "utility.jsonl"),
                    workers=args.workers, target_model_name=args.target_model, seed=args.seed)
    path = build_report(os.path.join(out, "results.jsonl"), out, meta)
    print(f"Report written to {path}")


if __name__ == "__main__":
    main()
