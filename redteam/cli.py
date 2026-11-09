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

from redteam.models import DEFAULT_MODELS
from redteam.report import build_report
from redteam.runner import run_experiment
from redteam.target import DEFENCES


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
    ap.add_argument("--report-only", metavar="FOLDER", help="rebuild report from FOLDER/results.jsonl")
    args = ap.parse_args()

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
    with open(os.path.join(out, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    print(f"Running {args.provider}: defences={args.defences} runs={args.runs} turns={args.turns}")
    run_experiment(args.provider, args.defences, args.runs, args.turns,
                   os.path.join(out, "results.jsonl"), workers=args.workers, goal_ids=args.goals,
                   attacker_model_name=args.attacker_model, target_model_name=args.target_model,
                   judge_model_name=args.judge_model, seed=args.seed)
    path = build_report(os.path.join(out, "results.jsonl"), out, meta)
    print(f"Report written to {path}")


if __name__ == "__main__":
    main()
