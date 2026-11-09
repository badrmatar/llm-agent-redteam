"""Runs attacker vs target conversations and records the outcome of each one."""
from __future__ import annotations

import json
import os
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict

from .attacker import Attacker
from .goals import GOALS, judge, rule_check
from .models import make_model
from .target import TargetAgent


def run_episode(goal, defence: str, attacker_model, target_model, judge_model, turns: int) -> dict:
    target = TargetAgent(target_model, defence)
    attacker = Attacker(attacker_model, goal)
    replies, transcript, reply = [], [], None
    success, method, used = False, "none", 0
    for t in range(turns):
        msg = attacker.next_message(reply)
        reply = target.respond(msg)
        replies.append(reply)
        transcript.append({"attacker": msg, "target": reply})
        used = t + 1
        if rule_check(goal, target.world, replies):  # cheap check every turn, stop early
            success, method = True, "rule"
            break
    if not success:  # one LLM-judge call at the end for fuzzy goals
        success, method = judge(goal, target.world, replies, judge_model)
    return {
        **asdict(goal), "goal_id": goal.id, "defence": defence, "success": success,
        "judge_method": method, "turns_used": used, "transcript": transcript,
        "tool_log": target.world.log,
    }


def run_experiment(provider: str, defences, runs: int, turns: int, out_path: str,
                   workers: int = 8, goal_ids=None, attacker_model_name=None,
                   target_model_name=None, judge_model_name=None, seed: int = 0, progress=True,
                   resume: bool = False):
    goals = [g for g in GOALS if not goal_ids or g.id in goal_ids]
    jobs = [(g, d, r) for d in defences for g in goals for r in range(runs)]
    results, done = [], set()
    if resume and os.path.exists(out_path):  # keep finished episodes, rerun only the missing ones
        with open(out_path) as f:
            for line in f:
                if line.strip():
                    rec = json.loads(line)
                    results.append(rec)
                    done.add((rec["goal_id"], rec["defence"], rec["run"]))
        jobs = [j for j in jobs if (j[0].id, j[1], j[2]) not in done]
        if progress:
            print(f"  resuming: {len(done)} episodes already done, {len(jobs)} to run")

    def one(job):
        g, d, r = job
        s = seed * 1_000_003 + zlib.crc32(f"{g.id}|{d}|{r}".encode()) % 1_000_003
        att = make_model(provider, attacker_model_name, seed=s)
        tgt = make_model(provider, target_model_name, seed=s + 1)
        jdg = make_model(provider, judge_model_name, seed=s + 2, temperature=0.0)
        res = run_episode(g, d, att, tgt, jdg, turns)
        res["run"] = r
        return res

    failed = 0
    with open(out_path, "a" if resume else "w") as f, ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(one, j) for j in jobs]
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                res = fut.result()
            except Exception as exc:  # keep going if one conversation fails
                failed += 1
                print(f"  episode failed: {exc}")
                continue
            results.append(res)
            f.write(json.dumps(res) + "\n")
            f.flush()
            if progress and (i % 20 == 0 or i == len(jobs)):
                print(f"  {i}/{len(jobs)} episodes done")
    if failed and progress:
        print(f"  {failed} episodes failed (e.g. network errors). Re-run the same command with --resume to fill them in.")
    return results
