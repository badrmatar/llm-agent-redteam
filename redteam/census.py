"""Batch runner: fuzz a whole list of local MCP servers and produce one scoreboard.

Point it at a targets file (one server per line) and it spins each one up, runs the argument
fuzzer against it, records the result, and moves on. At the end you get a census: "scanned N,
these are secure, these have findings, these failed to start." That census -- not any single
bug -- is the interesting result, because nobody has a systematic security baseline for the
MCP ecosystem yet.

Targets file format (see targets.example.txt), one per line, '#' for comments:

    name | server command

SAFETY. Each server is still launched locally and only locally (run_fuzz refuses remote
commands). But running a long list means running a long list of other people's code, so run
this inside a throwaway VM or container you are happy to destroy -- never your main machine.
Only test servers you are authorised to test, and disclose anything you find responsibly.
"""
from __future__ import annotations

import argparse
import json
import os
import time

from .fuzz import run_fuzz
from .mcp_client import MCPError


def load_targets(path: str) -> list:
    """Parse 'name | command' lines; skip blanks and '#' comments."""
    targets = []
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "|" not in line:
                continue
            name, cmd = line.split("|", 1)
            if name.strip() and cmd.strip():
                targets.append((name.strip(), cmd.strip()))
    return targets


def scan_one(name: str, cmd: str, read_timeout: float) -> dict:
    """Fuzz one server. Never raises -- a server that won't start is recorded as an error."""
    start = time.time()
    try:
        rep = run_fuzz(cmd, read_timeout=read_timeout)
        status = "VULNERABLE" if rep["findings"] else "secure"
        return {"name": name, "command": cmd, "status": status, "findings": rep["findings"],
                "tools": rep["tools"], "seconds": round(time.time() - start, 1)}
    except (MCPError, FileNotFoundError, OSError) as exc:
        return {"name": name, "command": cmd, "status": "error", "findings": [],
                "tools": [], "error": f"{type(exc).__name__}: {exc}",
                "seconds": round(time.time() - start, 1)}


def run_census(targets: list, out_dir: str, read_timeout: float = 90.0, progress=True) -> list:
    os.makedirs(out_dir, exist_ok=True)
    results = []
    path = os.path.join(out_dir, "census.jsonl")
    with open(path, "w") as f:
        for i, (name, cmd) in enumerate(targets, 1):
            if progress:
                print(f"[{i}/{len(targets)}] scanning {name} ...", flush=True)
            res = scan_one(name, cmd, read_timeout)
            results.append(res)
            f.write(json.dumps(res) + "\n")
            f.flush()
            if progress:
                note = res["status"]
                if res["status"] == "VULNERABLE":
                    note += f" ({len(res['findings'])} finding(s): " + \
                            ", ".join(sorted({x['vuln_class'] for x in res['findings']})) + ")"
                elif res["status"] == "error":
                    note += f" ({res.get('error', '')[:60]})"
                print(f"    -> {note}", flush=True)
    return results


def scoreboard(results: list) -> str:
    vuln = [r for r in results if r["status"] == "VULNERABLE"]
    secure = [r for r in results if r["status"] == "secure"]
    err = [r for r in results if r["status"] == "error"]
    lines = ["", "=" * 56, f"CENSUS: {len(results)} servers scanned",
             f"  vulnerable: {len(vuln)}   secure: {len(secure)}   errored: {len(err)}", "=" * 56]
    if vuln:
        lines.append("\nVULNERABLE:")
        for r in vuln:
            for fnd in r["findings"]:
                lines.append(f"  [{fnd['vuln_class']}] {r['name']}  tool={fnd['tool']}  payload={fnd['payload']}")
    if secure:
        lines.append("\nsecure (sandbox held): " + ", ".join(r["name"] for r in secure))
    if err:
        lines.append("\nerrored (did not start / no fuzzable tools): " + ", ".join(r["name"] for r in err))
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Fuzz a list of LOCAL MCP servers and print a scoreboard.")
    ap.add_argument("--targets", required=True, help="targets file (name | command per line)")
    ap.add_argument("--out", default="results/census", help="output folder")
    ap.add_argument("--timeout", type=float, default=90.0, help="per-server read timeout (seconds)")
    args = ap.parse_args()

    targets = load_targets(args.targets)
    if not targets:
        print("no targets found in", args.targets)
        return
    print(f"scanning {len(targets)} local MCP server(s) -- run this in a throwaway box, not your main machine\n")
    results = run_census(targets, args.out, read_timeout=args.timeout)
    board = scoreboard(results)
    print(board)
    with open(os.path.join(args.out, "scoreboard.txt"), "w") as f:
        f.write(board + "\n")
    print(f"\nfull results -> {os.path.join(args.out, 'census.jsonl')}")


if __name__ == "__main__":
    main()
