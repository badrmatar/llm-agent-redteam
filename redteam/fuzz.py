"""Argument fuzzing: hunt implementation bugs in a LOCAL MCP server's own tools.

The prompt-injection attacks try to fool a model. This instead feeds malformed arguments
straight to the server's tools and checks whether the server did something it shouldn't.
Detection uses canaries, so a hit is unambiguous and reproducible:

  * Path traversal. A secret file is planted OUTSIDE the server's allowed directory; its
    *contents* are a random token the fuzzer never transmits. If that token appears in a
    tool result, the file tool escaped its sandbox. Because the token is never sent, a server
    that merely echoes your path back in an error string cannot produce a false positive --
    this is the reflection-proof design.
  * Command injection. Payloads append shell metacharacters that would create a marker file.
    If the marker exists afterwards, the argument reached a shell. A reflected string can't
    create a file, so this is false-positive-proof by construction.

SAFETY. This only ever launches a LOCAL server process (mcp_client.ensure_local refuses any
command that looks like a URL or remote host). It builds its canaries under a temp workspace
and cleans up. Point it only at servers you run yourself; report what you find responsibly.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
import uuid
from dataclasses import asdict, dataclass

from .mcp_client import MCPServer, ensure_local

PATH_ARG_NAMES = ("path", "file", "filepath", "file_path", "filename", "src", "source", "target")
CMD_HINTS = ("run", "exec", "command", "shell", "spawn", "eval", "process")


@dataclass
class Finding:
    tool: str
    vuln_class: str          # "path-traversal" | "command-injection"
    payload: str             # the exact argument value that worked
    arg: str                 # which argument it was placed in
    signal: str              # how we knew (canary token / marker file)
    evidence: str            # short snippet proving it


# ---- payloads ------------------------------------------------------------------------
def traversal_payloads(allowed_dir: str, canary_abs: str) -> list:
    """Many ways to try to escape allowed_dir and reach the canary file."""
    name = os.path.basename(canary_abs)
    rel = os.path.relpath(canary_abs, allowed_dir)          # e.g. ../secret/canary.txt
    out = [canary_abs, rel]
    out += ["../" * k + os.path.join(os.path.basename(os.path.dirname(canary_abs)), name) for k in range(1, 9)]
    out += [
        rel.replace("../", "..%2f"), rel.replace("../", "..%252f"),
        rel.replace("../", "....//"), rel.replace("/", "\\"),
        os.path.join(allowed_dir, rel),                     # absolute-through-allowed
        "/" + rel, "file://" + canary_abs,
        rel.replace("/", "%2f"), "..%c0%af" + name,
    ]
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def cmdi_payloads(base: str, marker_abs: str) -> list:
    t = f"touch {marker_abs}"
    return [f"{base}; {t}", f"{base}| {t}", f"{base} && {t}", f"{base}`{t}`",
            f"{base}$({t})", f"{base}\n{t}", f"{base} & {t}"]


# ---- core fuzzing (testable without a live server) -----------------------------------
def fuzz_read_tool(call, tool: str, arg: str, other_args: dict, canary_token: str,
                   payloads: list) -> list:
    """Fire path payloads at one tool. A finding needs the canary TOKEN (never sent) to appear."""
    findings = []
    for p in payloads:
        result = call(tool, {arg: p, **other_args})
        text = result if isinstance(result, str) else json.dumps(result)
        if canary_token in text:                            # token is only on disk -> real read
            findings.append(Finding(tool, "path-traversal", p, arg, "canary token in result",
                                    _snippet(text, canary_token)))
            break                                           # one proof per tool is enough
    return findings


def fuzz_cmd_tool(call, tool: str, arg: str, other_args: dict, marker_abs: str,
                  payloads: list, exists=os.path.exists) -> list:
    findings = []
    for p in payloads:
        if exists(marker_abs):
            break
        call(tool, {arg: p, **other_args})
        if exists(marker_abs):
            findings.append(Finding(tool, "command-injection", p, arg, "marker file created",
                                    marker_abs))
            break
    return findings


def _snippet(text: str, needle: str) -> str:
    i = text.find(needle)
    return text[max(0, i - 20): i + len(needle) + 20]


def _string_args(tool: dict) -> list:
    props = (tool.get("inputSchema") or {}).get("properties") or {}
    return [k for k, v in props.items() if isinstance(v, dict) and v.get("type", "string") == "string"]


def classify(tool: dict) -> tuple:
    """Return (vuln_class, arg_name) if this tool looks fuzzable, else (None, None)."""
    name = tool.get("name", "")
    args = _string_args(tool)
    if any(h in name.lower() or h in tool.get("description", "").lower() for h in CMD_HINTS) and args:
        return "command-injection", args[0]
    for a in args:
        if a.lower() in PATH_ARG_NAMES:
            return "path-traversal", a
    if "read" in name.lower() and args:                     # a read tool with some string arg
        return "path-traversal", args[0]
    return None, None


# ---- orchestration against a real local server ---------------------------------------
def run_fuzz(mcp_cmd, workdir: str | None = None, keep: bool = False) -> dict:
    """Spawn a local server, plant canaries, fuzz its tools, return findings."""
    ws = workdir or tempfile.mkdtemp(prefix="redteam_fuzz_")
    allowed = os.path.join(ws, "allowed")
    secret = os.path.join(ws, "secret")
    os.makedirs(allowed, exist_ok=True)
    os.makedirs(secret, exist_ok=True)
    with open(os.path.join(allowed, "notes.txt"), "w") as f:
        f.write("ordinary in-bounds file\n")
    token = "CANARY_" + uuid.uuid4().hex                    # never sent; only lives on disk
    canary_abs = os.path.join(secret, "canary.txt")
    with open(canary_abs, "w") as f:
        f.write(token + "\n")
    marker_abs = os.path.join(secret, "pwned_" + uuid.uuid4().hex)

    cmd = mcp_cmd.replace("{allowed}", allowed) if "{allowed}" in mcp_cmd else f"{mcp_cmd} {allowed}"
    ensure_local(cmd)                                       # refuse remote targets before launching
    findings, tools_seen = [], []
    try:
        with MCPServer(cmd, timeout=60) as srv:
            for tool in srv.tools:
                tools_seen.append(tool["name"])
                vclass, arg = classify(tool)
                if not arg:
                    continue
                other = {a: "." for a in _string_args(tool) if a != arg}
                if vclass == "path-traversal":
                    findings += fuzz_read_tool(lambda n, a: srv.call(n, a)["text"], tool["name"],
                                               arg, other, token, traversal_payloads(allowed, canary_abs))
                else:
                    findings += fuzz_cmd_tool(lambda n, a: srv.call(n, a)["text"], tool["name"],
                                              arg, other, marker_abs,
                                              cmdi_payloads(os.path.join(allowed, "notes.txt"), marker_abs))
    finally:
        if not keep:
            shutil.rmtree(ws, ignore_errors=True)
    return {"command": cmd, "tools": tools_seen, "findings": [asdict(f) for f in findings]}


def main() -> None:
    ap = argparse.ArgumentParser(description="Fuzz a LOCAL MCP server's tools for traversal / injection bugs.")
    ap.add_argument("--mcp-cmd", required=True,
                    help="local server command; use {allowed} where its allowed directory goes, "
                         "or it is appended as the last argument")
    ap.add_argument("--out", help="write findings JSON here")
    ap.add_argument("--keep", action="store_true", help="keep the temp workspace for inspection")
    args = ap.parse_args()

    print(f"Fuzzing (local only): {args.mcp_cmd}")
    report = run_fuzz(args.mcp_cmd, keep=args.keep)
    print(f"tools probed: {', '.join(report['tools']) or '(none)'}")
    if report["findings"]:
        print(f"\n*** {len(report['findings'])} FINDING(S) ***")
        for f in report["findings"]:
            print(f"  [{f['vuln_class']}] tool={f['tool']} arg={f['arg']}")
            print(f"    payload : {f['payload']}")
            print(f"    evidence: {f['evidence']}")
    else:
        print("\nNo traversal or command-injection found (server refused every payload).")
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nfull report -> {args.out}")


if __name__ == "__main__":
    main()
