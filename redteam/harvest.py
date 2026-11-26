"""Build a long targets list for the census by searching the npm registry for MCP servers.

Discovery only. This queries the public npm registry's search API for packages whose names look
like MCP servers -- and, by default, like *file* servers, where path traversal is a meaningful
bug -- and writes '<name> | npx -y <package>' lines for the census (redteam-census). It does not
install, download, or run anything; it only reads package names.

Review the list before you scan it, run the census only inside a throwaway box, test only servers
you are authorised to test, and disclose anything you find responsibly.
"""
from __future__ import annotations

import argparse
import json
import urllib.parse
import urllib.request

SEARCH_URL = "https://registry.npmjs.org/-/v1/search?text={q}&size={n}"
QUERIES = ("mcp filesystem server", "mcp server filesystem", "modelcontextprotocol filesystem",
           "mcp file server")
FILE_HINTS = ("filesystem", "file", "-fs", "fs-", "directory", "files")


def search_npm(query: str, size: int = 40, opener=urllib.request.urlopen) -> list:
    url = SEARCH_URL.format(q=urllib.parse.quote(query), n=size)
    with opener(url, timeout=20) as resp:
        data = json.load(resp)
    return [o["package"]["name"] for o in data.get("objects", []) if o.get("package", {}).get("name")]


def looks_file_server(name: str) -> bool:
    n = name.lower()
    return "mcp" in n and any(k in n for k in FILE_HINTS)


def build_targets(names: list, file_only: bool = True) -> list:
    """Turn package names into 'name | command' lines, deduped and sorted."""
    picked = [n for n in sorted(set(names)) if (looks_file_server(n) if file_only else "mcp" in n.lower())]
    lines = ["official-filesystem | npx -y @modelcontextprotocol/server-filesystem"]
    for n in picked:
        if n == "@modelcontextprotocol/server-filesystem":
            continue
        slug = n.replace("@", "").replace("/", "-")
        lines.append(f"{slug} | npx -y {n}")
    return lines


HEADER = ("# Candidate MCP servers harvested from npm -- DISCOVERY ONLY, not yet verified.\n"
          "# Review each package before scanning. Run the census in a throwaway box, never your\n"
          "# main machine. Test only what you are authorised to test; disclose findings privately.\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Harvest candidate MCP server targets from npm for the census.")
    ap.add_argument("--out", default="targets.txt")
    ap.add_argument("--limit", type=int, default=40, help="results per query")
    ap.add_argument("--all", action="store_true", help="keep every mcp-ish package, not just file servers")
    args = ap.parse_args()

    names = []
    for q in QUERIES:
        try:
            names += search_npm(q, args.limit)
        except Exception as exc:  # network hiccup on one query shouldn't lose the rest
            print(f"  (query {q!r} failed: {type(exc).__name__})")
    lines = build_targets(names, file_only=not args.all)
    with open(args.out, "w") as f:
        f.write(HEADER + "\n".join(lines) + "\n")
    print(f"wrote {len(lines)} candidate targets to {args.out}")
    print("review them, then:  redteam-census --targets " + args.out)


if __name__ == "__main__":
    main()
