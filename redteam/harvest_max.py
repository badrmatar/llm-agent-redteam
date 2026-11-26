"""Deep npm sweep for MCP targets. Discovery only: reads public
registry metadata, runs nothing. Writes targets_max.txt."""
import json, sys, time, urllib.parse, urllib.request

SEARCH = "https://registry.npmjs.org/-/v1/search"
QUERIES = [
    "mcp", "mcp server", "mcp filesystem", "mcp file", "mcp fs",
    "modelcontextprotocol", "model context protocol", "mcp tools",
    "mcp directory", "mcp files", "mcp storage", "mcp local", "mcp disk",
]
FILE_HINTS = ("filesystem", "file", "-fs", "fs-", "directory",
              "dir", "files", "storage", "disk", "path")
OFFICIAL = "@modelcontextprotocol/server-filesystem"

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "redteam"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

def sweep(q, cap=1000):
    out = {}
    frm = 0
    while frm < cap:
        url = f"{SEARCH}?text={urllib.parse.quote(q)}&size=250&from={frm}"
        try:
            data = get(url)
        except Exception as e:
            print(f"  ! {q}@{frm}: {e}", file=sys.stderr); break
        objs = data.get("objects", [])
        if not objs: break
        for o in objs:
            p = o.get("package", {})
            if p.get("name"):
                out[p["name"]] = (p.get("description") or "")
        frm += 250
        if frm >= data.get("total", 0): break
        time.sleep(0.2)
    return out

def is_file_server(name, desc):
    blob = (name + " " + desc).lower()
    return any(h in blob for h in FILE_HINTS)

def main():
    take_all = "--all" in sys.argv
    found = {}
    for q in QUERIES:
        got = sweep(q)
        print(f"{q}: {len(got)}", file=sys.stderr)
        found.update(got)
    print(f"\nunique packages found: {len(found)}", file=sys.stderr)

    names = [n for n, d in found.items()
             if take_all or is_file_server(n, d)]
    names = [n for n in sorted(set(names)) if n != OFFICIAL]
    with open("targets_max.txt", "w") as f:
        f.write("# deep npm sweep (name | command)\n")
        f.write(f"official | npx -y {OFFICIAL}\n")
        for n in names:
            f.write(f"{n.replace('|','')} | npx -y {n.replace('|','')}\n")
    print(f"targets written: {len(names)+1}  -> targets_max.txt",
          file=sys.stderr)

if __name__ == "__main__":
    main()
