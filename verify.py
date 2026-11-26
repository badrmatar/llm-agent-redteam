import sys, tempfile, os
from redteam.mcp_client import MCPServer
cmd, tool = sys.argv[1], sys.argv[2]
parent  = tempfile.mkdtemp()
allowed = os.path.join(parent, "allowed"); os.makedirs(allowed)
secret  = os.path.join(parent, "secret");  os.makedirs(secret)
open(os.path.join(secret, "canary.txt"), "w").write("REAL-LEAK-CONFIRMED\n")
with MCPServer(f"{cmd} {allowed}", timeout=60) as s:
    print("ALLOWED:", allowed)
    for label, path in [
        ("sibling  (should be DENIED)", os.path.join(secret, "canary.txt")),
        ("/etc/passwd (control)",       "/etc/passwd"),
    ]:
        try:
            r = s.call(tool, {"path": path})
            print(f"  {label}: {r['text'][:60].replace(chr(10),' ')}")
        except Exception as e:
            print(f"  {label}: ERROR {str(e)[:50]}")
