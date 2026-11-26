"""LangChain file-toolkit sandbox-escape probe.
Same idea as the MCP fuzzer: a canary that exists ONLY on disk,
outside the tool's root_dir. If read_file returns it -> read escape.
If write_file creates a file outside root_dir -> write escape.
Reflection-proof: the token is never sent, only its path. Throwaway box only."""
import os, sys, tempfile, uuid

try:
    from langchain_community.agent_toolkits import FileManagementToolkit
except Exception as e:
    sys.exit(f"install first:  pip install langchain-community\n({e})")

def try_run(tool, payload):
    try:
        return str(tool.run(payload))
    except Exception as e:
        return f"__ERR__ {type(e).__name__}: {str(e)[:80]}"

def tool_by_name(tools, name):
    return next((t for t in tools if t.name == name), None)

def main():
    parent  = tempfile.mkdtemp(prefix="lc_fuzz_")
    allowed = os.path.join(parent, "allowed"); os.makedirs(allowed)
    secret  = os.path.join(parent, "secret");  os.makedirs(secret)
    token   = "LC-LEAK-" + uuid.uuid4().hex
    canary  = os.path.join(secret, "canary.txt")
    open(canary, "w").write(token + "\n")

    tools = FileManagementToolkit(
        root_dir=allowed,
        selected_tools=["read_file", "write_file"],
    ).get_tools()
    read_t, write_t = tool_by_name(tools, "read_file"), tool_by_name(tools, "write_file")

    print(f"root_dir (sandbox): {allowed}")
    print(f"canary (outside):   {canary}\n")
    findings = []

    print("[read_file]  (LEAK = sandbox escaped)")
    for label, p in [
        ("absolute sibling",     canary),
        ("relative ../secret",   "../secret/canary.txt"),
        ("nested ../",           "allowed/../secret/canary.txt"),
        ("deep ../ etc/passwd",  "../../../../../../etc/passwd"),
        ("absolute /etc/passwd", "/etc/passwd"),
    ]:
        out = try_run(read_t, {"file_path": p})
        if token in out:
            print(f"  {label:24} -> LEAK"); findings.append(("read-traversal", p))
        elif out.startswith("__ERR__"):
            print(f"  {label:24} -> err ({out[8:40]})")
        else:
            print(f"  {label:24} -> blocked")

    print("\n[write_file]  (ESCAPE = wrote outside sandbox)")
    for label, mk_rel in [("absolute outside", False), ("relative ../secret", True)]:
        mk = "pwned_" + uuid.uuid4().hex
        target = os.path.join(secret, mk)
        payload = f"../secret/{mk}" if mk_rel else target
        try_run(write_t, {"file_path": payload, "text": "pwned"})
        if os.path.exists(target):
            print(f"  {label:24} -> ESCAPE"); findings.append(("write-traversal", payload))
            os.remove(target)
        else:
            print(f"  {label:24} -> blocked")

    print("\n" + "=" * 50)
    if findings:
        print(f"VULNERABLE: {len(findings)} escape(s)")
        for kind, p in findings:
            print(f"  [{kind}] {p}")
    else:
        print("sandbox held - LangChain confined every payload")
    print("=" * 50)

if __name__ == "__main__":
    main()
