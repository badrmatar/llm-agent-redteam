"""A tiny MCP (Model Context Protocol) client that speaks to a LOCAL server over stdio.

MCP stdio transport is JSON-RPC 2.0 with one JSON message per line. This client does the
minimum the harness needs: initialize, tools/list, tools/call. It depends only on the
standard library, so a server written against the real spec works with no extra packages.

SAFETY: this only ever launches a local subprocess and talks to it over that process's own
stdin/stdout. It never opens a network connection. As a guard rail it refuses to launch a
command that looks like a URL or a remote host, so the harness cannot be pointed at a live
service by accident.
"""
from __future__ import annotations

import json
import select
import shlex
import subprocess
import threading
from typing import Any


class MCPError(RuntimeError):
    pass


def _looks_remote(token: str) -> bool:
    t = token.lower()
    return "://" in t or t.startswith(("http", "ws", "tcp", "ssh")) or "@" in t and "." in t


def ensure_local(command) -> list:
    """Return the command as an argv list, or raise if it looks like a remote target."""
    argv = shlex.split(command) if isinstance(command, str) else list(command)
    if not argv:
        raise MCPError("empty MCP command")
    for token in argv:
        if _looks_remote(token):
            raise MCPError(
                f"refusing to launch {token!r}: this harness only targets local processes, "
                "never a network address or remote host"
            )
    return argv


class MCPServer:
    """Spawns a local MCP server process and exposes its tools.

    Use as a context manager so the child process is always cleaned up:

        with MCPServer("python examples/mcp_support_server.py") as srv:
            srv.tools                      # list of {name, description, inputSchema}
            srv.call("get_record", {"id": "A1001"})
    """

    def __init__(self, command, timeout: float = 20.0):
        self.argv = ensure_local(command)
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        self._id = 0
        self._lock = threading.Lock()
        self.tools: list = []
        self.server_info: dict = {}

    # ---- lifecycle -----------------------------------------------------------
    def __enter__(self) -> MCPServer:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def start(self) -> MCPServer:
        self.proc = subprocess.Popen(
            self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )
        init = self._request("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "redteam-harness", "version": "0.3"},
        })
        self.server_info = init.get("serverInfo", {})
        self._notify("notifications/initialized")
        self.tools = self._request("tools/list").get("tools", [])
        return self

    def close(self) -> None:
        if self.proc is None:
            return
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
        finally:
            self.proc = None

    # ---- tool use ------------------------------------------------------------
    def call(self, name: str, arguments: dict | None = None) -> dict:
        """Call a tool. Returns {"text": <flattened text>, "is_error": bool, "raw": <result>}."""
        result = self._request("tools/call", {"name": name, "arguments": arguments or {}})
        parts = []
        for block in result.get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
        return {"text": "\n".join(parts), "is_error": bool(result.get("isError")), "raw": result}

    # ---- JSON-RPC over stdio -------------------------------------------------
    def _request(self, method: str, params: dict | None = None) -> dict:
        with self._lock:
            self._id += 1
            msg: dict[str, Any] = {"jsonrpc": "2.0", "id": self._id, "method": method}
            if params is not None:
                msg["params"] = params
            self._send(msg)
            while True:
                reply = self._read()
                if reply.get("id") != self._id:
                    continue  # skip notifications / out-of-order server messages
                if "error" in reply:
                    raise MCPError(f"{method} failed: {reply['error']}")
                return reply.get("result", {})

    def _notify(self, method: str, params: dict | None = None) -> None:
        with self._lock:
            msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                msg["params"] = params
            self._send(msg)

    def _send(self, msg: dict) -> None:
        if self.proc is None or self.proc.stdin is None:
            raise MCPError("server not started")
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _read(self) -> dict:
        if self.proc is None or self.proc.stdout is None:
            raise MCPError("server not started")
        ready, _, _ = select.select([self.proc.stdout], [], [], self.timeout)
        if not ready:
            raise MCPError(f"no response from MCP server within {self.timeout:.0f}s")
        line = self.proc.stdout.readline()
        if line == "":
            raise MCPError("MCP server closed the connection unexpectedly")
        line = line.strip()
        if not line:
            return {}
        try:
            return json.loads(line)
        except json.JSONDecodeError as exc:
            raise MCPError(f"invalid JSON from MCP server: {line[:200]!r}") from exc
