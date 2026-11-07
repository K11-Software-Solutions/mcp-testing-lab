"""Checks for MCP servers: protocol conformance, contract stability and security hygiene.

conformance(server)          initialize, tools/list shape, a valid call, invalid arguments rejected,
                             unknown tool and unknown method rejected with the right codes
list_stability(server)       the tool list does not change between listings without a
                             notifications/tools/list_changed message
error_hygiene(server)        failing tools do not return stack traces, file paths or secrets
scan_descriptions(tools)     tool descriptions without hidden instructions, hidden characters,
                             secrets-seeking text or references to other servers' tools
manifest / compare_manifest  a pinned fingerprint of every tool's name, description and schema,
                             so any change (same version or not) is detected
collisions(servers)          the same tool name offered by two servers
"""
from __future__ import annotations

import hashlib
import json
import re

from mcplab.protocol import INVALID_PARAMS, METHOD_NOT_FOUND, NAME_RE, Server, request


def _example_args(schema: dict) -> dict:
    sample = {"string": "test", "number": 1, "integer": 1, "boolean": True}
    return {k: sample.get(schema["properties"][k].get("type"), "test") for k in schema.get("required", [])}


def conformance(server: Server) -> list[str]:
    out = []
    init = request(server, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
    r = init.get("result", {})
    if not r.get("protocolVersion") or not r.get("serverInfo", {}).get("name") or "tools" not in r.get("capabilities", {}):
        out.append("initialize: missing protocolVersion, serverInfo or tools capability")
    tools = request(server, "tools/list").get("result", {}).get("tools", [])
    names = [t.get("name") for t in tools]
    if len(set(names)) != len(names):
        out.append("tools/list: duplicate tool names")
    for t in tools:
        if not NAME_RE.match(t.get("name", "")):
            out.append(f"tools/list: invalid tool name {t.get('name')!r}")
        if not t.get("description"):
            out.append(f"tools/list: {t.get('name')} has no description")
        schema = t.get("inputSchema", {})
        if schema.get("type") != "object" or "properties" not in schema:
            out.append(f"tools/list: {t.get('name')} inputSchema is not an object schema")
            continue
        ok = request(server, "tools/call", {"name": t["name"], "arguments": _example_args(schema)})
        if "result" not in ok or not isinstance(ok["result"].get("content"), list):
            out.append(f"tools/call: {t['name']} with valid arguments did not return content")
        bad = request(server, "tools/call", {"name": t["name"], "arguments": {"__unexpected__": 1}})
        rejected = bad.get("error", {}).get("code") == INVALID_PARAMS or bad.get("result", {}).get("isError")
        if not rejected:
            out.append(f"tools/call: {t['name']} accepted invalid arguments")
    unknown = request(server, "tools/call", {"name": "no_such_tool", "arguments": {}})
    if unknown.get("error", {}).get("code") != INVALID_PARAMS:
        out.append("tools/call: unknown tool not rejected with -32602")
    if request(server, "no/such/method").get("error", {}).get("code") != METHOD_NOT_FOUND:
        out.append("unknown method not rejected with -32601")
    return out


def list_stability(server: Server, listings: int = 3) -> list[str]:
    seen = None
    for _ in range(listings):
        before = len(server.notifications)
        specs = json.dumps(request(server, "tools/list")["result"]["tools"], sort_keys=True)
        if seen is not None and specs != seen and len(server.notifications) == before:
            return ["tools/list: tool definitions changed without a list_changed notification"]
        seen = specs
    return []


SECRET_PATTERNS = (r"sk_live_\w+", r"BEGIN [A-Z ]*PRIVATE KEY", r"Traceback \(most recent call last\)",
                   r"(/srv/|/home/|/etc/|[A-Z]:\\)", r"token\s+\S{12,}")


def error_hygiene(server: Server) -> list[str]:
    out = []
    for t in request(server, "tools/list")["result"]["tools"]:
        r = request(server, "tools/call", {"name": t["name"], "arguments": _example_args(t["inputSchema"])}).get("result", {})
        if r.get("isError"):
            text = " ".join(c.get("text", "") for c in r.get("content", []))
            hits = [p for p in SECRET_PATTERNS if re.search(p, text)]
            if hits:
                out.append(f"errors: {t['name']} error message exposes internals ({len(hits)} pattern(s))")
    return out


SUSPICIOUS = (r"<important>", r"do not (tell|mention|inform)", r"never tell", r"\bbefore using this tool\b",
              r"~/\.ssh|id_rsa|\.env\b|password", r"\bbcc\b", r"ignore (all|previous)", r"for the assistant",
              r"otherwise the tool will fail")
HIDDEN = re.compile("[​-‏⁠﻿]|[\U000e0000-\U000e007f]")


def scan_descriptions(tools: list[dict], other_tool_names: set[str] = frozenset()) -> list[str]:
    out = []
    for t in tools:
        d = t.get("description", "")
        low = d.lower()
        hits = [p for p in SUSPICIOUS if re.search(p, low)]
        if hits:
            out.append(f"description: {t['name']} contains instruction-like text ({', '.join(hits[:3])})")
        if HIDDEN.search(d):
            out.append(f"description: {t['name']} contains hidden characters")
        if len(d) > 400:
            out.append(f"description: {t['name']} is unusually long ({len(d)} characters)")
        # Only distinctive names: a tool called "add" or "search" would match ordinary words.
        distinctive = {n for n in other_tool_names if "_" in n or "-" in n or len(n) >= 8}
        refs = [n for n in distinctive if n != t["name"] and re.search(rf"\b{re.escape(n)}\b", d)]
        if refs:
            out.append(f"description: {t['name']} refers to other servers' tools ({', '.join(sorted(refs))})")
    return out


def manifest(server: Server) -> dict:
    tools = request(server, "tools/list")["result"]["tools"]
    info = request(server, "initialize")["result"]["serverInfo"]
    digest = hashlib.sha256(json.dumps(tools, sort_keys=True).encode()).hexdigest()[:16]
    return {"version": info["version"], "tools": digest}


def compare_manifest(name: str, current: dict, pinned: dict | None) -> list[str]:
    if pinned is None:
        return [f"manifest: server '{name}' is not on the approved list"]
    if current["tools"] != pinned["tools"]:
        same = current["version"] == pinned["version"]
        return [f"manifest: '{name}' tool definitions changed{' without a version bump' if same else ''}; re-approval required"]
    return []


def collisions(servers: list[Server]) -> list[str]:
    owners: dict[str, list[str]] = {}
    for s in servers:
        for t in request(s, "tools/list")["result"]["tools"]:
            owners.setdefault(t["name"], []).append(s.name)
    return [f"collision: tool '{n}' offered by {', '.join(o)}" for n, o in owners.items() if len(o) > 1]
