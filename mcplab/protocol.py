"""A minimal, in-process implementation of the Model Context Protocol's tool messages.

MCP is JSON-RPC 2.0 between a host (the AI application) and servers that offer tools.
This module implements just enough of it to test the tool supply chain, with no
dependencies and no network:

    initialize                      -> {protocolVersion, capabilities, serverInfo}
    tools/list                      -> {tools: [{name, description, inputSchema}]}
    tools/call {name, arguments}    -> {content: [{type: "text", text}], isError}
    notifications/tools/list_changed  (server -> host, when the tool list changes)

Errors use JSON-RPC codes: -32601 method not found, -32602 invalid params, -32603
internal error. A tool that runs but fails returns a result with isError true.

It is a teaching model of the message shapes, not the official SDK. The checks in this lab
apply unchanged to real servers reached through an MCP SDK (article 08).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable

PROTOCOL_VERSION = "2025-06-18"
METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = -32601, -32602, -32603
NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict], str]

    def spec(self) -> dict:
        return {"name": self.name, "description": self.description, "inputSchema": self.input_schema}


def validate(schema: dict, args: dict) -> list[str]:
    """A small JSON Schema subset: object, required, property types, additionalProperties."""
    if not isinstance(args, dict):
        return ["arguments must be an object"]
    problems = [f"missing '{k}'" for k in schema.get("required", []) if k not in args]
    props = schema.get("properties", {})
    if schema.get("additionalProperties") is False:
        problems += [f"unexpected '{k}'" for k in args if k not in props]
    kinds = {"string": str, "integer": int, "number": (int, float), "boolean": bool}
    for k, v in args.items():
        t = props.get(k, {}).get("type")
        if t in kinds and (not isinstance(v, kinds[t]) or (t != "boolean" and isinstance(v, bool))):
            problems.append(f"'{k}' must be {t}")
    return problems


@dataclass
class Server:
    """An MCP server: a name, a version, a set of tools and a transport-free `handle`."""
    name: str
    version: str = "1.0.0"
    tools: list[Tool] = field(default_factory=list)
    validate_args: bool = True
    notifications: list[dict] = field(default_factory=list)
    calls: int = 0

    def on_list(self) -> None:
        """Hook for servers whose tools change over time (see the rug-pull server)."""

    def handle(self, message: str) -> str | None:
        req = json.loads(message)
        rid, method, params = req.get("id"), req.get("method"), req.get("params") or {}
        if rid is None:                                   # a notification: no response
            return None
        try:
            result = self._dispatch(method, params)
            return json.dumps({"jsonrpc": "2.0", "id": rid, "result": result})
        except RpcError as e:
            return json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": e.code, "message": e.message}})

    def _dispatch(self, method: str, params: dict) -> dict:
        if method == "initialize":
            return {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": self.name, "version": self.version}}
        if method == "tools/list":
            self.on_list()
            return {"tools": [t.spec() for t in self.tools]}
        if method == "tools/call":
            tool = next((t for t in self.tools if t.name == params.get("name")), None)
            if tool is None:
                raise RpcError(INVALID_PARAMS, f"unknown tool '{params.get('name')}'")
            args = params.get("arguments", {})
            if self.validate_args:
                problems = validate(tool.input_schema, args)
                if problems:
                    raise RpcError(INVALID_PARAMS, "invalid arguments: " + "; ".join(problems))
            self.calls += 1
            try:
                return {"content": [{"type": "text", "text": tool.handler(args)}], "isError": False}
            except Exception as exc:                       # a tool failure is a result, not a protocol error
                return {"content": [{"type": "text", "text": self.error_text(exc)}], "isError": True}
        raise RpcError(METHOD_NOT_FOUND, f"method '{method}' not found")

    def error_text(self, exc: Exception) -> str:
        return f"tool failed: {type(exc).__name__}"

    def change_tools(self, tools: list[Tool]) -> None:
        self.tools = tools
        self.notifications.append({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def request(server: Server, method: str, params: dict | None = None, rid: int = 1) -> dict:
    """Send one JSON-RPC request through the server's JSON interface and parse the reply."""
    reply = server.handle(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}))
    return json.loads(reply)
