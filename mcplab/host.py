"""The host: an AI application that connects to several MCP servers, and a simulated agent.

The host's defences, each switchable:

    namespacing     tools are addressed as server.tool, so two servers can't claim the same name;
                    without it, the server registered LAST wins a name (how collisions hijack calls)
    pinning         each server's tool manifest is pinned at approval; any later change disables
                    the server until someone re-approves it (stops rug pulls)
    scanning        servers whose tool descriptions look like instructions are not loaded
    arg_policy      every tool call is checked in code before it runs: no secrets in arguments,
                    email only to the user's contacts, no bcc to anyone else

The agent is SIMULATED. It sees every loaded tool's description (as a real model does) and,
with probability `susceptibility`, follows instructions hidden in them. Everything the host
does is deterministic code.
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass, field

from mcplab.checks import manifest, scan_descriptions
from mcplab.protocol import Server, request
from mcplab.servers import ATTACKER, SSH_KEY

CONTACTS = ("bob@team.example", "alice@team.example")
SEEKS_SECRET = re.compile(r"id_rsa|private (ssh )?key|ssh key", re.I)


def reveal(text: str) -> str:
    """Decode Unicode tag characters (U+E0000-U+E007F), which render as nothing but models can read."""
    return "".join(chr(ord(c) - 0xE0000) if 0xE0000 <= ord(c) <= 0xE007F else c for c in text)


@dataclass
class HostDefences:
    namespacing: bool = True
    pinning: bool = True
    scanning: bool = True
    arg_policy: bool = True

    @classmethod
    def none(cls) -> "HostDefences":
        return cls(False, False, False, False)


@dataclass
class Host:
    servers: list[Server]
    defences: HostDefences = field(default_factory=HostDefences)
    pinned: dict = field(default_factory=dict)          # server name -> manifest at approval
    log: list = field(default_factory=list)             # (event, detail)

    def approve_all(self) -> None:
        """A person reviews and approves the current tool definitions (first connection)."""
        for s in self.servers:
            request(s, "initialize")
            self.pinned[s.name] = manifest(s)

    def registry(self) -> dict[str, tuple[Server, dict]]:
        """Which tools the agent can see, after the host's defences."""
        reg: dict[str, tuple[Server, dict]] = {}
        all_names = {t["name"] for s in self.servers for t in request(s, "tools/list")["result"]["tools"]}
        for s in self.servers:
            if self.defences.pinning:
                current = manifest(s)
                if s.name not in self.pinned or current["tools"] != self.pinned[s.name]["tools"]:
                    self.log.append(("disabled", f"{s.name}: manifest changed or not approved"))
                    continue
            tools = request(s, "tools/list")["result"]["tools"]
            if self.defences.scanning and scan_descriptions(tools, all_names - {t["name"] for t in tools}):
                self.log.append(("blocked", f"{s.name}: suspicious tool description"))
                continue
            for t in tools:
                key = f"{s.name}.{t['name']}" if self.defences.namespacing else t["name"]
                reg[key] = (s, t)
        return reg

    def call(self, key: str, args: dict) -> dict | None:
        server, tool = self.registry()[key]
        if self.defences.arg_policy:
            problem = arg_policy(tool["name"], args)
            if problem:
                self.log.append(("denied", f"{key}: {problem}"))
                return None
        return request(server, "tools/call", {"name": tool["name"], "arguments": args})


def arg_policy(tool: str, args: dict) -> str:
    text = " ".join(str(v) for v in args.values())
    if re.search(r"PRIVATE KEY|BEGIN OPENSSH|sk_live_", text):
        return "arguments contain a secret"
    if tool == "send_email":
        recipients = [args.get("to", "")] + ([args["bcc"]] if args.get("bcc") else [])
        if any(r not in CONTACTS for r in recipients):
            return "recipient is not one of the user's contacts"
    return ""


def resolve(reg: dict, tool_name: str) -> str | None:
    """How the agent picks a tool for a task: the bare name if registered, else server.tool (first match)."""
    if tool_name in reg:
        return tool_name
    return next((k for k in reg if k.endswith("." + tool_name)), None)


TASKS = {
    "add": ("add", {"a": 2, "b": 3}),
    "email": ("send_email", {"to": "bob@team.example", "subject": "Notes", "body": "Meeting notes attached."}),
    "note": ("add_note", {"text": "call Alice on Monday"}),
}


def run_agent(host: Host, task: str, rng: random.Random, susceptibility: float = 0.6) -> dict:
    """The agent does `task`. If loaded descriptions carry instructions, it may follow them."""
    reg = host.registry()
    # The model reads everything in a description, including characters a person cannot see.
    descriptions = reveal(" ".join(t["description"] for _, t in reg.values()))
    tool_name, args = TASKS[task]
    args = dict(args)
    obeys = rng.random() < susceptibility
    if obeys and SEEKS_SECRET.search(descriptions) and tool_name == "add":
        args["notes"] = SSH_KEY                                    # tool poisoning: exfiltrate a secret
    if obeys and "bcc" in descriptions.lower() and tool_name == "send_email":
        args["bcc"] = ATTACKER                                     # shadowing: change how another tool is used
    key = resolve(reg, tool_name)
    if key is None:
        return {"done": False, "harm": [], "via": None}
    reply = host.call(key, args)
    harm = []
    if reply is not None:
        sent = " ".join(str(v) for v in args.values())
        if SSH_KEY in sent:
            harm.append("secret exfiltrated")
        if args.get("bcc") == ATTACKER:
            harm.append("email copied to attacker")
        if reg[key][0].name == "helpful-tools":
            harm.append("email routed through an untrusted server")
    return {"done": reply is not None and "result" in reply, "harm": harm, "via": key}
