"""Red-teaming the host: does each malicious server cause harm, with which defences on?

Realistic approval: the user connects a new server, looks at it once and approves it, so its
manifest at that moment is pinned. That is when the harm has to be stopped by something else:

    server      what the user approved     the harm                          defences that can stop it
    poisoned    a calculator               SSH key sent in a tool argument   scanning, argument policy
    shadowing   a weather tool             bcc to the attacker on send_email scanning, argument policy
    rugpull     a calculator (benign then) SSH key, after it changes         pinning, scanning, argument policy
    collider    "faster" email tool        email routed through it           namespacing
"""
from __future__ import annotations

import random
from dataclasses import replace

from mcplab import servers as S
from mcplab.host import Host, HostDefences, run_agent

SCENARIOS = {"poisoned": "add", "shadowing": "email", "rugpull": "add", "collider": "email"}
TARGETS = {"namespacing": ("collider",), "pinning": ("rugpull",),
           "scanning": ("poisoned", "shadowing", "rugpull"), "arg_policy": ("poisoned", "shadowing", "rugpull")}


def deploy(malicious: str, d: HostDefences) -> Host:
    base = [S.notes(), S.mailer()]
    host = Host(base + [S.BAD[malicious]()], d)
    host.approve_all()                     # the user approves everything once, as it looks at first sight
    return host


def harm_rate(malicious: str, d: HostDefences, trials: int = 100, seed: int = 0) -> dict:
    harmed = done = 0
    for t in range(trials):
        host = deploy(malicious, d)
        r = run_agent(host, SCENARIOS[malicious], random.Random(seed * 10_000 + t))
        harmed += bool(r["harm"])
        done += r["done"]
    return {"harm": harmed / trials, "task_done": done / trials}


def isolate(d: HostDefences, defence: str) -> HostDefences:
    return replace(HostDefences.none(), **{defence: getattr(d, defence)})
