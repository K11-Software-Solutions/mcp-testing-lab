# 03. Conformance: Testing an MCP Server Like an API

> **Series:** MCP Testing Lab · [Index](../README.md#articles) · Previous: [02](02-servers-a-host-and-an-agent.md) · Next: [04. Tool Poisoning](04-tool-poisoning.md)

Before asking whether a server is malicious, ask whether it is **correct**. A server that accepts bad arguments, changes its contract silently or leaks secrets in its errors is a liability even when its author means well.

## The checks

[`mcplab/checks.py`](../mcplab/checks.py) runs against any server:

| Check | Passes when |
|---|---|
| **conformance** | `initialize` returns a protocol version, server info and the tools capability; every tool has a valid name, a description and an object input schema; a call with valid arguments returns content; a call with invalid arguments is rejected (−32602 or `isError`); an unknown tool gets −32602; an unknown method gets −32601 |
| **list stability** | listing the tools again returns the same definitions, unless the server sent `tools/list_changed` |
| **error hygiene** | a failing tool's error message has no stack trace, file path, private key or token |
| **manifest** | the server's tool definitions match the fingerprint pinned when it was approved |
| **description scan** | descriptions contain no instruction-like text, invisible characters or references to other servers' tools (article 04) |
| **collisions** | no two servers offer the same tool name (article 06) |

## Experiment E1: what catches what

| Server | Manifest | Conformance | List stability | Error hygiene | Description scan | Collision |
|---|---|---|---|---|---|---|
| sloppy | caught | caught | | | | |
| drifting | caught | | | | | |
| leaky | | | | caught | | |
| poisoned | caught | | | | caught | |
| rugpull | | | **caught** | | | |
| shadowing | caught | | | | caught | |
| collider | caught | | | | | caught |

Every faulty or malicious server is caught by at least one check, and no check catches them all.

- **The drifting server passes conformance.** Its schema is valid; it is just different from the one you approved, under the same version number. A client written for the old schema now sends arguments the server rejects. Only the pinned manifest notices.
- **The leaky server passes everything except error hygiene.** Its contract is identical; the problem only shows when a tool fails. Test the failure path, not just the success path.
- **The rug pull is clean on the day it is checked.** Its manifest matches what was approved and its description is harmless at first listing. Only listing it again catches the change, which is why list stability and continuous pinning (article 05) exist.

## Conformance is not a formality

A server that accepts invalid arguments (the sloppy one ignores its own schema) has no reliable contract: the schema the model reads is not the one the server enforces. That gap is where many tool-misuse bugs live. The check is cheap: send a call with an argument that the schema does not allow, and expect a refusal.

Two practical points for real servers:

- **Test both error channels.** Protocol errors (wrong method, bad parameters) and tool errors (`isError: true`) are different things; a server should use each for its purpose.
- **Run conformance in the server's own CI**, and in the host's CI against every server version you depend on. A server you don't control can change; your tests are how you find out.

## Takeaways

- **Test MCP servers like APIs**: contract, errors, stability.
- **A valid schema can still be the wrong schema.** Pin what you approved.
- **Test the failure path.** Leaks hide in error messages.
- **A server can pass every check on day one and change on day two.**
