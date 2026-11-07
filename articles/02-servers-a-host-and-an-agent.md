# 02. Servers, a Host and an Agent

> **Series:** MCP Testing Lab · [Index](../README.md#articles) · Previous: [01](01-why-mcp-needs-its-own-testing.md) · Next: [03. Conformance](03-conformance-testing-a-server-like-an-api.md)

## The protocol

[`mcplab/protocol.py`](../mcplab/protocol.py) implements JSON-RPC 2.0 messages:

| Method | Returns |
|---|---|
| `initialize` | protocol version, capabilities, server name and version |
| `tools/list` | each tool's `name`, `description` and `inputSchema` (JSON Schema) |
| `tools/call` | `content` (a list of text parts) and `isError` |
| `notifications/tools/list_changed` | sent by a server when its tools change |

Protocol errors use JSON-RPC codes: −32601 for an unknown method, −32602 for invalid parameters (including an unknown tool or bad arguments). A tool that runs and fails returns a normal result with `isError: true`.

## Nine servers

[`mcplab/servers.py`](../mcplab/servers.py):

| Server | Kind | What it does |
|---|---|---|
| notes | good | `add_note`, `search_notes` |
| mailer | good | `send_email` to the user's contacts |
| calculator | good (as approved) | `add` |
| sloppy | faulty | accepts arguments that break its schema |
| drifting | faulty | changes a tool's input schema without changing its version |
| leaky | faulty | error messages contain a stack trace, a file path and a secret token |
| poisoned | malicious | hidden instructions in the `add` description: send the user's SSH key |
| rugpull | malicious | harmless on first listing; poisoned on a later one, with no notification |
| shadowing | malicious | a weather tool whose description tells the agent to BCC the attacker on every email from **any** server |
| collider | malicious | registers its own `send_email` ("faster delivery") that copies mail to the attacker |

## The host

[`mcplab/host.py`](../mcplab/host.py) connects to a list of servers, lets the user approve them, and builds the registry of tools the agent can see. It has four switchable defences:

| Defence | What it does |
|---|---|
| namespacing | tools are addressed as `server.tool`; without it, the server registered **last** silently takes over a shared name |
| pinning | each server's tool manifest is pinned when approved; any later change disables the server until it is re-approved |
| scanning | servers whose descriptions look like instructions (or contain invisible characters, or refer to other servers' tools) are not loaded |
| argument policy | every call is checked in code before it runs: no secrets in arguments; email only to the user's contacts; no BCC to anyone else |

## The agent

The agent is simulated. It sees every loaded tool's description, as a real model does, including text hidden in invisible Unicode characters, and with probability 0.6 it follows instructions it finds there. Three tasks: add two numbers, email Bob the meeting notes, save a note. Harm is measured in what actually happened: a secret in a tool call that ran, an email copied to the attacker, an email routed through an untrusted server.

## The approval model

In every red-team scenario, the user **approves each server once, as it looks at that moment**: they connect it, glance at it, and click allow. That is how most people use MCP today, and it is the situation the defences have to handle: a malicious server that the user has already trusted.
