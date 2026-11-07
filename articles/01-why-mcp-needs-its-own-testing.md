# 01. Why MCP Needs Its Own Testing

> **Series:** MCP Testing Lab · [Index](../README.md#articles) · Next: [02. Servers, a Host and an Agent](02-servers-a-host-and-an-agent.md)

This is the tenth lab in a series for quality engineers moving into AI. The [Agent Testing Lab](https://github.com/K11-Software-Solutions/agent-testing-lab) built one agent with its own tools and served them over the Model Context Protocol (MCP). Real agents increasingly do the opposite: they **plug into tools other people wrote**, through MCP servers installed from a registry, a colleague's repository or a vendor. This lab tests that supply chain.

## What MCP changes

MCP is a standard way for an AI application (the **host**) to connect to **servers** that offer tools. The host asks each server for its tool list (names, descriptions, input schemas), shows those to the model, and forwards the model's tool calls. It works like a package manager for agent capabilities, and it brings a package manager's risks:

| A package ecosystem | The MCP equivalent |
|---|---|
| a package you install runs with your permissions | a server's tools run with the agent's permissions |
| a malicious package hides code | a malicious server hides **instructions**, in tool descriptions the model reads and the user rarely sees |
| a trusted package is updated with something malicious | a server's tools change after you approved them (a **rug pull**) |
| two packages define the same name | two servers offer the same tool name, and one wins (**collision**) |
| a dependency affects another package's behaviour | one server's description changes how the agent uses **another** server's tool (**shadowing**) |

The difference from code packages: the "payload" is natural language aimed at the model. Nothing is executed until the model decides to follow it, and nothing looks like code to a scanner.

## Two halves of the job

1. **Test the servers**, like any API you depend on: do they follow the protocol, keep their contract stable, fail cleanly, and keep secrets out of their errors? (articles 03 and 05)
2. **Test the host's defences**, like a security boundary: what stops a malicious server from hijacking the agent, and does each defence actually work on its own? (articles 04, 06 and 07)

## Why an in-process model of the protocol

The lab implements the parts of MCP that matter for tools (`initialize`, `tools/list`, `tools/call`, JSON-RPC error codes and the `tools/list_changed` notification) in plain Python, in-process, with no dependencies. Every test is deterministic and the whole gate runs in about a second. It is a teaching model of the message shapes, not the official SDK; article 08 explains how to point the same checks at real servers.
