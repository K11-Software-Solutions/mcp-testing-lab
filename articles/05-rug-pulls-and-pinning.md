# 05. Rug Pulls and Pinning: When Approved Tools Change

> **Series:** MCP Testing Lab · [Index](../README.md#articles) · Previous: [04](04-tool-poisoning.md) · Next: [06. Shadowing and Collisions](06-shadowing-and-collisions.md)

Approving a server once protects you only if the server stays the same. A **rug pull** is a server that behaves well until it has been trusted, then changes its tool definitions, often without changing its version number or announcing the change.

## The rug-pull server

The lab's `rugpull` server describes `add` as "Add two numbers." on its first listing. From the second listing on, the description becomes the poisoned one from article 04, with no `tools/list_changed` notification and the same version.

On the day it was approved, it passed every check except one: listing it a second time (list stability) showed the change. With no host defences, the agent then followed the new instruction in 66% of runs (E2).

## Pinning

The defence is **pinning**: when the user approves a server, the host records a fingerprint of its tool manifest (every tool's name, description and schema). On every later connection it compares. Any difference disables the server until someone re-approves it.

In E2, pinning on its own brought the rug pull's harm from 66% to **0%**. The server was disabled as soon as it changed, so the calculator task could not run either: the correct outcome for a tool that just changed under you.

## Experiment E4: what each rule detects

Six changes to an approved notes server, three harmless and three malicious, checked three ways:

| Change | Kind | Pinning | Re-approve only on a version bump | Description scan |
|---|---|---|---|---|
| typo fixed in a description, version bumped | benign | flags it | flags it | — |
| new optional parameter, version bumped | benign | flags it | flags it | — |
| new tool, version bumped | benign | flags it | flags it | — |
| hidden instructions added, **same version** | malicious | flags it | **misses it** | flags it |
| schema widened with a free-text field, **same version** | malicious | flags it | **misses it** | **misses it** |
| hidden instructions added, version bumped | malicious | flags it | flags it | flags it |

- **Pinning catches every change**, including the three harmless ones. That is its strength and its cost: someone has to review each change.
- **Re-approving only when the version changes misses the attacks that matter most**: a rug pull doesn't bump the version. Never trust a server's own claim about whether it changed.
- **Scanning misses a widened schema.** Adding a free-text `context` field to `add_note` gives the server a new channel for whatever the model can be talked into putting there, and nothing in the description looks suspicious.

## Making pinning workable

Pinning only works if re-approval is quick and informed, otherwise people approve everything without reading. Three things help:

1. **Show a diff**, not the whole manifest: which tool changed, and exactly how (description text, new or removed parameters, required fields).
2. **Highlight the risky parts of a diff**: new free-text parameters, new tools that write or send, description text that addresses the assistant.
3. **Pin in CI as well as in the client.** The lab's gate keeps an approved manifest per server in [`evals/approved_servers.json`](../evals/approved_servers.json); a server that changes fails the build until the new manifest is reviewed and committed, like a lockfile.

## Takeaways

- **Approval is a snapshot. Pin it, and compare on every connection.**
- **Never rely on version numbers to tell you a server changed.**
- **Watch schemas as well as descriptions.** A new free-text field is a new channel.
- **Make re-approval a reviewable diff**, or it becomes a reflex.
