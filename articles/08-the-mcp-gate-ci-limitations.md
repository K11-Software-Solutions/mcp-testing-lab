# 08. The MCP Gate, Negative Controls and Limitations

> **Series:** MCP Testing Lab · [Index](../README.md#articles) · Previous: [07](07-defending-the-host.md)

## The gate

`python -m evals.run_mcp_checks` checks the servers the host is about to load, then red-teams the host:

| Part | Requirement |
|---|---|
| Every deployed server | matches its pinned manifest in [`evals/approved_servers.json`](../evals/approved_servers.json); passes conformance, list stability and error hygiene; no suspicious descriptions |
| Across servers | no tool-name collisions |
| Each host defence alone | zero harm from the malicious servers it exists for |
| All host defences | zero harm from every malicious server, and the user's tasks complete on the approved servers |

New or changed servers are approved deliberately: `python -m evals.run_mcp_checks --approve` writes the current manifests, and the change is reviewed in the commit, like a lockfile.

## Negative controls

Eleven variants, each of which must fail for the right reason:

| Variant | Fails on |
|---|---|
| `sloppy` | conformance (invalid arguments accepted), manifest |
| `drifting` | manifest changed without a version bump |
| `leaky` | error hygiene |
| `poisoned` | description scan, manifest |
| `rugpull` | manifest (the gate lists it more than once), description scan |
| `shadowing` | unapproved server, description scan, cross-server reference |
| `collider` | unapproved server, collision |
| `no-namespacing` | the namespacing red-team check |
| `no-pinning` | the pinning red-team check |
| `no-scanning` | the scanning red-team checks |
| `no-arg-policy` | the argument-policy red-team checks |

## Reproducible experiments

The four experiments behind articles 03 to 07 are deterministic, and CI fails if they differ from the committed [`experiments/results/summary.md`](../experiments/results/summary.md).

## Limitations

- **A teaching model of the protocol.** Only the tool messages, in-process, without transports (stdio, HTTP), sessions, resources, prompts, sampling or authorisation. Real servers bring all of those, and each has its own failure modes (authorisation scopes in particular).
- **A simulated agent.** It follows hidden instructions with a fixed probability and recognises a fixed set of intentions. Real models differ by model, prompt and wording; measure your own.
- **A pattern-based description scanner.** Paraphrase gets past it (article 04). Model-based classifiers do better and still miss things.
- **A simple argument policy.** It knows about private keys, tokens and email recipients. Real policies need to cover file paths, URLs, data volumes and every tool that sends data out.
- **Approval is modelled, not designed.** How approval and re-approval are presented to people decides whether pinning works; that is a UX problem the lab doesn't test.

## Using the method on real servers

1. Connect to each server with an MCP SDK client and run the same checks: `initialize`, `tools/list` twice, calls with valid and invalid arguments, an unknown tool, an unknown method, a forced failure.
2. Keep an approved-manifest file in the repository and fail CI on any difference.
3. Scan descriptions for instruction-like text, invisible characters and references to other servers' tools, and review every hit.
4. Put argument policy in the host, in code, for every tool that can send data anywhere.
5. Red-team the host with deliberately malicious test servers like the ones in [`mcplab/servers.py`](../mcplab/servers.py), and keep them as permanent negative controls.

## Takeaways

- **Pin, check and red-team every server the agent can reach.**
- **Prove the gate with servers and host configurations that must fail.**
- **Know what the model and the scanner can't see**, and keep code-level policy as the safety net.
