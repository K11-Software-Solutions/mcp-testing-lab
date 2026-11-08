# MCP Testing Lab

[![CI quality gates](https://github.com/K11-Software-Solutions/mcp-testing-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/K11-Software-Solutions/mcp-testing-lab/actions/workflows/ci.yml)
[![Code: MIT](https://img.shields.io/badge/Code-MIT-blue.svg)](LICENSE) [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24039887.svg)](https://doi.org/10.5281/zenodo.24039887) [![Articles: CC BY 4.0](https://img.shields.io/badge/Articles-CC%20BY%204.0-lightgrey.svg)](articles/LICENSE.md)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![No dependencies](https://img.shields.io/badge/runtime%20deps-none-success)
![No API key needed](https://img.shields.io/badge/API%20key-not%20required-success)

**Test the Model Context Protocol supply chain: conformance and contract stability of MCP servers, tool poisoning (including invisible and paraphrased instructions), rug pulls, cross-server shadowing and tool-name collisions, and a host whose every defence is red-teamed on its own.**

The tenth lab in a series for quality engineers moving into AI:

| Lab | Question it answers |
|---|---|
| [Becoming an AI Quality Engineer](https://github.com/K11-Software-Solutions/becoming-ai-quality-engineer) | Is the RAG **application** good enough to ship? |
| [LLM Model Testing Lab](https://github.com/K11-Software-Solutions/llm-model-testing-lab) | Is the **model** good enough? |
| [Agent Testing Lab](https://github.com/K11-Software-Solutions/agent-testing-lab) | Is the **agent** safe to let act? |
| [AI Production Monitoring Lab](https://github.com/K11-Software-Solutions/ai-production-monitoring-lab) | Is it **still** good, for the users we actually have, right now? |
| [Multi-Agent Testing Lab](https://github.com/K11-Software-Solutions/multi-agent-testing-lab) | When **agents work together**, does the team do the right thing, and who broke it when it doesn't? |
| [AI Performance and Cost Lab](https://github.com/K11-Software-Solutions/ai-performance-cost-lab) | Is it **fast enough under load**, and what does each **good answer** cost? |
| [AI Evaluation Science Lab](https://github.com/K11-Software-Solutions/ai-evaluation-science-lab) | Can we **trust the evaluator**, and how sure are we? |
| [AI Data Quality Lab](https://github.com/K11-Software-Solutions/ai-data-quality-lab) | Is the **data** behind it all fit to learn from, test with and retrieve? |
| [AI Security Testing Lab](https://github.com/K11-Software-Solutions/ai-security-testing-lab) | Can an **attacker** make it misbehave, and how sure are we that they can't? |
| **MCP Testing Lab** (this repo) | Can we trust the **tools our agents plug into**? |
| [AI Assurance Case Lab](https://github.com/K11-Software-Solutions/ai-assurance-case-lab) (capstone) | Can we **sign it off**, on what evidence, and what risk are we accepting? |

## How it works

A dependency-free, in-process model of MCP's tool messages (`initialize`, `tools/list`, `tools/call`, JSON-RPC errors, `tools/list_changed`), with nine servers: three good ones (notes, mailer, calculator), three faulty ones (sloppy, drifting, leaky) and four malicious ones (poisoned, rug pull, shadowing, collider). A host connects to them with four switchable defences (namespacing, manifest pinning, description scanning and a code-level argument policy), and a simulated agent that reads every tool description, including invisible characters, and sometimes follows instructions it finds there.

## Articles

| # | Article |
|---|---|
| 01 | [Why MCP Needs Its Own Testing](articles/01-why-mcp-needs-its-own-testing.md) |
| 02 | [Servers, a Host and an Agent](articles/02-servers-a-host-and-an-agent.md) |
| 03 | [Conformance: Testing an MCP Server Like an API](articles/03-conformance-testing-a-server-like-an-api.md) |
| 04 | [Tool Poisoning: Instructions Hidden in Descriptions](articles/04-tool-poisoning.md) |
| 05 | [Rug Pulls and Pinning: When Approved Tools Change](articles/05-rug-pulls-and-pinning.md) |
| 06 | [Shadowing and Collisions: When Servers Interfere](articles/06-shadowing-and-collisions.md) |
| 07 | [Defending the Host: Four Layers and What Each Stops](articles/07-defending-the-host.md) |
| 08 | [The MCP Gate, Negative Controls and Limitations](articles/08-the-mcp-gate-ci-limitations.md) |

## Quick start

Requirements: Python 3.11+. No runtime dependencies and no API key.

```bash
git clone https://github.com/K11-Software-Solutions/mcp-testing-lab.git
cd mcp-testing-lab
python -m venv .venv
source .venv/bin/activate              # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

```bash
pytest                                                   # 36 tests
python -m evals.run_mcp_checks                           # the approved servers and the host: must pass
MCP_VARIANT=rugpull python -m evals.run_mcp_checks       # a malicious server: must fail
MCP_VARIANT=no-pinning python -m evals.run_mcp_checks    # a weakened host: must fail
python -m experiments.run_experiments                    # the four experiments behind the articles
```

## Repository layout

```text
mcplab/
  protocol.py   JSON-RPC 2.0 tool messages, error codes, schema validation, a Server base class
  servers.py    good, faulty and malicious servers; poisoning variants (plain, invisible, paraphrased)
  checks.py     conformance, list stability, error hygiene, description scan, manifests, collisions
  host.py       the host: namespacing, pinning, scanning, argument policy; the simulated agent
  redteam.py    malicious-server scenarios and harm rates, each defence alone or together
evals/
  run_mcp_checks.py      server checks against approved manifests, plus host red-team checks
  approved_servers.json  pinned manifests of the approved servers (a lockfile for tools)
experiments/   E1 checks by server, E2 host defences, E3 poisoning variants, E4 changes to approved servers
tests/         36 tests
articles/      the eight articles
.github/workflows/ci.yml   tests -> MCP gate + 11 servers and host configurations that must fail -> experiments
```

## What the lab finds

- **Every faulty or malicious server was caught by at least one check, and no check caught them all.** A drifting schema passed conformance; only the pinned manifest saw it. A rug pull was clean on the day it was approved; only listing it again showed the change.
- **A poisoned tool description made the agent send the user's private key in 66% of runs** while it correctly added 2 and 3.
- **A paraphrased poisoning passed description scanning untouched.** A code-level argument policy (no secrets in tool arguments) stopped every variant, because it checks what is sent, not how the request was worded.
- **A shadowing server caused harm without ever being called**, by telling the agent to BCC the attacker on a trusted server's email tool.
- **A tool-name collision hijacked 100% of emails** while every task appeared to succeed; only namespacing stopped it.
- **Pinning flagged every change, including harmless ones; re-approving only on version bumps missed every same-version attack**, and scanning missed a quietly widened schema.

## CI quality gates

Every push runs three jobs: **tests**; the **MCP gate** (server checks against pinned manifests, and each host defence red-teamed on its own) plus eleven malicious, faulty or weakened configurations that must each fail for the right reason; and an **experiments** job that fails if the results differ from the committed ones.

## Limitations

A teaching model of the protocol's tool messages (no transports, resources, prompts, sampling or authorisation), a simulated agent, a pattern-based scanner and a simple argument policy. [Article 08](articles/08-the-mcp-gate-ci-limitations.md#limitations) covers each and how to run the same checks against real servers through an MCP SDK.

## About

Created by **Kavita Jadhav**, founder of [K11 Software Solutions](https://github.com/K11-Software-Solutions), Senior SDET and AI Quality Engineer working on LLM evaluation, red teaming and agentic QA systems.

**Licences:** code under the [MIT License](LICENSE); the written material in [`articles/`](articles/LICENSE.md) under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (share and adapt with credit).

All servers, users, keys and addresses are fictional. The malicious servers are deliberately simple test fixtures for defences; use the techniques only on systems you are authorised to test.

## Citing

Use GitHub's **Cite this repository** button (from [`CITATION.cff`](CITATION.cff)). Each tagged release is archived on Zenodo with its own DOI. Cite the version you used:

> Jadhav, K. (2026). *MCP Testing Lab* (Version v1.0.0) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.24039888

To refer to the project as a whole (always resolves to the latest version), use the concept DOI: https://doi.org/10.5281/zenodo.24039887
