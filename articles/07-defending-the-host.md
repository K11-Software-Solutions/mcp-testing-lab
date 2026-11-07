# 07. Defending the Host: Four Layers and What Each Stops

> **Series:** MCP Testing Lab · [Index](../README.md#articles) · Previous: [06](06-shadowing-and-collisions.md) · Next: [08. The MCP Gate](08-the-mcp-gate-ci-limitations.md)

Articles 04 to 06 introduced the host's defences one attack at a time. Experiment E2 puts them side by side: each malicious server, approved once by the user, against no defences, each defence alone, and all four.

## Experiment E2

200 runs each. Each cell shows harm, then how often the user's task completed.

| Server | No defences | Namespacing | Pinning | Scanning | Argument policy | All four |
|---|---|---|---|---|---|---|
| poisoned | 66% / 100% | 66% / 100% | 66% / 100% | **0%** / 0% | **0%** / 34% | 0% / 0% |
| shadowing | 66% / 100% | 66% / 100% | 66% / 100% | **0%** / 100% | **0%** / 34% | 0% / 100% |
| rugpull | 66% / 100% | 66% / 100% | **0%** / 0% | **0%** / 0% | **0%** / 34% | 0% / 0% |
| collider | 100% / 100% | **0%** / 100% | 100% / 100% | 100% / 100% | 100% / 100% | 0% / 100% |

## Reading it

**Every defence has a job, and none does every job.** Namespacing is the only thing that stops a collision. Pinning is the only thing that stops a rug pull *as such* (scanning catches this particular one because its new description is crude). Scanning and the argument policy both stop poisoning and shadowing, in different ways.

**Two kinds of outcome when an attack is stopped:**

- **The malicious server is removed** (scanning, pinning): harm is zero, and so is the poisoned calculator's usefulness. Its task can't complete. For shadowing, the weather server is removed and the user's email still goes out normally (100% done), because the email never depended on it.
- **The malicious action is refused** (argument policy): harm is zero, and the task fails whenever the agent was fooled (34% done). The server stays loaded and keeps trying.

Removing a malicious server is the better outcome; refusing its actions is the better **safety net**, because it works even when the server wasn't recognised (paraphrased poisoning, article 04).

**All four together**: no harm in any scenario, and the user's legitimate tasks (on the approved, good servers) complete every time.

## Testing each defence on its own

As in the [AI Security Testing Lab](https://github.com/K11-Software-Solutions/ai-security-testing-lab), a defence that is switched off can go unnoticed when others cover for it. The gate therefore checks each defence **alone** against the servers it exists for, and requires zero harm:

| Defence | Must stop on its own |
|---|---|
| namespacing | collider |
| pinning | rugpull |
| scanning | poisoned, shadowing, rugpull |
| argument policy | poisoned, shadowing, rugpull |

Turning off any one of them fails the build (article 08).

## Takeaways

- **Map each attack to the defences that stop it**, and make sure every attack has at least one.
- **Prefer removing a malicious server; keep refusing bad actions as the safety net.**
- **Test each defence alone**, so one can't fail behind the others.
- **Check that legitimate work still completes** with every defence on.
