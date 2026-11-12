# bpcheckagent

A local model audits one firewall's rulebase and hardening against best practice. Code derives the answer key
from the same config, so there is no hand-made key to maintain.

## Uses

- Skills (from [`mechubsec/fwskillsshare`](https://github.com/mechubsec/fwskillsshare)): `parsing-srx-configs`, `firewall-best-practices-audit`.
- Junos MCP read tools only, through Hermes' tool bridge: `get_router_list`, `get_device_list`, `gather_device_facts`, `get_junos_config`, `junos_config_diff`.
- The model ends with one `json` block: `{"findings": [{rule, check, severity, summary, evidence}]}`.

## How findings are verified

Same four levels as [pcicomplyagent](pcicomplyagent.md): verified, rule exists, absence, unverified. There is no
heuristic fallback: an invalid block means no findings, and the report says why.

## How it is graded

Against a **derived key** (`grading.derive_key`), read from `set security policies` lines of the fetched config:

- every permit policy with source, destination and application all `any` must be named;
- if any permit policy has no `log`, the model must say logging is missing;
- a permit policy that is described, logged and narrow must not be rated a defect.

Plus the same tool-use criteria as pcicomplyagent. Limits: only those `set` lines are read (not default policy,
bracketed lists, order or shadowing), and policies are matched by name alone.

## Configuration

| Variable | Default |
|---|---|
| `BPCHECKAGENT_DEVICE` | `lab-vsrx` |
| `BPCHECKAGENT_MCP` | `junos-bpcheckagent` |
| `BPCHECKAGENT_PROFILE` | `bpcheckagent` |
| `BPCHECKAGENT_MODEL` | `qwen3-coder-next:latest` |
| `BPCHECKAGENT_STATE` | `~/.local/state/labbots/bpcheckagent.json` |

## Schedule

Collect Sunday 22:30, report Monday 07:50.

## Measured (November 2026)

One real run: **9 of 12 criteria**, 75 s of agent time, 6 calls, no tool attempts. It named two of the four
any-to-any rules and did not raise the missing logging. Its findings: 2 verified, 3 rule exists, 2 absence. One run
says little; the model is `qwen3-coder-next` for the reason given in [pcicomplyagent](pcicomplyagent.md).
