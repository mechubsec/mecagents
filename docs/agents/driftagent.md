# driftagent

Compares a device's live config with a golden copy. Code computes the difference; a local model is asked what
the change means, and only when there is one.

## What happens

1. No golden yet: the live config is saved as the golden (mode 600). No model runs.
2. Identical: "no drift". No model runs.
3. Different: code lists added and removed `set` lines and the objects they touch (policy, address, zone,
   interface, other); then one Hermes run explains the change. The report shows code's diff first, labelled
   certain, then the model's reading, labelled as such. It posts only on drift or a new golden, or to say the
   collect is missing or failed.

## Uses

- Skills (from [`mechubsec/fwskillsshare`](https://github.com/mechubsec/fwskillsshare)): `parsing-srx-configs`, `firewall-config-diff`.
- Junos MCP read tools only, through Hermes' tool bridge (same five as [pcicomplyagent](pcicomplyagent.md)).
- The model ends with `{"changes": [{object, kind, effect, risk, evidence}]}`.

## How changes are verified

| Level | Meaning |
|---|---|
| verified | the object is one the diff touched and the evidence is a changed line |
| object touched | the object is touched; the evidence is not a changed line verbatim |
| unverified | the object is not one the diff touched |

## How it is graded

Against a **derived key**: every policy the diff touched must be named. Plus the tool-use criteria.
Configs are compared as sets of lines, so a pure reorder is not drift, and lines that could hold a credential
are dropped from both sides, so a rotated secret is invisible.

## Configuration

| Variable | Default |
|---|---|
| `DRIFTAGENT_DEVICE` | `lab-vsrx` |
| `DRIFTAGENT_MCP` | `junos-driftagent` |
| `DRIFTAGENT_PROFILE` | `driftagent` |
| `DRIFTAGENT_MODEL` | `qwen3-coder-next:latest` |
| `DRIFTAGENT_STATE` | `~/.local/state/labbots/driftagent.json` |
| `DRIFTAGENT_GOLDEN` | `~/.config/labbots/driftagent/golden.set` |

## Schedule

Collect daily 23:00, report daily 07:55. Most days no model runs.

## Measured (November 2026)

One scratch run with three edits made to the golden copy: **7 of 8 criteria**. All three changes were explained
and verified against the diff. It tried a tool it was not offered (refused). It also called an address a
well-known public resolver when it was not: an error the checks cannot catch, because they test that the cited
object and line exist, not that the reading is right. The saved record of this run was later overwritten by a
no-drift run, so these numbers are as recorded at the time, not re-checked.
