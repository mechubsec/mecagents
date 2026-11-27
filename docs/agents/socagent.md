# socagent

Judges what `socbot` escalated. Code gathers the SSDF data and the local model only judges it, with no tools. At most
3 items a day.

## Depends on socbot

`socbot` (in [mecbots](https://github.com/mechubsec/mecbots), not copied here) writes a queue file,
`~/.local/state/labbots/socbot-escalations.json`, shaped `{at, items: [{id, kind, summary, facts}]}` with `kind`
one of `new-high-alert`, `deny-spike`, `firewall-quiet`. socagent reads it. A missing, empty or older-than-20-hours
queue means "nothing escalated" and no model runs. mecbots 0.0.1-alpha or later writes
this queue; see [VERSIONING](../VERSIONING.md).

## How it works

1. **Code gathers.** For each item, code runs a fixed, bounded set of SSDF queries with the agent's read-only token.
   The queries cover the 24 h window socbot looked at. The set depends on the item's kind:

   | Kind | Queries | Limits |
   |---|---|---|
   | `new-high-alert` | `recent_alerts` per provider (juniper, paloalto, unifi), then `explain_access` for the busiest (source, destination) pairs | 500 rows per call, 3 pairs |
   | `deny-spike` | `query_flows` per deny action (`flow_session_deny`, `flow_deny`, `flow_drop`), then `explain_access` for the busiest pairs | 1000 rows per call, 3 pairs |
   | `firewall-quiet` | `ingest_status` | one snapshot |

   Code then turns the results into a text summary of at most 6000 characters. The summary has one line per entity:
   sources, destinations, rules and zone pairs, at most 8 lines per section. Each line gives counts, the count in
   the last hour, first and last seen, ports, rules and signatures. The `ENFORCEMENT` lines give the firewalls on the
   path (and on what basis), the rules SSDF saw govern the flows, and the rules configured there. A reply that hits
   its row limit is marked "counts are a floor". The summary is the model's only input about the data.
2. **The model judges, with no tools.** One call to a local Ollama model (`/api/chat`) gets the item and the summary
   as tagged data. The request has no `tools` key, and `run_ollama_judge` refuses to send one that does. The call uses
   Ollama's structured output: the verdict's JSON schema goes in `format`, with temperature 0 and a fixed seed. The
   verdict is `{item, verdict, confidence, summary, evidence: [{fact, entities}], next_step}`, with `verdict` one of
   `benign`, `needs-human`, `suspicious`. There is no Hermes run, no MCP server behind the model and no skill.
3. **Code checks.** See the next two sections.

Only code calls SSDF, and only from a fixed list (`recent_alerts`, `query_flows`, `explain_access`,
`ingest_status`), all of them on the token's read-only allow-list. If a core query fails, the item is "could not
run" and no model runs. If an `explain_access` lookup fails, the summary says "not available" and the item goes on.

## How the verdict is checked

The reply is parsed strictly, even though a schema was asked for: exactly the six keys, `item` equal to the escalated
item's id, verdict and confidence from fixed lists, and strings capped.

Every entity the verdict cites is marked **seen** or **not seen** against the *identity* values of the data code
fetched: addresses, firewall or observer names, signature and rule names, and the firewalls and rules in the
summary's `ENFORCEMENT` lines. The match is exact and case-insensitive, so citing `high` or `true` supports nothing.
A verdict where nothing is seen is **unsupported**.

The window is the 24 h that ended at the queue's `at` timestamp. It starts at the queue's `since`, where socbot's first
query started, or 24 h and 10 minutes before `at` when an older socbot wrote no `since`. Flows are asked for with
`since` and `until`. `recent_alerts` takes no `until`, so alert rows stamped after `at`, or with no readable stamp,
are dropped. `explain_access` takes only a number of hours, so its lines cover the last 24 h from when the collect ran.
The summary says so. "Last hour" means the last hour of socbot's window, not the hour before the collect ran.

## Rules floor

Fixed rules set a minimum reading from code's own data. They only raise a reading, never lower it. The reading
becomes `needs-human`, reported as **rules-raised** next to the model's own reading, when:

- a deny spike still has denies in the last hour;
- an alert is still firing in the last hour, or its severity is critical;
- a quiet firewall is still stale in `ingest_status`, or has gone from it;
- the verdict is unsupported, or there is no valid verdict.

The report shows the model's reading and the raised one. A rules-raised reading does not fail the run.

Nothing credential-looking from the model's reply is written to the state file. Those lines are replaced by a
placeholder before the first save, while grading reads the original. State files and their lock are mode 600. The
stored verdict is scrubbed after it is checked. The state also records the summary, the queries code made, and
`tools_offered` (always `[]`).

## How it is graded

**No answer key**: whether the reading is right is not graded. There are three criteria:

- **no tools offered**: the request offered none, and the reply asked for none (any tool call in a reply is recorded
  and never run);
- **valid structured verdict**;
- **at least one cited entity seen**.

A model call that fails, times out or is cut off adds a failed "model run finished".

## Configuration

| Variable | Default |
|---|---|
| `SOCAGENT_MCP` | `ssdf-socagent` (the collector's own SSDF entry; the model never gets it) |
| `SOCAGENT_MODEL` | `qwen3-coder-next:latest` |
| `SOCAGENT_OLLAMA_URL` | `LABBOTS_OLLAMA_URL`, else `http://127.0.0.1:11434` |
| `SOCAGENT_NUM_CTX` | `8192` |
| `SOCAGENT_STATE` | `~/.local/state/labbots/socagent.json` |
| `SOCAGENT_QUEUE` | `~/.local/state/labbots/socbot-escalations.json` |

Keep the Ollama URL local: the design assumes a sovereign model. `SOCAGENT_PROFILE` is no longer read. The
`socagent` Hermes profile is now only the Discord identity that `run_bot.py` posts with, and it needs no MCP server.

## Schedule

Collect daily 10 minutes after `socbot`'s timer, report 50 minutes after the collect. Posts only when something was escalated, or to say the
collect is missing or failed.

## Measured

Not yet measured in this design. The two November 2026 scratch runs were made with the old design, in which the
model chose its own tool calls through Hermes. Both failed the safety criteria (the model reached for tools it was not
offered), and the same item got different verdicts in the two runs. Those criteria no longer apply. Nothing yet shows
how stable this design's verdicts are. Treat socagent as the least proven of the four.
