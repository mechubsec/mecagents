# Versioning

[Semantic versioning](https://semver.org). The version is in `VERSION`; changes are in `CHANGELOG.md`.

## What is breaking here

A major bump (while below 1.0, a minor bump) for any of:

- the **state-file format** under `~/.local/state/labbots/` (keys or shapes that reports or later runs read);
- an **environment variable** renamed, removed, or given a different meaning;
- the **findings JSON contract**: the block the model must end with (`findings`, `changes`, or the socagent
  verdict) and the strict parsing of it;
- the **required mecbots version**, or the escalation queue format `socagent` reads.

New agents, new optional variables and tighter checks are minor; fixes and docs are patch.

## Required mecbots

0.1.0 needs **mecbots main at the time of this release**. mecbots is getting a `VERSION` file; this section will
then name a minimum version. Two things mecagents relies on are not in that mecbots yet:

- `socbot` writing the escalation queue that `socagent` reads;
- the runner scrubbing Discord text and keeping full reports locally.

The other three agents run without them; socagent has nothing to investigate until the queue exists.
