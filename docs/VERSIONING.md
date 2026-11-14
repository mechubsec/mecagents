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

mecagents 0.0.5 needs **mecbots 0.0.2 or later** (0.0.3 for the exact socagent evidence window). mecbots has the socbot escalation queue that
`socagent` reads and a runner that scrubs Discord text and keeps full reports local.
