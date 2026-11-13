# Changelog

## 0.1.0

First release: `pcicomplyagent`, `bpcheckagent`, `driftagent`, `socagent`, and the shared `lib/agent.py`
(strict findings parser, offered-tool proof, recorded runs, grading). Needs mecbots 0.2.0 or later; see
`docs/VERSIONING.md`.

Included in this release, from review: the parsed findings grade the run (and the report says so); credential fields match as whole
tokens and key material is always dropped; a malformed tool call cannot abort a run; `non-critical` is not a rating; pcicomplyagent's
logged-deny check needs cardholder-zone coverage, a policy name in two zone pairs is judged on both, the triggered unit shares the
weekly instance's environment file and its time budget, and a commit during the weekly collect is deferred; bpcheckagent honours a
deactivated `match dynamic-application`; no credential-looking model text reaches a state file, which is mode 600; socagent's
evidence ends at the queue's timestamp.
