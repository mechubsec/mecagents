# Caveats

- **Agents are riskier than bots.** A bot's model has no tools and only adds advice. An agent's model chooses and
  runs tools against a live system. The containment (read-only scoped token, nothing but the MCP bridge offered,
  code that checks findings) limits the damage; it does not make the model reliable.
- **Results vary run to run.** pcicomplyagent: five real runs, one clean pass (12 of 12), two missing a finding,
  one aborted, one with only a tool-use failure. bpcheckagent: 9 of 12 in its one run. driftagent: 7 of 8 in a
  scratch run. socagent: two scratch runs, both failed safety criteria, and the verdict on the same item differed
  between runs. Measured in November 2026 with one model; do not read these as rates.
- **The model tries tools it does not have.** Hermes refuses them and the run is graded as failed, but it happens
  (`read_file`, `shell`, `skill_view`, `skill_call`), and an invented tool name can abort a run. The prompts say
  plainly which tools exist; that helped, not fully.
- **Code checks that a finding points at something real, not that the model's reading is right.** driftagent
  once called an address a well-known public resolver when it was not; every check passed.
- **Levels mean different things.** *verified*: the rule exists and the quoted evidence is in the config. *rule
  exists*: the rule is there, the evidence is not found verbatim. *absence*: a claim that something is missing,
  which cannot be checked by name. *unverified*: the rule is not on the device, or nothing was checkable. None
  of them says the model's judgement is correct. socagent's *seen* is an exact match against rows code fetched.
- **Skill reference files are not available.** Hermes cannot offer them read-only, so the model works from each
  skill's main file only.
- **No answer key for driftagent or socagent.** Their grades cover safety and anchoring, not correctness.
  bpcheckagent's key is derived from the config by simple rules and covers only what those rules read.
- **pcicomplyagent's key is derived from the config by simple rules** (any/any/any permits, untrusted into the
  cardholder zone with source any, a missing logged deny-all) and covers only what those rules read; the zone names are
  assumptions you set. A logged deny-all counts only if it covers the zone pairs that involve a cardholder zone, and a name
  shared by two policies is judged on all of them, because the agent's rule name has no scope.
- **A dry run can write state.** `run_bot.py <agent>.collect --dry-run` runs the real collect: it calls the
  model and writes the state file (and, for driftagent, may record a golden). Only the post is skipped.
- **State files hold no credential-looking model text, but the check is a heuristic.** Every string in the run record (model output, files, tool-call
  arguments and keys, and notes or grade details derived from them) that matches a credential field, key material or a long
  blob is replaced when the record is saved, and a value under a credential-named key is replaced whole; a plain-text secret
  in prose with no credential field name near it can pass. State files are mode 600.
- **Never run an agent with a write-capable token.** The token's scope is the real barrier; the prompt's
  "read only" is not.
- **Discord is a cloud service.** Reports name devices and rules. The mecbots runner (0.0.1-alpha or later, which
  this release needs) scrubs Discord text and keeps full reports local; check its redact list covers your
  devices before pointing agents at a shared server.
- **Do not put a self-hosted CI runner on a repo that may go public.** A pull request can run code on it.

## Known issues (from review, not yet fixed)

- **A commit just before the weekly run** starts the triggered run first; the weekly run then waits on the same
  state lock and may use up its time limit.
- **Two commits in quick succession** can be reported under the older commit's note (device and user).
- **`driftagent` is still graded from the model's prose**, not from a findings list.
- **The whole-record scrub is broad**: a value under any key containing "token" or "secret", and any run of 32 or
  more base64-like characters, is withheld from saved runs and reports, credential or not.
