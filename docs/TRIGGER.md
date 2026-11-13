# Commit-triggered pcicomplyagent

A commit on the device can start a `pcicomplyagent` run immediately instead of waiting for the weekly one. The chain:

```
device commit -> event policy -> Python event script -> POST to the receiver -> triggered unit -> collect + report
```

The trigger only tells you a commit happened. Code, not the model, decides whether the commit added a bad rule: the
collect asks the device what changed and flags policies deterministically (see the
[agent page](agents/pcicomplyagent.md#commit-triggered-mode)).

## 1. The device

Config lines (set format; the script language must be enabled, and the names are yours to choose):

```
set system scripts language python3
set event-options policy notify-on-commit events UI_COMMIT_COMPLETED
set event-options policy notify-on-commit then event-script commit_notify.py
set event-options event-script file commit_notify.py python-script-user <non-root-user>
```

The script is [`bots/pcicomplyagent/trigger/commit_notify.py`](../bots/pcicomplyagent/trigger/commit_notify.py), a template:
set `URL` (receiver address and port) and `DEVICE`, and replace `@@SECRET@@` with the shared secret **when you
transfer the file**, not in the repository. Placing it:

1. Transfer it to `/var/tmp` on the device.
2. Run `request system scripts refresh-from event file commit_notify.py url file:///var/tmp/commit_notify.py`.

The file must exist in the event-script directory **before** the commit that adds the `file` statement, or the commit
check fails. So refresh first, then commit the config.

If the receiver is on the same subnet as the device's management interface, no route or security policy is needed:
the script's traffic leaves through the management interface, not the data plane. Otherwise the device needs a route
to the receiver and, if the traffic crosses a zone, a policy that allows it.

## 2. The receiver

`bots/pcicomplyagent/trigger/receiver.py`, run by `pcicomplyagent-trigger-receiver.service` (a user unit). Settings are
environment variables: `TRIGGER_BIND` (default `192.0.2.10`), `TRIGGER_PORT` (`8802`), `TRIGGER_ALLOWED_SOURCE`
(`192.0.2.20`), `TRIGGER_SECRET_FILE` (`~/.config/labbots/pcicomplyagent-trigger.secret`, mode 600, one line) and
`TRIGGER_NOTE_FILE`. Its checks, in order, for `POST /commit`:

- **One source address**: anything but `TRIGGER_ALLOWED_SOURCE` gets 403.
- **Shared secret**: the `X-Trigger-Secret` header, compared in constant time; an empty secret file never matches.
- **Body ignored**: capped at 512 bytes and never acted on. Only `device=` and `user=` are kept, each capped at 32
  printable characters, in a small note file the run may show as "by <user>". It is the device's own text: untrusted.
- **Debounce**: a notice within 60 s of the last start, or while the unit runs, starts nothing at once (the reply is still 202).
  It is kept (the latest one wins) and one more run starts when the running one has finished, so the last commit is always reviewed.
- **Deferral**: while the weekly collect (`labbot@pcicomplyagent.collect.service`) is running, the notice is kept (the latest one
  wins) and the triggered unit starts when the weekly collect has finished: one run, however many notices. Without this the
  triggered collect would queue on the state lock and might time out.
- **Ordering**: the weekly collect and the report carry `After=pcicomplyagent-triggered.service` (shipped drop-ins), so a
  triggered run that started just before them finishes first; they wait in systemd's queue, which does not use up their time limit.

Open the receiver's port in the host firewall for the device's address only, for example with `ufw`:
`ufw allow from <device-address> to any port 8802 proto tcp`.

## 3. The triggered unit

`pcicomplyagent-triggered.service` runs the collect, then the posting report, once. It sets
`PCICOMPLYAGENT_TRIGGER=commit`. It is its own unit rather than `labbot@...` because the quiet-hours guard
(`ExecCondition` in the `labbot@` template) must not apply: a commit is worth knowing about at any hour, and a
triggered run always posts. Its limits are the weekly collect's budget plus the report step: `TimeoutStartSec=3300` and
`LABBOTS_TIMEOUT=2700`. Site settings (device, MCP server, zones, state path, provider, model, post target) go in
`~/.config/labbots/pcicomplyagent.env`, an optional file that the unit reads, like the weekly instance does (see
[SETUP](SETUP.md#6-configure-and-schedule)); without it the unit would run on the defaults. Copy both units to `~/.config/systemd/user/`, run `systemctl --user daemon-reload`, and
`systemctl --user enable --now pcicomplyagent-trigger-receiver.service`. Do not enable the triggered unit; the receiver
starts it.

## Caveats

- The event reports the committing user as the device sees it (for example an automation account, not the person
  behind it). Treat it as a hint.
- A dropped POST costs the script its 3-second timeout but never delays or fails a commit: every error is swallowed.
  A dropped notice means no triggered run; the weekly run still happens.
- A commit that changed nothing yields an empty diff; the report says no security policy changed.
- When `junos_config_diff` is not available to the agent's token, the collect compares with the policy lines saved
  by the previous run and says so; if there is no previous run either, it says it could not tell what changed.
- Several commits while a run is in progress produce one more run, not one each; its diff is against rollback 1 only, so
  it shows the last commit's changes. Keep commits apart or read the device's commit history for the ones in between.
