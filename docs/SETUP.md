# Setup

## Prerequisites

- Linux with systemd user units, Python 3.11+, PyYAML.
- [Ollama](https://ollama.com) with `qwen3-coder-next` pulled (or set `<AGENT>_MODEL`).
- [Hermes Agent](https://github.com/NousResearch/hermes-agent) (`hermes` on PATH).
- A Junos MCP server with a device to audit (pcicomplyagent, bpcheckagent, driftagent). socagent needs an SSDF MCP server and the escalation queue from `socbot`.
- A working [mecbots](https://github.com/mechubsec/mecbots) install, and a Discord server you administer.
- Skills `parsing-srx-configs`, `pci-ngfw-compliance`, `firewall-best-practices-audit`, `firewall-config-diff` from [`mechubsec/fwskillsshare`](https://github.com/mechubsec/fwskillsshare), installed for Hermes.

## 1. Overlay onto mecbots

```sh
git clone https://github.com/mechubsec/mecbots ~/mecbots
git clone https://github.com/mechubsec/mecagents /tmp/mecagents
cp -r /tmp/mecagents/bots /tmp/mecagents/lib /tmp/mecagents/tests /tmp/mecagents/systemd ~/mecbots/
```

This repo has the same tree shape as mecbots and does not carry its runner or MCP client. **Tests are run from the
overlaid tree**, not from this repo alone:

```sh
cd ~/mecbots && uvx --with pyyaml pytest -q tests
```

## 2. A read-only token for one device

Mint a token on your Junos MCP server that is limited **on the server** to:

- the five read tools: `get_router_list`, `get_device_list`, `gather_device_facts`, `get_junos_config`, `junos_config_diff`;
- one device.

Use your server's own token tooling (for rust-junosmcp, its `token` command; check its help for scope options).
One token per agent, so one can be revoked alone. Then test it: a write call (`load_and_commit_config`) and a call
for another device must both be refused. Do not continue until they are. For socagent, mint an SSDF token scoped to
the read tools listed in [socagent](agents/socagent.md), with no SQL and no re-identification.

## 3. The labbots MCP entry

`lib/mcp.py` finds servers by name in `~/.hermes/config.yaml`. Add one per agent, named as `<AGENT>_MCP`
(defaults: `junos-pcicomplyagent`, `junos-bpcheckagent`, `junos-driftagent`, `ssdf-socagent`):

```yaml
mcp_servers:
  junos-pcicomplyagent:
    url: https://junos.example.net:30031/mcp
    headers:
      Authorization: Bearer ${JUNOS_PCICOMPLYAGENT_TOKEN}
```

`${VAR}` is filled from `~/.hermes/.env` (mode 600; never commit it). This entry is for the collector's own
evidence fetch. Keep it out of the model's profile.

## 4. The restricted Hermes profile

One profile per agent, named like the agent (`~/.hermes/profiles/<agent>/`; step 5 creates it if it does not
exist). Edit its `config.yaml`:

- **toolsets emptied**: `platform_toolsets` set to `[]` for `cli`, `cron`, `discord`, `api_server`, `desktop`;
- **exactly one MCP server**: a `mcp_servers:` block with the model's own entry (the token above, by `${VAR}`);
- **skills**: disable every skill you do not preload;
- **provider**: under `providers:`, an entry pointing at your Ollama's `/v1` endpoint, named as `LABBOTS_HERMES_PROVIDER` (default `local-ollama`), with long timeouts (the live profile uses 1800 s).

Hermes then offers the model only its deferred-tool bridge for MCP: `tool_search`, `tool_describe`, `tool_call`.
Skill reference files cannot be offered read-only, so the model works from each skill's main file only.

**Prove the offered tools.** Every collect does this itself: `preflight_offered_tools` runs a trivial one-shot as
the profile, reads the tools Hermes offered from the profile's `state.db`, and refuses the run unless they are
exactly those three. To check by hand, from `~/mecbots`:

```sh
python3 -I -c "import sys; sys.path.insert(0, 'lib'); import agent; print(agent.preflight_offered_tools('pcicomplyagent', 'qwen3-coder-next:latest', 'parsing-srx-configs,pci-ngfw-compliance'))"
```

Expected: `['tool_search', 'tool_describe', 'tool_call']`. Anything else raises. Every saved run also records
`tools_offered` and each tool call.

## 5. Discord identity

One Discord application per agent, as for any bot (mecbots `docs/SETUP.md`, "Discord, per bot"): View Channels and
Send Messages only, then `hermes -p pcicomplyagent gateway setup`. The runner posts with `hermes -p <agent> send`,
so the profile name must equal the agent name; this is why the model profile and the Discord identity are the
same profile (its `discord` toolset is empty, so the model cannot post). Set `LABBOTS_TARGET` as for mecbots.

## 6. Configure and schedule

Site values are environment variables with placeholder defaults; set them in a drop-in such as
`~/.config/systemd/user/labbot@pcicomplyagent.collect.service.d/site.conf`:

```ini
[Service]
Environment=PCICOMPLYAGENT_DEVICE=my-firewall
Environment=LABBOTS_HERMES_PROVIDER=my-ollama
```

For pcicomplyagent, which also has a commit-triggered unit, put the same settings in one optional file instead,
`~/.config/labbots/pcicomplyagent.env` (`KEY=value` lines, mode 600): the weekly collect, the report and the triggered unit all
read it (`EnvironmentFile=-`, shipped in their drop-ins), so a setting reaches every run.

Variables per agent are in `docs/agents/`. Shared: `LABBOTS_HERMES_PROVIDER` (default `local-ollama`),
`LABBOTS_TIMEOUT` (set to 2700 by the shipped drop-ins; 4800 for socagent), `LABBOTS_TARGET`.

```sh
mkdir -p ~/.config/systemd/user
cp -r systemd/labbot@.service systemd/labbot*pcicomplyagent* ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now labbot-pcicomplyagent-collect.timer labbot-pcicomplyagent.timer
loginctl enable-linger "$USER"
```

Each agent has a collect timer and a report timer; the shipped drop-ins make the report wait for the collect.
There are no quiet hours: times are in the timers. The collect needs the model loaded; allow for a cold start.

pcicomplyagent derives its key from the device's config; check the zone names (`PCICOMPLYAGENT_UNTRUST_ZONES`, `PCICOMPLYAGENT_CDE_ZONES`) on its page. driftagent records its golden on
the first collect, so make sure the device is in its intended state then.

First check: `python3 -I bin/run_bot.py <agent>.collect --dry-run`, then `python3 -I bin/run_bot.py <agent> --dry-run`.
