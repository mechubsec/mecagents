<!-- brand:header:start -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mecagents-wordmark.svg">
    <img src="docs/assets/mecagents-wordmark-light.svg" width="300" alt="mecagents">
  </picture>
</h1>

<p align="center"><em>a mechub project — sovereign network-security automation</em></p>

<p align="center"><img src="docs/assets/icons/mecagents.png" width="96" alt="mecagents mascot"></p>
<!-- brand:header:end -->

## What this is

Four example **agents**, an add-on to [mecbots](https://github.com/mechubsec/mecbots). A bot is code that
builds a report; its local model only adds advice and has no tools. An agent is riskier: a local model runs
real firewall skills and calls an MCP server itself. Three rules contain it: a **read-only token** scoped to
one device, **no other tools** for the model (proved before every run), and **code that checks every finding**
before it is reported.

## Install

Needs Linux with systemd, Python 3.11+, PyYAML, [Ollama](https://ollama.com), [Hermes Agent](https://github.com/NousResearch/hermes-agent) and a Junos MCP server.

```sh
git clone https://github.com/mechubsec/mecbots ~/mecbots
git clone https://github.com/mechubsec/mecagents /tmp/mecagents
cp -r /tmp/mecagents/bots /tmp/mecagents/lib /tmp/mecagents/tests /tmp/mecagents/systemd ~/mecbots/
```

Then mint a read-only token and create the restricted Hermes profile: [docs/SETUP.md](docs/SETUP.md).

## Use

```sh
cd ~/mecbots
python3 -I bin/run_bot.py pcicomplyagent.collect --dry-run   # runs the real collect, posts nothing
python3 -I bin/run_bot.py pcicomplyagent --dry-run           # prints the report
cp -r systemd/labbot@.service systemd/labbot*pcicomplyagent* ~/.config/systemd/user/
systemctl --user enable --now labbot-pcicomplyagent-collect.timer labbot-pcicomplyagent.timer
```

| | Agent | What it does |
|---|---|---|
| <img src="docs/assets/icons/pcicomplyagent.png" width="48" alt=""> | [`pcicomplyagent`](docs/agents/pcicomplyagent.md) | PCI DSS evidence review of one firewall, graded against an answer key |
| <img src="docs/assets/icons/bpcheckagent.png" width="48" alt=""> | [`bpcheckagent`](docs/agents/bpcheckagent.md) | best-practice audit of one firewall, graded against a key derived from its config |
| <img src="docs/assets/icons/driftagent.png" width="48" alt=""> | [`driftagent`](docs/agents/driftagent.md) | explains config drift from a golden copy; the model runs only on drift |
| <img src="docs/assets/icons/socagent.png" width="48" alt=""> | [`socagent`](docs/agents/socagent.md) | investigates what `socbot` escalated, in SSDF event data |

## More

- [docs/SETUP.md](docs/SETUP.md) · [docs/CAVEATS.md](docs/CAVEATS.md) · [docs/VERSIONING.md](docs/VERSIONING.md)
- [CHANGELOG.md](CHANGELOG.md) · [LICENSE](LICENSE)
