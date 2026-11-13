"""driftagent collect (daily 23:00): intent drift of the fixture `lab-vsrx` against a golden config. Code fetches the
live config (set format) through the agent's own read-only token, normalises it and compares it with the golden at
~/.config/labbots/driftagent/golden.set (override DRIFTAGENT_GOLDEN). Three outcomes, no model needed for two:
  - no golden yet: the live config is saved as golden ("golden recorded"), no model run;
  - identical: "no drift", no model run;
  - different: code computes the added/removed lines and the objects they touch, then ONE Hermes one-shot (a local
    model, read-only MCP token, only the tool bridge offered) is asked what the change means; its claims are checked
    against the diff and graded (every touched policy named, tool-use safety). Posts nothing; report.py reads the state.

Safety: the device is asserted before every call, the model's token cannot write, the model has no shell, file, web
or messaging tool, its text is untrusted (stored and graded, never executed), and this script changes no device."""

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent  # noqa: E402
import grading  # noqa: E402
from mcp import mcp_call_tools  # noqa: E402

DEVICE = grading.DEVICE  # the one device this agent may address; see grading.py
JUNOS_MCP = os.environ.get("DRIFTAGENT_MCP", "junos-driftagent")  # entry in the Hermes config holding a read-only token for DEVICE only; labbots reads it, the model profile does not
PROFILE = os.environ.get("DRIFTAGENT_PROFILE", "driftagent")  # the restricted Hermes profile the model runs as
MODEL = os.environ.get("DRIFTAGENT_MODEL", "qwen3-coder-next:latest")
SKILLS = "parsing-srx-configs,firewall-config-diff"
STATE = Path(os.environ.get("DRIFTAGENT_STATE", Path.home() / ".local/state/labbots/driftagent.json"))
GOLDEN = Path(os.environ.get("DRIFTAGENT_GOLDEN", Path.home() / ".config/labbots/driftagent/golden.set"))
AGENT_TIMEOUT = 1800  # plus the preflight (<=600 s): must stay under LABBOTS_TIMEOUT in the systemd drop-in
HERE = Path(__file__).resolve().parent
PROMPT_LINES, PROMPT_LINE_CAP = 80, 400  # changed lines shown to the model per side


def assert_device(device) -> None:
    """Raise unless the device is the one fixture this agent may address."""
    if device != DEVICE:
        raise ValueError(f"driftagent may only address {DEVICE}, not {device!r}")


def device_answers() -> bool:
    """True when the fixture answers gather_device_facts through the agent's own read-only token."""
    arguments = {"device": DEVICE}
    assert_device(arguments["device"])
    mcp_call_tools(JUNOS_MCP, [("gather_device_facts", arguments)])
    return True


def fetch_config() -> str:
    """The fixture's active configuration, set format, through the agent's own read-only token."""
    arguments = {"device": DEVICE, "format": "set"}
    assert_device(arguments["device"])
    return agent.mcp_call_text(JUNOS_MCP, "get_junos_config", arguments)


def save_golden(path: Path, lines: list[str]) -> None:
    """Write the golden config (mode 600, directory 700): lab data, kept outside the repo."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write("\n".join(lines) + "\n")


def build_prompt(diff: dict) -> str:
    """The prompt with the changed lines as data (capped per side; the model fetches the live config itself)."""
    def side(title: str, lines: list[str]) -> str:
        shown = [line[:PROMPT_LINE_CAP] for line in lines[:PROMPT_LINES]]
        more = f"\n(... {len(lines) - PROMPT_LINES} more lines not shown)" if len(lines) > PROMPT_LINES else ""
        return f"{title} ({len(lines)}):\n" + ("\n".join(shown) + more if shown else "(none)")
    block = "```\n" + side("REMOVED", diff["removed"]) + "\n\n" + side("ADDED", diff["added"]) + "\n```"
    return (HERE / "prompt.md").read_text().strip().replace("<<DEVICE>>", DEVICE).replace("<<DIFF>>", block)


def timed(run: dict, phase: str, started: float) -> None:
    """Record how long a phase took, in seconds."""
    run["phases"][phase] = round(time.time() - started)


def run_agent_and_grade(run: dict, save, diff: dict) -> None:
    """The Hermes one-shot, then the changes verified against the diff and graded, recorded into `run`."""
    key = grading.derive_key(diff["objects"])
    assert_device(key["target"])
    run["key"] = key
    started = time.time()
    run["tools_offered_preflight"] = agent.preflight_offered_tools(PROFILE, MODEL, SKILLS)
    save()
    result = agent.run_hermes(PROFILE, MODEL, SKILLS, build_prompt(diff), AGENT_TIMEOUT)
    timed(run, "agent", started)
    # nothing credential-looking reaches the state file: the stored copies are scrubbed, grading below reads the raw ones
    run.update(agent_status=result["status"], packet=agent.scrub_text(result["output"][:30000]), files=agent.scrub_json(result["files"]),
               session_id=result["session_id"])
    if not result["session_id"]:  # Hermes never started a session: nothing to grade
        raise RuntimeError(f"hermes run did not start: {result['status']}")
    facts = agent.session_facts(PROFILE, result["session_id"])
    run.update(tools_offered=facts["tools_offered"], calls=agent.scrub_json(facts["calls"]))
    save()
    started = time.time()
    packet = "\n\n".join([result["output"], *result["files"].values()])
    changes, note = grading.structured_changes(packet, diff)
    run.update(changes=changes or [], changes_source="structured" if changes is not None else "none", changes_note=note)
    run["grade"] = agent.grade(packet, facts["calls"], key, facts["tools_offered"], agent.BRIDGE_TOOLS, result["status"])
    run["passed"] = all(ok for _, ok, _ in run["grade"])
    timed(run, "verify", started)


def main() -> int:
    """Run the whole collect; an empty report block means no post (report.py decides what is posted)."""
    with agent.recorded_run(STATE, model=MODEL, device=DEVICE, outcome="running", phases={}, golden=str(GOLDEN)) as (run, save):
        try:
            started = time.time()
            try:
                device_answers()
            except Exception as exc:  # the token is read-only: all we can say is that the device did not answer
                run.update(outcome="could not run", reason=f"device unreachable ({type(exc).__name__}: {str(exc)[:200]})")
                timed(run, "preflight", started)
                return finish()
            timed(run, "preflight", started)
            live = grading.normalise(fetch_config())
            if not live:  # an empty fetch would read as "everything removed"
                raise RuntimeError("the device returned no set lines")
            run["live_lines"] = len(live)
            if not GOLDEN.exists():
                save_golden(GOLDEN, live)
                run["outcome"] = "golden recorded"
                return finish()
            diff = grading.compare(GOLDEN.read_text(), "\n".join(live))
            run["diff"] = diff
            if not diff["added"] and not diff["removed"]:
                run["outcome"] = "no drift"
                return finish()
            save()
            run_agent_and_grade(run, save, diff)
            run["outcome"] = "graded"
        except Exception as exc:  # could not run: nothing here says the config or the model is wrong
            run.update(outcome="could not run", reason=f"{type(exc).__name__}: {str(exc)[:300]}")
    return finish()


def finish() -> int:
    """Print the empty report block run_bot.py expects."""
    print("REPORT START\nREPORT END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
