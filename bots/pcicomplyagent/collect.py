"""pcicomplyagent collect (Sunday 22:00): the first labbots *agent*. A local model (qwen3-coder-next through a Hermes
profile) runs a PCI evidence prompt itself, with two skills and a read-only Junos MCP token scoped to one PCI fixture
device (default `lab-vsrx`); deterministic code then checks what it claims against the device's own config and grades it
against a key derived from that config (grading.derive_key). Posts nothing; the Monday report reads what this saves.

Order: (1) check the fixture answers through the agent's own read-only token (it stays on permanently; this agent
starts and stops nothing and makes no Proxmox call); (2) fetch the active config with that token as independent
evidence (kept in memory only, never saved to the state file); (3) when PCICOMPLYAGENT_TRIGGER=commit (the commit-
triggered unit sets it), ask the device what the last commit changed and let code flag the policies; (4) one Hermes
one-shot, after proving the model is offered nothing but the MCP bridge; (5) extract and verify findings, grade. The
run is marked complete only at the very end.

Safety: the device is asserted before every call, the model's token cannot write, the model has no shell, file, web
or messaging tool, and its text is untrusted: it is stored and graded, never executed or interpreted."""

import json
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
JUNOS_MCP = os.environ.get("PCICOMPLYAGENT_MCP", "junos-pcicomplyagent")  # entry in the Hermes config holding a read-only token for DEVICE only; labbots reads it, the model profile does not
PROFILE = os.environ.get("PCICOMPLYAGENT_PROFILE", "pcicomplyagent")  # the restricted Hermes profile the model runs as
MODEL = os.environ.get("PCICOMPLYAGENT_MODEL", "qwen3-coder-next:latest")
SKILLS = "parsing-srx-configs,pci-ngfw-compliance"
STATE = Path(os.environ.get("PCICOMPLYAGENT_STATE", Path.home() / ".local/state/labbots/pcicomplyagent.json"))
AGENT_TIMEOUT = 1800  # plus the preflight (<=600 s): must stay under LABBOTS_TIMEOUT in the systemd drop-in
HERE = Path(__file__).resolve().parent
POLICY_LINES = STATE.with_name("pcicomplyagent-policy-lines.json")  # fallback baseline for a triggered run
TRIGGER_NOTE = Path(os.environ.get("TRIGGER_NOTE_FILE", STATE.with_name("pcicomplyagent-trigger.json")))  # left by the receiver
NOTE_MAX_AGE = 3600  # a note older than this belongs to some earlier commit, not to this run


def assert_device(device) -> None:
    """Raise unless the device is the one fixture this agent may address."""
    if device != DEVICE:
        raise ValueError(f"pcicomplyagent may only address {DEVICE}, not {device!r}")


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


def triggered() -> bool:
    """True when this run was started by a commit notice (the triggered unit sets PCICOMPLYAGENT_TRIGGER=commit)."""
    return os.environ.get("PCICOMPLYAGENT_TRIGGER") == "commit"


def fetch_diff() -> str:
    """What the last commit changed: the device's diff against rollback 1, through the agent's read-only token."""
    arguments = {"device": DEVICE, "version": 1}
    assert_device(arguments["device"])
    return agent.mcp_call_text(JUNOS_MCP, "junos_config_diff", arguments)


def load_policy_lines():
    """The policy lines saved by the previous collect, or None."""
    try:
        lines = json.loads(POLICY_LINES.read_text())
    except (OSError, ValueError):
        return None
    return lines if isinstance(lines, list) and all(isinstance(line, str) for line in lines) else None


def save_policy_lines(lines: list[str]) -> None:
    """Keep this run's policy lines (set/deactivate security policies only: no secrets) for the next; atomic, mode 600."""
    agent.write_private_atomic(POLICY_LINES, json.dumps(lines))


def read_trigger_note(now: float):
    """{device, user, at} from the receiver's note, or None when absent, unreadable or older than NOTE_MAX_AGE. The text
    is the device's own report: it is capped and defanged here and used only for display."""
    try:
        note = json.loads(TRIGGER_NOTE.read_text())
        received = float(note["at"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not 0 <= now - received <= NOTE_MAX_AGE:
        return None
    return {"device": agent.defang(note.get("device", ""), 40), "user": agent.defang(note.get("user", ""), 32), "at": received}


def analyse_commit(config_text: str, previous_lines, now: float) -> dict:
    """What the commit changed and which changed policies code flags: from the device's rollback-1 diff when the token
    can provide it, else from the previous run's policy lines (`source` says which), else nothing (`source` "none")."""
    note = read_trigger_note(now)
    try:
        changes, source = grading.changes_from_diff(fetch_diff()), "device diff against rollback 1"
    except Exception as exc:  # token or tool cannot give the diff: fall back, and say so
        if previous_lines is None:
            return {"source": "none", "reason": f"{type(exc).__name__}: {str(exc)[:150]}", "note": note}
        changes, source = grading.changes_from_lines(previous_lines, grading.policy_lines(config_text)), "previous run's policy lines"
    return {"source": source, **changes, "flags": grading.commit_flags(config_text, changes), "note": note}


def timed(run: dict, phase: str, started: float) -> None:
    """Record how long a phase took, in seconds."""
    run["phases"][phase] = round(time.time() - started)


def run_agent_and_grade(run: dict, save, config_text: str) -> None:
    """Phases 4 and 5: the Hermes one-shot, then findings and grade against the derived key, recorded into `run`."""
    key = grading.derive_key(config_text, grading.load_extra_key(HERE / "answer-key.json"))
    assert_device(key["target"])
    run["key"] = key
    started = time.time()
    run["tools_offered_preflight"] = agent.preflight_offered_tools(PROFILE, MODEL, SKILLS)
    save()
    result = agent.run_hermes(PROFILE, MODEL, SKILLS, (HERE / "prompt.md").read_text().strip().replace("<<DEVICE>>", DEVICE), AGENT_TIMEOUT)
    timed(run, "agent", started)
    run.update(agent_status=result["status"], packet=result["output"][:30000], files=result["files"], session_id=result["session_id"])
    if not result["session_id"]:  # Hermes never started a session: nothing to grade
        raise RuntimeError(f"hermes run did not start: {result['status']}")
    facts = agent.session_facts(PROFILE, result["session_id"])
    run.update(tools_offered=facts["tools_offered"], calls=facts["calls"])
    save()
    started = time.time()
    # a file the model wrote (it has no file tool, so normally none) is part of its answer
    packet = "\n\n".join([result["output"], *result["files"].values()])
    run["findings"], run["findings_source"], run["findings_note"] = grading.findings_for(packet, config_text)
    scored = run["findings"] if run["findings_source"] == "structured" else None  # no valid block: score the text
    run["grade_basis"] = "structured findings" if scored is not None else "from text (no structured findings)"
    run["grade"] = grading.grade(packet, facts["calls"], key, facts["tools_offered"], agent.BRIDGE_TOOLS, result["status"], scored)
    if run.get("commit"):
        run["grade"].append(grading.commit_criterion(sorted(run["commit"].get("flags", {})), scored, packet))
    run["passed"] = all(ok for _, ok, _ in run["grade"])
    timed(run, "verify", started)


def main() -> int:
    """Run the whole collect; an empty report means no post (this bot posts only the Monday report)."""
    with agent.recorded_run(STATE, model=MODEL, device=DEVICE, outcome="running", phases={}) as (run, save):
        try:
            started = time.time()
            try:
                device_answers()
            except Exception as exc:  # the token is read-only: all we can say is that the device did not answer
                run.update(outcome="could not run", reason=f"device unreachable ({type(exc).__name__}: {str(exc)[:200]})")
                timed(run, "preflight", started)
                return finish()
            timed(run, "preflight", started)
            started = time.time()
            config_text = grading.scrub_config(fetch_config())  # memory only: the report never reads it, the state file is long-lived
            previous_lines = load_policy_lines()
            if triggered():
                run.update(trigger="commit", commit=analyse_commit(config_text, previous_lines, time.time()))
            save_policy_lines(grading.policy_lines(config_text))
            timed(run, "evidence", started)
            save()
            run_agent_and_grade(run, save, config_text)
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
