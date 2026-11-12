"""bpcheckagent collect (Sunday 22:30): a labbots *agent*. A local model (qwen3-coder-next through a Hermes profile)
runs a best-practice audit of the fixture `lab-vsrx` itself, with two skills and a read-only Junos MCP token scoped to
that device; deterministic code then checks what it claims against the device's own config and grades it against an
answer key it DERIVES from that same config (grading.derive_key: any/any/any permits, permits without logging, narrow
logged policies that must not be flagged), never from a model run. Posts nothing; the Monday report reads what this saves.

Order: (1) check the fixture answers through the agent's own read-only token (it stays on permanently; this agent
starts and stops nothing and makes no hypervisor call); (2) fetch the active config with that token as independent
evidence; (3) one Hermes one-shot, after proving the model is offered nothing but the MCP bridge; (4) extract and
verify findings, grade. The run is marked complete only at the very end.

Safety: the device is asserted before every call, the model's token cannot write, the model has no shell, file, web
or messaging tool, and its text is untrusted: it is stored and graded, never executed or interpreted."""

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
JUNOS_MCP = os.environ.get("BPCHECKAGENT_MCP", "junos-bpcheckagent")  # entry in the Hermes config holding a read-only token for DEVICE only; labbots reads it, the model profile does not
PROFILE = os.environ.get("BPCHECKAGENT_PROFILE", "bpcheckagent")  # the restricted Hermes profile the model runs as
MODEL = os.environ.get("BPCHECKAGENT_MODEL", "qwen3-coder-next:latest")
SKILLS = "parsing-srx-configs,firewall-best-practices-audit"
STATE = Path(os.environ.get("BPCHECKAGENT_STATE", Path.home() / ".local/state/labbots/bpcheckagent.json"))
AGENT_TIMEOUT = 1800  # plus the preflight (<=600 s): must stay under LABBOTS_TIMEOUT in the systemd drop-in
HERE = Path(__file__).resolve().parent


def assert_device(device) -> None:
    """Raise unless the device is the one fixture this agent may address."""
    if device != DEVICE:
        raise ValueError(f"bpcheckagent may only address {DEVICE}, not {device!r}")


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


def timed(run: dict, phase: str, started: float) -> None:
    """Record how long a phase took, in seconds."""
    run["phases"][phase] = round(time.time() - started)


def run_agent_and_grade(run: dict, save, config_text: str) -> None:
    """Phases 3 and 4: the Hermes one-shot, then findings and grade, recorded into `run`."""
    key = grading.derive_key(config_text)
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
    run["grade"] = agent.grade(packet, facts["calls"], key, facts["tools_offered"], agent.BRIDGE_TOOLS, result["status"])
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
            config_text = agent.scrub_config(fetch_config())
            run.update(config=config_text)
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
