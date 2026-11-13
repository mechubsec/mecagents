"""socagent collect (daily, 10 minutes after socbot): investigates what socbot escalated. Reads socbot's queue
(~/.local/state/labbots/socbot-escalations.json, override SOCAGENT_QUEUE); an empty or stale (>20 h) queue is recorded as
"nothing escalated" and NO model runs. For each item (at most 3) code first fetches the item's own SSDF data with the
agent's read-only token (this also proves the server answers), then ONE Hermes one-shot (a local model, only the tool
bridge offered, one MCP server behind it) investigates and ends with a JSON verdict, which code parses strictly and
checks: every entity it cites is marked seen or not seen in the data code fetched. There is no answer key. Posts
nothing; report.py reads the state.

Safety: the model's token is read-only and scoped on the server (no SQL, no re-identification), the model has no shell,
file, web, messaging or skill tool, its text is untrusted (stored and graded, never executed), and this script changes
nothing anywhere."""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent  # noqa: E402
import grading  # noqa: E402
from mcp import mcp_call_tools  # noqa: E402

SSDF_MCP = os.environ.get("SOCAGENT_MCP", "ssdf-socagent")  # entry in the Hermes config holding a read-only token for one SSDF principal; labbots reads it, the model profile does not
PROFILE = os.environ.get("SOCAGENT_PROFILE", "socagent")  # the restricted Hermes profile the model runs as
MODEL = os.environ.get("SOCAGENT_MODEL", "qwen3-coder-next:latest")
SKILLS = ""  # no skills: there is no SOC skill
STATE = Path(os.environ.get("SOCAGENT_STATE", Path.home() / ".local/state/labbots/socagent.json"))
QUEUE = Path(os.environ.get("SOCAGENT_QUEUE", Path.home() / ".local/state/labbots/socbot-escalations.json"))
QUEUE_MAX_AGE = 20 * 3600
MAX_ITEMS = 3
QUERY_SLACK = 600  # socbot stamps the queue after its own `now-24h` queries ran: start this much earlier so their first minutes are covered
AGENT_TIMEOUT = 1200  # per item; plus one preflight (<=600 s): 3 items stay under LABBOTS_TIMEOUT in the systemd drop-in
HERE = Path(__file__).resolve().parent
DENY_ACTIONS = ("flow_session_deny", "flow_deny", "flow_drop")
ALERT_PROVIDERS = ("juniper", "paloalto", "unifi")


def read_queue(path: Path, now: float):
    """(items, reason): the escalated items, or ([], why there are none): no queue file, an empty queue or a stale one.
    A queue that is not valid JSON of the expected shape raises ValueError (that is "could not run", not "nothing")."""
    if not path.exists():
        return [], "no queue file"
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or not isinstance(data.get("items"), list) or not isinstance(data.get("at"), (int, float)):
        raise ValueError("queue file is not {at, items}")
    if now - data["at"] > QUEUE_MAX_AGE:
        return [], "queue older than 20 hours"
    if not data["items"]:
        return [], "queue empty"
    items = []
    for item in data["items"][:MAX_ITEMS]:
        if (not isinstance(item, dict) or item.get("kind") not in grading.KINDS or not isinstance(item.get("id"), str)
                or not isinstance(item.get("facts"), dict) or not isinstance(item.get("summary"), str)):
            raise ValueError("queue item is not {id, kind, summary, facts}")
        items.append({key: item[key] for key in ("id", "kind", "summary", "facts")})
    return items, ""


def fetch_item_data(item: dict, at: float, call=None) -> tuple[set, int]:
    """(values, rows): the lowercased identity values of the SSDF rows that concern the item, fetched with the agent's own
    token for the 24 h window socbot looked at (the 24 h ending at the queue's `at`, as absolute times, not "now": `until` where the
    tool takes it, else rows stamped after `at` are dropped);
    `rows` counts the matching rows. `call(tool, arguments)` returns one raw reply."""
    since, until = (datetime.fromtimestamp(moment, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") for moment in (at - 24 * 3600 - QUERY_SLACK, at))
    call = call or (lambda tool, arguments: mcp_call_tools(SSDF_MCP, [(tool, arguments)])[0])
    kind, facts = item["kind"], item["facts"]
    if kind == "new-high-alert":
        replies = [call("recent_alerts", {"since": since, "min_severity": "medium", "providers": provider, "limit": 500}) for provider in ALERT_PROVIDERS]
    elif kind == "deny-spike":
        replies = [call("query_flows", {"action": action, "since": since, "until": until, "limit": 1000}) for action in DENY_ACTIONS]
    else:
        replies = [call("ingest_status", {})]
    for reply in replies:
        if "error" in reply:
            raise RuntimeError(f"{reply['error']}: {str(reply.get('detail', ''))[:150]}")
    rows = grading.relevant_rows(kind, facts, replies, until=at)  # recent_alerts takes no `until`: rows after the queue was written are dropped by timestamp
    values: set = set()
    for row in rows:
        values |= grading.identity_values(row)
    return values, len(rows)


def build_prompt(item: dict) -> str:
    """The prompt with the item as JSON data between tags ('<' escaped so the data cannot close the tag)."""
    data = json.dumps({"id": item["id"], "kind": item["kind"], "summary": item["summary"], "facts": item["facts"]}, indent=1).replace("<", "\\u003c")
    return (HERE / "prompt.md").read_text().strip().replace("<<ITEM>>", data)


def investigate(item: dict, at: float) -> dict:
    """One item end to end (`at` is the queue's timestamp): fetch its data, run the model, parse and verify its verdict, grade the run. Returns the
    item's record. An unreachable SSDF server is "could not run" (no model run); an aborted Hermes run is graded as a failure."""
    record = {**item, "outcome": "running"}
    try:
        values, rows = fetch_item_data(item, at)
    except Exception as exc:
        return {**record, "outcome": "could not run", "reason": f"SSDF did not answer ({type(exc).__name__}: {str(exc)[:200]})"}
    record["evidence_rows"] = rows
    started = time.time()
    result = agent.run_hermes(PROFILE, MODEL, SKILLS, build_prompt(item), AGENT_TIMEOUT)
    # nothing credential-looking reaches the state file: the stored copies are scrubbed, verifying and grading read the raw ones
    record.update(agent_status=result["status"], packet=agent.scrub_text(result["output"][:30000]), session_id=result["session_id"], seconds=round(time.time() - started))
    if not result["session_id"]:  # Hermes never started a session: nothing to grade
        raise RuntimeError(f"hermes run did not start: {result['status']}")
    facts = agent.session_facts(PROFILE, result["session_id"])
    verdict, note = grading.parse_verdict(result["output"], item["id"])
    if verdict is not None:
        verdict = grading.verify(verdict, values, grading.called_tools(facts["calls"]))
    record["grade"] = grading.grade(facts["calls"], facts["tools_offered"], agent.BRIDGE_TOOLS, verdict, note, result["status"])
    record.update(tools_offered=facts["tools_offered"], calls=agent.scrub_json(facts["calls"]), verdict=agent.scrub_json(verdict), verdict_note=note)
    record["passed"] = all(ok for _, ok, _ in record["grade"])
    record["outcome"] = "investigated"
    return record


def main() -> int:
    """Run the whole collect; an empty report block means no post (report.py decides what is posted)."""
    with agent.recorded_run(STATE, model=MODEL, queue=str(QUEUE), outcome="running", items=[]) as (run, save):
        try:
            items, reason = read_queue(QUEUE, time.time())
            if not items:
                run.update(outcome="nothing escalated", reason=reason)
                return finish()
            queued_at = json.loads(QUEUE.read_text())["at"]  # the window socbot looked at ends here
            run["tools_offered_preflight"] = agent.preflight_offered_tools(PROFILE, MODEL, SKILLS)
            save()
            for item in items:
                try:
                    run["items"].append(investigate(item, queued_at))
                except Exception as exc:  # one item failing says nothing about the others
                    run["items"].append({**item, "outcome": "could not run", "reason": f"{type(exc).__name__}: {str(exc)[:300]}"})
                save()
            run["outcome"] = "investigated"
        except Exception as exc:  # could not run: nothing here says the estate or the model is wrong
            run.update(outcome="could not run", reason=f"{type(exc).__name__}: {str(exc)[:300]}")
    return finish()


def finish() -> int:
    """Print the empty report block run_bot.py expects."""
    print("REPORT START\nREPORT END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
