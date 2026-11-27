"""socagent collect (daily, 10 minutes after socbot): judges what socbot escalated. Reads socbot's queue
(~/.local/state/labbots/socbot-escalations.json, override SOCAGENT_QUEUE); an empty or stale (>20 h) queue is recorded as
"nothing escalated" and NO model runs. For each item (at most 3):

  1. code gathers: a fixed, bounded set of SSDF queries per item kind, over the agent's read-only token, for the 24 h
     window socbot looked at, turned into a compact summary capped at SUMMARY_CAP characters (one line per entity, with
     counts, first/last seen, last-hour counts, ports, rules and signatures, and the enforcement point where SSDF has one);
  2. the model judges: ONE call to a local Ollama model with no tools and no MCP server, given only the item and that
     summary as tagged data, answering in a JSON schema (Ollama's structured output);
  3. code checks: the verdict is parsed strictly, every entity it cites is marked seen or not seen in the data code
     fetched, and a fixed rules floor raises a reading the data contradicts (an ongoing deny spike is never benign).

There is no answer key. Posts nothing; report.py reads the state.

Safety: the model is offered no tool at all (the request is checked before it is sent and the reply's tool calls are
recorded, never run), its token-holding queries are made by code only, from a fixed list, its text is untrusted (stored
and graded, never executed), and this script changes nothing anywhere."""

import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent  # noqa: E402
import grading  # noqa: E402
from mcp import mcp_call_tools  # noqa: E402

SSDF_MCP = os.environ.get("SOCAGENT_MCP", "ssdf-socagent")  # entry in the Hermes config holding a read-only token for one SSDF principal; only this code reads it
MODEL = os.environ.get("SOCAGENT_MODEL", "qwen3-coder-next:latest")
OLLAMA_URL = os.environ.get("SOCAGENT_OLLAMA_URL", agent.OLLAMA_URL)  # a local Ollama; the default is LABBOTS_OLLAMA_URL's
NUM_CTX = int(os.environ.get("SOCAGENT_NUM_CTX", "8192"))  # room for the prompt and a capped summary
STATE = Path(os.environ.get("SOCAGENT_STATE", Path.home() / ".local/state/labbots/socagent.json"))
QUEUE = Path(os.environ.get("SOCAGENT_QUEUE", Path.home() / ".local/state/labbots/socbot-escalations.json"))
QUEUE_MAX_AGE = 20 * 3600
MAX_ITEMS = 3
QUERY_SLACK = 600  # only for a queue without `since` (mecbots before 0.0.3): a guess at how long socbot's queries took
JUDGE_TIMEOUT = 1200  # per item, a cold model load included: 3 items stay under LABBOTS_TIMEOUT in the systemd drop-in
LAST_HOUR = 3600
HERE = Path(__file__).resolve().parent
DENY_ACTIONS = ("flow_session_deny", "flow_deny", "flow_drop")
ALERT_PROVIDERS = ("juniper", "paloalto", "unifi")
ALERT_LIMIT, FLOW_LIMIT = 500, 1000  # per call; a reply that reaches it makes every count a floor
SUMMARY_CAP = 6000  # characters of summary the model gets
ENTITY_LINES = 8  # lines per section (sources, destinations, rules, zones)
ENFORCEMENT_PAIRS = 3  # explain_access calls per item: the busiest (source, destination) pairs
CONFIGURED_SHOWN = 6  # configured rules listed per enforcement line
CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


# --- queue -----------------------------------------------------------------------------------------------

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


# --- code gathers ----------------------------------------------------------------------------------------

def iso(moment: float | None) -> str:
    """Epoch seconds as `YYYY-MM-DDTHH:MM:SSZ`, or `?`."""
    return "?" if moment is None else datetime.fromtimestamp(moment, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean(value, cap: int = 80) -> str:
    """A log-derived value made safe for one summary line: unwrapped, control characters and newlines gone, `<` escaped
    (so it cannot close a tag), capped."""
    text = CONTROL.sub(" ", str(grading.unwrap(value) if value is not None else "")).strip().replace("<", "\\u003c")
    return text[:cap] or "-"


def tally(rows: list, field: str, hour_start: float, peer: str | None = None, extra: tuple = ()) -> list[dict]:
    """Rows grouped by `field` (one entity per group), busiest first: count, last-hour count, first and last seen, and the
    distinct values of `peer` and of each `extra` field (ports, rules, zones...)."""
    groups: dict[str, dict] = {}
    for row in rows:
        key = clean(row.get(field))
        if key == "-":
            continue
        moment = grading.row_time(row)
        group = groups.setdefault(key, {"value": key, "count": 0, "last_hour": 0, "first": None, "last": None, "peers": Counter(), **{name: Counter() for name in extra}})
        group["count"] += 1
        if moment is not None:
            group["last_hour"] += moment > hour_start
            group["first"] = moment if group["first"] is None else min(group["first"], moment)
            group["last"] = moment if group["last"] is None else max(group["last"], moment)
        if peer and row.get(peer) not in (None, ""):
            group["peers"][clean(row.get(peer))] += 1
        for name in extra:
            if row.get(name) not in (None, ""):
                group[name][clean(row.get(name), 40)] += 1
    return sorted(groups.values(), key=lambda group: (-group["count"], group["value"]))


def top(counter: Counter, shown: int = 3) -> str:
    """The `shown` most common values of a Counter, comma-separated, with `+N more`."""
    names = [name for name, _ in counter.most_common(shown)]
    return (",".join(names) or "-") + (f" (+{len(counter) - shown} more)" if len(counter) > shown else "")


def entity_lines(label: str, noun: str, groups: list[dict], peer_label: str, extra: dict) -> list[str]:
    """One line per entity: `<label> <value> <noun>=N last_hour=M first=.. last=.. <peer_label>=.. <extra>=..`,
    at most ENTITY_LINES, then a count of what was left out."""
    lines = []
    for group in groups[:ENTITY_LINES]:
        parts = [f"{label} {group['value']}", f"{noun}={group['count']}", f"last_hour={group['last_hour']}", f"first={iso(group['first'])}", f"last={iso(group['last'])}"]
        if peer_label:
            parts.append(f"{peer_label}={top(group['peers'])}")
        parts += [f"{name}={top(group[field])}" for name, field in extra.items()]
        lines.append(" ".join(parts))
    if len(groups) > ENTITY_LINES:
        lines.append(f"{label} ... {len(groups) - ENTITY_LINES} more not listed")
    return lines


def enforcement(ask_optional, rows: list) -> tuple[list[str], set]:
    """(lines, identity values) for the busiest (source, destination) pairs: explain_access names the firewalls on the path
    (and on what basis), the rules SSDF saw governing the flows and the rules configured there. A pair SSDF cannot
    explain is said to be so; it does not stop the item."""
    pairs = Counter((clean(row.get("source_ip")), clean(row.get("destination_ip"))) for row in rows if row.get("source_ip") and row.get("destination_ip"))
    lines, values = [], set()
    for (source, destination), _ in pairs.most_common(ENFORCEMENT_PAIRS):
        reply, note = ask_optional("explain_access", {"client": source, "server": destination, "since_hours": 24})
        if reply is None:
            lines.append(f"ENFORCEMENT {source} -> {destination}: not available ({note})")
            continue
        firewalls = [clean(name) for name in reply.get("firewalls") or []]
        observed = sorted({clean(control.get("rule")) for control in reply.get("controls") or [] if isinstance(control, dict)} - {"-"})
        configured = [f"{clean(control.get('rule'))}({clean(control.get('action'), 12)})" for control in reply.get("configured_controls") or [] if isinstance(control, dict)]
        flows = reply.get("observed_flows") if isinstance(reply.get("observed_flows"), dict) else {}
        shown = configured[:CONFIGURED_SHOWN]
        lines.append(f"ENFORCEMENT {source} -> {destination}: firewalls={','.join(firewalls) or 'none found'} ({clean(reply.get('firewall_basis'), 24)})"
                     f" observed_rules={','.join(observed) or '-'} configured_rules={','.join(shown) or '-'}"
                     + (f" (+{len(configured) - len(shown)} more)" if len(configured) > len(shown) else "")
                     + f" sessions={clean(flows.get('sessions', '?'), 12)} detections={len(reply.get('detections') or [])} (last 24 h from now)")
        values |= {name.lower() for name in firewalls + observed if name != "-"}
        values |= {control.split("(")[0].lower() for control in shown}
    return lines, values


def capped(lines: list[str]) -> str:
    """The summary lines joined, cut at SUMMARY_CAP characters on a line boundary with a note saying so."""
    text = "\n".join(lines)
    if len(text) <= SUMMARY_CAP:
        return text
    cut = text[:SUMMARY_CAP].rsplit("\n", 1)[0]
    return cut + f"\n[summary cut at {len(cut)} characters: more in the data than shown]"


def fetch_item_data(item: dict, at: float, call=None, since: float | None = None) -> dict:
    """Code's own investigation of one item: {values, rows, summary, signals, calls}. `values` are the lowercased identity
    values of the SSDF data that concerns the item (what a cited entity must be among), `rows` counts the matching rows,
    `summary` is the capped text the model judges, `signals` the facts the rules floor reads, `calls` the (tool, arguments)
    code made. The window is the 24 h socbot looked at, ending at the queue's `at` as absolute times, not "now" (`until`
    where the tool takes it, else rows stamped after `at` are dropped); `since` is the queue's own window start, and
    without one (an older socbot) the window starts 24 h and QUERY_SLACK before `at`. `call(tool, arguments)` returns one
    raw reply; only grading.CODE_TOOLS may be called. A core query that fails raises; an enforcement lookup that fails is noted."""
    start = at - 24 * 3600 - QUERY_SLACK if since is None else since
    since_iso, until_iso, hour_start = iso(start), iso(at), at - LAST_HOUR
    call = call or (lambda tool, arguments: mcp_call_tools(SSDF_MCP, [(tool, arguments)])[0])
    made: list = []

    def ask(tool: str, arguments: dict) -> dict:
        if tool not in grading.CODE_TOOLS:
            raise ValueError(f"{tool} is not one of the tools code may call")
        made.append((tool, arguments))
        reply = call(tool, arguments)
        if not isinstance(reply, dict) or "error" in reply:
            detail = reply.get("detail", "") if isinstance(reply, dict) else reply
            raise RuntimeError(f"{tool}: {reply.get('error') if isinstance(reply, dict) else 'not an object'}: {str(detail)[:150]}")
        return reply

    def ask_optional(tool: str, arguments: dict):
        try:
            return ask(tool, arguments), ""
        except Exception as exc:
            return None, str(exc)[:80]

    kind, facts = item["kind"], item["facts"]
    lines = [f"ITEM {clean(item['id'], 40)} ({kind})", f"WINDOW {since_iso} .. {until_iso} (socbot's 24 h); LAST HOUR = after {iso(hour_start)}"]
    signals: dict = {}
    extra_values: set = set()
    if kind == "new-high-alert":
        replies = [ask("recent_alerts", {"since": since_iso, "min_severity": "medium", "providers": provider, "limit": ALERT_LIMIT}) for provider in ALERT_PROVIDERS]
        rows = grading.relevant_rows(kind, facts, replies, until=at)  # recent_alerts takes no `until`: rows after the queue was written are dropped by timestamp
        floor = any(reply.get("truncated") or len(reply.get("rows", [])) >= ALERT_LIMIT for reply in replies)
        total = tally(rows, "signature", hour_start)
        overall = total[0] if total else {"count": 0, "last_hour": 0, "first": None, "last": None}
        severities = Counter(clean(row.get("severity"), 12) for row in rows)
        signals = {"last_hour": overall["last_hour"], "total": overall["count"], "severity": severities.most_common(1)[0][0] if severities else clean(facts.get("severity"), 12)}
        lines += [f"ALERT signature={clean(facts.get('signature'))} observer={clean(facts.get('observer'))} severity={top(severities) if severities else '-'}",
                  f"TOTAL alerts={overall['count']} last_hour={overall['last_hour']} first={iso(overall['first'])} last={iso(overall['last'])}"
                  + (" (a reply hit its row limit: counts are a floor)" if floor else "")]
        lines += entity_lines("SRC", "alerts", tally(rows, "source_ip", hour_start, "destination_ip", ("destination_port",)), "dsts", {"ports": "destination_port"})
        lines += entity_lines("DST", "alerts", tally(rows, "destination_ip", hour_start, "source_ip", ("destination_port",)), "srcs", {"ports": "destination_port"})
        lines += entity_lines("ZONE", "alerts", tally([{**row, "zones": f"{clean(row.get('ingress_zone'))}>{clean(row.get('egress_zone'))}"} for row in rows], "zones", hour_start), "", {})
        enforcement_lines, extra_values = enforcement(ask_optional, rows)
        lines += enforcement_lines
    elif kind == "deny-spike":
        replies = [ask("query_flows", {"action": action, "since": since_iso, "until": until_iso, "limit": FLOW_LIMIT}) for action in DENY_ACTIONS]
        rows = grading.relevant_rows(kind, facts, replies, until=at)
        per_action = [f"{action}={len(reply.get('rows', []))}{'+' if reply.get('truncated') or len(reply.get('rows', [])) >= FLOW_LIMIT else ''}" for action, reply in zip(DENY_ACTIONS, replies)]
        floor = any(part.endswith("+") for part in per_action)
        overall = {"count": len(rows), "last_hour": sum(1 for row in rows if (grading.row_time(row) or 0) > hour_start)}
        stamps = [moment for row in rows if (moment := grading.row_time(row)) is not None]
        signals = {"last_hour": overall["last_hour"], "total": overall["count"]}
        lines += [f"TOTAL denied_flows={overall['count']} last_hour={overall['last_hour']} first={iso(min(stamps) if stamps else None)} last={iso(max(stamps) if stamps else None)}"
                  + (" (a reply hit its row limit: counts are a floor, the newest rows are kept)" if floor else ""),
                  f"ACTIONS {' '.join(per_action)}",
                  f"SOCBOT counted {clean(facts.get('denied_total'), 12)} denies, previous run {clean(facts.get('previous_total'), 12)}"]
        lines += entity_lines("SRC", "flows", tally(rows, "source_ip", hour_start, "destination_ip", ("destination_port", "rule_name")), "dsts", {"ports": "destination_port", "rules": "rule_name"})
        lines += entity_lines("DST", "flows", tally(rows, "destination_ip", hour_start, "source_ip", ("destination_port", "rule_name")), "srcs", {"ports": "destination_port", "rules": "rule_name"})
        lines += entity_lines("RULE", "flows", tally(rows, "rule_name", hour_start, "source_ip"), "srcs", {})
        lines += entity_lines("ZONE", "flows", tally([{**row, "zones": f"{clean(row.get('observer_ingress_zone'))}>{clean(row.get('observer_egress_zone'))}"} for row in rows], "zones", hour_start), "", {})
        enforcement_lines, extra_values = enforcement(ask_optional, rows)
        lines += enforcement_lines
    else:
        reply = ask("ingest_status", {})
        rows = grading.relevant_rows(kind, facts, [reply])
        fleet = reply.get("firewalls", [])
        summary = reply.get("summary") if isinstance(reply.get("summary"), dict) else {}
        lines.append(f"SOCBOT saw {clean(facts.get('firewall'))} quiet for {clean(facts.get('hours_since'), 12)} h, last event {clean(facts.get('last_event'), 40)}")
        for row in rows:
            lines.append(f"FIREWALL {clean(row.get('name'))} provider={clean(row.get('provider'), 24)} last_event={clean(row.get('last_event'), 40)}"
                         f" hours_since={clean(row.get('hours_since'), 12)} stale={'yes' if row.get('stale') else 'no'} (ingest_status snapshot at {iso(time.time())})")
        if not rows:
            lines.append(f"FIREWALL {clean(facts.get('firewall'))}: not in ingest_status now")
        lines.append(f"FLEET firewalls={clean(summary.get('total', len(fleet)), 8)} stale={clean(summary.get('stale', '?'), 8)} fresh={clean(summary.get('fresh', '?'), 8)}"
                     + (f" other stale: {','.join(clean(row.get('name'), 40) for row in fleet if isinstance(row, dict) and row.get('stale') and row.get('name') != facts.get('firewall'))[:300] or '-'}"))
        signals = {"still_stale": not rows or any(row.get("stale") for row in rows)}
    values: set = set(extra_values)
    for row in rows:
        values |= grading.identity_values(row)
    return {"values": values, "rows": len(rows), "summary": capped(lines), "signals": signals, "calls": made}


# --- the model judges ------------------------------------------------------------------------------------

def build_prompt(item: dict, summary: str) -> str:
    """The prompt with the item as JSON data and code's summary as text, each between tags ('<' escaped so neither can
    close a tag)."""
    data = json.dumps({"id": item["id"], "kind": item["kind"], "summary": item["summary"], "facts": item["facts"]}, indent=1).replace("<", "\\u003c")
    return (HERE / "prompt.md").read_text().strip().replace("<<ITEM>>", data).replace("<<EVIDENCE>>", summary.replace("<", "\\u003c"))


def build_request(item: dict, summary: str) -> dict:
    """The Ollama chat request: the local model, the prompt, the verdict schema as `format`, deterministic sampling, and
    NO `tools` key at all."""
    return {"model": MODEL, "think": False, "format": grading.verdict_schema(item["id"]),
            "options": {"temperature": 0, "seed": 0, "num_ctx": NUM_CTX},
            "messages": [{"role": "user", "content": build_prompt(item, summary)}]}


def investigate(item: dict, at: float, since: float | None = None) -> dict:
    """One item end to end (`at` and `since` are the queue's window): code gathers its data, the model judges it with no
    tools, code parses and verifies the verdict, applies the rules floor and grades the run. Returns the item's record.
    An unreachable SSDF server is "could not run" (no model run); a failed model call is graded as a failure."""
    record = {**item, "outcome": "running"}
    try:
        data = fetch_item_data(item, at, since=since)
    except Exception as exc:
        return {**record, "outcome": "could not run", "reason": f"SSDF did not answer ({type(exc).__name__}: {str(exc)[:200]})"}
    record.update(evidence_rows=data["rows"], evidence_summary=data["summary"], signals=data["signals"],
                  code_calls=[{"tool": tool, "arguments": arguments} for tool, arguments in data["calls"]])
    body = build_request(item, data["summary"])
    offered = agent.offered_tools(body)
    result = agent.run_ollama_judge(body, JUDGE_TIMEOUT, OLLAMA_URL)
    # nothing credential-looking reaches the state file: the stored copies are scrubbed, verifying and grading read the raw ones
    record.update(agent_status=result["status"], packet=agent.scrub_text(result["output"][:30000]), seconds=result["seconds"],
                  tools_offered=offered, tool_calls_asked=len(result["tool_calls"]))
    verdict, note = grading.parse_verdict(result["output"], item["id"])
    if verdict is not None:
        verdict = grading.verify(verdict, data["values"])
    record["reading"] = grading.apply_floor(verdict, grading.rules_floor(item["kind"], data["signals"], verdict))
    record["grade"] = grading.grade(offered, result["tool_calls"], verdict, note, result["status"])
    record.update(verdict=agent.scrub_json(verdict), verdict_note=note)
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
            queue = json.loads(QUEUE.read_text())
            queued_at = queue["at"]  # the window socbot looked at ends here
            # and starts at `since`; anything else there (an older socbot wrote none) falls back to the padded guess
            since = queue.get("since")
            queued_since = since if isinstance(since, (int, float)) and not isinstance(since, bool) and since < queued_at else None
            for item in items:
                try:
                    run["items"].append(investigate(item, queued_at, queued_since))
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
