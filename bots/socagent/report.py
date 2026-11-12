"""socagent report (daily 08:20): one block per item socbot escalated and the agent investigated. Posts nothing (an empty
report) when nothing was escalated; otherwise socbot's own facts come first because they are certain, then the agent's
verdict labelled as a local model's reading, its evidence with each cited entity marked seen or not seen in SSDF data
code fetched independently, the next step, and the criteria that failed. There is no answer key, so correctness is
never graded, and nothing here ever tells the reader that something is safe. Model text is untrusted: defanged and
capped, never interpreted. A problem notice is posted when the collect is missing, unfinished or could not run."""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
from agent import defang  # noqa: E402

STATE = Path(os.environ.get("SOCAGENT_STATE", Path.home() / ".local/state/labbots/socagent.json"))
STALE_SECONDS = 20 * 3600
SHOWN = 8  # evidence entries per item
READINGS = {"benign": "benign (unverified judgement)", "suspicious": "suspicious", "needs-human": "needs-human"}


def fact_lines(facts: dict) -> list[str]:
    """socbot's structured facts, one defanged `key: value` line each."""
    return [f"- {defang(key, 30)}: {defang(json.dumps(value) if not isinstance(value, str) else value, 160)}" for key, value in facts.items()]


def item_block(item: dict) -> list[str]:
    """The lines for one escalated item."""
    lines = [f"**{defang(item['id'], 40)}** · escalated by socbot: {defang(item['summary'], 200)}", "Certain (socbot's own facts):", *fact_lines(item["facts"])]
    if item.get("outcome") != "investigated":
        return lines + [f"❓ could not run: {defang(item.get('reason', 'unknown'), 300)}"]
    criteria, verdict = item.get("grade", []), item.get("verdict")
    failed = [f"{name}" + (f" ({defang(detail, 60)})" if detail else "") for name, ok, detail in criteria if not ok]
    lines.append(f"{'🟢 PASS' if item.get('passed') else '🔴 FAIL'}: {sum(1 for _, ok, _ in criteria if ok)} of {len(criteria)} criteria"
                 + (f"; failed: {'; '.join(failed)}" if failed else ""))
    names = sorted({call["tool"] for call in item.get("calls", [])})
    lines.append(f"Tool calls: {len(item.get('calls', []))} ({defang(', '.join(names), 100)})")
    if verdict is None:
        return lines + [f"⚠️ no valid verdict block ({defang(item.get('verdict_note') or 'not recorded', 80)}): no reading listed"]
    lines.append(f"Agent's reading: {READINGS[verdict['verdict']]}, confidence {verdict['confidence']} (a local model's, not a finding)")
    lines.append(defang(verdict["summary"], 400))
    if verdict["status"] == "unsupported":
        lines.append("⚠️ unsupported: none of the entities it cites appears in the SSDF data for this item")
    lines.append(f"Evidence: {verdict['seen']} entities seen, {verdict['not_seen']} not seen (seen = found in data code fetched itself: {item.get('evidence_rows', 0)} matching rows)")
    for entry in verdict["evidence"][:SHOWN]:
        marks = ", ".join(f"{defang(entity['entity'], 80)} {'seen' if entity['seen'] else 'not seen'}" for entity in entry["entities"]) or "no entities cited"
        lines.append(f"- [{defang(entry['tool'], 40)}] {defang(entry['fact'], 250)} · {marks}")
    lines.append(f"Next step (the model's suggestion): {defang(verdict['next_step'], 200)}")
    return lines + ["No answer key: correctness of the reading is not graded."]


def build_report(state: dict, now: float) -> str:
    """The finished report text, or "" when there is nothing to post (nothing escalated)."""
    run = state.get("run")
    if not run or now - run["at"] > STALE_SECONDS:
        return "**socagent**\n❓ no collect run in the last 20h: check `labbot@socagent.collect.service`"
    if run.get("outcome") == "nothing escalated" and run.get("complete"):
        return ""
    lines = [f"**socagent** ({datetime.fromtimestamp(run['at']):%d %b %H:%M}, {defang(run['model'], 60)}, {len(run.get('items', []))} item(s))"]
    if not run.get("complete"):
        lines.append("⚠️ collect did not finish")
    if run.get("outcome") == "could not run":
        return "\n".join(lines + [f"❓ could not run: {defang(run.get('reason', 'unknown'), 300)}"])
    for item in run.get("items", []):
        lines += ["", *item_block(item)]
    return "\n".join(lines)


def main() -> int:
    """Print the report between the markers run_bot.py expects (empty when nothing is to be posted)."""
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    print("REPORT START")
    print(build_report(state, time.time()))
    print("REPORT END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
