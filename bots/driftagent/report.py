"""driftagent report (daily 07:55): posts only when the config drifted from the golden or the golden was just recorded
(otherwise an empty report, so nothing is posted), plus a problem notice when the collect is missing, unfinished or could
not run. Code's own diff summary comes first because it is certain; the model's reading follows, labelled as such, with
each change shown as verified, object touched, or unverified. Model text is untrusted: defanged and capped, never interpreted."""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
from agent import defang  # noqa: E402

STATE = Path(os.environ.get("DRIFTAGENT_STATE", Path.home() / ".local/state/labbots/driftagent.json"))
STALE_SECONDS = 20 * 3600
SHOWN = 8  # lines or changes listed per group; the rest are counted
GROUPS = (("verified", "Verified (object touched, evidence is a changed line)"),
          ("object touched", "Object touched, evidence is not a changed line"),
          ("unverified", "Unverified (names something the diff did not touch)"))


def diff_summary(diff: dict) -> list[str]:
    """Code's own facts: counts, touched objects by kind, and the changed lines (capped, defanged)."""
    kinds: dict[str, list[str]] = {}
    for name, kind in sorted(diff["objects"].items()):
        kinds.setdefault(kind, []).append(name)
    lines = [f"Certain (computed by code): {len(diff['added'])} lines added, {len(diff['removed'])} removed; "
             f"{len(diff['objects'])} objects touched"]
    lines += [f"- {kind}: {defang(', '.join(names), 200)}" for kind, names in kinds.items()]
    for sign, title in (("-", "removed"), ("+", "added")):
        changed = diff["removed" if sign == "-" else "added"]
        lines += [f"{sign} {defang(line, 160)}" for line in changed[:SHOWN]]
        lines += [f"{sign} … and {len(changed) - SHOWN} more {title}"] if len(changed) > SHOWN else []
    return lines


def reading(run: dict) -> list[str]:
    """The agent's reading, labelled as the model's: grade, then its changes grouped by verification level."""
    lines = ["The agent's reading (a local model's, checked only against the diff above):"]
    criteria = run.get("grade", [])
    lines.append(f"{'🟢 PASS' if run.get('passed') else '🔴 FAIL'}: {sum(1 for _, ok, _ in criteria if ok)} of {len(criteria)} criteria")
    lines += [f"{'✅' if ok else '❌'} {name}" + (f": {defang(detail, 80)}" if detail and not ok else "") for name, ok, detail in criteria]
    names = sorted({call["tool"] for call in run.get("calls", [])})
    lines.append(f"Tool calls: {len(run.get('calls', []))} ({defang(', '.join(names), 100)})")
    if run.get("changes_source") != "structured":
        lines.append(f"⚠️ no valid structured changes block ({defang(run.get('changes_note') or 'not recorded', 80)}): no reading listed")
    for status, title in GROUPS:
        group = [change for change in run.get("changes", []) if change["status"] == status]
        lines.append(f"{title}: " + ("none" if not group else f"{len(group)}"))
        lines += [f"- [{defang(change['risk'], 10).upper()}] {defang(change['object'], 60)} ({defang(change['kind'], 12)}) · "
                  f"{defang(change['effect'], 160)} · evidence: {defang(change['evidence'] or 'none', 120)}" for change in group[:SHOWN]]
        lines += [f"- … and {len(group) - SHOWN} more"] if len(group) > SHOWN else []
    return lines


def build_report(state: dict, now: float) -> str:
    """The finished report text, or "" when there is nothing to post (no drift)."""
    run = state.get("run")
    if not run or now - run["at"] > STALE_SECONDS:
        return "**driftagent**\n❓ no collect run in the last 20h: check `labbot@driftagent.collect.service`"
    outcome = run.get("outcome")
    if outcome == "no drift" and run.get("complete"):
        return ""
    minutes = round(sum(run.get("phases", {}).values()) / 60)
    lines = [f"**driftagent** ({datetime.fromtimestamp(run['at']):%d %b %H:%M}, {defang(run['model'], 60)}, {defang(run['device'], 30)}, {minutes} min)"]
    if not run.get("complete"):
        lines.append("⚠️ collect did not finish: " + ", ".join(f"{phase} {seconds}s" for phase, seconds in run.get("phases", {}).items()))
    if outcome == "golden recorded":
        return "\n".join(lines + [f"📌 golden recorded: {run.get('live_lines', '?')} lines saved as the baseline; no model run, nothing to compare yet"])
    if run.get("diff"):
        lines.append("🟠 DRIFT from the golden config")
        lines += diff_summary(run["diff"])
    if outcome == "could not run":
        return "\n".join(lines + [f"❓ could not run: {defang(run.get('reason', 'unknown'), 300)}"])
    if outcome != "graded":
        return "\n".join(lines)
    return "\n".join(lines + reading(run))


def main() -> int:
    """Print the report between the markers run_bot.py expects (empty when nothing is to be posted)."""
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    print("REPORT START")
    print(build_report(state, time.time()))
    print("REPORT END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
