"""pcicomplyagent report (Monday 07:45): what Sunday night's collect found. A local model's PCI evidence review of the
fixture `lab-vsrx`: first what code itself found in the config (the certain part), then the agent's grade against the
key derived from that config, the findings whose cited rules really exist in the device's config (verified when the
quoted evidence is in the config too, else listed as rule exists), those that do not (unverified, listed apart), and
what changed since the previous run. A run started by a commit leads with what that commit changed, written by code.
Model text is untrusted: defanged and length-capped, never interpreted. No advice section."""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
from agent import defang  # noqa: E402

STATE = Path(os.environ.get("PCICOMPLYAGENT_STATE", Path.home() / ".local/state/labbots/pcicomplyagent.json"))
STALE_SECONDS = 20 * 3600
SHOWN = 8  # findings listed per group; the rest are counted


def finding_line(finding: dict) -> str:
    """One finding as the packet gave it: severity, control, the cited names, a capped excerpt."""
    severity = (finding.get("severity") or "?").upper()
    control = finding.get("control") or "no valid control"
    cites = ", ".join(finding["cites"]) or ("absent: no rule" if finding.get("status") == "absence" else "no rule cited")
    return f"[{severity}] {control} · {defang(cites, 80)} · {defang(finding['text'], 160)}"


def finding_group(title: str, findings: list[dict]) -> list[str]:
    """A titled list of findings, capped at SHOWN."""
    if not findings:
        return [f"{title}: none"]
    lines = [f"{title} ({len(findings)}):"] + [f"- {finding_line(finding)}" for finding in findings[:SHOWN]]
    return lines + ([f"- … and {len(findings) - SHOWN} more"] if len(findings) > SHOWN else [])


def verified_rules(run: dict) -> set[str]:
    """Names cited by verified findings: what 'the same finding' means between two runs."""
    return {cite for finding in run.get("findings", []) if finding["status"] == "verified" for cite in finding["cites"]}


def changes(run: dict, previous: dict | None) -> list[str]:
    """What differs from the previous graded run: grade, newly verified rules, rules no longer reported."""
    if not previous or previous.get("outcome") != "graded":
        return ["📚 no earlier graded run to compare"]
    lines = []
    if run.get("passed") != previous.get("passed"):
        lines.append(f"🔁 grade changed: {'PASS' if previous.get('passed') else 'FAIL'} → {'PASS' if run.get('passed') else 'FAIL'}")
    now, before = verified_rules(run), verified_rules(previous)
    if now - before:
        lines.append("🆕 newly verified: " + defang(", ".join(sorted(now - before)), 200))
    if before - now:
        lines.append("➖ no longer reported: " + defang(", ".join(sorted(before - now)), 200))
    return lines or ["No change since the previous run."]


def plural(count: int, noun: str) -> str:
    """'1 rule-level problem', '2 rule-level problems'."""
    return f"{count} {noun}{'' if count == 1 else 's'}"


def commit_lines(run: dict) -> list[str]:
    """The triggered run's certain part, from code only: the commit, what it changed, and each policy it added or changed
    that code flags. Empty for a run that was not triggered."""
    commit = run.get("commit")
    if run.get("trigger") != "commit" or not commit:
        return []
    note = commit.get("note") or {}
    when = datetime.fromtimestamp(note.get("at") or run["at"]).strftime("%d %b %H:%M")
    by = f" by {defang(note['user'], 32)} (as the device reported it)" if note.get("user") else ""
    lines = [f"⚡ commit on {defang(run['device'], 30)} at {when}{by}"]
    if commit.get("source") == "none":
        return lines + [f"❓ could not determine what this commit changed: {defang(commit.get('reason', 'unknown'), 200)}"]
    parts = [f"{label} {defang(', '.join(commit[field]), 200)}" for label, field in (("added", "added"), ("removed", "removed"), ("changed", "changed")) if commit.get(field)]
    other = f"; {plural(commit.get('other_lines', 0), 'other config line')} changed" if commit.get("other_lines") else ""
    lines.append(f"Changed (from the {commit['source']}): " + ("; ".join(parts) or "no security policy") + other)
    flags = commit.get("flags", {})
    for name, reasons in flags.items():
        verb = "added" if name in commit.get("added", []) else "changed"
        lines.append(f"🔴 this commit {verb} {defang(name, 80)}: {defang(', '.join(reasons), 160)}")
    return lines + ([] if flags else ["🟢 this commit added nothing code considers a PCI rule problem"])


def key_lines(run: dict) -> list[str]:
    """What code found in the config (the derived key's problems): the certain part of the report."""
    key = run.get("key")
    if not key:
        return []
    problems = key.get("problems", [])
    return [f"{'🔴' if problems else '🟢'} code found {plural(len(problems), 'rule-level problem')}" + (":" if problems else "")] + \
        [f"- {defang(problem['rule'] or 'default deny', 80)}: {defang(problem['why'], 160)}" for problem in problems[:SHOWN]]


def build_report(state: dict, now: float) -> str:
    """The finished report text."""
    run = state.get("run")
    if not run or now - run["at"] > STALE_SECONDS:
        return "**pcicomplyagent**\n❓ no collect run in the last 20h: check `labbot@pcicomplyagent.collect.service`"
    minutes = round(sum(run.get("phases", {}).values()) / 60)
    lines = [f"**pcicomplyagent** ({datetime.fromtimestamp(run['at']):%d %b %H:%M}, {defang(run['model'], 60)}, {defang(run['device'], 30)}, {minutes} min)"]
    if not run.get("complete"):
        lines.append("⚠️ collect did not finish: " + ", ".join(f"{phase} {seconds}s" for phase, seconds in run.get("phases", {}).items()))
    lines += commit_lines(run)  # a triggered run always posts: this part is certain whatever the agent did
    if run.get("outcome") == "could not run":
        return "\n".join(lines + [f"❓ could not run: {defang(run.get('reason', 'unknown'), 300)}"])
    if run.get("outcome") != "graded":
        return "\n".join(lines)
    criteria = run["grade"]
    problems = (run.get("key") or {}).get("problems")
    if run.get("key") and not problems and run["passed"]:  # never "compliant": code found nothing at rule level, and the agent agrees
        lines.append("🟢 clean: no rule-level PCI problems found by code; agent agrees")
        lines.append(f"{sum(1 for _, ok, _ in criteria if ok)} of {len(criteria)} criteria, graded {defang(run.get('grade_basis') or 'not recorded', 60)}")
    else:
        lines += key_lines(run)
        basis = f", graded {defang(run['grade_basis'], 60)}" if run.get("grade_basis") else ""
        lines.append(f"Agent against that key{basis}: {'🟢 PASS' if run['passed'] else '🔴 FAIL'}, {sum(1 for _, ok, _ in criteria if ok)} of {len(criteria)} criteria")
    lines += [f"{'✅' if ok else '❌'} {name}" + (f": {defang(detail, 80)}" if detail and not ok else "") for name, ok, detail in criteria]
    names = sorted({call["tool"] for call in run.get("calls", [])})
    lines.append(f"Tool calls: {len(run.get('calls', []))} ({defang(', '.join(names), 100)})")
    findings = run.get("findings", [])
    if run.get("findings_source") != "structured":
        lines.append(f"⚠️ no structured findings block ({defang(run.get('findings_note') or 'not recorded', 80)}): "
                     "the findings below are a heuristic reading of the packet text")
    by_status = {status: [f for f in findings if f["status"] == status] for status in ("verified", "rule exists", "absence", "unverified")}
    lines += finding_group("Verified (the rule exists in the device config)", by_status["verified"])
    lines += finding_group("Rule exists on the device, quoted evidence not found verbatim", by_status["rule exists"])
    lines += finding_group("Absence claims, not checkable by rule name", by_status["absence"])
    lines += finding_group("Unverified (names a rule the device does not have, or nothing checkable)", by_status["unverified"])
    return "\n".join(lines + changes(run, state.get("previous")))


def main() -> int:
    """Print the report between the markers run_bot.py expects."""
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    print("REPORT START")
    print(build_report(state, time.time()))
    print("REPORT END")
    return 0


if __name__ == "__main__":
    sys.exit(main())
