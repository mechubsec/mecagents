"""bpcheckagent report (Monday 07:50): what Sunday night's collect found. A local model's best-practice audit of the
fixture `lab-vsrx`: the grade against the answer key derived from the device's own config (listed first, so a human can
check it), the findings whose cited rules really exist in the config (verified when the quoted evidence is in the config
too, else rule exists), those that do not (unverified, listed apart), and what changed since the previous run.
Model text is untrusted: defanged and length-capped, never interpreted. No advice section."""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
from agent import defang  # noqa: E402

STATE = Path(os.environ.get("BPCHECKAGENT_STATE", Path.home() / ".local/state/labbots/bpcheckagent.json"))
STALE_SECONDS = 20 * 3600
SHOWN = 8  # findings listed per group; the rest are counted


def finding_line(finding: dict) -> str:
    """One finding as the packet gave it: severity, check, the cited names, a capped excerpt."""
    severity = (finding.get("severity") or "?").upper()
    check = finding.get("check") or "no check"
    cites = ", ".join(finding["cites"]) or ("absent: no rule" if finding.get("status") == "absence" else "no rule cited")
    return f"[{severity}] {check} · {defang(cites, 80)} · {defang(finding['text'], 160)}"


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


def build_report(state: dict, now: float) -> str:
    """The finished report text."""
    run = state.get("run")
    if not run or now - run["at"] > STALE_SECONDS:
        return "**bpcheckagent**\n❓ no collect run in the last 20h: check `labbot@bpcheckagent.collect.service`"
    minutes = round(sum(run.get("phases", {}).values()) / 60)
    lines = [f"**bpcheckagent** ({datetime.fromtimestamp(run['at']):%d %b %H:%M}, {defang(run['model'], 60)}, {defang(run['device'], 30)}, {minutes} min)"]
    if not run.get("complete"):
        lines.append("⚠️ collect did not finish: " + ", ".join(f"{phase} {seconds}s" for phase, seconds in run.get("phases", {}).items()))
    if run.get("outcome") == "could not run":
        return "\n".join(lines + [f"❓ could not run: {defang(run.get('reason', 'unknown'), 300)}"])
    if run.get("outcome") != "graded":
        return "\n".join(lines)
    criteria = run["grade"]
    key = run.get("key", {})
    lines.append("Derived from the device config (code, not a model): must name " + (defang(", ".join(key.get("must_find", [])), 200) or "nothing")
                 + f"; {len(key.get('permits_without_log', []))} permit policies without logging; must not flag " + (defang(", ".join(key.get("must_not_flag", [])), 100) or "nothing"))
    lines.append(f"{'🟢 PASS' if run['passed'] else '🔴 FAIL'}: {sum(1 for _, ok, _ in criteria if ok)} of {len(criteria)} criteria")
    lines += [f"{'✅' if ok else '❌'} {name}" + (f": {defang(detail, 80)}" if detail and not ok else "") for name, ok, detail in criteria]
    names = sorted({call["tool"] for call in run.get("calls", [])})
    lines.append(f"Tool calls: {len(run.get('calls', []))} ({defang(', '.join(names), 100)})")
    findings = run.get("findings", [])
    if run.get("findings_source") != "structured":
        lines.append(f"⚠️ no valid structured findings block ({defang(run.get('findings_note') or 'not recorded', 80)}): no findings listed")
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
