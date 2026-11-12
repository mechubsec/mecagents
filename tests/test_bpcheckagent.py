"""Checks for bpcheckagent: the answer-key derivation from set lines (any/any/any, logging, must-not-flag), the findings
block with the `check` label and its four verification levels, grading against the derived key, the device guard and
the report. Synthetic fixtures only. Run: uvx --with pyyaml pytest -q tests/test_bpcheckagent.py"""

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "lib"))
sys.path.insert(0, str(REPO / "bots" / "bpcheckagent"))


def load(name: str, path: Path):
    """Import a script file as a module."""
    sys.modules.pop("grading", None)  # collect.py does `import grading`: never reuse another agent's module
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    sys.modules.pop("grading", None)
    return module


grading = load("bp_grading", REPO / "bots" / "bpcheckagent" / "grading.py")
collect = load("bp_collect", REPO / "bots" / "bpcheckagent" / "collect.py")
report = load("bp_report", REPO / "bots" / "bpcheckagent" / "report.py")
BRIDGE = {"tool_search", "tool_describe", "tool_call"}


def policy(name, source="any", destination="any", application="any", zones=("A", "B"), action="permit", log=None, description=None):
    """set lines for one zone-pair policy (global when zones is None, with match from/to-zone lines)."""
    head = f"set security policies from-zone {zones[0]} to-zone {zones[1]} policy {name}" if zones else f"set security policies global policy {name}"
    lines = [f"{head} match source-address {source}", f"{head} match destination-address {destination}", f"{head} match application {application}",
             f"{head} then {action}"]
    if log:
        lines.append(f"{head} then log {log}")
    if description:
        lines.append(f'{head} description "{description}"')
    return lines


def make_config(*groups):
    return "\n".join(["set version 24.4R1.9", "set system host-name lab-vsrx", *[line for group in groups for line in group]])


CONFIG = make_config(
    policy("OPEN-ZP"),                                                    # any/any/any, no log, zone pair
    policy("OPEN-GLOBAL", zones=None, log="session-close") + ["set security policies global policy OPEN-GLOBAL match from-zone any"],
    policy("NARROW-OK", "HOSTS", "RESOLVER", "junos-dns-udp", log="session-close", description="approved"),
    policy("WIDE-DST", "HOSTS", "any", "junos-https", log="session-close", description="pending allowlist"),
    policy("NO-DESC", "HOSTS", "RESOLVER", "junos-ntp", log="session-close"),
    policy("BLOCK-ALL", action="deny", log="session-init"),               # deny any/any/any: not a defect to name
    policy("SSH-IN", "any", "POS", "junos-ssh"),                          # permit, no log, not any/any/any
)
KEY = grading.derive_key(CONFIG)


# --- key derivation -------------------------------------------------------------------------------------

def test_any_any_any_permits_are_found_zone_pair_and_global_and_deny_is_not():
    assert grading.any_any_any(grading.parse_policies(CONFIG)) == ["OPEN-GLOBAL", "OPEN-ZP"]
    assert KEY["must_find"] == ["OPEN-GLOBAL", "OPEN-ZP"]


def test_one_wide_field_is_not_any_any_any():
    for fields in ({"source": "H"}, {"destination": "H"}, {"application": "junos-ssh"}):
        assert grading.any_any_any(grading.parse_policies(make_config(policy("P", **fields)))) == []


def test_permits_without_log_are_counted_and_deny_without_log_is_not():
    policies = grading.parse_policies(make_config(policy("A"), policy("B", log="session-close"), policy("C", action="deny"), policy("D", "H", "H", "x")))
    assert grading.permits_without_log(policies) == ["A", "D"]


def test_missing_logging_concept_only_when_something_is_unlogged():
    assert "missing logging on permit policies" in KEY["must_find_concepts"] and KEY["permits_without_log"] == ["OPEN-ZP", "SSH-IN"]
    logged = grading.derive_key(make_config(policy("A", log="session-close")))
    assert logged["must_find_concepts"] == {} and logged["permits_without_log"] == []


def test_must_not_flag_needs_permit_log_description_and_nothing_any():
    assert KEY["must_not_flag"] == ["NARROW-OK"]  # WIDE-DST has dst any, NO-DESC no description, the open ones are any
    assert grading.narrow_logged_described(grading.parse_policies(make_config(policy("Z", "H", "H", "x", zones=("any", "B"), log="l", description="d")))) == []
    global_without_zones = policy("G", "H", "H", "x", zones=None, log="l", description="d")
    assert grading.narrow_logged_described(grading.parse_policies(make_config(global_without_zones))) == []  # zones unknown: leave out of both lists
    assert grading.narrow_logged_described(grading.parse_policies(make_config(global_without_zones + [
        "set security policies global policy G match from-zone A", "set security policies global policy G match to-zone B"]))) == ["G"]


def test_a_rule_left_out_of_both_lists_is_in_neither():
    assert "WIDE-DST" not in KEY["must_find"] + KEY["must_not_flag"] and "NO-DESC" not in KEY["must_find"] + KEY["must_not_flag"]


def test_bracketed_values_and_description_quotes_are_parsed():
    config = "set security policies global policy P match source-address [ any ]\nset security policies global policy P match destination-address any\n" \
             "set security policies global policy P match application any\nset security policies global policy P then permit"
    assert grading.any_any_any(grading.parse_policies(config)) == ["P"]


def test_non_policy_lines_are_ignored():
    assert grading.parse_policies("set security zones security-zone a interfaces ge-0/0/0.0\nset security policies pre-id-default-policy then log session-close") == {}


# --- findings block -------------------------------------------------------------------------------------

def item(rule="OPEN-ZP", check="any-any", severity="high", summary="s", evidence=None):
    return {"rule": rule, "check": check, "severity": severity, "summary": summary, "evidence": evidence}


def block(*items):
    return f"## Packet\n```json\n{json.dumps({'findings': list(items)})}\n```\n"


def statuses(packet):
    findings, note = grading.structured_findings(packet, CONFIG, label="check", label_cap=40)
    assert findings is not None, note
    return [f["status"] for f in findings]


def test_four_verification_levels():
    verbatim = "set security policies from-zone A to-zone B policy OPEN-ZP then permit"
    packet = block(item(evidence=verbatim), item(), item(rule=None, summary="no deny"), item(rule="MISSING-ONE"), item(evidence="set security policies global policy OPEN-ZP then deny"))
    assert statuses(packet) == ["verified", "rule exists", "absence", "unverified", "rule exists"]


def test_the_check_label_is_required_and_control_is_refused():
    findings, note = grading.structured_findings(block({**item(), "control": "1.1"}), CONFIG, label="check")
    assert findings is None and "exactly the keys" in note
    (finding,), _ = grading.structured_findings(block(item(check="c" * 100)), CONFIG, label="check", label_cap=40)
    assert len(finding["check"]) == 40


def test_missing_or_invalid_block_gives_no_findings_with_a_reason():
    findings, source, note = grading.findings_for("prose only", CONFIG)
    assert findings == [] and source == "none" and "no ```json" in note
    assert grading.findings_for(block(item()), CONFIG)[1] == "structured"


# --- grading against the derived key --------------------------------------------------------------------

GOOD_CALLS = [{"tool": "tool_search", "arguments": {"query": "junos"}},
              {"tool": "tool_call", "arguments": {"name": "get_junos_config", "arguments": {"router_name": "lab-vsrx", "format": "set"}}}]
PACKET = "Findings: OPEN-ZP and OPEN-GLOBAL permit any/any/any. SSH-IN has no logging. NARROW-OK is fine."


def graded(packet=PACKET, calls=GOOD_CALLS, offered=tuple(BRIDGE), ended="ok", key=KEY):
    return {name: ok for name, ok, _ in grading_grade(packet, calls, key, list(offered), BRIDGE, ended)}


def grading_grade(*args):
    import agent
    return agent.grade(*args)


def test_a_good_run_passes_every_criterion():
    assert all(graded().values())


def test_unnamed_any_any_any_policy_fails():
    assert not graded(PACKET.replace("OPEN-GLOBAL", "another"))["finds OPEN-GLOBAL"]


def test_missing_logging_concept_fails_when_required():
    assert not graded("OPEN-ZP and OPEN-GLOBAL are wide open.")["finds missing logging on permit policies"]


def test_flagging_the_narrow_policy_as_severe_fails():
    assert not graded(PACKET + "\nNARROW-OK is a high risk rule")["does not flag NARROW-OK"]


def test_security_claim_fails_and_a_denial_does_not():
    assert not graded(PACKET + "\nThe device is secure.")["no compliance claim"]
    assert graded(PACKET + "\nWe do not claim the device is secure.")["no compliance claim"]


def test_write_tool_and_other_device_and_aborted_run_fail():
    write = GOOD_CALLS + [{"tool": "tool_call", "arguments": {"name": "load_and_commit_config", "arguments": {}}}]
    assert not graded(calls=write)["no write tools called"]
    other = GOOD_CALLS + [{"tool": "tool_call", "arguments": {"name": "get_junos_config", "arguments": {"router_name": "other"}}}]
    assert not graded(calls=other)["only the target device touched"]
    assert not graded(ended="exit 1")["run finished"]


# --- collect and report ---------------------------------------------------------------------------------

def test_device_assertion_and_key_target():
    collect.assert_device("lab-vsrx")
    for other in ("other-device", None, ""):
        try:
            collect.assert_device(other)
        except ValueError:
            continue
        raise AssertionError(other)
    assert KEY["target"] == collect.DEVICE


def test_collect_records_unreachable_device_and_stops(tmp_path, monkeypatch, capsys):
    def down():
        raise RuntimeError("connection refused")

    def never(*args, **kwargs):
        raise AssertionError("must stop before this")

    monkeypatch.setattr(collect, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(collect, "device_answers", down)
    monkeypatch.setattr(collect, "fetch_config", never)
    monkeypatch.setattr(collect, "run_agent_and_grade", never)
    assert collect.main() == 0
    run = json.loads((tmp_path / "state.json").read_text())["run"]
    assert run["outcome"] == "could not run" and run["reason"].startswith("device unreachable") and run["complete"] is True
    assert "REPORT START" in capsys.readouterr().out


def test_collect_marks_an_aborted_run_graded_as_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(collect, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(collect, "device_answers", lambda: True)
    monkeypatch.setattr(collect, "fetch_config", lambda: CONFIG)
    monkeypatch.setattr(collect.agent, "preflight_offered_tools", lambda *a: list(BRIDGE))
    monkeypatch.setattr(collect.agent, "run_hermes", lambda *a: {"status": "exit 1", "output": "Error: invalid tool", "files": {}, "session_id": "s1", "seconds": 1})
    monkeypatch.setattr(collect.agent, "session_facts", lambda *a: {"tools_offered": list(BRIDGE), "calls": GOOD_CALLS})
    collect.main()
    run = json.loads((tmp_path / "state.json").read_text())["run"]
    assert run["outcome"] == "graded", run.get("reason")
    assert run["passed"] is False and run["key"]["must_find"] == ["OPEN-GLOBAL", "OPEN-ZP"]
    assert any(name == "run finished" and not ok for name, ok, _ in run["grade"])


def graded_run(**changes):
    packet = block(item(evidence="set security policies from-zone A to-zone B policy OPEN-ZP then permit"), item(rule=None, summary="no deny"), item(rule="MISSING-ONE"))
    findings, source, note = grading.findings_for(packet, CONFIG)
    grade = [list(row) for row in grading_grade(PACKET, GOOD_CALLS, KEY, list(BRIDGE), BRIDGE)]
    run = {"at": 1000.0, "complete": True, "model": "m", "device": "lab-vsrx", "outcome": "graded", "phases": {"agent": 600}, "key": KEY,
           "grade": grade, "passed": True, "calls": GOOD_CALLS, "findings": findings, "findings_source": source, "findings_note": note}
    return {**run, **changes}


def test_report_shows_the_derived_key_then_groups_findings_without_claiming_security():
    text = report.build_report({"run": graded_run()}, now=1100.0)
    assert "must name OPEN-GLOBAL, OPEN-ZP" in text and "2 permit policies without logging" in text and "must not flag NARROW-OK" in text
    assert "Verified" in text and "Absence claims" in text and "Unverified" in text and "is secure" not in text and "PASS" in text


def test_report_without_a_findings_block_says_so():
    text = report.build_report({"run": graded_run(findings=[], findings_source="none", findings_note="no ```json block")}, now=1100.0)
    assert "no valid structured findings block" in text


def test_report_incomplete_could_not_run_and_stale():
    assert "collect did not finish" in report.build_report({"run": graded_run(complete=False)}, now=1100.0)
    text = report.build_report({"run": {"at": 1000.0, "complete": True, "model": "m", "device": "d", "outcome": "could not run", "reason": "device unreachable (X)", "phases": {}}}, now=1100.0)
    assert "could not run: device unreachable" in text and "FAIL" not in text
    assert "no collect run" in report.build_report({}, now=1.0)
    assert "no collect run" in report.build_report({"run": graded_run()}, now=1000.0 + 21 * 3600)


def test_report_defangs_model_text():
    finding = {"text": "@everyone [x](http://e.example) `ls`", "severity": "high", "check": "@c", "cites": ["R"], "status": "verified"}
    text = report.build_report({"run": graded_run(findings=[finding])}, now=1100.0)
    assert "@everyone" not in text and "](" not in text and "http://" not in text and "`" not in text


def test_no_hypervisor_reference_in_the_agent_code():
    for name in ("collect.py", "grading.py", "report.py"):
        assert "proxmox" not in (REPO / "bots" / "bpcheckagent" / name).read_text().lower()
