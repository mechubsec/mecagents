"""Checks for the shared agent module (lib/agent.py): no Proxmox or fixture power helpers, defanging, recorded runs,
offered-tool assertion. Run: uvx --with pyyaml pytest -q tests/test_agent.py"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import agent  # noqa: E402


def test_module_has_no_proxmox_or_power_path():
    for name in ("start_fixture", "stop_fixture", "check_fixture", "assert_fixture", "guest_status", "power_call",
                 "wait_until", "FixtureRefused", "PROXMOX_MCP", "mcp_call_tools"):
        assert not hasattr(agent, name), name


def test_offered_tools_must_be_only_the_bridge():
    agent.assert_offered_tools(["tool_search", "tool_describe", "tool_call"])
    for bad in (["tool_search", "terminal"], ["write_file"], ["skill_manage"], []):
        with pytest.raises(ValueError):
            agent.assert_offered_tools(bad)


def test_defang_makes_model_text_inert():
    text = "@everyone [click](http://evil.example) `rm -rf` **bold**\nline2 \x1b[31m this is PCI compliant " + "x" * 500
    out = agent.defang(text, cap=120)
    assert "@everyone" not in out and "](" not in out and "http://" not in out and "`" not in out and "*" not in out
    assert "\n" not in out and "\x1b" not in out and "PCI compliant" not in out.replace("[phrase removed]", "")
    assert len(out) <= 120 and out.endswith("…")


def test_defang_removes_the_forbidden_phrase_in_every_spelling():
    for phrase in ("PCI compliant", "pci-compliant", "Pci   Compliant"):
        assert "compliant" not in agent.defang(f"the network is {phrase} today")


def test_recorded_run_is_complete_only_when_the_block_finishes(tmp_path, monkeypatch):
    state = tmp_path / "x.json"
    with agent.recorded_run(state, model="m") as (run, save):
        assert json.loads(state.read_text())["run"]["complete"] is False
        run["outcome"] = "graded"
        save()
        assert json.loads(state.read_text())["run"]["complete"] is False
    assert json.loads(state.read_text())["run"]["complete"] is True
    with pytest.raises(RuntimeError):
        with agent.recorded_run(state, model="m") as (run, save):
            raise RuntimeError("killed halfway")
    assert json.loads(state.read_text())["run"]["complete"] is False


def test_recorded_run_keeps_yesterday_as_previous(tmp_path):
    state = tmp_path / "x.json"
    state.write_text(json.dumps({"run": {"at": 1, "day": "2020-01-01", "complete": True, "marker": "old"}}))
    with agent.recorded_run(state):
        pass
    saved = json.loads(state.read_text())
    assert saved["previous"]["marker"] == "old" and "marker" not in saved["run"]


def test_run_hermes_parses_session_and_timeout():
    class Done:
        returncode, stdout, stderr = 0, "the packet\n", "\nsession_id: local-abc123\n"

    result = agent.run_hermes("p", "m", "s", "prompt", 10, runner=lambda *a, **k: Done())
    assert result["status"] == "ok" and result["session_id"] == "local-abc123" and result["output"] == "the packet"

    class Timed(Done):
        returncode = 124

    assert agent.run_hermes("p", "m", "s", "prompt", 10, runner=lambda *a, **k: Timed())["status"] == "timeout"


# --- shared findings-block parser and grading (moved here from pcicomplyagent, reused by bpcheckagent and driftagent) ---

KEYS, CAPS = ("name", "level", "note"), {"name": 5, "level": 10, "note": 10}


def parsed(body, **kwargs):
    options = {"list_key": "things", "noun": "thing", "keys": KEYS, "enums": {"level": {"a", "b"}}, "caps": CAPS, **kwargs}
    return agent.strict_json_items(f"x\n```json\n{body}\n```", **options)


def test_strict_json_items_accepts_caps_lowercases_and_allows_declared_nulls():
    items, note = parsed(json.dumps({"things": [{"name": "toolong", "level": "A", "note": None}]}), nullable=("note",))
    assert note == "" and items == [{"name": "toolo", "level": "a", "note": None}]


def test_strict_json_items_refuses_each_malformation_with_a_reason():
    good = {"name": "n", "level": "a", "note": "x"}
    for body, reason in [("{bad", "invalid JSON"), ("[1]", "`things` list"), ('{"other": []}', "`things` list"),
                         (json.dumps({"things": [{"name": "n"}]}), "thing 1 does not have exactly the keys"),
                         (json.dumps({"things": ["s"]}), "exactly the keys"), (json.dumps({"things": [{**good, "level": "z"}]}), "thing 1 has level 'z'"),
                         (json.dumps({"things": [{**good, "note": None}]}), "wrong type"), (json.dumps({"things": [{**good, "name": 3}]}), "wrong type")]:
        items, note = parsed(body)
        assert items is None and reason in note
    assert agent.strict_json_items("no block", "things", "thing", KEYS, {}, CAPS)[1] == "no ```json block"


def test_strict_json_items_takes_the_last_block_and_at_most_max_items():
    packet = '```json\n{"things": []}\n```\ntext\n```json\n' + json.dumps({"things": [{"name": "n", "level": "a", "note": "x"}] * 50}) + "\n```"
    items, _ = agent.strict_json_items(packet, "things", "thing", KEYS, {"level": {"a"}}, CAPS)
    assert len(items) == agent.MAX_ITEMS


def test_structured_findings_label_decides_the_required_key():
    config = "set security policies global policy P then permit"
    finding = {"rule": "P", "check": "c", "severity": "HIGH", "summary": "s", "evidence": "set security policies global policy P then permit"}
    packet = lambda item: f"```json\n{json.dumps({'findings': [item]})}\n```"
    (verified,), _ = agent.structured_findings(packet(finding), config, label="check")
    assert verified["status"] == "verified" and verified["check"] == "c" and verified["severity"] == "high"
    assert agent.structured_findings(packet(finding), config)[0] is None  # default label is `control`
    assert agent.structured_findings(packet({**finding, "rule": "Q"}), config, label="check")[0][0]["status"] == "unverified"


def test_scrub_config_and_grade_run_finished_criterion():
    assert agent.scrub_config("set a b\nset system root-authentication encrypted-password x") == "set a b"
    key = {"target": "d", "must_find": [], "must_find_concepts": {}, "soft": [], "must_not_flag": [], "forbidden_phrases": [], "read_tools": ["get_junos_config"]}
    call = {"tool": "tool_call", "arguments": {"name": "get_junos_config", "arguments": {"device": "d"}}}
    assert all(ok for _, ok, _ in agent.grade("p", [call], key, ["tool_call"], agent.BRIDGE_TOOLS))
    assert ("run finished", False) == agent.grade("p", [call], key, ["tool_call"], agent.BRIDGE_TOOLS, "timeout")[-1][:2]
