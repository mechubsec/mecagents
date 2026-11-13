"""Grading for pcicomplyagent: the packet's findings, checked against evidence fetched independently, and the run
graded against an answer key DERIVED BY CODE from the device's own config (derive_key), so a clean device grades as
clean and a flawed one is graded on the flaws it really has. answer-key.json only adds optional extras.

The shared parts (score_text, score_calls, grade, scrub_config, the strict findings-block parser) live in
lib/agent.py and are re-exported here; what stays is PCI-specific: reading `set` policy lines (a deactivated policy is
not in force), the derived key, what a commit changed (from the device's rollback-1 diff, or from the previous run's
policy lines), and the heuristic reading of a packet that has no findings block. All functions are pure."""

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
from agent import (DEVICE_KEYS, JUNOS_WRITE_TOOLS, MAX_ITEMS as MAX_FINDINGS, SECRET_LINE, SEVERITIES,  # noqa: E402,F401
                   config_tokens, grade, is_mentioned, scrub_config, score_calls, score_text, structured_findings, underlying_calls)

DEVICE = os.environ.get("PCICOMPLYAGENT_DEVICE", "lab-vsrx")  # placeholder: name of your target device in the Junos MCP server
READ_TOOLS = ["get_device_list", "get_router_list", "gather_device_facts", "get_junos_config", "junos_config_diff"]
# zone names, overridable by env (comma separated): where untrusted traffic comes from, and the cardholder data zone
UNTRUST_ZONES = tuple(os.environ.get("PCICOMPLYAGENT_UNTRUST_ZONES", "untrust").split(","))
CDE_ZONES = tuple(os.environ.get("PCICOMPLYAGENT_CDE_ZONES", "CDE").split(","))
CONTROL_NUMBER = re.compile(r"^\d{1,2}(\.\d{1,2}){0,3}$")  # a PCI DSS requirement number: 1, 1.3, 1.3.2, 10.2.1.1
MAX_NAMES = 30
SEVERITY = re.compile(r"\b(critical|high|medium|low)\b", re.I)
# a PCI DSS requirement number like 1.3.1; not part of an IP address or a version ("v4.0.1", "4.0.1")
CONTROL = re.compile(r"(?<![\w./])(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)(?![\w/]|\.\d)")
LIST_ITEM = re.compile(r"(?:[-*\u2022]|\d+[.)])\s")
CITE_BACKTICKED = re.compile(r"`([^`\s]{2,60})`")
CITE_CAPS = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\b")
CITE_AFTER_KEYWORD = re.compile(r"\b(?:policy|rule|term)\s+[`'\"]?([A-Za-z][\w]*[-_][\w-]*\w)")
# "| **High** | 2 | F02, F03 |": a severity cell followed by a count (or nothing); "| High | CDE-ANY-OUT is open | 1.3.2 |" is a finding
SUMMARY_ROW = re.compile(r"\|\s*\W*(critical|high|medium|low)\W*\s*\|\s*(?:\d+(?:\s+findings?)?|[-\u2013\u2014]?)\s*\|", re.I)
SECURITY_POLICY_NAME = re.compile(r"^set security policies (?:from-zone \S+ to-zone \S+|global) policy (\S+)", re.M)
POLICY_LINE = re.compile(r"^(set|deactivate) security policies (?:from-zone (\S+) to-zone (\S+)|global) policy (\S+)(?: (.+))?$")


def policy_names(config_text: str) -> set[str]:
    """The security policy names in a set-format config: only what `set security policies ... policy <name>` defines."""
    return set(SECURITY_POLICY_NAME.findall(config_text))


def cited_names(line: str, known_policies: set[str]) -> list[str]:
    """What a finding line points at in the config: backticked words, ALL-CAPS-HYPHEN names, the name after
    'policy'/'rule'/'term', and any real policy name present as a whole word. Sorted, without trailing punctuation."""
    cites = set(CITE_BACKTICKED.findall(line)) | set(CITE_CAPS.findall(line)) | set(CITE_AFTER_KEYWORD.findall(line))
    cites |= {name for name in known_policies if re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", line)}
    return sorted(cite.strip(".,;:()") for cite in cites if cite.strip(".,;:()"))


def extract_findings(packet: str, config_text: str) -> list[dict]:
    """The packet's findings: every table row or list item that carries a severity (a PCI requirement number is kept when given).
    Each is {text, severity, control, cites}. Rows citing the same set of names count once (the packet repeats a
    finding in its remediation list); header and separator rows carry neither field and are skipped."""
    known = policy_names(config_text)
    findings, seen = [], set()
    for raw in packet.splitlines():
        line = raw.strip()
        is_row = line.startswith("|") and not re.fullmatch(r"[|\s:\-]+", line)
        if not (is_row or LIST_ITEM.match(line)):
            continue
        severity = SEVERITY.search(line)
        control = next((value for value in CONTROL.findall(line) if value != "4.0.1"), None)
        if not severity or SUMMARY_ROW.match(line):  # a finding is rated; a requirement checklist row is not
            continue
        cites = cited_names(line, known)
        key = tuple(cites) or line
        if key in seen:
            continue
        seen.add(key)
        findings.append({"text": line, "severity": severity.group(1).lower() if severity else None, "control": control, "cites": cites})
    return findings


def verify_findings(findings: list[dict], config_text: str) -> list[dict]:
    """Heuristic findings with `status` and `why`: verified only when the finding cites at least one name and every
    name it cites is in the independently fetched config; otherwise unverified (nothing checkable, or a name the
    device lacks). Used only when the packet has no valid structured block."""
    tokens = config_tokens(config_text)
    checked = []
    for finding in findings:
        missing = [cite for cite in finding["cites"] if cite not in tokens]
        if not finding["cites"]:
            status, why = "unverified", "cites no object that can be checked in the config"
        elif missing:
            status, why = "unverified", "not in the device config: " + ", ".join(missing)
        else:
            status, why = "verified", "every cited name is in the device config"
        checked.append({**finding, "status": status, "why": why})
    return checked


def findings_for(packet: str, config_text: str) -> tuple[list[dict], str, str]:
    """(findings, source, note): the structured block's findings (source "structured") or, when that is missing or
    invalid, the heuristic reading of the text (source "heuristic", note = why the block was not used).
    A structured finding's `rule` must be a security policy name defined in the config, else it is unverified (a
    quoted word such as "permit" is in the config but is not a rule), and a `control` that is not a requirement
    number becomes None ("no valid control")."""
    structured, note = structured_findings(packet, config_text)
    if structured is None:
        return verify_findings(extract_findings(packet, config_text), config_text), "heuristic", note
    names = policy_names(config_text)
    for finding in structured:
        if finding["rule"] is not None and finding["rule"] not in names:
            finding.update(status="unverified", why=f"rule {finding['rule']!r} is not a security policy in the device config")
        if not CONTROL_NUMBER.match(finding["control"]):
            finding["control"] = None
    return structured, "structured", ""


# --- policies in force, the derived answer key, and what a commit changed ---------------------------------------

def parse_policies(config_text: str) -> dict[tuple[str, str], dict]:
    """{(scope, name): facts} for every security policy in a set-format config; scope is "global" or "from>to".
    facts: source, destination, application, from_zones, to_zones (sets), permit, deny, log, described, active (bools).
    A `deactivate` line on the policy makes it inactive (not in force); on its `then permit`/`then log`/`description`
    it removes that statement. Shortcut: other deactivated statements and bracketed-list order are not interpreted."""
    policies: dict[tuple[str, str], dict] = {}
    for raw in config_text.splitlines():
        found = POLICY_LINE.match(raw.strip())
        if not found:
            continue
        verb, from_zone, to_zone, name, rest = found.groups()
        facts = policies.setdefault((f"{from_zone}>{to_zone}" if from_zone else "global", name), {
            "source": set(), "destination": set(), "application": set(), "from_zones": {from_zone} if from_zone else set(),
            "to_zones": {to_zone} if to_zone else set(), "permit": False, "deny": False, "log": False, "described": False, "active": True})
        words = (rest or "").replace("[", " ").replace("]", " ").replace('"', "").split()
        flag = verb == "set"
        if not words:
            facts["active"] = flag
        elif words[:2] == ["match", "source-address"] and flag:
            facts["source"].update(words[2:])
        elif words[:2] == ["match", "destination-address"] and flag:
            facts["destination"].update(words[2:])
        elif words[:2] == ["match", "application"] and flag:
            facts["application"].update(words[2:])
        elif words[:2] == ["match", "from-zone"] and flag:
            facts["from_zones"].update(words[2:])
        elif words[:2] == ["match", "to-zone"] and flag:
            facts["to_zones"].update(words[2:])
        elif words[:2] == ["then", "permit"]:
            facts["permit"] = flag
        elif words[:2] in (["then", "deny"], ["then", "reject"]):
            facts["deny"] = flag
        elif words[:2] == ["then", "log"]:
            facts["log"] = flag
        elif words[0] == "description":
            facts["described"] = flag
    return policies


def is_any_any_any(facts: dict) -> bool:
    """True when source, destination and application are all `any`."""
    return all("any" in facts[field] for field in ("source", "destination", "application"))


def untrust_into_cde(facts: dict) -> bool:
    """True when the policy runs from an untrusted zone into the cardholder zone."""
    return bool(facts["from_zones"] & set(UNTRUST_ZONES)) and bool(facts["to_zones"] & set(CDE_ZONES))


def policy_problems(facts: dict) -> list[str]:
    """Why an ACTIVE permit policy is a PCI rule-level problem on its own: any/any/any, or untrusted into the CDE with
    source any (the derived key's must-find rules). [] for a deny, an inactive policy or a clean permit."""
    if not (facts["active"] and facts["permit"]):
        return []
    reasons = ["permit any/any/any"] if is_any_any_any(facts) else []
    if untrust_into_cde(facts) and "any" in facts["source"]:
        reasons.append("untrusted zone into the cardholder zone, source any")
    return reasons


def narrow_logged_described(policies: dict) -> list[str]:
    """Names of active permit policies that are narrow (no `any` in source, destination or application, all given),
    described and logged: the agent must not rate these medium or higher. Sorted."""
    def narrow(facts: dict) -> bool:
        return all(facts[field] and "any" not in facts[field] for field in ("source", "destination", "application"))
    return sorted({name for (_, name), facts in policies.items()
                   if facts["active"] and facts["permit"] and facts["log"] and facts["described"] and narrow(facts)})


def has_logged_deny_all(policies: dict) -> bool:
    """True when an active deny policy matching any/any/any logs."""
    return any(facts["active"] and facts["deny"] and facts["log"] and is_any_any_any(facts) for facts in policies.values())


NO_DENY_PHRASES = ["default-deny", "default deny", "deny-all", "deny all", "explicit deny", "implicit deny"]
NO_DENY_CONCEPT = "no logged default deny"


def derive_key(config_text: str, extra: dict | None = None) -> dict:
    """The answer key for this config, in the shape lib/agent.py's score_text/grade take, plus `problems` (what code
    itself found, [{rule, why}]; rule None for the missing logged deny). `extra` is the optional answer-key.json:
    its must_find, concepts, soft, must_not_flag and forbidden_phrases are added to what the config yields."""
    extra = extra or {}
    policies = parse_policies(config_text)
    problems = {}
    for (_, name), facts in sorted(policies.items(), key=lambda item: item[0][1]):
        reasons = policy_problems(facts)
        if reasons:
            problems.setdefault(name, []).extend(reason for reason in reasons if reason not in problems.get(name, []))
    concepts = {} if has_logged_deny_all(policies) else {NO_DENY_CONCEPT: NO_DENY_PHRASES}
    listed = [{"rule": name, "why": "; ".join(why)} for name, why in problems.items()]
    if concepts:
        listed.append({"rule": None, "why": "no active deny-all policy that logs"})
    return {"target": extra.get("target", DEVICE), "derived_from": "the fetched config", "read_tools": READ_TOOLS,
            "must_find": sorted(set(problems) | set(extra.get("must_find", []))),
            "must_find_concepts": {**concepts, **extra.get("must_find_concepts", {})},
            "soft": list(extra.get("soft", [])),
            "must_not_flag": sorted(set(narrow_logged_described(policies)) | set(extra.get("must_not_flag", []))),
            "forbidden_phrases": list(extra.get("forbidden_phrases", [])), "problems": listed}


def load_extra_key(path: Path) -> dict:
    """The optional answer-key.json extras ({} when absent)."""
    return json.loads(path.read_text()) if path.exists() else {}


def policy_lines(config_text: str) -> list[str]:
    """The `set`/`deactivate` security policy lines of a config: what a run keeps for the next one's comparison."""
    return [line.strip() for line in config_text.splitlines() if POLICY_LINE.match(line.strip())]


def _unique(names: list[str]) -> list[str]:
    """Names in order without repeats, capped (device text is untrusted)."""
    return list(dict.fromkeys(name[:80] for name in names))[:MAX_NAMES]


def changes_from_diff(diff_text: str) -> dict:
    """{added, removed, changed, other_lines} policy names from the compare-format diff of `junos_config_diff`
    (`[edit ...]` headers, `+`/`-` lines, `!` for activate/deactivate). A `+`/`-  policy NAME {` line is an added or
    removed policy; any other changed line under a `... policy NAME` header, or an inactive/active marker, is a change to
    NAME; a name added and removed is changed; other_lines counts changed lines outside security policies.
    Shortcut: a change printed with no policy name in its header (e.g. policy order) is not attributed."""
    added, removed, changed, other, path = [], [], [], 0, ""
    for raw in diff_text.splitlines():
        line = raw.rstrip()
        if line.startswith("[edit"):
            path = line.strip()[len("[edit"):-1].strip()
            continue
        marker, body = line[:1], line[1:].strip()
        if marker not in ("+", "-", "!"):
            continue
        if not path.startswith("security policies"):
            other += 1
            continue
        block, state, named = re.match(r"policy (\S+) \{$", body), re.match(r"(?:inactive|active): policy (\S+)", body), re.search(r"\bpolicy (\S+)", path)
        if block and marker != "!":
            (added if marker == "+" else removed).append(block.group(1))
        elif state and marker == "!":
            changed.append(state.group(1))
        elif named:
            changed.append(named.group(1))
    both = set(added) & set(removed)
    added, removed = [name for name in added if name not in both], [name for name in removed if name not in both]
    changed = [name for name in changed + sorted(both) if name not in added and name not in removed]
    return {"added": _unique(added), "removed": _unique(removed), "changed": _unique(changed), "other_lines": other}


def changes_from_lines(old_lines: list[str], new_lines: list[str]) -> dict:
    """The same shape as changes_from_diff, from two runs' policy lines: a name only in the new lines is added, only in
    the old removed, in both with different lines changed. other_lines is unknown here (0)."""
    def by_name(lines: list[str]) -> dict[str, set[str]]:
        grouped: dict[str, set[str]] = {}
        for line in lines:
            found = POLICY_LINE.match(line)
            grouped.setdefault(found.group(4), set()).add(line)
        return grouped
    old, new = by_name(old_lines), by_name(new_lines)
    return {"added": _unique(sorted(set(new) - set(old))), "removed": _unique(sorted(set(old) - set(new))),
            "changed": _unique(sorted(name for name in set(old) & set(new) if old[name] != new[name])), "other_lines": 0}


def commit_flags(config_text: str, changes: dict) -> dict[str, list[str]]:
    """{policy: reasons} for each added or changed policy that is an ACTIVE permit now and is any/any/any, has no
    description, has no logging, or opens an untrusted zone into the cardholder zone (any source). Judged on the
    config as it stands, so a policy the commit left inactive or denying is not flagged."""
    policies = parse_policies(config_text)
    flags: dict[str, list[str]] = {}
    for (_, name), facts in policies.items():
        if name not in changes["added"] + changes["changed"] or not (facts["active"] and facts["permit"]):
            continue
        reasons = ["permit any/any/any"] if is_any_any_any(facts) else []
        reasons += ["opens untrusted into the cardholder zone"] if untrust_into_cde(facts) else []
        reasons += [] if facts["log"] else ["no log"]
        reasons += [] if facts["described"] else ["no description"]
        if reasons:
            flags.setdefault(name, []).extend(reason for reason in reasons if reason not in flags.get(name, []))
    return flags


def commit_criterion(flagged: list[str], findings: list[dict] | None, packet: str) -> tuple[str, bool, str]:
    """The triggered run's extra criterion: the agent names every policy code flagged in the commit (as a finding's
    rule when it gave a structured block, else anywhere in its text outside a denial)."""
    lowered = packet.lower()
    named = {finding["rule"] for finding in findings or []}
    missing = [name for name in flagged if (name not in named if findings is not None else not is_mentioned(lowered, name.lower()))]
    return ("names every policy flagged in the commit", not missing, ",".join(missing)[:200])
