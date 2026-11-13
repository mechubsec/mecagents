"""Grading for bpcheckagent: the answer key is derived by code from the device's own config (no hand-made key for best
practice exists), and the packet is scored against it with the shared criteria in lib/agent.py.

Derived from the `set` lines of the security policies:
- must_find: every permit policy whose source, destination and application are all `any`, zone-pair or global, unless a
  `match dynamic-application` other than `any` narrows it (then it is left out of both lists);
- a `deactivate security policies ...` line switches off everything at or below its path: a policy, a zone pair or all of
  them (the policy leaves every list), or one statement such as its `match dynamic-application` (that match then no longer narrows it);
- the missing-logging concept: required once if at least one permit policy has no `log` statement;
- must_not_flag: a permit policy that is described, logged and narrow (no `any` in source, destination or application,
  and a concrete from/to zone). Conservative: a policy that fits neither list is simply not graded.
Shortcut: only `set security policies ... policy <name> ...` lines are read (not default-policy, not order or shadowing); every policy name is matched by name alone, so equal names in two zone pairs count as one."""

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
from agent import structured_findings  # noqa: E402

DEVICE = os.environ.get("BPCHECKAGENT_DEVICE", "lab-vsrx")  # placeholder: name of your target device in the Junos MCP server
READ_TOOLS = ["get_device_list", "get_router_list", "gather_device_facts", "get_junos_config", "junos_config_diff"]
DEACTIVATE_LINE = re.compile(r"^deactivate security policies(?: (.+))?$")
POLICY_LINE = re.compile(r"^set security policies (?:from-zone (\S+) to-zone (\S+)|global) policy (\S+) (.+)$")
MISSING_LOG_PHRASES = ["no log", "not logged", "without log", "missing log", "lacks log", "lacking log", "no logging",
                       "logging is not", "logging disabled", "unlogged", "does not log", "doesn't log", "log is missing"]
FORBIDDEN_PHRASES = ["is secure", "fully secure", "is compliant", "follows best practices", "meets best practices"]


def parse_policies(config_text: str) -> dict[tuple[str, str], dict]:
    """{(scope, name): facts} for every security policy in a set-format config. scope is "global" or "from>to".
    facts: source, destination, application, dynamic (sets of names), permit, log, described (bools), from, to (a zone or
    None) for the zones a policy applies to. A `deactivate security policies <path>` line switches off everything at or
    below its path: a whole policy (or zone pair, or all of them), or one statement such as `... policy P match
    dynamic-application`, whose values then no longer narrow the policy. A deeper path deactivates one
    member of a `match` list, or a sub-statement of `then permit` (the permit stays)."""
    lines = [line.strip() for line in config_text.splitlines()]
    inactive = [(found.group(1) or "").replace('"', "").split() for found in map(DEACTIVATE_LINE.match, lines) if found]  # [] = every policy
    policies: dict[tuple[str, str], dict] = {}
    for line in lines:
        found = POLICY_LINE.match(line)
        if not found:
            continue
        from_zone, to_zone, name, rest = found.groups()
        path = line.removeprefix("set security policies ").replace("[", " ").replace("]", " ").replace('"', "").split()
        words = rest.replace("[", " ").replace("]", " ").replace('"', "").split()
        core_end = len(path) - len(words) + (2 if words[0] in ("match", "then") else 1)  # the statement itself: `match X`, `then X`, `description`
        if any(path[:len(prefix)] == prefix and len(prefix) <= core_end for prefix in inactive):  # this statement is deactivated, or something above it is
            continue
        members = {prefix[core_end] for prefix in inactive if len(prefix) == core_end + 1 and prefix[:core_end] == path[:core_end]}  # one deactivated list member
        if words[:1] == ["match"] or words[:2] == ["then", "log"]:
            kept = [word for word in words[2:] if word not in members]
            if words[:1] == ["then"] and words[2:] and not kept:  # every log leaf on this line is deactivated: no logging from it
                continue
            words = words[:2] + kept
        facts = policies.setdefault(("global" if not from_zone else f"{from_zone}>{to_zone}", name), {
            "source": set(), "destination": set(), "application": set(), "dynamic": set(), "permit": False, "log": False, "described": False,
            "from": from_zone, "to": to_zone})
        if words[:2] == ["match", "source-address"]:
            facts["source"].update(words[2:])
        elif words[:2] == ["match", "destination-address"]:
            facts["destination"].update(words[2:])
        elif words[:2] == ["match", "dynamic-application"]:
            facts["dynamic"].update(words[2:])
        elif words[:2] == ["match", "application"]:
            facts["application"].update(words[2:])
        elif words[:2] == ["match", "from-zone"]:
            facts["from"] = words[2] if len(words) > 2 else None
        elif words[:2] == ["match", "to-zone"]:
            facts["to"] = words[2] if len(words) > 2 else None
        elif words[:2] == ["then", "permit"]:
            facts["permit"] = True
        elif words[:2] == ["then", "log"]:
            facts["log"] = True
        elif words[0] == "description":
            facts["described"] = True
    return policies


def any_any_any(policies: dict) -> list[str]:
    """Names of permit policies with source, destination and application all `any`, sorted. A policy whose
    `match dynamic-application` is set and does not include `any` is narrowed by it and is not named."""
    return sorted({name for (_, name), p in policies.items() if p["permit"] and {"any"} <= p["source"] and {"any"} <= p["destination"] and {"any"} <= p["application"]
                   and (not p["dynamic"] or "any" in p["dynamic"])})


def permits_without_log(policies: dict) -> list[str]:
    """Names of permit policies with no `then log` statement, sorted."""
    return sorted({name for (_, name), p in policies.items() if p["permit"] and not p["log"]})


def narrow_logged_described(policies: dict) -> list[str]:
    """Names of permit policies that are described, logged and narrow: concrete source, destination, application and
    zones (nothing is `any`, nothing is missing). The agent must not rate these as defects."""
    def narrow(p: dict) -> bool:
        return all(p[key] and "any" not in p[key] for key in ("source", "destination", "application")) \
            and bool(p["from"]) and bool(p["to"]) and "any" not in (p["from"], p["to"])
    return sorted({name for (_, name), p in policies.items() if p["permit"] and p["log"] and p["described"] and narrow(p)})


def derive_key(config_text: str) -> dict:
    """The answer key for this config, in the shape lib/agent.py's score_text/grade take."""
    policies = parse_policies(config_text)
    unlogged = permits_without_log(policies)
    return {"target": DEVICE, "derived_from": "the fetched config", "read_tools": READ_TOOLS,
            "must_find": any_any_any(policies),
            "must_find_concepts": {"missing logging on permit policies": MISSING_LOG_PHRASES} if unlogged else {},
            "permits_without_log": unlogged, "soft": [], "must_not_flag": narrow_logged_described(policies),
            "forbidden_phrases": FORBIDDEN_PHRASES}


def findings_for(packet: str, config_text: str):
    """(findings, source, note): the structured findings (source "structured") or, when the block is missing or
    invalid, no findings at all (source "none", note = why); there is no heuristic reading for this agent."""
    findings, note = structured_findings(packet, config_text, label="check", label_cap=40)
    return (findings, "structured", "") if findings is not None else ([], "none", note)
