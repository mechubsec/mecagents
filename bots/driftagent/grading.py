"""Grading for driftagent: normalise two set-format configs, diff them, name the objects the changed lines touch, and
check the model's reading of the change against that diff. All functions are pure; the diff and the touched objects are
code's own work and are certain, the model's reading is only graded, never trusted.

Shortcut: configs are compared as sets of lines, so a pure reorder (policy order matters in Junos) is not drift, and
a line the server redacts or that carries a credential is dropped from both sides, so a rotated secret is invisible.
`deactivate ...` lines are compared like `set` lines (a deactivated policy is a change). Policies are keyed
`from-zone/to-zone/name` (or `global/name`) and address-book entries `book/name`, so equal names in two places are two objects.
Credential lines are matched by field (`pre-shared-key`, `secret "..."`, `snmp ... community`...), not by a bare word, so an
object merely named `allow-secret-server` is compared normally. This is a local copy of lib/agent.py's SECRET_LINE job."""

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
from agent import strict_json_items  # noqa: E402

DEVICE = os.environ.get("DRIFTAGENT_DEVICE", "lab-vsrx")  # placeholder: name of your target device in the Junos MCP server
READ_TOOLS = ["get_device_list", "get_router_list", "gather_device_facts", "get_junos_config", "junos_config_diff"]
FORBIDDEN_PHRASES = ["is secure", "is compliant", "fully compliant", "no risk"]
# the server's redaction placeholder in any spelling seen or plausible, so a changed spelling is never drift
PLACEHOLDER = re.compile(r'"?\[REDACTED\]"?|"?<redacted>"?|\*{3,}|"?\$\d\$\S+', re.I)
KINDS = {"policy", "address", "zone", "interface", "other"}
RISKS = {"high", "medium", "low", "none"}
CHANGE_KEYS = ("object", "kind", "effect", "risk", "evidence")
CHANGE_CAPS = {"object": 80, "kind": 20, "effect": 300, "risk": 20, "evidence": 300}
POLICY = re.compile(r"^security policies (?:from-zone (\S+) to-zone (\S+)|global) policy (\S+)")
ADDRESS = re.compile(r"^security address-book (\S+) address(?:-set)? (\S+)")
OBJECT_PATTERNS = [  # (regex over the line after "set "/"deactivate ", kind; every group names an object)
    (re.compile(r"^security zones security-zone (\S+)"), "zone"),
    (re.compile(r"^applications application(?:-set)? (\S+)"), "other"),
    (re.compile(r"^security nat \S+ rule-set (\S+)(?: rule (\S+))?"), "other"),
]
ZONE_INTERFACE = re.compile(r"^security zones security-zone \S+ interfaces (\S+)")
INTERFACE = re.compile(r"^interfaces (\S+)(?: unit (\d+))?")


# A credential-bearing field or form. Hyphen-bounded so `allow-secret-server` is a name, not a secret; a bare `secret` counts
# only when a quoted, $-crypted or redacted value follows it.
CREDENTIAL_LINE = re.compile(
    r"(?<![\w-])(?:encrypted-password|plain-text-password|authentication-key|authentication-password|pre-shared-key|privacy-key|privacy-password)(?![\w-])"
    r"|(?<![\w-])secret\s+(?:[\"$]|<redacted>)"
    r"|(?<![\w-])snmp(?![\w-]).*?(?<![\w-])community(?:-name)?\s+\S"
    r"|authentication ssh-(?:rsa|ed25519|ecdsa)")
# what model text must not carry into a report: a credential field or form, a Junos crypt string, or a long base64/hex blob
CREDENTIAL_TEXT = re.compile(CREDENTIAL_LINE.pattern + r"|\$\d\$\S|[A-Za-z0-9+/]{32,}={0,2}|(?<![\w-])[0-9A-Fa-f]{24,}(?![\w-])")


def looks_like_credential(text: str) -> bool:
    """True when model text contains something that looks like a credential (see CREDENTIAL_TEXT)."""
    return bool(CREDENTIAL_TEXT.search(text or ""))


def normalise(config_text: str) -> list[str]:
    """The comparable lines of a set-format config: whitespace-collapsed `set` and `deactivate` lines in order, without the version
    header, without anything that could hold a credential, redaction placeholders replaced by one fixed token, no repeats."""
    lines, seen = [], set()
    for raw in config_text.splitlines():
        line = " ".join(PLACEHOLDER.sub("<redacted>", raw).split())
        if not line.startswith(("set ", "deactivate ")) or line.startswith("set version ") or CREDENTIAL_LINE.search(line) or line in seen:
            continue
        seen.add(line)
        lines.append(line)
    return lines


def diff_lines(golden: list[str], live: list[str]) -> tuple[list[str], list[str]]:
    """(added, removed): lines only in the live config, lines only in the golden, each in its own file's order."""
    golden_set, live_set = set(golden), set(live)
    return [line for line in live if line not in golden_set], [line for line in golden if line not in live_set]


def touched_objects(lines: list[str]) -> dict[str, str]:
    """{name: kind} for every object a changed `set`/`deactivate` line names: policy (`from/to/name` or `global/name`),
    address-book entry (`book/name`), zone, interface (both `ge-0/0/1` and `ge-0/0/1.0`), application, NAT rule-set/rule;
    a line none of these match names its first two words as `other`."""
    objects: dict[str, str] = {}
    for line in lines:
        body = line.removeprefix("set ").removeprefix("deactivate ").replace('"', "")
        matched = False
        policy = POLICY.match(body)
        if policy:
            matched = True
            objects[f"{policy.group(1)}/{policy.group(2)}/{policy.group(3)}" if policy.group(1) else f"global/{policy.group(3)}"] = "policy"
        address = ADDRESS.match(body)
        if address:
            matched = True
            objects[f"{address.group(1)}/{address.group(2)}"] = "address"
        for pattern, kind in OBJECT_PATTERNS:
            found = pattern.match(body)
            if found:
                matched = True
                objects.update({name: kind for name in found.groups() if name})
        zone_interface = ZONE_INTERFACE.match(body)
        if zone_interface:
            objects[zone_interface.group(1)] = "interface"
            objects[zone_interface.group(1).split(".")[0]] = "interface"
        interface = INTERFACE.match(body)
        if interface and not matched:
            matched = True
            objects[interface.group(1)] = "interface"
            if interface.group(2):
                objects[f"{interface.group(1)}.{interface.group(2)}"] = "interface"
        if not matched and not zone_interface:
            objects.setdefault(" ".join(body.split()[:2]), "other")
    return objects


def compare(golden_text: str, live_text: str) -> dict:
    """The whole drift result: {added, removed, objects}; empty added and removed means identical."""
    added, removed = diff_lines(normalise(golden_text), normalise(live_text))
    return {"added": added, "removed": removed, "objects": touched_objects(added + removed)}


def derive_key(objects: dict[str, str]) -> dict:
    """The answer key for one drift: every touched policy (by its `from/to/name` key) must be named by the agent (the shape lib/agent.py's grade takes)."""
    return {"target": DEVICE, "read_tools": READ_TOOLS, "must_find": sorted(name for name, kind in objects.items() if kind == "policy"),
            "must_find_concepts": {}, "soft": [], "must_not_flag": [], "forbidden_phrases": FORBIDDEN_PHRASES}


def structured_changes(packet: str, diff: dict):
    """(changes, note): the packet's last ```json block `{"changes": [...]}`, strictly parsed (exactly the keys object,
    kind, effect, risk, evidence; kind and risk from fixed lists; capped), each checked against the code's diff:
    verified (object touched and evidence is one of the changed lines, whitespace normalised, `set ` optional; a model
    field that looks like a credential is replaced by [withheld] and the change is marked withheld),
    object touched (evidence is not a changed line), unverified (the object is not one the diff touched).
    Returns (None, reason) when the block is missing or invalid."""
    items, note = strict_json_items(packet, "changes", "change", CHANGE_KEYS, {"kind": KINDS, "risk": RISKS}, CHANGE_CAPS)
    if items is None:
        return None, note

    def flat(text: str) -> str:
        return " ".join(text.replace('"', "").split()).removeprefix("set ")

    changed = {flat(line) for line in diff["added"] + diff["removed"]}
    for change in items:
        withheld = any(looks_like_credential(change[field] or "") for field in ("object", "effect", "evidence"))
        evidence_ok = bool(change["evidence"]) and flat(change["evidence"]) in changed
        if change["object"] not in diff["objects"]:
            change["status"], change["why"] = "unverified", "names something the diff did not touch"
        elif evidence_ok:
            change["status"], change["why"] = "verified", "object touched and the evidence is a changed line"
        else:
            change["status"], change["why"] = "object touched", "object touched, evidence not a changed line verbatim"
        change["withheld"] = withheld  # the status above was judged on the real text; now nothing credential-like leaves this module
        if withheld:
            change.update(object="[withheld]", effect="[withheld]", evidence=None)
    return items, ""
