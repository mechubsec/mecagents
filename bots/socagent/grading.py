"""Grading for socagent: strict parsing of the model's structured verdict, independent checking of every entity it cites
against SSDF data that code fetched itself, the deterministic rules floor, and the run criteria. All functions are pure.
The item socbot escalated is code's own work and certain; the verdict is a model's reading. There is NO answer key:
whether the reading is right is not graded, only that the model was offered nothing, answered in the schema, and cited
something code could see.

Shortcut: "seen" is an exact, case-insensitive match against the IDENTITY values of the data code fetched (addresses,
firewall/observer names, signature and rule names; never severity, flags or counts). The model is given only code's
summary of that data, so an entity it did not take from the summary reads "not seen"."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
from agent import FENCED_JSON  # noqa: E402

# the token's server-side allow-list (principal socagent); alert_counts is on it but not on the server yet.
# Code, not the model, calls SSDF now: CODE_TOOLS is the fixed subset collect.py uses, and it refuses anything else.
ALLOWED_TOOLS = {"recent_alerts", "alert_counts", "query_flows", "top_talkers", "zone_matrix", "get_entity", "locate",
                 "neighbors", "observed_by", "enforcement_points", "explain_access", "ingest_status", "fabric_status"}
CODE_TOOLS = {"recent_alerts", "query_flows", "explain_access", "ingest_status"}
KINDS = {"new-high-alert", "deny-spike", "firewall-quiet"}
VERDICTS = ("benign", "needs-human", "suspicious")  # in rising order: the rules floor only ever raises
CONFIDENCES = ("low", "medium", "high")
VERDICT_KEYS = ("item", "verdict", "confidence", "summary", "evidence", "next_step")
EVIDENCE_KEYS = ("fact", "entities")
MAX_EVIDENCE, MAX_ENTITIES = 8, 6
# the row fields that name an entity; everything else in a row (severity, action, counts, flags) is not something to cite
IDENTITY_FIELDS = ("source_ip", "destination_ip", "source_address", "destination_address", "observer", "observer_hostname", "firewall",
                   "name", "signature", "rule_name")
CAPS = {"summary": 400, "next_step": 200, "fact": 250, "entity": 80}


def verdict_schema(item_id: str) -> dict:
    """The JSON schema handed to Ollama's `format` (structured output): the exact verdict shape, `item` pinned to the id.
    Ollama constrains decoding to it; parse_verdict still checks everything, because a schema is not a guarantee."""
    text = {"type": "string"}
    return {
        "type": "object",
        "properties": {
            "item": {"type": "string", "enum": [item_id]},
            "verdict": {"type": "string", "enum": list(VERDICTS)},
            "confidence": {"type": "string", "enum": list(CONFIDENCES)},
            "summary": text,
            "evidence": {"type": "array", "maxItems": MAX_EVIDENCE, "items": {
                "type": "object",
                "properties": {"fact": text, "entities": {"type": "array", "maxItems": MAX_ENTITIES, "items": text}},
                "required": list(EVIDENCE_KEYS), "additionalProperties": False}},
            "next_step": text,
        },
        "required": list(VERDICT_KEYS),
        "additionalProperties": False,
    }


def parse_verdict(content: str, item_id: str):
    """(verdict, note): the model's reply as the verdict object, or (None, reason). The reply should be the JSON object
    itself (structured output); one that is not, but has a ```json block, is read from its last block. Strict: an object
    with exactly VERDICT_KEYS, `item` equal to the escalated item's id, verdict and confidence from fixed lists
    (lowercased), strings capped, evidence a list of at most MAX_EVIDENCE objects with exactly EVIDENCE_KEYS whose
    entities are a list of at most MAX_ENTITIES non-empty strings."""
    try:
        data = json.loads(content.strip())
    except ValueError:
        blocks = FENCED_JSON.findall(content)
        if not blocks:
            return None, "reply is not JSON and has no ```json block"
        try:
            data = json.loads(blocks[-1])
        except ValueError as exc:
            return None, f"invalid JSON ({str(exc)[:60]})"
    if not isinstance(data, dict) or set(data) != set(VERDICT_KEYS):
        return None, f"the verdict does not have exactly the keys {', '.join(VERDICT_KEYS)}"
    if data["item"] != item_id:
        return None, f"the verdict is about item {str(data['item'])[:30]!r}, not {item_id}"
    for field in ("summary", "next_step"):
        if not isinstance(data[field], str):
            return None, f"{field} is not a string"
    for field, allowed in (("verdict", VERDICTS), ("confidence", CONFIDENCES)):
        if not isinstance(data[field], str) or data[field].lower() not in allowed:
            return None, f"{field} is {str(data[field])[:20]!r}"
    if not isinstance(data["evidence"], list):
        return None, "evidence is not a list"
    evidence = []
    for index, entry in enumerate(data["evidence"][:MAX_EVIDENCE], start=1):
        if not isinstance(entry, dict) or set(entry) != set(EVIDENCE_KEYS):
            return None, f"evidence {index} does not have exactly the keys {', '.join(EVIDENCE_KEYS)}"
        entities = entry["entities"]
        if (not isinstance(entry["fact"], str) or not isinstance(entities, list)
                or any(not isinstance(entity, str) or not entity.strip() for entity in entities)):
            return None, f"evidence {index} has a field of the wrong type"
        evidence.append({"fact": entry["fact"][:CAPS["fact"]], "entities": [entity.strip()[:CAPS["entity"]] for entity in entities[:MAX_ENTITIES]]})
    return {"item": item_id, "verdict": data["verdict"].lower(), "confidence": data["confidence"].lower(),
            "summary": data["summary"][:CAPS["summary"]], "evidence": evidence, "next_step": data["next_step"][:CAPS["next_step"]]}, ""


def unwrap(value):
    """SSDF's {value, truncated, untrusted} wrapper unwrapped (anything else unchanged)."""
    return value["value"] if isinstance(value, dict) and "value" in value else value


def flatten(value, found: set) -> set:
    """Every scalar in a reply, lowercased, into `found`; SSDF's {value, truncated, untrusted} wrapper is unwrapped."""
    if isinstance(value, dict) and "value" in value:
        return flatten(value["value"], found)
    if isinstance(value, dict):
        for inner in value.values():
            flatten(inner, found)
    elif isinstance(value, list):
        for inner in value:
            flatten(inner, found)
    elif value not in (None, ""):
        found.add(str(value).strip().lower())
    return found


def identity_values(row) -> set:
    """The lowercased values of one row's IDENTITY_FIELDS (a row that is not an object has none)."""
    found: set = set()
    for field in IDENTITY_FIELDS if isinstance(row, dict) else ():
        flatten(row.get(field), found)
    return found


def row_time(row):
    """The row's `timestamp` (UTC, `2026-11-12 17:11:40.704` or ISO with a T) as epoch seconds, or None when absent or unreadable."""
    try:
        moment = datetime.fromisoformat(str(row["timestamp"]).strip().replace("Z", "+00:00"))
    except (KeyError, ValueError, TypeError, AttributeError):
        return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).timestamp()


def relevant_rows(kind: str, facts: dict, replies: list[dict], until: float | None = None) -> list:
    """The part of the independently fetched replies that concerns the escalated item: for an alert the rows of that
    signature on that observer, for denies every denied flow row, for a quiet firewall its ingest_status entry. With `until`
    (epoch seconds) a row stamped after it, or with no readable stamp, is dropped: it cannot show what socbot saw. An
    ingest_status entry has no stamp and is a snapshot, so it is never filtered."""
    rows = [row for reply in replies for row in reply.get("rows", reply.get("firewalls", []))]
    if until is not None and kind != "firewall-quiet":
        rows = [row for row in rows if isinstance(row, dict) and (moment := row_time(row)) is not None and moment <= until]
    if kind == "new-high-alert":
        return [row for row in rows if flatten(row.get("signature"), set()) == {facts["signature"].lower()} and str(row.get("observer")) == facts["observer"]]
    if kind == "firewall-quiet":
        return [row for row in rows if row.get("name") == facts["firewall"]]
    return rows


def verify(verdict: dict, values: set) -> dict:
    """A copy of the verdict with each cited entity marked: evidence[i]["entities"] becomes [{entity, seen}], and the verdict gets
    status `supported` (some entity was seen in `values`, the identity values of the data code fetched) or `unsupported`."""
    evidence = [{**entry, "entities": [{"entity": entity, "seen": entity.lower() in values} for entity in entry["entities"]]}
                for entry in verdict["evidence"]]
    seen = sum(1 for entry in evidence for entity in entry["entities"] if entity["seen"])
    total = sum(len(entry["entities"]) for entry in evidence)
    return {**verdict, "evidence": evidence, "seen": seen, "not_seen": total - seen, "status": "supported" if seen else "unsupported"}


def rules_floor(kind: str, signals: dict, verdict: dict | None) -> tuple[str, str]:
    """(minimum verdict, why) set by fixed rules from code's own data, whatever the model said; ("benign", "") when no rule
    fires. Rules only ever raise: an ongoing deny spike, an alert still firing, a critical alert, a firewall still quiet,
    an unsupported reading or no valid reading at all can never stand as benign."""
    reasons = []
    if verdict is None:
        reasons.append("no valid verdict from the model")
    elif verdict.get("status") == "unsupported":
        reasons.append("none of the entities the model cites is in the data")
    if kind == "deny-spike" and signals.get("last_hour", 0) > 0:
        reasons.append(f"denies still arriving: {signals['last_hour']} in the last hour")
    if kind == "new-high-alert" and signals.get("last_hour", 0) > 0:
        reasons.append(f"the alert is still firing: {signals['last_hour']} in the last hour")
    if kind == "new-high-alert" and signals.get("severity") == "critical":
        reasons.append("severity is critical")
    if kind == "firewall-quiet" and signals.get("still_stale"):
        reasons.append("the firewall is still not logging")
    return ("needs-human", "; ".join(reasons)) if reasons else ("benign", "")


def apply_floor(verdict: dict | None, floor: tuple[str, str]) -> dict:
    """{final, raised, reason}: the final reading is the higher of the model's verdict and the rules floor. `raised` is
    true only when the rules changed it (a model's benign, or no reading at all, lifted to the floor)."""
    minimum, reason = floor
    said = verdict["verdict"] if verdict else None
    final = max(said or "benign", minimum, key=VERDICTS.index)
    return {"final": final, "raised": final != said, "reason": reason if final != said else ""}


def grade(offered: list, tool_calls: list, verdict: dict | None, note: str, ended: str = "ok") -> list[tuple[str, bool, str]]:
    """[(criterion, ok, detail)] for one judging run: no tools offered to the model (and none asked for in its reply), a
    valid structured verdict, at least one cited entity seen; plus a failed "model run finished" when the call did not end ok."""
    results = [
        ("no tools offered", not offered and not tool_calls,
         ",".join(map(str, offered))[:100] or (f"reply asked for {len(tool_calls)} tool call(s)" if tool_calls else "")),
        ("valid structured verdict", verdict is not None, note),
        ("at least one cited entity seen", bool(verdict and verdict.get("seen")), "" if verdict is None else f"{verdict.get('seen', 0)} seen, {verdict.get('not_seen', 0)} not seen"),
    ]
    return results if ended == "ok" else results + [("model run finished", False, ended)]
