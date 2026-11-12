"""Grading for pcicomplyagent: the packet's findings, checked against evidence fetched independently, and the run
checked against the lab-vsrx answer key.

The shared parts (score_text, score_calls, grade, scrub_config, the strict findings-block parser) live in
lib/agent.py and are re-exported here; what stays is PCI-specific: the heuristic reading of a packet that has no
findings block. All functions are pure."""

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib"))
from agent import (DEVICE_KEYS, JUNOS_WRITE_TOOLS, MAX_ITEMS as MAX_FINDINGS, SECRET_LINE, SEVERITIES,  # noqa: E402,F401
                   config_tokens, grade, scrub_config, score_calls, score_text, structured_findings, underlying_calls)

DEVICE = os.environ.get("PCICOMPLYAGENT_DEVICE", "lab-vsrx")  # placeholder: name of your target device in the Junos MCP server
SEVERITY = re.compile(r"\b(critical|high|medium|low)\b", re.I)
# a PCI DSS requirement number like 1.3.1; not part of an IP address or a version ("v4.0.1", "4.0.1")
CONTROL = re.compile(r"(?<![\w./])(\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)(?![\w/]|\.\d)")
LIST_ITEM = re.compile(r"(?:[-*\u2022]|\d+[.)])\s")
CITE_BACKTICKED = re.compile(r"`([^`\s]{2,60})`")
CITE_CAPS = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\b")
CITE_AFTER_KEYWORD = re.compile(r"\b(?:policy|rule|term)\s+[`'\"]?([A-Za-z][\w]*[-_][\w-]*\w)")
POLICY_NAME = re.compile(r"\bpolicy (\S+)")
SUMMARY_ROW = re.compile(r"\|\s*\W*(critical|high|medium|low)\W*\s*\|", re.I)  # "| **High** | 2 | F02, F03 |"
def policy_names(config_text: str) -> set[str]:
    """The security policy names in a set-format config."""
    return set(POLICY_NAME.findall(config_text))


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
    invalid, the heuristic reading of the text (source "heuristic", note = why the block was not used)."""
    structured, note = structured_findings(packet, config_text)
    if structured is not None:
        return structured, "structured", ""
    return verify_findings(extract_findings(packet, config_text), config_text), "heuristic", note


