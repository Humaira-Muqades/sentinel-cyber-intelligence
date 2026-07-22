"""Log parsing.

Parsing is deterministic on purpose. Sending raw text straight to an LLM
wastes tokens and produces inconsistent structure. We normalize first,
then let the agents reason over clean events.
"""

import re
from typing import List, Dict, Any

# Example:
# 2024-03-11 14:22:07 DENY TCP 203.0.113.44:51022 -> 10.0.4.12:22 rule=BLOCK_SSH
FIREWALL_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>ALLOW|DENY|DROP|REJECT)\s+"
    r"(?P<protocol>TCP|UDP|ICMP)\s+"
    r"(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s*->\s*"
    r"(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)"
    r"(?:\s+rule=(?P<rule>\S+))?",
    re.IGNORECASE,
)

# Example:
# Mar 11 14:22:09 web-01 sshd[2841]: Failed password for root from 203.0.113.44 port 51022 ssh2
AUTH_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>\w+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

AUTH_OUTCOME_RE = re.compile(
    r"(?P<outcome>Failed password|Accepted password|Invalid user|"
    r"authentication failure|session opened|session closed)",
    re.IGNORECASE,
)

AUTH_USER_RE = re.compile(r"for (?:invalid user )?(?P<user>\S+) from", re.IGNORECASE)
AUTH_IP_RE = re.compile(r"from (?P<ip>[\d.]+)")


def parse_firewall(text: str) -> List[Dict[str, Any]]:
    events = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = FIREWALL_RE.match(line)
        if m:
            e = m.groupdict()
            e["line"] = lineno
            e["source"] = "firewall"
            events.append(e)
        else:
            events.append(
                {"line": lineno, "source": "firewall", "unparsed": line}
            )
    return events


def parse_auth(text: str) -> List[Dict[str, Any]]:
    events = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = AUTH_RE.match(line)
        if not m:
            events.append({"line": lineno, "source": "auth", "unparsed": line})
            continue

        e = m.groupdict()
        e["line"] = lineno
        e["source"] = "auth"

        msg = e.get("message", "") or ""
        outcome = AUTH_OUTCOME_RE.search(msg)
        e["outcome"] = outcome.group("outcome") if outcome else "other"

        user = AUTH_USER_RE.search(msg)
        if user:
            e["user"] = user.group("user")

        ip = AUTH_IP_RE.search(msg)
        if ip:
            e["src_ip"] = ip.group("ip")

        events.append(e)
    return events


PARSERS = {"firewall": parse_firewall, "auth": parse_auth}


def parse(text: str, source_type: str) -> List[Dict[str, Any]]:
    parser = PARSERS.get(source_type)
    if parser is None:
        raise ValueError(
            f"Unknown source type {source_type!r}. "
            f"Expected one of: {', '.join(PARSERS)}"
        )
    return parser(text)


def parse_stats(events: List[Dict[str, Any]]) -> Dict[str, int]:
    """Quick summary used by the UI and by the detection prompt."""
    total = len(events)
    unparsed = sum(1 for e in events if "unparsed" in e)
    return {"total": total, "parsed": total - unparsed, "unparsed": unparsed}
