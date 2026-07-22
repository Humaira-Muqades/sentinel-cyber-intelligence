"""Agent 1 — Detection.

Reads normalized events and flags anything suspicious.
Deliberately does not try to connect findings; that is correlation's job.
"""

import json
from ..state import SentinelState
from ..llm import complete_json

MAX_EVENTS = 200  # keep the prompt within a sane token budget

SYSTEM = """You are a security detection engine. You review normalized log \
events and flag suspicious activity.

Report only what the events actually show. Do not invent IP addresses, \
usernames, or timestamps that do not appear in the input. If nothing is \
suspicious, return an empty list.

Respond with JSON only, in exactly this shape:
{
  "detections": [
    {
      "pattern": "short name for what was detected",
      "severity": "low" | "medium" | "high" | "critical",
      "evidence": ["specific log lines or field values from the input"],
      "rationale": "one or two sentences explaining why this is suspicious"
    }
  ]
}"""


def detection_agent(state: SentinelState) -> SentinelState:
    events = state.get("parsed_events", [])
    if not events:
        return {"detections": [], "errors": state.get("errors", []) + [
            "Detection skipped: no parsed events."
        ]}

    sample = events[:MAX_EVENTS]
    truncated = len(events) > MAX_EVENTS

    user = (
        f"Source type: {state.get('source_type')}\n"
        f"Event count: {len(events)}"
        f"{f' (showing first {MAX_EVENTS})' if truncated else ''}\n\n"
        f"Events:\n{json.dumps(sample, indent=1)}"
    )

    try:
        detections = complete_json(SYSTEM, user, key="detections")
        return {"detections": detections}
    except Exception as exc:  # noqa: BLE001 - surface failure in the UI
        return {
            "detections": [],
            "errors": state.get("errors", []) + [f"Detection agent failed: {exc}"],
        }
