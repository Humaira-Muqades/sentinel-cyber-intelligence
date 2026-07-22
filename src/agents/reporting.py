"""Agent 3 — Reporting.

Composes the analyst-facing write-up. This is the deliverable a human
actually reads, so it is the one place we let the model write prose.
"""

import json
from ..state import SentinelState
from ..llm import complete

SYSTEM = """You are a senior security analyst writing an incident report.

Write in Markdown with these sections:
## Executive Summary
## Incidents
## Recommended Actions

Guidance:
- Lead with what matters. An executive reads only the summary.
- Reference specific IPs, users, and timestamps from the incident data.
- State uncertainty plainly where the evidence is thin.
- No filler, no marketing language, no restating the obvious.
- If there are no incidents, say so clearly and briefly. Do not pad."""


def reporting_agent(state: SentinelState) -> SentinelState:
    incidents = state.get("incidents", [])
    stats = {
        "source_type": state.get("source_type"),
        "events_analyzed": len(state.get("parsed_events", [])),
        "detections": len(state.get("detections", [])),
        "incidents": len(incidents),
    }

    user = (
        f"Run summary:\n{json.dumps(stats, indent=1)}\n\n"
        f"Incidents:\n{json.dumps(incidents, indent=1)}"
    )

    try:
        return {"report": complete(SYSTEM, user)}
    except Exception as exc:  # noqa: BLE001
        return {
            "report": "",
            "errors": state.get("errors", []) + [f"Reporting agent failed: {exc}"],
        }
