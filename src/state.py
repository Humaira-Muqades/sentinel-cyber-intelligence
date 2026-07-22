"""Shared state passed between SENTINEL agents.

Every agent receives the full state and returns a partial update.
LangGraph merges the update into the state before the next node runs.
"""

from typing import TypedDict, List, Dict, Any


class SentinelState(TypedDict, total=False):
    # Input
    raw_logs: str
    source_type: str  # "firewall" | "auth"

    # Populated by the parser (deterministic, no LLM)
    parsed_events: List[Dict[str, Any]]

    # Populated by agents
    detections: List[Dict[str, Any]]
    incidents: List[Dict[str, Any]]
    report: str

    # Diagnostics
    errors: List[str]


def new_state(raw_logs: str, source_type: str) -> SentinelState:
    """Build a fresh state object for a pipeline run."""
    return {
        "raw_logs": raw_logs,
        "source_type": source_type,
        "parsed_events": [],
        "detections": [],
        "incidents": [],
        "report": "",
        "errors": [],
    }
