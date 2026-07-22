"""SENTINEL pipeline.

    ingest -> detect -> correlate -> report

Ingestion is a plain function, not an LLM call. Parsing is a solved
problem and determinism is worth more than flexibility here.
"""

from langgraph.graph import StateGraph, START, END

from .state import SentinelState, new_state
from .parsers import parse
from .agents.detection import detection_agent
from .agents.correlation import correlation_agent
from .agents.reporting import reporting_agent


def ingestion_node(state: SentinelState) -> SentinelState:
    try:
        events = parse(state["raw_logs"], state["source_type"])
        return {"parsed_events": events}
    except Exception as exc:  # noqa: BLE001
        return {
            "parsed_events": [],
            "errors": state.get("errors", []) + [f"Ingestion failed: {exc}"],
        }


def build_graph():
    g = StateGraph(SentinelState)

    g.add_node("ingest", ingestion_node)
    g.add_node("detect", detection_agent)
    g.add_node("correlate", correlation_agent)
    g.add_node("report", reporting_agent)

    g.add_edge(START, "ingest")
    g.add_edge("ingest", "detect")
    g.add_edge("detect", "correlate")
    g.add_edge("correlate", "report")
    g.add_edge("report", END)

    return g.compile()


def run(raw_logs: str, source_type: str) -> SentinelState:
    """Run the full pipeline and return the final state."""
    return build_graph().invoke(new_state(raw_logs, source_type))
