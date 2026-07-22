"""Agent 2 — Correlation.

Groups related detections into incidents and assigns risk scores.
A single failed login is noise; forty of them followed by a success is
an incident. That judgement happens here.
"""

import json
from ..state import SentinelState
from ..llm import complete_json

SYSTEM = """You are a security correlation engine. You group related \
detections into coherent incidents and score their risk.

Rules:
- Group detections that share an actor, target, or attack chain.
- A detection that stands alone is still an incident, just a lower-scoring one.
- risk_score is 0-100. Weigh both likely impact and your confidence.
- Base everything on the detections given. Do not invent new evidence.

Respond with JSON only, in exactly this shape:
{
  "incidents": [
    {
      "title": "short incident name",
      "risk_score": 0-100,
      "severity": "low" | "medium" | "high" | "critical",
      "entities": {"source_ips": [], "targets": [], "users": []},
      "narrative": "what appears to have happened, in 2-4 sentences",
      "remediation": ["concrete action", "concrete action"]
    }
  ]
}"""


def correlation_agent(state: SentinelState) -> SentinelState:
    detections = state.get("detections", [])
    if not detections:
        return {"incidents": []}

    user = (
        f"Source type: {state.get('source_type')}\n\n"
        f"Detections:\n{json.dumps(detections, indent=1)}"
    )

    try:
        incidents = complete_json(SYSTEM, user, key="incidents")
        incidents.sort(key=lambda i: i.get("risk_score", 0), reverse=True)
        return {"incidents": incidents}
    except Exception as exc:  # noqa: BLE001
        return {
            "incidents": [],
            "errors": state.get("errors", []) + [f"Correlation agent failed: {exc}"],
        }
