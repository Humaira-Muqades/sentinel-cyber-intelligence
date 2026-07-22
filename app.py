"""SENTINEL — Streamlit interface."""

import os
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

from src.graph import run
from src.parsers import parse, parse_stats

load_dotenv()

st.set_page_config(page_title="SENTINEL", page_icon="🛡️", layout="wide")

SEVERITY_COLORS = {
    "critical": "#FF4B4B",
    "high": "#FF8C42",
    "medium": "#FFD166",
    "low": "#00D084",
}

SAMPLES = {
    "firewall": Path("data/samples/firewall_sample.log"),
    "auth": Path("data/samples/auth_sample.log"),
}

st.title("🛡️ SENTINEL")
st.caption("AI-powered cyber defense intelligence — logs in, analyst report out.")

# ─── Sidebar ────────────────────────────────────────────────
with st.sidebar:
    st.header("Configuration")

    source_type = st.selectbox(
        "Log source",
        options=["firewall", "auth"],
        format_func=lambda s: {"firewall": "Firewall", "auth": "Authentication"}[s],
    )

    use_sample = st.checkbox("Use sample log", value=True)

    uploaded = None
    if not use_sample:
        uploaded = st.file_uploader("Upload log file", type=["log", "txt"])

    st.divider()
    if os.getenv("GROQ_API_KEY"):
        st.success("Groq API key loaded")
    else:
        st.error("No GROQ_API_KEY found. Add it to your .env file.")

# ─── Load input ─────────────────────────────────────────────
raw_logs = ""
if use_sample:
    sample_path = SAMPLES[source_type]
    if sample_path.exists():
        raw_logs = sample_path.read_text()
    else:
        st.warning(f"Sample file not found: {sample_path}")
elif uploaded is not None:
    raw_logs = uploaded.read().decode("utf-8", errors="replace")

if raw_logs:
    with st.expander("Input preview", expanded=False):
        st.code(raw_logs[:3000], language="log")

    events = parse(raw_logs, source_type)
    stats = parse_stats(events)
    c1, c2, c3 = st.columns(3)
    c1.metric("Lines", stats["total"])
    c2.metric("Parsed", stats["parsed"])
    c3.metric("Unrecognized", stats["unparsed"])

# ─── Run ────────────────────────────────────────────────────
if st.button("Run analysis", type="primary", disabled=not raw_logs):
    with st.spinner("Running the agent pipeline…"):
        result = run(raw_logs, source_type)

    for err in result.get("errors", []):
        st.error(err)

    incidents = result.get("incidents", [])
    detections = result.get("detections", [])

    st.subheader("Incidents")
    if not incidents:
        st.info("No incidents identified in this log sample.")
    for inc in incidents:
        sev = str(inc.get("severity", "low")).lower()
        color = SEVERITY_COLORS.get(sev, "#888888")
        score = inc.get("risk_score", 0)

        st.markdown(
            f"<span style='background:{color};color:#000;padding:2px 10px;"
            f"border-radius:10px;font-weight:600'>{sev.upper()} · {score}</span> "
            f"&nbsp;**{inc.get('title', 'Untitled incident')}**",
            unsafe_allow_html=True,
        )
        st.write(inc.get("narrative", ""))

        actions = inc.get("remediation", [])
        if actions:
            st.markdown("**Remediation**")
            for a in actions:
                st.markdown(f"- {a}")
        st.divider()

    with st.expander(f"Raw detections ({len(detections)})"):
        st.json(detections)

    report = result.get("report", "")
    if report:
        st.subheader("Intelligence report")
        st.markdown(report)
        st.download_button(
            "Download report",
            data=report,
            file_name="sentinel-report.md",
            mime="text/markdown",
        )
